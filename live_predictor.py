"""
Live scoring of an in-progress HTTP session, one request at a time.

Usage sketch (you wire the request-capture source - a reverse proxy,
a WAF hook, an app middleware, or a log tailer - this module only
needs a dict per request, it doesn't care where it came from):

    predictor = LiveAttackPredictor(
        model_path="lstm_stage_classifier.keras",
        hmm_params_path="hmm_params.npz",
    )

    # for each new HTTP request belonging to session_id:
    result = predictor.observe(
        session_id="client_abc123",
        request_data={
            "method": "GET",
            "path": "/rest/products/search",
            "query": "q=apple'))+UNION+SELECT+1,2,3,4--",
            "body": "",
            "headers": {"User-Agent": "..."},
        },
        response_data={"status": 200, "length": 512},
    )

    print(result.stage, result.confidence, result.escalated)

`result.stage` is the ONLINE VITERBI-SMOOTHED best guess (uses the
learned transition structure, not just this one request in
isolation). `result.lstm_stage` is the raw per-request LSTM guess,
included for comparison/debugging.
"""

import os
import json
import numpy as np
from dataclasses import dataclass
from typing import Optional, Any
from tensorflow import keras

from feature_engineering import STAGES, FEATURE_KEYS, SessionFeatureTracker, vectorize
from admin_alert import AdminAlertDispatcher, AdminAlert

MAX_LEN = 20
PAD_VALUE = -1.0
NUM_STAGES = len(STAGES)

# Stage severity order - used only to decide whether a session has
# "escalated" since its last observed request (for alerting), not
# used anywhere in the model itself.
SEVERITY_RANK = {stage: i for i, stage in enumerate(STAGES)}


@dataclass
class PredictionResult:
    session_id: str
    request_number: int
    stage: str                 # online-Viterbi smoothed best guess
    confidence: float          # calibrated prob of `stage` at this step
    lstm_stage: str            # raw single-request LSTM argmax, for comparison
    escalated: bool            # stage severity increased vs. this session's previous best guess
    full_probs: dict           # {stage_name: probability} from the LSTM at this step
    alert: Optional[AdminAlert] = None  # Admin alert if triggered


class _SessionState:
    __slots__ = ("tracker", "feature_window", "log_prob", "request_count", "last_stage_rank")

    def __init__(self, num_states):
        self.tracker = SessionFeatureTracker()
        self.feature_window = []          # last MAX_LEN feature vectors, most recent last
        self.log_prob = None              # (num_states,) running Viterbi log-probabilities
        self.request_count = 0
        self.last_stage_rank = 0          # NORMAL


class LiveAttackPredictor:
    def __init__(
        self,
        model_path,
        hmm_params_path,
        calib_params_path="calibration_params.json",
        enable_admin_alerts=True,
        max_len=MAX_LEN,
        session_ttl=None,
    ):
        self.model = keras.models.load_model(model_path)

        hmm = np.load(hmm_params_path, allow_pickle=True)
        self.transition_matrix = hmm["transition_matrix"]
        self.initial_probs = hmm["initial_probs"]

        # Load temperature scaling calibration if available
        self.temperature = 1.0
        if calib_params_path and os.path.exists(calib_params_path):
            try:
                with open(calib_params_path, "r") as f:
                    calib_data = json.load(f)
                    self.temperature = float(calib_data.get("temperature", 1.0))
                    print(f"Loaded confidence calibration: Temperature T={self.temperature:.3f}")
            except Exception as e:
                print(f"Warning: Could not load calibration params: {e}")

        # Initialize Admin Alert Dispatcher
        self.dispatcher = AdminAlertDispatcher() if enable_admin_alerts else None

        self.max_len = max_len
        self.sessions = {}  # session_id -> _SessionState

        eps = 1e-12
        self.log_transition = np.log(self.transition_matrix + eps)
        self.log_initial = np.log(self.initial_probs + eps)

    def _get_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = _SessionState(NUM_STAGES)
        return self.sessions[session_id]

    def _predict_emission(self, feature_window):
        """Run the LSTM on the current sliding window -> calibrated (num_states,) probs."""
        pad_count = self.max_len - len(feature_window)
        padded = [[PAD_VALUE] * len(FEATURE_KEYS)] * pad_count + feature_window
        batch = np.array([padded], dtype=np.float32)
        probs = self.model.predict(batch, verbose=0)[0]

        # Apply temperature calibration if T != 1.0
        if abs(self.temperature - 1.0) > 1e-3:
            eps = 1e-12
            logits = np.log(np.clip(probs, eps, 1.0 - eps))
            scaled = logits / self.temperature
            exp_s = np.exp(scaled - np.max(scaled))
            probs = exp_s / np.sum(exp_s)

        return probs

    def observe(self, session_id, request_data, response_data):
        state = self._get_session(session_id)
        state.request_count += 1

        features = state.tracker.compute(request_data, response_data)
        vector = vectorize(features)

        state.feature_window.append(vector)
        if len(state.feature_window) > self.max_len:
            state.feature_window = state.feature_window[-self.max_len:]

        emission_probs = self._predict_emission(state.feature_window)
        log_emission = np.log(emission_probs + 1e-12)

        # --- incremental (online) Viterbi step ---
        if state.log_prob is None:
            state.log_prob = self.log_initial + log_emission
        else:
            scores = state.log_prob[:, None] + self.log_transition  # (from, to)
            state.log_prob = scores.max(axis=0) + log_emission

        smoothed_stage_idx = int(np.argmax(state.log_prob))
        lstm_stage_idx = int(np.argmax(emission_probs))

        smoothed_stage = STAGES[smoothed_stage_idx]
        lstm_stage = STAGES[lstm_stage_idx]

        new_rank = SEVERITY_RANK[smoothed_stage]
        escalated = new_rank > state.last_stage_rank
        state.last_stage_rank = max(state.last_stage_rank, new_rank)

        result = PredictionResult(
            session_id=session_id,
            request_number=state.request_count,
            stage=smoothed_stage,
            confidence=float(emission_probs[smoothed_stage_idx]),
            lstm_stage=lstm_stage,
            escalated=escalated,
            full_probs={s: float(p) for s, p in zip(STAGES, emission_probs)},
        )

        # Dispatch real-time admin alert on malicious behavior or escalation
        if self.dispatcher:
            result.alert = self.dispatcher.process_prediction(
                result, request_data, response_data
            )

        return result

    def reset_session(self, session_id):
        """Call when a session ends (logout, long idle timeout, etc.)."""
        self.sessions.pop(session_id, None)

    def active_session_count(self):
        return len(self.sessions)
