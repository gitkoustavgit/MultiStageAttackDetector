"""
Online multi-stage predictor -- the deployable inference path.

Fixes the deployment gaps the audit found in the old live_predictor:
  * It deploys the model that was actually benchmarked: the LSTM+XGBoost ensemble
    smoothed by the causal HMM forward filter, not the LSTM alone.
  * Smoothing is the SAME causal forward filter that was scored, with the same
    validation-selected strength -- no offline Viterbi that peeks at the future.
  * Sessions expire: a TTL evicts idle sessions so state does not grow without bound.
  * The alert threshold actually gates. Severity is compared to a configured minimum
    and that is the only gate; there is no `or is_attack` clause silently overriding it.
  * The predicted stage can go DOWN as well as up, because the forward filter and the
    features both allow de-escalation. Escalation is derived per step, not latched.

One SessionFeatureExtractor per session guarantees training/inference feature parity.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

import glob

from .features import RequestView, SessionFeatureExtractor
from .models import (
    NUM_STAGES,
    build_lstm,
    ensemble_emissions,
    next_distinct_matrix,
    temper_transitions,
)

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
SEVERITY = {"NORMAL": "INFO", "RECON": "LOW", "FUZZING": "WARNING",
            "INJECTION": "CRITICAL", "EXPLOITATION": "CRITICAL"}
SEV_RANK = {"INFO": 0, "LOW": 1, "WARNING": 2, "CRITICAL": 3}


@dataclass
class Prediction:
    session_id: str
    request_number: int
    stage: str                 # causal forward-filter argmax at this step (CURRENT stage)
    confidence: float          # filtered posterior of `stage`
    raw_stage: str             # ensemble emission argmax (pre-smoothing), for comparison
    escalated: bool            # severity rose vs the previous step
    posterior: Dict[str, float]        # P(current stage | requests so far)
    next_stage: str = ""               # most likely NEXT stage
    next_posterior: Dict[str, float] = field(default_factory=dict)  # P(next stage | so far)
    alert: Optional[dict] = None


@dataclass
class _State:
    extractor: SessionFeatureExtractor
    alpha: Optional[np.ndarray] = None      # running forward-filter belief
    count: int = 0
    prev_rank: int = 0
    last_seen: float = field(default_factory=time.time)


class OnlinePredictor:
    def __init__(self, artifact_dir: str = ".", min_alert_severity: str = "WARNING",
                 session_ttl_seconds: Optional[float] = 1800.0):
        self.min_alert_severity = min_alert_severity
        self.session_ttl = session_ttl_seconds

        arch = json.load(open(f"{artifact_dir}/lstm_v2.arch.json"))
        self.lstm_models = []
        for path in sorted(glob.glob(f"{artifact_dir}/lstm_v2.seed*.weights.h5")):
            m = build_lstm(**arch); m.load_weights(path); self.lstm_models.append(m)
        if not self.lstm_models:
            m = build_lstm(**arch); m.load_weights(f"{artifact_dir}/lstm_v2.weights.h5")
            self.lstm_models = [m]

        import xgboost as xgb
        self.xgb = xgb.XGBClassifier()
        self.xgb.load_model(f"{artifact_dir}/xgb_v2.json")

        self.alpha = json.load(open(f"{artifact_dir}/fusion_v2.json")).get("alpha", 0.5)

        hmm = np.load(f"{artifact_dir}/hmm_v2.npz", allow_pickle=True)  # own artifact
        lam = float(hmm["smoothing_lambda"][0]) if "smoothing_lambda" in hmm else 0.0
        self.A = temper_transitions(hmm["transition_matrix"], lam)
        self.pi = hmm["initial_probs"]
        # P(next distinct stage | current) for the "where will they go next" forecast
        self.B = next_distinct_matrix(hmm["transition_matrix"])

        self.temperature = json.load(open(f"{artifact_dir}/calib_v2.json"))["temperature"]
        self.sessions: Dict[str, _State] = {}
        # Persist the LSTM hidden state per session by replaying the feature window.
        self._windows: Dict[str, List[List[float]]] = {}

    def _emission(self, session_id: str, feature_row: List[float]) -> np.ndarray:
        """Calibrated ensemble emission for the current request, via the ONE shared fusion
        path (seed-averaged LSTM over the session so far + XGBoost on this row, blended by
        the validation-tuned alpha). Returns the emission for the latest timestep."""
        window = self._windows.setdefault(session_id, [])
        window.append(feature_row)
        feats = np.asarray(window, dtype=np.float32)
        return ensemble_emissions(self.lstm_models, self.xgb, feats,
                                  self.alpha, self.temperature)[-1]

    def observe(self, session_id: str, request: RequestView) -> Prediction:
        self._expire(request_time=time.time())
        state = self.sessions.get(session_id)
        if state is None:
            state = _State(extractor=SessionFeatureExtractor())
            self.sessions[session_id] = state
        state.count += 1
        state.last_seen = time.time()

        feature_row = state.extractor.feed(request)
        emission = self._emission(session_id, feature_row)

        # causal forward-filter update
        if state.alpha is None:
            alpha = self.pi * (emission + 1e-12)
        else:
            alpha = (emission + 1e-12) * (state.alpha @ self.A)
        alpha /= alpha.sum()
        state.alpha = alpha

        stage_idx = int(alpha.argmax())
        stage = STAGES[stage_idx]
        raw_stage = STAGES[int(emission.argmax())]

        # NEXT-STAGE forecast: where will this user go WHEN they change phase? Propagate
        # the current-stage belief through the self-loop-removed transition matrix. This
        # answers "where can this user go next" -- the next distinct stage -- rather than
        # the near-useless "the next request is probably the same stage".
        next_dist = alpha @ self.B
        s = next_dist.sum()
        next_dist = next_dist / s if s > 0 else next_dist
        next_idx = int(next_dist.argmax())

        rank = SEV_RANK[SEVERITY[stage]]
        escalated = rank > state.prev_rank
        state.prev_rank = rank

        pred = Prediction(
            session_id=session_id,
            request_number=state.count,
            stage=stage,
            confidence=float(alpha[stage_idx]),
            raw_stage=raw_stage,
            escalated=escalated,
            posterior={s: float(p) for s, p in zip(STAGES, alpha)},
            next_stage=STAGES[next_idx],
            next_posterior={s: float(p) for s, p in zip(STAGES, next_dist)},
        )
        pred.alert = self._maybe_alert(pred, request)
        return pred

    def _maybe_alert(self, pred: Prediction, request: RequestView) -> Optional[dict]:
        severity = SEVERITY[pred.stage]
        # The ONLY gate: severity meets the configured minimum. No override clause.
        if SEV_RANK[severity] < SEV_RANK[self.min_alert_severity]:
            return None
        return {
            "severity": severity,
            "stage": pred.stage,
            "confidence": round(pred.confidence, 4),
            "escalated": pred.escalated,
            "method": request.method,
            "path": request.path,
            "query": request.query,
            "recommended_action": {
                "LOW": "Track reconnaissance; watch endpoint probe frequency.",
                "WARNING": "Anomalous probing; rate-limit or challenge the client.",
                "CRITICAL": "Active injection/exploitation; isolate the session and review.",
            }.get(severity, "Investigate."),
        }

    def _expire(self, request_time: float):
        if self.session_ttl is None:
            return
        dead = [sid for sid, st in self.sessions.items()
                if request_time - st.last_seen > self.session_ttl]
        for sid in dead:
            self.sessions.pop(sid, None)
            self._windows.pop(sid, None)

    def reset_session(self, session_id: str):
        self.sessions.pop(session_id, None)
        self._windows.pop(session_id, None)

    def active_sessions(self) -> int:
        return len(self.sessions)
