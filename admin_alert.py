"""
admin_alert.py

Real-Time Admin Alerting System for Multi-Stage Web Attack Detection.
Dispatches structured security alerts when malicious activity or stage escalation
is detected across in-progress HTTP sessions.
"""

import os
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Callable

ALERT_JSONL_PATH = "admin_alerts.jsonl"
TEXT_ALERT_LOG_PATH = "admin_alerts.log"

# Severity hierarchy for attack stages
STAGE_SEVERITY = {
    "NORMAL": "INFO",
    "RECON": "LOW",
    "FUZZING": "WARNING",
    "INJECTION": "CRITICAL",
    "EXPLOITATION": "CRITICAL",
}

SEVERITY_ACTIONS = {
    "INFO": "Log and continue monitoring session behavior.",
    "LOW": "Flag session for reconnaissance telemetry; track endpoint probe frequency.",
    "WARNING": "Anomalous fuzzing detected. Rate-limit IP / trigger WAF challenge.",
    "CRITICAL": "MALICIOUS INJECTION / EXPLOITATION DETECTED. Immediately terminate session and isolate client IP.",
}


@dataclass
class AdminAlert:
    alert_id: str
    timestamp: str
    session_id: str
    request_number: int
    severity: str
    detected_stage: str
    confidence: float
    escalated: bool
    method: str
    path: str
    query: str
    client_action_summary: str
    recommended_action: str
    details: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class AdminAlertDispatcher:
    """
    Central dispatcher that inspects incoming live prediction results
    and issues immediate alerts to administrators.
    """

    def __init__(
        self,
        alert_jsonl_path: str = ALERT_JSONL_PATH,
        alert_log_path: str = TEXT_ALERT_LOG_PATH,
        min_alert_severity: str = "WARNING",
        on_alert_callbacks: Optional[List[Callable[["AdminAlert"], None]]] = None,
    ):
        self.alert_jsonl_path = alert_jsonl_path
        self.alert_log_path = alert_log_path
        self.min_alert_severity = min_alert_severity
        self.callbacks = on_alert_callbacks or []
        self.alert_history: List[AdminAlert] = []
        self._rank = {"INFO": 0, "LOW": 1, "WARNING": 2, "CRITICAL": 3}

    def register_callback(self, callback: Callable[["AdminAlert"], None]):
        """Register a custom callback (e.g. webhook, Slack/Discord bot, email notifier)."""
        self.callbacks.append(callback)

    def process_prediction(
        self,
        prediction_result,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
    ) -> Optional[AdminAlert]:
        """
        Evaluates a prediction result and dispatches an alert if malicious
        activity or escalation meets the alert threshold.
        """
        stage = prediction_result.stage
        severity = STAGE_SEVERITY.get(stage, "INFO")
        escalated = prediction_result.escalated
        confidence = float(prediction_result.confidence)

        is_attack = stage in ("FUZZING", "INJECTION", "EXPLOITATION")
        should_alert = (
            self._rank.get(severity, 0) >= self._rank.get(self.min_alert_severity, 2)
            or (escalated and stage != "NORMAL")
            or is_attack
        )

        if not should_alert:
            return None

        alert_id = f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{prediction_result.session_id[-6:]}-{prediction_result.request_number}"
        action_summary = f"{request_data.get('method', 'GET')} {request_data.get('path', '/')} (Status: {response_data.get('status', 0)})"
        rec_action = SEVERITY_ACTIONS.get(severity, "Investigate session behavior.")

        alert = AdminAlert(
            alert_id=alert_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=prediction_result.session_id,
            request_number=prediction_result.request_number,
            severity=severity,
            detected_stage=stage,
            confidence=round(confidence, 4),
            escalated=escalated,
            method=request_data.get("method", "GET"),
            path=request_data.get("path", "/"),
            query=request_data.get("query", ""),
            client_action_summary=action_summary,
            recommended_action=rec_action,
            details={
                "lstm_stage": prediction_result.lstm_stage,
                "viterbi_stage": prediction_result.stage,
                "full_probabilities": getattr(prediction_result, "full_probs", {}),
                "response_length": response_data.get("length", 0),
                "response_status": response_data.get("status", 0),
            },
        )

        self._dispatch(alert)
        return alert

    def _dispatch(self, alert: AdminAlert):
        self.alert_history.append(alert)

        # 1. Console alert with high-visibility formatting
        border = "=" * 80
        if alert.severity == "CRITICAL":
            tag = ">>> [CRITICAL ADMIN ALERT - SECURITY INCIDENT] <<<"
        elif alert.severity == "WARNING":
            tag = ">>> [WARNING - ANOMALOUS BEHAVIOR DETECTED] <<<"
        else:
            tag = ">>> [INFO - SECURITY TELEMETRY EVENT] <<<"

        print(f"\n{border}")
        print(f"{tag}")
        print(f"Alert ID      : {alert.alert_id}")
        print(f"Timestamp     : {alert.timestamp}")
        print(f"Session ID    : {alert.session_id} (Req #{alert.request_number})")
        print(f"Attack Stage  : {alert.detected_stage} (Confidence: {alert.confidence * 100:.1f}%)")
        print(f"Escalation    : {'YES - Attack stage escalated!' if alert.escalated else 'No'}")
        print(f"Offending Req : {alert.client_action_summary}")
        if alert.query:
            print(f"Payload/Query : {alert.query[:120]}")
        print(f"Action Needed : {alert.recommended_action}")
        print(f"{border}\n")

        # 2. Append to JSONL structured audit log
        try:
            with open(self.alert_jsonl_path, "a", encoding="utf-8") as f:
                f.write(alert.to_json() + "\n")
        except Exception as e:
            print(f"Failed to write to JSONL alert log: {e}")

        # 3. Append to human-readable log
        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(
                    f"[{alert.timestamp}] [{alert.severity}] [Session: {alert.session_id}] "
                    f"Stage={alert.detected_stage} (Conf={alert.confidence:.3f}, Esc={alert.escalated}) "
                    f"Req={alert.method} {alert.path} Query={alert.query} -> Action: {alert.recommended_action}\n"
                )
        except Exception as e:
            print(f"Failed to write to text alert log: {e}")

        # 4. Invoke custom callbacks
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception as e:
                print(f"Error in alert callback {cb}: {e}")
