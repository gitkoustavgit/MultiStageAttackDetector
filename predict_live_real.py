"""
Runnable demo for live_predictor.py that hits REAL local Juice Shop
for each request, so response_status/response_length are genuine
values instead of placeholders - those are 2 of the 23 trained
features, so fabricated numbers there can meaningfully distort
predictions.

Requires:
  - Juice Shop running on localhost:9000
  - lstm_stage_classifier.keras + hmm_params.npz in this folder
    (from train_models.py)

Run:
    python predict_live_real.py
"""

from urllib.parse import urlsplit

import requests

from live_predictor import LiveAttackPredictor

MODEL_PATH = "lstm_stage_classifier.keras"
HMM_PARAMS_PATH = "hmm_params.npz"

BASE_URL = "http://localhost:9000"
ALLOWED_HOST = "localhost"
ALLOWED_PORT = 9000


def validate_local_url(url):
    parsed = urlsplit(url)
    if parsed.hostname != ALLOWED_HOST or parsed.port not in (None, ALLOWED_PORT):
        raise RuntimeError(f"Blocked non-local target: {url}")


# (method, path, query_params dict, extra_headers) - covering the full kill chain
# (NORMAL -> RECON -> FUZZING -> INJECTION(SQLi) -> INJECTION(XSS) -> EXPLOITATION)
demo_requests = [
    ("GET", "/", {}, {}),
    ("GET", "/rest/products/search", {"q": "apple"}, {}),
    ("GET", "/rest/user/whoami", {}, {}),
    ("GET", "/rest/products/search", {"q": "-1"}, {}),
    ("GET", "/rest/products/search", {"q": "999999"}, {}),
    ("GET", "/rest/products/search",
     {"q": "apple')) UNION SELECT id,email,password,4 FROM Users--"}, {}),
    ("GET", "/rest/products/search",
     {"q": "<script>alert('XSS-Attack')</script>"}, {}),
    ("GET", "/rest/admin/application-configuration", {},
     {"X-User-Email": "admin@juice-sh.op'--"}),
]


def do_request(session, method, path, params, extra_headers):
    url = BASE_URL + path
    validate_local_url(url)

    headers = {
        "User-Agent": "LiveDemo/1.0",
        "Accept": "application/json,text/plain,*/*",
        **extra_headers,
    }

    response = session.request(method=method, url=url, params=params, headers=headers, timeout=10)
    validate_local_url(response.url)

    final = urlsplit(response.url)
    request_data = {
        "method": method,
        "path": final.path or "/",
        "query": final.query,
        "body": "",
        "headers": headers,
    }
    response_data = {
        "status": response.status_code,
        "length": len(response.content),
    }
    return request_data, response_data


def main():
    print("\n" + "=" * 95)
    print("LIVE MULTI-STAGE INJECTION ATTACK DETECTOR & REAL-TIME ADMIN ALERTING")
    print("=" * 95)

    predictor = LiveAttackPredictor(
        model_path=MODEL_PATH,
        hmm_params_path=HMM_PARAMS_PATH,
        calib_params_path="calibration_params.json",
        enable_admin_alerts=True,
    )
    session = requests.Session()

    print(f"{'req#':<5}{'lstm guess':<14}{'viterbi guess':<16}{'confidence':<12}{'escalated':<11}{'alert':<10}resp_status/len")
    print("-" * 95)

    alerts_triggered = []

    for method, path, params, extra_headers in demo_requests:
        request_data, response_data = do_request(session, method, path, params, extra_headers)

        result = predictor.observe(
            session_id="demo_session_real",
            request_data=request_data,
            response_data=response_data,
        )

        has_alert = "ALERT!" if result.alert else "None"
        if result.alert:
            alerts_triggered.append(result.alert)

        print(
            f"{result.request_number:<5}{result.lstm_stage:<14}"
            f"{result.stage:<16}{result.confidence:<12.3f}{str(result.escalated):<11}"
            f"{has_alert:<10}{response_data['status']}/{response_data['length']}"
        )

    predictor.reset_session("demo_session_real")
    session.close()

    print("-" * 95)
    print(f"Demo complete. Total Alerts Triggered & Logged to admin_alerts.jsonl: {len(alerts_triggered)}")


if __name__ == "__main__":
    main()
