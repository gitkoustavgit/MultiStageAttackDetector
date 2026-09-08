"""
Live end-to-end demo: drive a scripted kill-chain against a local OWASP Juice Shop and
score each request online with the deployed ensemble + causal HMM predictor.

Unlike the old demo, response status and length are REAL (captured from the running
server), and the predictor is the full deployed model, not the LSTM alone. Only local
Juice Shop is allowed as a target.

    docker run -d -p 9000:3000 bkimminich/juice-shop
    python -m pipeline.live_demo
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

import requests

from .features import RequestView
from .predict import OnlinePredictor

BASE = "http://localhost:9000"
ALLOWED_HOST, ALLOWED_PORT = "localhost", 9000

# A realistic escalate-then-retreat session: browse, recon, fuzz, inject, exploit, then
# feign benign traffic. The retreat is exactly the shape the old always-escalating data
# never contained.
SCRIPT = [
    ("GET", "/", {}, {}),
    ("GET", "/rest/products/search", {"q": "apple"}, {}),
    ("GET", "/rest/user/whoami", {"fields": "email"}, {}),
    ("GET", "/rest/languages", {}, {}),
    ("GET", "/rest/products/search", {"q": "-1"}, {}),
    ("GET", "/rest/products/search", {"q": "999999"}, {}),
    ("GET", "/rest/products/search",
     {"q": "apple')) UNION SELECT id,email,password,4 FROM Users--"}, {}),
    ("GET", "/rest/products/search", {"q": "<script>alert(1)</script>"}, {}),
    ("GET", "/rest/admin/application-configuration", {}, {"X-User-Email": "admin@juice-sh.op'--"}),
    ("GET", "/api/Users/1", {}, {}),
    ("GET", "/rest/products/search", {"q": "banana"}, {}),
    ("GET", "/rest/products/search", {"q": "juice"}, {}),
]


def _check_local(url: str):
    u = urlsplit(url)
    if u.hostname != ALLOWED_HOST or u.port not in (None, ALLOWED_PORT):
        raise RuntimeError(f"blocked non-local target: {url}")


def main():
    predictor = OnlinePredictor(min_alert_severity="WARNING")
    session = requests.Session()
    print(f"{'req':<4}{'current stage':<14}{'-> likely next':<15}{'conf':<7}{'alert':<10}status/len")
    print("-" * 82)

    for i, (method, path, params, extra) in enumerate(SCRIPT):
        url = BASE + path
        _check_local(url)
        headers = {"User-Agent": "LiveDemo/2.0", "Accept": "application/json,text/plain,*/*", **extra}
        resp = session.request(method, url, params=params, headers=headers, timeout=10)
        _check_local(resp.url)
        final = urlsplit(resp.url)
        req = RequestView(
            method=method, path=final.path or "/", query=final.query, body="",
            headers=headers, status=resp.status_code, response_length=len(resp.content),
            epoch_seconds=time.time(),
        )
        r = predictor.observe("live_demo", req)
        alert = r.alert["severity"] if r.alert else "-"
        print(f"{r.request_number:<4}{r.stage:<14}{r.next_stage:<15}{r.confidence:<7.3f}"
              f"{alert:<10}{resp.status_code}/{len(resp.content)}")

    predictor.reset_session("live_demo")
    session.close()
    print("-" * 82)
    print("Current stage = responsive LSTM+XGBoost ensemble (tracks transitions sharply).")
    print("Likely next   = forecast from the causal HMM belief: where the user goes next.")
    print("Response status/len are real, captured from the running server.")


if __name__ == "__main__":
    main()
