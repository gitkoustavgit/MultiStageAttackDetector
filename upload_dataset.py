import os
import re
import json
import random
import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qsl, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from pymongo import MongoClient, UpdateOne
from pymongo.errors import ConfigurationError, ServerSelectionTimeoutError


# ============================================================
# CONFIG
# ============================================================

BASE_URL = "http://localhost:9000"

# MongoDB connection:
# PowerShell:
# $env:MONGO_URI="mongodb+srv://..."
#
# IMPORTANT: if you keep hitting
# "dns.resolver.LifetimeTimeout" / "ConfigurationError",
# your network is blocking the DNS SRV lookup that
# mongodb+srv:// requires. Switch to the STANDARD
# (non-SRV) connection string instead - in Atlas:
# Connect -> Drivers -> "..." / "View full driver example"
# usually has a toggle, or manually build it as:
#   mongodb://user:pass@shard-00-00.xxxxx.mongodb.net:27017,
#            shard-00-01.xxxxx.mongodb.net:27017,
#            shard-00-02.xxxxx.mongodb.net:27017/
#            ?ssl=true&replicaSet=atlas-xxxxxx-shard-0
#            &authSource=admin&retryWrites=true&w=majority
# That string needs no DNS SRV resolution at all.
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

DATABASE_NAME = "AttackDetection"

# New collections. Existing collections are untouched.
RAW_COLLECTION = "generated_http_sessions"
WINDOW_COLLECTION = "generated_training_windows"

RANDOM_SEED = 20260905
random.seed(RANDOM_SEED)

# Exactly 100 sessions for EACH target phase.
SESSIONS_PER_PHASE = 100

# Maximum context given to one LSTM training window.
MAX_CONTEXT_REQUESTS = 20

# Only local Juice Shop is allowed.
ALLOWED_HOST = "localhost"
ALLOWED_PORT = 9000

# Concurrency for local session generation (safe against
# localhost; does not affect determinism of counts/labels,
# only wall-clock time).
SESSION_WORKERS = 8

# Mongo connection retry policy.
MONGO_CONNECT_RETRIES = 3
MONGO_CONNECT_BACKOFF_SECONDS = 3

PHASES = [
    "NORMAL",
    "RECON",
    "FUZZING",
    "INJECTION",
    "EXPLOITATION",
]

STAGE_INDEX = {
    "NORMAL": 0,
    "RECON": 1,
    "FUZZING": 2,
    "INJECTION": 3,
    "EXPLOITATION": 4,
}


# ============================================================
# SECURITY / LAB CHECK
# ============================================================

def validate_local_url(url):
    parsed = urlsplit(url)

    if parsed.hostname != ALLOWED_HOST:
        raise RuntimeError(f"Blocked non-local target: {url}")

    if parsed.port not in (None, ALLOWED_PORT):
        raise RuntimeError(f"Blocked non-local port: {url}")


# ============================================================
# REQUEST COUNTS
# ============================================================
#
# 100 sessions per phase.
# Total = exactly 2,000 target requests per phase.
#
# Variable target-block sizes:
#     20 sessions x  5 requests = 100  (thin-context, rapid transitions)
#     20 sessions x 10 requests = 200
#     20 sessions x 15 requests = 300
#     20 sessions x 25 requests = 500
#     20 sessions x 45 requests = 900
#
# Total = 2,000 target requests/phase.
# ============================================================

def target_block_lengths():
    lengths = [5] * 20 + [10] * 20 + [15] * 20 + [25] * 20 + [45] * 20
    random.shuffle(lengths)
    assert len(lengths) == 100
    assert sum(lengths) == 2000
    return lengths


# ============================================================
# HTTP HELPERS
# ============================================================

def request(session, method, path, stage, params=None, json_body=None, headers=None):
    """Execute one request against local Juice Shop."""

    url = BASE_URL + path
    validate_local_url(url)

    req_headers = {
        "User-Agent": "MultiStageDatasetGenerator/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    if headers:
        req_headers.update(headers)

    started = datetime.now(timezone.utc)

    try:
        response = session.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            headers=req_headers,
            timeout=10,
        )

        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        final_url = response.url
        validate_local_url(final_url)

        return {
            "timestamp": started.isoformat(),
            "request": {
                "method": method,
                "url": final_url,
                "path": urlsplit(final_url).path or "/",
                "query": urlsplit(final_url).query,
                "headers": safe_headers(req_headers),
                "body": json.dumps(json_body) if json_body is not None else "",
            },
            "response": {
                "status": response.status_code,
                "length": len(response.content),
                "mime_type": response.headers.get("Content-Type", "Unknown"),
            },
            "stage_label": stage,
            "response_time_ms": round(elapsed * 1000, 3),
            "response_preview": response.text[:500],
        }

    except requests.RequestException as exc:
        return {
            "timestamp": started.isoformat(),
            "request": {
                "method": method,
                "url": url,
                "path": path,
                "query": "",
                "headers": safe_headers(req_headers),
                "body": json.dumps(json_body) if json_body is not None else "",
            },
            "response": {"status": 0, "length": 0, "mime_type": "ERROR"},
            "stage_label": stage,
            "response_time_ms": 0,
            "response_preview": str(exc),
        }


def safe_headers(headers):
    """Do not store session cookies or authorization tokens in the ML database."""

    sensitive = {"authorization", "cookie", "set-cookie", "x-auth-token", "x-access-token"}
    result = {}
    for key, value in headers.items():
        result[key] = "[REDACTED]" if key.lower() in sensitive else value
    return result


# ============================================================
# FEATURES
# ============================================================

# Precompiled once instead of re-compiling on every regex_hit()
# call (this was previously happening for every request in every
# context window - up to 20x per window x 10,000 windows).
SQLI_PATTERNS = [
    re.compile(r"'\s*or\s+1\s*=\s*1", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\band\s+1\s*=\s*1\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\binformation_schema\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"--", re.IGNORECASE | re.DOTALL),
]

XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript:", re.IGNORECASE | re.DOTALL),
    re.compile(r"onerror\s*=", re.IGNORECASE | re.DOTALL),
    re.compile(r"onload\s*=", re.IGNORECASE | re.DOTALL),
]

# NOTE: there is intentionally NO fixed word list here (no "test",
# "abc", "xyz", "null", etc.). A hardcoded vocabulary leaks labels:
# the same literal value ("test") gets used by the RECON generator
# AND the FUZZING generator, so matching on the word itself teaches
# the model "test" -> FUZZING regardless of the true label. Fuzzing
# is instead detected from two label-independent structural signals,
# computed below:
#   1. boundary_value_indicator - is THIS value, on its own, a
#      numeric edge case (negative, zero, or very large) or empty?
#      This needs no session history and catches obvious probes
#      like -1, 0, 999999 without caring what word/number it is.
#   2. endpoint_probe_diversity - across the ordered requests seen
#      so far IN THIS SESSION, how many distinct values has this
#      exact endpoint template been probed with? Real fuzzing shows
#      up as many different values hitting the same endpoint in
#      sequence (numeric OR word payloads) - that repetition-with-
#      variation is the actual behavioral signature, not any single
#      magic value. This is filled in by apply_sequential_features()
#      after a session's requests are enriched, since it requires
#      seeing prior requests in order.

BOUNDARY_NUMERIC_LOW = 0        # <= this is a boundary probe
BOUNDARY_NUMERIC_HIGH = 500     # >= this is a boundary probe
ENDPOINT_DIVERSITY_THRESHOLD = 2  # 3rd+ distinct value tried = fuzzing


def regex_hit(compiled_patterns, text):
    for pattern in compiled_patterns:
        if pattern.search(text):
            return 1
    return 0


def normalize_path_template(path):
    """
    Collapse a trailing numeric path segment into a template so
    /api/Products/17, /api/Products/999999, /api/Products/-1 are
    all recognized as probes against the SAME endpoint template
    (/api/Products/{id}) rather than treated as unrelated paths.
    """
    segments = [p for p in path.split("/") if p]
    if segments and re.fullmatch(r"-?\d+", segments[-1]):
        segments[-1] = "{id}"
    return "/" + "/".join(segments)


def extract_probe_value(path, params):
    """
    Return the single value being varied for this request, used to
    track endpoint-probing diversity. Prefers the first query-param
    value; falls back to a trailing numeric path segment.
    """
    if params:
        return unquote_plus(params[0][1])

    segments = [p for p in path.split("/") if p]
    if segments and re.fullmatch(r"-?\d+", segments[-1]):
        return segments[-1]

    return None


def is_boundary_value(value):
    """Numeric edge case (<=0 or >=500) or an empty value."""
    if value is None:
        return False
    if value == "":
        return True
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    return number <= BOUNDARY_NUMERIC_LOW or number >= BOUNDARY_NUMERIC_HIGH


def build_features(record):
    request_data = record["request"]
    response_data = record["response"]

    path = request_data["path"] or "/"
    query = request_data["query"] or ""
    body = request_data["body"] or ""

    decoded_query = unquote_plus(query)
    combined = f"{path} {query} {decoded_query} {body}"

    params = parse_qsl(query, keep_blank_values=True)

    lower_path = path.lower()

    admin_header = int(any(key.lower() == "x-user-email" for key in request_data["headers"]))
    auth_header = int(
        any(key.lower() in ("x-user-email", "authorization") for key in request_data["headers"])
    )
    admin_endpoint = int("/admin/" in lower_path or lower_path.endswith("/admin"))

    probe_value = extract_probe_value(path, params)
    boundary_hit = int(is_boundary_value(probe_value))

    return {
        "method_get": int(request_data["method"] == "GET"),
        "method_post": int(request_data["method"] == "POST"),
        "method_put": int(request_data["method"] == "PUT"),
        "method_delete": int(request_data["method"] == "DELETE"),
        "path_depth": len([p for p in path.split("/") if p]),
        "query_parameter_count": len(params),
        "query_length": len(query),
        "body_length": len(body),
        "payload_length": len(query + body),
        "sqli_indicator": regex_hit(SQLI_PATTERNS, combined),
        "xss_indicator": regex_hit(XSS_PATTERNS, combined),
        # boundary_value_indicator: label-independent, single-request
        # structural signal (does NOT depend on endpoint_probe_diversity).
        "boundary_value_indicator": boundary_hit,
        # These two are placeholders filled in by
        # apply_sequential_features() once the full ordered session
        # is available; a single request in isolation cannot know
        # how many distinct values its endpoint has been probed with.
        "endpoint_probe_diversity": 0,
        "fuzzing_indicator": boundary_hit,
        "fuzz_value_count": boundary_hit,
        "admin_endpoint_indicator": admin_endpoint,
        "admin_header_indicator": admin_header,
        "auth_bypass_header_indicator": auth_header,
        "authentication_endpoint_indicator": int(
            any(x in lower_path for x in ("/login", "/logout", "/whoami", "/authenticate"))
        ),
        "search_endpoint_indicator": int("search" in lower_path),
        "api_endpoint_indicator": int(
            lower_path.startswith("/api/") or lower_path.startswith("/rest/")
        ),
        "response_status": response_data["status"],
        "response_length": response_data["length"],
    }


def apply_sequential_features(enriched_records):
    """
    Second pass over ONE session's enriched requests, in order.
    Tracks, per normalized endpoint template, the distinct probe
    values seen so far this session, and finalizes:
      - endpoint_probe_diversity: distinct prior values tried
        against this endpoint (BEFORE this request)
      - fuzzing_indicator: boundary_value_indicator OR
        endpoint_probe_diversity >= ENDPOINT_DIVERSITY_THRESHOLD
      - fuzz_value_count: reused to carry endpoint_probe_diversity
        (kept for schema continuity with earlier versions)
    This is what actually captures "10 isn't a magic fuzz value in
    isolation, but the 4th different product ID tried in a row is
    fuzzing behavior" - variation across requests, not a fixed list.
    """
    endpoint_history = defaultdict(list)

    for item in enriched_records:
        request_data = item["request"]
        path = request_data["path"] or "/"
        params = parse_qsl(request_data["query"] or "", keep_blank_values=True)

        template = normalize_path_template(path)
        probe_value = extract_probe_value(path, params)

        prior_values = endpoint_history[template]
        diversity = len(set(prior_values))

        features = item["features"]
        features["endpoint_probe_diversity"] = diversity
        features["fuzzing_indicator"] = int(
            bool(features["boundary_value_indicator"])
            or diversity >= ENDPOINT_DIVERSITY_THRESHOLD
        )
        features["fuzz_value_count"] = diversity

        if probe_value is not None:
            endpoint_history[template].append(probe_value)

    return enriched_records


# ============================================================
# STAGE BLOCK GENERATORS
# ============================================================

def normal_block(session, count):
    actions = [
        ("GET", "/", {}),
        ("GET", "/rest/products/search", {"q": "apple"}),
        ("GET", "/rest/products/search", {"q": "banana"}),
        ("GET", "/rest/products/search", {"q": "juice"}),
        ("GET", "/api/Products/1", None),
        ("GET", "/api/Products/2", None),
        ("GET", "/rest/languages", None),
    ]
    records = []
    for _ in range(count):
        method, path, params = random.choice(actions)
        records.append(request(session, method, path, "NORMAL", params=params))
    return records


def recon_block(session, count):
    actions = [
        ("GET", "/api/Challenges/", None),
        ("GET", "/api/Feedbacks/", None),
        ("GET", "/api/Quantitys/", None),
        ("GET", "/rest/languages", None),
        ("GET", "/rest/user/whoami", None),
        ("GET", "/ftp/", None),
        ("GET", "/rest/products/search", {"q": "test"}),
    ]
    records = []
    for _ in range(count):
        method, path, params = random.choice(actions)
        records.append(request(session, method, path, "RECON", params=params))
    return records


def fuzzing_block(session, count):
    search_values = [
        "", "0", "-1", "-999", "999", "999999", "abc", "xyz", "test",
        "null", "undefined", "value1", "value2", "value3", "nonexistent",
    ]
    product_ids = ["-1", "0", "1", "2", "3", "10", "50", "99", "999", "999999"]

    actions = [("GET", "/rest/products/search", {"q": value}) for value in search_values]
    actions += [("GET", f"/api/Products/{value}", None) for value in product_ids]

    records = []
    for _ in range(count):
        method, path, params = random.choice(actions)
        records.append(request(session, method, path, "FUZZING", params=params))
    return records


def injection_block(session, count):
    sqli_payloads = [
        "apple'",
        "apple'))",
        "apple')) OR 1=1--",
        "apple' AND 1=0--",
        "apple')) UNION SELECT 1,2,3,4--",
        "apple')) UNION SELECT id,email,password,4 FROM Users--",
    ]
    xss_payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "\"><svg/onload=alert(1)>",
        "apple<script>alert(1)</script>",
        "test' onerror=alert(1)--",
    ]
    actions = [("GET", "/rest/products/search", {"q": payload}) for payload in sqli_payloads + xss_payloads]

    records = []
    for _ in range(count):
        method, path, params = random.choice(actions)
        records.append(request(session, method, path, "INJECTION", params=params))
    return records


def exploitation_block(session, count):
    """
    Read-only privilege-abuse actions against the intentionally
    vulnerable local Juice Shop. No state-changing user/account
    creation is performed.

    Deliberately spread across several DISTINCT techniques and
    endpoints, with header presence/value varied (including many
    requests with NO special header at all). A single repeated
    signature (one header value on every request) would let the
    model shortcut-learn "this exact header = EXPLOITATION" instead
    of learning the contextual progression that actually defines
    the stage.
    """

    # Technique 1: forced browsing straight to admin endpoints with
    # no auth-bypass header at all - just probing for an exposed
    # misconfigured route.
    forced_browsing_actions = [
        ("GET", "/rest/admin/application-configuration", None),
        ("GET", "/rest/admin/application-version", None),
    ]

    # Technique 2: forged-identity header attacks, varied payload
    # style each time (not one fixed string).
    auth_bypass_payloads = [
        "admin@juice-sh.op'--",
        "admin@juice-sh.op' OR '1'='1",
        "' OR 1=1--",
        "admin@juice-sh.op\"--",
        "administrator@juice-sh.op'#",
    ]
    auth_bypass_actions = [
        (
            "GET",
            random.choice(["/rest/admin/application-configuration", "/rest/admin/application-version"]),
            {"X-User-Email": payload},
        )
        for payload in auth_bypass_payloads
    ]

    # Technique 3: forged/malformed bearer token (alg=none JWT style
    # bypass attempt) against a protected endpoint.
    jwt_bypass_actions = [
        (
            "GET",
            "/rest/admin/application-configuration",
            {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
        ),
        (
            "GET",
            "/rest/admin/application-version",
            {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
        ),
    ]

    # Technique 4: IDOR - direct, unauthorized access to other
    # users'/other IDs' resources by enumerating numeric IDs, no
    # special header needed (this is the classic "just change the
    # ID in the URL" privilege-abuse pattern).
    idor_actions = [
        ("GET", f"/api/Users/{uid}", None)
        for uid in ("1", "2", "3", "5", "10")
    ] + [
        ("GET", f"/rest/basket/{bid}", None)
        for bid in ("1", "2", "3", "4")
    ]

    weighted_actions = (
        forced_browsing_actions * 2
        + auth_bypass_actions * 2
        + jwt_bypass_actions
        + idor_actions * 2
    )

    records = []
    for _ in range(count):
        method, path, headers = random.choice(weighted_actions)
        records.append(request(session, method, path, "EXPLOITATION", headers=headers))
    return records


BLOCK_FUNCTIONS = {
    "NORMAL": normal_block,
    "RECON": recon_block,
    "FUZZING": fuzzing_block,
    "INJECTION": injection_block,
    "EXPLOITATION": exploitation_block,
}

PREVIOUS_STAGES = {
    "NORMAL": [],
    "RECON": ["NORMAL"],
    "FUZZING": ["NORMAL", "RECON"],
    "INJECTION": ["NORMAL", "RECON", "FUZZING"],
    "EXPLOITATION": ["NORMAL", "RECON", "FUZZING", "INJECTION"],
}


def choose_prefix(target_stage):
    available = PREVIOUS_STAGES[target_stage]
    if not available:
        return []

    # Around 35% single-stage final target.
    roll = random.random()
    if roll < 0.35:
        return []

    number_of_blocks = random.randint(1, min(4, max(1, len(available) + 1)))
    return [random.choice(available) for _ in range(number_of_blocks)]


# ============================================================
# SESSION GENERATION
# ============================================================

def generate_session(target_stage, session_index, target_length):
    session_id = f"GEN_{target_stage}_{session_index:03d}"
    session = requests.Session()

    all_requests = []
    prefix_stages = choose_prefix(target_stage)

    for prefix_stage in prefix_stages:
        block_size = random.randint(1, 6)
        block_function = BLOCK_FUNCTIONS[prefix_stage]
        all_requests.extend(block_function(session, block_size))

    target_function = BLOCK_FUNCTIONS[target_stage]
    target_records = target_function(session, target_length)

    for record in target_records:
        record["target_request"] = True
        record["target_stage"] = target_stage

    all_requests.extend(target_records)

    for record in all_requests:
        if "target_request" not in record:
            record["target_request"] = False
            record["target_stage"] = target_stage

    session.close()

    return {
        "session_id": session_id,
        "target_stage": target_stage,
        "target_stage_index": STAGE_INDEX[target_stage],
        "prefix_stages": prefix_stages,
        "requests": all_requests,
    }


# ============================================================
# FEATURES + FINGERPRINT
# ============================================================

def enrich_request(record, session_id, request_number):
    record = dict(record)
    record["request_number"] = request_number
    record["session_id"] = session_id
    record["stage_index"] = STAGE_INDEX[record["stage_label"]]
    record["is_attack"] = int(record["stage_label"] != "NORMAL")
    record["features"] = build_features(record)

    signature = (
        record["request"]["method"] + "|"
        + record["request"]["path"] + "|"
        + record["request"]["query"] + "|"
        + record["request"]["body"] + "|"
        + str(record["response"]["status"])
    )
    record["request_fingerprint"] = hashlib.sha256(signature.encode()).hexdigest()

    return record


def build_windows(session):
    enriched = [
        enrich_request(record, session["session_id"], number)
        for number, record in enumerate(session["requests"], start=1)
    ]

    # Second pass: needs the full ordered session to compute
    # cross-request probe diversity (see apply_sequential_features).
    enriched = apply_sequential_features(enriched)

    windows = []
    target_block_step = 0

    for index, current in enumerate(enriched):
        if not current["target_request"]:
            continue
        target_block_step += 1

        start = max(0, index - MAX_CONTEXT_REQUESTS + 1)
        context_records = enriched[start:index + 1]

        sequence = []
        for item in context_records:
            sequence.append({
                "request_number": item["request_number"],
                "stage_label": item["stage_label"],
                "stage_index": item["stage_index"],
                "method": item["request"]["method"],
                "path": item["request"]["path"],
                "query": item["request"]["query"],
                "body_length": len(item["request"]["body"]),
                "response_status": item["response"]["status"],
                "response_length": item["response"]["length"],
                "features": item["features"],
            })

        context_stages = []
        for item in sequence:
            stage = item["stage_label"]
            if not context_stages or context_stages[-1] != stage:
                context_stages.append(stage)

        window_id = f'{session["session_id"]}_TARGET_{current["request_number"]}'

        windows.append({
            "_id": window_id,
            "window_id": window_id,
            "session_id": session["session_id"],
            "target_stage": current["stage_label"],
            "target_stage_index": current["stage_index"],
            "target_request_number": current["request_number"],
            "target_block_step": target_block_step,
            "is_thin_context": bool(target_block_step <= 3),
            "sequence_length": len(sequence),
            "context_stage_sequence": context_stages,
            "sequence": sequence,
            "target_features": current["features"],
            "split": session["split"],
            "generated": True,
            "generator_version": "1.0",
        })

    return enriched, windows


def get_split(session_index):
    # 70 / 15 / 15
    if session_index <= 70:
        return "train"
    if session_index <= 85:
        return "validation"
    return "test"


# ============================================================
# MONGODB UPLOAD
# ============================================================

def upload_collection(collection, documents):
    if not documents:
        return

    operations = [
        UpdateOne({"_id": document["_id"]}, {"$set": document}, upsert=True)
        for document in documents
    ]

    batch_size = 500
    for start in range(0, len(operations), batch_size):
        collection.bulk_write(operations[start:start + batch_size], ordered=False)


def connect_mongo(uri):
    """
    Connect with retries. Gives an actionable error message if
    the failure is the SRV-DNS-resolution problem specifically,
    instead of just dumping the raw dnspython traceback.
    """
    last_exc = None

    for attempt in range(1, MONGO_CONNECT_RETRIES + 1):
        try:
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
            )
            client.admin.command("ping")
            return client

        except (ConfigurationError, ServerSelectionTimeoutError) as exc:
            last_exc = exc
            print(
                f"  Mongo connection attempt {attempt}/{MONGO_CONNECT_RETRIES} "
                f"failed: {type(exc).__name__}"
            )
            if attempt < MONGO_CONNECT_RETRIES:
                time.sleep(MONGO_CONNECT_BACKOFF_SECONDS * attempt)

    is_srv_dns_issue = uri.startswith("mongodb+srv://") and (
        "resolver" in str(last_exc).lower() or "srv" in str(last_exc).lower()
        or isinstance(last_exc, ConfigurationError)
    )

    if is_srv_dns_issue:
        raise RuntimeError(
            "\nCould not connect to MongoDB after "
            f"{MONGO_CONNECT_RETRIES} attempts.\n\n"
            "This looks like a DNS SRV-lookup failure, not a credentials "
            "problem: mongodb+srv:// URIs require a DNS query for a "
            "_mongodb._tcp SRV record, and your network/DNS resolver is "
            "not answering it (common on campus networks, VPNs, or "
            "restrictive routers that block UDP/53 SRV lookups).\n\n"
            "Fix: use the STANDARD (non-SRV) connection string instead - "
            "in Atlas: Database > Connect > Drivers, and look for the "
            "option to view the non-SRV string, or build it manually as:\n"
            "  mongodb://user:pass@shard-00-00.xxxxx.mongodb.net:27017,"
            "shard-00-01.xxxxx.mongodb.net:27017,"
            "shard-00-02.xxxxx.mongodb.net:27017/"
            "?ssl=true&replicaSet=<your-replica-set-name>"
            "&authSource=admin&retryWrites=true&w=majority\n\n"
            "Then set it the same way:\n"
            '  $env:MONGO_URI="mongodb://...standard-string..."\n\n'
            "Alternatively, try switching your network's DNS to "
            "8.8.8.8 / 1.1.1.1, or disable any VPN, and retry with the "
            "original mongodb+srv:// string.\n"
        ) from last_exc

    raise RuntimeError(
        f"\nCould not connect to MongoDB after {MONGO_CONNECT_RETRIES} "
        f"attempts: {last_exc}\n"
    ) from last_exc


# ============================================================
# SUMMARY
# ============================================================

def print_summary(raw_documents, windows):
    print()
    print("=" * 72)
    print("GENERATION SUMMARY")
    print("=" * 72)

    stage_counts = defaultdict(int)
    target_counts = defaultdict(int)
    window_counts = defaultdict(int)

    for document in raw_documents:
        stage_counts[document["stage_label"]] += 1
        if document["target_request"]:
            target_counts[document["target_stage"]] += 1

    for window in windows:
        window_counts[window["target_stage"]] += 1

    print(f"RAW SESSION REQUESTS: {len(raw_documents)}")
    print(f"TRAINING WINDOWS: {len(windows)}")
    print()

    print("TARGET WINDOWS PER PHASE:")
    for phase in PHASES:
        print(f"  {phase:15s}{window_counts[phase]:6d}")
    print()

    print("ALL LABELED REQUESTS:")
    for phase in PHASES:
        print(f"  {phase:15s}{stage_counts[phase]:6d}")
    print()

    print(
        "Each phase should have exactly "
        f"{SESSIONS_PER_PHASE * 20} target requests/windows."
    )
    print("=" * 72)


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 72)
    print("MULTI-STAGE JUICE SHOP DATASET GENERATOR")
    print("=" * 72)

    if not MONGO_URI:
        raise RuntimeError(
            "\nMONGO_URI is missing.\n\n"
            "PowerShell:\n"
            '$env:MONGO_URI="YOUR_MONGODB_URI"\n'
        )

    lengths = target_block_lengths()
    print("\nTarget block lengths:")
    print({length: lengths.count(length) for length in sorted(set(lengths))})
    assert sum(lengths) == 2000

    # --------------------------------------------------------
    # Connect MongoDB (with retry + actionable diagnostics).
    # --------------------------------------------------------

    print("\nConnecting to MongoDB...")
    client = connect_mongo(MONGO_URI)
    print("Connected.")

    db = client[DATABASE_NAME]
    raw_collection = db[RAW_COLLECTION]
    window_collection = db[WINDOW_COLLECTION]

    raw_collection.create_index([("session_id", 1), ("request_number", 1)], unique=True)
    raw_collection.create_index("stage_label")
    raw_collection.create_index("target_stage")
    window_collection.create_index("target_stage")
    window_collection.create_index("split")
    window_collection.create_index([("session_id", 1), ("target_request_number", 1)])

    # --------------------------------------------------------
    # Build the (target_stage, local_index, target_length) job list,
    # then generate sessions concurrently (safe: localhost only,
    # each session has its own isolated requests.Session).
    # --------------------------------------------------------

    jobs = []
    for target_stage in PHASES:
        lengths_for_phase = list(lengths)
        random.shuffle(lengths_for_phase)
        for local_index in range(1, SESSIONS_PER_PHASE + 1):
            jobs.append((target_stage, local_index, lengths_for_phase[local_index - 1]))

    all_raw_documents = []
    all_windows = []
    generated_sessions = {}  # keep for ordered printing

    print(f"\nGenerating {len(jobs)} sessions with {SESSION_WORKERS} workers...")

    def run_job(job):
        target_stage, local_index, target_length = job
        session = generate_session(target_stage, local_index, target_length)
        session["split"] = get_split(local_index)
        enriched, windows = build_windows(session)
        return session, enriched, windows

    with ThreadPoolExecutor(max_workers=SESSION_WORKERS) as pool:
        futures = {pool.submit(run_job, job): job for job in jobs}

        for future in as_completed(futures):
            session, enriched, windows = future.result()
            target_stage = session["target_stage"]

            for request_record in enriched:
                request_record["target_session_stage"] = target_stage
                request_record["session_split"] = session["split"]
                request_record["source"] = {
                    "generated": True,
                    "generator_version": "1.0",
                    "generator_seed": RANDOM_SEED,
                    "session_type": "synthetic_local_juice_shop",
                }
                request_record["_id"] = (
                    session["session_id"] + "_" + str(request_record["request_number"])
                )
                all_raw_documents.append(request_record)

            for window in windows:
                window["target_session_stage"] = target_stage
                all_windows.append(window)

            generated_sessions[session["session_id"]] = session

            print(
                f"  {session['session_id']} | target requests={len(windows)} "
                f"| prefix={session['prefix_stages']} | split={session['split']}"
            )

    # --------------------------------------------------------
    # Verify exact balanced target counts.
    # --------------------------------------------------------

    target_counts = defaultdict(int)
    for document in all_raw_documents:
        if document["target_request"]:
            target_counts[document["target_stage"]] += 1

    for phase in PHASES:
        if target_counts[phase] != 2000:
            raise RuntimeError(
                f"{phase}: expected 2000 target requests, got {target_counts[phase]}"
            )

    unique_sessions = defaultdict(set)
    for window in all_windows:
        unique_sessions[window["target_session_stage"]].add(window["session_id"])

    for phase in PHASES:
        number_of_sessions = len(unique_sessions[phase])
        if number_of_sessions != SESSIONS_PER_PHASE:
            raise RuntimeError(
                f"{phase}: expected {SESSIONS_PER_PHASE} sessions, got {number_of_sessions}"
            )

    print_summary(all_raw_documents, all_windows)

    print()
    print("Clearing old generated collections before uploading fresh dataset...")
    raw_collection.delete_many({})
    window_collection.delete_many({})

    print("Uploading generated raw requests...")
    upload_collection(raw_collection, all_raw_documents)

    print("Uploading balanced target windows...")
    upload_collection(window_collection, all_windows)

    print()
    print("=" * 72)
    print("MONGODB COMPLETE")
    print("=" * 72)
    print(f"Database: {DATABASE_NAME}")
    print(f"Raw collection: {RAW_COLLECTION}")
    print(f"Training collection: {WINDOW_COLLECTION}")
    print(f"Raw documents: {raw_collection.count_documents({})}")
    print(f"Training windows: {window_collection.count_documents({})}")
    print()
    print("Existing collections NOT modified:")
    print("  http_payloads")
    print("  newSessions")
    print("  ml_http_requests")
    print()
    print("DONE.")


if __name__ == "__main__":
    main()