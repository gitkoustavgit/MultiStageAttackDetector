"""
Single source of truth for feature computation. Both the dataset
generator (upload_dataset.py) and live inference (live_predictor.py)
import from here, so a request is ALWAYS turned into the same
23-number vector regardless of whether it came from synthetic
generation or a real live request. If this ever drifts between
training-time and inference-time code, the model's learned weights
become meaningless on live traffic - so there is exactly one
implementation, imported everywhere.
"""

import re
from urllib.parse import parse_qsl, unquote_plus

# ============================================================
# STAGES
# ============================================================

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}

# ============================================================
# PATTERNS (compiled once)
# ============================================================

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

BOUNDARY_NUMERIC_LOW = 0
BOUNDARY_NUMERIC_HIGH = 500
ENDPOINT_DIVERSITY_THRESHOLD = 2

# EXACT order used everywhere a feature vector is built - this list
# IS the schema. Do not reorder without retraining.
FEATURE_KEYS = [
    "method_get",
    "method_post",
    "method_put",
    "method_delete",
    "path_depth",
    "query_parameter_count",
    "query_length",
    "body_length",
    "payload_length",
    "sqli_indicator",
    "xss_indicator",
    "boundary_value_indicator",
    "endpoint_probe_diversity",
    "fuzzing_indicator",
    "fuzz_value_count",
    "admin_endpoint_indicator",
    "admin_header_indicator",
    "auth_bypass_header_indicator",
    "authentication_endpoint_indicator",
    "search_endpoint_indicator",
    "api_endpoint_indicator",
    "response_status",
    "response_length",
]


def regex_hit(compiled_patterns, text):
    for pattern in compiled_patterns:
        if pattern.search(text):
            return 1
    return 0


def normalize_path_template(path):
    segments = [p for p in path.split("/") if p]
    if segments and re.fullmatch(r"-?\d+", segments[-1]):
        segments[-1] = "{id}"
    return "/" + "/".join(segments)


def extract_probe_value(path, params):
    if params:
        return unquote_plus(params[0][1])
    segments = [p for p in path.split("/") if p]
    if segments and re.fullmatch(r"-?\d+", segments[-1]):
        return segments[-1]
    return None


def is_boundary_value(value):
    if value is None:
        return False
    if value == "":
        return True
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    return number <= BOUNDARY_NUMERIC_LOW or number >= BOUNDARY_NUMERIC_HIGH


def build_features(request_data, response_data):
    """
    request_data: {"method": str, "path": str, "query": str,
                    "body": str, "headers": dict}
    response_data: {"status": int, "length": int}
    """
    path = request_data["path"] or "/"
    query = request_data.get("query") or ""
    body = request_data.get("body") or ""

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
        "boundary_value_indicator": boundary_hit,
        # filled in by SessionFeatureTracker below (needs history)
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


def vectorize(features):
    return [float(features.get(key, 0.0)) for key in FEATURE_KEYS]


class SessionFeatureTracker:
    """
    Stateful, per-session companion to build_features(). Call
    .compute(request_data, response_data) once per request IN ORDER
    for a given session; it fills in endpoint_probe_diversity /
    fuzzing_indicator / fuzz_value_count using that session's request
    history so far - exactly like apply_sequential_features() does
    for a finished batch, but incrementally, one live request at a
    time.

    One instance per active session. Discard (or expire) it when the
    session ends.
    """

    def __init__(self):
        self.endpoint_history = {}

    def compute(self, request_data, response_data):
        features = build_features(request_data, response_data)

        path = request_data["path"] or "/"
        params = parse_qsl(request_data.get("query") or "", keep_blank_values=True)
        template = normalize_path_template(path)
        probe_value = extract_probe_value(path, params)

        prior_values = self.endpoint_history.setdefault(template, [])
        diversity = len(set(prior_values))

        features["endpoint_probe_diversity"] = diversity
        features["fuzzing_indicator"] = int(
            bool(features["boundary_value_indicator"])
            or diversity >= ENDPOINT_DIVERSITY_THRESHOLD
        )
        features["fuzz_value_count"] = diversity

        if probe_value is not None:
            prior_values.append(probe_value)

        return features
