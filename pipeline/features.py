"""
Feature extraction -- the ONE implementation, used by both training and inference.

The original repository claimed a single source of truth but shipped two copies of
build_features (in feature_engineering.py and upload_dataset.py). Here there is exactly
one class, SessionFeatureExtractor, and both the dataset builder and the live predictor
instantiate it. A test (tests/test_features.py) asserts that training-time and
inference-time vectors are byte-identical for the same request stream.

DESIGN RULES
------------
1. Every feature is CAUSAL: it depends only on the current request and requests that
   came strictly before it in the same session. Nothing peeks at the future. This is
   what makes an offline benchmark honest about live behaviour.

2. No dead or duplicated columns. The audit of the old feature set found four constant
   method flags, a constant body_length, and two exact duplicate columns
   (payload_length, fuzz_value_count). Real captures make method and body informative;
   the duplicates are simply removed.

3. Session-context features use a DECAY WINDOW, not whole-session accumulators. The old
   endpoint_probe_diversity counted distinct values over the entire session and latched
   fuzzing_indicator on forever, so a shopper searching three products looked like a
   fuzzer for the rest of the visit. Here diversity/error/attack context are measured
   over a sliding window of recent requests, so behaviour can cool off.

4. Unbounded magnitudes (lengths, counts, timing) are log-compressed so the LSTM does
   not see response_length in [11, 1.2e6] next to 0/1 flags.
"""

from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus

# ---- pattern tables -------------------------------------------------------------

# SQLi patterns. The bare "--" of the old code matched any path with two hyphens; here
# the comment pattern requires a quote or space before it so it keys on injection, not
# on incidental double hyphens in a URL.
SQLI_PATTERNS = [
    re.compile(r"'\s*or\s+'?\d+'?\s*=\s*'?\d+", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"\band\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    re.compile(r"\bselect\b.{1,80}?\bfrom\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\binformation_schema\b", re.IGNORECASE),
    re.compile(r"\bsleep\s*\(", re.IGNORECASE),
    re.compile(r"['\")\s]--", re.IGNORECASE),
    re.compile(r";\s*(drop|insert|update|delete)\b", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on(error|load|mouseover|focus)\s*=", re.IGNORECASE),
    re.compile(r"<img\b[^>]*\bsrc\s*=", re.IGNORECASE),
    re.compile(r"<svg\b", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
]

_NUMERIC_RE = re.compile(r"^-?\d+$")
_TRAILING_ID_RE = re.compile(r"-?\d+$")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9\s]")

BOUNDARY_LOW = 0
BOUNDARY_HIGH = 500
RECENT_WINDOW = 8      # sliding window (in requests) for all context features
DECAY = 0.6            # geometric decay for the "recent attack pressure" signal
ENUM_NORM = 6.0        # id-diversity that saturates enum_pressure to ~1

# EXACT feature order. This list IS the schema; reordering requires retraining.
FEATURE_KEYS: List[str] = [
    # --- request method / shape ---
    "is_get",
    "is_post",
    "is_write",              # PUT or DELETE
    "path_depth",
    "has_query",
    "log_query_len",
    "log_body_len",
    "query_param_count",
    "special_char_ratio",
    # --- payload signals ---
    "sqli_score",            # fraction of SQLi patterns matched (0..1)
    "xss_score",             # fraction of XSS patterns matched (0..1)
    "numeric_query",
    "boundary_value",
    # --- endpoint class ---
    "admin_path",
    "api_path",
    "auth_path",
    "search_path",
    "has_auth_header",
    "has_identity_header",
    # --- response ---
    "status_2xx",
    "status_3xx",
    "status_4xx",
    "status_5xx",
    "log_resp_len",
    # --- causal session context (decaying / windowed) ---
    "log_request_index",
    "log_inter_arrival",
    "endpoint_diversity_recent",
    "path_diversity_recent",
    "error_rate_recent",
    "attack_pressure",       # decaying sqli/xss presence over recent requests
    "enum_pressure",         # decaying "sustained id/value enumeration" (recon signal)
]

NUM_FEATURES = len(FEATURE_KEYS)


@dataclass
class RequestView:
    """Minimal request shape the extractor needs; decouples it from corpus.Request."""

    method: str
    path: str
    query: str
    body: str
    headers: Dict[str, str]
    status: int
    response_length: int
    epoch_seconds: Optional[float]  # for inter-arrival; None on the very first request


def _log1p(x: float) -> float:
    return math.log1p(max(0.0, float(x)))


def _regex_fraction(patterns, text: str) -> float:
    if not text:
        return 0.0
    hits = sum(1 for p in patterns if p.search(text))
    return hits / len(patterns)


def _path_template(path: str) -> str:
    # Collapse EVERY numeric segment to {id}, not just the trailing one, so that
    # /rest/products/23/reviews and /rest/products/45/reviews share the template
    # /rest/products/{id}/reviews. Reconnaissance shows up as systematic enumeration of
    # ids on one template (product reviews, user ids, basket ids); the old trailing-only
    # rule missed mid-path ids and so could not see that enumeration at all.
    segments = [p for p in path.split("/") if p]
    segs = ["{id}" if _NUMERIC_RE.match(s) else s for s in segments]
    return "/" + "/".join(segs)


def _probe_value(path: str, params: List[Tuple[str, str]]) -> Optional[str]:
    if params:
        return unquote_plus(params[0][1])
    # No query: the varied value is the numeric id(s) in the path. Joining them lets the
    # diversity tracker count distinct ids enumerated against the same template.
    nums = [s for s in path.split("/") if s and _NUMERIC_RE.match(s)]
    return ",".join(nums) if nums else None


def _is_boundary(value: Optional[str]) -> bool:
    if value is None:
        return False
    if value == "":
        return True
    if not _NUMERIC_RE.match(value):
        return False
    n = int(value)
    return n <= BOUNDARY_LOW or n >= BOUNDARY_HIGH


class SessionFeatureExtractor:
    """
    Stateful, per-session. Call feed() once per request IN ORDER. Returns the feature
    vector for that request, using only that request and the ones before it.

    One instance per active session. In training, a fresh instance is created for each
    composed session; in live inference, one instance lives per client session and is
    dropped when the session is reset or expires.
    """

    def __init__(self, window: int = RECENT_WINDOW):
        self.window = window
        self.index = 0
        self.last_epoch: Optional[float] = None
        # recent per-request records for windowed context
        self._recent_templates: Deque[str] = deque(maxlen=window)
        self._recent_probe_by_template: Dict[str, Deque[str]] = {}
        self._recent_paths: Deque[str] = deque(maxlen=window)
        self._recent_errors: Deque[int] = deque(maxlen=window)
        self._attack_pressure = 0.0
        self._enum_pressure = 0.0

    def feed(self, req: RequestView) -> List[float]:
        self.index += 1
        path = req.path or "/"
        query = req.query or ""
        body = req.body or ""
        decoded_query = unquote_plus(query)
        combined = f"{path} {decoded_query} {body}"
        params = parse_qsl(query, keep_blank_values=True)
        lower_path = path.lower()
        method = (req.method or "").upper()

        # ---- payload signals (current request only) ----
        sqli = _regex_fraction(SQLI_PATTERNS, combined)
        xss = _regex_fraction(XSS_PATTERNS, combined)
        probe = _probe_value(path, params)
        special = 0.0
        if query:
            special = len(_SPECIAL_RE.findall(decoded_query)) / max(1, len(decoded_query))

        # ---- header signals ----
        header_keys = {k.lower() for k in req.headers}
        has_auth = int("authorization" in header_keys)
        has_identity = int("x-user-email" in header_keys)

        # ---- causal context using state from PRIOR requests (before updating) ----
        template = _path_template(path)
        prior_probes = self._recent_probe_by_template.get(template)
        endpoint_diversity = len(set(prior_probes)) if prior_probes else 0
        path_diversity = len(set(self._recent_paths))
        error_rate = (sum(self._recent_errors) / len(self._recent_errors)
                      if self._recent_errors else 0.0)
        attack_pressure = self._attack_pressure  # decayed value from before this request
        enum_pressure = self._enum_pressure      # decayed sustained-enumeration signal

        inter_arrival = 0.0
        if req.epoch_seconds is not None and self.last_epoch is not None:
            inter_arrival = max(0.0, req.epoch_seconds - self.last_epoch)

        status = int(req.status or 0)
        vector = [
            float(method == "GET"),
            float(method == "POST"),
            float(method in ("PUT", "DELETE")),
            float(len([p for p in path.split("/") if p])),
            float(bool(query)),
            _log1p(len(query)),
            _log1p(len(body)),
            float(len(params)),
            special,
            sqli,
            xss,
            float(probe is not None and _NUMERIC_RE.match(probe or "") is not None),
            float(_is_boundary(probe)),
            float("/admin/" in lower_path or lower_path.endswith("/admin")
                  or "administration" in lower_path),
            float(lower_path.startswith("/api/") or lower_path.startswith("/rest/")),
            float(any(x in lower_path for x in ("/login", "/logout", "/whoami", "/authenticate", "/token"))),
            float("search" in lower_path),
            float(has_auth),
            float(has_identity),
            float(200 <= status < 300),
            float(300 <= status < 400),
            float(400 <= status < 500),
            float(status >= 500),
            _log1p(req.response_length),
            _log1p(self.index),
            _log1p(inter_arrival),
            float(endpoint_diversity),
            float(path_diversity),
            error_rate,
            attack_pressure,
            enum_pressure,
        ]
        assert len(vector) == NUM_FEATURES, (len(vector), NUM_FEATURES)

        # ---- update state AFTER emitting (so context is strictly causal) ----
        self.last_epoch = req.epoch_seconds if req.epoch_seconds is not None else self.last_epoch
        self._recent_templates.append(template)
        self._recent_paths.append(lower_path)
        self._recent_errors.append(int(status >= 400))
        if probe is not None:
            dq = self._recent_probe_by_template.setdefault(template, deque(maxlen=self.window))
            dq.append(probe)
        # prune templates that fell out of the recent window entirely
        live_templates = set(self._recent_templates)
        for key in list(self._recent_probe_by_template):
            if key not in live_templates:
                del self._recent_probe_by_template[key]
        # decaying attack pressure: bumped by this request's payload signal
        self._attack_pressure = DECAY * self._attack_pressure + (1 - DECAY) * max(sqli, xss)
        self._enum_pressure = DECAY * self._enum_pressure + (1 - DECAY) * min(1.0, endpoint_diversity / ENUM_NORM)

        return vector


def extract_session(requests, window: int = RECENT_WINDOW) -> List[List[float]]:
    """Convenience: full causal feature matrix for a list of RequestView-like objects."""
    extractor = SessionFeatureExtractor(window=window)
    return [extractor.feed(r) for r in requests]
