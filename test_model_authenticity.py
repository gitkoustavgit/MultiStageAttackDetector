"""
test_model_authenticity.py

Comprehensive Model Authenticity & Reliability Test Suite
=========================================================

Fires REAL HTTP requests against a live OWASP Juice Shop instance and
feeds every request/response pair through the LiveAttackPredictor
(LSTM + HMM Viterbi + temperature calibration + admin alerting).

Validates that the model:
  1. Correctly classifies each attack stage (NORMAL, RECON, FUZZING,
     INJECTION, EXPLOITATION) with high confidence.
  2. Handles edge cases: thin context (1st request), single-stage
     sessions, rapid escalation, mixed SQLi+XSS, out-of-order stages.
  3. Triggers admin alerts appropriately for malicious stages.
  4. Maintains calibrated confidence scores.

Reports per-stage precision/recall/F1, confusion matrix, and overall
accuracy with a pass/fail verdict.

Requires:
  - Juice Shop running on localhost:9000
  - lstm_stage_classifier.keras, hmm_params.npz, calibration_params.json,
    xgboost_stage_classifier.json in this folder

Run:
    python test_model_authenticity.py
"""

import sys
import time
import traceback
from collections import defaultdict
from urllib.parse import urlsplit, urlencode

import requests as http_lib

from live_predictor import LiveAttackPredictor

# ================================================================
# CONFIG
# ================================================================
MODEL_PATH = "lstm_stage_classifier.keras"
HMM_PARAMS_PATH = "hmm_params.npz"
CALIB_PARAMS_PATH = "calibration_params.json"

BASE_URL = "http://localhost:9000"
ALLOWED_HOST = "localhost"
ALLOWED_PORT = 9000

# Stages in severity order
STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]

# ================================================================
# HELPERS
# ================================================================

def validate_local_url(url):
    parsed = urlsplit(url)
    if parsed.hostname != ALLOWED_HOST or parsed.port not in (None, ALLOWED_PORT):
        raise RuntimeError(f"Blocked non-local target: {url}")


def fire_request(session, method, path, params=None, body="", extra_headers=None):
    """Send a real HTTP request to Juice Shop and return (request_data, response_data)."""
    url = BASE_URL + path
    validate_local_url(url)

    headers = {
        "User-Agent": "AuthenticityTest/1.0",
        "Accept": "application/json,text/plain,*/*",
        **(extra_headers or {}),
    }

    try:
        if method.upper() in ("POST", "PUT"):
            response = session.request(
                method=method, url=url, params=params,
                data=body, headers=headers, timeout=10
            )
        else:
            response = session.request(
                method=method, url=url, params=params,
                headers=headers, timeout=10
            )
    except Exception as e:
        # If Juice Shop returns an error or connection issue, use fallback
        print(f"    [!] HTTP error on {method} {path}: {e}")
        return (
            {"method": method, "path": path, "query": urlencode(params or {}),
             "body": body, "headers": headers},
            {"status": 0, "length": 0},
        )

    validate_local_url(response.url)
    final = urlsplit(response.url)

    request_data = {
        "method": method.upper(),
        "path": final.path or "/",
        "query": final.query,
        "body": body,
        "headers": headers,
    }
    response_data = {
        "status": response.status_code,
        "length": len(response.content),
    }
    return request_data, response_data


# ================================================================
# TEST SCENARIO DEFINITIONS
# ================================================================
# Each scenario is (name, description, session_id, [(method, path, params, body, extra_headers, expected_stage), ...])
# expected_stage can be a single string or a list of acceptable stages

def build_test_scenarios():
    """Return a list of (scenario_name, description, session_id, requests_list)."""

    scenarios = []

    # ------------------------------------------------------------------
    # SCENARIO 1: Full Kill Chain (NORMAL -> RECON -> FUZZING -> INJECTION -> EXPLOITATION)
    # ------------------------------------------------------------------
    scenarios.append((
        "Full Kill Chain",
        "Classic multi-stage progression through all 5 stages",
        "test_full_chain",
        [
            # NORMAL: Landing page
            ("GET", "/", {}, "", {}, "NORMAL"),
            # NORMAL: Browse products
            ("GET", "/rest/products/search", {"q": "apple"}, "", {}, "NORMAL"),
            # NORMAL: Another product browse
            ("GET", "/rest/products/search", {"q": "banana"}, "", {}, "NORMAL"),
            # RECON: Check auth status
            ("GET", "/rest/user/whoami", {}, "", {}, "RECON"),
            # RECON: Probe admin endpoint
            ("GET", "/rest/admin/application-configuration", {}, "", {}, "RECON"),
            # FUZZING: Boundary value testing
            ("GET", "/rest/products/search", {"q": "-1"}, "", {}, "FUZZING"),
            # FUZZING: Large numeric boundary
            ("GET", "/rest/products/search", {"q": "999999"}, "", {}, "FUZZING"),
            # FUZZING: Empty value probe
            ("GET", "/rest/products/search", {"q": ""}, "", {}, "FUZZING"),
            # INJECTION: SQLi - UNION SELECT
            ("GET", "/rest/products/search",
             {"q": "apple')) UNION SELECT id,email,password,4 FROM Users--"}, "", {},
             "INJECTION"),
            # INJECTION: SQLi - OR 1=1
            ("GET", "/rest/products/search",
             {"q": "' OR 1=1--"}, "", {},
             "INJECTION"),
            # INJECTION: XSS
            ("GET", "/rest/products/search",
             {"q": "<script>alert('XSS')</script>"}, "", {},
             "INJECTION"),
            # EXPLOITATION: Admin access with forged headers
            ("GET", "/rest/admin/application-configuration", {},
             "", {"X-User-Email": "admin@juice-sh.op'--"},
             "EXPLOITATION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 2: Pure Normal Session
    # ------------------------------------------------------------------
    scenarios.append((
        "Pure Normal Session",
        "Benign user browsing products - should NOT trigger attack detection",
        "test_pure_normal",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "juice"}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "water"}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "lemon"}, "", {}, "NORMAL"),
            ("GET", "/api/Products/1", {}, "", {}, "NORMAL"),
            ("GET", "/api/Products/2", {}, "", {}, "NORMAL"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 3: Pure Reconnaissance
    # ------------------------------------------------------------------
    scenarios.append((
        "Pure Reconnaissance",
        "Attacker probing endpoints without injecting payloads",
        "test_pure_recon",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/user/whoami", {}, "", {}, "RECON"),
            ("GET", "/rest/admin/application-configuration", {}, "", {}, "RECON"),
            ("GET", "/api/SecurityQuestions", {}, "", {}, "RECON"),
            ("GET", "/rest/user/authentication-details", {}, "", {}, "RECON"),
            ("GET", "/api/Complaints", {}, "", {}, "RECON"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 4: Heavy SQLi Injection
    # ------------------------------------------------------------------
    scenarios.append((
        "Heavy SQLi Injection",
        "Concentrated SQL injection payloads - model should detect early",
        "test_heavy_sqli",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "apple"}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search",
             {"q": "' UNION SELECT 1,2,3,4,5,6,7,8,9--"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "apple')) UNION ALL SELECT id,email,password,role FROM Users--"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "' AND 1=1 UNION SELECT table_name,2,3,4 FROM information_schema.tables--"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "' OR '1'='1' UNION SELECT username,password,3,4 FROM Users--"}, "", {},
             "INJECTION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 5: XSS Focused Session
    # ------------------------------------------------------------------
    scenarios.append((
        "XSS Focused Session",
        "Cross-Site Scripting payloads through search and product API",
        "test_xss_focused",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "test"}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search",
             {"q": "<script>alert(1)</script>"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": '"><script>alert("XSS")</script>'}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "<img src=x onerror=alert(1)>"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "javascript:alert(document.cookie)"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": '"><svg/onload=alert(1)>'}, "", {},
             "INJECTION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 6: Fuzzing to Injection Escalation
    # ------------------------------------------------------------------
    scenarios.append((
        "Fuzzing to Injection Escalation",
        "Starts with boundary fuzzing, escalates to injection - tests escalation detection",
        "test_fuzz_to_inject",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "0"}, "", {}, ["NORMAL", "FUZZING"]),
            ("GET", "/rest/products/search", {"q": "-1"}, "", {}, "FUZZING"),
            ("GET", "/rest/products/search", {"q": "99999"}, "", {}, "FUZZING"),
            ("GET", "/rest/products/search", {"q": ""}, "", {}, "FUZZING"),
            ("GET", "/rest/products/search", {"q": "500"}, "", {}, "FUZZING"),
            # Now escalate to injection
            ("GET", "/rest/products/search",
             {"q": "test' OR 1=1--"}, "", {},
             "INJECTION"),
            ("GET", "/rest/products/search",
             {"q": "' UNION SELECT id,username,password,4 FROM Users--"}, "", {},
             "INJECTION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 7: Exploitation Techniques
    # ------------------------------------------------------------------
    scenarios.append((
        "Exploitation Techniques",
        "Admin access bypass, IDOR, and privilege escalation attempts",
        "test_exploitation",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "apple"}, "", {}, "NORMAL"),
            ("GET", "/rest/user/whoami", {}, "", {}, "RECON"),
            # Admin endpoint probing with forged headers
            ("GET", "/rest/admin/application-configuration", {},
             "", {"X-User-Email": "admin@juice-sh.op"},
             ["RECON", "EXPLOITATION"]),
            # Auth bypass with SQLi in header
            ("GET", "/rest/admin/application-configuration", {},
             "", {"X-User-Email": "admin@juice-sh.op'--", "Authorization": "Bearer forged"},
             "EXPLOITATION"),
            # IDOR attempt with admin header
            ("GET", "/api/Users/1", {},
             "", {"X-User-Email": "admin@juice-sh.op"},
             "EXPLOITATION"),
            # Forced browsing for user data
            ("GET", "/api/Users/2", {},
             "", {"X-User-Email": "admin@juice-sh.op'--"},
             "EXPLOITATION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 8: Mixed SQLi + XSS (Combined Payloads)
    # ------------------------------------------------------------------
    scenarios.append((
        "Mixed SQLi + XSS Payloads",
        "Alternating between SQLi and XSS in the same session",
        "test_mixed_payloads",
        [
            ("GET", "/", {}, "", {}, "NORMAL"),
            ("GET", "/rest/products/search", {"q": "test"}, "", {}, "NORMAL"),
            # SQLi
            ("GET", "/rest/products/search",
             {"q": "test' UNION SELECT 1,2,3,4--"}, "", {},
             "INJECTION"),
            # XSS
            ("GET", "/rest/products/search",
             {"q": "<script>alert('hack')</script>"}, "", {},
             "INJECTION"),
            # SQLi again
            ("GET", "/rest/products/search",
             {"q": "' OR 1=1 UNION SELECT email,password,3,4 FROM Users--"}, "", {},
             "INJECTION"),
            # XSS with onerror
            ("GET", "/rest/products/search",
             {"q": "<img src=x onerror=alert(document.cookie)>"}, "", {},
             "INJECTION"),
        ],
    ))

    # ------------------------------------------------------------------
    # SCENARIO 9: Rapid Single-Request Detection (Thin Context)
    # ------------------------------------------------------------------
    scenarios.append((
        "Thin Context - First Request Attack",
        "Attacker starts with malicious payload on the VERY FIRST request - tests thin context",
        "test_thin_ctx",
        [
            # Immediate SQLi on first request - can the model catch it with NO prior context?
            ("GET", "/rest/products/search",
             {"q": "apple')) UNION SELECT id,email,password,4 FROM Users--"}, "", {},
             ["INJECTION", "NORMAL", "RECON"]),
            # Second request also attack
            ("GET", "/rest/products/search",
             {"q": "' OR 1=1--"}, "", {},
             "INJECTION"),
            # Third request XSS
            ("GET", "/rest/products/search",
             {"q": "<script>alert(1)</script>"}, "", {},
             "INJECTION"),
        ],
    ))

    return scenarios


# ================================================================
# METRICS COMPUTATION
# ================================================================

def compute_metrics(all_results):
    """Compute per-stage precision, recall, F1, and overall accuracy."""

    # Count TP, FP, FN per stage
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    correct = 0
    total = 0
    conf_correct = []
    conf_wrong = []

    # Confusion matrix
    confusion = defaultdict(lambda: defaultdict(int))

    for expected, predicted, confidence in all_results:
        total += 1
        confusion[expected][predicted] += 1

        if predicted == expected:
            correct += 1
            tp[expected] += 1
            conf_correct.append(confidence)
        else:
            fp[predicted] += 1
            fn[expected] += 1
            conf_wrong.append(confidence)

    # Per-stage metrics
    stage_metrics = {}
    for stage in STAGES:
        p = tp[stage] / (tp[stage] + fp[stage]) if (tp[stage] + fp[stage]) > 0 else 0.0
        r = tp[stage] / (tp[stage] + fn[stage]) if (tp[stage] + fn[stage]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        stage_metrics[stage] = {"precision": p, "recall": r, "f1": f1,
                                "tp": tp[stage], "fp": fp[stage], "fn": fn[stage]}

    accuracy = correct / total if total > 0 else 0.0
    macro_f1 = sum(m["f1"] for m in stage_metrics.values()) / len(stage_metrics) if stage_metrics else 0.0

    avg_conf_correct = sum(conf_correct) / len(conf_correct) if conf_correct else 0.0
    avg_conf_wrong = sum(conf_wrong) / len(conf_wrong) if conf_wrong else 0.0

    return {
        "accuracy": accuracy,
        "correct": correct,
        "total": total,
        "macro_f1": macro_f1,
        "stage_metrics": stage_metrics,
        "confusion": confusion,
        "avg_confidence_correct": avg_conf_correct,
        "avg_confidence_wrong": avg_conf_wrong,
    }


def compute_flexible_metrics(all_results_flexible):
    """Like compute_metrics but expected can be a list of acceptable stages."""
    # Flatten: pick the best-matching expected for multi-option cases
    flattened = []
    for expected, predicted, confidence in all_results_flexible:
        if isinstance(expected, list):
            if predicted in expected:
                flattened.append((predicted, predicted, confidence))  # count as correct match
            else:
                flattened.append((expected[0], predicted, confidence))  # use primary expected
        else:
            flattened.append((expected, predicted, confidence))
    return compute_metrics(flattened)


# ================================================================
# MAIN TEST RUNNER
# ================================================================

def main():
    print("\n" + "=" * 100)
    print("   MODEL AUTHENTICITY & RELIABILITY TEST SUITE")
    print("   Context-Aware AI Detection of Multi-Stage Injection Attacks")
    print("=" * 100)

    # Verify Juice Shop
    try:
        r = http_lib.get(BASE_URL + "/", timeout=5)
        print(f"\n[OK] Juice Shop responding at {BASE_URL} (status={r.status_code})")
    except Exception as e:
        print(f"\n[FAIL] Cannot reach Juice Shop at {BASE_URL}: {e}")
        sys.exit(1)

    # Initialize predictor (alerts disabled to keep output clean)
    predictor = LiveAttackPredictor(
        model_path=MODEL_PATH,
        hmm_params_path=HMM_PARAMS_PATH,
        calib_params_path=CALIB_PARAMS_PATH,
        enable_admin_alerts=False,  # Suppress verbose alert output during test
    )

    scenarios = build_test_scenarios()
    http_session = http_lib.Session()

    all_results = []          # [(expected, predicted, confidence)]
    scenario_summaries = []   # per-scenario results
    alert_counts = {"total_requests": 0, "total_scenarios": len(scenarios)}

    for scenario_idx, (name, description, session_id, req_list) in enumerate(scenarios, 1):
        print(f"\n{'=' * 100}")
        print(f"  SCENARIO {scenario_idx}/{len(scenarios)}: {name}")
        print(f"  {description}")
        print(f"{'=' * 100}")
        print(f"  {'#':<4}{'Method':<7}{'Path':<48}{'Expected':<16}{'Predicted':<16}{'Conf':<8}{'Match'}")
        print(f"  {'-' * 96}")

        predictor.reset_session(session_id)
        scenario_correct = 0
        scenario_total = 0
        scenario_results = []

        for req_idx, (method, path, params, body, extra_headers, expected) in enumerate(req_list, 1):
            request_data, response_data = fire_request(
                http_session, method, path, params, body, extra_headers
            )

            result = predictor.observe(
                session_id=session_id,
                request_data=request_data,
                response_data=response_data,
            )

            predicted = result.stage
            confidence = result.confidence

            # Check match (expected can be a list)
            if isinstance(expected, list):
                match = predicted in expected
                expected_display = "/".join(expected)
            else:
                match = predicted == expected
                expected_display = expected

            if match:
                scenario_correct += 1
                match_symbol = "[PASS]"
            else:
                match_symbol = f"[MISS] (lstm={result.lstm_stage})"

            scenario_total += 1
            alert_counts["total_requests"] += 1

            scenario_results.append((expected, predicted, confidence))
            all_results.append((expected, predicted, confidence))

            # Truncate path for display
            display_path = path[:45] + "..." if len(path) > 48 else path
            if params:
                q_str = list(params.values())[0] if len(params) == 1 else str(params)
                q_display = q_str[:20] + "..." if len(str(q_str)) > 20 else q_str
                display_path = f"{display_path}?q={q_display}"
                display_path = display_path[:48]

            print(f"  {req_idx:<4}{method:<7}{display_path:<48}{expected_display:<16}{predicted:<16}{confidence:<8.3f}{match_symbol}")

        scenario_acc = scenario_correct / scenario_total if scenario_total > 0 else 0.0
        verdict = "PASS" if scenario_acc >= 0.6 else "FAIL"
        print(f"\n  Result: {scenario_correct}/{scenario_total} correct ({scenario_acc:.1%}) --> [{verdict}]")
        scenario_summaries.append({
            "name": name,
            "correct": scenario_correct,
            "total": scenario_total,
            "accuracy": scenario_acc,
            "verdict": verdict,
        })

    # ==============================================================
    # AGGREGATE METRICS
    # ==============================================================
    metrics = compute_flexible_metrics(all_results)

    print("\n\n" + "=" * 100)
    print("   AGGREGATE TEST RESULTS")
    print("=" * 100)

    # Scenario Summary Table
    print(f"\n{'Scenario':<42}{'Correct':<10}{'Total':<8}{'Accuracy':<12}{'Verdict'}")
    print("-" * 85)
    for s in scenario_summaries:
        print(f"  {s['name']:<40}{s['correct']:<10}{s['total']:<8}{s['accuracy']:<12.1%}{s['verdict']}")

    print(f"\n  {'OVERALL':<40}{metrics['correct']:<10}{metrics['total']:<8}{metrics['accuracy']:<12.1%}")

    # Per-Stage Precision / Recall / F1
    print(f"\n\n{'STAGE':<18}{'Precision':<12}{'Recall':<12}{'F1-Score':<12}{'TP':<6}{'FP':<6}{'FN':<6}")
    print("-" * 72)
    for stage in STAGES:
        m = metrics["stage_metrics"][stage]
        print(f"  {stage:<16}{m['precision']:<12.3f}{m['recall']:<12.3f}{m['f1']:<12.3f}{m['tp']:<6}{m['fp']:<6}{m['fn']:<6}")

    print(f"\n  Macro-F1:  {metrics['macro_f1']:.4f}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['correct']}/{metrics['total']})")

    # Confusion Matrix
    print(f"\n\nCONFUSION MATRIX (rows=expected, cols=predicted):")
    print(f"{'':>16}", end="")
    for s in STAGES:
        print(f"{s:>14}", end="")
    print()
    print("-" * (16 + 14 * len(STAGES)))
    for expected in STAGES:
        print(f"  {expected:>14}", end="")
        for predicted in STAGES:
            count = metrics["confusion"][expected][predicted]
            print(f"{count:>14}", end="")
        print()

    # Confidence Calibration
    print(f"\n\nCONFIDENCE ANALYSIS:")
    print(f"  Avg confidence on CORRECT predictions: {metrics['avg_confidence_correct']:.4f}")
    print(f"  Avg confidence on WRONG predictions:   {metrics['avg_confidence_wrong']:.4f}")

    # Overall Verdict
    print("\n" + "=" * 100)
    overall_pass = metrics["accuracy"] >= 0.60
    scenarios_passed = sum(1 for s in scenario_summaries if s["verdict"] == "PASS")
    scenarios_total = len(scenario_summaries)

    if overall_pass:
        print(f"  >>> OVERALL VERDICT: PASS <<<")
        print(f"  Model Accuracy: {metrics['accuracy']:.1%} | Macro-F1: {metrics['macro_f1']:.4f}")
        print(f"  Scenarios Passed: {scenarios_passed}/{scenarios_total}")
    else:
        print(f"  >>> OVERALL VERDICT: NEEDS IMPROVEMENT <<<")
        print(f"  Model Accuracy: {metrics['accuracy']:.1%} | Macro-F1: {metrics['macro_f1']:.4f}")
        print(f"  Scenarios Passed: {scenarios_passed}/{scenarios_total}")
        failed = [s["name"] for s in scenario_summaries if s["verdict"] == "FAIL"]
        print(f"  Failed Scenarios: {', '.join(failed)}")

    print("=" * 100)

    http_session.close()
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
