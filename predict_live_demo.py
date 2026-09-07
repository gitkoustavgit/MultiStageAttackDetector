"""
Minimal runnable demo for live_predictor.py.

Requires lstm_stage_classifier.keras and hmm_params.npz to already
exist in this same folder (produced by train_models.py). Run:

    python predict_live_demo.py

This simulates ONE session receiving requests one at a time, exactly
the way a real capture point (proxy/middleware/log-tailer) would call
predictor.observe() as traffic arrives. Replace `demo_requests` with
your real capture source when you wire this into something live.
"""

from live_predictor import LiveAttackPredictor

MODEL_PATH = "lstm_stage_classifier.keras"
HMM_PARAMS_PATH = "hmm_params.npz"

# (request_data, response_data) pairs, in arrival order, simulating
# one session drifting from normal browsing into an injection attempt.
demo_requests = [
    ({"method": "GET", "path": "/", "query": "", "body": "", "headers": {}},
     {"status": 200, "length": 4200}),

    ({"method": "GET", "path": "/rest/products/search", "query": "q=apple", "body": "", "headers": {}},
     {"status": 200, "length": 800}),

    ({"method": "GET", "path": "/rest/user/whoami", "query": "", "body": "", "headers": {}},
     {"status": 200, "length": 60}),

    ({"method": "GET", "path": "/rest/products/search", "query": "q=-1", "body": "", "headers": {}},
     {"status": 200, "length": 40}),

    ({"method": "GET", "path": "/rest/products/search", "query": "q=999999", "body": "", "headers": {}},
     {"status": 200, "length": 40}),

    ({"method": "GET", "path": "/rest/products/search",
      "query": "q=apple')) UNION SELECT id,email,password,4 FROM Users--", "body": "", "headers": {}},
     {"status": 200, "length": 1500}),

    ({"method": "GET", "path": "/rest/admin/application-configuration", "query": "", "body": "",
      "headers": {"X-User-Email": "admin@juice-sh.op'--"}},
     {"status": 200, "length": 2200}),
]


def main():
    predictor = LiveAttackPredictor(MODEL_PATH, HMM_PARAMS_PATH)

    print(f"{'req#':<5}{'lstm guess':<14}{'viterbi guess':<16}{'confidence':<12}{'escalated'}")
    print("-" * 60)

    for request_data, response_data in demo_requests:
        result = predictor.observe(
            session_id="demo_session_1",
            request_data=request_data,
            response_data=response_data,
        )
        print(
            f"{result.request_number:<5}{result.lstm_stage:<14}"
            f"{result.stage:<16}{result.confidence:<12.3f}{result.escalated}"
        )

    predictor.reset_session("demo_session_1")


if __name__ == "__main__":
    main()
