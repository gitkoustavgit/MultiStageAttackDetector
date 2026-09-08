"""
Invariant tests for the honest pipeline. Run with: python -m pytest tests/ -q

These lock in the properties the original repository silently violated:
  * features are causal (a future request cannot change a past request's vector)
  * there is genuinely ONE feature implementation (training == inference, byte for byte)
  * splits are disjoint at the file level (no request leaks train -> test)
  * the composed data is NOT a running-maximum staircase (the flaw that made the old
    benchmark trivially solvable)
  * the deployed decoder is causal (prefix-stable: extending a session never rewrites
    the stage already reported for an earlier request)
"""

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.corpus import load_capture_files, assign_file_splits
from pipeline.features import (
    NUM_FEATURES,
    RequestView,
    SessionFeatureExtractor,
    extract_session,
)
from pipeline.compose import (
    compose_sessions,
    next_stage_predictability,
    running_max_fraction,
)
from pipeline.models import (
    fit_transition_matrix,
    forward_filter,
    next_distinct_matrix,
    temper_transitions,
)

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SQLrequests")


def _view(method="GET", path="/", query="", body="", headers=None, status=200,
          rlen=100, epoch=None):
    return RequestView(method, path, query, body, headers or {}, status, rlen, epoch)


def test_feature_vector_width():
    x = SessionFeatureExtractor().feed(_view())
    assert len(x) == NUM_FEATURES


def test_features_are_causal():
    """A request's vector must not change when later requests are appended."""
    stream = [
        _view(path="/", epoch=0.0),
        _view(path="/rest/products/search", query="q=apple", epoch=1.0),
        _view(path="/rest/products/search", query="q=-1", epoch=2.0),
    ]
    short = extract_session(stream[:2])
    long = extract_session(stream)  # same first two requests, plus a third
    assert np.allclose(short[0], long[0])
    assert np.allclose(short[1], long[1])


def test_single_source_of_truth():
    """Feeding one request at a time (inference) equals batch extraction (training)."""
    stream = [
        _view(path="/", epoch=0.0),
        _view(path="/rest/user/whoami", query="fields=email", epoch=3.0),
        _view(path="/rest/products/search",
              query="q=apple')) UNION SELECT id,email,password,4 FROM Users--",
              status=500, epoch=5.0),
    ]
    batch = extract_session(stream)
    live_ex = SessionFeatureExtractor()
    live = [live_ex.feed(r) for r in stream]
    assert np.allclose(np.array(batch), np.array(live))


def test_sqli_pattern_does_not_match_plain_path():
    """The bare '--' bug: a normal path with hyphens must not read as SQLi."""
    x = SessionFeatureExtractor().feed(_view(path="/rest/admin/application-configuration"))
    from pipeline.features import FEATURE_KEYS

    assert x[FEATURE_KEYS.index("sqli_score")] == 0.0


def test_injection_payload_scores_sqli():
    x = SessionFeatureExtractor().feed(
        _view(path="/rest/products/search",
              query="q=apple')) UNION SELECT id,email,password,4 FROM Users--"))
    from pipeline.features import FEATURE_KEYS

    assert x[FEATURE_KEYS.index("sqli_score")] > 0.0


def test_fuzzing_indicator_decays():
    """Benign browsing must not latch an attack-context feature on forever."""
    from pipeline.features import FEATURE_KEYS, RECENT_WINDOW

    ex = SessionFeatureExtractor()
    idx = FEATURE_KEYS.index("endpoint_diversity_recent")
    # many distinct searches -> diversity rises
    for i in range(5):
        ex.feed(_view(path="/rest/products/search", query=f"q=item{i}", epoch=float(i)))
    peak = ex.feed(_view(path="/rest/products/search", query="q=item9", epoch=6.0))[idx]
    # then repeat ONE value for longer than the window -> diversity must fall back
    for i in range(RECENT_WINDOW + 2):
        last = ex.feed(_view(path="/rest/products/search", query="q=same", epoch=10.0 + i))[idx]
    assert last < peak


def test_splits_are_disjoint_by_file():
    caps = load_capture_files(ROOT)
    splits = assign_file_splits(caps)
    for c in caps:
        assert c.name in splits
    # every file has exactly one split; sets are disjoint by construction
    train = {n for n, s in splits.items() if s == "train"}
    test = {n for n, s in splits.items() if s == "test"}
    val = {n for n, s in splits.items() if s == "validation"}
    assert not (train & test) and not (train & val) and not (val & test)
    assert train and test  # both non-empty


def test_composed_sessions_break_running_max():
    """The core fix: the composed data must NOT be a running-maximum staircase."""
    caps = load_capture_files(ROOT)
    splits = assign_file_splits(caps)
    sessions = compose_sessions(caps, splits, "train", 200)
    frac = running_max_fraction(sessions)
    # old synthetic data scored 1.0 here; anything below ~0.85 means the shortcut is gone
    assert frac < 0.85, f"running-max fraction {frac:.3f} too high; shortcut still present"


def test_augmented_files_are_train_only():
    """Augmented (live-generated) sessions must never land in validation/test."""
    from pipeline.corpus import assign_file_splits, CaptureFile, Request

    real = load_capture_files(ROOT)
    fake = [CaptureFile(name=f"AUG_INJECTION_{i:03d}", stage="INJECTION",
                        requests=[Request("GET", "/x", "", "", {}, 200, 10, None,
                                          "INJECTION", f"AUG_INJECTION_{i:03d}")])
            for i in range(5)]
    splits = assign_file_splits(real + fake)
    for f in fake:
        assert splits[f.name] == "train", f"{f.name} leaked into {splits[f.name]}"


def test_forward_filter_is_prefix_stable():
    """
    Causality of the deployed decoder: the stage reported at step t must not change when
    more requests arrive after t. Viterbi's backward pass fails this; the forward filter
    must pass it.
    """
    rng = np.random.default_rng(0)
    A, pi = fit_transition_matrix([np.array([0, 1, 2, 3, 4, 3, 2, 1, 0])], smoothing=1.0)
    A = temper_transitions(A, 0.3)
    em = rng.dirichlet(np.ones(5), size=12)
    full = forward_filter(em, A, pi).argmax(1)
    for cut in (4, 7, 10):
        prefix = forward_filter(em[:cut], A, pi).argmax(1)
        assert np.array_equal(prefix, full[:cut]), f"prefix at cut={cut} disagrees"


def test_kill_chain_structure_is_learnable():
    """The composer must leave a learnable next-stage signal (so 'predict where he goes
    next' is possible), while still not being a running-max staircase."""
    caps = load_capture_files(ROOT)
    splits = assign_file_splits(caps)
    sessions = compose_sessions(caps, splits, "train", 300)
    # a first-order Markov model must beat chance (0.25 among 4 non-current stages) at
    # naming the next distinct stage
    assert next_stage_predictability(sessions) > 0.35
    # and the sequence must still de-escalate enough to defeat a running-max rule
    assert running_max_fraction(sessions) < 0.85


def test_next_distinct_matrix_removes_self_loops():
    A = np.array([
        [0.9, 0.06, 0.02, 0.01, 0.01],
        [0.1, 0.8, 0.05, 0.03, 0.02],
        [0.1, 0.05, 0.75, 0.07, 0.03],
        [0.1, 0.03, 0.05, 0.72, 0.10],
        [0.2, 0.03, 0.03, 0.04, 0.70],
    ])
    B = next_distinct_matrix(A)
    assert np.allclose(np.diag(B), 0.0)              # no self-loops
    assert np.allclose(B.sum(axis=1), 1.0)           # still a distribution


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
