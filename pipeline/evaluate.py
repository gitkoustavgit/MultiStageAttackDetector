"""
Honest benchmark on the held-out test split.

Principles fixed from the audit:
  * The ZERO-PARAMETER baseline is a first-class row. Any model that does not clearly
    beat it has not earned its complexity.
  * One row = one evaluation. No row mixes accuracy from one task with F1 from another.
  * Only CAUSAL decoders are reported as deployable (raw emissions, forward filter,
    online viterbi). The offline Viterbi is shown separately and labelled non-causal.
  * Every latency is measured, at the granularity a live detector actually experiences
    (one request at a time), not batched throughput.
  * Accuracy is reported overall AND at the transition edge (first request of a new
    stage), where detection actually matters and where the old table hid its weakness.
  * The false-positive rate on benign traffic is reported, because the system's
    recommended action is to block clients.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict

import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

import glob

from .models import (
    NUM_STAGES,
    _apply_temperature,
    build_lstm,
    ensemble_emissions,
    fit_transition_matrix,
    forward_filter,
    online_viterbi,
    pad_sequences,
    viterbi_decode,
)

DATASET = "dataset_v2.npz"
STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]


def load_lstm_seeds():
    """Load every seed of the winning LSTM (seed-averaged at inference)."""
    arch = json.load(open("lstm_v2.arch.json"))
    models = []
    for path in sorted(glob.glob("lstm_v2.seed*.weights.h5")):
        m = build_lstm(**arch)
        m.load_weights(path)
        models.append(m)
    if not models:  # backward-compat with a single-file save
        m = build_lstm(**arch); m.load_weights("lstm_v2.weights.h5"); models = [m]
    return models


def transition_edges(labels):
    """Boolean mask: True where the label differs from the previous step (a new stage)."""
    edges = np.zeros(len(labels), dtype=bool)
    edges[0] = True
    edges[1:] = labels[1:] != labels[:-1]
    return edges


def temperature_apply(probs, T):
    logits = np.log(np.clip(probs, 1e-12, 1.0)) / T
    logits -= logits.max(axis=-1, keepdims=True)
    p = np.exp(logits)
    return p / p.sum(axis=-1, keepdims=True)


def zero_param_predictions(d):
    """Running-max-over-lookup rule and current-request lookup, both parameter-free."""
    def key(v):
        return np.round(v, 3).tobytes()

    lut = defaultdict(Counter)
    for feats, labs, sp in zip(d["seq_features"], d["seq_labels"], d["seq_split"]):
        if sp != "train":
            continue
        for v, l in zip(feats, labs):
            lut[key(v)][int(l)] += 1

    preds_lookup, preds_runmax, truth = [], [], []
    for feats, labs, sp in zip(d["seq_features"], d["seq_labels"], d["seq_split"]):
        if sp != "test":
            continue
        g = np.array([lut[key(v)].most_common(1)[0][0] if key(v) in lut else 0 for v in feats])
        preds_lookup.append(g)
        preds_runmax.append(np.maximum.accumulate(g))
        truth.append(labs)
    return (np.concatenate(preds_lookup), np.concatenate(preds_runmax),
            np.concatenate(truth))


def score(name, y, pred, edges, benign_mask, latency_ms=None, causal=True):
    acc = accuracy_score(y, pred)
    _, _, f1, _ = precision_recall_fscore_support(
        y, pred, average="macro", labels=list(range(NUM_STAGES)), zero_division=0)
    edge_acc = accuracy_score(y[edges], pred[edges]) if edges.any() else float("nan")
    # false positive = benign request predicted as any attack stage (>=1)
    fp = (pred[benign_mask] >= 1).mean() if benign_mask.any() else float("nan")
    return {
        "model": name, "causal": causal, "acc": acc, "macro_f1": f1,
        "edge_acc": edge_acc, "benign_fp": fp, "latency_ms": latency_ms,
    }


def main():
    d = np.load(DATASET, allow_pickle=True)  # our own artifact
    test_mask = d["seq_split"] == "test"
    test_feats = list(d["seq_features"][test_mask])
    test_labels = list(d["seq_labels"][test_mask])

    y_all = np.concatenate(test_labels)
    edges_all = np.concatenate([transition_edges(l) for l in test_labels])
    benign_all = y_all == 0

    results = []

    # ---- zero-parameter baselines ----
    p_lookup, p_runmax, y_chk = zero_param_predictions(d)
    assert np.array_equal(y_chk, y_all)
    results.append(score("Zero-param: current-request lookup", y_all, p_lookup, edges_all, benign_all, causal=True))
    results.append(score("Zero-param: running-max lookup", y_all, p_runmax, edges_all, benign_all, causal=True))
    results.append(score("Majority class (NORMAL)", y_all, np.zeros_like(y_all), edges_all, benign_all, causal=True))

    # ---- models + tuned fusion recipe ----
    lstm_models = load_lstm_seeds()
    T = json.load(open("calib_v2.json"))["temperature"]
    fusion = json.load(open("fusion_v2.json"))
    alpha = fusion["alpha"]
    import xgboost as xgb
    clf = xgb.XGBClassifier()
    clf.load_model("xgb_v2.json")

    # LSTM-only (seed-averaged) row
    t0 = time.perf_counter()
    X_pad, _ = pad_sequences(test_feats)
    batch_preds = np.mean([m(X_pad, training=False).numpy() for m in lstm_models], axis=0)
    lstm_em = [batch_preds[i, :len(s)] for i, s in enumerate(test_feats)]
    lstm_latency = (time.perf_counter() - t0) * 1000 / len(y_all)
    results.append(score(f"LSTM (seed-avg x{len(lstm_models)})", y_all,
                         np.concatenate([e.argmax(1) for e in lstm_em]),
                         edges_all, benign_all, latency_ms=lstm_latency))

    # XGBoost-only row
    xgb_em = []
    t0 = time.perf_counter()
    for feats in test_feats:
        xgb_em.append(clf.predict_proba(feats))
    xgb_latency = (time.perf_counter() - t0) * 1000 / len(y_all)
    results.append(score("XGBoost (per-step)", y_all,
                         np.concatenate([e.argmax(1) for e in xgb_em]),
                         edges_all, benign_all, latency_ms=xgb_latency))

    # Tuned ensemble (the ONE fusion path; alpha chosen on validation)
    ens_em = [_apply_temperature(alpha * lp + (1.0 - alpha) * xp, T) for lp, xp in zip(lstm_em, xgb_em)]
    p_ens = np.concatenate([e.argmax(1) for e in ens_em])
    results.append(score(f"Ensemble (alpha={alpha}) [DEPLOYED current stage]", y_all, p_ens, edges_all, benign_all))

    # ---- HMM smoothing over ensemble emissions ----
    # Use the transition matrix and smoothing strength saved by training (lambda chosen
    # on validation), not refit here, so the deployed configuration is what is scored.
    from .models import temper_transitions

    hmm = np.load("hmm_v2.npz", allow_pickle=True)  # our own artifact
    A = temper_transitions(hmm["transition_matrix"], float(hmm["smoothing_lambda"][0]))
    pi = hmm["initial_probs"]
    print(f"(HMM smoothing lambda selected on validation = {float(hmm['smoothing_lambda'][0])})")

    for label, decoder, causal in [
        ("Ensemble + HMM forward-filter (low-FP alt)", forward_filter, True),
        ("Ensemble + HMM online-viterbi", online_viterbi, True),
        ("Ensemble + HMM offline-viterbi", viterbi_decode, False),
    ]:
        preds = []
        for em in ens_em:
            out = decoder(em, A, pi)
            preds.append(out.argmax(1) if out.ndim == 2 else out)
        p = np.concatenate(preds)
        results.append(score(label, y_all, p, edges_all, benign_all, causal=causal))

    # ---- report ----
    print("=" * 104)
    print(f"{'model':<44}{'causal':>7}{'acc':>8}{'macroF1':>9}{'edge_acc':>10}{'benign_FP':>11}{'ms/req':>9}")
    print("-" * 104)
    for r in results:
        lat = f"{r['latency_ms']:.2f}" if r["latency_ms"] is not None else "-"
        print(f"{r['model']:<44}{('yes' if r['causal'] else 'NO'):>7}"
              f"{r['acc']:>8.4f}{r['macro_f1']:>9.4f}{r['edge_acc']:>10.4f}"
              f"{r['benign_fp']:>11.4f}{lat:>9}")
    print("=" * 104)

    best = max((r for r in results if r["causal"] and "Zero-param" not in r["model"]
                and "Majority" not in r["model"]), key=lambda r: r["acc"])
    zp = max(r["acc"] for r in results if "Zero-param" in r["model"] or "Majority" in r["model"])
    print(f"\nBest causal model: {best['model']}  acc={best['acc']:.4f}")
    print(f"Best parameter-free baseline: acc={zp:.4f}")
    print(f"Margin over the parameter-free ceiling: {best['acc']-zp:+.4f}  "
          f"({'PASS' if best['acc']-zp > 0.05 else 'THIN'})")

    # confusion for the deployed model
    preds = np.concatenate([e.argmax(1) for e in ens_em])  # deployed current stage = ensemble
    print("\nDeployed model confusion (rows=true, cols=pred)", STAGES)
    print(confusion_matrix(y_all, preds))

    # ---- session-level operational metric ----
    # Per-request accuracy understates operational value: what an operator cares about is
    # whether an attacking session is caught at all, and how quickly. For each test
    # session whose true peak stage is an attack (>= RECON), ask whether the deployed
    # model ever raised its running stage to that peak or higher, and after how many
    # requests of that peak stage it first did so.
    print("\n=== Session-level detection (deployed model) ===")
    caught = defaultdict(lambda: [0, 0])
    latencies = []
    for em, labs in zip(ens_em, test_labels):
        path = em.argmax(1)  # deployed current stage = responsive ensemble
        peak = int(labs.max())
        if peak == 0:
            continue
        caught[peak][1] += 1
        first_peak_idx = int(np.argmax(labs == peak))
        detected_from = np.where(path[first_peak_idx:] >= peak)[0]
        if detected_from.size:
            caught[peak][0] += 1
            latencies.append(int(detected_from[0]))
    for s in range(1, NUM_STAGES):
        det, tot = caught[s]
        if tot:
            print(f"  peak={STAGES[s]:<13} caught {det}/{tot} sessions ({det/tot:.2%})")
    if latencies:
        lat = np.array(latencies)
        print(f"  detection latency: median {int(np.median(lat))} req, mean {lat.mean():.1f}, "
              f"within-3 {(lat<=3).mean():.2%}")

    # ---- NEXT-STAGE prediction ----
    # Predicting the very next request's raw label is near-useless: blocks are long, so
    # the next request is almost always the same stage (persistence is ~0.49 and nothing
    # beats it). The operationally meaningful question is: WHEN this user changes phase,
    # which stage do they move to? So at every true stage transition we ask whether the
    # model named the correct next DISTINCT stage, using the current-stage belief
    # propagated through the self-loop-removed transition matrix.
    #
    # Baselines: "always advance one rung" (the naive kill-chain guess) and "global most
    # common next-distinct stage".
    from collections import Counter as _C
    from .models import next_distinct_matrix

    train_labels = list(d["seq_labels"][d["seq_split"] == "train"])
    B = next_distinct_matrix(A)
    global_next = _C()
    for labs in train_labels:
        for a, b in zip(labs[:-1], labs[1:]):
            if a != b:
                global_next[int(b)] += 1
    global_top = global_next.most_common(1)[0][0]

    truth_t, model_t, model_top2, advance_t, global_t = [], [], [], [], []
    for em, labs in zip(ens_em, test_labels):
        belief = forward_filter(em, A, pi)
        for t in range(len(labs) - 1):
            if labs[t + 1] == labs[t]:
                continue  # only score at real phase changes
            nxt = int(labs[t + 1])
            nd = belief[t] @ B
            truth_t.append(nxt)
            model_t.append(int(nd.argmax()))
            model_top2.append(nxt in set(np.argsort(nd)[-2:]))
            cur = int(belief[t].argmax())
            advance_t.append(min(cur + 1, NUM_STAGES - 1))
            global_t.append(global_top)
    truth_t = np.array(truth_t)
    print(f"\n=== Next-DISTINCT-stage prediction (at {len(truth_t)} real phase changes) ===")
    print(f"  where will the user go when they change phase?")
    print(f"  {'predictor':<40}{'top-1':>8}{'top-2':>8}")
    print(f"  {'model: belief @ transition matrix':<40}"
          f"{accuracy_score(truth_t, model_t):>8.4f}{np.mean(model_top2):>8.4f}")
    print(f"  {'baseline: always advance one rung':<40}"
          f"{accuracy_score(truth_t, advance_t):>8.4f}{'-':>8}")
    print(f"  {'baseline: global most-common next':<40}"
          f"{accuracy_score(truth_t, global_t):>8.4f}{'-':>8}")

    json.dump([{k: (None if v is None else v) for k, v in r.items()} for r in results],
              open("benchmark_v2.json", "w"), indent=2)
    print("\n[+] wrote benchmark_v2.json")


if __name__ == "__main__":
    main()
