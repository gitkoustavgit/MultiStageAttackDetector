"""
Train all models on dataset_v2.npz and save artifacts. CPU-friendly.

Saves:
  lstm_v2.weights.h5   LSTM weights ONLY (not a full .keras) -- rebuild the architecture
                       with models.build_lstm then load_weights, which is immune to the
                       Keras-version deserialization bug that stopped the old .keras from
                       loading. Architecture hyperparameters go in lstm_v2.arch.json.
  lstm_v2.arch.json    the exact build_lstm kwargs, so the weights can always be reloaded
  xgb_v2.json          XGBoost booster
  hmm_v2.npz           transition matrix + initial distribution
  calib_v2.json        temperature (fit on VALIDATION), with ECE before/after on val

Selection of every hyperparameter is done on the VALIDATION split. The test split is
never read here.
"""

from __future__ import annotations

import json
import os

import numpy as np

from .models import (
    NUM_STAGES,
    build_lstm,
    fit_transition_matrix,
    pad_labels,
    pad_sequences,
)

DATASET = "dataset_v2.npz"
LSTM_WEIGHTS = "lstm_v2.weights.h5"
LSTM_ARCH = "lstm_v2.arch.json"
XGB_PATH = "xgb_v2.json"
HMM_PATH = "hmm_v2.npz"
CALIB_PATH = "calib_v2.json"

SEED = 20260907
LSTM_ARCH_KWARGS = dict(units=64, layers_n=1, dropout=0.4, lr=1e-3,
                        recurrent_dropout=0.2, l2=1e-4)
WEIGHT_POWER = 0.5   # soften inverse-frequency weighting to curb benign false positives


def load():
    d = np.load(DATASET, allow_pickle=True)  # our own artifact from pipeline.dataset
    return d


def split_sequences(d, split):
    m = d["seq_split"] == split
    return list(d["seq_features"][m]), list(d["seq_labels"][m])


def class_weights(y_flat, power=WEIGHT_POWER):
    """Softened inverse-frequency weights, normalized to mean 1.

    Full inverse frequency (power=1) over-weights the rare attack classes so heavily
    that the model fires on benign traffic; power=0.5 keeps recall on rare stages while
    holding the benign false-positive rate down."""
    counts = np.bincount(y_flat, minlength=NUM_STAGES).astype(np.float64)
    inv = (counts.sum() / (NUM_STAGES * np.maximum(counts, 1))) ** power
    return inv / inv.mean()  # index by label


def make_weighted(labels_padded, mask, cw):
    w = mask.copy()
    for s in range(NUM_STAGES):
        w[labels_padded == s] *= cw[s]
    return (w * mask).astype(np.float32)  # zero out padding


def temperature_apply(probs, T):
    """Apply temperature T to probability arrays of any shape (..., NUM_STAGES)."""
    logits = np.log(np.clip(probs, 1e-12, 1.0)) / T
    logits -= logits.max(axis=-1, keepdims=True)
    p = np.exp(logits)
    return p / p.sum(axis=-1, keepdims=True)


def temperature_fit(logits, y, mask):
    """Fit scalar T minimizing masked NLL on validation emissions."""
    from scipy.optimize import minimize_scalar

    idx = mask.astype(bool)
    L = logits[idx]           # (N, S) log-probabilities
    yy = y[idx]

    def nll(T):
        z = L / max(T, 1e-3)
        z = z - z.max(axis=1, keepdims=True)
        p = np.exp(z)
        p /= p.sum(axis=1, keepdims=True)
        return -np.mean(np.log(p[np.arange(len(yy)), yy] + 1e-12))

    res = minimize_scalar(nll, bounds=(0.25, 5.0), method="bounded")
    return float(res.x)


def ece(probs, y, mask, n_bins=10):
    idx = mask.astype(bool)
    P = probs[idx]
    yy = y[idx]
    conf = P.max(axis=1)
    correct = (P.argmax(axis=1) == yy).astype(float)
    e = 0.0
    for i in range(n_bins):
        lo, hi = i / n_bins, (i + 1) / n_bins
        b = (conf > lo) & (conf <= hi)
        if b.any():
            e += abs(correct[b].mean() - conf[b].mean()) * b.mean()
    return float(e)


def main():
    import tensorflow as tf

    tf.random.set_seed(SEED)
    np.random.seed(SEED)

    d = load()
    Xtr_seq, ytr_seq = split_sequences(d, "train")
    Xva_seq, yva_seq = split_sequences(d, "validation")
    num_features = Xtr_seq[0].shape[1]

    max_len = max(max(len(s) for s in Xtr_seq), max(len(s) for s in Xva_seq))
    Xtr, mtr = pad_sequences(Xtr_seq, max_len)
    Xva, mva = pad_sequences(Xva_seq, max_len)
    ytr = pad_labels(ytr_seq, max_len)
    yva = pad_labels(yva_seq, max_len)

    cw = class_weights(d["flat_y"][d["flat_split"] == "train"])
    wtr = make_weighted(ytr, mtr, cw)
    wva = make_weighted(yva, mva, cw)
    print(f"class weights: {np.round(cw, 3).tolist()}")

    from tensorflow import keras

    print("\n=== Training sequence LSTM ===")
    model = build_lstm(num_features, **LSTM_ARCH_KWARGS)
    model.fit(
        Xtr, ytr,
        sample_weight=wtr,
        validation_data=(Xva, yva, wva),
        epochs=40,
        batch_size=32,
        callbacks=[keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=6, restore_best_weights=True)],
        verbose=2,
    )
    model.save_weights(LSTM_WEIGHTS)
    with open(LSTM_ARCH, "w") as f:
        json.dump({"num_features": num_features, **LSTM_ARCH_KWARGS}, f, indent=2)
    print(f"[+] saved {LSTM_WEIGHTS} and {LSTM_ARCH}")

    # ---- temperature calibration on VALIDATION ----
    print("\n=== Calibrating temperature on validation ===")
    val_probs = model.predict(Xva, verbose=0)
    val_logits = np.log(np.clip(val_probs, 1e-12, 1.0))
    T = temperature_fit(val_logits, yva, mva)
    z = val_logits / T
    z -= z.max(axis=2, keepdims=True)
    cal = np.exp(z)
    cal /= cal.sum(axis=2, keepdims=True)
    e_before, e_after = ece(val_probs, yva, mva), ece(cal, yva, mva)
    with open(CALIB_PATH, "w") as f:
        json.dump({"temperature": T, "ece_before_val": e_before,
                   "ece_after_val": e_after}, f, indent=2)
    print(f"[+] T={T:.4f}  val ECE {e_before:.4f} -> {e_after:.4f}")

    # ---- XGBoost on flat per-step features ----
    print("\n=== Training XGBoost ===")
    import xgboost as xgb

    Xf = d["flat_X"]; yf = d["flat_y"]; sf = d["flat_split"]
    Xtr_f, ytr_f = Xf[sf == "train"], yf[sf == "train"]
    Xva_f, yva_f = Xf[sf == "validation"], yf[sf == "validation"]
    sample_w = cw[ytr_f]
    clf = xgb.XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, min_child_weight=2,
        objective="multi:softprob", num_class=NUM_STAGES,
        eval_metric="mlogloss", random_state=SEED, n_jobs=-1,
        early_stopping_rounds=30,
    )
    clf.fit(Xtr_f, ytr_f, sample_weight=sample_w,
            eval_set=[(Xva_f, yva_f)], verbose=False)
    clf.save_model(XGB_PATH)
    print(f"[+] saved {XGB_PATH}  (best_iteration={clf.best_iteration})")

    # ---- HMM transitions from TRAIN label sequences ----
    print("\n=== Fitting HMM transitions ===")
    A, pi = fit_transition_matrix(ytr_seq, smoothing=1.0, max_self_transition=None)

    # Select smoothing strength on VALIDATION using the deployed ensemble emissions.
    # This lets the HMM only help: if the fitted matrix is too sticky for data that
    # transitions often, the grid picks a flatter (or fully uniform) prior.
    from .models import select_smoothing, temper_transitions

    val_lstm = temperature_apply(model.predict(Xva, verbose=0), T)
    ens_val, lab_val = [], []
    for feats, labs in zip(Xva_seq, yva_seq):
        n = len(labs)
        # LSTM emission for this session = the first n valid steps of its padded row
        idx = len(ens_val)
        lstm_em = val_lstm[idx][:n]
        xgb_em = clf.predict_proba(feats)
        ens_val.append(0.5 * lstm_em + 0.5 * xgb_em)
        lab_val.append(labs)
    best_lam, lam_scores = select_smoothing(ens_val, lab_val, A, pi)
    print(f"HMM smoothing selection on validation: {{{', '.join(f'{k}:{v:.4f}' for k,v in lam_scores.items())}}}")
    print(f"  chosen lambda (uniform mix) = {best_lam}")

    np.savez(HMM_PATH, transition_matrix=A, initial_probs=pi,
             stages=d["stages"], smoothing_lambda=np.array([best_lam]))
    print(f"[+] saved {HMM_PATH}")
    print("fitted transition matrix (rows=from,cols=to):")
    print(np.round(A, 3))
    print("effective (tempered) matrix used at inference:")
    print(np.round(temper_transitions(A, best_lam), 3))


if __name__ == "__main__":
    main()
