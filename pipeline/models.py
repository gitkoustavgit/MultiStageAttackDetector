"""
Model architecture and the causal decoders that fuse them.

THE ARCHITECTURE (why it is shaped this way)
--------------------------------------------
Three views of the same causal per-request feature stream:

  LSTM (sequence)   unidirectional, return_sequences=True -> one stage posterior per
                    timestep. Unidirectional is deliberate: a live detector cannot see
                    future requests, so a bidirectional model would report offline
                    scores it can never reproduce in production.

  XGBoost (per-row) treats each request independently, but the request's feature vector
                    already carries causal rolling context (recent diversity, error
                    rate, decaying attack pressure), so the tree model still sees
                    "what just happened" without any sequence machinery.

  HMM (transitions) a supervised transition matrix over the five stages, estimated by
                    counting real stage-to-stage moves in the composed training
                    sessions. It encodes how sessions actually move now -- including the
                    down-the-chain retreats that the old always-escalating data never
                    contained.

FUSION
------
Emissions from LSTM and XGBoost are blended, then smoothed by the HMM using a CAUSAL
forward filter (sum-product): the posterior at step t uses only steps 1..t. This is the
online-safe smoother. A max-product Viterbi is also provided but only for offline
analysis -- its backward pass uses future steps, so it must never be quoted as a live
number. The audit found the old repo's headline "hybrid" score came from exactly that
non-causal Viterbi, while the deployed online version was actually worse than no HMM.
Forward filtering fixes that: it is both causal and soft, so it does not lock in early.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import numpy as np

NUM_STAGES = 5
PAD_SENTINEL = -10.0   # no real feature is ever negative (flags 0/1, log>=0), so safe


def _apply_temperature(probs: np.ndarray, T: float) -> np.ndarray:
    logits = np.log(np.clip(probs, 1e-12, 1.0)) / T
    logits -= logits.max(axis=-1, keepdims=True)
    e = np.exp(logits)
    return e / e.sum(axis=-1, keepdims=True)


def ensemble_emissions(lstm_models, xgb_clf, feats: np.ndarray,
                       alpha: float, temperature: float) -> np.ndarray:
    """
    THE ONE fusion path, shared by training selection, evaluation and live inference so
    they can never drift. Given a session's causal feature matrix (T, F):

      * average the softmax of every LSTM seed (seed-averaging reduces the run-to-run
        variance of a single CPU-trained LSTM and usually lifts accuracy a little),
      * blend with XGBoost's per-step probabilities by weight `alpha`
        (alpha=1 -> LSTM only, alpha=0 -> XGBoost only; tuned on validation),
      * temperature-calibrate the result.

    Returns calibrated emissions (T, NUM_STAGES).
    """
    feats = np.asarray(feats, dtype=np.float32)
    lstm_p = np.zeros((len(feats), NUM_STAGES), dtype=np.float64)
    for m in lstm_models:
        lstm_p += m(feats[None, :, :], training=False).numpy()[0]
    lstm_p /= max(1, len(lstm_models))
    xgb_p = xgb_clf.predict_proba(feats)
    ens = alpha * lstm_p + (1.0 - alpha) * xgb_p
    return _apply_temperature(ens, temperature)


# ---- LSTM -----------------------------------------------------------------------

def build_lstm(num_features: int, units: int = 64, layers_n: int = 1,
               dropout: float = 0.4, lr: float = 1e-3, recurrent_dropout: float = 0.2,
               l2: float = 1e-4):
    """Stacked unidirectional LSTM, sequence-to-sequence over stage labels.

    Regularized (L2 on recurrent/kernel weights, dropout, recurrent dropout) because the
    composed sessions reuse blocks from a limited set of real capture files, so an
    unregularized net memorizes training sessions and does not transfer to the disjoint
    validation/test files."""
    from tensorflow import keras
    from tensorflow.keras import layers, regularizers

    reg = regularizers.l2(l2)
    inp = keras.Input(shape=(None, num_features))
    x = layers.Masking(mask_value=PAD_SENTINEL)(inp)
    for i in range(layers_n):
        x = layers.LSTM(
            units,
            return_sequences=True,
            recurrent_dropout=recurrent_dropout,
            kernel_regularizer=reg,
            recurrent_regularizer=reg,
        )(x)
        x = layers.Dropout(dropout)(x)
    x = layers.TimeDistributed(layers.Dense(48, activation="relu", kernel_regularizer=reg))(x)
    out = layers.TimeDistributed(layers.Dense(NUM_STAGES, activation="softmax"))(x)
    model = keras.Model(inp, out)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
        weighted_metrics=["accuracy"],
    )
    return model


def pad_sequences(seqs: List[np.ndarray], max_len: Optional[int] = None):
    """Right-pad variable-length feature matrices to a common length with the sentinel."""
    if max_len is None:
        max_len = max(len(s) for s in seqs)
    f = seqs[0].shape[1]
    X = np.full((len(seqs), max_len, f), PAD_SENTINEL, dtype=np.float32)
    mask = np.zeros((len(seqs), max_len), dtype=np.float32)
    for i, s in enumerate(seqs):
        t = min(len(s), max_len)
        X[i, :t] = s[:t]
        mask[i, :t] = 1.0
    return X, mask


def pad_labels(label_seqs: List[np.ndarray], max_len: int):
    y = np.zeros((len(label_seqs), max_len), dtype=np.int64)
    for i, l in enumerate(label_seqs):
        t = min(len(l), max_len)
        y[i, :t] = l[:t]
    return y


# ---- HMM transitions ------------------------------------------------------------

def fit_transition_matrix(
    label_sequences: List[np.ndarray],
    smoothing: float = 1.0,
    max_self_transition: Optional[float] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """Supervised transition + initial distributions from observed stage sequences."""
    counts = np.full((NUM_STAGES, NUM_STAGES), smoothing, dtype=np.float64)
    init = np.full(NUM_STAGES, smoothing, dtype=np.float64)
    for seq in label_sequences:
        if len(seq) == 0:
            continue
        init[seq[0]] += 1
        for a, b in zip(seq[:-1], seq[1:]):
            counts[a, b] += 1
    A = counts / counts.sum(axis=1, keepdims=True)
    pi = init / init.sum()
    if max_self_transition is not None and max_self_transition < 1.0:
        for i in range(NUM_STAGES):
            if A[i, i] > max_self_transition:
                excess = A[i, i] - max_self_transition
                A[i, i] = max_self_transition
                others = [j for j in range(NUM_STAGES) if j != i]
                A[i, others] += excess / len(others)
    return A, pi


def next_distinct_matrix(A: np.ndarray) -> np.ndarray:
    """
    Turn a transition matrix into P(next DISTINCT stage | current stage) by removing the
    self-loop and renormalizing each row.

    Predicting the next request's raw label is near-useless because blocks are long, so
    the next request is almost always the same stage ("persistence"). The operationally
    meaningful forecast is: when this user changes phase, which stage do they move to?
    That is exactly this matrix, applied to the current-stage belief.
    """
    B = A.copy().astype(np.float64)
    np.fill_diagonal(B, 0.0)
    rs = B.sum(axis=1, keepdims=True)
    rs[rs == 0] = 1.0
    return B / rs


def temper_transitions(A: np.ndarray, lam: float) -> np.ndarray:
    """
    Mix the fitted transition matrix toward uniform: A' = (1-lam)*A + lam*U.

    lam=0 keeps the fitted (sticky) matrix; lam=1 makes transitions uniform, which
    lets the emission model speak for itself. The right amount of smoothing is chosen
    on validation (select_smoothing) rather than assumed, because on data that
    transitions often a sticky prior fights the truth and hurts edge accuracy.
    """
    if lam <= 0:
        return A
    U = np.full_like(A, 1.0 / A.shape[1])
    out = (1 - lam) * A + lam * U
    return out / out.sum(axis=1, keepdims=True)


def select_smoothing(emission_seqs, label_seqs, A, pi,
                     grid=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0)):
    """Pick the uniform-mixing lambda that maximizes forward-filter accuracy on a
    held-out (validation) set. Returns (best_lambda, {lambda: accuracy})."""
    from sklearn.metrics import accuracy_score

    scores = {}
    for lam in grid:
        A_t = temper_transitions(A, lam)
        preds, truth = [], []
        for em, lab in zip(emission_seqs, label_seqs):
            preds.append(forward_filter(em, A_t, pi).argmax(1))
            truth.append(lab)
        scores[lam] = accuracy_score(np.concatenate(truth), np.concatenate(preds))
    best = max(scores, key=scores.get)
    return best, scores


# ---- decoders -------------------------------------------------------------------

def forward_filter(emissions: np.ndarray, A: np.ndarray, pi: np.ndarray) -> np.ndarray:
    """
    CAUSAL online posterior. Returns (T, S) filtered distributions p(s_t | x_1..t).

    alpha_1 = pi * e_1;  alpha_t propto e_t * (alpha_{t-1} @ A). Normalized each step to
    stay a probability and avoid underflow. This is exactly what an online detector can
    compute at request t, and it is what the live predictor runs.
    """
    eps = 1e-12
    T, S = emissions.shape
    out = np.zeros((T, S))
    alpha = pi * (emissions[0] + eps)
    alpha /= alpha.sum()
    out[0] = alpha
    for t in range(1, T):
        alpha = (emissions[t] + eps) * (alpha @ A)
        alpha /= alpha.sum()
        out[t] = alpha
    return out


def viterbi_decode(emissions: np.ndarray, A: np.ndarray, pi: np.ndarray) -> np.ndarray:
    """OFFLINE max-product path. Uses a backward pass over future steps -- not causal.
    Provided for analysis only; never quote as a live score."""
    eps = 1e-12
    T, S = emissions.shape
    logE = np.log(emissions + eps)
    logA = np.log(A + eps)
    logp = np.zeros((T, S))
    back = np.zeros((T, S), dtype=int)
    logp[0] = np.log(pi + eps) + logE[0]
    for t in range(1, T):
        for s in range(S):
            scores = logp[t - 1] + logA[:, s]
            back[t, s] = int(np.argmax(scores))
            logp[t, s] = scores.max() + logE[t, s]
    path = np.zeros(T, dtype=int)
    path[-1] = int(np.argmax(logp[-1]))
    for t in range(T - 2, -1, -1):
        path[t] = back[t + 1, path[t + 1]]
    return path


def online_viterbi(emissions: np.ndarray, A: np.ndarray, pi: np.ndarray) -> np.ndarray:
    """CAUSAL max-product (greedy argmax of the running max-product score). Kept for
    comparison with the forward filter."""
    eps = 1e-12
    T, S = emissions.shape
    logA = np.log(A + eps)
    logp = np.log(pi + eps) + np.log(emissions[0] + eps)
    out = [int(np.argmax(logp))]
    for t in range(1, T):
        logp = (logp[:, None] + logA).max(axis=0) + np.log(emissions[t] + eps)
        out.append(int(np.argmax(logp)))
    return np.array(out)
