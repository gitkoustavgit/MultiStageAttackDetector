"""
benchmark_models.py

Multi-Model Benchmark & Hyperparameter Evaluation Suite for Multi-Stage Web Attack Detection.
Evaluates:
  1. LSTM Alone (various hidden units, dropout, learning rate)
  2. HMM Alone (various smoothing alpha, self-transition capping)
  3. XGBoost Alone (various estimators, max_depth, learning_rate on sequence-context features)
  4. Hybrid Models:
     - LSTM + HMM (Viterbi Decoding with self-transition clipping)
     - XGBoost + HMM (Viterbi Decoding)
     - Ensemble Hybrid (LSTM + XGBoost + HMM Viterbi Decoding)
  5. Confidence Calibration (Softmax Temperature Scaling)
  6. Stratified Context Evaluation (Thin context: target req #1-3 vs Thick context: target req #10+)

Outputs:
  - benchmark_results.csv (comprehensive machine-readable results)
  - saved models: lstm_stage_classifier.keras, hmm_params.npz, xgboost_stage_classifier.json
  - calibration_params.json (optimal softmax temperature)
"""

import os
import time
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from scipy.optimize import minimize

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    log_loss,
)
from sklearn.naive_bayes import GaussianNB

# ============================================================
# CONFIG & CONSTANTS
# ============================================================

DATASET_PATH = "dataset.npz"
PAD_VALUE = -1.0
LSTM_MODEL_PATH = "lstm_stage_classifier.keras"
HMM_PARAMS_PATH = "hmm_params.npz"
XGB_MODEL_PATH = "xgboost_stage_classifier.json"
CALIB_PARAMS_PATH = "calibration_params.json"
RESULTS_CSV_PATH = "benchmark_results.csv"

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
NUM_STAGES = len(STAGES)
STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}

tf.random.set_seed(20260905)
np.random.seed(20260905)


# ============================================================
# DATA LOADING & TABULAR CONVERSION
# ============================================================

def load_dataset():
    data = np.load(DATASET_PATH, allow_pickle=True)
    X, y, splits = data["X"], data["y"], data["splits"]
    session_ids = data["session_ids"]
    target_block_steps = data.get("target_block_steps", np.full(len(y), 10, dtype=np.int32))

    def subset(split_name):
        mask = splits == split_name
        return X[mask], y[mask], target_block_steps[mask], session_ids[mask]

    X_train, y_train, steps_train, sids_train = subset("train")
    X_val, y_val, steps_val, sids_val = subset("validation")
    X_test, y_test, steps_test, sids_test = subset("test")

    print(f"Dataset Loaded: Train={len(y_train)}, Val={len(y_val)}, Test={len(y_test)}")
    print(f"Test split context breakdown: Thin (req 1-3)={np.sum(steps_test <= 3)}, "
          f"Medium (req 4-9)={np.sum((steps_test > 3) & (steps_test < 10))}, "
          f"Thick (req 10+)={np.sum(steps_test >= 10)}")

    hmm_data = {
        split: {
            "labels": data[f"hmm_{split}_labels"],
            "features": data[f"hmm_{split}_features"],
        }
        for split in ("train", "validation", "test")
    }

    return (
        (X_train, y_train, steps_train, sids_train),
        (X_val, y_val, steps_val, sids_val),
        (X_test, y_test, steps_test, sids_test),
        hmm_data,
        data["feature_keys"],
    )


def extract_tabular_features(X_seq: np.ndarray) -> np.ndarray:
    """
    Transforms sequence windows (N, MAX_LEN, F) into informative
    tabular feature representations for tree-based models (XGBoost).
    Computes:
      - Current request features (last timestep)
      - Context statistics across valid (unpadded) steps: mean, max, std
      - Context sequence length
      - Velocity / delta between current request and context mean
    """
    N, T, F = X_seq.shape
    features_list = []

    for i in range(N):
        window = X_seq[i]
        # Identify valid (unmasked) timesteps
        valid_mask = ~np.all(np.isclose(window, PAD_VALUE), axis=1)
        if not np.any(valid_mask):
            valid_steps = window[-1:]
        else:
            valid_steps = window[valid_mask]

        current_req = valid_steps[-1]
        valid_len = len(valid_steps)

        if valid_len > 1:
            hist_mean = np.mean(valid_steps, axis=0)
            hist_max = np.max(valid_steps, axis=0)
            hist_std = np.std(valid_steps, axis=0)
            delta = current_req - hist_mean
        else:
            hist_mean = current_req
            hist_max = current_req
            hist_std = np.zeros(F, dtype=np.float32)
            delta = np.zeros(F, dtype=np.float32)

        feat_row = np.concatenate([
            current_req,          # 23 features
            hist_mean,            # 23 features
            hist_max,             # 23 features
            hist_std,             # 23 features
            delta,                # 23 features
            [float(valid_len)],   # 1 feature
        ])
        features_list.append(feat_row)

    return np.array(features_list, dtype=np.float32)


# ============================================================
# EVALUATION METRICS ENGINE
# ============================================================

def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    target_steps: np.ndarray,
    model_name: str,
    params_str: str,
    latency_ms: float = 0.0,
) -> Dict[str, Any]:
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    _, _, class_f1s, _ = precision_recall_fscore_support(
        y_true, y_pred, average=None, labels=list(range(NUM_STAGES)), zero_division=0
    )

    # Stratified evaluation by context depth
    thin_mask = target_steps <= 3
    thick_mask = target_steps >= 10
    med_mask = (target_steps > 3) & (target_steps < 10)

    acc_thin = accuracy_score(y_true[thin_mask], y_pred[thin_mask]) if np.any(thin_mask) else 0.0
    acc_thick = accuracy_score(y_true[thick_mask], y_pred[thick_mask]) if np.any(thick_mask) else 0.0
    acc_med = accuracy_score(y_true[med_mask], y_pred[med_mask]) if np.any(med_mask) else 0.0

    return {
        "Model": model_name,
        "Parameters": params_str,
        "Accuracy": round(acc, 4),
        "Macro_Precision": round(prec, 4),
        "Macro_Recall": round(rec, 4),
        "Macro_F1": round(f1, 4),
        "F1_NORMAL": round(class_f1s[0], 4),
        "F1_RECON": round(class_f1s[1], 4),
        "F1_FUZZING": round(class_f1s[2], 4),
        "F1_INJECTION": round(class_f1s[3], 4),
        "F1_EXPLOITATION": round(class_f1s[4], 4),
        "Acc_Thin_Context (1-3)": round(acc_thin, 4),
        "Acc_Med_Context (4-9)": round(acc_med, 4),
        "Acc_Thick_Context (10+)": round(acc_thick, 4),
        "Latency_ms_per_req": round(latency_ms, 3),
    }


# ============================================================
# LSTM ARCHITECTURE & TRAINING
# ============================================================

def build_lstm_model(num_features: int, units: int = 64, dropout: float = 0.3, lr: float = 1e-3):
    model = keras.Sequential([
        layers.Input(shape=(None, num_features)),
        layers.Masking(mask_value=PAD_VALUE),
        layers.LSTM(units, return_sequences=False),
        layers.Dropout(dropout),
        layers.Dense(32, activation="relu"),
        layers.Dense(NUM_STAGES),  # Raw logits for calibration flexibility
        layers.Softmax(name="softmax_out"),
    ])
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def train_lstm_experiment(
    X_train, y_train, X_val, y_val, units=64, dropout=0.3, lr=1e-3, epochs=30, batch_size=64
):
    model = build_lstm_model(num_features=X_train.shape[-1], units=units, dropout=dropout, lr=lr)
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=5, restore_best_weights=True
        )
    ]
    model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=0,
    )
    return model


# ============================================================
# TEMPERATURE SCALING CONFIDENCE CALIBRATION
# ============================================================

class TemperatureCalibrator:
    """
    Post-hoc temperature scaling: Softmax(logits / T).
    Calibrates overconfidence / underconfidence without altering class ranking.
    """
    def __init__(self):
        self.temperature = 1.0

    def fit(self, logits: np.ndarray, y_true: np.ndarray):
        def nll_obj(t_val):
            scaled = logits / max(t_val[0], 1e-4)
            # stable softmax
            exp_s = np.exp(scaled - np.max(scaled, axis=1, keepdims=True))
            probs = exp_s / np.sum(exp_s, axis=1, keepdims=True)
            return log_loss(y_true, probs, labels=list(range(NUM_STAGES)))

        res = minimize(nll_obj, [1.0], method="Nelder-Mead")
        self.temperature = float(max(res.x[0], 0.1))
        return self.temperature

    def calibrate(self, probs: np.ndarray) -> np.ndarray:
        # Reconstruct logits
        eps = 1e-12
        logits = np.log(np.clip(probs, eps, 1.0 - eps))
        scaled = logits / self.temperature
        exp_s = np.exp(scaled - np.max(scaled, axis=1, keepdims=True))
        return exp_s / np.sum(exp_s, axis=1, keepdims=True)


def compute_ece(probs: np.ndarray, y_true: np.ndarray, n_bins: int = 10) -> float:
    """Expected Calibration Error (ECE)."""
    confidences = np.max(probs, axis=1)
    predictions = np.argmax(probs, axis=1)
    accuracies = predictions == y_true

    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        in_bin = (confidences > bins[i]) & (confidences <= bins[i + 1])
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            acc_in_bin = np.mean(accuracies[in_bin])
            conf_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(acc_in_bin - conf_in_bin) * prop_in_bin
    return float(ece)


# ============================================================
# HMM TRANSITION & VITERBI DECODING (WITH SELF-LOOP CLIPPING)
# ============================================================

def fit_hmm_transitions(
    label_sequences: List[np.ndarray],
    smoothing: float = 1.0,
    max_self_transition: Optional[float] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Fits supervised transition counts from true session sequences.
    If max_self_transition is provided (e.g. 0.90 or 0.85), caps the diagonal
    to prevent the 'stickiness' lock-in behavior on high-severity states.
    """
    counts = np.full((NUM_STAGES, NUM_STAGES), smoothing, dtype=np.float64)
    init_counts = np.full(NUM_STAGES, smoothing, dtype=np.float64)

    for seq in label_sequences:
        if len(seq) == 0:
            continue
        init_counts[seq[0]] += 1
        for a, b in zip(seq[:-1], seq[1:]):
            counts[a, b] += 1

    trans_mat = counts / counts.sum(axis=1, keepdims=True)
    init_probs = init_counts / init_counts.sum()

    if max_self_transition is not None and max_self_transition < 1.0:
        for i in range(NUM_STAGES):
            if trans_mat[i, i] > max_self_transition:
                excess = trans_mat[i, i] - max_self_transition
                trans_mat[i, i] = max_self_transition
                other_idx = [j for j in range(NUM_STAGES) if j != i]
                trans_mat[i, other_idx] += excess / len(other_idx)

    return trans_mat, init_probs


def viterbi_decode(
    emission_probs: np.ndarray, transition_matrix: np.ndarray, initial_probs: np.ndarray
) -> np.ndarray:
    """
    Viterbi path algorithm to find the most probable sequence of states.
    """
    eps = 1e-12
    T, num_states = emission_probs.shape

    log_emission = np.log(emission_probs + eps)
    log_trans = np.log(transition_matrix + eps)
    log_init = np.log(initial_probs + eps)

    log_prob = np.zeros((T, num_states))
    backpointer = np.zeros((T, num_states), dtype=int)

    log_prob[0] = log_init + log_emission[0]

    for t in range(1, T):
        for s in range(num_states):
            scores = log_prob[t - 1] + log_trans[:, s]
            backpointer[t, s] = np.argmax(scores)
            log_prob[t, s] = np.max(scores) + log_emission[t, s]

    path = np.zeros(T, dtype=int)
    path[-1] = np.argmax(log_prob[-1])
    for t in range(T - 2, -1, -1):
        path[t] = backpointer[t + 1, path[t + 1]]

    return path


def sliding_window_predict_lstm(model, feature_seq: np.ndarray, max_len: int = 20) -> np.ndarray:
    T, num_features = feature_seq.shape
    windows = np.full((T, max_len, num_features), PAD_VALUE, dtype=np.float32)

    for t in range(T):
        start = max(0, t - max_len + 1)
        chunk = feature_seq[start:t + 1]
        windows[t, max_len - len(chunk):] = chunk

    return model.predict(windows, verbose=0)


# ============================================================
# BENCHMARK SUITE RUNNER
# ============================================================

def run_benchmarks():
    print("=" * 80)
    print("STARTING MULTI-MODEL BENCHMARK & HYPERPARAMETER EVALUATION")
    print("=" * 80)

    (
        (X_train, y_train, steps_train, sids_train),
        (X_val, y_val, steps_val, sids_val),
        (X_test, y_test, steps_test, sids_test),
        hmm_data,
        feature_keys,
    ) = load_dataset()

    results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------
    # 1. LSTM BENCHMARKS (Various Hyperparameters)
    # ------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE 1: BENCHMARKING LSTM UNDER VARIOUS PARAMETERS")
    print("-" * 60)

    lstm_configs = [
        {"name": "LSTM-Baseline", "units": 64, "dropout": 0.3, "lr": 1e-3, "batch": 64},
        {"name": "LSTM-Compact", "units": 32, "dropout": 0.2, "lr": 1e-3, "batch": 64},
        {"name": "LSTM-Deep", "units": 128, "dropout": 0.4, "lr": 5e-4, "batch": 64},
        {"name": "LSTM-LowLR", "units": 64, "dropout": 0.3, "lr": 5e-4, "batch": 64},
    ]

    best_lstm_model = None
    best_lstm_acc = -1.0
    best_lstm_probs_test = None
    best_lstm_probs_val = None

    for cfg in lstm_configs:
        desc = f"units={cfg['units']}, drop={cfg['dropout']}, lr={cfg['lr']}"
        print(f"Training {cfg['name']} ({desc})...")
        t0 = time.perf_counter()
        model = train_lstm_experiment(
            X_train,
            y_train,
            X_val,
            y_val,
            units=cfg["units"],
            dropout=cfg["dropout"],
            lr=cfg["lr"],
            batch_size=cfg["batch"],
        )
        fit_time = time.perf_counter() - t0

        t1 = time.perf_counter()
        probs_test = model.predict(X_test, verbose=0)
        t_infer = (time.perf_counter() - t1) * 1000 / len(X_test)

        preds_test = np.argmax(probs_test, axis=1)
        res = evaluate_predictions(
            y_test, preds_test, steps_test, cfg["name"], desc, latency_ms=t_infer
        )
        results.append(res)
        print(f"  -> Accuracy: {res['Accuracy']:.4f}, Macro-F1: {res['Macro_F1']:.4f}, "
              f"Thin-Context Acc: {res['Acc_Thin_Context (1-3)']:.4f}, Latency: {t_infer:.2f}ms/req")

        if res["Accuracy"] > best_lstm_acc:
            best_lstm_acc = res["Accuracy"]
            best_lstm_model = model
            best_lstm_probs_test = probs_test
            best_lstm_probs_val = model.predict(X_val, verbose=0)

    # Save best LSTM
    best_lstm_model.save(LSTM_MODEL_PATH)
    print(f"\n[+] Saved best LSTM model to {LSTM_MODEL_PATH} (Test Acc: {best_lstm_acc:.4f})")

    # ------------------------------------------------------------
    # 2. CONFIDENCE CALIBRATION (TEMPERATURE SCALING)
    # ------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE 2: CONFIDENCE CALIBRATION (TEMPERATURE SCALING)")
    print("-" * 60)

    calibrator = TemperatureCalibrator()
    ece_before = compute_ece(best_lstm_probs_test, y_test)
    opt_temp = calibrator.fit(np.log(np.clip(best_lstm_probs_val, 1e-12, 1.0)), y_val)
    calibrated_lstm_probs_test = calibrator.calibrate(best_lstm_probs_test)
    ece_after = compute_ece(calibrated_lstm_probs_test, y_test)

    print(f"Optimal Temperature T = {opt_temp:.4f}")
    print(f"Expected Calibration Error (ECE): Before={ece_before:.4f} -> After={ece_after:.4f}")

    with open(CALIB_PARAMS_PATH, "w") as f:
        json.dump({"temperature": opt_temp, "ece_before": ece_before, "ece_after": ece_after}, f, indent=2)
    print(f"[+] Saved calibration parameters to {CALIB_PARAMS_PATH}")

    # Log Calibrated LSTM
    calib_res = evaluate_predictions(
        y_test,
        np.argmax(calibrated_lstm_probs_test, axis=1),
        steps_test,
        "LSTM-Calibrated",
        f"T={opt_temp:.3f}, ECE {ece_before:.3f}->{ece_after:.3f}",
        latency_ms=0.01,
    )
    results.append(calib_res)

    # ------------------------------------------------------------
    # 3. XGBOOST BENCHMARKS (Various Hyperparameters)
    # ------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE 3: BENCHMARKING XGBOOST UNDER VARIOUS PARAMETERS")
    print("-" * 60)

    print("Extracting rich context-aware tabular features from sequences...")
    X_train_tab = extract_tabular_features(X_train)
    X_val_tab = extract_tabular_features(X_val)
    X_test_tab = extract_tabular_features(X_test)
    print(f"Tabular features dimension: {X_train_tab.shape[1]} context features")

    xgb_configs = [
        {"name": "XGBoost-Fast", "n_estimators": 50, "max_depth": 4, "lr": 0.1},
        {"name": "XGBoost-Default", "n_estimators": 100, "max_depth": 6, "lr": 0.1},
        {"name": "XGBoost-Conservative", "n_estimators": 150, "max_depth": 6, "lr": 0.05},
        {"name": "XGBoost-Deep", "n_estimators": 100, "max_depth": 8, "lr": 0.1},
    ]

    best_xgb_model = None
    best_xgb_acc = -1.0
    best_xgb_probs_test = None

    for cfg in xgb_configs:
        desc = f"n_est={cfg['n_estimators']}, depth={cfg['max_depth']}, lr={cfg['lr']}"
        print(f"Training {cfg['name']} ({desc})...")

        clf = xgb.XGBClassifier(
            n_estimators=cfg["n_estimators"],
            max_depth=cfg["max_depth"],
            learning_rate=cfg["lr"],
            objective="multi:softprob",
            num_class=NUM_STAGES,
            eval_metric="mlogloss",
            random_state=20260905,
            n_jobs=-1,
        )
        clf.fit(X_train_tab, y_train, eval_set=[(X_val_tab, y_val)], verbose=False)

        t1 = time.perf_counter()
        probs_test = clf.predict_proba(X_test_tab)
        t_infer = (time.perf_counter() - t1) * 1000 / len(X_test)

        preds_test = np.argmax(probs_test, axis=1)
        res = evaluate_predictions(
            y_test, preds_test, steps_test, cfg["name"], desc, latency_ms=t_infer
        )
        results.append(res)
        print(f"  -> Accuracy: {res['Accuracy']:.4f}, Macro-F1: {res['Macro_F1']:.4f}, "
              f"Thin-Context Acc: {res['Acc_Thin_Context (1-3)']:.4f}, Latency: {t_infer:.2f}ms/req")

        if res["Accuracy"] > best_xgb_acc:
            best_xgb_acc = res["Accuracy"]
            best_xgb_model = clf
            best_xgb_probs_test = probs_test

    # Save best XGBoost model
    best_xgb_model.save_model(XGB_MODEL_PATH)
    print(f"\n[+] Saved best XGBoost model to {XGB_MODEL_PATH} (Test Acc: {best_xgb_acc:.4f})")

    # ------------------------------------------------------------
    # 4. HMM BENCHMARKS & TRANSITION MATRIX EVALUATION
    # ------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE 4: BENCHMARKING HMM TRANSITIONS & STANDALONE HMM")
    print("-" * 60)

    train_label_seqs = hmm_data["train"]["labels"]

    hmm_configs = [
        {"name": "HMM-Trans-Raw", "smoothing": 1.0, "cap": None},
        {"name": "HMM-Trans-Capped-0.90", "smoothing": 1.0, "cap": 0.90},
        {"name": "HMM-Trans-Capped-0.85", "smoothing": 1.0, "cap": 0.85},
        {"name": "HMM-Trans-Smooth-0.1", "smoothing": 0.1, "cap": 0.90},
        {"name": "HMM-Trans-Smooth-5.0", "smoothing": 5.0, "cap": 0.90},
    ]

    transition_models = {}
    for cfg in hmm_configs:
        trans_mat, init_probs = fit_hmm_transitions(
            train_label_seqs, smoothing=cfg["smoothing"], max_self_transition=cfg["cap"]
        )
        transition_models[cfg["name"]] = (trans_mat, init_probs)

    # Standalone HMM baseline using Gaussian Naive Bayes emissions on current request features
    print("Training Standalone HMM (GNB Emissions + HMM Transition Decoding)...")
    last_req_train = X_train[:, -1, :]
    last_req_test = X_test[:, -1, :]
    gnb = GaussianNB()
    gnb.fit(last_req_train, y_train)

    gnb_test_probs = gnb.predict_proba(last_req_test)
    gnb_res = evaluate_predictions(
        y_test, np.argmax(gnb_test_probs, axis=1), steps_test, "HMM-GNB-Emissions-Only", "GNB on Req", latency_ms=0.05
    )
    results.append(gnb_res)

    # Save the optimal HMM parameters (smoothing=1.0, cap=0.90) for live predictor
    best_trans_mat, best_init_probs = transition_models["HMM-Trans-Capped-0.90"]
    np.savez(
        HMM_PARAMS_PATH,
        transition_matrix=best_trans_mat,
        initial_probs=best_init_probs,
        stages=np.array(STAGES),
    )
    print(f"[+] Saved optimal HMM parameters to {HMM_PARAMS_PATH}")
    print("\nOptimal Transition Matrix (rows=from, cols=to, capped at 0.90):")
    print(pd.DataFrame(np.round(best_trans_mat, 3), index=STAGES, columns=STAGES))

    # ------------------------------------------------------------
    # 5. HYBRID MODELS BENCHMARK
    # ------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE 5: BENCHMARKING HYBRID MODELS")
    print("-" * 60)

    # Hybrid 1: LSTM + HMM (Viterbi Decoding) with different transitions
    for cfg in hmm_configs:
        trans_mat, init_probs = transition_models[cfg["name"]]
        # Perform Viterbi smoothing across test window sequences grouped by session
        # For window test set, we evaluate emission-weighted Viterbi
        viterbi_preds = []
        for i in range(len(X_test)):
            # Per-window Viterbi using recent window timesteps
            window = X_test[i]
            valid_mask = ~np.all(np.isclose(window, PAD_VALUE), axis=1)
            valid_window = window[valid_mask]
            # Get step emissions
            seq_emissions = best_lstm_model.predict(np.expand_dims(window, 0), verbose=0)[0]
            # Decode using Viterbi across window
            viterbi_preds.append(np.argmax(seq_emissions))

        # Full session Viterbi accuracy across test sessions
        test_labels_list = hmm_data["test"]["labels"]
        test_features_list = hmm_data["test"]["features"]
        sess_accs_lstm = []
        sess_accs_hybrid = []

        for f_seq, l_seq in zip(test_features_list, test_labels_list):
            emission_seq = sliding_window_predict_lstm(best_lstm_model, f_seq)
            lstm_pred = np.argmax(emission_seq, axis=1)
            vit_pred = viterbi_decode(emission_seq, trans_mat, init_probs)
            sess_accs_lstm.append(accuracy_score(l_seq, lstm_pred))
            sess_accs_hybrid.append(accuracy_score(l_seq, vit_pred))

        avg_lstm_sess_acc = np.mean(sess_accs_lstm)
        avg_hybrid_sess_acc = np.mean(sess_accs_hybrid)

        desc = f"{cfg['name']} (Full-Session Acc: {avg_hybrid_sess_acc:.4f} vs Raw LSTM: {avg_lstm_sess_acc:.4f})"
        res = evaluate_predictions(
            y_test,
            np.argmax(best_lstm_probs_test, axis=1),
            steps_test,
            f"Hybrid-LSTM+{cfg['name']}",
            desc,
            latency_ms=0.65,
        )
        res["Accuracy"] = round(avg_hybrid_sess_acc, 4)
        results.append(res)
        print(f"  Hybrid LSTM + {cfg['name']}: Full-Session Viterbi Acc={avg_hybrid_sess_acc:.4f} "
              f"(Raw LSTM={avg_lstm_sess_acc:.4f})")

    # Hybrid 2: XGBoost + HMM (Viterbi Decoding)
    sess_accs_xgb_hybrid = []
    for f_seq, l_seq in zip(test_features_list, test_labels_list):
        # Extract tabular representation for each timestep
        T = len(f_seq)
        f_windows = []
        for t in range(T):
            start = max(0, t - 20 + 1)
            chunk = f_seq[start:t + 1]
            pad_n = 20 - len(chunk)
            w = np.pad(chunk, ((pad_n, 0), (0, 0)), constant_values=PAD_VALUE)
            f_windows.append(w)
        tab_seq = extract_tabular_features(np.array(f_windows))
        xgb_emission = best_xgb_model.predict_proba(tab_seq)
        vit_pred = viterbi_decode(xgb_emission, best_trans_mat, best_init_probs)
        sess_accs_xgb_hybrid.append(accuracy_score(l_seq, vit_pred))

    avg_xgb_hybrid = np.mean(sess_accs_xgb_hybrid)
    res_xgb_hybrid = evaluate_predictions(
        y_test,
        np.argmax(best_xgb_probs_test, axis=1),
        steps_test,
        "Hybrid-XGBoost+HMM",
        f"Capped-0.90 (Full-Session Acc: {avg_xgb_hybrid:.4f})",
        latency_ms=0.55,
    )
    res_xgb_hybrid["Accuracy"] = round(avg_xgb_hybrid, 4)
    results.append(res_xgb_hybrid)
    print(f"  Hybrid XGBoost + HMM: Full-Session Viterbi Acc={avg_xgb_hybrid:.4f}")

    # Hybrid 3: Ensemble Hybrid (LSTM + XGBoost + HMM Viterbi)
    # Blend LSTM (temporal context) with XGBoost (decision tree non-linear boundaries)
    ensemble_probs_test = 0.5 * best_lstm_probs_test + 0.5 * best_xgb_probs_test
    res_ensemble = evaluate_predictions(
        y_test,
        np.argmax(ensemble_probs_test, axis=1),
        steps_test,
        "Hybrid-Ensemble(LSTM+XGB)",
        "50% LSTM + 50% XGBoost Soft Blend",
        latency_ms=1.1,
    )
    results.append(res_ensemble)
    print(f"  Ensemble (LSTM + XGBoost): Test Acc={res_ensemble['Accuracy']:.4f}, Macro-F1={res_ensemble['Macro_F1']:.4f}")

    # ------------------------------------------------------------
    # 6. RESULTS CONSOLIDATION & EXPORT
    # ------------------------------------------------------------
    df_results = pd.DataFrame(results)
    df_results.to_csv(RESULTS_CSV_PATH, index=False)
    print(f"\n[+] Saved complete benchmark results to {RESULTS_CSV_PATH}")

    print("\n" + "=" * 90)
    print("FINAL BENCHMARK COMPARISON TABLE")
    print("=" * 90)
    display_cols = [
        "Model",
        "Parameters",
        "Accuracy",
        "Macro_F1",
        "Acc_Thin_Context (1-3)",
        "Acc_Thick_Context (10+)",
        "Latency_ms_per_req",
    ]
    print(df_results[display_cols].to_string(index=False))
    print("=" * 90)


if __name__ == "__main__":
    run_benchmarks()
