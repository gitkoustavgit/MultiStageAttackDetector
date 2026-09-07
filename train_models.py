"""
Trains the LSTM stage classifier and the HMM transition model on the
exported dataset.npz (produced by export_dataset.py). No MongoDB
connection needed here - everything runs off the small local file.

    python train_models.py

Runs comfortably on CPU. With ~7,000 training windows x 20 timesteps
x 23 features, expect this to finish in a few minutes on a laptop.
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

DATASET_PATH = "dataset.npz"
PAD_VALUE = -1.0
LSTM_MODEL_PATH = "lstm_stage_classifier.keras"
HMM_PARAMS_PATH = "hmm_params.npz"

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
NUM_STAGES = len(STAGES)


# ============================================================
# LOAD
# ============================================================

def load_dataset():
    data = np.load(DATASET_PATH, allow_pickle=True)

    X, y, splits = data["X"], data["y"], data["splits"]

    def subset(split_name):
        mask = splits == split_name
        return X[mask], y[mask]

    X_train, y_train = subset("train")
    X_val, y_val = subset("validation")
    X_test, y_test = subset("test")

    print(f"train={len(y_train)}  validation={len(y_val)}  test={len(y_test)}")

    hmm_data = {
        split: {
            "labels": data[f"hmm_{split}_labels"],
            "features": data[f"hmm_{split}_features"],
        }
        for split in ("train", "validation", "test")
    }

    return (X_train, y_train), (X_val, y_val), (X_test, y_test), hmm_data


# ============================================================
# LSTM
# ============================================================

def build_lstm(num_features):
    model = keras.Sequential([
        layers.Input(shape=(None, num_features)),
        layers.Masking(mask_value=PAD_VALUE),
        layers.LSTM(64, return_sequences=False),
        layers.Dropout(0.3),
        layers.Dense(32, activation="relu"),
        layers.Dense(NUM_STAGES, activation="softmax"),
    ])
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def train_lstm(X_train, y_train, X_val, y_val):
    model = build_lstm(num_features=X_train.shape[-1])
    model.summary()

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=5, restore_best_weights=True
        ),
        keras.callbacks.ModelCheckpoint(
            LSTM_MODEL_PATH, monitor="val_loss", save_best_only=True
        ),
    ]

    model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=50,
        batch_size=64,
        callbacks=callbacks,
        verbose=2,
    )
    return model


def evaluate_lstm(model, X_test, y_test):
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"\nTest loss={loss:.4f}  accuracy={accuracy:.4f}")

    y_pred = np.argmax(model.predict(X_test, verbose=0), axis=1)

    try:
        from sklearn.metrics import classification_report, confusion_matrix
        print("\nClassification report:")
        print(classification_report(y_test, y_pred, target_names=STAGES, digits=3))
        print("Confusion matrix (rows=true, cols=predicted):")
        print(STAGES)
        print(confusion_matrix(y_test, y_pred))
    except ImportError:
        # Manual per-class accuracy if scikit-learn isn't installed
        for i, stage in enumerate(STAGES):
            mask = y_test == i
            acc = (y_pred[mask] == i).mean() if mask.sum() else float("nan")
            print(f"  {stage:15s} accuracy={acc:.3f}  (n={mask.sum()})")


# ============================================================
# HMM (supervised transition-matrix estimation)
# ============================================================
#
# We already know the TRUE stage label of every request in every
# training session (that's the whole point of a generated/labeled
# dataset) - so instead of unsupervised Baum-Welch (which can drift
# to the wrong state ordering), we directly COUNT transitions between
# consecutive true labels across all train sessions. This is the
# standard supervised way to estimate an HMM's parameters when the
# state sequence is observed during training.
# ============================================================

def fit_hmm_transition_matrix(label_sequences, num_states=NUM_STAGES, smoothing=1.0):
    counts = np.full((num_states, num_states), smoothing, dtype=np.float64)
    initial_counts = np.full(num_states, smoothing, dtype=np.float64)

    for seq in label_sequences:
        if len(seq) == 0:
            continue
        initial_counts[seq[0]] += 1
        for a, b in zip(seq[:-1], seq[1:]):
            counts[a, b] += 1

    transition_matrix = counts / counts.sum(axis=1, keepdims=True)
    initial_probs = initial_counts / initial_counts.sum()

    return transition_matrix, initial_probs


# ============================================================
# VITERBI - combine LSTM emissions with HMM transition structure
# ============================================================

def viterbi_decode(emission_probs, transition_matrix, initial_probs):
    """
    emission_probs: (T, num_states) - per-timestep class probabilities,
        e.g. straight from the LSTM's softmax output for each step of
        a session.
    transition_matrix: (num_states, num_states) from fit_hmm_transition_matrix.
    initial_probs: (num_states,) from fit_hmm_transition_matrix.

    Returns the most likely full state sequence (length T), smoothed
    by known stage-progression structure instead of trusting each
    per-timestep LSTM prediction in isolation.
    """
    eps = 1e-12
    T, num_states = emission_probs.shape

    log_emission = np.log(emission_probs + eps)
    log_transition = np.log(transition_matrix + eps)
    log_initial = np.log(initial_probs + eps)

    log_prob = np.zeros((T, num_states))
    backpointer = np.zeros((T, num_states), dtype=int)

    log_prob[0] = log_initial + log_emission[0]

    for t in range(1, T):
        for state in range(num_states):
            scores = log_prob[t - 1] + log_transition[:, state]
            backpointer[t, state] = np.argmax(scores)
            log_prob[t, state] = scores.max() + log_emission[t, state]

    path = np.zeros(T, dtype=int)
    path[-1] = np.argmax(log_prob[-1])
    for t in range(T - 2, -1, -1):
        path[t] = backpointer[t + 1, path[t + 1]]

    return path


def sliding_window_predict(model, feature_seq, max_len=20, pad_value=PAD_VALUE):
    """
    Re-runs the trained LSTM across an ENTIRE raw session (every
    request, not just target windows), using the same sliding-window
    shape the model was trained on, to get one emission distribution
    per timestep - the input Viterbi decoding needs.
    """
    T, num_features = feature_seq.shape
    windows = np.full((T, max_len, num_features), pad_value, dtype=np.float32)

    for t in range(T):
        start = max(0, t - max_len + 1)
        chunk = feature_seq[start:t + 1]
        windows[t, max_len - len(chunk):] = chunk

    return model.predict(windows, verbose=0)  # (T, num_states)


def demo_combined_decoding(model, transition_matrix, initial_probs, hmm_data, split="test", n_sessions=3):
    print(f"\n--- Demo: LSTM-only vs LSTM+HMM(Viterbi) on {n_sessions} {split} sessions ---")

    labels_list = hmm_data[split]["labels"]
    features_list = hmm_data[split]["features"]

    for i in range(min(n_sessions, len(labels_list))):
        true_labels = labels_list[i]
        feature_seq = features_list[i]

        emission_probs = sliding_window_predict(model, feature_seq)
        lstm_only_pred = np.argmax(emission_probs, axis=1)
        viterbi_pred = viterbi_decode(emission_probs, transition_matrix, initial_probs)

        lstm_acc = (lstm_only_pred == true_labels).mean()
        viterbi_acc = (viterbi_pred == true_labels).mean()

        print(f"session {i}: length={len(true_labels)}  "
              f"lstm_only_acc={lstm_acc:.3f}  lstm+hmm_acc={viterbi_acc:.3f}")


# ============================================================
# MAIN
# ============================================================

def main():
    tf.random.set_seed(20260905)

    print("Loading dataset...")
    (X_train, y_train), (X_val, y_val), (X_test, y_test), hmm_data = load_dataset()

    print("\nTraining LSTM...")
    model = train_lstm(X_train, y_train, X_val, y_val)

    print("\nEvaluating LSTM on held-out test windows...")
    evaluate_lstm(model, X_test, y_test)

    print("\nFitting HMM transition matrix from TRAIN session label sequences...")
    transition_matrix, initial_probs = fit_hmm_transition_matrix(hmm_data["train"]["labels"])

    print("\nTransition matrix (rows=from, cols=to):")
    print(STAGES)
    print(np.round(transition_matrix, 3))

    np.savez(HMM_PARAMS_PATH, transition_matrix=transition_matrix, initial_probs=initial_probs, stages=np.array(STAGES))
    print(f"\nSaved HMM parameters to {HMM_PARAMS_PATH}")
    print(f"Saved best LSTM to {LSTM_MODEL_PATH}")

    demo_combined_decoding(model, transition_matrix, initial_probs, hmm_data, split="test")


if __name__ == "__main__":
    main()
