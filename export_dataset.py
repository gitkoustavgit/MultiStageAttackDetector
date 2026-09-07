"""
Exports the generated dataset from MongoDB into a single compact
.npz file on disk, so training never needs a live Mongo connection
or the bulky nested JSON documents in memory at once.

Run this ONCE after generation. Then train_models.py only ever
touches the small .npz file.

PowerShell:
  $env:MONGO_URI="mongodb://localhost:27017"   (or your Atlas string)
  python export_dataset.py
"""

import os
import numpy as np
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = "AttackDetection"
WINDOW_COLLECTION = "generated_training_windows"
RAW_COLLECTION = "generated_http_sessions"

OUTPUT_PATH = "dataset.npz"

MAX_LEN = 20            # matches MAX_CONTEXT_REQUESTS in the generator
PAD_VALUE = -1.0         # sentinel: no real feature in this schema is ever negative

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}

# EXACT key order emitted by build_features() in the generator.
# Order matters - it defines column position in every feature vector.
# NOTE: stage_label / stage_index are deliberately NOT in this list.
# They live outside "features" in each sequence item specifically so
# they can never leak into the LSTM input (see project notes) - only
# the fields below are used as model input.
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


def vectorize_timestep(features):
    return [float(features.get(key, 0.0)) for key in FEATURE_KEYS]


def build_lstm_arrays(window_docs):
    """
    For each window: build a (MAX_LEN, num_features) matrix, left-padded
    with PAD_VALUE so the real, informative timesteps are right-aligned
    (the target request is always the LAST real timestep). Label is the
    window's target_stage_index. Split comes straight from the field
    the generator already assigned per session.
    """
    X, y, splits, session_ids, target_block_steps = [], [], [], [], []

    for doc in window_docs:
        sequence = doc["sequence"]

        vectors = [vectorize_timestep(item["features"]) for item in sequence]
        vectors = vectors[-MAX_LEN:]  # keep most recent MAX_LEN if longer

        pad_count = MAX_LEN - len(vectors)
        padded = [[PAD_VALUE] * len(FEATURE_KEYS)] * pad_count + vectors

        X.append(padded)
        y.append(doc["target_stage_index"])
        splits.append(doc["split"])
        session_ids.append(doc["session_id"])
        target_block_steps.append(doc.get("target_block_step", 10))

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)
    splits = np.array(splits)
    session_ids = np.array(session_ids)
    target_block_steps = np.array(target_block_steps, dtype=np.int32)

    return X, y, splits, session_ids, target_block_steps


def build_hmm_sequences(raw_docs):
    """
    Group raw (non-target-window) requests by session, in request order,
    to get BOTH:
      - the full stage-label sequence per session (fits the HMM's
        transition matrix)
      - the full feature-vector sequence per session (lets the trained
        LSTM be re-run across an ENTIRE session, not just isolated
        target windows, so Viterbi decoding has something real to
        smooth over)
    Kept split-aware so only TRAIN sessions are used for fitting the
    transition matrix - same leakage discipline as the LSTM split.
    """
    by_session = {}
    for doc in raw_docs:
        sid = doc["session_id"]
        by_session.setdefault(sid, {"split": doc["session_split"], "items": []})
        by_session[sid]["items"].append(
            (doc["request_number"], doc["stage_index"], vectorize_timestep(doc["features"]))
        )

    result = {
        "train": {"labels": [], "features": []},
        "validation": {"labels": [], "features": []},
        "test": {"labels": [], "features": []},
    }

    for sid, info in by_session.items():
        ordered = sorted(info["items"], key=lambda t: t[0])
        labels = np.array([stage for _, stage, _ in ordered], dtype=np.int64)
        features = np.array([vec for _, _, vec in ordered], dtype=np.float32)
        result[info["split"]]["labels"].append(labels)
        result[info["split"]]["features"].append(features)

    return result


def main():
    if not MONGO_URI:
        raise RuntimeError('MONGO_URI is missing. $env:MONGO_URI="..." first.')

    print("Connecting to MongoDB...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    client.admin.command("ping")
    db = client[DATABASE_NAME]
    print("Connected.")

    print("Pulling training windows (projected, no response_preview/headers)...")
    window_projection = {
        "sequence.features": 1,
        "target_stage_index": 1,
        "target_block_step": 1,
        "split": 1,
        "session_id": 1,
    }
    window_docs = list(db[WINDOW_COLLECTION].find({}, window_projection))
    print(f"  {len(window_docs)} windows pulled")

    print("Pulling raw session requests (projected, features + stage_index)...")
    raw_projection = {
        "session_id": 1,
        "request_number": 1,
        "stage_index": 1,
        "session_split": 1,
        "features": 1,
    }
    raw_docs = list(db[RAW_COLLECTION].find({}, raw_projection))
    print(f"  {len(raw_docs)} raw requests pulled")

    client.close()  # free the connection before the (larger) array build

    print("Building LSTM arrays...")
    X, y, splits, session_ids, target_block_steps = build_lstm_arrays(window_docs)
    del window_docs  # done with the nested JSON, drop it before HMM step

    print("Building HMM per-session label sequences...")
    hmm_sequences = build_hmm_sequences(raw_docs)
    del raw_docs

    print(f"\nX shape: {X.shape}  (windows, timesteps, features)")
    print(f"y shape: {y.shape}")
    for split_name in ["train", "validation", "test"]:
        mask = splits == split_name
        n_sessions = len(hmm_sequences[split_name]["labels"])
        print(f"  {split_name:10s} windows={mask.sum():5d}  hmm_sessions={n_sessions:4d}")

    save_kwargs = dict(
        X=X,
        y=y,
        splits=splits,
        session_ids=session_ids,
        target_block_steps=target_block_steps,
        feature_keys=np.array(FEATURE_KEYS),
        stages=np.array(STAGES),
    )
    for split_name in ["train", "validation", "test"]:
        save_kwargs[f"hmm_{split_name}_labels"] = np.array(
            hmm_sequences[split_name]["labels"], dtype=object
        )
        save_kwargs[f"hmm_{split_name}_features"] = np.array(
            hmm_sequences[split_name]["features"], dtype=object
        )

    np.savez_compressed(OUTPUT_PATH, **save_kwargs)

    size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
    print(f"\nSaved {OUTPUT_PATH} ({size_mb:.1f} MB). Mongo is no longer needed for training.")


if __name__ == "__main__":
    main()
