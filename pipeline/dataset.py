"""
Build the training dataset from composed sessions and save it to disk.

Output (dataset_v2.npz):
  seq_features   object array of (T_i, F) float32 matrices, one per session
  seq_labels     object array of (T_i,) int64 stage indices
  seq_split      object array of "train"/"validation"/"test"
  seq_archetype  object array of archetype names
  flat_X         (sum T_i, F) float32  -- every request as an independent row (for XGBoost)
  flat_y         (sum T_i,)   int64
  flat_split     (sum T_i,)   <U10
  feature_keys   (F,) str
  stages         (5,) str

Both the LSTM (sequence view) and XGBoost (flat view) consume the SAME causal per-step
feature vectors produced by SessionFeatureExtractor. There is no separate tabular
extraction that could drift from what the sequence model sees.
"""

from __future__ import annotations

import os
from typing import List

import numpy as np

from .compose import Session, compose_sessions
from .corpus import STAGES, assign_file_splits, load_capture_files
from .features import FEATURE_KEYS, NUM_FEATURES, RequestView, SessionFeatureExtractor

OUTPUT_PATH = "dataset_v2.npz"

# How many sessions to compose per split. Train is large; val/test are held out on
# disjoint capture files, so their sessions are built from requests the model never saw.
N_TRAIN = 1500
N_VAL = 300
N_TEST = 300


def _to_view(req, prev_epoch) -> RequestView:
    epoch = req.timestamp.timestamp() if req.timestamp is not None else None
    return RequestView(
        method=req.method,
        path=req.path,
        query=req.query,
        body=req.body,
        headers=req.headers,
        status=req.status,
        response_length=req.response_length,
        epoch_seconds=epoch,
    )


def featurize_session(session: Session) -> np.ndarray:
    extractor = SessionFeatureExtractor()
    rows = []
    prev = None
    for req in session.requests:
        rows.append(extractor.feed(_to_view(req, prev)))
        prev = req
    return np.asarray(rows, dtype=np.float32)


def build(seed: int = 20260907, include_augmented: bool = True) -> dict:
    from .corpus import load_augmented

    captures = load_capture_files()
    if include_augmented:
        aug = load_augmented()
        if aug:
            print(f"  merging {len(aug)} augmented (train-only) sessions")
            captures = captures + aug
    splits = assign_file_splits(captures)

    sessions: List[Session] = []
    sessions += compose_sessions(captures, splits, "train", N_TRAIN, seed=seed)
    sessions += compose_sessions(captures, splits, "validation", N_VAL, seed=seed)
    sessions += compose_sessions(captures, splits, "test", N_TEST, seed=seed)

    seq_features, seq_labels, seq_split, seq_arch = [], [], [], []
    flat_X, flat_y, flat_split = [], [], []

    for session in sessions:
        feats = featurize_session(session)
        labels = np.asarray(session.labels, dtype=np.int64)
        assert feats.shape == (len(labels), NUM_FEATURES), feats.shape
        seq_features.append(feats)
        seq_labels.append(labels)
        seq_split.append(session.split)
        seq_arch.append(session.archetype)
        flat_X.append(feats)
        flat_y.append(labels)
        flat_split.append(np.full(len(labels), session.split, dtype="<U10"))

    payload = dict(
        seq_features=np.array(seq_features, dtype=object),
        seq_labels=np.array(seq_labels, dtype=object),
        seq_split=np.array(seq_split),
        seq_archetype=np.array(seq_arch),
        flat_X=np.concatenate(flat_X).astype(np.float32),
        flat_y=np.concatenate(flat_y).astype(np.int64),
        flat_split=np.concatenate(flat_split),
        feature_keys=np.array(FEATURE_KEYS),
        stages=np.array(STAGES),
    )
    return payload


def main():
    payload = build()
    np.savez_compressed(OUTPUT_PATH, **payload)
    size = os.path.getsize(OUTPUT_PATH) / 1e6
    n_sessions = len(payload["seq_features"])
    n_req = len(payload["flat_y"])
    print(f"Saved {OUTPUT_PATH} ({size:.1f} MB)")
    print(f"  sessions={n_sessions}  requests={n_req}  features={NUM_FEATURES}")
    for split in ("train", "validation", "test"):
        m = payload["flat_split"] == split
        sm = payload["seq_split"] == split
        print(f"  {split:11s} sessions={int(sm.sum()):4d}  requests={int(m.sum()):6d}  "
              f"label dist={np.bincount(payload['flat_y'][m], minlength=5).tolist()}")


if __name__ == "__main__":
    main()
