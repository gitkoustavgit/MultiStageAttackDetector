from pymongo import MongoClient
import numpy as np
from collections import Counter

c = MongoClient("mongodb://localhost:27017")
db = c["AttackDetection"]

print("=== MONGODB (AttackDetection) DETAILED STATS ===")
for name in ["generated_http_sessions", "generated_training_windows", "newSessions", "http_payloads"]:
    col = db[name]
    total_docs = col.count_documents({})
    distinct_sessions = col.distinct("session_id")
    n_sessions = len(distinct_sessions)
    print(f"\n--- Collection: '{name}' ---")
    print(f"  Total records (requests/windows): {total_docs:,}")
    print(f"  Distinct session IDs: {n_sessions:,}")
    
    # Session length stats
    pipeline = [{"$group": {"_id": "$session_id", "count": {"$sum": 1}}}]
    cursor = list(col.aggregate(pipeline))
    if cursor:
        counts = [d["count"] for d in cursor]
        print(f"  Requests per session -> Min: {min(counts)}, Max: {max(counts)}, Mean: {np.mean(counts):.1f}")
        
    # Attack stage / label breakdown
    sample = col.find_one()
    stage_key = None
    for k in ["stage_label", "attack_stage", "target_stage"]:
        if sample and k in sample:
            stage_key = k
            break
    if stage_key:
        p_stages = [{"$group": {"_id": f"${stage_key}", "count": {"$sum": 1}}}]
        stage_counts = list(col.aggregate(p_stages))
        print(f"  Stage breakdown (by '{stage_key}'):")
        for sc in sorted(stage_counts, key=lambda x: str(x["_id"])):
            print(f"    {sc['_id']}: {sc['count']:,}")

# Also compare with offline dataset files
print("\n=== OFFLINE DATASET FILES (.NPZ) STATS ===")
for npz_path in ["dataset.npz", "dataset_v2.npz"]:
    try:
        d = np.load(npz_path, allow_pickle=True)
        print(f"\n--- File: '{npz_path}' ---")
        if "seq_labels" in d:
            n_sess = len(d["seq_labels"])
            total_reqs = sum(len(x) for x in d["seq_labels"])
            print(f"  Distinct Sessions: {n_sess:,}")
            print(f"  Total Requests: {total_reqs:,}")
            print(f"  Mean Requests / Session: {total_reqs / n_sess:.1f}")
            stage_counts = Counter(d["flat_y"])
            stages = d["stages"]
            print(f"  Stage breakdown:")
            for idx, name in enumerate(stages):
                print(f"    {name} (Stage {idx}): {stage_counts[idx]:,} ({stage_counts[idx]/total_reqs:.1%})")
            splits = Counter(d["seq_split"])
            print(f"  Session Split breakdown: {dict(splits)}")
        elif "y" in d:
            print(f"  Total Records: {len(d['y']):,}")
            if "session_ids" in d:
                unique_sess = len(np.unique(d["session_ids"]))
                print(f"  Distinct Sessions: {unique_sess:,}")
            stage_counts = Counter(d["y"])
            stages = d["stages"]
            print(f"  Stage breakdown:")
            for idx, name in enumerate(stages):
                print(f"    {name} (Stage {idx}): {stage_counts[idx]:,}")
    except Exception as e:
        print(f"  Error loading {npz_path}: {e}")
