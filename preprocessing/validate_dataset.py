import os
from collections import Counter, defaultdict
from urllib.parse import quote_plus

from dotenv import load_dotenv
from pymongo import MongoClient


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

REQUIRED_ENV = [
    "MONGO_USERNAME",
    "MONGO_PASSWORD",
    "MONGO_CLUSTER",
    "DATABASE_NAME",
    "COLLECTION_NAME",
]

missing = [key for key in REQUIRED_ENV if not os.getenv(key)]

if missing:
    raise RuntimeError(
        "Missing environment variables: " + ", ".join(missing)
    )

USERNAME = quote_plus(os.getenv("MONGO_USERNAME"))
PASSWORD = quote_plus(os.getenv("MONGO_PASSWORD"))
CLUSTER = os.getenv("MONGO_CLUSTER")

DATABASE_NAME = os.getenv("DATABASE_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

URI = (
    f"mongodb+srv://{USERNAME}:{PASSWORD}@{CLUSTER}/"
    "?retryWrites=true&w=majority&appName=ids-dataset-cluster"
)

EXPECTED_STAGES = [
    "NORMAL",
    "RECON",
    "FUZZING",
    "INJECTION",
    "EXPLOITATION",
]

STAGE_ORDER = {
    "NORMAL": 0,
    "RECON": 1,
    "FUZZING": 2,
    "INJECTION": 3,
    "EXPLOITATION": 4,
}


# ============================================================
# DATABASE CONNECTION
# ============================================================

print("=" * 70)
print("CONNECTING TO MONGODB ATLAS")
print("=" * 70)

client = MongoClient(
    URI,
    serverSelectionTimeoutMS=10000
)

try:
    client.admin.command("ping")
    print("MongoDB connection: OK")
except Exception as exc:
    raise RuntimeError(
        f"Could not connect to MongoDB Atlas:\n{exc}"
    )

collection = client[DATABASE_NAME][COLLECTION_NAME]

print(f"Database   : {DATABASE_NAME}")
print(f"Collection : {COLLECTION_NAME}")


# ============================================================
# BASIC DATASET INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("BASIC DATASET INFORMATION")
print("=" * 70)

total_documents = collection.count_documents({})

print(f"Total requests/documents : {total_documents:,}")

if total_documents == 0:
    raise RuntimeError("The selected collection is empty.")


# ============================================================
# STAGE COUNTS
# ============================================================

print("\n" + "=" * 70)
print("REQUEST COUNT BY ATTACK STAGE")
print("=" * 70)

stage_counts = Counter()

for doc in collection.find(
    {},
    {"attack_stage": 1}
):
    stage = doc.get("attack_stage", "MISSING")
    stage_counts[stage] += 1

for stage in EXPECTED_STAGES:
    print(f"{stage:<15}: {stage_counts.get(stage, 0):,}")

unexpected_stages = [
    stage
    for stage in stage_counts
    if stage not in EXPECTED_STAGES
]

if unexpected_stages:
    print("\nWARNING: Unexpected labels found:")
    for stage in unexpected_stages:
        print(f"  - {stage}")


# ============================================================
# SESSION ANALYSIS
# ============================================================

print("\n" + "=" * 70)
print("SESSION ANALYSIS")
print("=" * 70)

sessions = defaultdict(list)

cursor = collection.find(
    {},
    {
        "session_id": 1,
        "request_number": 1,
        "attack_stage": 1,
    }
)

for doc in cursor:
    session_id = doc.get("session_id")

    if not session_id:
        continue

    sessions[session_id].append(
        (
            doc.get("request_number"),
            doc.get("attack_stage")
        )
    )

print(f"Total sessions : {len(sessions):,}")


# ============================================================
# REQUESTS PER SESSION
# ============================================================

session_lengths = []

for session_id, requests in sessions.items():
    session_lengths.append(len(requests))

if session_lengths:
    print(
        f"Requests/session - min : {min(session_lengths)}"
    )
    print(
        f"Requests/session - max : {max(session_lengths)}"
    )
    print(
        f"Requests/session - avg : "
        f"{sum(session_lengths) / len(session_lengths):.2f}"
    )


# ============================================================
# SESSIONS PER STAGE
# ============================================================

print("\n" + "=" * 70)
print("SESSION COUNT BY STAGE")
print("=" * 70)

sessions_per_stage = Counter()

for session_id, requests in sessions.items():

    stages = {
        stage
        for _, stage in requests
        if stage in EXPECTED_STAGES
    }

    for stage in stages:
        sessions_per_stage[stage] += 1

for stage in EXPECTED_STAGES:
    print(
        f"{stage:<15}: "
        f"{sessions_per_stage.get(stage, 0):,}"
    )


# ============================================================
# STAGE SEQUENCES
# ============================================================

print("\n" + "=" * 70)
print("SESSION STAGE SEQUENCES")
print("=" * 70)

sequence_counter = Counter()

for session_id, requests in sessions.items():

    ordered = sorted(
        requests,
        key=lambda x: (
            x[0] is None,
            x[0] if x[0] is not None else 0
        )
    )

    sequence = []

    for _, stage in ordered:

        if stage not in EXPECTED_STAGES:
            continue

        if not sequence or sequence[-1] != stage:
            sequence.append(stage)

    sequence_counter[tuple(sequence)] += 1


for sequence, count in sequence_counter.most_common():

    print(
        f"{count:>4} session(s): "
        + " -> ".join(sequence)
    )


# ============================================================
# TRANSITION VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("STAGE TRANSITION VALIDATION")
print("=" * 70)

valid_transitions = 0
backward_transitions = 0
same_stage_transitions = 0
invalid_transitions = []

for session_id, requests in sessions.items():

    ordered = sorted(
        requests,
        key=lambda x: (
            x[0] is None,
            x[0] if x[0] is not None else 0
        )
    )

    previous_stage = None

    for request_number, current_stage in ordered:

        if current_stage not in EXPECTED_STAGES:
            continue

        if previous_stage is None:
            previous_stage = current_stage
            continue

        previous_index = STAGE_ORDER[previous_stage]
        current_index = STAGE_ORDER[current_stage]

        if current_index == previous_index:
            same_stage_transitions += 1

        elif current_index > previous_index:
            valid_transitions += 1

        else:
            backward_transitions += 1

            invalid_transitions.append(
                {
                    "session_id": session_id,
                    "request_number": request_number,
                    "previous_stage": previous_stage,
                    "current_stage": current_stage,
                }
            )

        previous_stage = current_stage


print(
    f"Forward transitions : {valid_transitions:,}"
)

print(
    f"Same-stage transitions : {same_stage_transitions:,}"
)

print(
    f"Backward transitions : {backward_transitions:,}"
)


if invalid_transitions:

    print("\nWARNING: Backward transitions detected.")

    print("\nFirst 20 examples:")

    for transition in invalid_transitions[:20]:
        print(
            f"Session {transition['session_id']} | "
            f"Request {transition['request_number']} | "
            f"{transition['previous_stage']} -> "
            f"{transition['current_stage']}"
        )

else:

    print(
        "\nGOOD: No backward stage transitions detected."
    )


# ============================================================
# MISSING / INVALID CORE FIELDS
# ============================================================

print("\n" + "=" * 70)
print("CORE FIELD VALIDATION")
print("=" * 70)

required_fields = [
    "session_id",
    "request_number",
    "attack_stage",
    "request",
    "response",
    "source",
]

missing_field_counts = Counter()

for doc in collection.find({}):

    for field in required_fields:

        if field not in doc or doc[field] is None:
            missing_field_counts[field] += 1

if missing_field_counts:

    print("Missing fields:")

    for field, count in missing_field_counts.items():
        print(f"{field:<20}: {count:,}")

else:

    print("All core fields are present.")


# ============================================================
# REQUEST STRUCTURE VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("REQUEST / RESPONSE STRUCTURE VALIDATION")
print("=" * 70)

request_problems = 0
response_problems = 0

for doc in collection.find(
    {},
    {
        "request": 1,
        "response": 1,
    }
):

    request = doc.get("request")
    response = doc.get("response")

    if not isinstance(request, dict):
        request_problems += 1

    if not isinstance(response, dict):
        response_problems += 1


print(
    f"Invalid request objects  : {request_problems:,}"
)

print(
    f"Invalid response objects : {response_problems:,}"
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("DATASET VALIDATION COMPLETE")
print("=" * 70)

print(
    f"Requests : {total_documents:,}"
)

print(
    f"Sessions : {len(sessions):,}"
)

print(
    f"Backward transitions : {backward_transitions:,}"
)

print(
    f"Unexpected labels : {len(unexpected_stages):,}"
)

print("\nNo data was modified.")
print("The validation script is READ-ONLY.")

client.close()