"""
link.py

Burp Suite XML -> MongoDB Atlas importer
Project: Context-Aware AI-Based Detection of Multi-Stage Web Injection Attacks
"""

import os
import base64
from urllib.parse import quote_plus, urlparse
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from pymongo import MongoClient
load_dotenv()
required = [
    "MONGO_USERNAME",
    "MONGO_PASSWORD",
    "MONGO_CLUSTER",
    "DATABASE_NAME",
    "COLLECTION_NAME",
    "DATASET_ROOT",
]

missing = [key for key in required if not os.getenv(key)]

if missing:
    raise ValueError(
        f"Missing environment variables: {', '.join(missing)}"
    )

# ---------------- MongoDB ---------------- #

USERNAME = os.getenv("MONGO_USERNAME")
PASSWORD = quote_plus(os.getenv("MONGO_PASSWORD"))

CLUSTER = os.getenv("MONGO_CLUSTER")
DATABASE_NAME = os.getenv("DATABASE_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
ROOT_FOLDER = os.getenv("DATASET_ROOT")

URI = (
    f"mongodb+srv://{USERNAME}:{PASSWORD}@{CLUSTER}/"
    "?retryWrites=true&w=majority"
    "&appName=ids-dataset-cluster"
)

STAGE_MAP = {
    "normal": "NORMAL",
    "recon": "RECON",
    "fuzzing": "FUZZING",
    "injection": "INJECTION",
    "exploitation": "EXPLOITATION",
}

client = MongoClient(URI, serverSelectionTimeoutMS=10000)
client.admin.command("ping")
collection = client[DATABASE_NAME][COLLECTION_NAME]

collection.create_index(
    [("session_id", 1), ("request_number", 1)],
    unique=True
)

print("[+] Connected to MongoDB Atlas")


def decode_node(node):
    if node is None or node.text is None:
        return ""
    txt = node.text
    if node.get("base64", "").lower() == "true":
        try:
            return base64.b64decode(txt).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return txt


def parse_headers(lines):
    headers = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_request(raw):
    if not raw:
        return "", {}, ""

    raw = raw.replace("\r\n", "\n")
    parts = raw.split("\n\n", 1)
    header_part = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_part.split("\n")
    headers = parse_headers(lines[1:])

    method = ""
    if lines:
        toks = lines[0].split()
        if toks:
            method = toks[0]

    return method, headers, body.strip()


def parse_response(raw):
    if not raw:
        return {}, ""

    raw = raw.replace("\r\n", "\n")
    parts = raw.split("\n\n", 1)
    header_part = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    headers = parse_headers(header_part.split("\n")[1:])
    return headers, body


total = 0

for traffic_type in os.listdir(ROOT_FOLDER):
    folder = os.path.join(ROOT_FOLDER, traffic_type)

    if not os.path.isdir(folder):
        continue

    attack_stage = STAGE_MAP.get(traffic_type.lower())
    if attack_stage is None:
        print(f"[WARNING] Unknown folder '{traffic_type}' - skipping.")
        continue

    for xml_file in sorted(os.listdir(folder)):
        if not xml_file.endswith(".xml"):
            continue

        session_id = os.path.splitext(xml_file)[0].upper()

        print(f"[{traffic_type.upper()}] Processing {xml_file}")
        
        with open(os.path.join(folder, xml_file),
                  encoding="utf-8",
                  errors="ignore") as f:

            soup = BeautifulSoup(f.read(), "xml")

        items = soup.find_all("item")

        for req_no, item in enumerate(items, start=1):

            url = item.url.text if item.url else ""
            path = item.path.text if item.path else urlparse(url).path

            raw_request = decode_node(item.request)
            raw_response = decode_node(item.response)

            method, req_headers, req_body = parse_request(raw_request)
            resp_headers, resp_body = parse_response(raw_response)

            status = int(item.status.text) if item.status and item.status.text.isdigit() else None

            mime = (
                item.mimetype.text
                if item.mimetype and item.mimetype.text
                else resp_headers.get("Content-Type", "Unknown")
            )

            document = {
                "traffic_type": traffic_type.lower(),
                "session_id": session_id,
                "request_number": req_no,
                "attack_stage": attack_stage,
                "request": {
                    "method": method,
                    "url": url,
                    "path": path,
                    "headers": req_headers,
                    "body": req_body
                },
                "response": {
                    "status": status,
                    "length": len(resp_body),
                    "mime_type": mime
                },
                "source": {
                    "xml_file": xml_file,
                    "generated": False
                }
            }

            collection.update_one(
                {
                    "session_id": session_id,
                    "request_number": req_no
                },
                {"$set": document},
                upsert=True
            )

            total += 1

print(f"\nDone. Processed {total} requests.")
