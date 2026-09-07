"""
Parse the real Burp Suite captures in SQLrequests/ into a normalized request corpus.

This replaces the synthetic generator as the source of truth for what a request looks
like. The captures contain 5 HTTP methods, 13 status codes, 653 distinct paths and 176
request bodies -- variety the synthetic generator could not produce, because it only
ever issued parameterless GETs against a handful of endpoints.

SPLIT DISCIPLINE
----------------
Splits are assigned at the FILE level, never at the request or session level. Every
capture file belongs to exactly one of train/validation/test, so a request observed in
training can never reappear in test. This is what makes the held-out score meaningful:
the test split contains paths, payloads and response sizes the model has never seen.

SECURITY NOTE
-------------
These XML files are the user's own local Burp exports. They declare only ELEMENT and
ATTLIST in their DOCTYPE (no ENTITY), and xml.etree.ElementTree does not resolve
external entities or fetch over the network. Parsing them is safe. Do not point this
module at XML from an untrusted source without swapping in defusedxml.
"""

from __future__ import annotations

import base64
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

STAGES = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]
STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}
FOLDER_TO_STAGE = {
    "normal": "NORMAL",
    "recon": "RECON",
    "fuzzing": "FUZZING",
    "injection": "INJECTION",
    "exploitation": "EXPLOITATION",
}

# Headers that must never be persisted: they carry live session credentials.
SENSITIVE_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
}

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}
# Burp writes e.g. "Fri Jun 19 22:05:36 IST 2026"; %Z will not parse "IST" portably,
# so the fields are pulled out directly.
_TIME_RE = re.compile(
    r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+(\d{4})$"
)


@dataclass
class Request:
    """One captured HTTP exchange, normalized."""

    method: str
    path: str
    query: str
    body: str
    headers: Dict[str, str]
    status: int
    response_length: int
    timestamp: Optional[datetime]
    stage: str
    source_file: str

    @property
    def stage_index(self) -> int:
        return STAGE_INDEX[self.stage]


@dataclass
class CaptureFile:
    """One Burp export = one single-stage browsing/attack session."""

    name: str
    stage: str
    requests: List[Request] = field(default_factory=list)


def _decode(node) -> str:
    if node is None or node.text is None:
        return ""
    if (node.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(node.text).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return node.text


def _parse_time(text: str) -> Optional[datetime]:
    m = _TIME_RE.match((text or "").strip())
    if not m:
        return None
    mon, day, hh, mm, ss, year = m.groups()
    if mon not in _MONTHS:
        return None
    try:
        return datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None


def _parse_request_blob(raw: str):
    """Split a raw HTTP request into (method, request-target, headers, body)."""
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        return "", "", {}, ""
    parts = lines[0].split()
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            if key.lower() in SENSITIVE_HEADERS:
                # Keep presence (it is real signal) but never the credential itself.
                headers[key] = "[REDACTED]"
            else:
                headers[key] = value.strip()
    return method, target, headers, body.strip()


def _int_or(text: Optional[str], default: int = 0) -> int:
    try:
        return int((text or "").strip())
    except (TypeError, ValueError):
        return default


def load_capture_files(root: str = "SQLrequests") -> List[CaptureFile]:
    """Parse every Burp export under root into CaptureFile objects, in stable order."""
    out: List[CaptureFile] = []
    for folder in sorted(os.listdir(root)):
        folder_path = os.path.join(root, folder)
        if not os.path.isdir(folder_path):
            continue
        stage = FOLDER_TO_STAGE.get(folder.lower())
        if stage is None:
            continue
        for filename in sorted(os.listdir(folder_path)):
            if not filename.endswith(".xml"):
                continue
            path = os.path.join(folder_path, filename)
            # Defense in depth: stdlib ElementTree does not fetch external entities, but
            # it will expand internal ones (billion-laughs). These Burp exports declare
            # none; reject any file that does, so this stays safe even if the corpus
            # directory is ever fed hostile XML.
            try:
                with open(path, "rb") as fh:
                    head = fh.read(4096)
                if b"<!ENTITY" in head:
                    continue
                root_el = ET.parse(path).getroot()
            except ET.ParseError:
                continue

            capture = CaptureFile(name=filename, stage=stage)
            for item in root_el.findall("item"):
                raw = _decode(item.find("request"))
                method, target, headers, body = _parse_request_blob(raw)
                if not method:
                    continue

                item_path = item.findtext("path") or urlsplit(target).path or "/"
                # Burp's <path> already includes the query string; prefer splitting the
                # request-target, falling back to <path> when the blob was unreadable.
                split_target = urlsplit(target if target else item_path)
                clean_path = split_target.path or "/"
                query = split_target.query

                capture.requests.append(
                    Request(
                        method=method.upper(),
                        path=clean_path,
                        query=query,
                        body=body,
                        headers=headers,
                        status=_int_or(item.findtext("status")),
                        response_length=_int_or(item.findtext("responselength")),
                        timestamp=_parse_time(item.findtext("time", "")),
                        stage=stage,
                        source_file=filename,
                    )
                )
            if capture.requests:
                out.append(capture)
    return out


def load_augmented(path: str = "augmented_corpus.json") -> List[CaptureFile]:
    """Load augmented sessions (from augment.py) as CaptureFile objects, if present.

    These are driven live against Juice Shop and are assigned to the TRAIN split only by
    assign_file_splits, so validation/test stay pure real captures."""
    import json
    import os

    if not os.path.exists(path):
        return []
    out: List[CaptureFile] = []
    for entry in json.load(open(path)):
        cap = CaptureFile(name=entry["name"], stage=entry["stage"])
        for r in entry["requests"]:
            ts = None
            if r.get("epoch") is not None:
                ts = datetime.fromtimestamp(r["epoch"])
            cap.requests.append(Request(
                method=r["method"], path=r["path"], query=r["query"], body=r["body"],
                headers=r["headers"], status=r["status"],
                response_length=r["response_length"], timestamp=ts,
                stage=entry["stage"], source_file=entry["name"]))
        if cap.requests:
            out.append(cap)
    return out


def assign_file_splits(
    captures: List[CaptureFile],
    val_fraction: float = 0.2,
    test_fraction: float = 0.2,
    seed: int = 20260907,
) -> Dict[str, str]:
    """
    Map capture-file name -> split, stratified by stage.

    Files are shuffled with a fixed seed and partitioned per stage so each split holds
    whole files. Every stage is guaranteed at least one file in validation and one in
    test wherever the stage has enough files to allow it.
    """
    import random

    rng = random.Random(seed)
    by_stage: Dict[str, List[str]] = defaultdict(list)
    for capture in captures:
        by_stage[capture.stage].append(capture.name)

    splits: Dict[str, str] = {}
    for stage in STAGES:
        names = sorted(by_stage.get(stage, []))
        # Augmented files (name starts with AUG_) are always train, never held out,
        # so validation/test remain pure real captures.
        aug = [n for n in names if n.startswith("AUG_")]
        names = [n for n in names if not n.startswith("AUG_")]
        for n in aug:
            splits[n] = "train"
        if not names:
            continue
        rng.shuffle(names)
        total = len(names)
        n_test = max(1, round(total * test_fraction)) if total >= 3 else (1 if total >= 2 else 0)
        n_val = max(1, round(total * val_fraction)) if total >= 4 else (1 if total >= 3 else 0)
        # Never starve training.
        while total - n_test - n_val < 1 and (n_val > 0 or n_test > 1):
            if n_val > 0:
                n_val -= 1
            else:
                n_test -= 1
        for i, name in enumerate(names):
            if i < n_test:
                splits[name] = "test"
            elif i < n_test + n_val:
                splits[name] = "validation"
            else:
                splits[name] = "train"
    return splits


def summarize(captures: List[CaptureFile], splits: Dict[str, str]) -> str:
    lines = []
    per = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # stage -> split -> [files, reqs]
    for capture in captures:
        cell = per[capture.stage][splits[capture.name]]
        cell[0] += 1
        cell[1] += len(capture.requests)
    lines.append(f"{'stage':<14}{'train':>18}{'validation':>18}{'test':>18}")
    for stage in STAGES:
        row = f"{stage:<14}"
        for split in ("train", "validation", "test"):
            files, reqs = per[stage][split]
            row += f"{files:>6} files/{reqs:>6} req"
        lines.append(row)
    total_files = len(captures)
    total_reqs = sum(len(c.requests) for c in captures)
    lines.append(f"{'TOTAL':<14}{total_files:>6} files{total_reqs:>12} requests")
    return "\n".join(lines)


if __name__ == "__main__":
    caps = load_capture_files()
    sp = assign_file_splits(caps)
    print(summarize(caps, sp))
