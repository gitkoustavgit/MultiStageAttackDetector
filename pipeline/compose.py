"""
Compose realistic multi-stage sessions from the real capture corpus.

WHY THIS EXISTS
---------------
The original synthetic generator built every session as "a prefix of earlier stages,
then a solid block of the target stage". Because a session could only ever move up the
severity ladder, the label of request t was always max(label[0..t]) -- verified true for
100% of the original 10,000 training windows. That made the whole task solvable by a
lookup table plus a maximum, which scored 0.9987 and beat every trained model.

This module deliberately generates session shapes that destroy that property:

  benign          only normal browsing
  recon_only      probes, never escalates
  escalating      climbs the chain, may stop at any rung
  de_escalating   attacks, then retreats to normal browsing      <- breaks running max
  interleaved     attack blocks scattered through benign traffic <- breaks running max
  oscillating     bounces between two attack stages              <- breaks running max
  abandoned       starts an attack, gives up, goes quiet         <- breaks running max
  direct          jumps straight to injection with no warm-up    <- breaks "prefix" assumption

Blocks are contiguous runs lifted from real capture files, so local behaviour (hitting
the same endpoint repeatedly, a burst of 304s) stays realistic. Only files belonging to
the session's own split are ever drawn from, so no request crosses a split boundary.
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List, Sequence

from .corpus import STAGES, CaptureFile, Request

# Archetype -> relative weight. Roughly half of all sessions contain a shape that the
# running-maximum rule cannot represent.
ARCHETYPE_WEIGHTS = {
    "benign": 14,
    "recon_only": 8,
    "escalating": 22,
    "de_escalating": 16,
    "interleaved": 16,
    "oscillating": 10,
    "abandoned": 8,
    "direct": 6,
}

CHAIN = ["NORMAL", "RECON", "FUZZING", "INJECTION", "EXPLOITATION"]


@dataclass
class Session:
    session_id: str
    split: str
    archetype: str
    requests: List[Request]

    @property
    def labels(self) -> List[int]:
        return [r.stage_index for r in self.requests]


class BlockSampler:
    """Draws contiguous runs of requests of a given stage from one split's files."""

    def __init__(self, captures: Sequence[CaptureFile], splits: Dict[str, str], split: str,
                 rng: random.Random):
        self.rng = rng
        self.by_stage: Dict[str, List[CaptureFile]] = defaultdict(list)
        for capture in captures:
            if splits.get(capture.name) == split:
                self.by_stage[capture.stage].append(capture)
        self.split = split

    def available(self, stage: str) -> bool:
        return bool(self.by_stage.get(stage))

    def block(self, stage: str, length: int) -> List[Request]:
        """A contiguous run of `length` requests of `stage`, wrapping if the file is short."""
        files = self.by_stage.get(stage)
        if not files or length <= 0:
            return []
        capture = self.rng.choice(files)
        pool = capture.requests
        if len(pool) <= length:
            # Short file: take all of it, then top up from another file of the same stage.
            out = list(pool)
            while len(out) < length:
                other = self.rng.choice(files)
                need = length - len(out)
                start = self.rng.randrange(0, max(1, len(other.requests)))
                out.extend(other.requests[start:start + need])
                if not other.requests:
                    break
            return out[:length]
        start = self.rng.randrange(0, len(pool) - length + 1)
        return list(pool[start:start + length])


def _retimestamp(requests: List[Request], rng: random.Random) -> List[Request]:
    """
    Give the composed session one coherent, monotonically increasing timeline.

    Gaps are drawn from a realistic mixture: rapid automated bursts, ordinary
    click-through pauses, and occasional long think-time. Timing is genuine signal --
    a scanner and a human browse at very different rates -- so it must not be an
    artefact of which files the blocks came from.
    """
    if not requests:
        return requests
    out: List[Request] = []
    clock = requests[0].timestamp
    if clock is None:
        from datetime import datetime

        clock = datetime(2026, 6, 19, 22, 0, 0)
    for i, req in enumerate(requests):
        if i:
            roll = rng.random()
            if roll < 0.55:
                gap = rng.uniform(0.05, 0.9)      # automated / page-driven burst
            elif roll < 0.9:
                gap = rng.uniform(0.9, 6.0)       # ordinary interaction
            else:
                gap = rng.uniform(6.0, 90.0)      # think time / pause
            clock = clock + timedelta(seconds=gap)
        out.append(
            Request(
                method=req.method,
                path=req.path,
                query=req.query,
                body=req.body,
                headers=req.headers,
                status=req.status,
                response_length=req.response_length,
                timestamp=clock,
                stage=req.stage,
                source_file=req.source_file,
            )
        )
    return out


def _plan(archetype: str, rng: random.Random) -> List[tuple]:
    """Return a list of (stage, block_length) describing the session's shape."""
    def size(lo, hi):
        return rng.randint(lo, hi)

    if archetype == "benign":
        return [("NORMAL", size(12, 40))]

    if archetype == "recon_only":
        plan = []
        if rng.random() < 0.7:
            plan.append(("NORMAL", size(3, 10)))
        plan.append(("RECON", size(10, 30)))
        if rng.random() < 0.4:
            plan.append(("NORMAL", size(2, 8)))
        return plan

    if archetype == "escalating":
        stop = rng.randint(1, 4)  # index into CHAIN of the highest stage reached
        plan = []
        if rng.random() < 0.75:
            plan.append(("NORMAL", size(3, 12)))
        for i in range(1, stop + 1):
            plan.append((CHAIN[i], size(4, 16)))
        return plan

    if archetype == "de_escalating":
        peak = rng.randint(2, 4)
        plan = [("NORMAL", size(2, 8))] if rng.random() < 0.6 else []
        for i in range(1, peak + 1):
            plan.append((CHAIN[i], size(3, 12)))
        # The retreat: back down the chain and/or straight to benign traffic.
        for i in range(peak - 1, 0, -1):
            if rng.random() < 0.5:
                plan.append((CHAIN[i], size(2, 8)))
        plan.append(("NORMAL", size(6, 20)))
        return plan

    if archetype == "interleaved":
        plan = [("NORMAL", size(4, 12))]
        for _ in range(rng.randint(2, 4)):
            plan.append((CHAIN[rng.randint(1, 4)], size(2, 8)))
            plan.append(("NORMAL", size(3, 12)))
        return plan

    if archetype == "oscillating":
        a, b = sorted(rng.sample([1, 2, 3, 4], 2))
        plan = [("NORMAL", size(2, 6))] if rng.random() < 0.5 else []
        for _ in range(rng.randint(2, 4)):
            plan.append((CHAIN[a], size(3, 10)))
            plan.append((CHAIN[b], size(3, 10)))
        return plan

    if archetype == "abandoned":
        peak = rng.randint(1, 3)
        plan = [("NORMAL", size(3, 10))]
        plan.append((CHAIN[peak], size(3, 9)))
        plan.append(("NORMAL", size(10, 28)))
        return plan

    if archetype == "direct":
        top = rng.randint(3, 4)
        plan = [(CHAIN[top], size(6, 18))]
        if rng.random() < 0.5:
            plan.append(("NORMAL", size(3, 12)))
        return plan

    raise ValueError(f"unknown archetype {archetype}")


def compose_sessions(
    captures: Sequence[CaptureFile],
    splits: Dict[str, str],
    split: str,
    n_sessions: int,
    seed: int = 20260907,
    max_length: int = 80,
) -> List[Session]:
    rng = random.Random(seed + hash(split) % 10_000)
    sampler = BlockSampler(captures, splits, split, rng)

    names = [a for a in ARCHETYPE_WEIGHTS]
    weights = [ARCHETYPE_WEIGHTS[a] for a in names]

    sessions: List[Session] = []
    attempts = 0
    while len(sessions) < n_sessions and attempts < n_sessions * 20:
        attempts += 1
        archetype = rng.choices(names, weights=weights, k=1)[0]
        plan = _plan(archetype, rng)
        # Drop plan entries whose stage has no file in this split.
        plan = [(stage, n) for stage, n in plan if sampler.available(stage)]
        if not plan:
            continue

        requests: List[Request] = []
        for stage, length in plan:
            requests.extend(sampler.block(stage, length))
            if len(requests) >= max_length:
                break
        requests = requests[:max_length]
        if len(requests) < 6:
            continue

        requests = _retimestamp(requests, rng)
        sessions.append(
            Session(
                session_id=f"{split.upper()}_{archetype}_{len(sessions):04d}",
                split=split,
                archetype=archetype,
                requests=requests,
            )
        )
    return sessions


def running_max_fraction(sessions: Sequence[Session]) -> float:
    """
    Fraction of requests whose label equals the running maximum of labels so far.

    This is the acceptance metric for the fix. The original dataset scored 1.0 on the
    target windows, which is what let a parameter-free maximum win. Lower is better;
    anything near 1.0 means the generator still has the shortcut in it.
    """
    total = hit = 0
    for session in sessions:
        best = -1
        for label in session.labels:
            best = max(best, label)
            total += 1
            hit += int(label == best)
    return hit / total if total else 0.0


def describe(sessions: Sequence[Session]) -> str:
    from collections import Counter

    arch = Counter(s.archetype for s in sessions)
    labels = Counter()
    for s in sessions:
        labels.update(s.labels)
    lens = [len(s.requests) for s in sessions]
    lines = [
        f"sessions={len(sessions)}  requests={sum(lens)}  "
        f"len min/mean/max={min(lens)}/{sum(lens)/len(lens):.1f}/{max(lens)}",
        "  archetypes: " + ", ".join(f"{k}={v}" for k, v in sorted(arch.items())),
        "  labels: " + ", ".join(f"{STAGES[i]}={labels.get(i,0)}" for i in range(len(STAGES))),
        f"  label == running max for {running_max_fraction(sessions):.4f} of requests",
    ]
    return "\n".join(lines)
