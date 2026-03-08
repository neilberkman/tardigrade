#!/usr/bin/env python3
"""Shared fault-campaign data structures and helpers."""

from __future__ import annotations

import dataclasses
import itertools
import random
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclasses.dataclass
class FaultResult:
    fault_at: int
    boot_outcome: str
    boot_slot: Optional[str]
    nvm_state: Any
    raw_log: str
    is_control: bool = False


@dataclasses.dataclass
class MultiFaultResult:
    """Result from a multi-fault (sequential interruption) run."""

    fault_sequence: List[int]  # ordered list of fault-at indices
    boot_outcome: str
    boot_slot: Optional[str]
    nvm_state: Any
    per_fault_states: List[Dict[str, Any]]  # nvm_state snapshot after each fault
    raw_log: str
    is_control: bool = False


@dataclasses.dataclass
class MultiFaultPlan:
    """Generated plan for multi-fault sweep runs."""

    sequences: List[List[int]]
    strategy: str
    interesting_point_count: int
    max_faults_per_run: int
    seed: Optional[int]
    diagnostics: Dict[str, Any]


def parse_fault_range(expr: str) -> Iterable[int]:
    start_s, end_s = expr.split(":", 1)
    start = int(start_s)
    end = int(end_s)
    if end < start:
        raise ValueError("invalid fault range: {}".format(expr))
    return range(start, end + 1)


def parse_multi_fault_spec(expr: str) -> List[List[int]]:
    """Parse a multi-fault specification string into fault sequences.

    Formats:
        "100,200"       -> [[100, 200]]   (one run, faults at write 100 and 200)
        "100,200;300,400" -> [[100, 200], [300, 400]]  (two runs)

    Each sequence is a sorted list of fault-at write indices.
    """
    if not expr or not expr.strip():
        raise ValueError("empty multi-fault spec")

    sequences: List[List[int]] = []
    for run_spec in expr.split(";"):
        run_spec = run_spec.strip()
        if not run_spec:
            continue
        indices = sorted(int(s.strip()) for s in run_spec.split(","))
        if len(indices) < 2:
            raise ValueError(
                "multi-fault sequence must have at least 2 fault points, got: {!r}".format(run_spec)
            )
        if any(idx < 0 for idx in indices):
            raise ValueError("fault indices must be non-negative, got: {!r}".format(run_spec))
        sequences.append(indices)

    if not sequences:
        raise ValueError("no valid fault sequences in spec: {!r}".format(expr))
    return sequences


# ---------------------------------------------------------------------------
# Multi-fault sweep engine
# ---------------------------------------------------------------------------

# Type alias used by combination generators.
COMBO_TYPE = Tuple[int, ...]


def generate_multi_fault_sequences(
    strategy: str,
    interesting_points: List[int],
    max_faults_per_run: int = 2,
    max_pairs: int = 5000,
    seed: Optional[int] = None,
    explicit_sequences: Optional[List[List[int]]] = None,
) -> MultiFaultPlan:
    """Generate multi-fault sequences using the given strategy.

    Strategies:
        explicit            - Use user-provided sequences verbatim.
        pairwise_interesting - C(N,2) pairwise from interesting points.
        random_sample        - Seeded random sampling from interesting points.

    Returns a MultiFaultPlan with sequences and diagnostics.
    """
    if max_faults_per_run < 2:
        raise ValueError("max_faults_per_run must be >= 2, got {}".format(max_faults_per_run))

    known = {"explicit", "pairwise_interesting", "random_sample"}
    if strategy not in known:
        raise ValueError("unknown multi-fault strategy {!r}, expected one of {}".format(strategy, sorted(known)))

    if strategy == "explicit":
        return generate_explicit(explicit_sequences, max_faults_per_run)
    elif strategy == "pairwise_interesting":
        return generate_pairwise_interesting(interesting_points, max_faults_per_run, max_pairs)
    else:
        return generate_random_sample(interesting_points, max_faults_per_run, max_pairs, seed)


def generate_explicit(
    sequences: Optional[List[List[int]]], max_faults_per_run: int
) -> MultiFaultPlan:
    """Validate and return user-provided explicit sequences."""
    if not sequences:
        raise ValueError("explicit strategy requires non-empty sequences list")
    validated: List[List[int]] = []
    for seq in sequences:
        if len(seq) < 2:
            raise ValueError(
                "each multi-fault sequence must have >= 2 points, got {}".format(seq)
            )
        if len(seq) > max_faults_per_run:
            raise ValueError(
                "sequence {} exceeds max_faults_per_run={}".format(seq, max_faults_per_run)
            )
        validated.append(sorted(seq))
    return MultiFaultPlan(
        sequences=validated,
        strategy="explicit",
        interesting_point_count=0,
        max_faults_per_run=max_faults_per_run,
        seed=None,
        diagnostics={"source": "user_provided", "count": len(validated)},
    )


def generate_pairwise_interesting(
    interesting_points: List[int], max_faults_per_run: int, max_pairs: int
) -> MultiFaultPlan:
    """Generate C(N, k) combinations from deduplicated interesting points."""
    pts = sorted(set(interesting_points))
    if len(pts) < 2:
        reason = "no_interesting_points" if len(pts) == 0 else "single_point"
        return MultiFaultPlan(
            sequences=[],
            strategy="pairwise_interesting",
            interesting_point_count=len(pts),
            max_faults_per_run=max_faults_per_run,
            seed=None,
            diagnostics={"reason": reason, "exhaustive": True, "theoretical_combinations": 0},
        )

    k = min(max_faults_per_run, len(pts))
    all_combos = list(itertools.combinations(pts, k))
    theoretical = len(all_combos)
    exhaustive = theoretical <= max_pairs

    if exhaustive:
        seqs = [list(c) for c in all_combos]
    else:
        # Deterministic truncation (stable order from sorted input).
        seqs = [list(c) for c in all_combos[:max_pairs]]

    return MultiFaultPlan(
        sequences=seqs,
        strategy="pairwise_interesting",
        interesting_point_count=len(pts),
        max_faults_per_run=max_faults_per_run,
        seed=None,
        diagnostics={
            "exhaustive": exhaustive,
            "theoretical_combinations": theoretical,
            "capped_at": max_pairs if not exhaustive else None,
        },
    )


def generate_random_sample(
    interesting_points: List[int],
    max_faults_per_run: int,
    max_pairs: int,
    seed: Optional[int],
) -> MultiFaultPlan:
    """Random sampling of fault-point combinations with collision avoidance."""
    pts = sorted(set(interesting_points))
    if len(pts) < 2:
        return MultiFaultPlan(
            sequences=[],
            strategy="random_sample",
            interesting_point_count=len(pts),
            max_faults_per_run=max_faults_per_run,
            seed=seed,
            diagnostics={"reason": "insufficient_points"},
        )

    k = min(max_faults_per_run, len(pts))
    all_combos = list(itertools.combinations(pts, k))
    theoretical = len(all_combos)

    rng = random.Random(seed)

    if theoretical <= max_pairs:
        # All fit; shuffle for variety but return all.
        seqs = [list(c) for c in all_combos]
        rng.shuffle(seqs)
        return MultiFaultPlan(
            sequences=seqs,
            strategy="random_sample",
            interesting_point_count=len(pts),
            max_faults_per_run=max_faults_per_run,
            seed=seed,
            diagnostics={"exhaustive": True, "theoretical_combinations": theoretical},
        )

    # Sample without replacement.
    sampled_indices = rng.sample(range(theoretical), max_pairs)
    seqs = [list(all_combos[i]) for i in sorted(sampled_indices)]

    return MultiFaultPlan(
        sequences=seqs,
        strategy="random_sample",
        interesting_point_count=len(pts),
        max_faults_per_run=max_faults_per_run,
        seed=seed,
        diagnostics={
            "exhaustive": False,
            "theoretical_combinations": theoretical,
            "sampled": max_pairs,
        },
    )


# ---------------------------------------------------------------------------
# Encoding / decoding multi-fault sequences for the fault_types pipeline
# ---------------------------------------------------------------------------


def encode_multi_fault_sequence(seq: List[int]) -> str:
    """Encode a multi-fault sequence as 'mf:<fp1>:<fp2>:...'."""
    if len(seq) < 2:
        raise ValueError("multi-fault sequence must have >= 2 points")
    return "mf:" + ":".join(str(x) for x in seq)


def decode_multi_fault_sequence(encoded: str) -> List[int]:
    """Decode 'mf:<fp1>:<fp2>:...' back to a list of ints."""
    if not encoded.startswith("mf:"):
        raise ValueError("not a multi-fault encoding: {!r}".format(encoded))
    parts = encoded.split(":")
    if len(parts) < 3:  # "mf" + at least 2 points
        raise ValueError("multi-fault encoding needs >= 2 fault points: {!r}".format(encoded))
    return [int(p) for p in parts[1:]]


def multi_fault_plan_summary(plan: Optional[MultiFaultPlan]) -> Optional[Dict[str, Any]]:
    """Return a JSON-serializable summary of a multi-fault plan."""
    if plan is None:
        return None
    return {
        "strategy": plan.strategy,
        "sequences": len(plan.sequences),
        "interesting_points": plan.interesting_point_count,
        "max_faults_per_run": plan.max_faults_per_run,
        "seed": plan.seed,
        "diagnostics": plan.diagnostics,
    }
