#!/usr/bin/env python3
"""Shared fault-campaign data structures and helpers."""

from __future__ import annotations

import dataclasses
import itertools
import math
import random
import struct as _struct
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclasses.dataclass
class BootloaderRegionConfig:
    """Address range of the bootloader's own code region."""

    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end


def validate_bootloader_vector_table(
    memory_bytes: bytes,
    region_base: int,
    region_size: int,
    sram_start: int = 0x20000000,
    sram_end: int = 0x30000000,
) -> tuple:
    """Validate the ARM vector table at the start of a bootloader region.

    Checks:
      1. Initial SP (first word) is in the SRAM range.
      2. Reset vector (second word) points into the bootloader region.

    Returns:
        (True, "ok") if valid, or (False, reason_string) if invalid.
    """
    if len(memory_bytes) < 8:
        return False, "region too small ({} bytes, need >= 8)".format(len(memory_bytes))
    sp = _struct.unpack_from("<I", memory_bytes, 0)[0]
    reset_vector = _struct.unpack_from("<I", memory_bytes, 4)[0]
    region_end = region_base + region_size
    if not (sram_start <= sp < sram_end):
        return False, "initial SP 0x{:08X} not in SRAM range 0x{:08X}-0x{:08X}".format(
            sp, sram_start, sram_end
        )
    if not (region_base <= reset_vector < region_end):
        return False, "reset vector 0x{:08X} not in bootloader region 0x{:08X}-0x{:08X}".format(
            reset_vector, region_base, region_end
        )
    return True, "ok"


NVS_CORRUPTION_MODES = {"bit_flip", "partial_erase", "truncate", "scramble"}


@dataclasses.dataclass
class NvsCorruptionSpec:
    """Specification for NVS/config region corruption fault injection."""

    region_start: int
    region_end: int
    corruption_mode: str  # one of NVS_CORRUPTION_MODES
    seed: int = 0

    def __post_init__(self) -> None:
        if self.region_end <= self.region_start:
            raise ValueError(
                "region_end (0x{:X}) must be greater than region_start (0x{:X})".format(
                    self.region_end, self.region_start
                )
            )
        if self.corruption_mode not in NVS_CORRUPTION_MODES:
            raise ValueError(
                "corruption_mode must be one of {}, got {!r}".format(
                    sorted(NVS_CORRUPTION_MODES), self.corruption_mode
                )
            )

    @property
    def region_size(self) -> int:
        return self.region_end - self.region_start


def generate_nvs_corruption_variants(
    region_data: bytes,
    region_size: int,
    modes: Optional[List[str]] = None,
    seed: int = 0,
) -> List[Tuple[str, bytes]]:
    """Generate corrupted NVS region variants for each requested mode.

    Args:
        region_data: Original NVS region contents (padded to region_size with 0xFF).
        region_size: Total size of the NVS region in bytes.
        modes: List of corruption modes to generate. Defaults to all modes.
        seed: RNG seed for deterministic corruption.

    Returns:
        List of (mode_name, corrupted_bytes) tuples.
    """
    if modes is None:
        modes = sorted(NVS_CORRUPTION_MODES)
    for mode in modes:
        if mode not in NVS_CORRUPTION_MODES:
            raise ValueError(
                "unknown NVS corruption mode {!r}, expected one of {}".format(
                    mode, sorted(NVS_CORRUPTION_MODES)
                )
            )

    data = bytearray(region_data[:region_size])
    if len(data) < region_size:
        data.extend(b"\xFF" * (region_size - len(data)))

    variants: List[Tuple[str, bytes]] = []
    rng = random.Random(seed)

    for mode in modes:
        corrupted = bytearray(data)
        if mode == "bit_flip":
            num_flips = max(1, min(8, region_size // 256))
            for _ in range(num_flips):
                byte_idx = rng.randint(0, len(corrupted) - 1)
                bit_idx = rng.randint(0, 7)
                corrupted[byte_idx] ^= 1 << bit_idx
        elif mode == "partial_erase":
            half = len(corrupted) // 2
            corrupted[half:] = b"\xFF" * (len(corrupted) - half)
        elif mode == "truncate":
            if len(corrupted) > 16:
                corrupted[16:] = b"\x00" * (len(corrupted) - 16)
        elif mode == "scramble":
            for i in range(len(corrupted)):
                corrupted[i] = rng.randint(0, 255)
        variants.append((mode, bytes(corrupted)))

    return variants


@dataclasses.dataclass
class ReadFaultSpec:
    """Specification for a read-time bit-flip fault injection region."""

    region_start: int
    region_end: int
    bit_flip_count: int = 1
    probability: float = 1.0
    seed: int = 0

    def __post_init__(self) -> None:
        if self.region_end <= self.region_start:
            raise ValueError(
                "region_end (0x{:X}) must be greater than region_start (0x{:X})".format(
                    self.region_end, self.region_start
                )
            )
        if self.bit_flip_count < 1:
            raise ValueError(
                "bit_flip_count must be >= 1, got {}".format(self.bit_flip_count)
            )
        if not (0.0 <= self.probability <= 1.0):
            raise ValueError(
                "probability must be in [0.0, 1.0], got {}".format(self.probability)
            )

    @property
    def region_size(self) -> int:
        return self.region_end - self.region_start


@dataclasses.dataclass
class ReadFaultResult:
    """Result from a read-time bit-flip fault injection run."""

    fault_at: int
    boot_outcome: str
    boot_slot: Optional[str]
    nvm_state: Any
    raw_log: str
    reads_corrupted: int
    total_reads: int
    is_control: bool = False


@dataclasses.dataclass
class MetadataFaultRegion:
    """A named address range for metadata fault classification."""

    name: str
    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


def classify_fault_region(
    fault_address: int,
    metadata_regions: List[MetadataFaultRegion],
    bootloader_region: Optional[BootloaderRegionConfig] = None,
) -> Optional[str]:
    """Classify a fault address into a region category.

    Returns:
        "bootloader_region" if bootloader_region is defined and the address
            falls within it (highest priority).
        "metadata:<name>" if the address falls within a metadata region.
        "data" if metadata_regions or bootloader_region are defined but the
            address doesn't match any named region.
        None if no metadata_regions and no bootloader_region are defined.
    """
    if not metadata_regions and bootloader_region is None:
        return None
    if bootloader_region is not None and bootloader_region.contains(fault_address):
        return "bootloader_region"
    for region in metadata_regions:
        if region.contains(fault_address):
            return "metadata:{}".format(region.name)
    return "data"


@dataclasses.dataclass
class FaultResult:
    fault_at: int
    boot_outcome: str
    boot_slot: Optional[str]
    nvm_state: Any
    raw_log: str
    is_control: bool = False
    fault_region: Optional[str] = None
    elapsed_virtual_time_s: Optional[float] = None


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
    fault_region: Optional[str] = None


@dataclasses.dataclass

class MultiComponentFaultResult:
    """Result from a multi-component fault injection run.

    In multi-component scenarios, one component is faulted while the
    others run cleanly.  A ``split_brain`` outcome indicates the faulted
    component failed while the clean component succeeded, leaving the
    device in an inconsistent state where components are running
    different firmware versions.
    """

    faulted_component: str
    fault_at: int
    per_component: Dict[str, Dict[str, Any]]  # component_name -> result dict
    combined_outcome: str  # "success", "split_brain", "all_failed", etc.
    is_control: bool = False
    fault_type: Optional[str] = None


@dataclasses.dataclass
class FaultDistributionConfig:
    """Configuration for spatially-correlated fault distribution.

    Models sector-local degradation where faults cluster in a specific
    address range rather than being uniformly distributed across all
    write points.
    """

    mode: str = "uniform"  # "uniform" or "clustered"
    cluster_start: int = 0
    cluster_end: int = 0
    flip_probability_in_cluster: float = 0.1
    flip_probability_outside: float = 0.001
    seed: int = 0

    def __post_init__(self) -> None:
        if self.mode not in ("uniform", "clustered"):
            raise ValueError(
                "fault_distribution.mode must be 'uniform' or 'clustered', got {!r}".format(
                    self.mode
                )
            )
        if self.mode == "clustered":
            if self.cluster_end <= self.cluster_start:
                raise ValueError(
                    "cluster_end (0x{:X}) must be > cluster_start (0x{:X})".format(
                        self.cluster_end, self.cluster_start
                    )
                )
            if not (0.0 <= self.flip_probability_in_cluster <= 1.0):
                raise ValueError(
                    "flip_probability_in_cluster must be in [0.0, 1.0], got {}".format(
                        self.flip_probability_in_cluster
                    )
                )
            if not (0.0 <= self.flip_probability_outside <= 1.0):
                raise ValueError(
                    "flip_probability_outside must be in [0.0, 1.0], got {}".format(
                        self.flip_probability_outside
                    )
                )


def apply_clustered_distribution(
    fault_points: List[int],
    distribution: FaultDistributionConfig,
    write_addresses: Optional[List[int]] = None,
    total_writes: int = 0,
    write_granularity: int = 8,
    slot_base: int = 0,
) -> List[Tuple[int, int]]:
    """Filter and annotate fault points using a clustered degradation model.

    For each fault point, determines the NVM address it targets and applies
    sector-local probability weighting.  Points inside the cluster sector
    range have a higher probability of being included; points outside have
    a lower probability.

    Args:
        fault_points: Write-index fault points to filter.
        distribution: Clustered distribution parameters.
        write_addresses: Optional pre-computed address for each write index.
            If provided, must be same length as total_writes.
        total_writes: Total writes in the OTA operation.
        write_granularity: Bytes per write word.
        slot_base: Base bus address of the target slot.

    Returns:
        List of (fault_point, corruption_seed) tuples for points that pass
        the probability filter.  corruption_seed is a deterministic value
        derived from the fault point and distribution seed.
    """
    if distribution.mode == "uniform":
        return [(fp, distribution.seed) for fp in fault_points]

    rng = random.Random(distribution.seed)
    result: List[Tuple[int, int]] = []

    for fp in fault_points:
        # Determine the bus address for this write index.
        if write_addresses is not None and 0 <= fp < len(write_addresses):
            addr = write_addresses[fp]
        else:
            addr = slot_base + fp * write_granularity

        in_cluster = distribution.cluster_start <= addr < distribution.cluster_end
        prob = (
            distribution.flip_probability_in_cluster
            if in_cluster
            else distribution.flip_probability_outside
        )

        if rng.random() < prob:
            # Deterministic seed per point: combine distribution seed with
            # fault point for reproducible per-write corruption patterns.
            point_seed = (distribution.seed * 2654435761 + fp) & 0xFFFFFFFF
            result.append((fp, point_seed))

    return result


def classify_multi_component_outcome(
    per_component: Dict[str, Dict[str, Any]],
) -> str:
    """Classify the combined outcome of a multi-component fault run.

    Returns:
        "success" if all components booted successfully.
        "split_brain" if some components succeeded and others failed --
            the most dangerous OTA failure mode where components end up
            running incompatible firmware versions.
        "all_failed" if every component failed to boot.
        "degraded" if multiple components were tested and outcomes are
            mixed but don't constitute a clean split-brain (e.g. one
            component has wrong_image while another has no_boot).
    """
    if not per_component:
        return "unknown"

    success_outcomes = {"success"}
    brick_outcomes = {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}

    outcomes = {}
    for name, result in per_component.items():
        outcome = str(result.get("boot_outcome", "unknown")).strip().lower()
        outcomes[name] = outcome

    all_success = all(o in success_outcomes for o in outcomes.values())
    all_failed = all(
        o in brick_outcomes or o == "wrong_image" for o in outcomes.values()
    )
    any_success = any(o in success_outcomes for o in outcomes.values())
    any_failed = any(
        o in brick_outcomes or o == "wrong_image" for o in outcomes.values()
    )

    if all_success:
        return "success"
    if all_failed:
        return "all_failed"
    if any_success and any_failed:
        return "split_brain"
    return "degraded"



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
    fallback_strategy: Optional[str] = None,
    fallback_points: Optional[List[int]] = None,
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
        plan = generate_pairwise_interesting(
            interesting_points, max_faults_per_run, max_pairs
        )
        return maybe_apply_fallback(
            primary_plan=plan,
            fallback_strategy=fallback_strategy,
            fallback_points=fallback_points,
            max_faults_per_run=max_faults_per_run,
            max_pairs=max_pairs,
            seed=seed,
        )
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


def generate_boundary_pairs(
    candidate_points: List[int],
    max_faults_per_run: int,
    max_pairs: int,
) -> MultiFaultPlan:
    """Generate deterministic boundary-focused sequences from candidate points."""
    pts = sorted(set(candidate_points))
    if len(pts) < 2:
        return MultiFaultPlan(
            sequences=[],
            strategy="boundary_pairs",
            interesting_point_count=len(pts),
            max_faults_per_run=max_faults_per_run,
            seed=None,
            diagnostics={"reason": "insufficient_points"},
        )

    k = min(max_faults_per_run, len(pts))
    seqs: List[List[int]] = []
    seen = set()

    def _add(seq: Iterable[int]) -> None:
        norm = tuple(sorted(int(x) for x in seq))
        if len(norm) < 2 or norm in seen:
            return
        seen.add(norm)
        seqs.append(list(norm))

    # Sliding windows capture adjacent boundaries.
    for i in range(0, len(pts) - k + 1):
        _add(pts[i : i + k])
        if len(seqs) >= max_pairs:
            break

    # Wide boundary-spanning pair/window.
    if len(seqs) < max_pairs:
        if k == 2:
            _add((pts[0], pts[-1]))
        else:
            _add(tuple([pts[0]] + pts[-(k - 1) :]))

    if len(seqs) > max_pairs:
        seqs = seqs[:max_pairs]

    return MultiFaultPlan(
        sequences=seqs,
        strategy="boundary_pairs",
        interesting_point_count=len(pts),
        max_faults_per_run=max_faults_per_run,
        seed=None,
        diagnostics={
            "exhaustive": False,
            "candidate_points": len(pts),
            "generated_sequences": len(seqs),
            "capped_at": max_pairs if len(seqs) >= max_pairs else None,
        },
    )


def maybe_apply_fallback(
    primary_plan: MultiFaultPlan,
    fallback_strategy: Optional[str],
    fallback_points: Optional[List[int]],
    max_faults_per_run: int,
    max_pairs: int,
    seed: Optional[int],
) -> MultiFaultPlan:
    """Apply a deterministic fallback plan when the primary plan yields nothing."""
    strategy = str(fallback_strategy or "none")
    if primary_plan.sequences or strategy == "none":
        return primary_plan

    candidates = list(fallback_points or [])
    if strategy == "boundary_pairs":
        fallback_plan = generate_boundary_pairs(
            candidates, max_faults_per_run=max_faults_per_run, max_pairs=max_pairs
        )
    elif strategy == "random_sample":
        fallback_plan = generate_random_sample(
            candidates,
            max_faults_per_run=max_faults_per_run,
            max_pairs=max_pairs,
            seed=seed,
        )
    else:
        raise ValueError(
            "unknown fallback strategy {!r}, expected one of {}".format(
                strategy, ["none", "boundary_pairs", "random_sample"]
            )
        )

    merged_diag = dict(primary_plan.diagnostics)
    merged_diag.update(
        {
            "primary_strategy": primary_plan.strategy,
            "primary_reason": primary_plan.diagnostics.get("reason"),
            "fallback_strategy": strategy,
            "fallback_candidate_points": len(set(candidates)),
            "fallback_used": bool(fallback_plan.sequences),
            "fallback_diagnostics": fallback_plan.diagnostics,
        }
    )
    return MultiFaultPlan(
        sequences=fallback_plan.sequences,
        strategy=primary_plan.strategy,
        interesting_point_count=primary_plan.interesting_point_count,
        max_faults_per_run=max_faults_per_run,
        seed=seed,
        diagnostics=merged_diag,
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
    preview_limit = 10
    preview = [list(seq) for seq in plan.sequences[:preview_limit]]
    return {
        "strategy": plan.strategy,
        "sequences": len(plan.sequences),
        "interesting_points": plan.interesting_point_count,
        "max_faults_per_run": plan.max_faults_per_run,
        "seed": plan.seed,
        "sequence_semantics": (
            "stage_relative_reboot"
            if plan.max_faults_per_run >= 2
            else "single_fault"
        ),
        "sequence_description": (
            "Each sequence element is the fault index for a successive "
            "reboot/recovery stage, not two faults in one uninterrupted run."
            if plan.max_faults_per_run >= 2
            else "Single-fault execution."
        ),
        "sample_sequences": preview,
        "sample_truncated": len(plan.sequences) > preview_limit,
        "diagnostics": plan.diagnostics,
    }
