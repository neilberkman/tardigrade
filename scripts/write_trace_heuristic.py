"""
Heuristic fault-point prioritization from NVMC write traces.

During calibration, the NVMC records (write_index, flash_offset) for every
word write.  This module classifies writes into priority tiers and produces
a reduced set of fault points that concentrates testing on high-risk writes
(trailer/metadata regions, erase boundaries) while sparsely sampling bulk
data copies.

Tier 0 (CRITICAL): test every write -- bootloader self-update region
  - Writes to the bootloader's own code region (if configured)
  - Corruption here can permanently brick with no recovery path

Tier 1 (EXHAUSTIVE): test every write
  - Writes to trailer regions (last page of each slot)
  - Writes where address jumps discontinuously (region transitions)
  - First/last N writes surrounding any address discontinuity
  - First write to each new page (page entry)
  - Last write before leaving a page (page exit)
  - Overwrites (same word address as previous write)

Tier 2 (DENSE): test every Kth write
  - Writes in the first and last sectors of each slot (boundary sectors)

Tier 3 (SPARSE): stratified sampling of bulk sequential copies
  - Short runs (<=20 writes): sampled at tier2_step density
  - Medium runs (21-100 writes): start/mid/end anchors + every tier3_step-th
  - Long runs (>100 writes): structural anchors at 0/10/25/50/75/90/100%
    plus evenly spaced fill points
"""

import csv
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple, Union


def load_trace(trace_path: str) -> List[Tuple[int, int]]:
    """Load a write trace CSV into a list of (write_index, flash_offset)."""
    entries: List[Tuple[int, int]] = []
    with open(trace_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append((int(row["write_index"]), int(row["flash_offset"])))
    return entries


def _segment_runs(
    tier3_indices: List[int],
    trace: List[Tuple[int, int]],
    page_size: int = 4096,
) -> List[Tuple[int, int, int]]:
    """
    Segment tier3 writes into contiguous runs of sequential/nearby addresses.

    A run breaks when there's a gap > 1 page between consecutive tier3 writes,
    or when the next tier3 write is not adjacent in trace index (meaning a
    non-tier3 write intervened).

    Args:
        tier3_indices: Sorted list of trace indices (0-based into trace list)
            that were classified as tier3.
        trace: The full write trace.
        page_size: Flash page size in bytes.

    Returns:
        List of (run_start_trace_idx, run_end_trace_idx, run_length) tuples.
        run_start and run_end are inclusive trace indices from tier3_indices.
    """
    if not tier3_indices:
        return []

    runs: List[Tuple[int, int, int]] = []
    run_start = tier3_indices[0]
    prev_idx = tier3_indices[0]

    for k in range(1, len(tier3_indices)):
        cur_idx = tier3_indices[k]
        prev_off = trace[prev_idx][1]
        cur_off = trace[cur_idx][1]

        # Break run if: non-contiguous trace indices OR address gap > 1 page.
        if cur_idx != prev_idx + 1 or abs(cur_off - prev_off) > page_size:
            run_len = prev_idx - run_start + 1
            runs.append((run_start, prev_idx, run_len))
            run_start = cur_idx

        prev_idx = cur_idx

    # Close the final run.
    run_len = prev_idx - run_start + 1
    runs.append((run_start, prev_idx, run_len))

    return runs


def _sample_bulk_run(
    run_start: int,
    run_end: int,
    run_length: int,
    tier3_step: int,
    tier2_step: int,
) -> List[int]:
    """
    Return selected trace indices from a single bulk (tier3) run using
    stratified sampling.

    - Short runs (<=20): every tier2_step-th index (denser).
    - Medium runs (21-100): start, midpoint, end, plus every tier3_step-th.
    - Long runs (>100): structural anchors at 0/10/25/50/75/90/100% plus
      evenly spaced fill to reach a budget of max(7, run_length // tier3_step).

    Args:
        run_start: First trace index in the run (inclusive).
        run_end: Last trace index in the run (inclusive).
        run_length: Number of writes in the run.
        tier3_step: Base sparse sampling step.
        tier2_step: Denser sampling step for short runs.

    Returns:
        Sorted list of trace indices selected from this run.
    """
    selected: Set[int] = set()

    if run_length <= 20:
        # Short run: dense sampling.
        for i, idx in enumerate(range(run_start, run_end + 1)):
            if i % tier2_step == 0:
                selected.add(idx)
        # Always include endpoints.
        selected.add(run_start)
        selected.add(run_end)

    elif run_length <= 100:
        # Medium run: structural anchors + periodic.
        selected.add(run_start)
        selected.add(run_end)
        midpoint = run_start + run_length // 2
        selected.add(midpoint)
        # Fill with periodic sampling.
        for i, idx in enumerate(range(run_start, run_end + 1)):
            if i % tier3_step == 0:
                selected.add(idx)

    else:
        # Long run: percentage-based structural anchors + fill.
        anchors = [0.0, 0.10, 0.25, 0.50, 0.75, 0.90, 1.0]
        for pct in anchors:
            offset = int(pct * (run_length - 1))
            selected.add(run_start + offset)

        # Fill budget: enough points to match roughly the old tier3_step density.
        budget = max(7, run_length // tier3_step)
        if len(selected) < budget:
            remaining = budget - len(selected)
            # Evenly space the fill points across the run.
            step = max(1, run_length // (remaining + 1))
            for i in range(1, remaining + 1):
                candidate = run_start + i * step
                if candidate <= run_end:
                    selected.add(candidate)

    return sorted(selected)


def classify_trace(
    trace: List[Tuple[int, int]],
    slot_ranges: Dict[str, Tuple[int, int]],
    flash_base: int = 0,
    page_size: int = 4096,
    tier2_step: int = 3,
    tier3_step: int = 100,
    discontinuity_window: int = 3,
    bootloader_region: Optional[Tuple[int, int]] = None,
    return_details: bool = False,
) -> Union[List[int], Dict[str, Any]]:
    """
    Classify trace entries into priority tiers and return a sorted list of
    fault points to test.

    Args:
        trace: List of (write_index, flash_offset) from calibration.
        slot_ranges: Dict mapping slot name to (bus_start, bus_end).
            e.g. {"exec": (0xC000, 0x82000), "staging": (0x82000, 0xF8000)}
        flash_base: Bus address of the start of the flash MappedMemory.
        page_size: Flash page size in bytes.
        tier2_step: Test every Nth write in tier 2 regions.
        tier3_step: Test every Nth write in tier 3 regions.
        discontinuity_window: Number of writes before/after a discontinuity
            to include as tier 1.
        bootloader_region: Optional (bus_start, bus_end) of bootloader code
            region.  Writes here are Tier 0 (always tested).
        return_details: If True, return a dict with fault_points and per-tier
            membership info instead of a plain list.

    Returns:
        If return_details is False: sorted list of fault point indices.
        If return_details is True: dict with keys fault_points, tier0, tier1,
            tier2_selected, tier3_selected, tier2_total, tier3_total,
            discontinuity_count, and heuristic_config.
    """
    if not trace:
        if return_details:
            return {
                "fault_points": [],
                "tier0": set(),
                "tier1": set(),
                "tier2_selected": set(),
                "tier3_selected": set(),
                "tier2_total": 0,
                "tier3_total": 0,
                "discontinuity_count": 0,
                "heuristic_config": {
                    "tier2_step": tier2_step,
                    "tier3_step": tier3_step,
                    "discontinuity_window": discontinuity_window,
                },
            }
        return []

    # Tier 0: bootloader self-update region, if configured.
    bl_region: Optional[Tuple[int, int]] = None
    if bootloader_region is not None:
        bl_region = (bootloader_region[0] - flash_base, bootloader_region[1] - flash_base)

    def in_bootloader_region(offset: int) -> bool:
        return bl_region is not None and bl_region[0] <= offset < bl_region[1]

    # Build trailer regions: last page of each slot.
    trailer_regions: List[Tuple[int, int]] = []
    for _name, (bus_start, bus_end) in slot_ranges.items():
        # Trailer is at the end of the slot.  Last page.
        trailer_page_start = bus_end - page_size
        # Convert bus address to flash offset (relative to MappedMemory).
        t_start = trailer_page_start - flash_base
        t_end = bus_end - flash_base
        trailer_regions.append((t_start, t_end))

    # Build boundary sectors: first and last page of each slot.
    boundary_regions: List[Tuple[int, int]] = []
    for _name, (bus_start, bus_end) in slot_ranges.items():
        # First page.
        boundary_regions.append(
            (bus_start - flash_base, bus_start - flash_base + page_size)
        )
        # Last page (overlaps with trailer — that's fine, tier 1 takes priority).
        boundary_regions.append(
            (bus_end - page_size - flash_base, bus_end - flash_base)
        )

    def in_any_region(
        offset: int, regions: List[Tuple[int, int]]
    ) -> bool:
        return any(start <= offset < end for start, end in regions)

    # Pass 1: find discontinuities (address jumps > 1 page between consecutive writes).
    discontinuity_indices: Set[int] = set()
    discontinuity_count = 0
    for i in range(1, len(trace)):
        prev_off = trace[i - 1][1]
        cur_off = trace[i][1]
        # A discontinuity is a jump larger than one page or a direction reversal.
        if abs(cur_off - prev_off) > page_size:
            discontinuity_count += 1
            # Mark writes in the window around the discontinuity.
            for j in range(
                max(0, i - discontinuity_window),
                min(len(trace), i + discontinuity_window + 1),
            ):
                discontinuity_indices.add(j)

    # Pass 2: structural signal detection for tier1 promotion.
    # These are cheap single-pass detections run over the full trace.
    page_entry_indices: Set[int] = set()   # first write to a new page
    page_exit_indices: Set[int] = set()    # last write before page change
    overwrite_indices: Set[int] = set()    # same word address as previous write

    prev_page: Optional[int] = None
    for i, (write_idx, flash_off) in enumerate(trace):
        cur_page = flash_off // page_size

        # Page entry: first write to a page we haven't just been writing to.
        if cur_page != prev_page:
            page_entry_indices.add(i)
            # The previous write was a page exit (if it exists).
            if i > 0:
                page_exit_indices.add(i - 1)

        # Overwrite: same word address as the immediately preceding write.
        if i > 0 and flash_off == trace[i - 1][1]:
            overwrite_indices.add(i)

        prev_page = cur_page

    # Pass 3: classify each write into tiers.
    tier0: Set[int] = set()  # bootloader region (critical)
    tier1: Set[int] = set()
    tier2: Set[int] = set()
    tier3_trace_indices: List[int] = []  # trace indices (not fault points)

    for i, (write_idx, flash_off) in enumerate(trace):
        # Fault point is 0-based: write_idx is 1-based from NVMC.
        fault_point = write_idx - 1

        if in_bootloader_region(flash_off):
            tier0.add(fault_point)
        elif in_any_region(flash_off, trailer_regions):
            tier1.add(fault_point)
        elif i in discontinuity_indices:
            tier1.add(fault_point)
        elif (
            i in page_entry_indices
            or i in page_exit_indices
            or i in overwrite_indices
        ):
            # Structural signal promotion: these patterns indicate
            # high-risk transition points even in non-trailer regions.
            tier1.add(fault_point)
        elif in_any_region(flash_off, boundary_regions):
            tier2.add(fault_point)
        else:
            tier3_trace_indices.append(i)

    # Build final fault point list.
    selected: Set[int] = set()

    # Tier 0: all (bootloader region -- critical).
    selected.update(tier0)

    # Tier 1: all.
    selected.update(tier1)

    # Tier 2: every Kth.
    tier2_selected: Set[int] = set()
    tier2_sorted = sorted(tier2 - tier1)
    for i, fp in enumerate(tier2_sorted):
        if i % tier2_step == 0:
            tier2_selected.add(fp)
    selected.update(tier2_selected)

    # Tier 3: stratified bulk sampling via run segmentation.
    tier3_selected: Set[int] = set()
    runs = _segment_runs(tier3_trace_indices, trace, page_size)

    for run_start, run_end, run_length in runs:
        sampled_trace_indices = _sample_bulk_run(
            run_start, run_end, run_length, tier3_step, tier2_step
        )
        for trace_idx in sampled_trace_indices:
            fault_point = trace[trace_idx][0] - 1
            tier3_selected.add(fault_point)
    selected.update(tier3_selected)

    # Always include first and last fault points.
    all_fps = [w - 1 for w, _ in trace]
    if all_fps:
        selected.add(min(all_fps))
        selected.add(max(all_fps))

    result = sorted(selected)

    if return_details:
        return {
            "fault_points": result,
            "tier0": tier0,
            "tier1": tier1,
            "tier2_selected": tier2_selected,
            "tier3_selected": tier3_selected,
            "tier2_total": len(tier2),
            "tier3_total": len(tier3_trace_indices),
            "discontinuity_count": discontinuity_count,
            "heuristic_config": {
                "tier2_step": tier2_step,
                "tier3_step": tier3_step,
                "discontinuity_window": discontinuity_window,
            },
        }

    return result


def summarize_classification(
    trace: List[Tuple[int, int]],
    fault_points: List[int],
    slot_ranges: Dict[str, Tuple[int, int]],
    flash_base: int = 0,
    page_size: int = 4096,
    bootloader_region: Optional[Tuple[int, int]] = None,
    tier_details: Optional[Dict[str, Any]] = None,
) -> Dict:
    """Return a summary dict for logging/JSON output.

    Args:
        tier_details: Optional dict from classify_trace(return_details=True).
            When provided, per-tier counts and heuristic config are included
            in the output.
    """
    trailer_regions: List[Tuple[int, int]] = []
    for _name, (bus_start, bus_end) in slot_ranges.items():
        t_start = bus_end - page_size - flash_base
        t_end = bus_end - flash_base
        trailer_regions.append((t_start, t_end))

    trailer_writes = sum(
        1
        for _, off in trace
        if any(s <= off < e for s, e in trailer_regions)
    )

    bl_writes = 0
    if bootloader_region is not None:
        bl_start = bootloader_region[0] - flash_base
        bl_end = bootloader_region[1] - flash_base
        bl_writes = sum(
            1
            for _, off in trace
            if bl_start <= off < bl_end
        )
    result: Dict[str, Any] = {
        "total_writes": len(trace),
        "trailer_writes": trailer_writes,
        "bulk_writes": len(trace) - trailer_writes - bl_writes,
        "selected_fault_points": len(fault_points),
        "reduction_ratio": round(len(fault_points) / max(len(trace), 1), 3),
    }
    if bl_writes > 0:
        result["bootloader_region_writes"] = bl_writes
        result["bulk_writes"] = max(0, result["bulk_writes"] - bl_writes)

    if tier_details is not None:
        result["tier0_count"] = len(tier_details["tier0"])
        result["tier1_count"] = len(tier_details["tier1"])
        result["tier2_count"] = len(tier_details["tier2_selected"])
        result["tier3_count"] = len(tier_details["tier3_selected"])
        result["tier2_total"] = tier_details["tier2_total"]
        result["tier3_total"] = tier_details["tier3_total"]
        result["discontinuity_count"] = tier_details["discontinuity_count"]
        result["heuristic_config"] = tier_details["heuristic_config"]

    return result
