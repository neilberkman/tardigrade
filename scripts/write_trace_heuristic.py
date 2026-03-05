"""
Heuristic fault-point prioritization from NVMC write traces.

During calibration, the NVMC records (write_index, flash_offset) for every
word write.  This module classifies writes into priority tiers and produces
a reduced set of fault points that concentrates testing on high-risk writes
(trailer/metadata regions, erase boundaries) while sparsely sampling bulk
data copies.

Tier 1 (EXHAUSTIVE): test every write
  - Writes to trailer regions (last page of each slot)
  - Writes where address jumps discontinuously (region transitions)
  - First/last N writes surrounding any address discontinuity

Tier 2 (DENSE): test every Kth write
  - Writes in the first and last sectors of each slot (boundary sectors)

Tier 3 (SPARSE): test every Kth write
  - Bulk sequential image data copy (same sector, sequential addresses)
"""

import csv
import json
import os
from typing import Dict, List, Optional, Set, Tuple


def load_trace(trace_path: str) -> List[Tuple[int, int]]:
    """Load a write trace CSV into a list of (write_index, flash_offset)."""
    entries: List[Tuple[int, int]] = []
    with open(trace_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append((int(row["write_index"]), int(row["flash_offset"])))
    return entries


def classify_trace(
    trace: List[Tuple[int, int]],
    slot_ranges: Dict[str, Tuple[int, int]],
    flash_base: int = 0,
    page_size: int = 4096,
    tier2_step: int = 3,
    tier3_step: int = 100,
    discontinuity_window: int = 3,
) -> List[int]:
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

    Returns:
        Sorted list of fault point indices (0-based write numbers to test).
    """
    if not trace:
        return []

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
    for i in range(1, len(trace)):
        prev_off = trace[i - 1][1]
        cur_off = trace[i][1]
        # A discontinuity is a jump larger than one page or a direction reversal.
        if abs(cur_off - prev_off) > page_size:
            # Mark writes in the window around the discontinuity.
            for j in range(
                max(0, i - discontinuity_window),
                min(len(trace), i + discontinuity_window + 1),
            ):
                discontinuity_indices.add(j)

    # Pass 2: classify each write.
    tier1: Set[int] = set()
    tier2: Set[int] = set()
    tier3: Set[int] = set()

    for i, (write_idx, flash_off) in enumerate(trace):
        # Fault point is 0-based: write_idx is 1-based from NVMC.
        fault_point = write_idx - 1

        if in_any_region(flash_off, trailer_regions):
            tier1.add(fault_point)
        elif i in discontinuity_indices:
            tier1.add(fault_point)
        elif in_any_region(flash_off, boundary_regions):
            tier2.add(fault_point)
        else:
            tier3.add(fault_point)

    # Build final fault point list.
    selected: Set[int] = set()

    # Tier 1: all.
    selected.update(tier1)

    # Tier 2: every Kth.
    tier2_sorted = sorted(tier2 - tier1)
    for i, fp in enumerate(tier2_sorted):
        if i % tier2_step == 0:
            selected.add(fp)

    # Tier 3: every Kth.
    tier3_sorted = sorted(tier3 - tier1 - tier2)
    for i, fp in enumerate(tier3_sorted):
        if i % tier3_step == 0:
            selected.add(fp)

    # Always include first and last fault points.
    all_fps = [w - 1 for w, _ in trace]
    if all_fps:
        selected.add(min(all_fps))
        selected.add(max(all_fps))

    result = sorted(selected)
    return result


def summarize_classification(
    trace: List[Tuple[int, int]],
    fault_points: List[int],
    slot_ranges: Dict[str, Tuple[int, int]],
    flash_base: int = 0,
    page_size: int = 4096,
) -> Dict:
    """Return a summary dict for logging/JSON output."""
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

    return {
        "total_writes": len(trace),
        "trailer_writes": trailer_writes,
        "bulk_writes": len(trace) - trailer_writes,
        "selected_fault_points": len(fault_points),
        "reduction_ratio": round(len(fault_points) / max(len(trace), 1), 3),
    }
