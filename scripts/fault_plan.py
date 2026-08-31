"""Fault point generation and combinatorial plan building.

Given calibration results and a profile, produce the full list of fault
points + type codes to sweep.  Extracted from audit_bootloader.main().
"""

from __future__ import annotations

import dataclasses
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import apply_clustered_distribution
from fault_types import FAULT_TYPE_NAME_TO_CODE
from profile_loader import MAX_PROFILE_FAULT_POINTS, ProfileConfig, ProfileError
from renode_runner import quick_subset
from trace_utils import (
    flash_base_for_profile,
    load_clean_erase_trace,
    load_clean_write_trace,
)
from security_state_layout import select_security_state_erase_cutpoints
from thumb_instructions import (
    build_instruction_skip_patch_plan,
    enumerate_instruction_skip_addresses,
    make_elf_halfword_reader,
)

INSTRUCTION_SKIP_QUICK_POINTS_PER_RANGE = 5


class _BoundedFaultPointList(list):
    """List that enforces the profile-wide total fault-plan ceiling."""

    def __init__(self, values=(), *, limit: Optional[int] = None):
        self.limit = int(
            MAX_PROFILE_FAULT_POINTS if limit is None else limit
        )
        super().__init__()
        self.extend(values)

    def _reserve_one(self) -> None:
        if len(self) >= self.limit:
            raise ProfileError(
                "fault plan exceeds safety limit {} total points".format(
                    self.limit
                )
            )

    def append(self, value) -> None:
        self._reserve_one()
        super().append(value)

    def extend(self, values) -> None:
        for value in values:
            self.append(value)

    def __iadd__(self, values):
        self.extend(values)
        return self


@dataclasses.dataclass
class FaultPlan:
    """The output of fault point generation."""

    fault_points: List[int]
    fault_types_list: Optional[List[str]]
    heuristic_summary: Optional[Dict[str, Any]]
    swap_progress_summary: Optional[Dict[str, Any]] = None
    security_state_erase_summary: Optional[Dict[str, Any]] = None
    clustered_bit_count: int = 0


@dataclasses.dataclass
class CalibrationInputs:
    """Calibration data needed by the fault planner."""

    max_writes: int
    total_erases: int = 0
    total_i2c_transactions: int = 0
    total_otp_blows: int = 0
    setup_writes: int = 0
    trace_file: Optional[str] = None
    erase_trace_file: Optional[str] = None


def _build_swap_progress_erase_map(
    profile: ProfileConfig,
    erase_entries: List[Dict[str, Any]],
) -> List[Tuple[int, int]]:
    erase_map: List[Tuple[int, int]] = []
    seen: set[Tuple[int, int]] = set()
    page_size = max(1, int(getattr(profile.memory, "page_size", 4096) or 4096))
    flash_base = flash_base_for_profile(profile)

    for entry in erase_entries:
        start = int(entry.get("flash_offset", 0))
        size = int(entry.get("erase_size", 0) or 0)
        if size <= 0:
            size = page_size
        end = start + size
        key = (start, end)
        if end > start and key not in seen:
            seen.add(key)
            erase_map.append(key)

    if erase_map:
        erase_map.sort()
        return erase_map

    for slot in profile.memory.slots.values():
        start = int(slot.base) - flash_base
        end = start + int(slot.size)
        cursor = start
        while cursor < end:
            sector = (cursor, min(end, cursor + page_size))
            if sector not in seen:
                seen.add(sector)
                erase_map.append(sector)
            cursor += page_size
    erase_map.sort()
    return erase_map


def find_swap_progress_boundaries(
    write_entries: List[Dict[str, int]],
    erase_map: List[Tuple[int, int]],
    slot_ranges: List[Tuple[int, int]],
) -> List[int]:
    """Return zero-based power-loss points at slot erase-sector transitions."""

    def _infer_boundaries_from_write_pattern() -> List[int]:
        if not write_entries:
            return []
        granularity = 4
        deltas: List[int] = []
        for prev, curr in zip(write_entries, write_entries[1:]):
            prev_off = int(prev.get("flash_offset", 0))
            curr_off = int(curr.get("flash_offset", 0))
            for slot_start, slot_end in slot_ranges:
                if (
                    slot_start <= prev_off < slot_end
                    and slot_start <= curr_off < slot_end
                    and curr_off > prev_off
                ):
                    delta = curr_off - prev_off
                    if delta > granularity:
                        deltas.append(delta)
                    break
        if not deltas:
            return []
        jump_threshold = max(granularity * 8, min(deltas))
        boundaries: List[int] = []
        prev_entry = None
        prev_slot = None
        for entry in write_entries:
            flash_offset = int(entry.get("flash_offset", 0))
            write_index = int(entry.get("write_index", 0))
            slot_key = None
            for slot_start, slot_end in slot_ranges:
                if slot_start <= flash_offset < slot_end:
                    slot_key = slot_start
                    break
            if slot_key is None:
                continue
            if prev_entry is not None and prev_slot == slot_key:
                prev_off = int(prev_entry.get("flash_offset", 0))
                delta = flash_offset - prev_off
                if delta < 0 or delta >= jump_threshold:
                    boundary = write_index - 1
                    if boundary >= 0 and (not boundaries or boundaries[-1] != boundary):
                        boundaries.append(boundary)
            prev_entry = entry
            prev_slot = slot_key
        return boundaries

    if not erase_map:
        return _infer_boundaries_from_write_pattern()

    def sector_of(flash_offset: int) -> Optional[int]:
        for start, end in erase_map:
            if start <= flash_offset < end:
                return start
        return None

    boundaries: List[int] = []
    current_sectors: Dict[int, int] = {}

    for entry in write_entries:
        write_index = int(entry.get("write_index", 0))
        flash_offset = int(entry.get("flash_offset", 0))
        for slot_start, slot_end in slot_ranges:
            if slot_start <= flash_offset < slot_end:
                sector_start = sector_of(flash_offset)
                if sector_start is None:
                    break
                prev = current_sectors.get(slot_start)
                if prev is not None and sector_start != prev:
                    boundary = write_index - 1
                    if boundary >= 0 and (not boundaries or boundaries[-1] != boundary):
                        boundaries.append(boundary)
                current_sectors[slot_start] = sector_start
                break

    if boundaries:
        return boundaries
    return _infer_boundaries_from_write_pattern()


def find_swap_progress_boundaries_from_erases(
    erase_entries: List[Dict[str, Any]],
    slot_ranges: List[Tuple[int, int]],
) -> List[int]:
    """Return zero-based power-loss points inferred from erase transitions."""
    boundaries: List[int] = []
    current_sectors: Dict[int, int] = {}

    for entry in erase_entries:
        writes_at = entry.get("writes_at_this_point")
        if writes_at is None:
            continue
        flash_offset = int(entry.get("flash_offset", 0))
        for slot_start, slot_end in slot_ranges:
            if slot_start <= flash_offset < slot_end:
                prev = current_sectors.get(slot_start)
                if prev is not None and prev != flash_offset:
                    boundary = int(writes_at)
                    if boundary >= 0 and (not boundaries or boundaries[-1] != boundary):
                        boundaries.append(boundary)
                current_sectors[slot_start] = flash_offset
                break
    return boundaries


def summarize_swap_progress_inference(
    profile: ProfileConfig,
    write_entries: List[Dict[str, Any]],
    erase_entries: List[Dict[str, Any]],
    erase_map: List[Tuple[int, int]],
    slot_ranges: List[Tuple[int, int]],
    boundary_points: List[int],
    *,
    source: str,
) -> Dict[str, Any]:
    """Describe geometry inferred for swap-progress planning."""
    if not write_entries and not erase_entries:
        return {
            "status": "unavailable",
            "reason": "no calibration trace available",
        }

    page_size = max(1, int(getattr(profile.memory, "page_size", 4096) or 4096))
    slot_summaries: List[Dict[str, Any]] = []
    sector_sizes_seen: List[int] = []

    def sector_for(flash_offset: int) -> Optional[Tuple[int, int]]:
        for start, end in erase_map:
            if start <= flash_offset < end:
                return (start, end)
        return None

    for slot_start, slot_end in slot_ranges:
        write_offsets_in_slot = [
            int(entry.get("flash_offset", 0))
            for entry in write_entries
            if slot_start <= int(entry.get("flash_offset", 0)) < slot_end
        ]
        erase_offsets_in_slot = [
            int(entry.get("flash_offset", 0))
            for entry in erase_entries
            if slot_start <= int(entry.get("flash_offset", 0)) < slot_end
        ]
        if not write_offsets_in_slot and not erase_offsets_in_slot:
            continue

        sector_starts: List[int] = []
        inferred_sizes: List[int] = []
        if source == "erase_trace":
            for offset in erase_offsets_in_slot or write_offsets_in_slot:
                sector = sector_for(offset)
                if sector is None:
                    continue
                start, end = sector
                if not sector_starts or sector_starts[-1] != start:
                    sector_starts.append(start)
                    inferred_sizes.append(end - start)
        else:
            aligned = sorted({(offset // page_size) * page_size for offset in write_offsets_in_slot})
            sector_starts = aligned
            inferred_sizes = [page_size] * len(aligned)

        if not sector_starts:
            continue

        sector_sizes_seen.extend(inferred_sizes)
        slot_summaries.append(
            {
                "slot_offset": "0x{:X}".format(slot_start),
                "slot_size": "0x{:X}".format(slot_end - slot_start),
                "touched_sectors": len(sector_starts),
                "first_sector": "0x{:X}".format(sector_starts[0]),
                "last_sector": "0x{:X}".format(sector_starts[-1]),
                "inferred_sector_sizes": [
                    "0x{:X}".format(size) for size in sorted(set(inferred_sizes))
                ],
            }
        )

    if not slot_summaries:
        return {
            "status": "unavailable",
            "reason": "write trace did not touch configured slots",
        }

    return {
        "status": "inferred",
        "source": source,
        "boundary_count": len(boundary_points),
        "boundary_points": list(boundary_points[:32]),
        "inferred_sector_sizes": [
            "0x{:X}".format(size) for size in sorted(set(sector_sizes_seen))
        ],
        "slots": slot_summaries,
    }


def _derive_read_fault_points(
    profile: ProfileConfig,
    *,
    fault_step: int = 1,
    fault_start: Optional[int] = None,
    fault_end: Optional[int] = None,
) -> List[int]:
    """Derive read-fault indices directly from configured target regions.

    Read-bit-flip points index aligned words in the configured read regions;
    they do not require calibration's write-count trace.
    """
    read_cfg = getattr(profile.fault_sweep, "read_fault_config", None)
    if read_cfg is None or not read_cfg.target_regions:
        return []

    granularity = max(1, int(getattr(profile.memory, "write_granularity", 1) or 1))
    total_region_bytes = sum(
        max(0, int(end) - int(start))
        for start, end in read_cfg.target_regions
    )
    if total_region_bytes <= 0:
        return []

    point_count = max(1, (total_region_bytes + granularity - 1) // granularity)
    step = max(1, fault_step)
    start = max(0, fault_start or 0)
    end = point_count if fault_end is None else min(point_count, int(fault_end))
    if start >= end:
        return []

    selected_count = (end - start + step - 1) // step
    if fault_end is None and (point_count - 1 - start) % step != 0:
        selected_count += 1
    if selected_count > MAX_PROFILE_FAULT_POINTS:
        raise ProfileError(
            "read fault plan exceeds safety limit {} total points".format(
                MAX_PROFILE_FAULT_POINTS
            )
        )

    points = list(range(start, end, step))
    if (point_count - 1) not in points and fault_end is None:
        points.append(point_count - 1)
    return points


def _slice_explicit_points(
    points: List[int],
    *,
    fault_step: int = 1,
    fault_start: Optional[int] = None,
    fault_end: Optional[int] = None,
) -> List[int]:
    """Filter an explicit point list by value range and stride."""
    start = 0 if fault_start is None else int(fault_start)
    end = None if fault_end is None else int(fault_end)
    filtered = [
        point for point in points
        if point >= start and (end is None or point < end)
    ]
    step = max(1, int(fault_step))
    if step > 1:
        filtered = filtered[::step]
    return filtered


def _sample_evenly_spaced_points(points: List[int], *, sample_count: int) -> List[int]:
    """Return up to ``sample_count`` representatives across an ordered point list."""
    if len(points) <= sample_count:
        return list(points)
    if sample_count <= 1:
        return [points[0]]
    last_index = len(points) - 1
    indices: List[int] = []
    for sample_index in range(sample_count):
        idx = (sample_index * last_index) // (sample_count - 1)
        if not indices or indices[-1] != idx:
            indices.append(idx)
    return [points[idx] for idx in indices]


def _sample_edge_points(points: List[int], *, sample_count: int) -> List[int]:
    """Return first/last-biased samples from an ordered point list."""
    if len(points) <= sample_count:
        return list(points)
    if sample_count <= 1:
        return [points[-1]]
    if sample_count == 2:
        return [points[0], points[-1]]
    middle = _sample_evenly_spaced_points(points[1:-1], sample_count=sample_count - 2)
    return [points[0], *middle, points[-1]]


def _looks_like_thumb_branch_check(halfword: int) -> bool:
    """Return True for common 16-bit branch/check opcodes worth prioritizing."""
    opcode = int(halfword) & 0xFFFF
    if (opcode & 0xF500) == 0xB100:  # CBZ / CBNZ
        return True
    if (opcode & 0xF000) == 0xD000 and ((opcode >> 8) & 0xF) < 0xE:  # B<cond>
        return True
    if (opcode & 0xF800) == 0xE000:  # B (T2, 16-bit unconditional)
        return True
    return False


def _looks_like_thumb_compare_check(halfword: int) -> bool:
    """Return True for common 16-bit compare/test opcodes."""
    opcode = int(halfword) & 0xFFFF
    if (opcode & 0xF800) == 0x2800:  # CMP (immediate)
        return True
    if (opcode & 0xFFC0) == 0x4280:  # CMP (register)
        return True
    if (opcode & 0xFF00) == 0x4500:  # CMP (high register)
        return True
    if (opcode & 0xFFC0) == 0x4200:  # TST (register)
        return True
    return False


def _sample_instruction_skip_range_points(
    range_points: List[int],
    *,
    read_halfword,
    sample_count: int,
) -> List[int]:
    """Bias quick instruction-skip sampling toward control-flow checks."""
    if len(range_points) <= sample_count:
        return list(range_points)

    branch_points: List[int] = []
    compare_points: List[int] = []
    for point in range_points:
        if read_halfword is None:
            break
        try:
            halfword = int(read_halfword(point)) & 0xFFFF
        except Exception:
            continue
        if _looks_like_thumb_branch_check(halfword):
            branch_points.append(point)
        elif _looks_like_thumb_compare_check(halfword):
            compare_points.append(point)

    selected: List[int] = []
    seen: set[int] = set()

    def _add_priority_points(points: List[int], count: int) -> None:
        if count <= 0 or not points:
            return
        for point in _sample_edge_points(
            points,
            sample_count=min(count, len(points)),
        ):
            if point not in seen:
                selected.append(point)
                seen.add(point)

    def _add_fallback_points(points: List[int], count: int) -> None:
        if count <= 0 or not points:
            return
        for point in _sample_evenly_spaced_points(
            points,
            sample_count=min(count, len(points)),
        ):
            if point not in seen:
                selected.append(point)
                seen.add(point)

    remaining = sample_count
    _add_priority_points(branch_points, min(2, remaining))
    remaining = sample_count - len(selected)
    _add_priority_points(compare_points, min(2, remaining))
    remaining = sample_count - len(selected)
    _add_fallback_points(range_points, remaining)
    return [point for point in range_points if point in seen]


def _quick_subset_instruction_skip_ranges(
    points_by_range: List[List[int]],
    *,
    read_halfword=None,
    sample_count: int = INSTRUCTION_SKIP_QUICK_POINTS_PER_RANGE,
) -> List[int]:
    """Sample instruction-skip targets per configured range instead of globally."""
    sampled: List[int] = []
    seen: set[int] = set()
    for range_points in points_by_range:
        for point in _sample_instruction_skip_range_points(
            range_points,
            read_halfword=read_halfword,
            sample_count=sample_count,
        ):
            if point not in seen:
                sampled.append(point)
                seen.add(point)
    return sampled


def build_fault_plan(
    profile: ProfileConfig,
    calibration: CalibrationInputs,
    quick: bool = False,
    fault_step: int = 1,
    fault_start: Optional[int] = None,
    fault_end: Optional[int] = None,
) -> FaultPlan:
    """Build the full combinatorial fault plan from profile + calibration.

    Returns a FaultPlan with fault_points, fault_types_list, and
    optional heuristic_summary.
    """
    max_writes = int(calibration.max_writes)
    total_erases = int(calibration.total_erases)
    total_i2c_transactions = int(calibration.total_i2c_transactions)
    total_otp_blows = int(calibration.total_otp_blows)
    setup_writes = int(calibration.setup_writes)
    for field_name, value in (
        ("max_writes", max_writes),
        ("total_erases", total_erases),
        ("total_i2c_transactions", total_i2c_transactions),
        ("total_otp_blows", total_otp_blows),
        ("setup_writes", setup_writes),
    ):
        if value < 0 or value > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "calibration.{} must be between 0 and {}".format(
                    field_name,
                    MAX_PROFILE_FAULT_POINTS,
                )
            )
    configured_otp_bound = getattr(profile.fault_sweep, "max_otp_blows", None)
    if configured_otp_bound is not None:
        configured_otp_bound = int(configured_otp_bound)
        total_otp_blows = (
            min(total_otp_blows, configured_otp_bound)
            if total_otp_blows > 0
            else configured_otp_bound
        )
    trace_file = calibration.trace_file
    erase_trace_file = calibration.erase_trace_file

    fault_types = list(getattr(profile.fault_sweep, "fault_types", []) or [])
    include_power_loss = "power_loss" in fault_types or not fault_types
    include_swap_progress = "swap_progress" in fault_types
    include_security_state_erase = "security_state_erase" in fault_types
    include_erases = (
        "interrupted_erase" in fault_types or "multi_sector_atomicity" in fault_types
    )
    include_multi_sector_atomicity = "multi_sector_atomicity" in fault_types
    include_bit_corruption = "bit_corruption" in fault_types
    include_silent_write_failure = "silent_write_failure" in fault_types
    include_driver_error = "driver_error" in fault_types
    include_rc_injection = "rc_injection" in fault_types
    include_write_disturb = "write_disturb" in fault_types
    include_wear_leveling = "wear_leveling_corruption" in fault_types
    include_write_rejection = "write_rejection" in fault_types
    include_reset_at_time = "reset_at_time" in fault_types
    include_read_bit_flip = "read_bit_flip" in fault_types
    include_command_drop = "command_drop" in fault_types
    include_instruction_skip = "instruction_skip" in fault_types
    include_i2c_faults = any(ft.startswith("i2c_") for ft in fault_types)
    i2c_fault_types = [ft for ft in fault_types if ft.startswith("i2c_")]
    include_otp_faults = any(ft.startswith("otp_") for ft in fault_types)
    otp_fault_types = [ft for ft in fault_types if ft.startswith("otp_")]
    include_nvs_corruption = "nvs_corruption" in fault_types
    include_timed_bit_corruption = "timed_bit_corruption" in fault_types
    include_metadata_fault = getattr(profile.fault_sweep, "metadata_fault", None) is not None and profile.fault_sweep.metadata_fault.enabled

    # -------------------------------------------------------------------
    # Heuristic vs exhaustive point selection
    # -------------------------------------------------------------------
    heuristic_summary: Optional[Dict[str, Any]] = None
    quick_use_heuristic = bool(
        getattr(profile.fault_sweep, "quick_use_heuristic", False)
    )
    use_heuristic = (
        trace_file
        and os.path.exists(trace_file)
        and (not quick or quick_use_heuristic)
        and fault_start is None
        and fault_end is None
        and fault_step == 1
        and getattr(profile.fault_sweep, "sweep_strategy", "heuristic") != "exhaustive"
    )

    if use_heuristic:
        from write_trace_heuristic import (
            classify_trace,
            load_trace,
            summarize_classification,
        )

        trace = load_trace(trace_file)
        slot_ranges_for_heuristic: Dict[str, Tuple[int, int]] = {}
        for sname, sinfo in profile.memory.slots.items():
            slot_ranges_for_heuristic[sname] = (sinfo.base, sinfo.base + sinfo.size)
        flash_base = flash_base_for_profile(profile)

        bl_region_for_heuristic = None
        if profile.bootloader_region is not None:
            bl = profile.bootloader_region
            bl_region_for_heuristic = (bl.base, bl.base + bl.size)

        heuristic_kwargs: Dict[str, Any] = {}
        if profile.fault_sweep.heuristic_config is not None:
            hc = profile.fault_sweep.heuristic_config
            heuristic_kwargs["tier2_step"] = hc.tier2_step
            heuristic_kwargs["tier3_step"] = hc.tier3_step
            heuristic_kwargs["discontinuity_window"] = hc.discontinuity_window
            if hc.critical_regions:
                heuristic_kwargs["critical_regions"] = hc.critical_regions
            if hc.target_points is not None:
                heuristic_kwargs["target_points"] = hc.target_points
            if hc.shard_count > 1:
                heuristic_kwargs["shard_count"] = hc.shard_count
                heuristic_kwargs["shard_index"] = hc.shard_index
            if hc.random_tail_budget > 0:
                heuristic_kwargs["random_tail_budget"] = hc.random_tail_budget
        if "target_points" not in heuristic_kwargs:
            max_heuristic_points = getattr(profile.fault_sweep, "max_heuristic_points", 2000)
            if max_heuristic_points is not None:
                heuristic_kwargs["target_points"] = int(max_heuristic_points)
        classification = classify_trace(
            trace=trace,
            slot_ranges=slot_ranges_for_heuristic,
            flash_base=flash_base,
            page_size=getattr(profile.memory, "page_size", 4096),
            bootloader_region=bl_region_for_heuristic,
            return_details=True,
            **heuristic_kwargs,
        )
        fault_points = classification["fault_points"]
        heuristic_summary = summarize_classification(
            trace=trace,
            fault_points=fault_points,
            slot_ranges=slot_ranges_for_heuristic,
            flash_base=flash_base,
            bootloader_region=bl_region_for_heuristic,
            critical_regions=heuristic_kwargs.get("critical_regions"),
            tier_details=classification,
        )
        print(
            "Heuristic: {} fault points from {} writes (reduction {:.1f}x). "
            "Trailer writes: {}.".format(
                heuristic_summary["selected_fault_points"],
                heuristic_summary["total_writes"],
                1.0 / max(heuristic_summary["reduction_ratio"], 0.001),
                heuristic_summary["trailer_writes"],
            ),
            file=sys.stderr,
        )
    else:
        if max_writes > 0:
            step = max(1, fault_step)
            fp_start = fault_start if fault_start is not None else 0
            # CLI slicing selects from the calibrated write domain; it must
            # never expand that bounded domain and allocate unplanned points.
            fp_end = (
                min(fault_end, max_writes)
                if fault_end is not None
                else max_writes
            )
            fault_points = list(range(fp_start, fp_end, step))
            if (
                max_writes - 1 not in fault_points
                and fault_end is None
                and fp_start < max_writes
            ):
                fault_points.append(max_writes - 1)
        elif include_read_bit_flip:
            fault_points = _derive_read_fault_points(
                profile,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
        else:
            fault_points = []

    if quick and not quick_use_heuristic:
        fault_points = quick_subset(fault_points)
    if len(fault_points) > MAX_PROFILE_FAULT_POINTS:
        raise ProfileError(
            "fault plan exceeds safety limit {} base points".format(
                MAX_PROFILE_FAULT_POINTS
            )
        )

    # -------------------------------------------------------------------
    # Build combined fault point list
    # -------------------------------------------------------------------
    fault_types_list: Optional[List[str]] = None
    has_mixed_types = (
        (include_erases and total_erases > 0)
        or include_bit_corruption
        or include_silent_write_failure
        or include_driver_error
        or include_rc_injection
        or include_write_disturb
        or include_wear_leveling
        or include_write_rejection
        or include_reset_at_time
        or include_read_bit_flip
        or include_command_drop
        or include_swap_progress
        or include_security_state_erase
        or include_instruction_skip
        or include_i2c_faults
        or include_otp_faults
        or include_nvs_corruption
        or include_timed_bit_corruption
        or profile.fault_sweep.phase2_fault.enabled
        or profile.fault_sweep.multi_fault.enabled
        or include_metadata_fault
        or profile.fault_sweep.hook_fault.enabled
        or profile.fault_sweep.confirm_cycle.enabled
    )
    clustered_bit_count = 0
    swap_progress_summary: Optional[Dict[str, Any]] = None
    security_state_erase_summary: Optional[Dict[str, Any]] = None
    if has_mixed_types:
        write_fps: List[Tuple[int, str]] = []
        if include_power_loss:
            write_fps = [(fp, 'w') for fp in fault_points] if max_writes > 0 else []
        combined = _BoundedFaultPointList(write_fps)
        swap_progress_count = 0

        # Security-state erase-domain selector.  It emits ordinary power-loss
        # points and only annotates their wire label with the semantic phase;
        # the runtime therefore uses the existing reboot path.
        if include_security_state_erase:
            security_write_entries = load_clean_write_trace(trace_file)
            security_erase_entries = load_clean_erase_trace(erase_trace_file)
            try:
                security_cutpoints, security_state_erase_summary = (
                    select_security_state_erase_cutpoints(
                        getattr(profile, "persistent_state_layout", None),
                        security_write_entries,
                        security_erase_entries,
                        flash_base=flash_base_for_profile(profile),
                        max_writes=max_writes,
                        trace_address_map=getattr(
                            profile.memory, "trace_address_map", None
                        ),
                    )
                )
            except ValueError as exc:
                raise ProfileError(
                    "security_state_erase campaign preflight failed: {}".format(exc)
                ) from exc
            for cutpoint in security_cutpoints:
                combined.append((cutpoint["fault_at"], cutpoint["wire_type"]))
            if not security_cutpoints:
                print(
                    "Skipping security_state_erase: no shared security erase units found.",
                    file=sys.stderr,
                )

        if include_swap_progress:
            swap_entries = load_clean_write_trace(trace_file)
            erase_entries = load_clean_erase_trace(erase_trace_file)
            if swap_entries:
                flash_base = flash_base_for_profile(profile)
                slot_ranges = sorted(
                    (
                        int(slot.base) - flash_base,
                        int(slot.base) - flash_base + int(slot.size),
                    )
                    for slot in profile.memory.slots.values()
                )
                erase_map = _build_swap_progress_erase_map(profile, erase_entries)
                summary_source = "erase_trace" if erase_entries else "write_pattern"
                swap_fps = find_swap_progress_boundaries(swap_entries, erase_map, slot_ranges)
                swap_fps = _slice_explicit_points(
                    swap_fps,
                    fault_step=fault_step,
                    fault_start=fault_start,
                    fault_end=fault_end,
                )
                swap_progress_summary = summarize_swap_progress_inference(
                    profile,
                    swap_entries,
                    erase_entries,
                    erase_map,
                    slot_ranges,
                    swap_fps,
                    source=summary_source,
                )
                if quick and not quick_use_heuristic:
                    swap_fps = quick_subset(swap_fps)
                combined.extend(
                    (fp, FAULT_TYPE_NAME_TO_CODE["swap_progress"])
                    for fp in swap_fps
                )
                swap_progress_count = len(swap_fps)
            elif erase_entries:
                flash_base = flash_base_for_profile(profile)
                slot_ranges = sorted(
                    (
                        int(slot.base) - flash_base,
                        int(slot.base) - flash_base + int(slot.size),
                    )
                    for slot in profile.memory.slots.values()
                )
                erase_map = _build_swap_progress_erase_map(profile, erase_entries)
                swap_fps = find_swap_progress_boundaries_from_erases(
                    erase_entries,
                    slot_ranges,
                )
                swap_fps = _slice_explicit_points(
                    swap_fps,
                    fault_step=fault_step,
                    fault_start=fault_start,
                    fault_end=fault_end,
                )
                swap_progress_summary = summarize_swap_progress_inference(
                    profile,
                    [],
                    erase_entries,
                    erase_map,
                    slot_ranges,
                    swap_fps,
                    source="erase_trace",
                )
                if quick and not quick_use_heuristic:
                    swap_fps = quick_subset(swap_fps)
                combined.extend(
                    (fp, FAULT_TYPE_NAME_TO_CODE["swap_progress"])
                    for fp in swap_fps
                )
                swap_progress_count = len(swap_fps)
            else:
                swap_progress_summary = {
                    "status": "unavailable",
                    "reason": "no calibration trace available",
                }
                print(
                    "Skipping swap_progress fault points: no calibration trace available.",
                    file=sys.stderr,
                )

        # Erase-based fault points.
        is_mram_backend = (
            profile.flash_backend
            and "mram" in profile.flash_backend.lower()
        )
        erase_count = 0
        atomicity_count = 0
        if include_erases and total_erases > 0 and not is_mram_backend:
            erase_fps = list(range(0, total_erases))
            erase_fps = _slice_explicit_points(
                erase_fps,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
            if quick and not quick_use_heuristic:
                erase_fps = quick_subset(erase_fps)
            if "interrupted_erase" in fault_types:
                combined.extend((ep, 'e') for ep in erase_fps)
                erase_count = len(erase_fps)
            if include_multi_sector_atomicity:
                combined.extend((ep, 'a') for ep in erase_fps)
                atomicity_count = len(erase_fps)
        elif include_erases and is_mram_backend:
            print(
                "Skipping erase fault points: MRAM backend '{}' has no "
                "page erases.".format(profile.flash_backend),
                file=sys.stderr,
            )

        # Bit-corruption fault points.
        bit_count = 0
        clustered_bit_count = 0
        if include_bit_corruption:
            bit_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                bit_fps = quick_subset(bit_fps)

            combined.extend((bp, 'b') for bp in bit_fps)
            bit_count = len(bit_fps)

            dist = profile.fault_sweep.fault_distribution
            if dist is not None and dist.mode == "clustered":
                slot_base = 0
                wg = profile.memory.write_granularity
                if profile.memory.slots:
                    staging = profile.memory.slots.get(
                        "staging",
                        next(iter(profile.memory.slots.values())),
                    )
                    slot_base = staging.base

                filtered = apply_clustered_distribution(
                    fault_points=bit_fps,
                    distribution=dist,
                    write_granularity=wg,
                    slot_base=slot_base,
                )
                for fp, cseed in filtered:
                    combined.append((fp, "b:{}".format(cseed)))
                clustered_bit_count = len(filtered)

        silent_count = 0
        if include_silent_write_failure:
            silent_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                silent_fps = quick_subset(silent_fps)
            combined.extend((sp, 's') for sp in silent_fps)
            silent_count = len(silent_fps)

        driver_error_count = 0
        if include_driver_error:
            driver_error_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                driver_error_fps = quick_subset(driver_error_fps)
            combined.extend((gp, 'g') for gp in driver_error_fps)
            driver_error_count = len(driver_error_fps)

        rc_injection_count = 0
        if include_rc_injection:
            rc_injection_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                rc_injection_fps = quick_subset(rc_injection_fps)
            combined.extend((xp, 'x') for xp in rc_injection_fps)
            rc_injection_count = len(rc_injection_fps)

        disturb_count = 0
        if include_write_disturb:
            disturb_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                disturb_fps = quick_subset(disturb_fps)
            combined.extend((dp, 'd') for dp in disturb_fps)
            disturb_count = len(disturb_fps)

        wear_count = 0
        if include_wear_leveling:
            wear_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                wear_fps = quick_subset(wear_fps)
            combined.extend((wp, 'l') for wp in wear_fps)
            wear_count = len(wear_fps)

        rejection_count = 0
        if include_write_rejection:
            rejection_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                rejection_fps = quick_subset(rejection_fps)
            combined.extend((rp, 'r') for rp in rejection_fps)
            rejection_count = len(rejection_fps)

        timed_reset_count = 0
        if include_reset_at_time:
            timed_reset_fps = list(fault_points)
            if not timed_reset_fps:
                timed_reset_fps = [0]
            if quick and not quick_use_heuristic:
                timed_reset_fps = quick_subset(timed_reset_fps)
            combined.extend((tp, 't') for tp in timed_reset_fps)
            timed_reset_count = len(timed_reset_fps)

        read_flip_count = 0
        if include_read_bit_flip:
            read_flip_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                read_flip_fps = quick_subset(read_flip_fps)
            combined.extend((fp, 'f') for fp in read_flip_fps)
            read_flip_count = len(read_flip_fps)

        command_drop_count = 0
        if include_command_drop:
            command_drop_fps = list(fault_points)
            if quick and not quick_use_heuristic:
                command_drop_fps = quick_subset(command_drop_fps)
            combined.extend((fp, 'k') for fp in command_drop_fps)
            command_drop_count = len(command_drop_fps)

        # I2C bus fault injection.
        i2c_fault_count = 0
        if include_i2c_faults and total_i2c_transactions > 0:
            i2c_fps = list(range(total_i2c_transactions))
            i2c_fps = _slice_explicit_points(
                i2c_fps,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
            if quick and not quick_use_heuristic:
                i2c_fps = quick_subset(i2c_fps)
            for i2c_ft in i2c_fault_types:
                i2c_code = FAULT_TYPE_NAME_TO_CODE[i2c_ft]
                combined.extend((fp, i2c_code) for fp in i2c_fps)
                i2c_fault_count += len(i2c_fps)

        # OTP fault injection.
        otp_fault_count = 0
        if include_otp_faults and total_otp_blows > 0:
            otp_fps = list(range(total_otp_blows))
            otp_fps = _slice_explicit_points(
                otp_fps,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
            if quick and not quick_use_heuristic:
                otp_fps = quick_subset(otp_fps)
            for otp_ft in otp_fault_types:
                otp_code = FAULT_TYPE_NAME_TO_CODE[otp_ft]
                combined.extend((fp, otp_code) for fp in otp_fps)
                otp_fault_count += len(otp_fps)
        elif include_otp_faults and total_otp_blows == 0:
            print(
                "Skipping OTP fault points: calibration found 0 OTP blows.",
                file=sys.stderr,
            )

        # NVS corruption variants.
        nvs_fault_count = 0
        if include_nvs_corruption:
            nvs_cfg = profile.fault_sweep.nvs_corruption
            if nvs_cfg.enabled and profile.nvs_region is not None:
                nvs_variants = nvs_cfg.variant_specs()
                for vi, _variant in enumerate(nvs_variants):
                    combined.append((vi, "nv:{}".format(vi)))
                    nvs_fault_count += 1
            elif not nvs_cfg.enabled:
                print(
                    "nvs_corruption in fault_types but nvs_corruption "
                    "config not enabled; skipping.",
                    file=sys.stderr,
                )
            elif profile.nvs_region is None:
                print(
                    "nvs_corruption in fault_types but no nvs_region "
                    "configured; skipping.",
                    file=sys.stderr,
                )

        # Instruction-skip fault injection.
        instruction_skip_count = 0
        literal_pool_excluded = 0
        if include_instruction_skip:
            isc = profile.fault_sweep.instruction_skip_config
            if isc is not None and isc.target_addresses:
                # Classify halfwords as code vs literal pool data.
                literal_pools: set = set()
                read_halfword = None
                elf_path = profile.bootloader_elf
                if elf_path:
                    try:
                        read_halfword = make_elf_halfword_reader(elf_path)
                    except Exception as exc:
                        print(
                            "WARNING: failed to read bootloader ELF for width-aware "
                            "instruction_skip planning ({}); falling back to "
                            "halfword enumeration".format(exc),
                            file=sys.stderr,
                        )
                if not isc.include_literal_pools:
                    if elf_path:
                        from thumb_classify import find_literal_pools

                        literal_pools = find_literal_pools(
                            elf_path, isc.target_addresses
                        )
                    else:
                        print(
                            "WARNING: no bootloader ELF — literal pool "
                            "filtering disabled",
                            file=sys.stderr,
                        )

                skip_ranges: List[List[int]] = []
                sc = isc.skip_count if isc.skip_count > 0 else 1
                instruction_candidate_total = 0
                for region_start, region_end in isc.target_addresses:
                    region_point_upper_bound = max(
                        0,
                        (int(region_end) - int(region_start) + 1) // 2,
                    )
                    instruction_candidate_total += region_point_upper_bound
                    if instruction_candidate_total > MAX_PROFILE_FAULT_POINTS:
                        raise ProfileError(
                            "instruction-skip regions exceed safety limit {} "
                            "candidate points".format(MAX_PROFILE_FAULT_POINTS)
                        )
                    region_skip_addrs: List[int] = []
                    if read_halfword is not None:
                        candidate_addrs = enumerate_instruction_skip_addresses(
                            read_halfword,
                            region_start,
                            region_end,
                            skip_count=sc,
                        )
                        for addr in candidate_addrs:
                            patch_plan = build_instruction_skip_patch_plan(
                                read_halfword,
                                addr,
                                sc,
                                patch_model="nop",
                            )
                            patch_addrs = patch_plan.get("patched_addresses", [])
                            if any(int(patch_addr) in literal_pools for patch_addr in patch_addrs):
                                literal_pool_excluded += 1
                                continue
                            region_skip_addrs.append(addr)
                    else:
                        end = region_end - (sc - 1) * 2
                        for addr in range(region_start, max(end, region_start), 2):
                            hits_pool = any(
                                (addr + i * 2) in literal_pools
                                for i in range(sc)
                            )
                            if hits_pool:
                                literal_pool_excluded += 1
                                continue
                            region_skip_addrs.append(addr)
                    skip_ranges.append(region_skip_addrs)
                if (
                    quick
                    and not quick_use_heuristic
                    and fault_step == 1
                    and fault_start is None
                    and fault_end is None
                ):
                    skip_addrs = _quick_subset_instruction_skip_ranges(
                        skip_ranges,
                        read_halfword=read_halfword,
                    )
                else:
                    skip_addrs = [
                        addr
                        for region_skip_addrs in skip_ranges
                        for addr in region_skip_addrs
                    ]
                    skip_addrs = _slice_explicit_points(
                        skip_addrs,
                        fault_step=fault_step,
                        fault_start=fault_start,
                        fault_end=fault_end,
                    )
                    if quick and not quick_use_heuristic:
                        skip_addrs = quick_subset(skip_addrs)
                for addr in skip_addrs:
                    combined.append((addr, "i:0x{:X}".format(addr)))
                instruction_skip_count = len(skip_addrs)

        # Timed bit-corruption (TOCTOU) fault injection.
        timed_bit_corruption_count = 0
        if include_timed_bit_corruption:
            tbc = getattr(profile.fault_sweep, "timed_bit_corruption_config", None)
            if tbc is not None and tbc.pairs:
                for pair in tbc.pairs:
                    trigger = pair.get("trigger", {})
                    corrupt_addr = pair.get("corrupt_address", 0)
                    bit_flips = pair.get("bit_flips", 1)
                    # If trigger has a symbol, resolve it the same way
                    # instruction_skip does.  Otherwise use the address directly.
                    trigger_addr = trigger.get("address", 0)
                    if trigger_addr:
                        combined.append((
                            trigger_addr,
                            "tb:0x{:X}:0x{:X}:{}".format(
                                trigger_addr, corrupt_addr, bit_flips
                            ),
                        ))
                        timed_bit_corruption_count += 1

        # Metadata fault injection.
        metadata_count = 0
        if include_metadata_fault:
            _setup_writes = setup_writes
            if _setup_writes == 0:
                _setup_writes = len(profile.pre_boot_state)
            if _setup_writes > MAX_PROFILE_FAULT_POINTS:
                raise ProfileError(
                    "metadata fault plan exceeds safety limit {} points".format(
                        MAX_PROFILE_FAULT_POINTS
                    )
                )
            if _setup_writes > 0:
                mf_types = profile.fault_sweep.metadata_fault.fault_types
                mf_fps = list(range(0, _setup_writes))
                mf_fps = _slice_explicit_points(
                    mf_fps,
                    fault_step=fault_step,
                    fault_start=fault_start,
                    fault_end=fault_end,
                )
                if quick and not quick_use_heuristic:
                    mf_fps = quick_subset(mf_fps)
                for mf_fp in mf_fps:
                    for mf_name in mf_types:
                        mf_code = FAULT_TYPE_NAME_TO_CODE[mf_name]
                        combined.append((mf_fp, "m:{}".format(mf_code)))
                        metadata_count += 1

        # Hook fault injection.
        hook_count = 0
        hf_config = profile.fault_sweep.hook_fault
        if (
            hf_config.enabled
            and profile.fault_sweep.boot_cycle_hook
            and profile.fault_sweep.boot_cycles > 1
        ):
            hook_max = (
                hf_config.max_points
                if hf_config.max_points > 0
                else min(50, max(max_writes, 1))
            )
            hf_types = [FAULT_TYPE_NAME_TO_CODE[ft] for ft in hf_config.fault_types]
            hook_fps = list(range(0, hook_max))
            hook_fps = _slice_explicit_points(
                hook_fps,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
            if quick and not quick_use_heuristic:
                hook_fps = quick_subset(hook_fps)
            for hf_fp in hook_fps:
                for hf_code in hf_types:
                    combined.append((hf_fp, "h:{}:{}".format(hf_fp, hf_code)))
                    hook_count += 1

        # Confirm-cycle fault injection.
        confirm_count = 0
        cc_config = profile.fault_sweep.confirm_cycle
        if cc_config.enabled and cc_config.confirm_function:
            cc_max = (
                cc_config.max_points
                if cc_config.max_points > 0
                else min(50, max(max_writes, 1))
            )
            cc_types = [FAULT_TYPE_NAME_TO_CODE[ft] for ft in cc_config.fault_types]
            cc_fps = list(range(0, cc_max))
            cc_fps = _slice_explicit_points(
                cc_fps,
                fault_step=fault_step,
                fault_start=fault_start,
                fault_end=fault_end,
            )
            if quick and not quick_use_heuristic:
                cc_fps = quick_subset(cc_fps)
            for cc_fp in cc_fps:
                for cc_code in cc_types:
                    combined.append((cc_fp, "cc:{}:{}".format(cc_fp, cc_code)))
                    confirm_count += 1

        # Phase 2 recovery fault injection.
        p2_config = profile.fault_sweep.phase2_fault
        phase2_count = 0
        if p2_config.enabled and (write_fps or include_reset_at_time):
            p2_max = p2_config.max_points if p2_config.max_points > 0 else min(50, max(max_writes, 1))
            p2_type_codes = [
                FAULT_TYPE_NAME_TO_CODE[ft] for ft in p2_config.fault_types
            ]

            p2_timed_codes = [c for c in p2_type_codes if c == "t"]
            p2_write_codes = [c for c in p2_type_codes if c != "t"]

            if p2_write_codes and write_fps:
                if quick_use_heuristic:
                    p1_representatives = [fp for fp, _ in write_fps]
                else:
                    p1_representatives = quick_subset([fp for fp, _ in write_fps])
                p2_range = list(range(0, p2_max))
                if quick and not quick_use_heuristic:
                    p2_range = quick_subset(p2_range)
                for p1_fp in p1_representatives:
                    for p2_fp in p2_range:
                        for p2_code in p2_write_codes:
                            enc = "p2:{}:{}:w:{}".format(p1_fp, p2_fp, p2_code)
                            combined.append((p1_fp, enc))
                            phase2_count += 1

            if p2_timed_codes:
                timed_p1_fps = list(fault_points) if fault_points else [0]
                if quick_use_heuristic:
                    timed_p1_reps = timed_p1_fps
                else:
                    timed_p1_reps = quick_subset(timed_p1_fps)
                timed_p2_range = list(range(0, p2_max))
                if quick and not quick_use_heuristic:
                    timed_p2_range = quick_subset(timed_p2_range)
                for p1_fp in timed_p1_reps:
                    for p2_fp in timed_p2_range:
                        enc = "p2:{}:{}:t:t".format(p1_fp, p2_fp)
                        combined.append((p1_fp, enc))
                        phase2_count += 1

        fault_points = [fp for fp, _ in combined]
        fault_types_list = [ft for _, ft in combined]
        parts = ["{} writes".format(len(write_fps))]
        if erase_count:
            parts.append("{} erases".format(erase_count))
        if atomicity_count:
            parts.append("{} multi-sector".format(atomicity_count))
        if bit_count:
            bit_label = "{} bit-corrupt".format(bit_count)
            if clustered_bit_count:
                bit_label += " (clustered)"
            parts.append(bit_label)
        if silent_count:
            parts.append("{} silent-write".format(silent_count))
        if driver_error_count:
            parts.append("{} driver-error".format(driver_error_count))
        if rc_injection_count:
            parts.append("{} rc-injection".format(rc_injection_count))
        if disturb_count:
            parts.append("{} disturb".format(disturb_count))
        if wear_count:
            parts.append("{} wear-level".format(wear_count))
        if rejection_count:
            parts.append("{} write-reject".format(rejection_count))
        if timed_reset_count:
            parts.append("{} timed-reset".format(timed_reset_count))
        if read_flip_count:
            parts.append("{} read-flip".format(read_flip_count))
        if command_drop_count:
            parts.append("{} command-drop".format(command_drop_count))
        if swap_progress_count:
            parts.append("{} swap-progress".format(swap_progress_count))
        if security_state_erase_summary:
            parts.append(
                "{} security-state erase cutpoints".format(
                    len(security_state_erase_summary.get("cutpoints", []))
                )
            )
        if i2c_fault_count:
            parts.append("{} i2c-fault".format(i2c_fault_count))
        if otp_fault_count:
            parts.append("{} otp-fault".format(otp_fault_count))
        if nvs_fault_count:
            parts.append("{} nvs-corruption".format(nvs_fault_count))
        if timed_bit_corruption_count:
            parts.append(
                "{} timed-bit-corruption".format(timed_bit_corruption_count)
            )
        if instruction_skip_count:
            isc_label = "{} instruction-skip".format(instruction_skip_count)
            if literal_pool_excluded:
                isc_label += " ({} literal-pool excluded)".format(
                    literal_pool_excluded
                )
            parts.append(isc_label)
        if phase2_count:
            parts.append("{} phase2-recovery".format(phase2_count))
        if metadata_count:
            parts.append("{} metadata-fault".format(metadata_count))
        if hook_count:
            parts.append("{} hook-fault".format(hook_count))
        if confirm_count:
            parts.append("{} confirm-cycle".format(confirm_count))
        print(
            "Running {} fault points ({}) for '{}'...".format(
                len(fault_points),
                " + ".join(parts),
                profile.name,
            ),
            file=sys.stderr,
        )
    else:
        print(
            "Running {} fault points for '{}'...".format(len(fault_points), profile.name),
            file=sys.stderr,
        )

    return FaultPlan(
        fault_points=fault_points,
        fault_types_list=fault_types_list,
        heuristic_summary=heuristic_summary,
        swap_progress_summary=swap_progress_summary,
        security_state_erase_summary=security_state_erase_summary,
        clustered_bit_count=clustered_bit_count,
    )
