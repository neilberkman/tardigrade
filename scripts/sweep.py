"""Sweep orchestration for runtime, partial-staging, and multi-component fault injection.

Extracted from audit_bootloader.py to isolate sweep execution logic from
the CLI entry point.
"""

from __future__ import annotations

import os
import sys
import importlib.util
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dataclasses
import json
import time as _time_mod

from audit_report import summarize_runtime_sweep
from fault_plan import CalibrationInputs, build_fault_plan
from fault_classification import (
    _effective_boot_result,
    _interesting_multi_fault_points,
    finding_validation_disposition,
    finding_validation_stage,
    result_issue_reasons,
)
from fault_inject import (
    AnnotatedSequence,
    MultiFaultPlan,
    classify_multi_component_outcome,
    decode_multi_fault_sequence,
    encode_multi_fault_sequence,
    generate_multi_fault_sequences,
    multi_fault_plan_summary,
)
from invariants import check_state_relations, default_invariants, run_invariants
from fault_types import EXECUTE_ONLY_FAULT_TYPES, TRACE_REPLAY_WIRE_CODES
from partial_staging import (
    PartialStagingConfig,
    PartialStagingResult,
    TruncationPoint,
    classify_partial_staging_outcome,
    write_partial_image_to_temp,
)
from profile_loader import ProfileConfig, load_profile
from renode_runner import (
    RenodeTimeoutError,
    _progress,
    _run_batches_chunked,
    _base_fault_type_code,
    merge_robot_vars,
    quick_subset,
    run_calibration,
    run_single_point,
)
from result_checks import annotate_result_checks
from trace_utils import (
    flash_base_for_profile,
    load_clean_erase_trace,
    load_clean_write_trace,
)


def _cleanup_generated_robot_vars(robot_vars: List[str]) -> None:
    """Remove temp files created by ProfileConfig.robot_vars()."""
    for entry in robot_vars:
        if not entry.startswith(("PRE_BOOT_STATE_BIN:", "UPDATE_SEQUENCE_FILE:")):
            continue
        path = entry.split(":", 1)[1]
        if not path:
            continue
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _with_sweep_hash_bypass(
    robot_vars: List[str],
    profile: ProfileConfig,
    *,
    enabled: bool,
) -> List[str]:
    """Scope hash-bypass patches to faulted sweep runs only."""
    filtered_vars = [
        rv
        for rv in robot_vars
        if not rv.startswith("HASH_BYPASS_SYMBOLS:")
        and not rv.startswith("HASH_BYPASS_ADDRS:")
    ]
    if not enabled:
        return filtered_vars

    # Pre-resolved addresses are an optimization for faulted runs only.  They
    # activate the bypass independently of the symbol list in the runtime.
    filtered_vars.extend(
        rv for rv in robot_vars if rv.startswith("HASH_BYPASS_ADDRS:")
    )

    symbols: List[str] = []
    seen: set[str] = set()
    for rv in robot_vars:
        if not rv.startswith("HASH_BYPASS_SYMBOLS:"):
            continue
        for symbol in rv.split(":", 1)[1].split(","):
            cleaned = symbol.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                symbols.append(cleaned)
    for symbol in getattr(profile.fault_sweep, "sweep_hash_bypass_symbols", []) or []:
        cleaned = str(symbol).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            symbols.append(cleaned)

    if symbols:
        filtered_vars.append("HASH_BYPASS_SYMBOLS:{}".format(",".join(symbols)))
    return filtered_vars


def build_fault_robot_vars(
    robot_vars: List[str],
    profile: ProfileConfig,
    *,
    no_hash_bypass: bool = False,
) -> List[str]:
    """Return the robot vars for faulted runs, including sweep hash-bypass."""
    return _with_sweep_hash_bypass(
        robot_vars,
        profile,
        enabled=not no_hash_bypass,
    )


def build_control_robot_vars(
    robot_vars: List[str],
    profile: ProfileConfig,
    *,
    no_hash_bypass: bool = False,
) -> List[str]:
    """Return the robot vars for clean/control runs."""
    return _with_sweep_hash_bypass(
        robot_vars,
        profile,
        enabled=False,
    )


def _validate_runtime_control_result(
    profile: ProfileConfig,
    result: Dict[str, Any],
) -> None:
    """Fail closed when the clean control does not meet its profile contract."""
    expect = getattr(profile, "expect", None)
    expected_outcome = str(
        getattr(expect, "control_outcome", "success") or "success"
    ).strip().lower()
    observed_outcome, observed_slot = _effective_boot_result(result)
    observed_outcome = str(observed_outcome or "unknown").strip().lower()
    observed_slot_name = str(observed_slot or "").strip().lower()

    if observed_outcome != expected_outcome:
        raise RuntimeError(
            "Clean control failed: expected outcome {!r}, observed {!r}. "
            "Fault dispatch was aborted.".format(
                expected_outcome,
                observed_outcome,
            )
        )

    # Slot and marker checks describe successful application handoff.  They do
    # not apply to profiles whose clean control intentionally expects no boot
    # or another non-success outcome.
    if expected_outcome != "success":
        return

    criteria = getattr(profile, "success_criteria", None)
    if criteria is None:
        return

    for criterion_name in ("pc_in_slot", "vtor_in_slot"):
        expected_slot = str(
            getattr(criteria, criterion_name, "") or ""
        ).strip().lower()
        if (
            expected_slot
            and expected_slot != "any"
            and observed_slot_name != expected_slot
        ):
            raise RuntimeError(
                "Clean control failed: success_criteria.{} requires slot {!r}, "
                "observed {!r}. Fault dispatch was aborted.".format(
                    criterion_name,
                    expected_slot,
                    observed_slot_name or None,
                )
            )

    marker_address = getattr(criteria, "marker_address", None)
    if marker_address in (None, 0):
        return

    marker_value = getattr(criteria, "marker_value", None)
    try:
        expected_marker = int(str(marker_value), 0)
    except (TypeError, ValueError):
        expected_marker = 0
    if expected_marker == 0:
        raise RuntimeError(
            "Clean control failed: a configured success marker must use a "
            "non-zero sentinel. Fault dispatch was aborted."
        )

    signals = result.get("signals")
    if not isinstance(signals, dict) or signals.get("marker_ok") is not True:
        raise RuntimeError(
            "Clean control failed: configured success marker was not confirmed. "
            "Fault dispatch was aborted."
        )

    marker_actual_raw = signals.get("marker_actual")
    try:
        marker_actual = int(str(marker_actual_raw), 0)
    except (TypeError, ValueError):
        marker_actual = None
    if marker_actual != expected_marker:
        raise RuntimeError(
            "Clean control failed: expected marker {}, observed {}. "
            "Fault dispatch was aborted.".format(
                _fmt_u32(expected_marker),
                marker_actual_raw,
            )
        )


def _fmt_u32(value: int) -> str:
    return "0x{0:08X}".format(int(value) & 0xFFFFFFFF)


def _load_mcuboot_state_evaluator(repo_root: Path) -> Any:
    module_path = repo_root / "targets" / "mcuboot" / "state_evaluator.py"
    spec = importlib.util.spec_from_file_location(
        "__tardigrade_mcuboot_state_evaluator__",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load MCUboot state evaluator from {}".format(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _looks_like_mcuboot_profile(profile: ProfileConfig) -> bool:
    state_probe = getattr(profile, "state_probe", None)
    script = str(getattr(state_probe, "script", "") or "")
    if script.replace("\\", "/").endswith("targets/mcuboot/probe.py"):
        return True
    name = str(getattr(profile, "name", "") or "").lower()
    return "mcuboot" in name


def _build_mcuboot_state_slot_config(
    profile: ProfileConfig,
    repo_root: Path,
) -> Dict[str, Any]:
    slots = profile.memory.slots
    flash_base = flash_base_for_profile(profile)
    flash_ends = [
        int(slot.base) + int(slot.size)
        for slot in slots.values()
    ]
    flash_ends.extend(
        int(region.base) + int(region.size)
        for region in getattr(profile.memory, "erase_regions", ()) or ()
    )
    flash_ends.extend(
        int(region.base) + int(region.size)
        for region in getattr(profile.memory, "postmortem_partitions", ()) or ()
    )
    flash_end = max(flash_ends)
    if profile.pre_boot_state:
        flash_base = min(
            flash_base,
            min(int(write.address) for write in profile.pre_boot_state),
        )
        flash_end = max(
            flash_end,
            max(int(write.address) + 4 for write in profile.pre_boot_state),
        )
    criteria_runtime = profile._success_criteria_runtime_dict(  # type: ignore[attr-defined]
        repo_root,
        profile.success_criteria,
        profile.images,
    )
    return {
        "flash_base": int(flash_base),
        "flash_end": int(flash_end),
        "slots": {
            name: {"base": int(slot.base), "size": int(slot.size)}
            for name, slot in slots.items()
        },
        "sram_start": int(profile.memory.sram_start),
        "sram_end": int(profile.memory.sram_end),
        "vector_table_offset": int(profile.success_criteria.vector_table_offset),
        "trailer_align": 8,
        "trailer_window": int(getattr(profile.memory, "page_size", 4096) or 4096),
        "page_size": int(getattr(profile.memory, "page_size", 4096) or 4096),
        "pad_byte": 0x00
        if str(getattr(profile, "flash_backend", "") or "").strip().lower() == "mram"
        else 0xFF,
        "marker_address": profile.success_criteria.marker_address,
        "marker_value": profile.success_criteria.marker_value,
        "image_hash": bool(profile.success_criteria.image_hash),
        "image_hash_slot": profile.success_criteria.image_hash_slot or "",
        "image_exec_sha256": str(criteria_runtime.get("image_exec_sha256", "") or ""),
        "image_staging_sha256": str(criteria_runtime.get("image_staging_sha256", "") or ""),
        "expected_exec_sha256": str(criteria_runtime.get("expected_exec_sha256", "") or ""),
    }


def _build_mcuboot_initial_flash(
    profile: ProfileConfig,
    repo_root: Path,
    slot_config: Dict[str, Any],
) -> bytearray:
    flash_base = int(slot_config["flash_base"])
    flash_end = int(slot_config["flash_end"])
    fill = int(slot_config.get("pad_byte", 0xFF)) & 0xFF
    flash = bytearray([fill] * max(0, flash_end - flash_base))

    for slot_name, image_path in profile.images.items():
        if slot_name not in slot_config["slots"]:
            continue
        resolved = Path(profile.resolve_path(repo_root, image_path))
        if not resolved.exists():
            continue
        slot_info = slot_config["slots"][slot_name]
        slot_offset = int(slot_info["base"]) - flash_base
        slot_size = int(slot_info["size"])
        raw = resolved.read_bytes()
        payload = raw[:slot_size]
        flash[slot_offset:slot_offset + len(payload)] = payload

    for write in profile.pre_boot_state:
        offset = int(write.address) - flash_base
        if offset < 0 or offset + 4 > len(flash):
            continue
        flash[offset:offset + 4] = int(write.u32).to_bytes(4, "little")

    return flash


class _MCUbootTraceCursor:
    def __init__(
        self,
        base_flash: bytearray,
        *,
        flash_base: int,
        write_entries: List[Dict[str, int]],
        erase_entries: List[Dict[str, Any]],
        page_size: int,
        erase_fill: int = 0xFF,
    ) -> None:
        self.flash = bytearray(base_flash)
        self.flash_base = int(flash_base)
        self.write_entries = sorted(
            (
                {
                    "write_index": int(entry["write_index"]),
                    "flash_offset": int(entry["flash_offset"]),
                    "value": int(entry["value"]),
                }
                for entry in write_entries
            ),
            key=lambda entry: entry["write_index"],
        )
        self.erase_entries = sorted(
            (
                {
                    "flash_offset": int(entry["flash_offset"]),
                    "writes_at_this_point": (
                        None
                        if entry.get("writes_at_this_point") is None
                        else int(entry["writes_at_this_point"])
                    ),
                }
                for entry in erase_entries
            ),
            key=lambda entry: (
                entry["writes_at_this_point"] is None,
                entry["writes_at_this_point"]
                if entry["writes_at_this_point"] is not None
                else 0,
            ),
        )
        self.page_size = max(1, int(page_size))
        self.erase_fill = int(erase_fill) & 0xFF
        self._write_pos = 0
        self._erase_pos = 0
        self._committed_writes = 0
        self._last_fault_at = -1

    def _apply_write(self, entry: Dict[str, int]) -> None:
        off = int(entry["flash_offset"])
        self.flash[off:off + 4] = int(entry["value"]).to_bytes(4, "little")
        self._committed_writes += 1

    def _apply_erase(self, entry: Dict[str, Any]) -> None:
        off = int(entry["flash_offset"])
        end = min(len(self.flash), off + self.page_size)
        if off < 0 or off >= len(self.flash):
            return
        self.flash[off:end] = bytes([self.erase_fill]) * (end - off)

    def advance_to_fault_point(self, fault_at: int) -> int:
        if int(fault_at) < self._last_fault_at:
            raise RuntimeError("trace cursor fault points must be monotonic")

        while self._write_pos < len(self.write_entries):
            entry = self.write_entries[self._write_pos]
            write_index = int(entry["write_index"])
            if write_index > int(fault_at):
                break
            while self._erase_pos < len(self.erase_entries):
                erase_entry = self.erase_entries[self._erase_pos]
                writes_at = erase_entry["writes_at_this_point"]
                if writes_at is None or int(writes_at) >= write_index:
                    break
                self._apply_erase(erase_entry)
                self._erase_pos += 1
            self._apply_write(entry)
            self._write_pos += 1

        while self._erase_pos < len(self.erase_entries):
            erase_entry = self.erase_entries[self._erase_pos]
            writes_at = erase_entry["writes_at_this_point"]
            if writes_at is None or int(writes_at) > int(fault_at):
                break
            self._apply_erase(erase_entry)
            self._erase_pos += 1

        self._last_fault_at = int(fault_at)
        return int(self._committed_writes)

    def target_fault_address(self, fault_at: int) -> Optional[int]:
        target_write_index = int(fault_at) + 1
        entry_idx = self._write_pos
        while entry_idx < len(self.write_entries):
            entry = self.write_entries[entry_idx]
            if int(entry["write_index"]) == target_write_index:
                return self.flash_base + int(entry["flash_offset"])
            if int(entry["write_index"]) > target_write_index:
                break
            entry_idx += 1
        for entry in self.write_entries:
            if int(entry["write_index"]) == target_write_index:
                return self.flash_base + int(entry["flash_offset"])
        return None


def _is_trace_replay_execute_batch(
    *,
    trace_file: Optional[str],
    trace_file_bin: Optional[str],
    fault_types_list: Optional[List[str]],
) -> bool:
    # Writeback power-loss points use Python trace reconstruction followed by
    # recovery/follow-up boots.  They remain trace-replay batches, but their
    # expensive runtime is handled explicitly by the planner below.
    if not (trace_file or trace_file_bin):
        return False
    if not fault_types_list:
        return True
    return all(_base_fault_type_code(ft) in TRACE_REPLAY_WIRE_CODES for ft in fault_types_list)


def _auto_execute_batch_points(
    *,
    profile: ProfileConfig,
    evaluation_mode: str,
    fault_points: List[int],
    fault_types_list: Optional[List[str]],
    max_batch_points: int,
    trace_file: Optional[str],
    trace_file_bin: Optional[str],
) -> int:
    if max_batch_points > 0 or not fault_points:
        return max_batch_points

    eval_mode = str(evaluation_mode)
    if eval_mode not in {"execute", "state"}:
        return max_batch_points

    if eval_mode == "execute" and fault_types_list and all(
        _base_fault_type_code(ft) == "i" for ft in fault_types_list
    ):
        _progress(
            "Execute mode instruction-skip: forcing 1 pt/batch to avoid batch fallback churn "
            "({} points).".format(len(fault_points))
        )
        return 1

    has_full_execute_only_points = bool(
        fault_types_list
        and any(
            _base_fault_type_code(ft) not in TRACE_REPLAY_WIRE_CODES
            for ft in fault_types_list
        )
    )
    writeback_durability = str(
        getattr(getattr(profile, "fault_sweep", None), "durability_model", "direct")
    ).strip().lower() == "writeback"
    update_sequence_overhead_s = (
        12.0 if getattr(profile, "has_update_sequence", False) else 0.0
    )

    if eval_mode == "execute" and writeback_durability:
        _progress(
            "Writeback recovery replay: forcing 1 pt/batch until measured timing "
            "can be used safely ({} points).".format(len(fault_points))
        )
        return 1

    if eval_mode == "execute" and _is_trace_replay_execute_batch(
        trace_file=trace_file,
        trace_file_bin=trace_file_bin,
        fault_types_list=fault_types_list,
    ) and not has_full_execute_only_points:
        platform = str(getattr(profile, "platform", "") or "").lower()
        is_stm32f4 = "stm32f4" in platform
        batch_budget_s = 180.0
        point_budget_s = max(30.0, batch_budget_s - update_sequence_overhead_s)
        point_cost_s = 1.25 if is_stm32f4 else 0.9
        max_per_batch = 192 if is_stm32f4 else 128
        computed = max(8, int(point_budget_s // point_cost_s))
        chosen = max(1, min(max_per_batch, computed, len(fault_points)))
        est_batches = (len(fault_points) + chosen - 1) // chosen
        total_est_s = (len(fault_points) * point_cost_s) + (est_batches * update_sequence_overhead_s)
        _progress(
            "Execute mode with trace replay: ~{} batches, {} pts/batch "
            "({}s budget, {:.0f}s total est, {} points).".format(
                est_batches,
                chosen,
                int(batch_budget_s),
                total_est_s,
                len(fault_points),
            )
        )
        return chosen

    # Full sweeps without trace replay are memory-heavy in long single Renode
    # sessions. Late fault points (high fp value) are much more expensive than
    # early ones because Phase 1 must emulate up to fp writes. Use a
    # time-budget approach so each Renode session completes within ~180s.
    if has_full_execute_only_points or (not trace_file and not trace_file_bin):
        batch_time_budget_s = 180.0
        base_cost_s = 2.0
        per_write_cost_s = 0.012
        max_per_batch = 64
        point_budget_s = max(30.0, batch_time_budget_s - update_sequence_overhead_s)
        sequential_faults = {"w", "b", "e", "a", "s", "g", "x", "d", "l", "r", "k"}

        def point_cost(idx: int, fp: int) -> float:
            ft = (
                fault_types_list[idx]
                if fault_types_list and idx < len(fault_types_list)
                else None
            )
            if ft is None or _base_fault_type_code(ft) in sequential_faults:
                return base_cost_s + abs(fp) * per_write_cost_s
            return 5.0

        chunk_boundaries: List[int] = [0]
        budget_used = 0.0
        for idx, fault_point in enumerate(fault_points):
            cost = point_cost(idx, fault_point)
            budget_used += cost
            points_in_chunk = idx - chunk_boundaries[-1] + 1
            if budget_used > point_budget_s or points_in_chunk >= max_per_batch:
                chunk_boundaries.append(idx)
                budget_used = cost

        max_point_cost_s = max(
            point_cost(idx, fp) for idx, fp in enumerate(fault_points)
        )
        chosen = max(1, int(point_budget_s // max(1.0, max_point_cost_s)))
        chosen = max(1, min(max_per_batch, chosen, len(fault_points)))
        total_est_s = (
            sum(point_cost(idx, fp) for idx, fp in enumerate(fault_points))
            + len(chunk_boundaries) * update_sequence_overhead_s
        )
        mode_label = (
            "Execute mode without trace replay"
            if eval_mode == "execute"
            else "State mode without trace replay"
        )
        print(
            "{}: ~{} batches, safe {} pts/batch "
            "({}s budget, {:.0f}s total est, {} points, max fp={}).".format(
                mode_label,
                len(chunk_boundaries),
                chosen,
                int(batch_time_budget_s),
                total_est_s,
                len(fault_points),
                max(fault_points) if fault_points else 0,
            ),
            file=sys.stderr,
        )
        return chosen

    return max_batch_points


def _select_mcuboot_state_evaluator_points(
    *,
    repo_root: Path,
    profile: ProfileConfig,
    evaluation_mode: str,
    fault_points: List[int],
    fault_types_list: Optional[List[str]],
    trace_file: Optional[str],
) -> Optional[Dict[str, Any]]:
    if str(evaluation_mode) != "execute":
        return None
    if not _looks_like_mcuboot_profile(profile):
        return None
    # Shared/aliased backing stores need inverse address translation before a
    # byte-level state reconstruction can be sound.  Keep those points on the
    # real execute path until the evaluator supports that mapping explicitly.
    if getattr(profile.memory, "trace_address_map", None):
        return None
    if not trace_file or not os.path.exists(trace_file):
        return None
    if getattr(profile, "has_update_sequence", False):
        return None
    if "exec" not in profile.memory.slots or "staging" not in profile.memory.slots:
        return None

    evaluator = _load_mcuboot_state_evaluator(repo_root)
    slot_config = _build_mcuboot_state_slot_config(profile, repo_root)
    write_entries = load_clean_write_trace(trace_file)
    if not write_entries:
        return None

    target_addr_by_fault_at: Dict[int, int] = {}
    for entry in write_entries:
        target_addr_by_fault_at[int(entry["write_index"]) - 1] = (
            int(slot_config["flash_base"]) + int(entry["flash_offset"])
        )

    evaluate_points: List[int] = []
    evaluate_types: List[str] = []
    execute_points: List[int] = []
    execute_types: List[str] = []

    for idx, fault_at in enumerate(fault_points):
        fault_type = fault_types_list[idx] if fault_types_list and idx < len(fault_types_list) else "w"
        original_fault_type = str(fault_type or "w")
        fault_address = target_addr_by_fault_at.get(int(fault_at))
        if original_fault_type == "w" and fault_address is not None and not evaluator.should_use_execute_mode(
            fault_address,
            slot_config,
        ):
            evaluate_points.append(int(fault_at))
            evaluate_types.append(original_fault_type)
            continue
        execute_points.append(int(fault_at))
        execute_types.append(str(fault_type))

    if not evaluate_points:
        return None

    return {
        "module": evaluator,
        "slot_config": slot_config,
        "evaluate_points": evaluate_points,
        "evaluate_types": evaluate_types,
        "execute_points": execute_points,
        "execute_types": execute_types,
        "write_entries": write_entries,
    }


def _run_mcuboot_state_evaluator_points(
    *,
    repo_root: Path,
    profile: ProfileConfig,
    trace_file: str,
    erase_trace_file: Optional[str],
    selection: Dict[str, Any],
) -> List[Dict[str, Any]]:
    base_flash = _build_mcuboot_initial_flash(profile, repo_root, selection["slot_config"])
    cursor = _MCUbootTraceCursor(
        base_flash,
        flash_base=int(selection["slot_config"]["flash_base"]),
        write_entries=selection["write_entries"],
        erase_entries=load_clean_erase_trace(erase_trace_file),
        page_size=int(selection["slot_config"].get("page_size", 4096)),
        erase_fill=int(selection["slot_config"].get("pad_byte", 0xFF)),
    )
    evaluator = selection["module"]
    results: List[Dict[str, Any]] = []
    evaluate_types = selection.get("evaluate_types", [])
    type_by_fault_at = {
        int(point): str(fault_type)
        for point, fault_type in zip(selection["evaluate_points"], evaluate_types)
    }
    for fault_at in sorted(selection["evaluate_points"]):
        committed_writes = cursor.advance_to_fault_point(fault_at)
        prediction = evaluator.predict_boot_outcome(cursor.flash, selection["slot_config"])
        signals = dict(prediction.get("signals", {}) or {})
        signals["state_evaluator_used"] = True
        result: Dict[str, Any] = {
            "fault_at": int(fault_at),
            "fault_requested": int(fault_at),
            "fault_type": type_by_fault_at.get(int(fault_at), "w"),
            "fault_injected": True,
            "fault_address": _fmt_u32(cursor.target_fault_address(fault_at) or 0),
            "boot_outcome": prediction.get("boot_outcome", "unknown"),
            "boot_slot": prediction.get("boot_slot"),
            "actual_writes": int(committed_writes),
            "signals": signals,
        }
        results.append(result)
    return results


def _run_batch_worker(
    repo_root_str: str,
    renode_test: str,
    robot_suite: str,
    profile_path: str,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir_str: str,
    renode_remote_server_dir: str,
    worker_id: int,
    trace_file: Optional[str] = None,
    erase_trace_file: Optional[str] = None,
    trace_file_bin: Optional[str] = None,
    erase_trace_file_bin: Optional[str] = None,
    fault_types_list: Optional[List[str]] = None,
    max_batch_points: int = 0,
    keep_run_artifacts: bool = False,
    profile_component_name: Optional[str] = None,
    profile_initial_state_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Worker function for parallel batch execution.

    Runs in a subprocess via ProcessPoolExecutor.  Reloads the profile
    from disk so everything is picklable.
    """
    repo_root = Path(repo_root_str)
    work_dir = Path(work_dir_str)
    worker_dir = work_dir / "worker_{}".format(worker_id)
    worker_dir.mkdir(parents=True, exist_ok=True)
    # Share a single .NET bundle dir across all workers to avoid 160MB× N duplication.
    shared_bundle = work_dir / ".dotnet_bundle"
    shared_bundle.mkdir(parents=True, exist_ok=True)
    _progress("worker {} starting: {} fault points.".format(worker_id, len(fault_points)))

    # Re-create the renode config for this worker's directory.
    renode_config = worker_dir / "renode.config"
    renode_config.write_text(
        "[general]\n"
        "terminal = Termsharp\n"
        "compiler-cache-enabled = False\n"
        "serialization-mode = Generated\n"
        "use-synchronous-logging = False\n"
        "always-log-machine-name = False\n"
        "collapse-repeated-log-entries = True\n"
        "log-history-limit = 1000\n"
        "store-table-bits = 41\n"
        "[monitor]\n"
        "consume-exceptions-from-command = True\n"
        "break-script-on-exception = True\n"
        "number-format = Hexadecimal\n"
        "[plugins]\n"
        "enabled-plugins = \n"
        "[translation]\n"
        "min-tb-size = 33554432\n"
        "max-tb-size = 536870912\n",
        encoding="utf-8",
    )

    profile = load_profile(profile_path)
    if profile_initial_state_name:
        state_matches = [
            state
            for state in profile.initial_states
            if state.name == profile_initial_state_name
        ]
        if len(state_matches) != 1:
            raise RuntimeError(
                "parallel worker could not resolve initial state {!r} from {}".format(
                    profile_initial_state_name, profile_path
                )
            )
        profile = profile.resolve_initial_state(state_matches[0])
    if profile_component_name:
        matches = [
            component
            for component in profile.multi_component.components
            if component.name == profile_component_name
        ] if profile.multi_component is not None else []
        if len(matches) != 1:
            raise RuntimeError(
                "parallel worker could not resolve component {!r} from {}".format(
                    profile_component_name, profile_path
                )
            )
        profile = matches[0].to_profile_config(profile)

    results = _run_batches_chunked(
        repo_root=repo_root,
        renode_test=renode_test,
        robot_suite=robot_suite,
        profile=profile,
        fault_points=fault_points,
        robot_vars=robot_vars,
        work_dir=worker_dir,
        renode_remote_server_dir=renode_remote_server_dir,
        trace_file=trace_file,
        erase_trace_file=erase_trace_file,
        trace_file_bin=trace_file_bin,
        erase_trace_file_bin=erase_trace_file_bin,
        fault_types_list=fault_types_list,
        max_batch_points=max_batch_points,
        keep_run_artifacts=keep_run_artifacts,
        progress_label="worker {}".format(worker_id),
        shared_bundle_dir=shared_bundle,
    )
    _progress("worker {} complete: {} results.".format(worker_id, len(results)))
    return results


def _run_partial_staging_worker(
    repo_root_str: str,
    renode_test: str,
    robot_suite: str,
    profile_path: str,
    original_image: bytes,
    image_size: int,
    trunc_points_dicts: List[Dict[str, Any]],
    base_robot_vars: List[str],
    staging_slot_name: str,
    exec_slot_name: str,
    fill_pattern: int,
    work_dir_str: str,
    renode_remote_server_dir: str,
    worker_id: int,
    keep_run_artifacts: bool = False,
    profile_initial_state_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Worker function for parallel partial staging execution.

    Runs in a subprocess via ProcessPoolExecutor.  Reloads the profile
    from disk so everything is picklable.  Each worker gets its own
    work_dir and temp files to avoid collisions.
    """
    repo_root = Path(repo_root_str)
    work_dir = Path(work_dir_str)
    worker_dir = work_dir / "partial_staging" / "worker_{}".format(worker_id)
    worker_dir.mkdir(parents=True, exist_ok=True)

    # Re-create the renode config for this worker's directory.
    renode_config = worker_dir / "renode.config"
    renode_config.write_text(
        "[general]\n"
        "terminal = Termsharp\n"
        "compiler-cache-enabled = False\n"
        "serialization-mode = Generated\n"
        "use-synchronous-logging = False\n"
        "always-log-machine-name = False\n"
        "collapse-repeated-log-entries = True\n"
        "log-history-limit = 1000\n"
        "store-table-bits = 41\n"
        "[monitor]\n"
        "consume-exceptions-from-command = True\n"
        "break-script-on-exception = True\n"
        "number-format = Hexadecimal\n"
        "[plugins]\n"
        "enabled-plugins = \n"
        "[translation]\n"
        "min-tb-size = 33554432\n"
        "max-tb-size = 536870912\n",
        encoding="utf-8",
    )

    profile = load_profile(profile_path)
    if profile_initial_state_name:
        state_matches = [
            state
            for state in profile.initial_states
            if state.name == profile_initial_state_name
        ]
        if len(state_matches) != 1:
            raise RuntimeError(
                "partial-staging worker could not resolve initial state {!r}".format(
                    profile_initial_state_name
                )
            )
        profile = profile.resolve_initial_state(state_matches[0])
    staging_key = "IMAGE_{}_PATH".format(staging_slot_name.upper())
    staging_var = "IMAGE_{}".format(staging_slot_name.upper())

    results: List[Dict[str, Any]] = []
    temp_files: List[str] = []

    for tp_dict in trunc_points_dicts:
        tp = TruncationPoint(
            offset=tp_dict["offset"],
            label=tp_dict["label"],
            description=tp_dict["description"],
        )
        # Write temp image with worker_id in the label to avoid collisions.
        temp_path = write_partial_image_to_temp(
            original_image,
            tp.offset,
            fill=fill_pattern,
            label="w{}_{}".format(worker_id, tp.label),
        )
        temp_files.append(temp_path)

        # Build robot vars with the truncated staging image.
        ps_robot_vars = [
            rv
            for rv in base_robot_vars
            if not rv.startswith(staging_key + ":")
            and not rv.startswith(staging_var + ":")
            and not rv.startswith("HASH_BYPASS_SYMBOLS:")
            and not rv.startswith("HASH_BYPASS_ADDRS:")
        ]
        ps_robot_vars.append("{}:{}".format(staging_var, temp_path))
        ps_robot_vars.append("{}:{}".format(staging_key, temp_path))

        try:
            data = run_single_point(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=profile,
                fault_at=-1,
                robot_vars=ps_robot_vars,
                work_dir=worker_dir,
                renode_remote_server_dir=renode_remote_server_dir,
                is_control=True,
                keep_run_artifacts=keep_run_artifacts,
            )
            boot_outcome = str(data.get("boot_outcome", "unknown"))
            boot_slot = data.get("boot_slot")
        except Exception as exc:
            _progress(
                "PS worker {} point {} (offset=0x{:X}) failed: {}".format(
                    worker_id, tp.label, tp.offset, exc
                )
            )
            boot_outcome = (
                "timeout" if isinstance(exc, RenodeTimeoutError) else "infra_error"
            )
            boot_slot = None
            data = None

        classification = classify_partial_staging_outcome(
            boot_outcome=boot_outcome,
            boot_slot=boot_slot,
            truncation_offset=tp.offset,
            image_size=image_size,
            expected_exec_slot=exec_slot_name,
        )

        results.append({
            "truncation_point": tp.as_dict,
            "boot_outcome": boot_outcome,
            "boot_slot": boot_slot,
            "classification": classification,
        })
        _progress(
            "  PS w{}: {} (0x{:X}): {} -> {}".format(
                worker_id, tp.label, tp.offset, boot_outcome, classification
            )
        )

    # Clean up temp files.
    for tf in temp_files:
        try:
            os.unlink(tf)
        except OSError:
            pass

    _progress("PS worker {} complete: {} results.".format(worker_id, len(results)))
    return results


def run_partial_staging_sweep(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    ps_config: PartialStagingConfig,
    original_image: bytes,
    trunc_points: List[TruncationPoint],
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    num_workers: int = 1,
    keep_run_artifacts: bool = False,
    profile_initial_state_name: Optional[str] = None,
) -> Tuple[List[PartialStagingResult], List[Dict[str, Any]]]:
    """Run the partial staging sweep, optionally in parallel.

    Returns a tuple of (typed results, serializable dicts).
    """
    image_size = len(original_image)

    # Determine exec slot name.
    exec_slot_name = "exec"
    for sn in profile.memory.slots:
        if sn in {"exec", "primary", "slot_a", "slot0"}:
            exec_slot_name = sn
            break

    if num_workers > 1 and len(trunc_points) > 1:
        # Parallel: distribute points across workers via round-robin interleave.
        n = min(num_workers, len(trunc_points))
        chunks = [trunc_points[i::n] for i in range(n)]

        _progress(
            "Parallel partial staging: {} workers, ~{} points each".format(
                len(chunks), len(chunks[0])
            )
        )

        # Serialize truncation points as dicts for pickling.
        chunks_dicts = [[tp.as_dict for tp in chunk] for chunk in chunks]

        all_result_dicts: List[Dict[str, Any]] = []
        with ProcessPoolExecutor(max_workers=len(chunks)) as pool:
            futures = {}
            for wid, chunk_dicts in enumerate(chunks_dicts):
                f = pool.submit(
                    _run_partial_staging_worker,
                    repo_root_str=str(repo_root),
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile_path=str(profile.profile_path),
                    original_image=original_image,
                    image_size=image_size,
                    trunc_points_dicts=chunk_dicts,
                    base_robot_vars=robot_vars,
                    staging_slot_name=ps_config.staging_slot_name,
                    exec_slot_name=exec_slot_name,
                    fill_pattern=ps_config.fill_pattern,
                    work_dir_str=str(work_dir),
                    renode_remote_server_dir=renode_remote_server_dir,
                    worker_id=wid,
                    keep_run_artifacts=keep_run_artifacts,
                    profile_initial_state_name=profile_initial_state_name,
                )
                futures[f] = wid

            for f in as_completed(futures):
                wid = futures[f]
                try:
                    worker_results = f.result()
                    all_result_dicts.extend(worker_results)
                    _progress(
                        "PS worker {} finished: {} results".format(
                            wid, len(worker_results)
                        )
                    )
                except Exception as exc:
                    _progress("PS worker {} FAILED: {}".format(wid, exc))
                    raise

        # Sort by offset for deterministic output.
        all_result_dicts.sort(key=lambda r: r["truncation_point"]["offset"])

        # Reconstruct typed results from dicts.
        ps_results_typed = []
        for rd in all_result_dicts:
            tp_d = rd["truncation_point"]
            ps_results_typed.append(
                PartialStagingResult(
                    truncation_point=TruncationPoint(
                        offset=tp_d["offset"],
                        label=tp_d["label"],
                        description=tp_d["description"],
                    ),
                    boot_outcome=rd["boot_outcome"],
                    boot_slot=rd["boot_slot"],
                    classification=rd["classification"],
                )
            )

        return ps_results_typed, all_result_dicts

    # Serial path (single worker).
    staging_key = "IMAGE_{}_PATH".format(ps_config.staging_slot_name.upper())
    staging_var = "IMAGE_{}".format(ps_config.staging_slot_name.upper())

    ps_results_typed: List[PartialStagingResult] = []
    temp_files: List[str] = []

    for tp in trunc_points:
        temp_path = write_partial_image_to_temp(
            original_image,
            tp.offset,
            fill=ps_config.fill_pattern,
            label=tp.label,
        )
        temp_files.append(temp_path)

        ps_robot_vars = [
            rv
            for rv in robot_vars
            if not rv.startswith(staging_key + ":")
            and not rv.startswith(staging_var + ":")
            and not rv.startswith("HASH_BYPASS_SYMBOLS:")
            and not rv.startswith("HASH_BYPASS_ADDRS:")
        ]
        ps_robot_vars.append("{}:{}".format(staging_var, temp_path))
        ps_robot_vars.append("{}:{}".format(staging_key, temp_path))

        try:
            data = run_single_point(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=profile,
                fault_at=-1,
                robot_vars=ps_robot_vars,
                work_dir=work_dir / "partial_staging",
                renode_remote_server_dir=renode_remote_server_dir,
                is_control=True,
                keep_run_artifacts=keep_run_artifacts,
            )
            boot_outcome = str(data.get("boot_outcome", "unknown"))
            boot_slot = data.get("boot_slot")
        except Exception as exc:
            _progress(
                "Partial staging point {} (offset=0x{:X}) failed: {}".format(
                    tp.label, tp.offset, exc
                )
            )
            boot_outcome = (
                "timeout" if isinstance(exc, RenodeTimeoutError) else "infra_error"
            )
            boot_slot = None
            data = None

        classification = classify_partial_staging_outcome(
            boot_outcome=boot_outcome,
            boot_slot=boot_slot,
            truncation_offset=tp.offset,
            image_size=image_size,
            expected_exec_slot=exec_slot_name,
        )

        ps_results_typed.append(
            PartialStagingResult(
                truncation_point=tp,
                boot_outcome=boot_outcome,
                boot_slot=boot_slot,
                classification=classification,
                temp_image_path=temp_path,
                raw_result=data,
            )
        )
        _progress(
            "  {} (0x{:X}): {} -> {}".format(
                tp.label, tp.offset, boot_outcome, classification
            )
        )

    # Clean up temp files.
    for tf in temp_files:
        try:
            os.unlink(tf)
        except OSError:
            pass

    serial_dicts = [
        {
            "truncation_point": r.truncation_point.as_dict,
            "boot_outcome": r.boot_outcome,
            "boot_slot": r.boot_slot,
            "classification": r.classification,
        }
        for r in ps_results_typed
    ]

    return ps_results_typed, serial_dicts


def run_runtime_sweep(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    include_control: bool,
    num_workers: int = 1,
    evaluation_mode: str = "state",
    max_batch_points: int = 0,
    trace_file: Optional[str] = None,
    erase_trace_file: Optional[str] = None,
    trace_file_bin: Optional[str] = None,
    erase_trace_file_bin: Optional[str] = None,
    fault_types_list: Optional[List[str]] = None,
    keep_run_artifacts: bool = False,
    no_hash_bypass: bool = False,
    allow_state_evaluator: bool = False,
    profile_component_name: Optional[str] = None,
    profile_initial_state_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Run the full runtime fault sweep.

    Runs and validates the clean control first, then uses batch mode for all
    fault points.  The returned control remains last for report compatibility.
    When num_workers > 1, fault points are split across parallel Renode
    instances.

    If trace_file is provided, uses trace-replay mode: reconstructs
    flash state from the calibration trace instead of re-emulating
    Phase 1.  This eliminates the O(N^2) prefix cost.

    fault_types_list: parallel list of per-point fault type codes.
    allow_state_evaluator: explicit opt-in to the experimental MCUboot
    reconstructed-state evaluator; disabled by default.
    """
    control_robot_vars = build_control_robot_vars(
        robot_vars,
        profile,
        no_hash_bypass=no_hash_bypass,
    )
    fault_robot_vars = build_fault_robot_vars(
        robot_vars,
        profile,
        no_hash_bypass=no_hash_bypass,
    )

    control_result: Optional[Dict[str, Any]] = None
    if include_control:
        max_fp = max(fault_points) if fault_points else 999999
        control_at = max(999999, max_fp) + 1
        control_result = run_single_point(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_at=control_at,
            robot_vars=control_robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            is_control=True,
            keep_run_artifacts=keep_run_artifacts,
        )
        control_result["is_control"] = True
        _validate_runtime_control_result(profile, control_result)

    hybrid_eval_results: List[Dict[str, Any]] = []
    hybrid_selection = None
    if allow_state_evaluator:
        hybrid_selection = _select_mcuboot_state_evaluator_points(
            repo_root=repo_root,
            profile=profile,
            evaluation_mode=evaluation_mode,
            fault_points=fault_points,
            fault_types_list=fault_types_list,
            trace_file=trace_file,
        )
    execute_fault_points = list(fault_points)
    execute_fault_types_list = list(fault_types_list) if fault_types_list is not None else None
    if hybrid_selection is not None:
        hybrid_eval_results = _run_mcuboot_state_evaluator_points(
            repo_root=repo_root,
            profile=profile,
            trace_file=str(trace_file),
            erase_trace_file=erase_trace_file,
            selection=hybrid_selection,
        )
        execute_fault_points = list(hybrid_selection["execute_points"])
        execute_fault_types_list = list(hybrid_selection["execute_types"])
        _progress(
            "MCUboot hybrid sweep: {} fast state-evaluator points, {} execute-mode points.".format(
                len(hybrid_eval_results),
                len(execute_fault_points),
            )
        )

    max_batch_points = _auto_execute_batch_points(
        profile=profile,
        evaluation_mode=evaluation_mode,
        fault_points=execute_fault_points,
        fault_types_list=execute_fault_types_list,
        max_batch_points=max_batch_points,
        trace_file=trace_file,
        trace_file_bin=trace_file_bin,
    )

    if execute_fault_points and num_workers > 1:
        # Interleave fault points across workers for load balancing.
        # High-index fault points take 10-100x longer (more Phase 2 emulation).
        # Round-robin interleaving gives each worker a mix of fast and slow points.
        n = min(num_workers, len(execute_fault_points))
        chunks = [execute_fault_points[i::n] for i in range(n)]
        ft_chunks: List[Optional[List[str]]] = []
        if execute_fault_types_list:
            ft_chunks = [execute_fault_types_list[i::n] for i in range(n)]
        else:
            ft_chunks = [None] * len(chunks)

        _progress(
            "Parallel sweep: {} workers, ~{} points each (interleaved)".format(
                len(chunks), len(chunks[0])
            )
        )

        batch_results: List[Dict[str, Any]] = []
        with ProcessPoolExecutor(max_workers=len(chunks)) as pool:
            futures = {}
            for wid, chunk in enumerate(chunks):
                f = pool.submit(
                    _run_batch_worker,
                    repo_root_str=str(repo_root),
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile_path=str(profile.profile_path),
                    fault_points=chunk,
                    robot_vars=fault_robot_vars,
                    work_dir_str=str(work_dir),
                    renode_remote_server_dir=renode_remote_server_dir,
                    worker_id=wid,
                    trace_file=trace_file,
                    erase_trace_file=erase_trace_file,
                    trace_file_bin=trace_file_bin,
                    erase_trace_file_bin=erase_trace_file_bin,
                    fault_types_list=ft_chunks[wid] if wid < len(ft_chunks) else None,
                    max_batch_points=max_batch_points,
                    keep_run_artifacts=keep_run_artifacts,
                    profile_component_name=profile_component_name,
                    profile_initial_state_name=profile_initial_state_name,
                )
                futures[f] = wid

            for f in as_completed(futures):
                wid = futures[f]
                try:
                    worker_results = f.result()
                    batch_results.extend(worker_results)
                    _progress(
                        "Worker {} finished: {} results".format(
                            wid, len(worker_results)
                        )
                    )
                except Exception as exc:
                    _progress("Worker {} FAILED: {}".format(wid, exc))
                    raise
    elif execute_fault_points:
        batch_results = _run_batches_chunked(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_points=execute_fault_points,
            robot_vars=fault_robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            trace_file=trace_file,
            erase_trace_file=erase_trace_file,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=erase_trace_file_bin,
            fault_types_list=execute_fault_types_list,
            max_batch_points=max_batch_points,
            keep_run_artifacts=keep_run_artifacts,
        )
    else:
        batch_results = []

    results: List[Dict[str, Any]] = []
    results.extend(hybrid_eval_results)
    for data in batch_results:
        data["is_control"] = False
        results.append(data)

    if control_result is not None:
        results.append(control_result)

    if fault_types_list is not None:
        original_order = {
            (int(fp), str(ft)): idx
            for idx, (fp, ft) in enumerate(zip(fault_points, fault_types_list))
        }
        sortable_results = results[:-1] if include_control else list(results)
        sorted_fault_results = sorted(
            sortable_results,
            key=lambda item: original_order.get(
                (int(item.get("fault_at", -1)), str(item.get("fault_type", "w"))),
                len(original_order),
            ),
        )
        if include_control:
            results = sorted_fault_results + [results[-1]]
        else:
            results = sorted_fault_results

    # Clean up bulky worker temp artifacts (robot logs, .NET bundles) after
    # sweep completes.  The result JSON has all the data; per-chunk robot
    # output and .dotnet_bundle copies waste 2-5GB per sweep.
    #
    # When keep_run_artifacts is False, always clean.  When True, still
    # clean the .dotnet_bundle dirs (pure waste) but keep robot logs.
    has_findings = any(
        r.get("fault_class") not in (None, "benign", "skipped")
        and r.get("boot_outcome") not in ("success", "skipped")
        for r in results
        if r.get("fault_at", -1) >= 0
    )
    import shutil
    # Always clean .dotnet_bundle — 160MB per worker, never useful.
    for pattern in (".dotnet_bundle", "worker_*/.dotnet_bundle"):
        for target in work_dir.glob(pattern):
            shutil.rmtree(target, ignore_errors=True)
    # Clean robot logs and finding_validation unless keeping artifacts
    # and there are actual findings worth investigating.
    if not keep_run_artifacts or not has_findings:
        for pattern in ("worker_*/chunk_*", "finding_validation"):
            for target in work_dir.glob(pattern):
                shutil.rmtree(target, ignore_errors=True)

    return results


def evaluate_config_checks(result: Dict[str, Any], profile: "ProfileConfig") -> Optional[str]:
    """Evaluate config checks against a boot result."""
    config_checks = getattr(profile.success_criteria, "config_checks", None)
    if not config_checks:
        return None
    eff_outcome, _ = _effective_boot_result(result)
    outcome = str(eff_outcome or "unknown").strip().lower()
    nvs_corruption_active = result.get("nvs_corruption_mode") is not None
    if outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}:
        if nvs_corruption_active:
            return "config_crash"
        return None
    if outcome != "success":
        return None
    config_values = result.get("config_values", {})
    if not isinstance(config_values, dict):
        return None
    for check in config_checks:
        addr_key = "0x{:X}".format(check.address)
        if addr_key not in config_values:
            return "config_lost"
        actual = config_values[addr_key]
        if not isinstance(actual, int):
            try:
                actual = int(str(actual), 0)
            except (ValueError, TypeError):
                return "config_lost"
        if not check.evaluate(actual):
            return "config_lost"
    return None


def validate_runtime_fault_mode_compat(profile: "ProfileConfig", eval_mode: str) -> None:
    """Fail fast on profile/mode combinations the runtime runner cannot support."""
    if (
        str(getattr(profile.fault_sweep, "durability_model", "direct")).strip().lower()
        == "writeback"
        and str(eval_mode or "").strip().lower() != "execute"
    ):
        raise RuntimeError(
            "durability_model=writeback requires evaluation_mode 'execute'."
        )
    if str(getattr(profile.fault_sweep, "mode", "runtime")) != "runtime":
        return
    if getattr(profile, "has_update_sequence", False) and str(eval_mode) != "execute":
        raise RuntimeError(
            "update_sequence profiles currently require evaluation_mode 'execute'."
        )
    if str(eval_mode) != "state":
        return

    platform = str(getattr(profile, "platform", "") or "")
    pure_nvm_platform = (
        "nvm" in platform
        and "flash_fast" not in platform
        and "hybrid" not in platform
    )
    if not pure_nvm_platform:
        return

    fault_types = list(getattr(profile.fault_sweep, "fault_types", []) or [])
    incompatible = sorted(set(fault_types) & EXECUTE_ONLY_FAULT_TYPES)
    if not incompatible:
        return

    raise RuntimeError(
        "evaluation_mode 'state' on pure NVMemory platform '{}' does not support "
        "fault type(s) {}. These faults currently use execute-mode handling in "
        "the runtime runner, and execute mode is intentionally unsupported on "
        "pure NVMemory platforms. Use power_loss only, move the target to a "
        "flash_fast/hybrid platform, or keep this profile out of generic "
        "self-test.".format(platform, ", ".join(incompatible))
    )


def _bounded_component_write_count(
    profile: ProfileConfig,
    write_count: int,
) -> int:
    """Apply the component profile's campaign ceiling to a derived count."""
    return min(int(write_count), int(profile.fault_sweep.max_writes_cap))


def _component_state_payload(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the final semantic state that a component reported."""
    cycles = result.get("boot_cycles")
    if isinstance(cycles, list) and cycles:
        last = cycles[-1]
        if isinstance(last, dict) and isinstance(last.get("semantic_state"), dict):
            return last["semantic_state"]
    for key in ("semantic_state", "nvm_state"):
        value = result.get(key)
        if isinstance(value, dict):
            return value
    signals = result.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("semantic_state"), dict):
        return signals["semantic_state"]
    return None


def _component_relation_record(
    result: Dict[str, Any], *, expected_outcome: Optional[str] = None
) -> Dict[str, Any]:
    """Retain state evidence alongside the boot outcome in combined reports."""
    record = {
        "boot_outcome": result.get("boot_outcome"),
        "boot_slot": result.get("boot_slot"),
    }
    if expected_outcome is not None:
        record["expected_outcome"] = str(expected_outcome)
    state = _component_state_payload(result)
    if state is not None:
        record["semantic_state"] = state
    if isinstance(result.get("pre_state"), dict):
        record["pre_state"] = result["pre_state"]
    if isinstance(result.get("nvm_state"), dict):
        record["nvm_state"] = result["nvm_state"]
    return record


def _non_reportable_multi_component_result(result: Dict[str, Any]) -> bool:
    """Return true for outcomes deliberately excluded from security findings."""
    fault_class = str(result.get("fault_class") or "").strip().lower()
    if fault_class in {"bus_fault", "dos_only", "safe_dos", "harness", "harness_artifact"}:
        return True
    if finding_validation_stage(result) in {"candidate", "dismissed"}:
        return True
    if finding_validation_disposition(result) in {
        "harness_artifact", "dos_only", "self_healed", "defense_in_depth",
        "no_verification_bypass", "low_confidence", "model_specific_candidate",
        "needs_mechanism_confirmation",
    }:
        return True
    return False


def _multi_component_issue_annotation(
    result: Dict[str, Any],
    *,
    expected_outcome: str,
    combined_outcome: str,
    combined_expected_outcome: str = "success",
    relation_violations: List[Dict[str, Any]],
    require_fault: bool,
    component_control_reliable: bool = True,
    supporting_controls_reliable: bool = True,
) -> Dict[str, Any]:
    """Return trustworthy, point-level issue accounting for one observation."""
    effective_outcome, _ = _effective_boot_result(result)
    effective = str(effective_outcome or "unknown").strip().lower()
    fault_flag = result.get("fault_injected")
    fault_state_valid = (
        fault_flag is True if require_fault else fault_flag is False
    )
    component_reliable = bool(
        fault_state_valid
        and component_control_reliable
        and not result.get("infrastructure_error")
        and not result.get("timeout")
        and effective not in {"infra_error", "timeout", "skipped", "unknown"}
    )
    non_reportable = _non_reportable_multi_component_result(result)
    relation_findings = [
        item
        for item in relation_violations
        if isinstance(item, dict) and item.get("name") == "state_relations"
    ]
    relation_errors = [item for item in relation_violations if item not in relation_findings]
    combined_reliable = bool(
        component_reliable
        and supporting_controls_reliable
        and not relation_errors
        and not non_reportable
    )
    component_reasons = result_issue_reasons(result, expected_outcome)
    sources: List[str] = []
    if component_reliable and component_reasons and not non_reportable:
        sources.append("component")
    if combined_reliable and combined_outcome != combined_expected_outcome:
        sources.append("combined_outcome")
    if combined_reliable and relation_findings:
        sources.append("state_relation")
    return {
        "fault_injected": fault_flag,
        "component_reliable": component_reliable,
        "reliable": combined_reliable,
        "component_issue": bool(component_reasons),
        "component_issue_reasons": component_reasons,
        "security_issue": bool(sources),
        "issue_sources": sources,
        "fault_class": result.get("fault_class"),
        "non_reportable": non_reportable,
    }


def _multi_component_security_counts(
    combined_results: List[Dict[str, Any]],
    control_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Count the exact union of trustworthy fault and control observations."""
    reliable_fault_points = sum(
        1 for result in combined_results if result.get("reliable") is True
    )
    component_reliable_fault_points = sum(
        1
        for result in combined_results
        if result.get("component_reliable") is True
    )
    return {
        "component_reliable_fault_points": component_reliable_fault_points,
        "reliable_fault_points": reliable_fault_points,
        "unreliable_fault_points": len(combined_results) - reliable_fault_points,
        "control_reliable": control_record.get("reliable") is True,
        "security_issue_points": sum(
            1
            for result in combined_results
            if result.get("security_issue") is True
        ),
        "control_security_issue_points": int(
            control_record.get("security_issue") is True
        ),
    }


def _expected_combined_outcome(
    component_profiles: Dict[str, ProfileConfig],
) -> str:
    """Compute the combined baseline from each component's expected outcome."""
    return classify_multi_component_outcome(
        {
            name: {"boot_outcome": component.expect.control_outcome}
            for name, component in component_profiles.items()
        }
    )


def _evaluate_component_state_relations(
    combined: Dict[str, Any],
    profile: ProfileConfig,
) -> List[Dict[str, Any]]:
    """Evaluate parent-level relations over an atomic component snapshot."""
    configured_invariants = set(profile.invariants or [])
    if "state_relations" not in configured_invariants and "strict" not in configured_invariants:
        return []
    per_component = combined.get("per_component") or {}
    post_components: Dict[str, Any] = {}
    pre_components: Dict[str, Any] = {}
    for name, item in per_component.items():
        if not isinstance(item, dict):
            continue
        state = item.get("semantic_state")
        if isinstance(state, dict):
            post_components[name] = state
        pre = item.get("pre_state")
        if not isinstance(pre, dict):
            # A clean control's semantic state is the pre-update baseline for
            # the faulted component when no explicit pre-state was emitted.
            pre = state
        if isinstance(pre, dict):
            pre_components[name] = pre
    from fault_inject import FaultResult

    aggregate = FaultResult(
        fault_at=int(combined.get("fault_at", 0) or 0),
        boot_outcome=str(combined.get("combined_outcome", "unknown")),
        boot_slot=None,
        nvm_state={"components": post_components},
        raw_log="",
        is_control=bool(combined.get("is_control", False)),
    )
    try:
        violations = run_invariants(
            aggregate,
            [check_state_relations],
            pre_state={"components": pre_components},
            invariant_config=getattr(profile, "invariant_config", {}) or {},
        )
    except (TypeError, ValueError, KeyError) as exc:
        return [{
            "name": "state_relations_error",
            "description": "State relation evaluation failed: {}".format(exc),
            "infrastructure_error": True,
        }]
    return [
        {
            "name": (
                "state_relations_error"
                if violation.invariant_name == "invariant_evaluation_error"
                and (violation.details or {}).get("check") == "check_state_relations"
                else violation.invariant_name
            ),
            "description": violation.description,
            "details": violation.details,
            "finding": (violation.details or {}).get("finding_code"),
            "infrastructure_error": bool(
                violation.invariant_name == "invariant_evaluation_error"
                and (violation.details or {}).get("check") == "check_state_relations"
            ),
        }
        for violation in violations
    ]


def run_multi_component_sweep(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    robot_vars_base: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    evaluation_mode: str = "state",
    quick: bool = False,
    fault_step: int = 1,
    fault_start: Optional[int] = None,
    fault_end: Optional[int] = None,
    num_workers: int = 1,
    max_batch_points: int = 0,
    no_trace_replay: bool = False,
    no_hash_bypass: bool = False,
    keep_run_artifacts: bool = False,
    no_control: bool = False,
    allow_state_evaluator: bool = False,
) -> Dict[str, Any]:
    """Orchestrate fault injection across multiple components.

    For ``cross_product`` fault matrix: for each component, calibrate and
    sweep that component while running all other components cleanly.
    Classify combined results as ``split_brain`` when the faulted
    component fails but the others succeed.

    Returns a dict with per-component results and combined summary.
    """
    mc = profile.multi_component
    if mc is None:
        raise RuntimeError("run_multi_component_sweep called on single-component profile")
    if no_control:
        raise RuntimeError(
            "multi-component sweeps require observed clean controls for every component"
        )

    component_profiles = profile.component_profiles()
    _progress(
        "Multi-component sweep: {} components, fault_matrix={}".format(
            len(component_profiles), mc.fault_matrix
        )
    )

    per_component_data: Dict[str, Dict[str, Any]] = {}
    combined_results: List[Dict[str, Any]] = []

    for comp_idx, comp_profile in enumerate(component_profiles):
        comp_name = mc.components[comp_idx].name
        comp_dir = work_dir / "component_{}".format(comp_name)
        comp_dir.mkdir(parents=True, exist_ok=True)

        _progress(
            "Component '{}' ({}/{}): starting calibration and sweep.".format(
                comp_name, comp_idx + 1, len(component_profiles)
            )
        )

        # Build robot vars for this component.  ``robot_vars_base`` contains
        # campaign-only values (CLI additions and stall timeouts), never the
        # parent profile's rendered variables.  Layer the component-specific
        # profile vars on top so optional parent settings cannot bleed into a
        # component that omitted them.
        # Determine eval mode from component or parent.
        comp_eval_mode = evaluation_mode
        if comp_profile.fault_sweep.evaluation_mode:
            comp_eval_mode = comp_profile.fault_sweep.evaluation_mode
        component_owned_robot_vars = comp_profile.robot_vars(repo_root)
        comp_robot_vars = merge_robot_vars(
            merge_robot_vars(
                robot_vars_base,
                component_owned_robot_vars,
            ),
            [
                "EVALUATION_MODE:{}".format(comp_eval_mode),
                "EXPECT_CONTROL_OUTCOME:{}".format(
                    comp_profile.expect.control_outcome
                ),
            ],
        )

        # Calibrate this component.
        comp_max_writes = comp_profile.fault_sweep.max_writes
        trace_file: Optional[str] = None
        erase_trace_file: Optional[str] = None
        trace_file_bin: Optional[str] = None
        erase_trace_file_bin: Optional[str] = None
        total_erases = 0
        total_i2c_transactions = 0
        total_otp_blows = 0
        setup_writes = 0

        if comp_max_writes == "auto":
            if comp_eval_mode == "state" and "exec" in comp_profile.memory.slots:
                exec_slot = comp_profile.memory.slots["exec"]
                comp_max_writes = exec_slot.size // comp_profile.memory.write_granularity
                _progress(
                    "Component '{}': computed {} writes from slot geometry.".format(
                        comp_name, comp_max_writes
                    )
                )
            else:
                _progress(
                    "Component '{}': calibrating write count...".format(comp_name)
                )
                cal = run_calibration(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=comp_profile,
                    robot_vars=comp_robot_vars,
                    work_dir=comp_dir,
                    renode_remote_server_dir=renode_remote_server_dir,
                    keep_run_artifacts=keep_run_artifacts,
                )
                comp_max_writes = cal.total_writes
                total_erases = cal.total_erases
                total_i2c_transactions = cal.total_i2c_transactions
                total_otp_blows = cal.total_otp_blows
                setup_writes = cal.setup_writes
                trace_file = cal.trace_file
                erase_trace_file = cal.erase_trace_file
                trace_file_bin = cal.trace_file_bin
                erase_trace_file_bin = cal.erase_trace_file_bin
                _progress(
                    "Component '{}': calibrated to {} writes.".format(
                        comp_name, comp_max_writes
                    )
                )
        else:
            comp_max_writes = int(comp_max_writes)

        comp_max_writes = int(comp_max_writes)
        bounded_write_count = _bounded_component_write_count(
            comp_profile,
            comp_max_writes,
        )
        if bounded_write_count < comp_max_writes:
            _progress(
                "Component '{}': capping writes from {} to {}.".format(
                    comp_name,
                    comp_max_writes,
                    bounded_write_count,
                )
            )
            comp_max_writes = bounded_write_count

        # Use the canonical planner so component-local erase, OTP, I2C,
        # instruction, metadata, and other declared fault types retain their
        # runtime wire encodings.
        component_plan = build_fault_plan(
            comp_profile,
            CalibrationInputs(
                max_writes=int(comp_max_writes),
                total_erases=total_erases,
                total_i2c_transactions=total_i2c_transactions,
                total_otp_blows=total_otp_blows,
                setup_writes=setup_writes,
                trace_file=trace_file,
                erase_trace_file=erase_trace_file,
            ),
            quick=quick,
            fault_step=max(1, fault_step),
            fault_start=fault_start,
            fault_end=fault_end,
        )
        fault_points = component_plan.fault_points
        fault_types_list = component_plan.fault_types_list

        _progress(
            "Component '{}': sweeping {} fault points.".format(
                comp_name, len(fault_points)
            )
        )

        # Sweep this component.
        comp_results = run_runtime_sweep(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=comp_profile,
            fault_points=fault_points,
            robot_vars=comp_robot_vars,
            work_dir=comp_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            include_control=not no_control,
            num_workers=num_workers,
            evaluation_mode=comp_eval_mode,
            max_batch_points=max_batch_points,
            trace_file=trace_file if not no_trace_replay else None,
            erase_trace_file=erase_trace_file if not no_trace_replay else None,
            trace_file_bin=trace_file_bin if not no_trace_replay else None,
            erase_trace_file_bin=erase_trace_file_bin if not no_trace_replay else None,
            fault_types_list=fault_types_list,
            keep_run_artifacts=keep_run_artifacts,
            no_hash_bypass=no_hash_bypass,
            allow_state_evaluator=allow_state_evaluator,
            profile_component_name=comp_name,
        )

        # Parent-level state relations consume an aggregate ``components``
        # snapshot.  Keep them out of component-local checks; they are
        # evaluated after controls and faulted component states are joined.
        original_invariants = comp_profile.invariants
        relation_enabled = (
            "state_relations" in original_invariants
            or "strict" in original_invariants
        )
        component_invariants: List[str] = []
        for invariant in original_invariants:
            if invariant == "state_relations":
                continue
            if invariant == "strict" and relation_enabled:
                component_invariants.extend(
                    fn.__name__.replace("check_", "", 1)
                    for fn in default_invariants("strict")
                    if fn is not check_state_relations
                )
            else:
                component_invariants.append(invariant)
        comp_profile.invariants = component_invariants
        try:
            annotate_result_checks(comp_results, comp_profile, repo_root=repo_root)
        finally:
            comp_profile.invariants = original_invariants

        # Store per-component summary.
        comp_summary = summarize_runtime_sweep(
            comp_results,
            total_writes=comp_max_writes,
            profile=comp_profile,
            expected_fault_points=len(fault_points),
        )
        per_component_data[comp_name] = {
            "calibrated_writes": comp_max_writes,
            "fault_points_tested": len(fault_points),
            "fault_types_list": fault_types_list,
            "heuristic": component_plan.heuristic_summary,
            "summary": comp_summary,
            "results": comp_results,
        }
        _cleanup_generated_robot_vars(component_owned_robot_vars)

    # Combine each faulted component with independently observed clean
    # controls from every other component.  This remains a cross-run model,
    # but no outcome is fabricated from profile expectations.
    component_profiles_by_name = {
        config.name: component_profile
        for config, component_profile in zip(mc.components, component_profiles)
    }
    expected_combined_outcome = _expected_combined_outcome(component_profiles_by_name)
    observed_controls: Dict[str, Dict[str, Any]] = {}
    for comp_name, data in per_component_data.items():
        controls = [r for r in data["results"] if r.get("is_control")]
        if len(controls) != 1:
            raise RuntimeError(
                "component '{}' produced {} clean controls; exactly one is required".format(
                    comp_name, len(controls)
                )
            )
        outcome, slot = _effective_boot_result(controls[0])
        control_annotation = _multi_component_issue_annotation(
            controls[0],
            expected_outcome=component_profiles_by_name[comp_name].expect.control_outcome,
            combined_outcome="success",
            # Control findings are accounted for per component; do not turn
            # the parent classifier into a second control finding.
            combined_expected_outcome="success",
            relation_violations=[],
            require_fault=False,
        )
        observed_controls[comp_name] = {
            **_component_relation_record(
                controls[0],
                expected_outcome=component_profiles_by_name[comp_name].expect.control_outcome,
            ),
            **control_annotation,
            "boot_outcome": outcome,
            "boot_slot": slot,
            "faulted": False,
            "observed_control": True,
        }

    control_relation_record = {
        "combined_outcome": classify_multi_component_outcome(
            {
                name: {"boot_outcome": control.get("boot_outcome")}
                for name, control in observed_controls.items()
            }
        ),
        "per_component": observed_controls,
        "is_control": True,
        "expected_outcomes": {
            name: component_profiles_by_name[name].expect.control_outcome
            for name in observed_controls
        },
        "expected_combined_outcome": expected_combined_outcome,
    }
    control_relation_violations = _evaluate_component_state_relations(
        control_relation_record, profile
    )
    control_components_reliable = bool(
        observed_controls
        and all(item.get("reliable") is True for item in observed_controls.values())
    )
    control_component_issue = any(
        item.get("component_reliable") is True
        and item.get("component_issue") is True
        for item in observed_controls.values()
    )
    control_relation_findings = [
        item
        for item in control_relation_violations
        if isinstance(item, dict) and item.get("name") == "state_relations"
    ]
    control_relation_errors = [
        item
        for item in control_relation_violations
        if item not in control_relation_findings
    ]
    control_reliable = bool(
        control_components_reliable and not control_relation_errors
    )
    control_issue_sources = (
        (["component"] if control_component_issue else [])
        + (
            ["state_relation"]
            if control_reliable and control_relation_findings
            else []
        )
    )
    control_relation_record.update({
        "fault_injected": False,
        "component_reliable": control_components_reliable,
        "reliable": control_reliable,
        "component_issue": control_component_issue,
        "security_issue": bool(control_issue_sources),
        "issue_sources": control_issue_sources,
    })
    supporting_controls_reliable = bool(
        control_reliable
        and not control_component_issue
        and not control_relation_findings
    )

    for comp_name, data in per_component_data.items():
        for result in data["results"]:
            if result.get("is_control") or result.get("fault_injected") is not True:
                continue
            faulted_outcome, faulted_slot = _effective_boot_result(result)
            per_comp_outcomes = {
                name: dict(control)
                for name, control in observed_controls.items()
            }
            per_comp_outcomes[comp_name] = {
                **_component_relation_record(
                    result,
                    expected_outcome=component_profiles_by_name[comp_name].expect.control_outcome,
                ),
                "boot_outcome": faulted_outcome,
                "boot_slot": faulted_slot,
                "fault_at": result.get("fault_at"),
                "faulted": True,
                "observed_control": False,
            }
            combined_record = {
                    "faulted_component": comp_name,
                    "fault_at": result.get("fault_at"),
                    "fault_type": result.get("fault_type"),
                    "combined_outcome": classify_multi_component_outcome(
                        per_comp_outcomes
                    ),
                    "per_component": per_comp_outcomes,
                    "is_control": False,
                    "expected_outcomes": {
                        name: component_profiles_by_name[name].expect.control_outcome
                        for name in per_comp_outcomes
                    },
                    "expected_combined_outcome": expected_combined_outcome,
                }
            relation_violations = _evaluate_component_state_relations(
                combined_record, profile
            )
            if relation_violations:
                combined_record["invariant_violations"] = relation_violations
            combined_record.update(
                _multi_component_issue_annotation(
                    result,
                    expected_outcome=(
                        component_profiles_by_name[comp_name].expect.control_outcome
                    ),
                    combined_outcome=combined_record["combined_outcome"],
                    relation_violations=relation_violations,
                    require_fault=True,
                    component_control_reliable=bool(
                        observed_controls[comp_name].get("reliable") is True
                        and observed_controls[comp_name].get("component_issue") is False
                    ),
                    supporting_controls_reliable=supporting_controls_reliable,
                )
            )
            combined_results.append(combined_record)

    # Compute multi-component combined summary.
    total_combined = len(combined_results)
    split_brain_count = sum(
        1 for r in combined_results if r.get("combined_outcome") == "split_brain"
    )
    all_failed_count = sum(
        1 for r in combined_results if r.get("combined_outcome") == "all_failed"
    )
    success_count = sum(
        1 for r in combined_results if r.get("combined_outcome") == "success"
    )
    degraded_count = sum(
        1 for r in combined_results if r.get("combined_outcome") == "degraded"
    )
    state_relation_violation_count = sum(
        1
        for item in combined_results
        if any(
            isinstance(violation, dict)
            and violation.get("name") == "state_relations"
            for violation in (item.get("invariant_violations") or [])
        )
    )
    state_relation_control_violation_count = len(control_relation_findings)
    security_counts = _multi_component_security_counts(
        combined_results, control_relation_record
    )

    combined_summary = {
        "total_fault_points": total_combined,
        **security_counts,
        "split_brain": split_brain_count,
        "all_failed": all_failed_count,
        "success": success_count,
        "degraded": degraded_count,
        "state_relation_violations": state_relation_violation_count,
        "state_relation_control_violations": state_relation_control_violation_count,
        "split_brain_rate": (
            float(split_brain_count) / float(total_combined)
        ) if total_combined > 0 else 0.0,
    }

    _progress(
        "Multi-component sweep complete: {} total points, {} split-brain ({:.1%})".format(
            total_combined,
            split_brain_count,
            combined_summary["split_brain_rate"],
        )
    )

    return {
        "multi_component": True,
        "fault_matrix": mc.fault_matrix,
        "components": [c.name for c in mc.components],
        "per_component": per_component_data,
        "combined_results": combined_results,
        "control_combined_result": control_relation_record,
        "control_state": observed_controls,
        "control_invariant_violations": control_relation_violations,
        "combined_summary": combined_summary,
    }


@dataclasses.dataclass
class MultiFaultPhaseResult:
    """Aggregated outputs from the multi-fault planning and execution phase."""
    plan: Optional[MultiFaultPlan] = None
    plan_data: Optional[Dict[str, Any]] = None
    results: Optional[List[Dict[str, Any]]] = None
    summary: Optional[Dict[str, Any]] = None


def run_multi_fault_phase(
    *,
    profile: ProfileConfig,
    sweep_results: List[Dict[str, Any]],
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: Optional[str],
    num_workers: int,
    max_batch_points: int,
    max_writes: int,
    no_hash_bypass: bool = False,
    explain_only: bool = False,
    keep_run_artifacts: bool = False,
    profile_initial_state_name: Optional[str] = None,
) -> MultiFaultPhaseResult:
    """Plan and optionally execute multi-fault sequences.

    Returns a :class:`MultiFaultPhaseResult` with plan, execution results,
    and summary.  If the multi-fault config is disabled, returns an empty
    result with all fields ``None``.
    """
    from result_checks import annotate_result_checks  # avoid circular import

    out = MultiFaultPhaseResult()
    mf_config = profile.fault_sweep.multi_fault
    if not mf_config.enabled:
        return out

    expected_outcome = "success"
    if getattr(profile.expect, "control_outcome", None):
        expected_outcome = profile.expect.control_outcome
    interesting_pts = _interesting_multi_fault_points(
        sweep_results, expected_outcome
    )
    interesting_fps = [p.fault_at for p in interesting_pts]
    point_provenance: Dict[int, Dict[str, Any]] = {
        p.fault_at: {
            "reason": p.reason,
            "boot_outcome": p.boot_outcome,
            "fault_address": p.fault_address,
        }
        for p in interesting_pts
    }
    print(
        "Multi-fault: {} interesting points from single-fault sweep "
        "(strategy={}, max_pairs={}).".format(
            len(interesting_fps), mf_config.strategy, mf_config.max_pairs,
        ),
        file=sys.stderr,
    )

    mf_plan = generate_multi_fault_sequences(
        strategy=mf_config.strategy,
        interesting_points=interesting_fps,
        max_faults_per_run=mf_config.max_faults_per_run,
        max_pairs=mf_config.max_pairs,
        explicit_sequences=mf_config.sequences or None,
        seed=mf_config.seed,
        fallback_strategy=mf_config.fallback_strategy,
        fallback_points=[
            int(r.get("fault_at", 0))
            for r in sweep_results
            if r.get("fault_injected", False) and not r.get("is_control", False)
        ],
        point_provenance=point_provenance,
    )
    out.plan = mf_plan
    out.plan_data = multi_fault_plan_summary(mf_plan)
    print(
        "Multi-fault plan: {} sequences generated.".format(
            len(mf_plan.sequences)
        ),
        file=sys.stderr,
    )

    if explain_only and out.plan_data is not None:
        out.plan_data["execution_skipped"] = True
        out.plan_data["interesting_point_provenance"] = [
            dataclasses.asdict(p) for p in interesting_pts
        ]
        print(
            json.dumps(
                {"multi_fault_plan": out.plan_data}, indent=2, sort_keys=True,
            ),
            file=sys.stderr,
        )
        return out

    if not mf_plan.sequences:
        out.results = []
        out.summary = summarize_runtime_sweep(
            [],
            total_writes=max_writes,
            profile=profile,
            expected_fault_points=0,
            expected_control_points=0,
        )
        out.summary["plan_empty"] = True
        out.summary["plan_empty_reason"] = (
            mf_plan.diagnostics.get("reason")
            or mf_plan.diagnostics.get("primary_reason")
            or "multi-fault planner generated no sequences"
        )
        return out

    multi_fault_points = [seq[0] for seq in mf_plan.sequences]
    multi_fault_types = [
        encode_multi_fault_sequence(seq) for seq in mf_plan.sequences
    ]
    _mf_rationale_lookup: Dict[str, str] = {}
    for _seq_obj in mf_plan.sequences:
        if isinstance(_seq_obj, AnnotatedSequence):
            _mf_key = encode_multi_fault_sequence(_seq_obj)
            _mf_rationale_lookup[_mf_key] = _seq_obj.rationale

    mf_wall_t0 = _time_mod.time()
    out.results = run_runtime_sweep(
        repo_root=repo_root,
        renode_test=renode_test,
        robot_suite=robot_suite,
        profile=profile,
        fault_points=multi_fault_points,
        robot_vars=robot_vars,
        work_dir=work_dir / "multi_fault",
        renode_remote_server_dir=renode_remote_server_dir,
        include_control=False,
        num_workers=num_workers,
        evaluation_mode="execute",
        max_batch_points=max_batch_points,
        trace_file=None,
        erase_trace_file=None,
        trace_file_bin=None,
        erase_trace_file_bin=None,
        fault_types_list=multi_fault_types,
        keep_run_artifacts=keep_run_artifacts,
        no_hash_bypass=no_hash_bypass,
        profile_initial_state_name=profile_initial_state_name,
    )
    mf_wall_s = _time_mod.time() - mf_wall_t0

    for mf_r in out.results:
        ft = mf_r.get("fault_type", "")
        if isinstance(ft, str) and ft.startswith("mf:"):
            try:
                mf_r["fault_sequence"] = decode_multi_fault_sequence(ft)
            except (ValueError, TypeError):
                pass
            _rat = _mf_rationale_lookup.get(ft)
            if _rat:
                mf_r["sequence_rationale"] = _rat

    annotate_result_checks(out.results, profile, repo_root=repo_root)
    out.summary = summarize_runtime_sweep(
        out.results,
        total_writes=max_writes,
        profile=profile,
        expected_fault_points=len(multi_fault_points),
        expected_control_points=0,
    )
    out.summary["wall_time_s"] = round(mf_wall_s, 1)
    print(
        "Multi-fault sweep completed: {} sequences in {:.1f}s "
        "({:.0f}ms/sequence avg)".format(
            len(multi_fault_points), mf_wall_s,
            (mf_wall_s * 1000 / len(multi_fault_points))
            if multi_fault_points else 0,
        ),
        file=sys.stderr,
    )
    return out
