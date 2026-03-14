"""Sweep orchestration for runtime, partial-staging, and multi-component fault injection.

Extracted from audit_bootloader.py to isolate sweep execution logic from
the CLI entry point.
"""

from __future__ import annotations

import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dataclasses
import json
import time as _time_mod

from audit_report import summarize_runtime_sweep
from fault_classification import _effective_boot_result, _interesting_multi_fault_points
from fault_inject import (
    AnnotatedSequence,
    MultiFaultPlan,
    classify_multi_component_outcome,
    decode_multi_fault_sequence,
    encode_multi_fault_sequence,
    generate_multi_fault_sequences,
    multi_fault_plan_summary,
)
from fault_types import EXECUTE_ONLY_FAULT_TYPES
from partial_staging import (
    PartialStagingConfig,
    PartialStagingResult,
    TruncationPoint,
    classify_partial_staging_outcome,
    write_partial_image_to_temp,
)
from profile_loader import ProfileConfig, load_profile
from renode_runner import (
    _progress,
    _run_batches_chunked,
    merge_robot_vars,
    quick_subset,
    run_calibration,
    run_single_point,
)
from result_checks import annotate_result_checks


def _with_sweep_hash_bypass(
    robot_vars: List[str],
    profile: ProfileConfig,
    *,
    enabled: bool,
) -> List[str]:
    """Scope hash-bypass patches to faulted sweep runs only."""
    filtered_vars = [
        rv for rv in robot_vars if not rv.startswith("HASH_BYPASS_SYMBOLS:")
    ]
    if not enabled:
        return filtered_vars

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
) -> List[Dict[str, Any]]:
    """Worker function for parallel batch execution.

    Runs in a subprocess via ProcessPoolExecutor.  Reloads the profile
    from disk so everything is picklable.
    """
    repo_root = Path(repo_root_str)
    work_dir = Path(work_dir_str)
    worker_dir = work_dir / "worker_{}".format(worker_id)
    worker_dir.mkdir(parents=True, exist_ok=True)
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
            boot_outcome = "infra_error"
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
            boot_outcome = "infra_error"
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
) -> List[Dict[str, Any]]:
    """Run the full runtime fault sweep.

    Uses batch mode (single Renode session) for all fault points, then
    runs the control point separately.  When num_workers > 1, fault
    points are split across parallel Renode instances.

    If trace_file is provided, uses trace-replay mode: reconstructs
    flash state from the calibration trace instead of re-emulating
    Phase 1.  This eliminates the O(N^2) prefix cost.

    fault_types_list: parallel list of per-point fault type codes.
    """
    control_robot_vars = _with_sweep_hash_bypass(
        robot_vars,
        profile,
        enabled=False,
    )
    fault_robot_vars = _with_sweep_hash_bypass(
        robot_vars,
        profile,
        enabled=not no_hash_bypass,
    )

    # Full execute-mode without trace replay is memory-heavy in long single
    # Renode sessions.  Late fault points (high fp value) are much more
    # expensive than early ones because Phase 1 must emulate up to fp writes.
    # Use a time-budget approach: pack variable-sized batches so each Renode
    # session completes within ~180s.  Early cheap points get packed densely
    # (up to 64/batch), late expensive points get packed sparsely (down to 1).
    if (
        max_batch_points <= 0
        and evaluation_mode == "execute"
        and not trace_file
        and not trace_file_bin
        and fault_points
    ):
        _BATCH_TIME_BUDGET_S = 180.0
        _BASE_COST_S = 2.0     # overhead per point (setup + Phase 2)
        _PER_WRITE_COST_S = 0.003  # Phase 1 emulation scales with fp value
        _MAX_PER_BATCH = 64    # cap for memory safety

        # Compute variable-sized chunk boundaries.
        _exe_chunk_boundaries: List[int] = [0]
        _budget_used = 0.0
        for i, fp in enumerate(fault_points):
            cost = _BASE_COST_S + abs(fp) * _PER_WRITE_COST_S
            _budget_used += cost
            pts_in_chunk = i - _exe_chunk_boundaries[-1] + 1
            if _budget_used > _BATCH_TIME_BUDGET_S or pts_in_chunk >= _MAX_PER_BATCH:
                _exe_chunk_boundaries.append(i)
                _budget_used = cost
        _n_chunks = len(_exe_chunk_boundaries)
        # Derive a representative max_batch_points for the chunking below.
        # The actual chunk sizes vary, but the downstream chunker uses this
        # as a uniform cap — set it to the median chunk size so most chunks
        # are processed in one go, and the few oversized ones get one split.
        _chunk_sizes = []
        for j in range(len(_exe_chunk_boundaries)):
            start = _exe_chunk_boundaries[j]
            end = _exe_chunk_boundaries[j + 1] if j + 1 < len(_exe_chunk_boundaries) else len(fault_points)
            _chunk_sizes.append(end - start)
        _chunk_sizes.sort()
        max_batch_points = max(1, _chunk_sizes[len(_chunk_sizes) // 2])
        # Clamp to [1, 64]
        max_batch_points = max(1, min(_MAX_PER_BATCH, max_batch_points))
        _total_est = sum(_BASE_COST_S + abs(fp) * _PER_WRITE_COST_S for fp in fault_points)
        print(
            "Execute mode without trace replay: ~{} batches, median {} pts/batch "
            "({}s budget, {:.0f}s total est, {} points, max fp={}).".format(
                _n_chunks, max_batch_points, int(_BATCH_TIME_BUDGET_S),
                _total_est, len(fault_points),
                max(fault_points) if fault_points else 0,
            ),
            file=sys.stderr,
        )

    if fault_points and num_workers > 1:
        # Interleave fault points across workers for load balancing.
        # High-index fault points take 10-100x longer (more Phase 2 emulation).
        # Round-robin interleaving gives each worker a mix of fast and slow points.
        n = min(num_workers, len(fault_points))
        chunks = [fault_points[i::n] for i in range(n)]
        ft_chunks: List[Optional[List[str]]] = []
        if fault_types_list:
            ft_chunks = [fault_types_list[i::n] for i in range(n)]
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
    elif fault_points:
        batch_results = _run_batches_chunked(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_points=fault_points,
            robot_vars=fault_robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            trace_file=trace_file,
            erase_trace_file=erase_trace_file,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=erase_trace_file_bin,
            fault_types_list=fault_types_list,
            max_batch_points=max_batch_points,
            keep_run_artifacts=keep_run_artifacts,
        )
    else:
        batch_results = []

    results: List[Dict[str, Any]] = []
    for data in batch_results:
        data["is_control"] = False
        results.append(data)

    # Control point runs separately (fault_at far beyond max writes).
    if include_control:
        max_fp = max(fault_points) if fault_points else 999999
        control_at = max(999999, max_fp) + 1
        data = run_single_point(
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
        data["is_control"] = True
        results.append(data)

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

        # Build robot vars for this component.  Start from caller-supplied
        # base vars (CLI overrides, stall timeouts, etc.) and layer the
        # component-specific profile vars on top so that component-local
        # settings win on conflict.
        comp_robot_vars = merge_robot_vars(robot_vars_base, comp_profile.robot_vars(repo_root))
        comp_robot_vars.append("EVALUATION_MODE:{}".format(evaluation_mode))
        comp_robot_vars.append(
            "EXPECT_CONTROL_OUTCOME:{}".format(comp_profile.expect.control_outcome)
        )

        # Determine eval mode from component or parent.
        comp_eval_mode = evaluation_mode
        if comp_profile.fault_sweep.evaluation_mode:
            comp_eval_mode = comp_profile.fault_sweep.evaluation_mode

        # Calibrate this component.
        comp_max_writes = comp_profile.fault_sweep.max_writes
        trace_file: Optional[str] = None
        erase_trace_file: Optional[str] = None
        trace_file_bin: Optional[str] = None
        erase_trace_file_bin: Optional[str] = None

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

        # Build fault points for this component.
        step = max(1, fault_step)
        fp_start = fault_start if fault_start is not None else 0
        fp_end = fault_end if fault_end is not None else comp_max_writes
        fault_points = list(range(fp_start, fp_end, step))
        if comp_max_writes > 0 and comp_max_writes - 1 not in fault_points and fault_end is None:
            fault_points.append(comp_max_writes - 1)
        if quick:
            fault_points = quick_subset(fault_points)

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
            keep_run_artifacts=keep_run_artifacts,
            no_hash_bypass=no_hash_bypass,
        )

        annotate_result_checks(comp_results, comp_profile)

        # For cross_product: classify each faulted result against clean
        # outcomes of other components.  Since each component is swept
        # independently in separate Renode instances, we use the control
        # result of other components as their "clean" outcome.
        other_control_outcomes: Dict[str, str] = {}
        for other_idx, other_profile in enumerate(component_profiles):
            if other_idx == comp_idx:
                continue
            other_name = mc.components[other_idx].name
            # Other components are assumed to boot successfully when not faulted.
            other_control_outcomes[other_name] = other_profile.expect.control_outcome

        for result in comp_results:
            if result.get("is_control", False):
                continue
            if not result.get("fault_injected", False):
                continue

            faulted_outcome, _ = _effective_boot_result(result)
            per_comp_outcomes: Dict[str, Dict[str, Any]] = {
                comp_name: {
                    "boot_outcome": faulted_outcome,
                    "boot_slot": result.get("boot_slot"),
                    "fault_at": result.get("fault_at"),
                    "faulted": True,
                },
            }
            for other_name, other_expected in other_control_outcomes.items():
                per_comp_outcomes[other_name] = {
                    "boot_outcome": other_expected,
                    "boot_slot": None,
                    "faulted": False,
                }

            combined_outcome = classify_multi_component_outcome(per_comp_outcomes)

            combined_result = {
                "faulted_component": comp_name,
                "fault_at": result.get("fault_at"),
                "fault_type": result.get("fault_type"),
                "combined_outcome": combined_outcome,
                "per_component": per_comp_outcomes,
                "is_control": False,
            }
            combined_results.append(combined_result)

        # Store per-component summary.
        comp_summary = summarize_runtime_sweep(
            comp_results, total_writes=comp_max_writes, profile=comp_profile
        )
        per_component_data[comp_name] = {
            "calibrated_writes": comp_max_writes,
            "fault_points_tested": len(fault_points),
            "summary": comp_summary,
            "results": comp_results,
        }

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

    combined_summary = {
        "total_fault_points": total_combined,
        "split_brain": split_brain_count,
        "all_failed": all_failed_count,
        "success": success_count,
        "degraded": degraded_count,
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

    annotate_result_checks(out.results, profile)
    out.summary = summarize_runtime_sweep(
        out.results, total_writes=max_writes, profile=profile,
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
