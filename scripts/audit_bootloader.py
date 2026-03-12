#!/usr/bin/env python3
"""Profile-driven bootloader audit via runtime fault sweep.

Loads a declarative YAML profile, runs fault injection at every NVM write
point during an OTA update, and reports which fault points result in a
bricked device.

Usage::

    python3 scripts/audit_bootloader.py \\
        --profile profiles/naive_bare_copy.yaml \\
        --output results/naive_audit.json

    python3 scripts/audit_bootloader.py \\
        --profile profiles/mcuboot_swap_current.yaml \\
        --output results/mcuboot_audit.json \\
        --quick
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import (
    AnnotatedSequence,
    MultiFaultPlan,
    apply_clustered_distribution,
    decode_multi_fault_sequence,
    encode_multi_fault_sequence,
    generate_multi_fault_sequences,
    multi_fault_plan_summary,
)
from partial_staging import (
    generate_truncation_points,
    parse_partial_staging_config,
    summarize_partial_staging,
)
from fault_classification import _interesting_multi_fault_points
from fault_types import FAULT_TYPE_NAME_TO_CODE
from trace_utils import (
    annotate_fault_windows,
    build_clean_operation_trace,
    load_clean_erase_trace,
    load_clean_write_trace,
)
from audit_report import git_metadata, summarize_runtime_sweep
from result_checks import annotate_result_checks
from renode_runner import (
    CalibrationResult,
    _progress,
    ensure_tool,
    parse_robot_vars,
    quick_subset,
    run_calibration,
)
from sweep import (
    evaluate_config_checks,
    run_multi_component_sweep,
    run_partial_staging_sweep,
    run_runtime_sweep,
    validate_runtime_fault_mode_compat,
)
from profile_loader import HeuristicConfig, ProfileConfig, load_profile

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RENODE_TEST = os.environ.get("RENODE_TEST", "renode-test")
DEFAULT_ROBOT_SUITE = "tests/ota_fault_point.robot"
EXIT_ASSERTION_FAILURE = 1
EXIT_INFRA_FAILURE = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile-driven bootloader fault-injection audit."
    )
    parser.add_argument(
        "--profile", required=True,
        help="Path to a YAML bootloader profile.",
    )
    parser.add_argument("--output", required=True, help="Output JSON report path.")
    parser.add_argument(
        "--evaluation-mode",
        choices=("state", "execute"),
        default="state",
        help="Fault evaluation: state (fast Python simulation) or execute (CPU boot). Default: state.",
    )
    parser.add_argument(
        "--renode-test",
        default=DEFAULT_RENODE_TEST,
        help="renode-test executable path, or docker://IMAGE to run inside Docker.",
    )
    parser.add_argument(
        "--renode-remote-server-dir", default="",
        help="Optional directory containing the renode remote-server binary.",
    )
    parser.add_argument("--robot-suite", default=DEFAULT_ROBOT_SUITE)
    parser.add_argument(
        "--robot-var", action="append", default=[], metavar="KEY:VALUE",
        help="Extra Robot variable (repeatable).",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Run a smoke subset (first, middle, last fault points).",
    )
    parser.add_argument(
        "--fault-step", type=int, default=1,
        help="Step between fault points (default: 1 = test every write).",
    )
    parser.add_argument(
        "--fault-start", type=int, default=None,
        help="First fault point to test (default: 0).",
    )
    parser.add_argument(
        "--fault-end", type=int, default=None,
        help="Last fault point to test (exclusive; default: max_writes).",
    )
    parser.add_argument("--keep-run-artifacts", action="store_true")
    parser.add_argument(
        "--no-control", action="store_true",
        help="Skip automatic unfaulted control run.",
    )
    parser.add_argument(
        "--no-assert-control-boots", action="store_true",
        help="Disable control-boot assertion.",
    )
    parser.add_argument(
        "--no-assert-verdict", action="store_true",
        help="Disable verdict assertion (still writes summary and report).",
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel Renode instances (default: 1).",
    )
    parser.add_argument(
        "--max-batch-points",
        type=int,
        default=int(os.environ.get("OTA_MAX_BATCH_POINTS", "0")),
        help=(
            "Maximum fault points per Renode batch session (0 = auto). "
            "For execute mode without trace replay, auto defaults to 4."
        ),
    )
    parser.add_argument(
        "--no-trace-replay", action="store_true",
        help="Disable trace replay optimization; force full CPU execution for every fault point.",
    )
    parser.add_argument(
        "--no-hash-bypass", action="store_true",
        help="Disable hash validation bypass; run full crypto in emulation (slower but hyper-realistic).",
    )
    parser.add_argument(
        "--progress-stall-timeout-s",
        type=float,
        default=float(os.environ.get("OTA_PROGRESS_STALL_TIMEOUT_S", "20")),
        help=(
            "No-progress timeout forwarded to runtime .resc. "
            "Set <=0 to disable. Default from OTA_PROGRESS_STALL_TIMEOUT_S or 20."
        ),
    )
    parser.add_argument(
        "--explain-multi-fault-plan",
        action="store_true",
        help=(
            "Explain the generated multi-fault plan and skip executing the "
            "multi-fault sweep."
        ),
    )
    return parser.parse_args()



def main() -> int:
    args = parse_args()
    repo_root = REPO_ROOT
    temp_ctx: Optional[tempfile.TemporaryDirectory[str]] = None

    try:
        profile = load_profile(args.profile)
        robot_suite = args.robot_suite

        if profile.success_criteria.image_hash:
            print("Discovery mode: image hash validation enabled.", file=sys.stderr)
        if profile.update_trigger:
            print(
                "Update trigger: {} on slot '{}' ({} pre_boot writes generated).".format(
                    profile.update_trigger.type,
                    profile.update_trigger.slot,
                    len(profile.pre_boot_state),
                ),
                file=sys.stderr,
            )

        # Resolve evaluation mode: profile default, then CLI override.
        eval_mode = args.evaluation_mode
        if profile.fault_sweep.evaluation_mode and not any(
            a.startswith("--evaluation-mode") for a in sys.argv
        ):
            eval_mode = profile.fault_sweep.evaluation_mode
        validate_runtime_fault_mode_compat(profile, eval_mode)
        renode_test = ensure_tool(args.renode_test)

        # Build robot vars from profile + CLI extras.
        robot_vars = profile.robot_vars(repo_root) + parse_robot_vars(args.robot_var)
        robot_vars.append("EVALUATION_MODE:{}".format(eval_mode))
        # Stall timeout: CLI overrides profile, profile overrides default.
        stall_timeout = args.progress_stall_timeout_s
        cli_explicitly_set = any(
            a.startswith("--progress-stall-timeout") for a in sys.argv
        )
        if not cli_explicitly_set and profile.fault_sweep.progress_stall_timeout_s is not None:
            stall_timeout = profile.fault_sweep.progress_stall_timeout_s
        robot_vars.append(
            "PROGRESS_STALL_TIMEOUT_S:{:.6f}".format(stall_timeout)
        )
        robot_vars.append(
            "EXPECT_CONTROL_OUTCOME:{}".format(profile.expect.control_outcome)
        )

        # Strip hash bypass symbols if --no-hash-bypass was requested.
        if args.no_hash_bypass:
            robot_vars = [v for v in robot_vars if not v.startswith("HASH_BYPASS_SYMBOLS:")]

        # Write success_criteria_overrides to a temp file so the .resc can
        # read it directly, bypassing Robot→Renode variable escaping issues.
        _overrides_file = None
        _overrides_prefix = "SUCCESS_CRITERIA_OVERRIDES:"
        for rv in robot_vars:
            if rv.startswith(_overrides_prefix):
                import base64
                b64_val = rv[len(_overrides_prefix):]
                padded = b64_val + "=" * (-len(b64_val) % 4)
                raw_json = base64.b64decode(padded).decode()
                _overrides_file = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", prefix="tardigrade_overrides_",
                    delete=False,
                )
                _overrides_file.write(raw_json)
                _overrides_file.close()
                robot_vars = [
                    v for v in robot_vars if not v.startswith(_overrides_prefix)
                ]
                robot_vars.append(
                    "SUCCESS_CRITERIA_OVERRIDES_FILE:{}".format(_overrides_file.name)
                )
                break

        # -------------------------------------------------------------------
        # Multi-component dispatch
        # -------------------------------------------------------------------
        if profile.is_multi_component:
            _progress(
                "Multi-component profile detected: {} components.".format(
                    len(profile.multi_component.components)
                )
            )

            # Work directory for multi-component run.
            if args.keep_run_artifacts:
                execution_dir = repo_root / "results" / "audit_runs"
                execution_dir.mkdir(parents=True, exist_ok=True)
                work_dir = execution_dir / dt.datetime.now(dt.timezone.utc).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                work_dir.mkdir(parents=True, exist_ok=True)
            else:
                temp_ctx = tempfile.TemporaryDirectory(prefix="ota_audit_")
                work_dir = Path(temp_ctx.name)

            mc_result = run_multi_component_sweep(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=profile,
                robot_vars_base=robot_vars,
                work_dir=work_dir,
                renode_remote_server_dir=args.renode_remote_server_dir,
                evaluation_mode=eval_mode,
                quick=args.quick,
                fault_step=args.fault_step,
                fault_start=args.fault_start,
                fault_end=args.fault_end,
                num_workers=args.workers,
                max_batch_points=args.max_batch_points,
                no_trace_replay=args.no_trace_replay,
                no_hash_bypass=args.no_hash_bypass,
                keep_run_artifacts=args.keep_run_artifacts,
                no_control=args.no_control,
            )

            # Determine verdict for multi-component.
            combined_summary = mc_result["combined_summary"]
            split_brain_count = combined_summary["split_brain"]
            mc_verdict = "PASS"
            if profile.expect.should_find_issues and split_brain_count == 0:
                mc_verdict = "FAIL -- expected to find split-brain issues but found none"
            elif not profile.expect.should_find_issues and split_brain_count > 0:
                mc_verdict = "FAIL -- found {} split-brain points".format(
                    split_brain_count
                )

            payload: Dict[str, Any] = {
                "engine": "renode-test",
                "profile": profile.name,
                "profile_path": str(profile.profile_path) if profile.profile_path else None,
                "schema_version": profile.schema_version,
                "multi_component": True,
                "verdict": mc_verdict,
                "summary": {
                    "combined": combined_summary,
                    "per_component": {
                        name: data["summary"]
                        for name, data in mc_result["per_component"].items()
                    },
                },
                "combined_results": mc_result["combined_results"],
                "expect": {
                    "should_find_issues": profile.expect.should_find_issues,
                },
                "execution": {
                    "run_utc": dt.datetime.now(dt.timezone.utc).replace(
                        microsecond=0
                    ).isoformat().replace("+00:00", "Z"),
                    "workers": args.workers,
                },
                "git": git_metadata(repo_root),
            }

            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
            )

            print(json.dumps({
                "profile": profile.name,
                "verdict": mc_verdict,
                "summary": payload["summary"],
            }, indent=2, sort_keys=True))

            if mc_verdict.startswith("FAIL") and not args.no_assert_verdict:
                return EXIT_ASSERTION_FAILURE
            return 0

        # Work directory.
        if args.keep_run_artifacts:
            execution_dir = repo_root / "results" / "audit_runs"
            execution_dir.mkdir(parents=True, exist_ok=True)
            work_dir = execution_dir / dt.datetime.now(dt.timezone.utc).strftime(
                "%Y%m%dT%H%M%SZ"
            )
            work_dir.mkdir(parents=True, exist_ok=True)
            report_artifacts_dir = str(work_dir.relative_to(repo_root))
        else:
            temp_ctx = tempfile.TemporaryDirectory(prefix="ota_audit_")
            work_dir = Path(temp_ctx.name)
            report_artifacts_dir = "temporary"

        # -------------------------------------------------------------------
        # Calibration
        # -------------------------------------------------------------------
        cal: Optional[CalibrationResult] = None
        max_writes = profile.fault_sweep.max_writes
        trace_file: Optional[str] = None
        erase_trace_file: Optional[str] = None
        trace_file_bin: Optional[str] = None
        erase_trace_file_bin: Optional[str] = None
        total_erases: int = 0
        total_i2c_transactions: int = 0
        setup_writes: int = 0
        # Determine which fault classes are requested.
        fault_types = profile.fault_sweep.fault_types
        include_erases = (
            "interrupted_erase" in fault_types
            or "multi_sector_atomicity" in fault_types
        )
        include_power_loss = "power_loss" in fault_types
        include_bit_corruption = "bit_corruption" in fault_types
        include_silent_write_failure = "silent_write_failure" in fault_types
        include_write_disturb = "write_disturb" in fault_types
        include_wear_leveling = "wear_leveling_corruption" in fault_types
        include_write_rejection = "write_rejection" in fault_types
        include_reset_at_time = "reset_at_time" in fault_types
        include_metadata_fault = profile.fault_sweep.metadata_fault.enabled
        include_multi_sector_atomicity = "multi_sector_atomicity" in fault_types
        include_read_bit_flip = "read_bit_flip" in fault_types
        include_command_drop = "command_drop" in fault_types
        include_instruction_skip = "instruction_skip" in fault_types
        include_i2c_faults = any(ft.startswith("i2c_") for ft in fault_types)
        i2c_fault_types = [ft for ft in fault_types if ft.startswith("i2c_")]
        include_otp_faults = any(ft.startswith("otp_") for ft in fault_types)
        otp_fault_types = [ft for ft in fault_types if ft.startswith("otp_")]
        include_nvs_corruption = "nvs_corruption" in fault_types

        # Pass fault_types to calibration so erase trace is captured.
        if include_erases:
            robot_vars.append("FAULT_TYPES:both")

        if max_writes == "auto":
            if eval_mode == "state" and "exec" in profile.memory.slots:
                # State mode: compute write count from slot geometry.
                exec_slot = profile.memory.slots["exec"]
                max_writes = exec_slot.size // profile.memory.write_granularity
                print("Computed write count from slot geometry: {} writes.".format(max_writes), file=sys.stderr)
            else:
                print("Calibrating write count for '{}'...".format(profile.name), file=sys.stderr)
                cal = run_calibration(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    robot_vars=robot_vars,
                    work_dir=work_dir,
                    renode_remote_server_dir=args.renode_remote_server_dir,
                    keep_run_artifacts=args.keep_run_artifacts,
                )
                max_writes = cal.total_writes
                total_erases = cal.total_erases
                trace_file = cal.trace_file
                erase_trace_file = cal.erase_trace_file
                trace_file_bin = cal.trace_file_bin
                erase_trace_file_bin = cal.erase_trace_file_bin
                # For image hash discovery mode: use calibration-computed
                # exec hash as the ground truth for what a successful
                # operation produces.
                if cal.calibration_exec_hash:
                    robot_vars.append(
                        "EXPECTED_EXEC_SHA256:{}".format(cal.calibration_exec_hash)
                    )
                    print(
                        "Calibration: exec slot hash = {}...".format(
                            cal.calibration_exec_hash[:16]
                        ),
                        file=sys.stderr,
                    )
                setup_writes = cal.setup_writes
                total_i2c_transactions = cal.total_i2c_transactions
                cal_parts = ["{} NVM writes".format(max_writes)]
                if include_erases:
                    cal_parts.append("{} page erases".format(total_erases))
                if total_i2c_transactions > 0:
                    cal_parts.append("{} I2C transactions".format(total_i2c_transactions))
                print("Calibration: {}.".format(", ".join(cal_parts)), file=sys.stderr)
        else:
            max_writes = int(max_writes)

        # Apply safety cap.
        cap = profile.fault_sweep.max_writes_cap
        if max_writes > cap:
            print(
                "Capping max_writes from {} to {}".format(max_writes, cap),
                file=sys.stderr,
            )
            max_writes = cap

        # -------------------------------------------------------------------
        # Build fault point list
        # -------------------------------------------------------------------
        heuristic_summary: Optional[Dict] = None
        use_heuristic = (
            trace_file
            and os.path.exists(trace_file)
            and not args.quick
            and args.fault_start is None
            and args.fault_end is None
            and args.fault_step == 1
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
            flash_base = int(profile.memory.slots.get("exec", profile.memory.slots[list(profile.memory.slots.keys())[0]]).base) if profile.memory.slots else 0
            # Reconstruct slot ranges as bus addresses.
            for sname, sinfo in profile.memory.slots.items():
                slot_ranges_for_heuristic[sname] = (sinfo.base, sinfo.base + sinfo.size)
            # The flash_base for heuristic is the FlashBaseAddress of the NVMC.
            # In our platform, nvm starts at the exec slot base.
            flash_base = min(s.base for s in profile.memory.slots.values())

            bl_region_for_heuristic = None
            if profile.memory.bootloader_region is not None:
                bl = profile.memory.bootloader_region
                bl_region_for_heuristic = (bl.base, bl.base + bl.size)

            heuristic_kwargs: Dict[str, Any] = {}
            if profile.fault_sweep.heuristic_config is not None:
                hc = profile.fault_sweep.heuristic_config
                heuristic_kwargs["tier2_step"] = hc.tier2_step
                heuristic_kwargs["tier3_step"] = hc.tier3_step
                heuristic_kwargs["discontinuity_window"] = hc.discontinuity_window
                if hc.target_points is not None:
                    heuristic_kwargs["target_points"] = hc.target_points
                if hc.shard_count > 1:
                    heuristic_kwargs["shard_count"] = hc.shard_count
                    heuristic_kwargs["shard_index"] = hc.shard_index
                if hc.random_tail_budget > 0:
                    heuristic_kwargs["random_tail_budget"] = hc.random_tail_budget
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
            step = max(1, args.fault_step)
            fp_start = args.fault_start if args.fault_start is not None else 0
            fp_end = args.fault_end if args.fault_end is not None else max_writes
            fault_points = list(range(fp_start, fp_end, step))
            if max_writes > 0 and max_writes - 1 not in fault_points and args.fault_end is None:
                fault_points.append(max_writes - 1)

        if args.quick:
            fault_points = quick_subset(fault_points)

        # Build combined fault point list.
        # Each fault point has a type:
        #   'w' write power-loss, 'b' bit corruption, 's' silent write failure,
        #   'r' write rejection, 'd' write disturb,
        #   'l' wear-leveling corruption, 't' reset-at-time,
        #   'e' interrupted erase, 'a' multi-sector atomicity fault,
        #   'f' read bit-flip (transient read corruption).
        fault_types_list: Optional[List[str]] = None
        multi_fault_plan: Optional[MultiFaultPlan] = None
        has_mixed_types = (
            (include_erases and total_erases > 0)
            or include_bit_corruption
            or include_silent_write_failure
            or include_write_disturb
            or include_wear_leveling
            or include_write_rejection
            or include_reset_at_time
            or include_read_bit_flip
            or include_command_drop
            or include_instruction_skip
            or include_i2c_faults
            or include_otp_faults
            or include_nvs_corruption
            or profile.fault_sweep.phase2_fault.enabled
            or profile.fault_sweep.multi_fault.enabled
            or include_metadata_fault
        )
        clustered_bit_count = 0
        if has_mixed_types:
            write_fps: List[Tuple[int, str]] = []
            if include_power_loss:
                # no_boot baselines can legitimately calibrate to 0 writes.
                # In that case, skip write-based points.
                write_fps = [(fp, 'w') for fp in fault_points] if max_writes > 0 else []
            combined = list(write_fps)

            # Add erase-based fault points.
            # MRAM has no page erases -- skip erase fault points entirely.
            is_mram_backend = (
                profile.flash_backend
                and "mram" in profile.flash_backend.lower()
            )
            erase_count = 0
            atomicity_count = 0
            if include_erases and total_erases > 0 and not is_mram_backend:
                erase_fps = list(range(0, total_erases))
                if args.quick:
                    erase_fps = quick_subset(erase_fps)
                if "interrupted_erase" in fault_types:
                    combined += [(ep, 'e') for ep in erase_fps]
                    erase_count = len(erase_fps)
                if include_multi_sector_atomicity:
                    combined += [(ep, 'a') for ep in erase_fps]
                    atomicity_count = len(erase_fps)
            elif include_erases and is_mram_backend:
                print(
                    "Skipping erase fault points: MRAM backend '{}' has no "
                    "page erases.".format(profile.flash_backend),
                    file=sys.stderr,
                )

            # Add bit-corruption fault points (same write indices, different mode).
            # If a clustered fault_distribution is configured, apply spatial
            # probability weighting to bias corruption toward specific sectors.
            bit_count = 0
            clustered_bit_count = 0
            if include_bit_corruption:
                bit_fps = list(fault_points)  # same write indices
                if args.quick:
                    bit_fps = quick_subset(bit_fps)

                # Always include uniform bit_corruption for all points.
                combined += [(bp, 'b') for bp in bit_fps]
                bit_count = len(bit_fps)

                # If clustered distribution is configured, ADD extra
                # spatially-weighted points (additive, not replacement).
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
                if args.quick:
                    silent_fps = quick_subset(silent_fps)
                combined += [(sp, 's') for sp in silent_fps]
                silent_count = len(silent_fps)

            disturb_count = 0
            if include_write_disturb:
                disturb_fps = list(fault_points)
                if args.quick:
                    disturb_fps = quick_subset(disturb_fps)
                combined += [(dp, 'd') for dp in disturb_fps]
                disturb_count = len(disturb_fps)

            wear_count = 0
            if include_wear_leveling:
                wear_fps = list(fault_points)
                if args.quick:
                    wear_fps = quick_subset(wear_fps)
                combined += [(wp, 'l') for wp in wear_fps]
                wear_count = len(wear_fps)

            rejection_count = 0
            if include_write_rejection:
                rejection_fps = list(fault_points)
                if args.quick:
                    rejection_fps = quick_subset(rejection_fps)
                combined += [(rp, 'r') for rp in rejection_fps]
                rejection_count = len(rejection_fps)

            timed_reset_count = 0
            if include_reset_at_time:
                timed_reset_fps = list(fault_points)
                if not timed_reset_fps:
                    # Keep reset-at-time coverage available even when
                    # calibration found 0 writes (e.g. expected no_boot).
                    timed_reset_fps = [0]
                if args.quick:
                    timed_reset_fps = quick_subset(timed_reset_fps)
                combined += [(tp, 't') for tp in timed_reset_fps]
                timed_reset_count = len(timed_reset_fps)

            read_flip_count = 0
            if include_read_bit_flip:
                read_flip_fps = list(fault_points)
                if args.quick:
                    read_flip_fps = quick_subset(read_flip_fps)
                combined += [(fp, 'f') for fp in read_flip_fps]
                read_flip_count = len(read_flip_fps)

            command_drop_count = 0
            if include_command_drop:
                command_drop_fps = list(fault_points)
                if args.quick:
                    command_drop_fps = quick_subset(command_drop_fps)
                combined += [(fp, 'k') for fp in command_drop_fps]
                command_drop_count = len(command_drop_fps)

            # I2C bus fault injection: iterate FaultAtTransaction from 1 to N
            # for each configured I2C fault type.
            i2c_fault_count = 0
            if include_i2c_faults and total_i2c_transactions > 0:
                i2c_fps = list(range(total_i2c_transactions))
                if args.quick:
                    i2c_fps = quick_subset(i2c_fps)
                for i2c_ft in i2c_fault_types:
                    i2c_code = FAULT_TYPE_NAME_TO_CODE.get(i2c_ft, "in")
                    combined += [(fp, i2c_code) for fp in i2c_fps]
                    i2c_fault_count += len(i2c_fps)

            # OTP fault injection: same write indices as power-loss, but
            # each OTP fault type uses a different BlowFaultMode on the
            # OTPMemory peripheral.
            otp_fault_count = 0
            if include_otp_faults:
                otp_fps = list(fault_points)
                if args.quick:
                    otp_fps = quick_subset(otp_fps)
                for otp_ft in otp_fault_types:
                    otp_code = FAULT_TYPE_NAME_TO_CODE.get(otp_ft, "op")
                    combined += [(fp, otp_code) for fp in otp_fps]
                    otp_fault_count += len(otp_fps)

            # NVS corruption: pre-boot region corruption variants.
            # Each variant corrupts the NVS region with a different mode
            # (bit_flip, partial_erase, truncate, scramble) and boots.
            # Encoded as 'nv:<variant_index>' where variant_index selects
            # the corruption mode from the NvsCorruptionConfig.
            nvs_fault_count = 0
            if include_nvs_corruption:
                nvs_cfg = profile.fault_sweep.nvs_corruption
                if nvs_cfg.enabled and profile.memory.nvs_region is not None:
                    nvs_modes = nvs_cfg.modes
                    for vi, mode in enumerate(nvs_modes):
                        combined.append((vi, "nv:{}".format(vi)))
                        nvs_fault_count += 1
                elif not nvs_cfg.enabled:
                    print(
                        "nvs_corruption in fault_types but nvs_corruption "
                        "config not enabled; skipping.",
                        file=sys.stderr,
                    )
                elif profile.memory.nvs_region is None:
                    print(
                        "nvs_corruption in fault_types but no nvs_region "
                        "configured; skipping.",
                        file=sys.stderr,
                    )

            # Instruction-skip fault injection: enumerate halfword-aligned
            # addresses in configured target ranges.  Each fault point is
            # an address (not a write index), encoded as 'i:<addr>'.
            instruction_skip_count = 0
            if include_instruction_skip:
                isc = profile.fault_sweep.instruction_skip_config
                if isc is not None and isc.target_addresses:
                    skip_addrs: List[int] = []
                    sc = isc.skip_count if isc.skip_count > 0 else 1
                    for region_start, region_end in isc.target_addresses:
                        # Stop early so that patching skip_count consecutive
                        # halfwords from the start address stays in bounds.
                        end = region_end - (sc - 1) * 2
                        for addr in range(region_start, max(end, region_start), 2):
                            skip_addrs.append(addr)
                    if args.quick:
                        skip_addrs = quick_subset(skip_addrs)
                    for addr in skip_addrs:
                        combined.append((addr, "i:0x{:X}".format(addr)))
                    instruction_skip_count = len(skip_addrs)

            # Metadata fault injection: fault during pre_boot_state writes.
            metadata_count = 0
            if include_metadata_fault:
                if setup_writes == 0:
                    setup_writes = len(profile.pre_boot_state)
                if setup_writes > 0:
                    mf_types = profile.fault_sweep.metadata_fault.fault_types
                    mf_fps = list(range(0, setup_writes))
                    if args.quick:
                        mf_fps = quick_subset(mf_fps)
                    for mf_fp in mf_fps:
                        for mf_name in mf_types:
                            mf_code = FAULT_TYPE_NAME_TO_CODE.get(mf_name, "w")
                            combined.append((mf_fp, "m:{}".format(mf_code)))
                            metadata_count += 1

            # Hook fault injection: fault writes performed by boot_cycle_hook
            # between boot cycles.
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
                hf_types = [FAULT_TYPE_NAME_TO_CODE.get(ft, "w") for ft in hf_config.fault_types]
                hook_fps = list(range(0, hook_max))
                if args.quick:
                    hook_fps = quick_subset(hook_fps)
                for hf_fp in hook_fps:
                    for hf_code in hf_types:
                        combined.append((hf_fp, "h:{}:{}".format(hf_fp, hf_code)))
                        hook_count += 1

            # Phase 2 recovery fault injection: for selected Phase 1 fault
            # points, also sweep faults during the recovery boot.
            p2_config = profile.fault_sweep.phase2_fault
            phase2_count = 0
            if p2_config.enabled and (write_fps or include_reset_at_time):
                p2_max = p2_config.max_points if p2_config.max_points > 0 else min(50, max(max_writes, 1))
                p2_type_codes = [
                    FAULT_TYPE_NAME_TO_CODE.get(ft, "w") for ft in p2_config.fault_types
                ]
                if not p2_type_codes:
                    p2_type_codes = ["w"]

                # Separate timed-reset Phase 2 codes from write/erase codes.
                p2_timed_codes = [c for c in p2_type_codes if c == "t"]
                p2_write_codes = [c for c in p2_type_codes if c != "t"]

                # Write/erase Phase 2: Phase 1 is always a write-fault.
                if p2_write_codes and write_fps:
                    p1_representatives = quick_subset([fp for fp, _ in write_fps])
                    p2_range = list(range(0, p2_max))
                    if args.quick:
                        p2_range = quick_subset(p2_range)
                    for p1_fp in p1_representatives:
                        for p2_fp in p2_range:
                            for p2_code in p2_write_codes:
                                enc = "p2:{}:{}:w:{}".format(p1_fp, p2_fp, p2_code)
                                combined.append((p1_fp, enc))
                                phase2_count += 1

                # Timed-reset Phase 2 (double-fault scenario):
                # Phase 1 uses a timed reset, Phase 2 also uses a timed reset
                # during recovery boot.  This tests whether a reset during
                # recovery from a prior timed reset can brick the device.
                if p2_timed_codes:
                    timed_p1_fps = list(fault_points) if fault_points else [0]
                    timed_p1_reps = quick_subset(timed_p1_fps)
                    timed_p2_range = list(range(0, p2_max))
                    if args.quick:
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
            if i2c_fault_count:
                parts.append("{} i2c-fault".format(i2c_fault_count))
            if otp_fault_count:
                parts.append("{} otp-fault".format(otp_fault_count))
            if nvs_fault_count:
                parts.append("{} nvs-corruption".format(nvs_fault_count))
            if instruction_skip_count:
                parts.append("{} instruction-skip".format(instruction_skip_count))
            if phase2_count:
                parts.append("{} phase2-recovery".format(phase2_count))
            if metadata_count:
                parts.append("{} metadata-fault".format(metadata_count))
            if hook_count:
                parts.append("{} hook-fault".format(hook_count))
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

        # -------------------------------------------------------------------
        # Fault sweep
        # -------------------------------------------------------------------
        import time as _time_mod
        sweep_wall_t0 = _time_mod.time()

        sweep_results = run_runtime_sweep(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_points=fault_points,
            robot_vars=robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=args.renode_remote_server_dir,
            include_control=not args.no_control,
            num_workers=args.workers,
            evaluation_mode=eval_mode,
            max_batch_points=args.max_batch_points,
            trace_file=trace_file if not args.no_trace_replay else None,
            erase_trace_file=erase_trace_file if not args.no_trace_replay else None,
            trace_file_bin=trace_file_bin if not args.no_trace_replay else None,
            erase_trace_file_bin=erase_trace_file_bin if not args.no_trace_replay else None,
            fault_types_list=fault_types_list,
            keep_run_artifacts=args.keep_run_artifacts,
        )

        sweep_wall_s = _time_mod.time() - sweep_wall_t0
        print(
            "Sweep completed: {} points in {:.1f}s ({:.0f}ms/point avg)".format(
                len(fault_points), sweep_wall_s,
                (sweep_wall_s * 1000 / len(fault_points)) if fault_points else 0,
            ),
            file=sys.stderr,
        )

        clean_trace_meta: Optional[Dict[str, Any]] = None
        if trace_file and os.path.exists(trace_file):
            flash_base = 0
            if profile.memory.slots:
                flash_base = min(slot.base for slot in profile.memory.slots.values())
            clean_write_trace = load_clean_write_trace(trace_file)
            clean_erase_trace = load_clean_erase_trace(erase_trace_file)
            clean_ops = build_clean_operation_trace(
                write_entries=clean_write_trace,
                erase_entries=clean_erase_trace,
                flash_base=flash_base,
            )
            erase_missing_writes_at = sum(
                1
                for e in clean_erase_trace
                if e.get("writes_at_this_point") is None
            )
            window_stats = annotate_fault_windows(sweep_results, clean_ops)
            clean_trace_meta = {
                "trace_file": trace_file,
                "erase_trace_file": erase_trace_file,
                "writes": len(clean_write_trace),
                "erases": len(clean_erase_trace),
                "erases_missing_writes_at": erase_missing_writes_at,
                "operations": len(clean_ops),
                "fault_windows_annotated": window_stats["annotated"],
                "fault_windows_skipped_unknown_interleaving": window_stats[
                    "skipped_unknown_interleaving"
                ],
            }
            print(
                "Fault-window annotation: {} points mapped to clean trace.".format(
                    window_stats["annotated"]
                ),
                file=sys.stderr,
            )
            if erase_missing_writes_at > 0:
                print(
                    "Clean erase trace: {} entries missing writes_at; "
                    "{} fault windows skipped because precise erase ordering is unknown.".format(
                        erase_missing_writes_at,
                        window_stats["skipped_unknown_interleaving"],
                    ),
                    file=sys.stderr,
                )

        annotate_result_checks(sweep_results, profile)
        sweep_summary = summarize_runtime_sweep(
            sweep_results, total_writes=max_writes, profile=profile
        )
        sweep_summary["wall_time_s"] = round(sweep_wall_s, 1)

        # Report skip reasons so operators know why points were discarded.
        skip_reasons = sweep_summary.get("skip_reasons")
        if skip_reasons:
            parts = [
                "{} {}".format(count, reason)
                for reason, count in sorted(skip_reasons.items())
            ]
            _progress(
                "Skipped {} fault points (not injected): {}".format(
                    sweep_summary.get("discarded_no_fault_fired", 0),
                    ", ".join(parts),
                )
            )
        phase2_skip_reasons = sweep_summary.get("phase2_skip_reasons")
        if phase2_skip_reasons:
            parts = [
                "{} {}".format(count, reason)
                for reason, count in sorted(phase2_skip_reasons.items())
            ]
            _progress(
                "Phase 2 fault points skipped before injection: {}".format(
                    ", ".join(parts),
                )
            )
        hook_skip_reasons = sweep_summary.get("hook_skip_reasons")
        if hook_skip_reasons:
            parts = [
                "{} {}".format(count, reason)
                for reason, count in sorted(hook_skip_reasons.items())
            ]
            _progress(
                "Hook fault points skipped before injection: {}".format(
                    ", ".join(parts),
                )
            )

        # -------------------------------------------------------------------
        # Multi-fault plan (opt-in)
        # -------------------------------------------------------------------
        multi_fault_plan_data = None
        multi_fault_results: Optional[List[Dict[str, Any]]] = None
        multi_fault_summary: Optional[Dict[str, Any]] = None
        mf_config = profile.fault_sweep.multi_fault

        if mf_config.enabled:
            expected_outcome = "success"
            if getattr(profile.expect, "control_outcome", None):
                expected_outcome = profile.expect.control_outcome
            interesting_pts = _interesting_multi_fault_points(
                sweep_results, expected_outcome
            )
            interesting_fps = [p.fault_at for p in interesting_pts]
            # Build provenance mapping for the plan generator.
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
                    len(interesting_fps),
                    mf_config.strategy,
                    mf_config.max_pairs,
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
            multi_fault_plan = mf_plan
            multi_fault_plan_data = multi_fault_plan_summary(mf_plan)
            print(
                "Multi-fault plan: {} sequences generated.".format(
                    len(mf_plan.sequences)
                ),
                file=sys.stderr,
            )
            if args.explain_multi_fault_plan and multi_fault_plan_data is not None:
                multi_fault_plan_data["execution_skipped"] = True
                multi_fault_plan_data["interesting_point_provenance"] = [
                    dataclasses.asdict(p) for p in interesting_pts
                ]
                print(
                    json.dumps(
                        {"multi_fault_plan": multi_fault_plan_data},
                        indent=2,
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
            if mf_plan.sequences and not args.explain_multi_fault_plan:
                multi_fault_points = [seq[0] for seq in mf_plan.sequences]
                multi_fault_types = [
                    encode_multi_fault_sequence(seq) for seq in mf_plan.sequences
                ]
                # Build a lookup from encoded sequence -> rationale for
                # attaching provenance to each result after execution.
                _mf_rationale_lookup: Dict[str, str] = {}
                for _seq_obj in mf_plan.sequences:
                    if isinstance(_seq_obj, AnnotatedSequence):
                        _mf_key = encode_multi_fault_sequence(_seq_obj)
                        _mf_rationale_lookup[_mf_key] = _seq_obj.rationale
                mf_wall_t0 = _time_mod.time()
                multi_fault_results = run_runtime_sweep(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    fault_points=multi_fault_points,
                    robot_vars=robot_vars,
                    work_dir=work_dir / "multi_fault",
                    renode_remote_server_dir=args.renode_remote_server_dir,
                    include_control=False,
                    num_workers=args.workers,
                    evaluation_mode="execute",
                    max_batch_points=args.max_batch_points,
                    trace_file=None,
                    erase_trace_file=None,
                    trace_file_bin=None,
                    erase_trace_file_bin=None,
                    fault_types_list=multi_fault_types,
                    keep_run_artifacts=args.keep_run_artifacts,
                )
                mf_wall_s = _time_mod.time() - mf_wall_t0
                # Decode and attach fault_sequence to each multi-fault result
                # so invariants and failure categorization see the full
                # sequence, not just seq[0].
                for mf_r in multi_fault_results:
                    ft = mf_r.get("fault_type", "")
                    if isinstance(ft, str) and ft.startswith("mf:"):
                        try:
                            mf_r["fault_sequence"] = decode_multi_fault_sequence(ft)
                        except (ValueError, TypeError):
                            pass
                        _rat = _mf_rationale_lookup.get(ft)
                        if _rat:
                            mf_r["sequence_rationale"] = _rat
                annotate_result_checks(multi_fault_results, profile)
                multi_fault_summary = summarize_runtime_sweep(
                    multi_fault_results,
                    total_writes=max_writes,
                    profile=profile,
                )
                multi_fault_summary["wall_time_s"] = round(mf_wall_s, 1)
                print(
                    "Multi-fault sweep completed: {} sequences in {:.1f}s "
                    "({:.0f}ms/sequence avg)".format(
                        len(multi_fault_points),
                        mf_wall_s,
                        (mf_wall_s * 1000 / len(multi_fault_points))
                        if multi_fault_points
                        else 0,
                    ),
                    file=sys.stderr,
                )

        # -------------------------------------------------------------------
        # State fuzzer (opt-in)
        # -------------------------------------------------------------------
        state_fuzz_results: Optional[List[Dict[str, Any]]] = None
        state_fuzz_summary: Optional[Dict[str, Any]] = None

        if profile.state_fuzzer.enabled:
            _progress("WARNING: state_fuzzer is enabled but not yet implemented — skipping")
            # State fuzzer runs via audit.robot / run_state_fuzz_point.resc
            # using a future scenario generator plugin.
            # This is the opt-in plugin path. For now, mark as placeholder.
            state_fuzz_results = []
            state_fuzz_summary = {"status": "not_yet_wired", "metadata_model": profile.state_fuzzer.metadata_model}

        # -------------------------------------------------------------------
        # Partial staging sweep (opt-in)
        # -------------------------------------------------------------------
        partial_staging_results: Optional[List[Dict[str, Any]]] = None
        partial_staging_summary: Optional[Dict[str, Any]] = None

        ps_raw = profile.fault_sweep.partial_staging
        if ps_raw is not None:
            ps_config = parse_partial_staging_config(
                ps_raw,
                images=profile.images,
                slots=profile.memory.slots,
                sector_size=profile.memory.write_granularity or 4096,
            )
            if ps_config is not None:
                staging_image_path = profile.resolve_path(
                    repo_root, ps_config.staging_image_path
                )
                if not os.path.exists(staging_image_path):
                    _progress(
                        "WARNING: partial_staging image not found: {}".format(
                            staging_image_path
                        )
                    )
                else:
                    with open(staging_image_path, "rb") as fh:
                        original_image = fh.read()
                    image_size = len(original_image)

                    trunc_points = generate_truncation_points(
                        image_size=image_size,
                        strategy=ps_config.truncation_points,
                        header_size=ps_config.header_size,
                        sector_size=ps_config.sector_size,
                        trailer_size=ps_config.trailer_size,
                        explicit_offsets=ps_config.explicit_offsets,
                        max_points=ps_config.max_points,
                    )
                    _progress(
                        "Partial staging: {} truncation points for {}-byte image".format(
                            len(trunc_points), image_size
                        )
                    )

                    ps_results_typed, partial_staging_results = (
                        run_partial_staging_sweep(
                            repo_root=repo_root,
                            renode_test=renode_test,
                            robot_suite=robot_suite,
                            profile=profile,
                            ps_config=ps_config,
                            original_image=original_image,
                            trunc_points=trunc_points,
                            robot_vars=robot_vars,
                            work_dir=work_dir,
                            renode_remote_server_dir=args.renode_remote_server_dir,
                            num_workers=args.workers,
                            keep_run_artifacts=args.keep_run_artifacts,
                        )
                    )

                    partial_staging_summary = summarize_partial_staging(
                        ps_results_typed
                    )

                    _progress(
                        "Partial staging complete: {} points, {} issues "
                        "({} bricks, {} partial boots)".format(
                            partial_staging_summary["total_points"],
                            partial_staging_summary["issue_count"],
                            partial_staging_summary.get("brick", 0),
                            partial_staging_summary.get(
                                "partial_image_booted", 0
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # Verdict
        # -------------------------------------------------------------------
        found_issues = int(
            sweep_summary.get("issue_points", sweep_summary["bricks"])
        ) > 0
        if multi_fault_summary is not None:
            found_issues = found_issues or (
                int(
                    multi_fault_summary.get(
                        "issue_points", multi_fault_summary["bricks"]
                    )
                )
                > 0
            )
        if partial_staging_summary is not None:
            found_issues = found_issues or (
                int(partial_staging_summary.get("issue_count", 0)) > 0
            )
        control_issue_count = int(
            (sweep_summary.get("control") or {}).get("issue_count", 0)
        )

        verdict = "PASS"
        if control_issue_count:
            verdict = "FAIL — control checks failed"
        elif profile.expect.should_find_issues and not found_issues:
            verdict = "FAIL — expected to find issues but found none"
        elif not profile.expect.should_find_issues and found_issues:
            total_issues = sweep_summary.get("issue_points", 0)
            if multi_fault_summary:
                total_issues += int(multi_fault_summary.get("issue_points", multi_fault_summary.get("bricks", 0)))
            if partial_staging_summary:
                total_issues += int(partial_staging_summary.get("issue_count", 0))
            verdict = "FAIL — found {} issue points ({} boot mismatches, {} semantic, {} invariant)".format(
                total_issues,
                sweep_summary.get("bricks", 0),
                sweep_summary.get("semantic_issue_points", 0),
                sweep_summary.get("invariant_issue_points", 0),
            )

        # -------------------------------------------------------------------
        # Build output
        # -------------------------------------------------------------------
        if Path(sys.argv[0]).suffix == ".py":
            command_parts = ["python3"] + sys.argv
        else:
            command_parts = sys.argv

        payload: Dict[str, Any] = {
            "engine": "renode-test",
            "profile": profile.name,
            "profile_path": str(profile.profile_path) if profile.profile_path else None,
            "schema_version": profile.schema_version,
            "calibrated_writes": max_writes,
            "calibrated_erases": total_erases,
            "setup_writes": setup_writes,
            "fault_points_tested": len(fault_points),
            "quick": bool(args.quick),
            "heuristic": heuristic_summary,
            "heuristic_config": (
                profile.fault_sweep.heuristic_config.to_dict()
                if profile.fault_sweep.heuristic_config is not None
                else HeuristicConfig().to_dict()
            ),
            "multi_fault": multi_fault_plan_summary(multi_fault_plan),
            "verdict": verdict,
            "summary": {
                "runtime_sweep": sweep_summary,
            },
            "expect": {
                "should_find_issues": profile.expect.should_find_issues,
            },
            "security_policy": {
                "anti_rollback": profile.security_policy.anti_rollback,
                "minimum_version": profile.security_policy.minimum_version,
                "toctou_protection": profile.security_policy.toctou_protection,
            },
            "runtime_sweep_results": sweep_results,
            "execution": {
                "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "campaign_command": " ".join(shlex.quote(a) for a in command_parts),
                "artifacts_dir": report_artifacts_dir,
                "workers": args.workers,
            },
            "git": git_metadata(repo_root),
        }
        dist = profile.fault_sweep.fault_distribution
        if dist is not None and dist.mode != "uniform":
            payload["fault_distribution"] = {
                "mode": dist.mode,
                "cluster_start": "0x{:X}".format(dist.cluster_start),
                "cluster_end": "0x{:X}".format(dist.cluster_end),
                "flip_probability_in_cluster": dist.flip_probability_in_cluster,
                "flip_probability_outside": dist.flip_probability_outside,
                "seed": dist.seed,
                "clustered_bit_corruption_points": clustered_bit_count if has_mixed_types else 0,
            }
        payload["contracts"] = {
            "state_probe": (
                {
                    "script": profile.state_probe.script,
                    "format": profile.state_probe.format,
                    "contract_version": profile.state_probe.contract_version,
                    "required_paths": profile.state_probe.required_paths,
                }
                if getattr(profile, "state_probe", None) is not None
                else None
            ),
            "invariant_providers": list(getattr(profile, "invariant_providers", []) or []),
        }
        calibration_source = "executed"
        if cal is None:
            if profile.fault_sweep.max_writes == "auto" and eval_mode == "state":
                calibration_source = "derived"
            else:
                calibration_source = "profile"
        payload["calibration"] = {
            "performed": cal is not None,
            "source": calibration_source,
            "writes": max_writes,
            "erases": total_erases,
            "stop_reason": cal.stop_reason if cal is not None else None,
            "emulated_s": cal.emulated_s if cal is not None else None,
            "elapsed_s": cal.elapsed_s if cal is not None else None,
            "pc": cal.pc if cal is not None else None,
        }
        if clean_trace_meta is not None:
            payload["clean_trace"] = clean_trace_meta

        if state_fuzz_results is not None:
            payload["state_fuzz_results"] = state_fuzz_results
            payload["summary"]["state_fuzz"] = state_fuzz_summary

        if multi_fault_plan_data is not None:
            payload["summary"]["multi_fault_plan"] = multi_fault_plan_data
        if multi_fault_results is not None:
            payload["multi_fault_results"] = multi_fault_results
        if multi_fault_summary is not None:
            payload["summary"]["multi_fault_runtime_sweep"] = multi_fault_summary

        if partial_staging_results is not None:
            payload["partial_staging_results"] = partial_staging_results
        if partial_staging_summary is not None:
            payload["summary"]["partial_staging"] = partial_staging_summary

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        # Print summary.
        print(json.dumps({
            "profile": profile.name,
            "verdict": verdict,
            "summary": payload["summary"],
        }, indent=2, sort_keys=True))

        # -------------------------------------------------------------------
        # Assertions
        # -------------------------------------------------------------------
        control_assert = (not args.no_control) and (not args.no_assert_control_boots)
        expected_control = profile.expect.control_outcome
        if control_assert and "control" in sweep_summary:
            ctrl = sweep_summary["control"]
            ctrl_effective = ctrl.get("effective_outcome", ctrl.get("boot_outcome"))
            if ctrl_effective != expected_control:
                print(
                    "ASSERTION FAILED: control point outcome '{}' != expected '{}'"
                    " (raw boot_outcome='{}')".format(
                        ctrl_effective, expected_control, ctrl.get("boot_outcome")
                    ),
                    file=sys.stderr,
                )
                return EXIT_ASSERTION_FAILURE
            if ctrl.get("issue_count", 0):
                print(
                    "ASSERTION FAILED: control checks reported {} issue(s)".format(
                        ctrl.get("issue_count", 0)
                    ),
                    file=sys.stderr,
                )
                return EXIT_ASSERTION_FAILURE

        if verdict.startswith("FAIL") and not args.no_assert_verdict:
            return EXIT_ASSERTION_FAILURE

        return 0

    except Exception as exc:
        print("INFRASTRUCTURE FAILURE: {}".format(exc), file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return EXIT_INFRA_FAILURE
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
