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
import copy
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import (
    MultiFaultPlan,
    multi_fault_plan_summary,
)
from partial_staging import (
    generate_truncation_points,
    parse_partial_staging_config,
    summarize_partial_staging,
)
from trace_utils import annotate_clean_trace
from audit_report import (
    compute_verdict,
    git_metadata,
    report_skip_reasons,
    summarize_runtime_sweep,
)
from result_checks import annotate_result_checks
from state_fuzz import (
    derive_default_metadata_base,
    extract_state_fuzz_result,
    generate_state_scenarios,
    resolve_metadata_model,
    summarize_state_campaign,
)
from fuzz_corpus import convert_corpus
from renode_runner import (
    CalibrationResult,
    _progress,
    ensure_tool,
    parse_robot_vars,
    run_calibration,
    run_single_point,
)
from fault_plan import CalibrationInputs, FaultPlan, build_fault_plan
from sweep import (
    MultiFaultPhaseResult,
    evaluate_config_checks,
    run_multi_component_sweep,
    run_multi_fault_phase,
    run_partial_staging_sweep,
    run_runtime_sweep,
    validate_runtime_fault_mode_compat,
)
from profile_loader import HeuristicConfig, PreBootWrite, ProfileConfig, load_profile, load_profile_raw

# Use absolute() not resolve() to preserve symlinks — resolve() follows
# them, breaking paths through /tmp symlinks on "External SSD" volumes.
REPO_ROOT = Path(__file__).absolute().parent.parent
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
        help="Disable sweep-only hash validation bypass; run full crypto in emulation (slower but hyper-realistic).",
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
    parser.add_argument(
        "--fuzz-crash-dir",
        default="",
        help=(
            "Directory of fuzzer crash inputs to auto-convert into regression "
            "profiles and audit alongside the main profile."
        ),
    )
    return parser.parse_args()


def _cleanup_generated_robot_files(robot_vars: List[str]) -> None:
    for prefix in ("PRE_BOOT_STATE_BIN:", "UPDATE_SEQUENCE_FILE:"):
        for entry in robot_vars:
            if not entry.startswith(prefix):
                continue
            path = entry.split(":", 1)[1]
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass


def _common_robot_vars(
    profile: ProfileConfig,
    repo_root: Path,
    *,
    evaluation_mode: str,
    stall_timeout: float,
    extra_robot_vars: List[str],
) -> List[str]:
    robot_vars = profile.robot_vars(repo_root) + list(extra_robot_vars)
    robot_vars.append("EVALUATION_MODE:{}".format(evaluation_mode))
    robot_vars.append("PROGRESS_STALL_TIMEOUT_S:{:.6f}".format(stall_timeout))
    robot_vars.append(
        "EXPECT_CONTROL_OUTCOME:{}".format(profile.expect.control_outcome)
    )
    return robot_vars


def run_state_fuzz_campaign(
    profile: ProfileConfig,
    *,
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    work_dir: Path,
    renode_remote_server_dir: str,
    evaluation_mode: str,
    stall_timeout: float,
    extra_robot_vars: List[str],
    keep_run_artifacts: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    default_base = derive_default_metadata_base(profile.memory.slots)
    model = resolve_metadata_model(profile.state_fuzzer.metadata_model, default_base)
    scenarios = generate_state_scenarios(
        model,
        iterations=profile.state_fuzzer.iterations,
        seed=profile.state_fuzzer.seed,
    )
    results: List[Dict[str, Any]] = []
    state_fuzz_dir = work_dir / "state_fuzz"
    state_fuzz_dir.mkdir(parents=True, exist_ok=True)

    _progress(
        "State fuzzer: {} scenarios from {} model".format(
            len(scenarios),
            "legacy" if isinstance(profile.state_fuzzer.metadata_model, str) else "structured",
        )
    )

    for scenario in scenarios:
        scenario_profile = copy.deepcopy(profile)
        scenario_profile.name = "{}_statefuzz_{:03d}".format(
            profile.name,
            int(scenario["index"]),
        )
        scenario_profile.pre_boot_state = list(profile.pre_boot_state) + [
            PreBootWrite(address=addr, u32=value)
            for addr, value in scenario["pre_boot_state"]
        ]
        robot_vars = _common_robot_vars(
            scenario_profile,
            repo_root,
            evaluation_mode=evaluation_mode,
            stall_timeout=stall_timeout,
            extra_robot_vars=extra_robot_vars,
        )
        try:
            data = run_single_point(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=scenario_profile,
                fault_at=0,
                robot_vars=robot_vars,
                work_dir=state_fuzz_dir,
                renode_remote_server_dir=renode_remote_server_dir,
                is_control=True,
                keep_run_artifacts=keep_run_artifacts,
            )
        finally:
            _cleanup_generated_robot_files(robot_vars)
        data["is_control"] = True
        annotate_result_checks([data], scenario_profile)
        results.append(
            extract_state_fuzz_result(
                scenario=scenario,
                result=data,
                expected_outcome=profile.expect.control_outcome,
            )
        )

    return (
        results,
        summarize_state_campaign(
            results,
            expected_outcome=profile.expect.control_outcome,
            metadata_model=profile.state_fuzzer.metadata_model,
            iterations=profile.state_fuzzer.iterations,
        ),
    )


def _build_fuzz_audit_command(
    script_path: Path,
    generated_profile_path: Path,
    output_path: Path,
    args: argparse.Namespace,
) -> List[str]:
    cmd = [
        sys.executable,
        str(script_path),
        "--profile",
        str(generated_profile_path),
        "--output",
        str(output_path),
        "--evaluation-mode",
        args.evaluation_mode,
        "--renode-test",
        args.renode_test,
        "--robot-suite",
        args.robot_suite,
        "--fault-step",
        str(args.fault_step),
        "--workers",
        str(args.workers),
        "--max-batch-points",
        str(args.max_batch_points),
        "--progress-stall-timeout-s",
        str(args.progress_stall_timeout_s),
        "--no-assert-verdict",
        "--no-assert-control-boots",
    ]
    if args.quick:
        cmd.append("--quick")
    if args.keep_run_artifacts:
        cmd.append("--keep-run-artifacts")
    if args.no_trace_replay:
        cmd.append("--no-trace-replay")
    if args.no_hash_bypass:
        cmd.append("--no-hash-bypass")
    if args.renode_remote_server_dir:
        cmd.extend(["--renode-remote-server-dir", args.renode_remote_server_dir])
    if args.fault_start is not None:
        cmd.extend(["--fault-start", str(args.fault_start)])
    if args.fault_end is not None:
        cmd.extend(["--fault-end", str(args.fault_end)])
    for robot_var in args.robot_var:
        cmd.extend(["--robot-var", robot_var])
    return cmd


def run_fuzz_crash_campaign(
    profile: ProfileConfig,
    *,
    repo_root: Path,
    args: argparse.Namespace,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if profile.profile_path is None:
        raise RuntimeError("--fuzz-crash-dir requires a profile loaded from disk")
    crash_dir = Path(args.fuzz_crash_dir)
    if not crash_dir.is_dir():
        raise RuntimeError("fuzz crash dir does not exist: {}".format(crash_dir))

    with tempfile.TemporaryDirectory(prefix="fuzz_crash_regressions_") as td:
        output_dir = Path(td)
        convert_summary = convert_corpus(
            crash_dir=crash_dir,
            base_profile=Path(profile.profile_path),
            output_dir=output_dir,
            skip_existing=False,
        )
        results: List[Dict[str, Any]] = []
        for generated in convert_summary["generated"]:
            generated_profile_path = Path(generated["profile_path"])
            audit_output_path = output_dir / "{}.json".format(generated_profile_path.stem)
            cmd = _build_fuzz_audit_command(
                Path(__file__),
                generated_profile_path,
                audit_output_path,
                args,
            )
            proc = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if audit_output_path.exists():
                audit_payload = json.loads(
                    audit_output_path.read_text(encoding="utf-8")
                )
            else:
                audit_payload = {}
            security_finding = bool(
                audit_payload.get("expect", {}).get("should_find_issues")
                and str(audit_payload.get("verdict", "")).startswith("PASS")
            )
            result_entry: Dict[str, Any] = {
                "crash_file": generated["crash_file"],
                "sha256": generated["sha256"],
                "generated_profile": generated_profile_path.name,
                "returncode": proc.returncode,
                "verdict": audit_payload.get("verdict"),
                "security_finding": security_finding,
            }
            if audit_payload:
                result_entry["summary"] = audit_payload.get("summary", {})
            if proc.returncode != 0 and not audit_payload:
                result_entry["error"] = proc.stderr.strip() or proc.stdout.strip()
            results.append(result_entry)

    summary = {
        "status": "completed",
        "crash_dir": str(crash_dir),
        "generated_profiles": int(convert_summary.get("generated_count", 0)),
        "security_findings": sum(1 for entry in results if entry.get("security_finding")),
        "results": len(results),
    }
    return results, summary



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
        extra_robot_vars = parse_robot_vars(args.robot_var)
        robot_vars = profile.robot_vars(repo_root) + extra_robot_vars
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
        total_otp_blows: int = 0
        setup_writes: int = 0
        # Determine whether erase-trace capture is needed during calibration.
        fault_types = profile.fault_sweep.fault_types
        include_erases = (
            "interrupted_erase" in fault_types
            or "multi_sector_atomicity" in fault_types
        )

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
                total_otp_blows = cal.total_otp_blows
                cal_parts = ["{} NVM writes".format(max_writes)]
                if include_erases:
                    cal_parts.append("{} page erases".format(total_erases))
                if total_i2c_transactions > 0:
                    cal_parts.append("{} I2C transactions".format(total_i2c_transactions))
                if total_otp_blows > 0:
                    cal_parts.append("{} OTP blows".format(total_otp_blows))
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
        plan = build_fault_plan(
            profile=profile,
            calibration=CalibrationInputs(
                max_writes=max_writes,
                total_erases=total_erases,
                total_i2c_transactions=total_i2c_transactions,
                total_otp_blows=total_otp_blows,
                setup_writes=setup_writes,
                trace_file=trace_file,
            ),
            quick=args.quick,
            fault_step=args.fault_step,
            fault_start=args.fault_start,
            fault_end=args.fault_end,
        )
        fault_points = plan.fault_points
        fault_types_list = plan.fault_types_list
        heuristic_summary = plan.heuristic_summary
        clustered_bit_count = plan.clustered_bit_count
        multi_fault_plan: Optional[MultiFaultPlan] = None

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
            no_hash_bypass=args.no_hash_bypass,
        )

        sweep_wall_s = _time_mod.time() - sweep_wall_t0
        print(
            "Sweep completed: {} points in {:.1f}s ({:.0f}ms/point avg)".format(
                len(fault_points), sweep_wall_s,
                (sweep_wall_s * 1000 / len(fault_points)) if fault_points else 0,
            ),
            file=sys.stderr,
        )

        flash_base = 0
        if profile.memory.slots:
            flash_base = min(slot.base for slot in profile.memory.slots.values())
        clean_trace_meta = annotate_clean_trace(
            sweep_results, trace_file, erase_trace_file, flash_base,
        )

        annotate_result_checks(sweep_results, profile)
        sweep_summary = summarize_runtime_sweep(
            sweep_results, total_writes=max_writes, profile=profile
        )
        sweep_summary["wall_time_s"] = round(sweep_wall_s, 1)

        report_skip_reasons(sweep_summary, _progress)

        # -------------------------------------------------------------------
        # Multi-fault plan (opt-in)
        # -------------------------------------------------------------------
        mf_phase = run_multi_fault_phase(
            profile=profile,
            sweep_results=sweep_results,
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            robot_vars=robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=args.renode_remote_server_dir,
            num_workers=args.workers,
            max_batch_points=args.max_batch_points,
            max_writes=max_writes,
            no_hash_bypass=args.no_hash_bypass,
            explain_only=args.explain_multi_fault_plan,
            keep_run_artifacts=args.keep_run_artifacts,
        )
        multi_fault_plan: Optional[MultiFaultPlan] = mf_phase.plan
        multi_fault_plan_data = mf_phase.plan_data
        multi_fault_results = mf_phase.results
        multi_fault_summary = mf_phase.summary

        # -------------------------------------------------------------------
        # State fuzzer (opt-in)
        # -------------------------------------------------------------------
        state_fuzz_results: Optional[List[Dict[str, Any]]] = None
        state_fuzz_summary: Optional[Dict[str, Any]] = None

        if profile.state_fuzzer.enabled:
            state_fuzz_results, state_fuzz_summary = run_state_fuzz_campaign(
                profile,
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                work_dir=work_dir,
                renode_remote_server_dir=args.renode_remote_server_dir,
                evaluation_mode=eval_mode,
                stall_timeout=stall_timeout,
                extra_robot_vars=extra_robot_vars,
                keep_run_artifacts=args.keep_run_artifacts,
            )

        # -------------------------------------------------------------------
        # Partial staging sweep (opt-in)
        # -------------------------------------------------------------------
        partial_staging_results: Optional[List[Dict[str, Any]]] = None
        partial_staging_summary: Optional[Dict[str, Any]] = None
        fuzz_crash_results: Optional[List[Dict[str, Any]]] = None
        fuzz_crash_summary: Optional[Dict[str, Any]] = None

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
        # Fuzzer crash regression campaign (opt-in)
        # -------------------------------------------------------------------
        if args.fuzz_crash_dir:
            fuzz_crash_results, fuzz_crash_summary = run_fuzz_crash_campaign(
                profile,
                repo_root=repo_root,
                args=args,
            )

        # -------------------------------------------------------------------
        # Verdict
        # -------------------------------------------------------------------
        verdict = compute_verdict(
            sweep_summary,
            profile.expect,
            multi_fault_summary=multi_fault_summary,
            partial_staging_summary=partial_staging_summary,
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
                "clustered_bit_corruption_points": clustered_bit_count,
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
        if fuzz_crash_results is not None:
            payload["fuzz_crash_results"] = fuzz_crash_results
        if fuzz_crash_summary is not None:
            payload["summary"]["fuzz_crash"] = fuzz_crash_summary

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
