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
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import (
    AnnotatedSequence,
    MultiFaultPlan,
    apply_clustered_distribution,
    classify_multi_component_outcome,
    decode_multi_fault_sequence,
    encode_multi_fault_sequence,
    generate_multi_fault_sequences,
    multi_fault_plan_summary,
)
from partial_staging import (
    PartialStagingConfig,
    PartialStagingResult,
    TruncationPoint,
    classify_partial_staging_outcome,
    generate_truncation_points,
    parse_partial_staging_config,
    summarize_partial_staging,
    write_partial_image_to_temp,
)
from fault_classification import (
    InterestingPoint,
    _MULTI_BOOT_SUCCESS_STATUSES,
    _effective_boot_result,
    _interesting_multi_fault_points,
    result_is_brick,
)
from fault_types import (
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
)
from trace_utils import (
    annotate_fault_windows,
    build_clean_operation_trace,
    load_clean_erase_trace,
    load_clean_write_trace,
)
from audit_report import (
    categorize_failure,
    check_bootloader_integrity,
    compute_region_breakdown,
    enrich_results_with_fault_regions,
    git_metadata,
    summarize_runtime_sweep,
)
from result_checks import (
    annotate_result_checks,
    check_write_order_constraints,
)
from profile_loader import HeuristicConfig, ProfileConfig, load_profile

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RENODE_TEST = os.environ.get("RENODE_TEST", "renode-test")
DEFAULT_ROBOT_SUITE = "tests/ota_fault_point.robot"
EXIT_ASSERTION_FAILURE = 1
EXIT_INFRA_FAILURE = 2
DOCKER_RENODE_PREFIX = "docker://"
CALIBRATION_INCOMPLETE_PREFIXES = (
    "wall_timeout(",
    "no_progress_stall(",
    "no_boot_stall(",
    "op_trace_limit",
)


def _progress(message: str) -> None:
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    print("[audit {}] {}".format(stamp, message), file=sys.stderr, flush=True)


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


def ensure_tool(path: str) -> str:
    if path.startswith(DOCKER_RENODE_PREFIX):
        image = path[len(DOCKER_RENODE_PREFIX):].strip()
        if not image:
            raise ValueError(
                "docker renode-test spec must use docker://IMAGE, got {!r}".format(path)
            )
        if shutil.which("docker") is None:
            raise FileNotFoundError(
                "docker is required for dockerized renode-test spec '{}'".format(path)
            )
        return path
    if os.path.isabs(path):
        if not os.path.exists(path):
            raise FileNotFoundError("renode-test not found at {}".format(path))
        return path
    resolved = shutil.which(path)
    if resolved is None:
        raise FileNotFoundError(
            "renode-test executable '{}' not found in PATH".format(path)
        )
    return resolved


def prepare_renode_command(
    renode_test: str,
    base_cmd: List[str],
    cwd: Path,
    env: Dict[str, str],
) -> List[str]:
    """Expand docker://IMAGE renode-test specs into a concrete docker run command."""
    if not renode_test.startswith(DOCKER_RENODE_PREFIX):
        return base_cmd

    image = renode_test[len(DOCKER_RENODE_PREFIX):].strip()
    platform = os.environ.get("OTA_RENODE_DOCKER_PLATFORM", "linux/amd64")
    mount_dirs: Dict[str, None] = {}

    def add_mount(raw_path: str) -> None:
        if not raw_path or not os.path.isabs(raw_path):
            return
        p = Path(raw_path)
        target = p if p.is_dir() else p.parent
        mount_dirs[str(target)] = None
        try:
            resolved = str(target.resolve())
        except FileNotFoundError:
            resolved = None
        if resolved and resolved != str(target):
            mount_dirs[resolved] = None

    def normalize_container_path(raw_path: str) -> str:
        if not raw_path or not os.path.isabs(raw_path):
            return raw_path
        p = Path(raw_path)
        target = p if p.is_dir() else p.parent
        try:
            resolved_target = target.resolve()
        except FileNotFoundError:
            return raw_path
        if p.is_dir():
            return str(resolved_target)
        return str(resolved_target / p.name)

    add_mount(str(cwd))
    forwarded_env: List[Tuple[str, str]] = []
    for key in ("DOTNET_BUNDLE_EXTRACT_BASE_DIR", "TMPDIR", "TMP", "TEMP"):
        value = env.get(key)
        if not value:
            continue
        if os.path.isabs(value):
            add_mount(value)
            value = normalize_container_path(value)
        forwarded_env.append((key, value))

    container_args: List[str] = []
    for arg in base_cmd[1:]:
        if os.path.isabs(arg):
            add_mount(arg)
            container_args.append(normalize_container_path(arg))
            continue
        key, sep, value = arg.partition(":")
        if sep and value:
            # Handle comma-separated paths (e.g. EXTRA_PERIPHERALS:/a.cs,/b.cs).
            sub_values = value.split(",") if "," in value else [value]
            any_abs = False
            normalized_subs = []
            for sv in sub_values:
                if os.path.isabs(sv):
                    add_mount(sv)
                    normalized_subs.append(normalize_container_path(sv))
                    any_abs = True
                else:
                    normalized_subs.append(sv)
            if any_abs:
                container_args.append(
                    "{}:{}".format(key, ",".join(normalized_subs))
                )
                continue
        container_args.append(arg)

    container_config_path = "/tmp/renode.config"
    if "--renode-config" in container_args:
        idx = container_args.index("--renode-config")
        if idx + 1 < len(container_args):
            container_args[idx + 1] = container_config_path

    cmd: List[str] = [
        "docker",
        "run",
        "--rm",
        "--platform",
        platform,
    ]
    for mount_dir in sorted(mount_dirs.keys()):
        cmd.extend(["-v", "{}:{}".format(mount_dir, mount_dir)])
    for key, value in forwarded_env:
        cmd.extend(["-e", "{}={}".format(key, value)])
    cmd.extend(
        [
            "-w",
            str(cwd),
            image,
            "renode-test",
        ]
    )
    cmd.extend(container_args)
    return cmd


def parse_robot_vars(raw_vars: List[str]) -> List[str]:
    parsed: List[str] = []
    for rv in raw_vars:
        key, sep, value = rv.partition(":")
        if not sep or not key or not value:
            raise ValueError("--robot-var must use KEY:VALUE, got '{}'".format(rv))
        parsed.append("{}:{}".format(key, value))
    return parsed


def merge_robot_vars(base: List[str], overlay: List[str]) -> List[str]:
    """Merge two robot var lists, with *overlay* winning on key conflicts.

    Each entry is ``KEY:VALUE``.  Base vars provide campaign-level defaults
    (CLI overrides, stall timeouts, etc.) while overlay vars are the
    component-specific values that should take precedence.
    """
    merged: Dict[str, str] = {}
    for var in base:
        key, _sep, value = var.partition(":")
        if key:
            merged[key] = value
    for var in overlay:
        key, _sep, value = var.partition(":")
        if key:
            merged[key] = value
    return ["{}:{}".format(k, v) for k, v in merged.items()]


def parse_renode_point_timeout(env: Dict[str, str]) -> Optional[float]:
    """Read per-run renode-test timeout from environment.

    OTA_RENODE_POINT_TIMEOUT_S:
      - >0 seconds: enforce timeout
      - <=0: disable timeout
    """
    raw = env.get("OTA_RENODE_POINT_TIMEOUT_S", "300")
    try:
        value = float(raw)
    except ValueError:
        raise RuntimeError(
            "Invalid OTA_RENODE_POINT_TIMEOUT_S='{}' (must be numeric)".format(raw)
        )
    if value <= 0:
        return None
    return value


def prepare_run_environment(
    base_env: Dict[str, str],
    bundle_dir: Path,
    temp_root: Path,
) -> Dict[str, str]:
    """Prepare a subprocess environment with isolated temp directories."""
    env = dict(base_env)
    env.setdefault("DOTNET_BUNDLE_EXTRACT_BASE_DIR", str(bundle_dir))
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_root_str = str(temp_root)
    env["TMPDIR"] = temp_root_str
    env["TMP"] = temp_root_str
    env["TEMP"] = temp_root_str
    return env


def quick_subset(points: List[int]) -> List[int]:
    if len(points) <= 3:
        return points
    mid = len(points) // 2
    return sorted(set([points[0], points[mid], points[-1]]))


def run_single_point(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    fault_at: int,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    is_control: bool = False,
    calibration: bool = False,
    keep_run_artifacts: bool = False,
) -> Dict[str, Any]:
    """Run a single fault point (or calibration) via renode-test."""
    label = "calibration" if calibration else ("control" if is_control else "fault_{}".format(fault_at))
    point_dir = work_dir / "{}_{}".format(profile.name, label)
    point_dir.mkdir(parents=True, exist_ok=True)

    result_file = point_dir / "result.json"
    rf_results = point_dir / "robot"
    temp_root = point_dir / ".tmp"
    bundle_dir = work_dir / ".dotnet_bundle"
    renode_config = work_dir / "renode.config"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    point_fault_at = -1 if is_control else fault_at

    cmd = [
        renode_test,
        "--renode-config", str(renode_config),
        robot_suite,
        "--results-dir", str(rf_results),
        "--variable", "FAULT_AT:{}".format(point_fault_at),
        "--variable", "RESULT_FILE:{}".format(result_file),
        "--variable", "CALIBRATION_MODE:{}".format("true" if calibration else "false"),
    ]
    if renode_remote_server_dir:
        cmd.extend(["--robot-framework-remote-server-full-directory", renode_remote_server_dir])

    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)
    cmd = prepare_renode_command(renode_test, cmd, repo_root, env)
    timeout_s = parse_renode_point_timeout(env)
    if calibration and timeout_s is not None:
        timeout_s = max(timeout_s, 900.0)

    try:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            raise RuntimeError(
                "renode-test timed out for {} fault_at={} after {}s\nSTDOUT:\n{}\nSTDERR:\n{}\n"
                "Adjust with OTA_RENODE_POINT_TIMEOUT_S (seconds; <=0 disables timeout).".format(
                    label, fault_at, timeout_s, out, err
                )
            )

        if proc.returncode != 0:
            raise RuntimeError(
                "renode-test failed for {} fault_at={}\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    label, fault_at, proc.stdout, proc.stderr,
                )
            )

        if not result_file.exists():
            raise RuntimeError("Run did not produce {}".format(result_file))

        return json.loads(result_file.read_text(encoding="utf-8"))
    finally:
        if not keep_run_artifacts and rf_results.exists():
            shutil.rmtree(rf_results, ignore_errors=True)
        if not keep_run_artifacts and temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)


@dataclasses.dataclass
class CalibrationResult:
    total_writes: int
    total_erases: int
    trace_file: Optional[str]
    erase_trace_file: Optional[str]
    trace_file_bin: Optional[str]
    erase_trace_file_bin: Optional[str]
    calibration_exec_hash: Optional[str] = None
    stop_reason: Optional[str] = None
    emulated_s: Optional[float] = None
    elapsed_s: Optional[float] = None
    pc: Optional[str] = None
    setup_writes: int = 0
    total_i2c_transactions: int = 0


def calibration_completed(
    stop_reason: Optional[str],
    expected_control_outcome: str = "success",
) -> bool:
    """Return whether a calibration stop reason represents a complete pass."""
    if not stop_reason:
        return False
    if stop_reason == "budget":
        return False
    if any(stop_reason.startswith(prefix) for prefix in CALIBRATION_INCOMPLETE_PREFIXES):
        return False
    if stop_reason in {"no_boot_no_writes", "no_writes_brick", "vtor_captured_hardfault"}:
        return expected_control_outcome == "no_boot"
    return True


def run_calibration(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    keep_run_artifacts: bool = False,
) -> CalibrationResult:
    """Run calibration to discover total NVM writes and erases during a clean update."""
    data = run_single_point(
        repo_root=repo_root,
        renode_test=renode_test,
        robot_suite=robot_suite,
        profile=profile,
        fault_at=0,  # ignored in calibration
        robot_vars=robot_vars,
        work_dir=work_dir,
        renode_remote_server_dir=renode_remote_server_dir,
        calibration=True,
        keep_run_artifacts=keep_run_artifacts,
    )
    total_writes = int(data.get("total_writes", 0))
    total_erases = int(data.get("total_erases", 0))
    stop_reason = data.get("calibration_stop_reason")
    if not calibration_completed(stop_reason, profile.expect.control_outcome):
        raise RuntimeError(
            "Calibration did not complete cleanly (reason={!r}, writes={}, erases={}). "
            "Refusing to run a partial sweep.".format(
                stop_reason, total_writes, total_erases
            )
        )
    if total_writes <= 0 and total_erases <= 0:
        if profile.expect.control_outcome == "no_boot":
            print(
                "Calibration found 0 NVM operations (expected no_boot baseline).",
                file=sys.stderr,
            )
        else:
            print(
                "WARNING: Calibration found 0 NVM operations — bootloader is stateless "
                "(e.g., XIP bootloader). No fault points to test.".format(),
                file=sys.stderr,
            )
    cap = profile.fault_sweep.max_writes_cap
    if total_writes > cap:
        print(
            "WARNING: Calibration found {} writes, capping to {}".format(
                total_writes, cap
            ),
            file=sys.stderr,
        )
        total_writes = cap
    return CalibrationResult(
        total_writes=total_writes,
        total_erases=total_erases,
        trace_file=data.get("trace_file"),
        erase_trace_file=data.get("erase_trace_file"),
        trace_file_bin=data.get("trace_file_bin"),
        erase_trace_file_bin=data.get("erase_trace_file_bin"),
        calibration_exec_hash=data.get("calibration_exec_hash"),
        stop_reason=stop_reason,
        emulated_s=data.get("calibration_emulated_s"),
        elapsed_s=data.get("calibration_elapsed_s"),
        pc=data.get("calibration_pc"),
        setup_writes=int(data.get("setup_writes", 0)),
        total_i2c_transactions=int(data.get("total_i2c_transactions", 0)),
    )


def run_batch(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    trace_file: Optional[str] = None,
    erase_trace_file: Optional[str] = None,
    trace_file_bin: Optional[str] = None,
    erase_trace_file_bin: Optional[str] = None,
    fault_types_list: Optional[List[str]] = None,
    keep_run_artifacts: bool = False,
) -> List[Dict[str, Any]]:
    """Run multiple fault points in a single Renode session (batch mode).

    fault_types_list: parallel list of fault types per fault point.
    """
    batch_dir = work_dir / "{}_batch".format(profile.name)
    batch_dir.mkdir(parents=True, exist_ok=True)

    result_file = batch_dir / "result.json"
    rf_results = batch_dir / "robot"
    temp_root = batch_dir / ".tmp"
    bundle_dir = work_dir / ".dotnet_bundle"
    renode_config = work_dir / "renode.config"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    csv = ",".join(str(fp) for fp in fault_points)
    ft_csv = ",".join(fault_types_list) if fault_types_list else ""

    # Determine fault_types mode for the .resc.
    erase_types = {'e', 'a'}
    write_types = {'w', 'b', 's', 'd', 'l', 'r', 't', 'k'}

    def _ft_base(ft: str) -> str:
        """Extract base fault type code (first character before any colon)."""
        return ft.split(":")[0] if ":" in ft else ft

    has_erase = bool(fault_types_list and any(_ft_base(ft) in erase_types for ft in fault_types_list))
    has_write = bool(fault_types_list and any(_ft_base(ft) in write_types for ft in fault_types_list))
    if has_erase and has_write:
        fault_types_mode = "both"
    elif has_erase:
        fault_types_mode = "erase"
    else:
        fault_types_mode = "write"

    # Scale the Robot Framework per-suite timeout to the batch size. Large
    # state-mode batches can legitimately exceed the default 2-minute timeout,
    # which otherwise triggers expensive fallback splits even when the batch is
    # healthy.
    robot_test_timeout_s = max(120, 120 + len(fault_points) * 4)
    robot_test_timeout_m = max(2, (robot_test_timeout_s + 59) // 60)

    cmd = [
        renode_test,
        "--renode-config", str(renode_config),
        robot_suite,
        "--results-dir", str(rf_results),
        "--variable", "FAULT_POINTS_CSV:{}".format(csv),
        "--variable", "FAULT_AT:0",
        "--variable", "RESULT_FILE:{}".format(result_file),
        "--variable", "CALIBRATION_MODE:false",
        "--variable", "TRACE_FILE:{}".format(trace_file or ""),
        "--variable", "ERASE_TRACE_FILE:{}".format(erase_trace_file or ""),
        "--variable", "TRACE_FILE_BIN:{}".format(trace_file_bin or ""),
        "--variable", "ERASE_TRACE_FILE_BIN:{}".format(erase_trace_file_bin or ""),
        "--variable", "FAULT_TYPES:{}".format(fault_types_mode),
        "--variable", "FAULT_TYPE_CSV:{}".format(ft_csv),
        "--variable", "TEST_TIMEOUT:{} minutes".format(robot_test_timeout_m),
    ]
    if renode_remote_server_dir:
        cmd.extend(["--robot-framework-remote-server-full-directory", renode_remote_server_dir])

    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)
    cmd = prepare_renode_command(renode_test, cmd, repo_root, env)
    per_point_timeout = parse_renode_point_timeout(env)
    # Scale batch timeout by number of fault points.  Each point typically
    # takes 0.5-3s on CI runners; add 120s startup overhead.
    if per_point_timeout is not None:
        timeout_s: Optional[float] = max(
            per_point_timeout,
            120.0 + len(fault_points) * 4.0,
        )
    else:
        timeout_s = None

    try:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            raise RuntimeError(
                "renode-test batch timed out after {}s ({} points)\nSTDOUT:\n{}\nSTDERR:\n{}\n"
                "Adjust with OTA_RENODE_POINT_TIMEOUT_S (seconds; <=0 disables timeout).".format(
                    timeout_s, len(fault_points), out, err
                )
            )

        if proc.returncode != 0:
            raise RuntimeError(
                "renode-test batch failed\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    proc.stdout, proc.stderr,
                )
            )

        if not result_file.exists():
            raise RuntimeError("Batch run did not produce {}".format(result_file))

        data = json.loads(result_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return [data]
    finally:
        if not keep_run_artifacts and rf_results.exists():
            shutil.rmtree(rf_results, ignore_errors=True)
        if not keep_run_artifacts and temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)


def _split_batch_plan(
    fault_points: List[int],
    fault_types_list: Optional[List[str]],
    max_batch_points: int,
) -> List[Tuple[List[int], Optional[List[str]]]]:
    """Split fault points/types into fixed-size batches."""
    if max_batch_points <= 0 or len(fault_points) <= max_batch_points:
        return [(fault_points, fault_types_list)]

    plan: List[Tuple[List[int], Optional[List[str]]]] = []
    for i in range(0, len(fault_points), max_batch_points):
        chunk_points = fault_points[i:i + max_batch_points]
        chunk_types = (
            fault_types_list[i:i + max_batch_points]
            if fault_types_list
            else None
        )
        plan.append((chunk_points, chunk_types))
    return plan


def _run_batch_with_fallback(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    trace_file: Optional[str] = None,
    erase_trace_file: Optional[str] = None,
    trace_file_bin: Optional[str] = None,
    erase_trace_file_bin: Optional[str] = None,
    fault_types_list: Optional[List[str]] = None,
    keep_run_artifacts: bool = False,
) -> List[Dict[str, Any]]:
    """Run one batch; on failure recursively retry smaller sub-batches."""
    try:
        results = run_batch(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_points=fault_points,
            robot_vars=robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            trace_file=trace_file,
            erase_trace_file=erase_trace_file,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=erase_trace_file_bin,
            fault_types_list=fault_types_list,
            keep_run_artifacts=keep_run_artifacts,
        )
        if len(fault_points) == 1:
            _progress("Fallback point {} complete.".format(fault_points[0]))
        return results
    except Exception as exc:
        if len(fault_points) <= 1:
            raise
        mid = max(1, len(fault_points) // 2)
        left_points = fault_points[:mid]
        right_points = fault_points[mid:]
        left_types = fault_types_list[:mid] if fault_types_list else None
        right_types = fault_types_list[mid:] if fault_types_list else None
        _progress(
            "Batch run failed; retrying smaller sub-batches ({} -> {} + {}). {}".format(
                len(fault_points), len(left_points), len(right_points), exc
            )
        )
        results: List[Dict[str, Any]] = []
        fallback_root = work_dir / "batch_fallback"
        fallback_root.mkdir(parents=True, exist_ok=True)
        if left_points:
            results.extend(
                _run_batch_with_fallback(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    fault_points=left_points,
                    robot_vars=robot_vars,
                    work_dir=fallback_root / "chunk_{:07d}_{:07d}".format(
                        left_points[0], left_points[-1]
                    ),
                    renode_remote_server_dir=renode_remote_server_dir,
                    trace_file=trace_file,
                    erase_trace_file=erase_trace_file,
                    trace_file_bin=trace_file_bin,
                    erase_trace_file_bin=erase_trace_file_bin,
                    fault_types_list=left_types,
                    keep_run_artifacts=keep_run_artifacts,
                )
            )
        if right_points:
            results.extend(
                _run_batch_with_fallback(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    fault_points=right_points,
                    robot_vars=robot_vars,
                    work_dir=fallback_root / "chunk_{:07d}_{:07d}".format(
                        right_points[0], right_points[-1]
                    ),
                    renode_remote_server_dir=renode_remote_server_dir,
                    trace_file=trace_file,
                    erase_trace_file=erase_trace_file,
                    trace_file_bin=trace_file_bin,
                    erase_trace_file_bin=erase_trace_file_bin,
                    fault_types_list=right_types,
                    keep_run_artifacts=keep_run_artifacts,
                )
            )
        return results


def _run_batches_chunked(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    fault_points: List[int],
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
    trace_file: Optional[str] = None,
    erase_trace_file: Optional[str] = None,
    trace_file_bin: Optional[str] = None,
    erase_trace_file_bin: Optional[str] = None,
    fault_types_list: Optional[List[str]] = None,
    max_batch_points: int = 0,
    keep_run_artifacts: bool = False,
    progress_label: str = "",
) -> List[Dict[str, Any]]:
    """Run one or more fault batches with optional fixed-size chunking."""
    plan = _split_batch_plan(
        fault_points=fault_points,
        fault_types_list=fault_types_list,
        max_batch_points=max_batch_points,
    )

    label_prefix = "{} ".format(progress_label) if progress_label else ""

    if len(plan) > 1:
        _progress(
            "{}sub-batching {} points into {} chunks (max {} points/chunk).".format(
                label_prefix, len(fault_points), len(plan), max_batch_points
            )
        )

    combined: List[Dict[str, Any]] = []
    for i, (chunk_points, chunk_types) in enumerate(plan):
        chunk_dir = work_dir / "chunk_{:04d}".format(i)
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_start = time.monotonic()
        span = "{}..{}".format(chunk_points[0], chunk_points[-1]) if chunk_points else "empty"
        _progress(
            "{}chunk {}/{} start: {} points (faults {}).".format(
                label_prefix, i + 1, len(plan), len(chunk_points), span
            )
        )
        chunk_results = _run_batch_with_fallback(
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            profile=profile,
            fault_points=chunk_points,
            robot_vars=robot_vars,
            work_dir=chunk_dir,
            renode_remote_server_dir=renode_remote_server_dir,
            trace_file=trace_file,
            erase_trace_file=erase_trace_file,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=erase_trace_file_bin,
            fault_types_list=chunk_types,
            keep_run_artifacts=keep_run_artifacts,
        )
        combined.extend(chunk_results)
        _progress(
            "{}chunk {}/{} complete: {} results in {:.1f}s.".format(
                label_prefix,
                i + 1,
                len(plan),
                len(chunk_results),
                time.monotonic() - chunk_start,
            )
        )
    return combined


def normalize_classic_result(data: Dict[str, Any], fault_at: int) -> Dict[str, Any]:
    """Normalize a classic .resc result to the runtime sweep format."""
    nvm = data.get("nvm_state", {})
    return {
        "fault_at": fault_at,
        "fault_requested": fault_at,
        "fault_injected": nvm.get("faulted", False),
        "fault_address": nvm.get("fault_address", "0x00000000"),
        "boot_outcome": data.get("boot_outcome", "hard_fault"),
        "boot_slot": data.get("boot_slot"),
        "actual_writes": nvm.get("write_index", 0),
        "signals": {
            "evaluation_mode": nvm.get("evaluation_mode", "state"),
            "chosen_slot": nvm.get("chosen_slot"),
            "requested_slot": nvm.get("requested_slot"),
            "replica0_valid": nvm.get("replica0_valid"),
            "replica1_valid": nvm.get("replica1_valid"),
        },
    }



# annotate_result_checks, check_write_order_constraints imported from result_checks.py.


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
    # Full execute-mode without trace replay is memory-heavy in long single
    # Renode sessions. Enforce safe sub-batching by default.
    if (
        max_batch_points <= 0
        and evaluation_mode == "execute"
        and not trace_file
        and not trace_file_bin
        and fault_points
    ):
        max_batch_points = 32
        print(
            "Execute mode without trace replay: enforcing sub-batches of 32 points.",
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
                    robot_vars=robot_vars,
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
            robot_vars=robot_vars,
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
            robot_vars=robot_vars,
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



# enrich_results_with_fault_regions, compute_region_breakdown,
# check_bootloader_integrity, categorize_failure, summarize_runtime_sweep,
# and git_metadata are imported from audit_report.py.


def validate_runtime_fault_mode_compat(profile: "ProfileConfig", eval_mode: str) -> None:
    """Fail fast on profile/mode combinations the runtime runner cannot support."""
    if str(getattr(profile.fault_sweep, "mode", "runtime")) != "runtime":
        return
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

        if no_hash_bypass:
            comp_robot_vars = [
                v for v in comp_robot_vars if not v.startswith("HASH_BYPASS_SYMBOLS:")
            ]

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
