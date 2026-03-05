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
import csv
import dataclasses
import datetime as dt
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import FaultResult
from profile_loader import ProfileConfig, load_profile

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
    parser.add_argument("--renode-test", default=DEFAULT_RENODE_TEST)
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
    return parser.parse_args()


def ensure_tool(path: str) -> str:
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


def parse_robot_vars(raw_vars: List[str]) -> List[str]:
    parsed: List[str] = []
    for rv in raw_vars:
        key, sep, value = rv.partition(":")
        if not sep or not key or not value:
            raise ValueError("--robot-var must use KEY:VALUE, got '{}'".format(rv))
        parsed.append("{}:{}".format(key, value))
    return parsed


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
) -> Dict[str, Any]:
    """Run a single fault point (or calibration) via renode-test."""
    label = "calibration" if calibration else ("control" if is_control else "fault_{}".format(fault_at))
    point_dir = work_dir / "{}_{}".format(profile.name, label)
    point_dir.mkdir(parents=True, exist_ok=True)

    result_file = point_dir / "result.json"
    rf_results = point_dir / "robot"
    bundle_dir = work_dir / ".dotnet_bundle"
    renode_config = work_dir / "renode.config"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        renode_test,
        "--renode-config", str(renode_config),
        robot_suite,
        "--results-dir", str(rf_results),
        "--variable", "FAULT_AT:{}".format(fault_at),
        "--variable", "RESULT_FILE:{}".format(result_file),
        "--variable", "CALIBRATION_MODE:{}".format("true" if calibration else "false"),
    ]
    if renode_remote_server_dir:
        cmd.extend(["--robot-framework-remote-server-full-directory", renode_remote_server_dir])

    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    env = os.environ.copy()
    env.setdefault("DOTNET_BUNDLE_EXTRACT_BASE_DIR", str(bundle_dir))
    timeout_s = parse_renode_point_timeout(env)
    if calibration and timeout_s is not None:
        timeout_s = max(timeout_s, 900.0)

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


def run_calibration(
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    profile: ProfileConfig,
    robot_vars: List[str],
    work_dir: Path,
    renode_remote_server_dir: str,
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
    )
    total_writes = int(data.get("total_writes", 0))
    total_erases = int(data.get("total_erases", 0))
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
        stop_reason=data.get("calibration_stop_reason"),
        emulated_s=data.get("calibration_emulated_s"),
        elapsed_s=data.get("calibration_elapsed_s"),
        pc=data.get("calibration_pc"),
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
) -> List[Dict[str, Any]]:
    """Run multiple fault points in a single Renode session (batch mode).

    fault_types_list: parallel list of fault types per fault point.
    """
    batch_dir = work_dir / "{}_batch".format(profile.name)
    batch_dir.mkdir(parents=True, exist_ok=True)

    result_file = batch_dir / "result.json"
    rf_results = batch_dir / "robot"
    bundle_dir = work_dir / ".dotnet_bundle"
    renode_config = work_dir / "renode.config"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    csv = ",".join(str(fp) for fp in fault_points)
    ft_csv = ",".join(fault_types_list) if fault_types_list else ""

    # Determine fault_types mode for the .resc.
    erase_types = {'e', 'a'}
    write_types = {'w', 'b', 's', 'd', 'l', 'r', 't'}
    has_erase = bool(fault_types_list and any(ft in erase_types for ft in fault_types_list))
    has_write = bool(fault_types_list and any(ft in write_types for ft in fault_types_list))
    if has_erase and has_write:
        fault_types_mode = "both"
    elif has_erase:
        fault_types_mode = "erase"
    else:
        fault_types_mode = "write"

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
    ]
    if renode_remote_server_dir:
        cmd.extend(["--robot-framework-remote-server-full-directory", renode_remote_server_dir])

    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    env = os.environ.copy()
    env.setdefault("DOTNET_BUNDLE_EXTRACT_BASE_DIR", str(bundle_dir))
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
) -> List[Dict[str, Any]]:
    """Run one batch; on failure retry each point in separate Renode sessions."""
    try:
        return run_batch(
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
        )
    except Exception as exc:
        print(
            "Batch run failed; retrying per-point Renode sessions. {}".format(exc),
            file=sys.stderr,
        )
        results: List[Dict[str, Any]] = []
        fallback_root = work_dir / "batch_fallback"
        fallback_root.mkdir(parents=True, exist_ok=True)
        for idx, fp in enumerate(fault_points):
            point_fault_types: Optional[List[str]] = None
            if fault_types_list and idx < len(fault_types_list):
                point_fault_types = [fault_types_list[idx]]
            point_results = run_batch(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=profile,
                fault_points=[fp],
                robot_vars=robot_vars,
                work_dir=fallback_root / "fp_{:07d}".format(fp),
                renode_remote_server_dir=renode_remote_server_dir,
                trace_file=trace_file,
                erase_trace_file=erase_trace_file,
                trace_file_bin=trace_file_bin,
                erase_trace_file_bin=erase_trace_file_bin,
                fault_types_list=point_fault_types,
            )
            results.extend(point_results)
            print(
                "Fallback point {} complete ({}/{})".format(
                    fp, idx + 1, len(fault_points)
                ),
                file=sys.stderr,
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
) -> List[Dict[str, Any]]:
    """Run one or more fault batches with optional fixed-size chunking."""
    plan = _split_batch_plan(
        fault_points=fault_points,
        fault_types_list=fault_types_list,
        max_batch_points=max_batch_points,
    )

    if len(plan) > 1:
        print(
            "Sub-batching {} points into {} chunks (max {} points/chunk).".format(
                len(fault_points), len(plan), max_batch_points
            ),
            file=sys.stderr,
        )

    combined: List[Dict[str, Any]] = []
    for i, (chunk_points, chunk_types) in enumerate(plan):
        chunk_dir = work_dir / "chunk_{:04d}".format(i)
        chunk_dir.mkdir(parents=True, exist_ok=True)
        combined.extend(
            _run_batch_with_fallback(
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
) -> List[Dict[str, Any]]:
    """Worker function for parallel batch execution.

    Runs in a subprocess via ProcessPoolExecutor.  Reloads the profile
    from disk so everything is picklable.
    """
    repo_root = Path(repo_root_str)
    work_dir = Path(work_dir_str)
    worker_dir = work_dir / "worker_{}".format(worker_id)
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

    return _run_batches_chunked(
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
    )


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
        max_batch_points = 4
        print(
            "Execute mode without trace replay: enforcing sub-batches of 4 points.",
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

        print(
            "Parallel sweep: {} workers, ~{} points each (interleaved)".format(
                len(chunks), len(chunks[0])
            ),
            file=sys.stderr,
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
                )
                futures[f] = wid

            for f in as_completed(futures):
                wid = futures[f]
                try:
                    worker_results = f.result()
                    batch_results.extend(worker_results)
                    print(
                        "Worker {} finished: {} results".format(wid, len(worker_results)),
                        file=sys.stderr,
                    )
                except Exception as exc:
                    print(
                        "Worker {} FAILED: {}".format(wid, exc),
                        file=sys.stderr,
                    )
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
        )
        data["is_control"] = True
        results.append(data)

    return results


def classify_failure_class(result: Dict[str, Any]) -> str:
    """Return normalized failure class for a sweep result."""
    raw = str(result.get("fault_class", "") or "").strip().lower()
    if raw:
        return raw

    outcome = str(result.get("boot_outcome", "unknown") or "unknown").strip().lower()
    if outcome == "success":
        return "recoverable"
    if outcome == "wrong_image":
        signals = result.get("signals", {})
        if not isinstance(signals, dict):
            signals = {}
        hash_match = str(signals.get("image_hash_match", "") or "").strip().lower()
        expected_slot = str(signals.get("image_hash_slot", "") or "").strip().lower()
        boot_slot = str(result.get("boot_slot", "") or "").strip().lower()
        if hash_match == "unknown" and (
            not expected_slot or expected_slot == "any" or boot_slot == expected_slot
        ):
            return "silent_corruption"
        return "wrong_image"
    if outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}:
        return "unrecoverable"
    return "unrecoverable"


def load_clean_write_trace(trace_file: Optional[str]) -> List[Dict[str, int]]:
    """Load calibration write trace CSV."""
    if not trace_file or not os.path.exists(trace_file):
        return []
    entries: List[Dict[str, int]] = []
    with open(trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                entries.append(
                    {
                        "write_index": int(row.get("write_index", "0")),
                        "flash_offset": int(row.get("flash_offset", "0")),
                        "value": int(row.get("value", "0") or "0"),
                    }
                )
            except Exception:
                continue
    entries.sort(key=lambda e: e["write_index"])
    return entries


def _parse_optional_int(value: Any) -> Optional[int]:
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except Exception:
        return None


def load_clean_erase_trace(erase_trace_file: Optional[str]) -> List[Dict[str, Any]]:
    """Load calibration erase trace CSV (if available).

    The preferred column is `writes_at_this_point`. Some traces may omit it;
    in that case entries are still loaded and kept in source order with
    `writes_at_this_point=None` so downstream interleaving can degrade safely.
    """
    if not erase_trace_file or not os.path.exists(erase_trace_file):
        return []
    entries: List[Dict[str, Any]] = []
    with open(erase_trace_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames:
            fieldnames = {name.strip().lower() for name in reader.fieldnames if name}
        else:
            fieldnames = set()
        writes_at_key: Optional[str] = None
        for candidate in (
            "writes_at_this_point",
            "writes_at",
            "write_index",
            "write_count_at_erase",
        ):
            if candidate in fieldnames:
                writes_at_key = candidate
                break
        for idx, row in enumerate(reader, start=1):
            try:
                erase_index_raw = row.get("erase_index", str(idx))
                erase_index = int(str(erase_index_raw).strip() or str(idx), 0)
                flash_offset_raw = row.get("flash_offset")
                if flash_offset_raw is None:
                    flash_offset_raw = row.get("offset", "0")
                flash_offset = int(str(flash_offset_raw).strip() or "0", 0)
            except Exception:
                continue
            writes_at: Optional[int] = None
            if writes_at_key is not None:
                writes_at = _parse_optional_int(row.get(writes_at_key, ""))
            if writes_at is not None and writes_at < 0:
                writes_at = None
            entries.append(
                {
                    "erase_index": erase_index,
                    "flash_offset": flash_offset,
                    "writes_at_this_point": writes_at,
                    "source_order": idx,
                }
            )
    entries.sort(
        key=lambda e: (
            e["writes_at_this_point"] is None,
            e["writes_at_this_point"] if e["writes_at_this_point"] is not None else 0,
            e["source_order"],
            e["erase_index"],
        )
    )
    return entries


def _fmt_u32(value: int) -> str:
    return "0x{0:08X}".format(int(value) & 0xFFFFFFFF)


def build_clean_operation_trace(
    write_entries: List[Dict[str, int]],
    erase_entries: List[Dict[str, Any]],
    flash_base: int,
) -> List[Dict[str, Any]]:
    """Interleave clean-run write+erase operations into a single timeline."""
    ops: List[Dict[str, Any]] = []
    max_write_index = 0
    for w in write_entries:
        idx = int(w["write_index"])
        if idx > max_write_index:
            max_write_index = idx
        off = int(w["flash_offset"])
        val = int(w["value"])
        ops.append(
            {
                "_sort_key": (idx, 1, 0),
                "kind": "write",
                "write_index": idx,
                "flash_offset": off,
                "address": _fmt_u32(flash_base + off),
                "value": _fmt_u32(val),
            }
        )
    for e in erase_entries:
        erase_idx = int(e["erase_index"])
        writes_at_raw = e.get("writes_at_this_point")
        source_order = int(e.get("source_order", erase_idx))
        if writes_at_raw is None:
            # Missing writes_at means precise interleaving is unavailable.
            # Keep deterministic ordering by appending after known write-indexed
            # operations while preserving original erase row order.
            writes_at = max_write_index + source_order
            writes_at_known = False
        else:
            writes_at = int(writes_at_raw)
            writes_at_known = True
        off = int(e["flash_offset"])
        ops.append(
            {
                "_sort_key": (writes_at + 1, 0, erase_idx),
                "kind": "erase",
                "erase_index": erase_idx,
                "writes_at_this_point": writes_at_raw,
                "writes_at_known": writes_at_known,
                "flash_offset": off,
                "address": _fmt_u32(flash_base + off),
            }
        )
    ops.sort(key=lambda o: o["_sort_key"])
    for i, op in enumerate(ops, start=1):
        op["sequence"] = i
        op.pop("_sort_key", None)
    return ops


def _compact_operation(op: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(op, dict):
        return None
    base = {
        "sequence": int(op.get("sequence", 0)),
        "kind": op.get("kind"),
        "address": op.get("address"),
        "flash_offset": int(op.get("flash_offset", 0)),
    }
    if op.get("kind") == "write":
        base["write_index"] = int(op.get("write_index", 0))
        base["value"] = op.get("value")
    elif op.get("kind") == "erase":
        base["erase_index"] = int(op.get("erase_index", 0))
        writes_at = op.get("writes_at_this_point")
        if writes_at is not None:
            base["writes_at_this_point"] = int(writes_at)
        base["writes_at_known"] = bool(op.get("writes_at_known", True))
    return base


def annotate_fault_windows(
    results: List[Dict[str, Any]],
    clean_operations: List[Dict[str, Any]],
) -> int:
    """Attach clean-trace window annotations to injected results."""
    if not clean_operations:
        return 0

    annotated = 0
    write_pos = {int(op["write_index"]): i for i, op in enumerate(clean_operations) if op.get("kind") == "write"}
    erase_pos = {int(op["erase_index"]): i for i, op in enumerate(clean_operations) if op.get("kind") == "erase"}

    for r in results:
        if r.get("is_control", False):
            continue
        if not r.get("fault_injected", False):
            continue

        fp = int(r.get("fault_at", 0))
        fault_type = str(r.get("fault_type", "w") or "w")
        target_pos: Optional[int] = None

        if fault_type in {"e", "a"}:
            target_pos = erase_pos.get(fp + 1)
        else:
            target_pos = write_pos.get(fp + 1)

        if target_pos is None:
            continue

        before_op = clean_operations[target_pos - 1] if target_pos > 0 else None
        target_op = clean_operations[target_pos]
        next_op = clean_operations[target_pos + 1] if target_pos + 1 < len(clean_operations) else None

        r["fault_window"] = {
            "fault_type": fault_type,
            "fault_at": fp,
            "before": _compact_operation(before_op),
            "at": _compact_operation(target_op),
            "after": _compact_operation(next_op),
        }
        annotated += 1

    return annotated


def categorize_failure(
    result: Dict[str, Any],
    total_writes: int,
    profile: ProfileConfig,
) -> Dict[str, Any]:
    """Classify a single failure by outcome type and fault region."""
    fp = result.get("fault_at", 0)
    outcome = result.get("boot_outcome", "unknown")
    fault_addr = result.get("fault_address", "0x00000000")

    # Parse fault address.
    if isinstance(fault_addr, str):
        addr = int(fault_addr, 16)
    else:
        addr = int(fault_addr)

    # Determine which memory region the faulted write targeted.
    # MCUboot puts trailers at the end of each slot (last page), so
    # check trailer before data to get the more specific classification.
    region = "unknown"
    page_size = getattr(profile.memory, "page_size", 4096)
    for slot_name, slot_info in profile.memory.slots.items():
        slot_end = slot_info.base + slot_info.size
        if slot_end - page_size <= addr < slot_end:
            region = slot_name + "_trailer"
            break
        if slot_info.base <= addr < slot_end:
            region = slot_name + "_data"
            break

    # Swap phase based on position.
    if total_writes > 0:
        pct = fp / total_writes
    else:
        pct = 0.0
    if pct < 0.01:
        phase = "early"
    elif pct > 0.99:
        phase = "late"
    else:
        phase = "mid"

    payload = {
        "fault_at": fp,
        "outcome": outcome,
        "failure_class": classify_failure_class(result),
        "fault_address": fault_addr,
        "region": region,
        "phase": phase,
        "position_pct": round(pct * 100, 2),
    }
    window = result.get("fault_window")
    if isinstance(window, dict):
        payload["fault_window"] = window
    return payload


def summarize_runtime_sweep(
    results: List[Dict[str, Any]],
    total_writes: int = 0,
    profile: Optional["ProfileConfig"] = None,
) -> Dict[str, Any]:
    """Compute summary statistics from runtime sweep results."""
    non_control = [r for r in results if not r.get("is_control", False)]
    control = [r for r in results if r.get("is_control", False)]

    # Fail-closed: exclude points where fault didn't actually fire.
    injected = [r for r in non_control if r.get("fault_injected", False)]
    not_injected = [r for r in non_control if not r.get("fault_injected", False)]

    total = len(injected)
    # Treat the profile's control outcome as the expected successful outcome.
    expected_outcome = "success"
    if profile and getattr(profile, "expect", None):
        expected_outcome = (
            getattr(profile.expect, "control_outcome", "success") or "success"
        )
    failures = [r for r in injected if r.get("boot_outcome") != expected_outcome]
    recoveries = sum(1 for r in injected if r.get("boot_outcome") == expected_outcome)

    # Categorize failures by outcome type.
    outcome_counts: Dict[str, int] = {}
    class_counts: Dict[str, int] = {}
    categorized_failures: List[Dict[str, Any]] = []
    for r in failures:
        outcome = r.get("boot_outcome", "unknown")
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        fclass = classify_failure_class(r)
        class_counts[fclass] = class_counts.get(fclass, 0) + 1
        if profile:
            categorized_failures.append(
                categorize_failure(r, total_writes, profile)
            )

    summary: Dict[str, Any] = {
        "total_fault_points": total,
        "bricks": len(failures),
        "recoveries": recoveries,
        "brick_rate": (float(len(failures)) / float(total)) if total else 0.0,
        "discarded_no_fault_fired": len(not_injected),
        "failure_outcomes": outcome_counts,
        "failure_classes": class_counts,
    }

    if categorized_failures:
        summary["failures"] = categorized_failures

    if control:
        ctrl = control[-1]
        control_summary: Dict[str, Any] = {
            "boot_outcome": ctrl.get("boot_outcome"),
            "boot_slot": ctrl.get("boot_slot"),
        }
        ctrl_signals = ctrl.get("signals") or {}
        control_telemetry = {
            key: ctrl_signals.get(key)
            for key in (
                "phase1_stop_reason",
                "phase1_emulated_s",
                "phase2_stop_reason",
                "phase2_emulated_s",
                "trace_replay_mode",
                "reload_ms",
                "replay_ms",
                "reset_ms",
                "setup_ms",
                "emulation_ms",
                "total_ms",
                "p2_iters",
                "vtor",
                "vtor_final",
                "pc",
            )
            if ctrl_signals.get(key) is not None
        }
        if control_telemetry:
            control_summary["signals"] = control_telemetry
        summary["control"] = control_summary

    # Aggregate per-step timing from signals.
    timing_keys = [
        "reload_ms", "replay_ms", "reset_ms", "setup_ms",
        "emulation_ms", "total_ms", "p2_iters",
    ]
    timing_sums: Dict[str, int] = {}
    timing_maxes: Dict[str, int] = {}
    timing_count = 0
    for r in injected:
        s = r.get("signals", {})
        if "total_ms" not in s:
            continue
        timing_count += 1
        for k in timing_keys:
            v = s.get(k, 0)
            timing_sums[k] = timing_sums.get(k, 0) + v
            timing_maxes[k] = max(timing_maxes.get(k, 0), v)
    if timing_count > 0:
        summary["timing"] = {
            "points": timing_count,
            "totals": {k: timing_sums.get(k, 0) for k in timing_keys},
            "averages": {k: timing_sums.get(k, 0) // timing_count for k in timing_keys},
            "maximums": {k: timing_maxes.get(k, 0) for k in timing_keys},
        }

    return summary


def git_metadata(repo_root: Path) -> Dict[str, str]:
    def run_git(*args: str) -> str:
        proc = subprocess.run(
            ["git"] + list(args), cwd=str(repo_root),
            capture_output=True, text=True, check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    commit = run_git("rev-parse", "HEAD")
    short_commit = run_git("rev-parse", "--short", "HEAD")
    if not commit:
        commit = "unavailable"
    if not short_commit:
        short_commit = commit

    return {
        "commit": commit,
        "short_commit": short_commit,
        "dirty": "true" if run_git("status", "--porcelain") else "false",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    temp_ctx: Optional[tempfile.TemporaryDirectory[str]] = None

    try:
        renode_test = ensure_tool(args.renode_test)
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
        max_writes = profile.fault_sweep.max_writes
        trace_file: Optional[str] = None
        erase_trace_file: Optional[str] = None
        trace_file_bin: Optional[str] = None
        erase_trace_file_bin: Optional[str] = None
        total_erases: int = 0
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
        include_multi_sector_atomicity = "multi_sector_atomicity" in fault_types

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
                if include_erases:
                    print("Calibration: {} NVM writes, {} page erases.".format(max_writes, total_erases), file=sys.stderr)
                else:
                    print("Calibration: {} NVM writes.".format(max_writes), file=sys.stderr)
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

            fault_points = classify_trace(
                trace=trace,
                slot_ranges=slot_ranges_for_heuristic,
                flash_base=flash_base,
                page_size=getattr(profile.memory, "page_size", 4096),
            )
            heuristic_summary = summarize_classification(
                trace=trace,
                fault_points=fault_points,
                slot_ranges=slot_ranges_for_heuristic,
                flash_base=flash_base,
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
        #   'e' interrupted erase, 'a' multi-sector atomicity fault.
        fault_types_list: Optional[List[str]] = None
        has_mixed_types = (
            (include_erases and total_erases > 0)
            or include_bit_corruption
            or include_silent_write_failure
            or include_write_disturb
            or include_wear_leveling
            or include_write_rejection
            or include_reset_at_time
        )
        if has_mixed_types:
            write_fps: List[Tuple[int, str]] = []
            if include_power_loss:
                # no_boot baselines can legitimately calibrate to 0 writes.
                # In that case, skip write-based points.
                write_fps = [(fp, 'w') for fp in fault_points] if max_writes > 0 else []
            combined = list(write_fps)

            # Add erase-based fault points.
            erase_count = 0
            atomicity_count = 0
            if include_erases and total_erases > 0:
                erase_fps = list(range(0, total_erases))
                if args.quick:
                    erase_fps = quick_subset(erase_fps)
                if "interrupted_erase" in fault_types:
                    combined += [(ep, 'e') for ep in erase_fps]
                    erase_count = len(erase_fps)
                if include_multi_sector_atomicity:
                    combined += [(ep, 'a') for ep in erase_fps]
                    atomicity_count = len(erase_fps)

            # Add bit-corruption fault points (same write indices, different mode).
            bit_count = 0
            if include_bit_corruption:
                bit_fps = list(fault_points)  # same write indices
                if args.quick:
                    bit_fps = quick_subset(bit_fps)
                combined += [(bp, 'b') for bp in bit_fps]
                bit_count = len(bit_fps)

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

            fault_points = [fp for fp, _ in combined]
            fault_types_list = [ft for _, ft in combined]
            parts = ["{} writes".format(len(write_fps))]
            if erase_count:
                parts.append("{} erases".format(erase_count))
            if atomicity_count:
                parts.append("{} multi-sector".format(atomicity_count))
            if bit_count:
                parts.append("{} bit-corrupt".format(bit_count))
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
            annotated_windows = annotate_fault_windows(sweep_results, clean_ops)
            clean_trace_meta = {
                "trace_file": trace_file,
                "erase_trace_file": erase_trace_file,
                "writes": len(clean_write_trace),
                "erases": len(clean_erase_trace),
                "erases_missing_writes_at": erase_missing_writes_at,
                "operations": len(clean_ops),
                "fault_windows_annotated": annotated_windows,
            }
            print(
                "Fault-window annotation: {} points mapped to clean trace.".format(
                    annotated_windows
                ),
                file=sys.stderr,
            )
            if erase_missing_writes_at > 0:
                print(
                    "Clean erase trace: {} entries missing writes_at; "
                    "using deterministic fallback ordering.".format(
                        erase_missing_writes_at
                    ),
                    file=sys.stderr,
                )

        sweep_summary = summarize_runtime_sweep(
            sweep_results, total_writes=max_writes, profile=profile
        )
        sweep_summary["wall_time_s"] = round(sweep_wall_s, 1)

        # -------------------------------------------------------------------
        # State fuzzer (opt-in)
        # -------------------------------------------------------------------
        state_fuzz_results: Optional[List[Dict[str, Any]]] = None
        state_fuzz_summary: Optional[Dict[str, Any]] = None

        if profile.state_fuzzer.enabled:
            print("State fuzzer enabled (model={}), running...".format(
                profile.state_fuzzer.metadata_model
            ), file=sys.stderr)
            # State fuzzer runs via audit.robot / run_state_fuzz_point.resc
            # using a future scenario generator plugin.
            # This is the opt-in plugin path. For now, mark as placeholder.
            state_fuzz_results = []
            state_fuzz_summary = {"status": "not_yet_wired", "metadata_model": profile.state_fuzzer.metadata_model}

        # -------------------------------------------------------------------
        # Verdict
        # -------------------------------------------------------------------
        found_issues = sweep_summary["bricks"] > 0

        verdict = "PASS"
        if profile.expect.should_find_issues and not found_issues:
            verdict = "FAIL — expected to find bricks but found none"
        elif not profile.expect.should_find_issues and found_issues:
            verdict = "FAIL — found {} bricks (expected none)".format(
                sweep_summary["bricks"]
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
            "fault_points_tested": len(fault_points),
            "quick": bool(args.quick),
            "heuristic": heuristic_summary,
            "verdict": verdict,
            "summary": {
                "runtime_sweep": sweep_summary,
            },
            "expect": {
                "should_find_issues": profile.expect.should_find_issues,
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
        payload["calibration"] = {
            "writes": cal.total_writes,
            "erases": total_erases,
            "stop_reason": cal.stop_reason,
            "emulated_s": cal.emulated_s,
            "elapsed_s": cal.elapsed_s,
            "pc": cal.pc,
        }
        if clean_trace_meta is not None:
            payload["clean_trace"] = clean_trace_meta

        if state_fuzz_results is not None:
            payload["state_fuzz_results"] = state_fuzz_results
            payload["summary"]["state_fuzz"] = state_fuzz_summary

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
            if ctrl.get("boot_outcome") != expected_control:
                print(
                    "ASSERTION FAILED: control point outcome '{}' != expected '{}'".format(
                        ctrl.get("boot_outcome"), expected_control
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
