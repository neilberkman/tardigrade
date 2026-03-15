"""Renode execution infrastructure: batch dispatch, calibration, and utilities.

Extracted from audit_bootloader.py to provide a focused module for
invoking renode-test, running fault-point batches, and calibration logic.
"""

from __future__ import annotations

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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from profile_loader import HeuristicConfig, ProfileConfig, load_profile


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

    # Calibration can take much longer than 2 minutes for large swap operations
    # (e.g. MCUboot HEAD 448KB swap-move). Give it 15 minutes.
    single_point_timeout_m = 15 if calibration else 2

    cmd = [
        renode_test,
        "--renode-config", str(renode_config),
        robot_suite,
        "--results-dir", str(rf_results),
        "--variable", "FAULT_AT:{}".format(point_fault_at),
        "--variable", "RESULT_FILE:{}".format(result_file),
        "--variable", "CALIBRATION_MODE:{}".format("true" if calibration else "false"),
        "--variable", "TEST_TIMEOUT:{} minutes".format(single_point_timeout_m),
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
    total_otp_blows: int = 0


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
        total_otp_blows=int(data.get("total_otp_blows", 0)),
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
    # Scale robot test timeout with actual fault point cost, not just count.
    # Execute-mode late points (fp=10000+) need long Phase 1 emulation.
    # 0.012s/fp matches measured ~160s for fp=13000 execute-mode points.
    robot_test_timeout_s = max(120, 120 + sum(2.0 + fp * 0.012 for fp in fault_points))
    robot_test_timeout_m = max(2, (int(robot_test_timeout_s) + 59) // 60)

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
    # Scale batch timeout by fault point values, not just count.
    # Execute-mode late fault points (fp=10000+) need long Phase 1
    # emulation — 4s/point is fine for trace replay but way too low
    # for execute-mode where each point must emulate up to fp writes.
    if per_point_timeout is not None:
        # Estimate per-point cost: base 2s + 0.012s per fault_at value.
        # 0.012 matches measured ~160s for fp=13000 execute-mode points.
        estimated_s = sum(2.0 + fp * 0.012 for fp in fault_points)
        timeout_s: Optional[float] = max(
            per_point_timeout,
            120.0 + estimated_s,
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
    _depth: int = 0,
    _fallback_root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Run one batch; on failure recursively retry smaller sub-batches.

    Fallback directories are FLAT (all at _fallback_root level) to avoid
    deeply nested paths that exceed OS path length limits on macOS.
    Max recursion depth is 10 to prevent infinite spirals.
    """
    _MAX_FALLBACK_DEPTH = 10
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
        if len(fault_points) <= 1 or _depth >= _MAX_FALLBACK_DEPTH:
            if _depth >= _MAX_FALLBACK_DEPTH:
                _progress(
                    "Fallback depth limit ({}) reached for {} points (fp {}..{}); skipping.".format(
                        _MAX_FALLBACK_DEPTH, len(fault_points),
                        fault_points[0], fault_points[-1],
                    )
                )
            raise
        mid = max(1, len(fault_points) // 2)
        left_points = fault_points[:mid]
        right_points = fault_points[mid:]
        left_types = fault_types_list[:mid] if fault_types_list else None
        right_types = fault_types_list[mid:] if fault_types_list else None
        _progress(
            "Batch run failed (depth {}); retrying sub-batches ({} -> {} + {}). {}".format(
                _depth, len(fault_points), len(left_points), len(right_points), exc
            )
        )
        results: List[Dict[str, Any]] = []
        # Use a FLAT fallback directory to avoid deeply nested paths.
        # All sub-batches at all depths share the same fallback_root.
        if _fallback_root is None:
            _fallback_root = work_dir / "batch_fallback"
        _fallback_root.mkdir(parents=True, exist_ok=True)
        if left_points:
            results.extend(
                _run_batch_with_fallback(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    fault_points=left_points,
                    robot_vars=robot_vars,
                    work_dir=_fallback_root / "d{}_fp{:07d}_{:07d}".format(
                        _depth + 1, left_points[0], left_points[-1]
                    ),
                    renode_remote_server_dir=renode_remote_server_dir,
                    trace_file=trace_file,
                    erase_trace_file=erase_trace_file,
                    trace_file_bin=trace_file_bin,
                    erase_trace_file_bin=erase_trace_file_bin,
                    fault_types_list=left_types,
                    keep_run_artifacts=keep_run_artifacts,
                    _depth=_depth + 1,
                    _fallback_root=_fallback_root,
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
                    work_dir=_fallback_root / "d{}_fp{:07d}_{:07d}".format(
                        _depth + 1, right_points[0], right_points[-1]
                    ),
                    renode_remote_server_dir=renode_remote_server_dir,
                    trace_file=trace_file,
                    erase_trace_file=erase_trace_file,
                    trace_file_bin=trace_file_bin,
                    erase_trace_file_bin=erase_trace_file_bin,
                    fault_types_list=right_types,
                    keep_run_artifacts=keep_run_artifacts,
                    _depth=_depth + 1,
                    _fallback_root=_fallback_root,
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
