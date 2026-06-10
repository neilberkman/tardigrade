"""Renode execution infrastructure: batch dispatch, calibration, and utilities.

Extracted from audit_bootloader.py to provide a focused module for
invoking renode-test, running fault-point batches, and calibration logic.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import math
import os
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_types import TRACE_REPLAY_WIRE_CODES
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


def parse_renode_robot_timeout_minutes(env: Dict[str, str]) -> Optional[int]:
    """Read optional Robot per-suite timeout override from environment."""
    raw = str(env.get("OTA_RENODE_ROBOT_TIMEOUT_MINUTES", "") or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise RuntimeError(
            "Invalid OTA_RENODE_ROBOT_TIMEOUT_MINUTES='{}' (must be numeric)".format(
                raw
            )
        )
    if value <= 0:
        return None
    return int(math.ceil(value))


def profile_robot_timeout_minutes(profile: ProfileConfig) -> Optional[int]:
    """Derive a Robot timeout floor from the profile's execute budget."""
    fault_sweep = getattr(profile, "fault_sweep", None)
    if fault_sweep is None:
        return None
    raw = str(getattr(fault_sweep, "run_duration", "") or "").strip()
    if not raw:
        return None
    try:
        duration_s = float(raw)
    except ValueError:
        return None
    if duration_s <= 0:
        return None
    robot_timeout_s = max(120.0, max(4.0, duration_s) * 30.0)
    return int(math.ceil(robot_timeout_s / 60.0))


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


def _renode_process_timeout(timeout_s: Optional[float]) -> Optional[float]:
    if timeout_s is None:
        return None
    return max(float(timeout_s), float(timeout_s) * 1.5)


def _base_fault_type_code(fault_type: Optional[str]) -> str:
    raw = str(fault_type or "")
    return raw.split(":", 1)[0] if ":" in raw else raw


def _is_trace_replay_batch(
    *,
    trace_file: Optional[str],
    trace_file_bin: Optional[str],
    fault_types_list: Optional[List[str]],
) -> bool:
    if not (trace_file or trace_file_bin):
        return False
    if not fault_types_list:
        return True
    return all(_base_fault_type_code(ft) in TRACE_REPLAY_WIRE_CODES for ft in fault_types_list)


def _estimate_batch_runtime_seconds(
    *,
    profile: ProfileConfig,
    fault_points: List[int],
    fault_types_list: Optional[List[str]],
    trace_replay: bool,
) -> float:
    update_sequence_overhead_s = (
        12.0 if getattr(profile, "has_update_sequence", False) else 0.0
    )
    if trace_replay:
        platform = str(getattr(profile, "platform", "") or "").lower()
        trace_replay_point_cost_s = 1.25 if "stm32f4" in platform else 0.9
        return update_sequence_overhead_s + (len(fault_points) * trace_replay_point_cost_s)

    sequential_faults = {"w", "b", "e", "a", "s", "g", "x", "d", "l", "r", "k"}

    def point_cost(idx: int, fp: int) -> float:
        ft = (
            fault_types_list[idx]
            if fault_types_list and idx < len(fault_types_list)
            else None
        )
        if ft is None or _base_fault_type_code(ft) in sequential_faults:
            return 2.0 + abs(fp) * 0.012
        return 5.0

    return update_sequence_overhead_s + sum(
        point_cost(i, fp) for i, fp in enumerate(fault_points)
    )


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def run_renode_subprocess(
    cmd: List[str],
    *,
    cwd: str,
    env: Dict[str, str],
    timeout_s: Optional[float],
) -> subprocess.CompletedProcess[str]:
    """Run renode-test with a process-group wall timeout.

    `subprocess.run(timeout=...)` only kills the direct child. Renode hangs can
    leave descendants alive, so launch a fresh session and SIGKILL the process
    group on timeout.
    """
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=timeout_s,
            output=stdout,
            stderr=stderr,
        )
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=int(proc.returncode or 0),
        stdout=stdout or "",
        stderr=stderr or "",
    )


def quick_subset(points: List[int]) -> List[int]:
    if len(points) <= 3:
        return points
    mid = len(points) // 2
    return sorted(set([points[0], points[mid], points[-1]]))


def _synthetic_failed_batch_results(
    fault_points: List[int],
    fault_types_list: Optional[List[str]],
    error: str,
    *,
    timeout: bool = True,
) -> List[Dict[str, Any]]:
    """Return synthetic results when fallback cannot isolate further."""
    results: List[Dict[str, Any]] = []
    for idx, fault_at in enumerate(fault_points):
        payload: Dict[str, Any] = {
            "fault_at": fault_at,
            "fault_requested": fault_at,
            "fault_injected": True,
            "fault_address": "0x00000000",
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "timeout": timeout,
            "error": error,
        }
        if fault_types_list and idx < len(fault_types_list):
            payload["fault_type"] = fault_types_list[idx]
        results.append(payload)
    return results


def _is_process_timeout_error(error: str) -> bool:
    return "renode-test batch timed out after" in str(error or "")


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
    trace_file = point_dir / "trace.csv" if calibration else None
    erase_trace_file = point_dir / "erase_trace.csv" if calibration else None
    trace_file_bin = point_dir / "trace.bin" if calibration else None
    erase_trace_file_bin = point_dir / "erase_trace.bin" if calibration else None

    # Calibration can take much longer than 2 minutes for large swap operations
    # (e.g. MCUboot HEAD 448KB swap-move). Give it 15 minutes.
    single_point_timeout_m = 15 if calibration else 2
    env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)
    profile_timeout_m = profile_robot_timeout_minutes(profile)
    if profile_timeout_m is not None:
        single_point_timeout_m = max(single_point_timeout_m, profile_timeout_m)
    robot_timeout_override_m = parse_renode_robot_timeout_minutes(env)
    if robot_timeout_override_m is not None:
        single_point_timeout_m = max(single_point_timeout_m, robot_timeout_override_m)

    cmd = [
        renode_test,
        "--renode-config", str(renode_config),
        robot_suite,
        "--results-dir", str(rf_results),
        "--variable", "FAULT_AT:{}".format(point_fault_at),
        "--variable", "RESULT_FILE:{}".format(result_file),
        "--variable", "CALIBRATION_MODE:{}".format("true" if calibration else "false"),
        "--variable", "TRACE_FILE:{}".format(trace_file or ""),
        "--variable", "ERASE_TRACE_FILE:{}".format(erase_trace_file or ""),
        "--variable", "TRACE_FILE_BIN:{}".format(trace_file_bin or ""),
        "--variable", "ERASE_TRACE_FILE_BIN:{}".format(erase_trace_file_bin or ""),
        "--variable", "TEST_TIMEOUT:{} minutes".format(single_point_timeout_m),
    ]
    if renode_remote_server_dir:
        cmd.extend(["--robot-framework-remote-server-full-directory", renode_remote_server_dir])

    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    cmd = prepare_renode_command(renode_test, cmd, repo_root, env)
    timeout_s = parse_renode_point_timeout(env)
    if calibration and timeout_s is not None:
        timeout_s = max(timeout_s, 900.0)
    if profile_timeout_m is not None:
        profile_timeout_s = float(profile_timeout_m) * 60.0
        timeout_s = (
            profile_timeout_s
            if timeout_s is None
            else max(timeout_s, profile_timeout_s)
        )
    if robot_timeout_override_m is not None:
        robot_timeout_s = float(robot_timeout_override_m) * 60.0
        timeout_s = (
            robot_timeout_s
            if timeout_s is None
            else max(timeout_s, robot_timeout_s)
        )
    process_timeout_s = _renode_process_timeout(timeout_s)

    try:
        try:
            proc = run_renode_subprocess(
                cmd,
                cwd=str(repo_root),
                env=env,
                timeout_s=process_timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            raise RuntimeError(
                "renode-test timed out for {} fault_at={} after {}s\nSTDOUT:\n{}\nSTDERR:\n{}\n"
                "Adjust with OTA_RENODE_POINT_TIMEOUT_S (seconds; <=0 disables timeout).".format(
                    label, fault_at, process_timeout_s, out, err
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
    calibration_boot_outcome: Optional[str] = None
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
    total_writes: int = 0,
    total_erases: int = 0,
) -> bool:
    """Return whether a calibration stop reason represents a complete pass."""
    if not stop_reason:
        return False
    if stop_reason == "budget":
        # Budget exhaustion with NVM activity means the bootloader ran and
        # wrote metadata/data before the step or time limit was reached.
        # For direct-XIP bootloaders this IS the complete boot — there is
        # no swap phase, so metadata writes are the only NVM activity.
        # Treat as complete when writes or erases were observed.
        if total_writes > 0 or total_erases > 0:
            return True
        return False
    if any(stop_reason.startswith(prefix) for prefix in CALIBRATION_INCOMPLETE_PREFIXES):
        return False
    if stop_reason in {"no_boot_no_writes", "no_boot_settled_writes", "no_writes_brick", "vtor_captured_hardfault"}:
        return expected_control_outcome == "no_boot"
    return True


def describe_zero_op_calibration(
    data: Dict[str, Any],
    stop_reason: Optional[str],
    expected_control_outcome: str,
) -> str:
    if expected_control_outcome == "no_boot":
        return "Calibration found 0 NVM operations (expected no_boot baseline)."
    if stop_reason and stop_reason.startswith("console_fatal("):
        signals = data.get("signals") if isinstance(data.get("signals"), dict) else {}
        fatal_pattern = str(signals.get("phase1_console_fatal_pattern") or "").strip()
        last_line = str(signals.get("phase1_console_last_line") or "").strip()
        details = fatal_pattern or stop_reason
        if last_line:
            details = "{}; last_console_line={!r}".format(details, last_line)
        return (
            "WARNING: Calibration found 0 NVM operations because the bootloader "
            "hit a fatal console-detected stop before any flash activity ({}) . "
            "Treat this as a control-path failure or geometry/platform mismatch, "
            "not a stateless/XIP updater."
        ).format(details)
    return (
        "WARNING: Calibration found 0 NVM operations — bootloader is stateless "
        "(e.g., XIP bootloader). No fault points to test."
    )


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
    if not calibration_completed(stop_reason, profile.expect.control_outcome, total_writes, total_erases):
        raise RuntimeError(
            "Calibration did not complete cleanly (reason={!r}, writes={}, erases={}). "
            "Refusing to run a partial sweep.".format(
                stop_reason, total_writes, total_erases
            )
        )
    if total_writes <= 0 and total_erases <= 0:
        print(
            describe_zero_op_calibration(
                data=data,
                stop_reason=stop_reason,
                expected_control_outcome=profile.expect.control_outcome,
            ),
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
        calibration_boot_outcome=data.get("calibration_boot_outcome"),
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
    bundle_dir: Optional[Path] = None,
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
    bundle_dir = bundle_dir or (work_dir / ".dotnet_bundle")
    renode_config = work_dir / "renode.config"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    csv = ",".join(str(fp) for fp in fault_points)
    ft_csv = ",".join(fault_types_list) if fault_types_list else ""

    # Determine fault_types mode for the .resc.
    erase_types = {'e', 'a'}
    write_types = {'w', 'b', 's', 'g', 'x', 'd', 'l', 'r', 't', 'k'}

    has_erase = bool(
        fault_types_list
        and any(_base_fault_type_code(ft) in erase_types for ft in fault_types_list)
    )
    has_write = bool(
        fault_types_list
        and any(_base_fault_type_code(ft) in write_types for ft in fault_types_list)
    )
    if has_erase and has_write:
        fault_types_mode = "both"
    elif has_erase:
        fault_types_mode = "erase"
    else:
        fault_types_mode = "write"

    trace_replay_batch = _is_trace_replay_batch(
        trace_file=trace_file,
        trace_file_bin=trace_file_bin,
        fault_types_list=fault_types_list,
    )
    estimated_s = _estimate_batch_runtime_seconds(
        profile=profile,
        fault_points=fault_points,
        fault_types_list=fault_types_list,
        trace_replay=trace_replay_batch,
    )
    robot_test_timeout_s = max(120, 120 + estimated_s)
    if getattr(profile, "has_update_sequence", False):
        # Multi-phase clean baselines add significant fixed overhead before the
        # fault points run. Keep a higher floor so healthy batches do not trip
        # Robot's per-suite timeout and recursively split.
        robot_test_timeout_s = max(robot_test_timeout_s, 600.0)
    robot_test_timeout_m = max(2, (int(robot_test_timeout_s) + 59) // 60)
    env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)
    robot_timeout_override_m = parse_renode_robot_timeout_minutes(env)
    if robot_timeout_override_m is not None:
        robot_test_timeout_m = max(robot_test_timeout_m, robot_timeout_override_m)
    per_point_timeout = parse_renode_point_timeout(env)
    if per_point_timeout is not None and len(fault_points) == 1:
        # Fallback-isolated one-point batches use the subprocess guard below.
        # Keep Robot's in-suite timeout at least that long, or Robot can abort
        # first and force a synthetic timeout even though the execute-mode
        # harness still had runner budget remaining.
        process_guard_s = _renode_process_timeout(per_point_timeout)
        robot_test_timeout_m = max(
            robot_test_timeout_m,
            int(math.ceil(float(process_guard_s) / 60.0)),
        )

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

    cmd = prepare_renode_command(renode_test, cmd, repo_root, env)
    # Scale batch timeout by fault point values, not just count.
    # Execute-mode late fault points (fp=10000+) need long Phase 1
    # emulation — 4s/point is fine for trace replay but way too low
    # for execute-mode where each point must emulate up to fp writes.
    if per_point_timeout is not None:
        if len(fault_points) == 1:
            # Once fallback has isolated a batch to one point, use the same
            # tight wall-time budget as run_single_point() instead of the bulk
            # batch floor. This keeps isolated instruction-skip retries from
            # waiting 120s+ when the caller explicitly requested a lower per-
            # point timeout (e.g. OTA_RENODE_POINT_TIMEOUT_S=40).
            timeout_s = per_point_timeout
        else:
            # Estimate per-point cost: base 2s + 0.012s per fault_at value.
            # 0.012 matches measured ~160s for fp=13000 execute-mode points.
            # instruction_skip uses flat cost (addresses, not write indices).
            timeout_s = min(
                7200.0,  # 2h hard cap to prevent overflow
                max(per_point_timeout, 120.0 + estimated_s),
            )
            if getattr(profile, "has_update_sequence", False):
                timeout_s = min(7200.0, max(timeout_s, 600.0))
    else:
        timeout_s = None
    process_timeout_s = _renode_process_timeout(timeout_s)

    try:
        try:
            proc = run_renode_subprocess(
                cmd,
                cwd=str(repo_root),
                env=env,
                timeout_s=process_timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            raise RuntimeError(
                "renode-test batch timed out after {}s ({} points)\nSTDOUT:\n{}\nSTDERR:\n{}\n"
                "Adjust with OTA_RENODE_POINT_TIMEOUT_S (seconds; <=0 disables timeout).".format(
                    process_timeout_s, len(fault_points), out, err
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
        results_list = data if isinstance(data, list) else [data]

        # Pick up the per-batch read-fault sidecar and stamp the
        # accounting onto the first result entry so downstream summary
        # builders can aggregate it without rereading the sidecar.
        sidecar = Path(str(result_file) + ".read_fault_summary.json")
        if sidecar.exists() and results_list:
            try:
                payload = json.loads(sidecar.read_text(encoding="utf-8"))
            except Exception:
                payload = None
            if payload and isinstance(results_list[0], dict):
                results_list[0].setdefault("read_fault_summary", payload)
        return results_list
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
    bundle_dir: Optional[Path] = None,
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
            bundle_dir=bundle_dir,
            keep_run_artifacts=keep_run_artifacts,
        )
        if len(fault_points) == 1:
            _progress("Fallback point {} complete.".format(fault_points[0]))
        return results
    except Exception as exc:
        if len(fault_points) <= 1 or _depth >= _MAX_FALLBACK_DEPTH:
            error_text = str(exc)
            isolated_instruction_skip_timeout = (
                len(fault_points) == 1
                and bool(fault_types_list)
                and _base_fault_type_code(fault_types_list[0]) == "i"
                and _is_process_timeout_error(error_text)
            )
            if len(fault_points) <= 1:
                if isolated_instruction_skip_timeout:
                    _progress(
                        "Fallback point {} hit the isolated execute timeout; recording synthetic no-boot result. {}".format(
                            fault_points[0], error_text
                        )
                    )
                else:
                    _progress(
                        "Fallback point {} failed after isolation; recording synthetic timeout result. {}".format(
                            fault_points[0], error_text
                        )
                    )
            if _depth >= _MAX_FALLBACK_DEPTH:
                _progress(
                    "Fallback depth limit ({}) reached for {} points (fp {}..{}); recording synthetic timeout results. {}".format(
                        _MAX_FALLBACK_DEPTH, len(fault_points),
                        fault_points[0], fault_points[-1],
                        error_text,
                    )
                )
            return _synthetic_failed_batch_results(
                fault_points=fault_points,
                fault_types_list=fault_types_list,
                error=error_text,
                timeout=not isolated_instruction_skip_timeout,
            )
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
                    bundle_dir=bundle_dir,
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
                    bundle_dir=bundle_dir,
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
    shared_bundle_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Run one or more fault batches with optional fixed-size chunking."""
    if shared_bundle_dir is None:
        shared_bundle_dir = work_dir / ".dotnet_bundle"
    shared_bundle_dir.mkdir(parents=True, exist_ok=True)

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
            bundle_dir=shared_bundle_dir,
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
