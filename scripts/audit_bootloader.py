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
import hashlib
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
from trace_utils import annotate_clean_trace, summarize_calibration_coverage
from trigger_discovery import (
    TriggerDiscoveryResult,
    discover_update_trigger,
    should_auto_discover_trigger,
    validate_compiled_flash_map,
)
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
    merge_robot_vars,
    parse_robot_vars,
    run_calibration,
    run_single_point,
)
from calibration_cache import compute_cache_key, load_calibration, save_calibration
from fault_plan import CalibrationInputs, FaultPlan, build_fault_plan
from fault_types import EXECUTE_ONLY_FAULT_TYPES, TRACE_REPLAY_FAULT_TYPES
from security_state_layout import analyze_persistent_state_layout
from finding_validator import validate_runtime_findings
from authorization_review_analyzer import analyze_authorization_review, load_trace
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
from terminal_error_escape import (
    discover_terminal_error_paths,
    evaluate_terminal_error_differential,
)
from boundary_campaigns import aggregate_boundary_results, boundary_campaign_dict
from report_security_status import attach_security_aggregate
from verdicts import is_pass_verdict

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RENODE_TEST = os.environ.get("RENODE_TEST", "renode-test")
DEFAULT_ROBOT_SUITE = "tests/ota_fault_point.robot"


def _resolve_hash_bypass_addresses(
    elf_path: str,
    symbols: List[str],
) -> Dict[str, List[int]]:
    """Resolve hash bypass symbol names to addresses on the HOST side via nm.

    Returns {symbol_name: [addr, ...]} for each symbol found.
    IronPython's subprocess support inside Renode is unreliable for nm,
    so we resolve here and pass addresses directly.
    """
    import shutil
    nm_bin = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
    if not nm_bin or not elf_path or not symbols:
        return {}
    try:
        result = subprocess.run(
            [nm_bin, str(elf_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {}
    except Exception:
        return {}

    # Build lookup from nm output
    nm_entries: Dict[str, List[int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16) & ~1  # clear Thumb bit
            except ValueError:
                continue
            name = parts[2]
            nm_entries.setdefault(name, []).append(addr)

    resolved: Dict[str, List[int]] = {}
    for sym in symbols:
        if sym in nm_entries:
            resolved[sym] = sorted(nm_entries[sym])
    return resolved
EXIT_ASSERTION_FAILURE = 1
EXIT_INFRA_FAILURE = 2


def _trace_replay_eligible_fault_types(fault_types: List[str]) -> bool:
    normalized = {
        str(ft or "power_loss").split(":", 1)[0]
        for ft in fault_types or ["power_loss"]
    }
    return bool(normalized.intersection(TRACE_REPLAY_FAULT_TYPES))


def _can_skip_auto_calibration(profile: ProfileConfig, eval_mode: str) -> bool:
    """Return whether auto-calibration can be skipped for this execute sweep."""
    if eval_mode != "execute":
        return False

    fault_types = {str(ft or "").strip() for ft in profile.fault_sweep.fault_types or []}
    fault_types.discard("")
    if not fault_types:
        return False

    calibration_dependent_faults = {
        "power_loss",
        "swap_progress",
        "security_state_erase",
        "bit_corruption",
        "interrupted_erase",
        "multi_sector_atomicity",
        "silent_write_failure",
        "driver_error",
        "rc_injection",
        "write_disturb",
        "wear_leveling_corruption",
        "write_rejection",
        "reset_at_time",
        "command_drop",
    }
    if fault_types.intersection(calibration_dependent_faults):
        return False
    if any(ft.startswith("i2c_") or ft.startswith("otp_") for ft in fault_types):
        return False
    if profile.fault_sweep.metadata_fault.enabled:
        return False
    if profile.fault_sweep.phase2_fault.enabled:
        return False
    if profile.fault_sweep.multi_fault.enabled:
        return False

    return fault_types.issubset({"instruction_skip", "read_bit_flip", "nvs_corruption"})


def _can_fallback_to_control_only_calibration(
    profile: ProfileConfig,
    exc: Exception,
) -> bool:
    """Return whether a calibration failure can fall back to control-only reporting."""
    expect = getattr(profile, "expect", None)
    if expect is None:
        return False
    if not bool(getattr(expect, "allow_control_only_issues", False)):
        return False
    expected_outcome = str(getattr(expect, "control_outcome", "success") or "success")
    if expected_outcome == "success":
        return False
    message = str(exc)
    return (
        "Calibration did not complete cleanly" in message
        and "writes=0, erases=0" in message
    )


def _allow_expected_control_only_issues(profile: ProfileConfig) -> bool:
    """Return whether control-path issue counts are an expected broken baseline."""
    expect = getattr(profile, "expect", None)
    if expect is None:
        return False
    return bool(getattr(expect, "allow_control_only_issues", False))


def _multi_component_verdict(
    result: Dict[str, Any],
    profile: ProfileConfig,
) -> str:
    """Derive one fail-closed verdict from every observed component run."""
    per_component = result.get("per_component") or {}
    combined = result.get("combined_summary") or {}
    if not isinstance(per_component, dict) or not per_component:
        return "INCONCLUSIVE -- multi-component campaign produced no component results"

    issue_points = 0
    unreliable_points = 0
    control_failures: List[str] = []
    total_planned = 0
    component_profiles = {
        component.name: component.to_profile_config(profile)
        for component in profile.multi_component.components
    }
    configured_names = set(component_profiles)
    observed_names = set(per_component)
    if observed_names != configured_names:
        differences: List[str] = []
        missing = sorted(configured_names - observed_names)
        unexpected = sorted(observed_names - configured_names)
        if missing:
            differences.append("missing {}".format(", ".join(missing)))
        if unexpected:
            differences.append("unexpected {}".format(", ".join(unexpected)))
        return (
            "INCONCLUSIVE -- multi-component results did not match configured "
            "components ({})".format("; ".join(differences))
        )
    for name, data in per_component.items():
        if not isinstance(data, dict):
            return "INCONCLUSIVE -- component '{}' result was malformed".format(
                name
            )
        summary = data.get("summary") or {}
        if not isinstance(summary, dict) or summary.get("campaign_complete") is not True:
            return "INCONCLUSIVE -- component '{}' campaign was incomplete".format(
                name
            )
        component_planned = int(data.get("fault_points_tested", 0) or 0)
        if component_planned <= 0:
            return "INCONCLUSIVE -- component '{}' planned no fault points".format(
                name
            )
        total_planned += component_planned
        issue_points += int(summary.get("issue_points", summary.get("bricks", 0)) or 0)
        unreliable_points += sum(
            int(summary.get(key, 0) or 0)
            for key in (
                "infrastructure_error_points",
                "timeout_points",
                "discarded_no_fault_fired",
                "missing_result_points",
                "extra_result_points",
            )
        )
        control = summary.get("control") or {}
        expected = component_profiles[name].expect.control_outcome
        actual = (
            control.get("effective_outcome")
            or control.get("final_boot_outcome")
            or control.get("boot_outcome")
        )
        if actual != expected or int(control.get("issue_count", 0) or 0) > 0:
            control_failures.append(
                "{} expected {} but observed {}".format(name, expected, actual or "missing")
            )

    canonical_issue_points = combined.get("security_issue_points")
    if canonical_issue_points is None:
        # Legacy reports did not preserve point-level union accounting.  Keep
        # the security gate fail-closed without double-counting overlapping
        # component, combined-outcome, and relation observations.
        adverse_combined = sum(
            int(combined.get(key, 0) or 0)
            for key in ("split_brain", "all_failed", "degraded")
        )
        relation_findings = int(
            combined.get("state_relation_violations", 0) or 0
        )
        canonical_issue_points = max(
            issue_points, adverse_combined, relation_findings
        )
    else:
        canonical_issue_points = int(canonical_issue_points or 0)
    control_security_issue_points = int(
        combined.get("control_security_issue_points", 0) or 0
    )
    if result.get("control_invariant_violations") and not control_security_issue_points:
        # Backward-compatible fallback for an older in-memory producer.
        control_security_issue_points = 1
    found_issues = canonical_issue_points > 0
    if control_failures:
        return "FAIL -- component control checks failed: {}".format(
            "; ".join(control_failures)
        )
    if control_security_issue_points:
        return "FAIL -- component control state relation checks failed"
    if total_planned <= 0:
        return "INCONCLUSIVE -- multi-component campaign planned no fault points"
    if unreliable_points:
        return "INCONCLUSIVE -- {} component fault results were incomplete".format(
            unreliable_points
        )
    if profile.expect.should_find_issues and not found_issues:
        return "FAIL -- expected to find multi-component issues but found none"
    if not profile.expect.should_find_issues and found_issues:
        return "FAIL -- found {} component issues".format(
            canonical_issue_points
        )
    return "PASS"


def _aggregate_auxiliary_verdict(
    base_verdict: str,
    profile: ProfileConfig,
    *,
    state_fuzz_results: Optional[List[Dict[str, Any]]],
    state_fuzz_summary: Optional[Dict[str, Any]],
    fuzz_crash_results: Optional[List[Dict[str, Any]]],
    fuzz_crash_summary: Optional[Dict[str, Any]],
    geometry_preflight: Optional[Dict[str, Any]],
) -> str:
    """Fold every enabled campaign and preflight into the top verdict."""
    if geometry_preflight and geometry_preflight.get("status") == "mismatch":
        return "INCONCLUSIVE -- geometry preflight mismatch: {}".format(
            geometry_preflight.get("reason") or "compiled map differs from profile"
        )

    auxiliary_findings = 0
    if state_fuzz_summary is not None:
        requested = int(state_fuzz_summary.get("iterations_requested", 0) or 0)
        completed = int(state_fuzz_summary.get("iterations_completed", 0) or 0)
        if requested <= 0:
            return "INCONCLUSIVE -- state-fuzz campaign planned no scenarios"
        if completed != requested:
            return "INCONCLUSIVE -- state-fuzz completed {}/{} scenarios".format(
                completed, requested
            )
        if int(state_fuzz_summary.get("infrastructure_errors", 0) or 0):
            return "INCONCLUSIVE -- state-fuzz produced infrastructure errors"
        if int(state_fuzz_summary.get("timeouts", 0) or 0):
            return "INCONCLUSIVE -- state-fuzz produced timeouts"
        for entry in state_fuzz_results or []:
            outcome = str(entry.get("boot_outcome") or "unknown")
            if entry.get("infrastructure_error"):
                return "INCONCLUSIVE -- state-fuzz produced an infrastructure error"
            if entry.get("timeout"):
                return "INCONCLUSIVE -- state-fuzz produced a timeout"
            if outcome in {"infra_error", "timeout", "unknown"}:
                return "INCONCLUSIVE -- state-fuzz produced {}".format(outcome)
        reported_findings = int(state_fuzz_summary.get("findings", 0) or 0)
        observed_findings = sum(
            1 for entry in state_fuzz_results or [] if entry.get("finding")
        )
        if observed_findings != reported_findings:
            return "INCONCLUSIVE -- state-fuzz finding count is inconsistent"
        auxiliary_findings += reported_findings

    if fuzz_crash_summary is not None:
        expected_results = int(fuzz_crash_summary.get("generated_profiles", 0) or 0)
        completed_results = int(fuzz_crash_summary.get("results", 0) or 0)
        if expected_results <= 0:
            return "INCONCLUSIVE -- fuzz-crash campaign generated no regressions"
        if completed_results != expected_results:
            return "INCONCLUSIVE -- fuzz-crash completed {}/{} regressions".format(
                completed_results, expected_results
            )
        for entry in fuzz_crash_results or []:
            returncode = int(entry.get("returncode", -1))
            if returncode != 0:
                return "INCONCLUSIVE -- fuzz-crash child exited with status {}".format(
                    returncode
                )
            child_verdict = str(entry.get("verdict") or "")
            if not child_verdict:
                return "INCONCLUSIVE -- fuzz-crash regression produced no verdict"
            if not is_pass_verdict(child_verdict):
                return "FAIL -- fuzz-crash regression failed: {}".format(
                    child_verdict
                )
        reported_security_findings = int(
            fuzz_crash_summary.get("security_findings", 0) or 0
        )
        observed_security_findings = sum(
            1 for entry in fuzz_crash_results or [] if entry.get("security_finding")
        )
        if observed_security_findings != reported_security_findings:
            return "INCONCLUSIVE -- fuzz-crash finding count is inconsistent"
        auxiliary_findings += reported_security_findings

    if auxiliary_findings:
        if not profile.expect.should_find_issues:
            return "FAIL -- auxiliary campaigns found {} issues".format(
                auxiliary_findings
            )
        if "expected to find issues but found none" in base_verdict:
            return "PASS"
    return base_verdict


def _merge_calibration_expected_exec_hash(
    robot_vars: List[str],
    calibration_exec_hash: str,
    calibration_boot_outcome: Optional[str] = None,
) -> Tuple[List[str], bool]:
    """Use calibration ground-truth exec hash as the expected hash.

    The calibration runs the bootloader cleanly (no faults) and hashes
    the exec slot after boot.  This is the empirical ground truth for
    what a correct operation produces — bootloaders legitimately modify
    the data region during swap (headers, TLVs, status bytes), so the
    file-based hash from ``expected_image`` will not match.

    Only override when the calibration control boot actually succeeded
    (``boot_outcome == 'success'``).  If the calibration boot itself
    was broken (wrong_image, no_boot), the hash reflects incorrect
    behavior and must NOT replace the profile's expected hash.
    """
    if not calibration_exec_hash:
        return robot_vars, False
    # Only trust the calibration hash when the control boot explicitly
    # succeeded.  Missing outcome data is not evidence of a clean baseline.
    if calibration_boot_outcome != "success":
        return robot_vars, False
    # Check whether the profile already declared an expected hash.
    profile_declared = False
    for var in robot_vars:
        key, sep, value = var.partition(":")
        if key == "EXPECTED_EXEC_SHA256" and sep and value:
            profile_declared = True
            break
    if profile_declared:
        return robot_vars, False
    # Populate only an otherwise-undeclared expectation.
    return merge_robot_vars(
        robot_vars,
        ["EXPECTED_EXEC_SHA256:{}".format(calibration_exec_hash)],
    ), True


def _without_hash_bypass(robot_vars: List[str]) -> List[str]:
    """Return clean-control variables with all bypass inputs removed."""
    return [
        value
        for value in robot_vars
        if not value.startswith("HASH_BYPASS_SYMBOLS:")
        and not value.startswith("HASH_BYPASS_ADDRS:")
    ]


def _validate_profile_asset_containment(
    profile: ProfileConfig,
    repo_root: Path,
) -> None:
    """Require every strict-profile runtime asset to stay under repo_root."""
    root = repo_root.resolve(strict=True)

    def validate(raw_path: Optional[str], label: str) -> None:
        if not raw_path:
            return
        candidate = Path(profile.resolve_path(root, raw_path)).resolve(strict=True)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(
                "strict profile asset escapes repository root: {}={}".format(
                    label, raw_path
                )
            ) from exc
        if not candidate.is_file():
            raise RuntimeError(
                "strict profile asset is not a file: {}={}".format(label, raw_path)
            )

    def validate_one(current: ProfileConfig, prefix: str) -> None:
        validate(current.platform, prefix + "platform")
        validate(current.bootloader_elf, prefix + "bootloader.elf")
        validate(current.firmware_elf, prefix + "firmware_elf")
        validate(current.setup_script, prefix + "setup_script")
        for name, path in current.images.items():
            validate(path, prefix + "images." + name)
        for index, path in enumerate(current.extra_peripherals):
            validate(path, prefix + "extra_peripherals[{}]".format(index))
        if current.state_probe is not None:
            validate(current.state_probe.script, prefix + "state_probe.script")
        for index, path in enumerate(current.invariant_providers):
            validate(path, prefix + "invariant_providers[{}]".format(index))
        validate(current.fuzz_corpus, prefix + "fuzz_corpus")
        if current.residual_image is not None:
            validate(
                current.residual_image.prior_image,
                prefix + "residual_image.prior_image",
            )
        if current.nvs_region is not None:
            validate(current.nvs_region.snapshot, prefix + "nvs_region.snapshot")
        validate(
            current.fault_sweep.boot_cycle_hook,
            prefix + "fault_sweep.boot_cycle_hook",
        )
        partial_staging = current.fault_sweep.partial_staging
        if isinstance(partial_staging, dict):
            validate(
                partial_staging.get("staging_image"),
                prefix + "fault_sweep.partial_staging.staging_image",
            )
        for phase_index, phase in enumerate(current.update_sequence):
            phase_prefix = prefix + "update_sequence[{}].".format(phase_index)
            validate(phase.setup_script, phase_prefix + "setup_script")
            validate(phase.boot_cycle_hook, phase_prefix + "boot_cycle_hook")
            for name, path in phase.images.items():
                validate(path, phase_prefix + "images." + name)
            for name, path in phase.start_images.items():
                validate(path, phase_prefix + "start_images." + name)

    validate_one(profile, "")
    for index, component in enumerate(profile.component_profiles()):
        validate_one(component, "multi_component[{}].".format(index))


def _requested_zero_fault_points(args: argparse.Namespace) -> bool:
    """Return whether CLI bounds request a zero-point execute sweep."""
    if args.fault_end is None:
        return False
    start = 0 if args.fault_start is None else int(args.fault_start)
    end = int(args.fault_end)
    return end <= start


def _profile_requests_zero_fault_points(max_writes: object) -> bool:
    """Return whether the profile explicitly requests a control-only execute run."""
    if isinstance(max_writes, str):
        if max_writes.strip().lower() == "auto":
            return False
        try:
            return int(max_writes, 0) <= 0
        except ValueError:
            return False
    try:
        return int(max_writes) <= 0
    except (TypeError, ValueError):
        return False


def _write_trigger_discovery_failure(
    *,
    args: argparse.Namespace,
    profile: ProfileConfig,
    repo_root: Path,
    report_artifacts_dir: str,
    discovery: TriggerDiscoveryResult,
) -> None:
    verdict = "INCONCLUSIVE -- could not trigger firmware update."
    checks = [
        "Is the staging image valid for this bootloader? (header, signature, version)",
        "Do the declared slots match the bootloader's compiled flash map and erase-sector layout?",
        "Does the bootloader require a different trigger mechanism?",
    ]
    payload: Dict[str, Any] = {
        "engine": "renode-test",
        "profile": profile.name,
        "profile_path": str(profile.profile_path) if profile.profile_path else None,
        "schema_version": profile.schema_version,
        "verdict": verdict,
        "summary": {
            "trigger_discovery": discovery.to_summary(),
        },
        "expect": {
            "should_find_issues": profile.expect.should_find_issues,
        },
        "calibration": {
            "performed": False,
            "source": "trigger_discovery_failed",
            "writes": 0,
            "erases": 0,
            "coverage": None,
        },
        "trigger_discovery": {
            **discovery.to_summary(),
            "checks": checks,
        },
        "execution": {
            "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "campaign_command": " ".join(shlex.quote(a) for a in (["python3"] + sys.argv)),
            "artifacts_dir": report_artifacts_dir,
            "workers": args.workers,
        },
        "git": git_metadata(repo_root),
    }
    attach_security_aggregate(payload)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "profile": profile.name,
                "verdict": verdict,
                "summary": payload["summary"],
            },
            indent=2,
            sort_keys=True,
        )
    )


def _write_geometry_preflight_failure(
    *,
    args: argparse.Namespace,
    profile: ProfileConfig,
    repo_root: Path,
    geometry: Dict[str, Any],
) -> None:
    verdict = "INCONCLUSIVE -- geometry preflight mismatch: {}".format(
        geometry.get("reason") or "compiled map differs from profile"
    )
    payload = {
        "engine": "renode-test",
        "profile": profile.name,
        "profile_path": str(profile.profile_path) if profile.profile_path else None,
        "schema_version": profile.schema_version,
        "verdict": verdict,
        "summary": {"geometry_preflight": geometry},
        "expect": {"should_find_issues": profile.expect.should_find_issues},
        "execution": {
            "run_utc": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        },
        "git": git_metadata(repo_root),
    }
    attach_security_aggregate(payload)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "profile": profile.name,
                "verdict": verdict,
                "summary": payload["summary"],
            },
            indent=2,
            sort_keys=True,
        )
    )


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
    parser.add_argument(
        "--repo-root",
        default="",
        help=(
            "Override repo root path. Useful when running via symlinks to "
            "avoid space-in-path issues (e.g. /tmp/tardigrade_repo)."
        ),
    )
    parser.add_argument(
        "--strict-profile",
        action="store_true",
        help="Reject unknown profile fields and missing observable success criteria.",
    )
    parser.add_argument(
        "--authorization-review-trace", "--trace",
        dest="authorization_review_traces", action="append", default=[],
        metavar="PATH",
        help="Authorization-review trace JSON (repeatable; requires authorization_review).",
    )
    parser.add_argument(
        "--reuse-calibration",
        default="",
        metavar="PATH",
        help=(
            "Path to a calibration cache JSON file. If the file exists and "
            "the cache key matches, calibration is loaded from it instead of "
            "running Renode. After a fresh calibration the result is saved "
            "to this path for future reuse."
        ),
    )
    parser.add_argument(
        "--reuse-calibration-sha256",
        default="",
        metavar="SHA256",
        help=(
            "Require --reuse-calibration to match this exact SHA-256 before "
            "loading it. Use this when the cache crosses a trust boundary."
        ),
    )
    parser.add_argument(
        "--trust-unsigned-calibration-cache",
        action="store_true",
        help=(
            "Load an existing cache without a trusted digest. Only use for a "
            "local cache that untrusted writers cannot modify."
        ),
    )
    parser.add_argument(
        "--initial-state",
        default="",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 64:
        parser.error("--workers must be between 1 and 64")
    if args.fault_step < 1:
        parser.error("--fault-step must be at least 1")
    if args.max_batch_points < 0 or args.max_batch_points > 100000:
        parser.error("--max-batch-points must be between 0 and 100000")
    if args.fault_start is not None and args.fault_start < 0:
        parser.error("--fault-start must be non-negative")
    if args.fault_end is not None and args.fault_end < 0:
        parser.error("--fault-end must be non-negative")
    if args.reuse_calibration_sha256:
        digest = args.reuse_calibration_sha256.strip().lower()
        if not args.reuse_calibration:
            parser.error("--reuse-calibration-sha256 requires --reuse-calibration")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            parser.error("--reuse-calibration-sha256 must be 64 hexadecimal characters")
        args.reuse_calibration_sha256 = digest
    if args.trust_unsigned_calibration_cache and not args.reuse_calibration:
        parser.error(
            "--trust-unsigned-calibration-cache requires --reuse-calibration"
        )
    return args


def _compute_calibration_cache_key(
    profile: ProfileConfig,
    repo_root: Path,
    renode_test: str = "",
    robot_suite: str = "",
    robot_vars: Optional[List[str]] = None,
    renode_remote_server_dir: str = "",
) -> str:
    """Compute a cache key for calibration based on profile inputs."""
    resolved_images = {
        name: profile.resolve_path(repo_root, path)
        for name, path in profile.images.items()
    }
    if profile.firmware_elf:
        resolved_images["firmware_elf"] = profile.resolve_path(
            repo_root, profile.firmware_elf
        )
    if profile.nvs_region is not None and profile.nvs_region.snapshot:
        resolved_images["nvs_region_snapshot"] = profile.resolve_path(
            repo_root, profile.nvs_region.snapshot
        )
    if (
        profile.residual_image is not None
        and profile.residual_image.prior_image
    ):
        resolved_images["residual_image_prior"] = profile.resolve_path(
            repo_root, profile.residual_image.prior_image
        )
    setup_files: Dict[str, str] = {}
    hook_files: Dict[str, str] = {}
    if profile.setup_script:
        setup_files["profile"] = profile.resolve_path(repo_root, profile.setup_script)
    boot_cycle_hook = profile.fault_sweep.boot_cycle_hook
    if boot_cycle_hook:
        candidate = profile.resolve_path(repo_root, boot_cycle_hook)
        if os.path.isfile(candidate):
            hook_files["profile"] = candidate
    if profile.state_probe is not None and profile.state_probe.script:
        candidate = profile.resolve_path(repo_root, profile.state_probe.script)
        if os.path.isfile(candidate):
            hook_files["state_probe"] = candidate
    for index, provider in enumerate(profile.invariant_providers):
        candidate = profile.resolve_path(repo_root, provider)
        if os.path.isfile(candidate):
            hook_files["invariant_provider{}".format(index)] = candidate
    for index, phase in enumerate(profile.update_sequence):
        for name, path in sorted(phase.images.items()):
            resolved_images["phase{}:{}".format(index, name)] = profile.resolve_path(
                repo_root, path
            )
        for name, path in sorted(phase.start_images.items()):
            resolved_images["phase{}:start:{}".format(index, name)] = profile.resolve_path(
                repo_root, path
            )
        if phase.setup_script:
            setup_files["phase{}".format(index)] = profile.resolve_path(
                repo_root, phase.setup_script
            )
        if phase.boot_cycle_hook:
            candidate = profile.resolve_path(repo_root, phase.boot_cycle_hook)
            if os.path.isfile(candidate):
                hook_files["phase{}".format(index)] = candidate

    platform_files = {
        "platform": profile.resolve_path(repo_root, profile.platform),
        "runtime_fault_sweep": str(
            (REPO_ROOT / "scripts" / "run_runtime_fault_sweep.py").resolve()
        ),
    }
    # Platform descriptions and setup scripts can include other repo-native
    # files.  Hash the full public platform/RESC surface conservatively so an
    # indirect include can never leave a stale trace cache valid.
    for pattern in ("platforms/**/*.repl", "scripts/**/*.resc"):
        for candidate in sorted(repo_root.glob(pattern)):
            if candidate.is_file():
                platform_files["repo:{}".format(candidate.relative_to(repo_root))] = str(
                    candidate.resolve()
                )
    robot_suite_path = Path(robot_suite)
    if robot_suite and not robot_suite_path.is_absolute():
        robot_suite_path = repo_root / robot_suite_path
    if robot_suite and robot_suite_path.is_file():
        platform_files["robot_suite"] = str(robot_suite_path.resolve())
    for peripheral_path in sorted((REPO_ROOT / "peripherals").glob("*.cs")):
        platform_files["builtin:{}".format(peripheral_path.name)] = str(
            peripheral_path.resolve()
        )
    for index, peripheral in enumerate(profile.extra_peripherals):
        candidate = profile.resolve_path(repo_root, peripheral)
        if os.path.isfile(candidate):
            platform_files["peripheral{}".format(index)] = candidate

    renode_identity = _renode_cache_identity(
        renode_test,
        renode_remote_server_dir=renode_remote_server_dir,
    )
    return compute_cache_key(
        bootloader_elf=profile.resolve_path(repo_root, profile.bootloader_elf),
        images=resolved_images,
        fault_types=list(profile.fault_sweep.fault_types or []),
        flash_backend=profile.flash_backend,
        memory_slots=profile.memory.slots,
        pre_boot_state=list(profile.pre_boot_state),
        hash_bypass_symbols=list(profile.fault_sweep.sweep_hash_bypass_symbols or []),
        write_granularity=profile.memory.write_granularity,
        platform_files=platform_files,
        setup_files=setup_files,
        hook_files=hook_files,
        entry_point=profile.bootloader_entry,
        image_load_addresses=profile.effective_image_load_addresses(),
        tool_versions={"renode": renode_identity},
        runtime_config={
            "robot_suite": robot_suite,
            "fault_sweep": profile.fault_sweep,
            # Keep the activation boundary explicit in the cache material even
            # when callers omit the generated Robot variable list.
            "tracking_start_address": profile.fault_sweep.tracking_start_address,
            "memory": profile.memory,
            "success_criteria": profile.success_criteria,
            "success_criteria_overrides": profile.success_criteria_overrides,
            "security_policy": profile.security_policy,
            "state_probe": profile.state_probe,
            "semantic_assertions": profile.semantic_assertions,
            "invariants": profile.invariants,
            "invariant_config": profile.invariant_config,
            "expect_control_outcome": profile.expect.control_outcome,
            "bootloader_region": profile.bootloader_region,
            "update_trigger": profile.update_trigger,
            "update_sequence": profile.update_sequence,
            "extra_peripherals": profile.extra_peripherals,
            "nvm_controller": profile.nvm_controller,
            "otp_peripheral": profile.otp_peripheral,
            "boot_register_pre_writes": profile.boot_register_pre_writes,
            "residual_image": profile.residual_image,
            "terminal_error_paths": [
                item.to_dict() for item in getattr(profile, "terminal_error_paths", [])
            ],
            "nvs_region": profile.nvs_region,
            "boundary_campaign": (
                {
                    "name": profile.boundary_campaign.name,
                    "parameter": profile.boundary_campaign.parameter,
                    "setup_environment": profile.boundary_campaign.setup_environment,
                    "value": profile.boundary_value,
                    "previous_value": profile.boundary_previous_value,
                }
                if getattr(profile, "boundary_campaign", None) is not None
                else None
            ),
            "boundary_campaigns": [
                boundary_campaign_dict(item)
                for item in getattr(profile, "boundary_campaigns", [])
            ],
            "effective_calibration_robot_vars": _cache_robot_var_material(
                robot_vars or []
            ),
        },
    )


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_robot_var_material(robot_vars: List[str]) -> List[Dict[str, str]]:
    """Normalize effective Robot variables, hashing every file-valued input."""
    generated_file_keys = {
        "PRE_BOOT_STATE_BIN",
        "UPDATE_SEQUENCE_FILE",
        "SUCCESS_CRITERIA_OVERRIDES_FILE",
    }
    material: List[Dict[str, str]] = []
    for raw in robot_vars:
        key, separator, value = str(raw).partition(":")
        entry = {
            "key": key,
            "value": value if separator else "",
        }
        if not separator:
            entry["raw"] = str(raw)
            material.append(entry)
            continue
        try:
            candidate = Path(value)
            if value and candidate.is_file():
                entry["file_sha256"] = _sha256_path(candidate.resolve())
                # Generated temp names vary on every invocation; their bytes
                # are the semantic input and therefore the stable identity.
                if key in generated_file_keys:
                    entry["value"] = "<generated-file>"
        except OSError:
            # The raw value remains in the key and runtime will report an
            # unreadable input if it is intended to be a file.
            pass
        material.append(entry)
    return material


def _renode_cache_identity(
    renode_test: str,
    *,
    renode_remote_server_dir: str = "",
) -> str:
    """Return a fail-closed identity for the Renode implementation in use."""
    spec = str(renode_test or "unspecified")
    if spec.startswith("docker://"):
        image = spec[len("docker://"):]
        if not image:
            raise RuntimeError("Docker Renode runner is missing an image reference")
        if "@sha256:" in image:
            return "docker:{}".format(image)
        try:
            inspected = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                "calibration reuse with a mutable Docker tag requires a locally "
                "inspectable image ID or an @sha256 digest"
            ) from exc
        image_id = inspected.stdout.strip() if inspected.returncode == 0 else ""
        if not image_id.startswith("sha256:"):
            raise RuntimeError(
                "calibration reuse with Docker tag {!r} requires a locally "
                "inspectable image ID or an @sha256 digest".format(image)
            )
        return "docker:{}@{}".format(image, image_id)

    identity: Dict[str, Any] = {"command": spec}
    runner = Path(spec)
    if runner.is_file():
        resolved_runner = runner.resolve()
        identity["runner_sha256"] = _sha256_path(resolved_runner)
        candidate_roots = [
            resolved_runner.parent,
            resolved_runner.parent / "bin",
            resolved_runner.parent.parent / "bin",
            resolved_runner.parent / "lib" / "renode",
        ]
        if renode_remote_server_dir:
            candidate_roots.append(Path(renode_remote_server_dir))
        core_digests: Dict[str, str] = {}
        seen_paths: set[Path] = set()
        for root in candidate_roots:
            for name in ("Renode.dll", "Renode.exe"):
                candidate = root / name
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, FileNotFoundError):
                    continue
                if resolved in seen_paths or not resolved.is_file():
                    continue
                seen_paths.add(resolved)
                core_digests["{}:{}".format(name, len(core_digests))] = _sha256_path(
                    resolved
                )
        if core_digests:
            identity["core_sha256"] = core_digests

    if spec != "unspecified":
        try:
            version_proc = subprocess.run(
                [spec, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            version_text = (version_proc.stdout or version_proc.stderr).strip()
            if version_proc.returncode == 0 and version_text:
                identity["version"] = version_text.splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            pass
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _cleanup_generated_robot_files(robot_vars: List[str]) -> None:
    for prefix in (
        "PRE_BOOT_STATE_BIN:",
        "UPDATE_SEQUENCE_FILE:",
    ):
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
    # Overlay child-run variables by key so a follow-up's N-1 transport value
    # replaces the resolved candidate default rather than relying on Robot's
    # duplicate-variable precedence.
    robot_vars = merge_robot_vars(profile.robot_vars(repo_root), list(extra_robot_vars))
    robot_vars.append("EVALUATION_MODE:{}".format(evaluation_mode))
    robot_vars.append("PROGRESS_STALL_TIMEOUT_S:{:.6f}".format(stall_timeout))
    robot_vars.append(
        "EXPECT_CONTROL_OUTCOME:{}".format(profile.expect.control_outcome)
    )
    return robot_vars


def _multi_component_campaign_robot_vars(
    extra_robot_vars: List[str],
    stall_timeout: float,
) -> List[str]:
    """Return only profile-independent variables for component overlays."""
    return merge_robot_vars(
        extra_robot_vars,
        ["PROGRESS_STALL_TIMEOUT_S:{:.6f}".format(stall_timeout)],
    )


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
        annotate_result_checks([data], scenario_profile, repo_root=repo_root)
        results.append(
            extract_state_fuzz_result(
                scenario=scenario,
                result=data,
                expected_outcome=profile.expect.control_outcome,
                metadata_model=model,
            )
        )

    summary = summarize_state_campaign(
        results,
        expected_outcome=profile.expect.control_outcome,
        metadata_model=profile.state_fuzzer.metadata_model,
        iterations=profile.state_fuzzer.iterations,
    )
    for warning in summary.get("warnings") or []:
        _progress("state_fuzz WARNING: {}".format(warning))
    return results, summary


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
    if args.repo_root:
        cmd.extend(["--repo-root", args.repo_root])
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
            child_verdict = str(audit_payload.get("verdict", ""))
            child_passed = is_pass_verdict(child_verdict)
            security_finding = bool(
                proc.returncode == 0
                and audit_payload.get("expect", {}).get("should_find_issues")
                and child_passed
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
            if proc.returncode != 0:
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



def _main_single() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root) if args.repo_root else REPO_ROOT
    temp_ctx: Optional[tempfile.TemporaryDirectory[str]] = None

    try:
        profile = load_profile(args.profile, strict=args.strict_profile)
        if args.initial_state:
            matches = [
                state
                for state in profile.initial_states
                if state.name == args.initial_state
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    "initial state {!r} was not declared exactly once by {}".format(
                        args.initial_state, args.profile
                    )
                )
            profile = profile.resolve_initial_state(matches[0])
        if args.strict_profile:
            _validate_profile_asset_containment(profile, repo_root)
        authorization_review_analysis = None
        if getattr(profile, "authorization_review", None) is not None:
            authorization_traces = [load_trace(path) for path in args.authorization_review_traces]
            authorization_review_analysis = analyze_authorization_review(
                profile.authorization_review, authorization_traces
            )
        elif args.authorization_review_traces:
            raise RuntimeError("authorization-review traces were provided but profile has no authorization_review block")
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

        # Stall timeout: CLI overrides profile, profile overrides default.
        stall_timeout = args.progress_stall_timeout_s
        cli_explicitly_set = any(
            a.startswith("--progress-stall-timeout") for a in sys.argv
        )
        if not cli_explicitly_set and profile.fault_sweep.progress_stall_timeout_s is not None:
            stall_timeout = profile.fault_sweep.progress_stall_timeout_s
        extra_robot_vars = parse_robot_vars(args.robot_var)
        robot_vars = _common_robot_vars(
            profile,
            repo_root,
            evaluation_mode=eval_mode,
            stall_timeout=stall_timeout,
            extra_robot_vars=extra_robot_vars,
        )
        # Follow-up children intentionally reuse the candidate initial-state
        # profile while overriding only the fixed transport value.  Echo the
        # effective value in the report, rather than the profile's original N,
        # so the host can prove that the child actually ran N-1.
        boundary_report_value = getattr(profile, "boundary_value", None)
        for robot_var in robot_vars:
            key, separator, raw_value = str(robot_var).partition(":")
            if key == "BOUNDARY_VALUE" and separator:
                try:
                    boundary_report_value = int(raw_value, 10)
                except (TypeError, ValueError):
                    boundary_report_value = None
                break

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
                # Only campaign-level CLI values belong in the base layer.
                # Passing the parent's fully rendered profile variables here
                # lets conditional settings (for example image hashing or a
                # structured success-check contract) leak into components that
                # intentionally omit them.
                robot_vars_base=_multi_component_campaign_robot_vars(
                    extra_robot_vars,
                    stall_timeout,
                ),
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

            # Determine a verdict from all per-component controls, fault
            # results, and combined outcomes.
            combined_summary = mc_result["combined_summary"]
            mc_verdict = _multi_component_verdict(mc_result, profile)
            if authorization_review_analysis is not None:
                if authorization_review_analysis["verdict"] == "FAIL":
                    mc_verdict = "FAIL -- authorization review analysis found a mismatch"
                elif authorization_review_analysis["verdict"] != "PASS":
                    mc_verdict = "INCONCLUSIVE -- authorization review evidence incomplete"

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
                "control_combined_result": mc_result.get(
                    "control_combined_result"
                ),
                "control_state": mc_result.get("control_state"),
                "control_invariant_violations": mc_result.get(
                    "control_invariant_violations", []
                ),
                "authorization_review_analysis": authorization_review_analysis,
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

            attach_security_aggregate(payload)
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

            if not is_pass_verdict(mc_verdict) and not args.no_assert_verdict:
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

        discovery: Optional[TriggerDiscoveryResult] = None
        geometry_preflight: Optional[Dict[str, Any]] = None
        max_writes = profile.fault_sweep.max_writes
        zero_point_execute_request = eval_mode == "execute" and (
            _requested_zero_fault_points(args)
            or _profile_requests_zero_fault_points(max_writes)
        )
        if zero_point_execute_request:
            robot_vars = merge_robot_vars(
                robot_vars,
                ["ZERO_POINT_EXECUTE_CONTROL:true"],
            )

        if should_auto_discover_trigger(profile, eval_mode) and not zero_point_execute_request:
            discovery = discover_update_trigger(
                profile,
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                work_dir=work_dir,
                renode_remote_server_dir=args.renode_remote_server_dir,
                keep_run_artifacts=args.keep_run_artifacts,
                robot_vars_factory=lambda candidate: _common_robot_vars(
                    candidate,
                    repo_root,
                    evaluation_mode=eval_mode,
                    stall_timeout=min(float(stall_timeout), 10.0),
                    extra_robot_vars=extra_robot_vars,
                ),
            )
            if not discovery.succeeded:
                _write_trigger_discovery_failure(
                    args=args,
                    profile=profile,
                    repo_root=repo_root,
                    report_artifacts_dir=report_artifacts_dir,
                    discovery=discovery,
                )
                if args.no_assert_verdict:
                    return 0
                return EXIT_ASSERTION_FAILURE
            profile = discovery.selected_profile or profile
            robot_vars = discovery.selected_robot_vars or robot_vars
            print(
                "Trigger discovery selected '{}' for '{}'.".format(
                    discovery.selected_strategy,
                    profile.name,
                ),
                file=sys.stderr,
            )
        else:
            geometry_preflight = validate_compiled_flash_map(profile, repo_root)
            if geometry_preflight.get("status") == "mismatch":
                _write_geometry_preflight_failure(
                    args=args,
                    profile=profile,
                    repo_root=repo_root,
                    geometry=geometry_preflight,
                )
                return 0 if args.no_assert_verdict else EXIT_ASSERTION_FAILURE

        # -------------------------------------------------------------------
        # Calibration
        # -------------------------------------------------------------------
        cal: Optional[CalibrationResult] = (
            discovery.selected_calibration if discovery is not None else None
        )
        trace_file: Optional[str] = None
        erase_trace_file: Optional[str] = None
        trace_file_bin: Optional[str] = None
        erase_trace_file_bin: Optional[str] = None
        total_erases: int = 0
        total_i2c_transactions: int = 0
        total_otp_blows: int = 0
        setup_writes: int = 0
        calibration_source_override: Optional[str] = (
            "trigger_discovery" if cal is not None else None
        )
        control_only_calibration_fallback: Optional[str] = None
        # Determine whether erase-trace capture is needed during calibration.
        fault_types = profile.fault_sweep.fault_types
        include_erases = (
            "interrupted_erase" in fault_types
            or "multi_sector_atomicity" in fault_types
        )
        include_erase_trace = include_erases or "swap_progress" in fault_types
        include_erase_trace = include_erase_trace or "security_state_erase" in fault_types

        # Pass fault_types to calibration so erase trace is captured.
        if include_erase_trace:
            robot_vars.append("FAULT_TYPES:both")

        should_calibrate_for_trace = (
            eval_mode == "execute"
            and not args.no_trace_replay
            and _trace_replay_eligible_fault_types(fault_types)
        )
        # Prepare hash bypass for faulted sweep runs only.  Calibration and
        # clean controls always execute without bypass so they remain a
        # trustworthy baseline.
        # Auto-disable when instruction_skip is a fault type — hash bypass
        # patches SHA-256 to return 0, which breaks image validation and
        # makes instruction_skip findings meaningless.
        effective_no_hash_bypass = bool(args.no_hash_bypass)
        if not effective_no_hash_bypass:
            bypass_syms = list(profile.fault_sweep.sweep_hash_bypass_symbols or [])
            if bypass_syms and "instruction_skip" in fault_types:
                print(
                    "WARNING: sweep_hash_bypass_symbols disabled — "
                    "incompatible with instruction_skip fault type",
                    file=sys.stderr,
                )
                bypass_syms = []
                effective_no_hash_bypass = True
            if bypass_syms:
                robot_vars.append(
                    "HASH_BYPASS_SYMBOLS:{}".format(",".join(bypass_syms))
                )
                # Pre-resolve symbol addresses on the host side so the
                # Renode-embedded IronPython doesn't need to call nm.
                elf_path = profile.resolve_path(repo_root, profile.bootloader_elf)
                pre_resolved = _resolve_hash_bypass_addresses(elf_path, bypass_syms)
                if pre_resolved:
                    addr_parts = []
                    for sym, addrs in pre_resolved.items():
                        for addr in addrs:
                            addr_parts.append("{}=0x{:08X}".format(sym, addr))
                    robot_vars.append(
                        "HASH_BYPASS_ADDRS:{}".format(",".join(addr_parts))
                    )

        if max_writes == "auto":
            if zero_point_execute_request:
                max_writes = int(profile.fault_sweep.max_writes_cap)
                calibration_source_override = "skipped_control_only"
                print(
                    "Skipping calibration for '{}' — zero fault points requested; "
                    "using control budget {} writes.".format(
                        profile.name,
                        max_writes,
                    ),
                    file=sys.stderr,
                )
            elif eval_mode == "state" and "exec" in profile.memory.slots:
                # State mode: compute write count from slot geometry.
                exec_slot = profile.memory.slots["exec"]
                max_writes = exec_slot.size // profile.memory.write_granularity
                print("Computed write count from slot geometry: {} writes.".format(max_writes), file=sys.stderr)
            elif _can_skip_auto_calibration(profile, eval_mode):
                max_writes = 0
                print(
                    "Skipping calibration for '{}' — fault points derive from "
                    "configured regions/symbols without write-count tracing.".format(
                        profile.name
                    ),
                    file=sys.stderr,
                )
            else:
                # Try loading from calibration cache.
                _cal_cache_path = args.reuse_calibration
                _cal_cache_key = ""
                if _cal_cache_path:
                    _cal_cache_key = _compute_calibration_cache_key(
                        profile,
                        repo_root,
                        renode_test=renode_test,
                        robot_suite=robot_suite,
                        robot_vars=_without_hash_bypass(robot_vars),
                        renode_remote_server_dir=args.renode_remote_server_dir,
                    )
                    cal = load_calibration(
                        _cal_cache_path,
                        _cal_cache_key,
                        work_dir,
                        expected_sha256=args.reuse_calibration_sha256 or None,
                        allow_unsigned=args.trust_unsigned_calibration_cache,
                    )
                    if cal is not None:
                        print(
                            "Loaded calibration from cache: {}".format(_cal_cache_path),
                            file=sys.stderr,
                        )

                if cal is None:
                    print("Calibrating write count for '{}'...".format(profile.name), file=sys.stderr)
                    try:
                        cal = run_calibration(
                            repo_root=repo_root,
                            renode_test=renode_test,
                            robot_suite=robot_suite,
                            profile=profile,
                            robot_vars=_without_hash_bypass(robot_vars),
                            work_dir=work_dir,
                            renode_remote_server_dir=args.renode_remote_server_dir,
                            keep_run_artifacts=args.keep_run_artifacts,
                        )
                    except RuntimeError as exc:
                        if not _can_fallback_to_control_only_calibration(profile, exc):
                            raise
                        control_only_calibration_fallback = str(exc)
                        calibration_source_override = "control_only_fallback"
                        max_writes = 0
                        total_erases = 0
                        setup_writes = 0
                        total_i2c_transactions = 0
                        total_otp_blows = 0
                        trace_file = None
                        erase_trace_file = None
                        trace_file_bin = None
                        erase_trace_file_bin = None
                        cal = None
                        print(
                            "Calibration fallback: {}. Proceeding with control-only execute report.".format(
                                exc
                            ),
                            file=sys.stderr,
                        )
                    if _cal_cache_path and cal is not None:
                        save_calibration(_cal_cache_path, cal, _cal_cache_key)
                        print(
                            "Saved calibration to cache: {}".format(_cal_cache_path),
                            file=sys.stderr,
                        )
                if cal is not None:
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
                        robot_vars, discovered_hash_used = _merge_calibration_expected_exec_hash(
                            robot_vars,
                            cal.calibration_exec_hash,
                            cal.calibration_boot_outcome,
                        )
                        message = (
                            "Calibration: populated undeclared exec slot hash = {}..."
                            if discovered_hash_used
                            else "Calibration: retained declared exec slot hash; observed {}..."
                        )
                        print(
                            message.format(cal.calibration_exec_hash[:16]),
                            file=sys.stderr,
                        )
                    setup_writes = cal.setup_writes
                    total_i2c_transactions = cal.total_i2c_transactions
                    total_otp_blows = cal.total_otp_blows
                    cal_parts = ["{} NVM writes".format(max_writes)]
                    if include_erase_trace:
                        cal_parts.append("{} page erases".format(total_erases))
                    if total_i2c_transactions > 0:
                        cal_parts.append("{} I2C transactions".format(total_i2c_transactions))
                    if total_otp_blows > 0:
                        cal_parts.append("{} OTP blows".format(total_otp_blows))
                    print("Calibration: {}.".format(", ".join(cal_parts)), file=sys.stderr)
        else:
            max_writes = int(max_writes)
            if zero_point_execute_request:
                calibration_source_override = "skipped_control_only"
                print(
                    "Skipping trace calibration for '{}' — zero fault points requested.".format(
                        profile.name
                    ),
                    file=sys.stderr,
                )
            elif should_calibrate_for_trace:
                # Try loading from calibration cache.
                _cal_cache_path = args.reuse_calibration
                _cal_cache_key = ""
                if _cal_cache_path:
                    _cal_cache_key = _compute_calibration_cache_key(
                        profile,
                        repo_root,
                        renode_test=renode_test,
                        robot_suite=robot_suite,
                        robot_vars=_without_hash_bypass(robot_vars),
                        renode_remote_server_dir=args.renode_remote_server_dir,
                    )
                    cal = load_calibration(
                        _cal_cache_path,
                        _cal_cache_key,
                        work_dir,
                        expected_sha256=args.reuse_calibration_sha256 or None,
                        allow_unsigned=args.trust_unsigned_calibration_cache,
                    )
                    if cal is not None:
                        print(
                            "Loaded calibration from cache: {}".format(_cal_cache_path),
                            file=sys.stderr,
                        )

                if cal is None:
                    print(
                        "Calibrating trace for bounded execute-mode sweep '{}'...".format(
                            profile.name
                        ),
                        file=sys.stderr,
                    )
                    try:
                        cal = run_calibration(
                            repo_root=repo_root,
                            renode_test=renode_test,
                            robot_suite=robot_suite,
                            profile=profile,
                            robot_vars=_without_hash_bypass(robot_vars),
                            work_dir=work_dir,
                            renode_remote_server_dir=args.renode_remote_server_dir,
                            keep_run_artifacts=args.keep_run_artifacts,
                        )
                    except RuntimeError as exc:
                        if not _can_fallback_to_control_only_calibration(profile, exc):
                            raise
                        control_only_calibration_fallback = str(exc)
                        calibration_source_override = "control_only_fallback"
                        max_writes = 0
                        total_erases = 0
                        setup_writes = 0
                        total_i2c_transactions = 0
                        total_otp_blows = 0
                        trace_file = None
                        erase_trace_file = None
                        trace_file_bin = None
                        erase_trace_file_bin = None
                        cal = None
                        print(
                            "Calibration fallback: {}. Proceeding with control-only execute report.".format(
                                exc
                            ),
                            file=sys.stderr,
                        )
                    if _cal_cache_path and cal is not None:
                        save_calibration(_cal_cache_path, cal, _cal_cache_key)
                        print(
                            "Saved calibration to cache: {}".format(_cal_cache_path),
                            file=sys.stderr,
                        )
                if cal is not None:
                    total_erases = cal.total_erases
                    trace_file = cal.trace_file
                    erase_trace_file = cal.erase_trace_file
                    trace_file_bin = cal.trace_file_bin
                    erase_trace_file_bin = cal.erase_trace_file_bin
                    if cal.calibration_exec_hash:
                        robot_vars, discovered_hash_used = _merge_calibration_expected_exec_hash(
                            robot_vars,
                            cal.calibration_exec_hash,
                            cal.calibration_boot_outcome,
                        )
                        message = (
                            "Calibration: exec slot hash = {}..."
                            if discovered_hash_used
                            else "Calibration: overriding profile EXPECTED_EXEC_SHA256 with ground-truth; exec slot hash = {}..."
                        )
                        print(
                            message.format(cal.calibration_exec_hash[:16]),
                            file=sys.stderr,
                        )
                    setup_writes = cal.setup_writes
                    total_i2c_transactions = cal.total_i2c_transactions
                    total_otp_blows = cal.total_otp_blows
                    cal_parts = ["{} NVM writes (trace source)".format(cal.total_writes)]
                    if include_erases:
                        cal_parts.append("{} page erases".format(total_erases))
                    if total_i2c_transactions > 0:
                        cal_parts.append(
                            "{} I2C transactions".format(total_i2c_transactions)
                        )
                    if total_otp_blows > 0:
                        cal_parts.append("{} OTP blows".format(total_otp_blows))
                    print("Calibration: {}.".format(", ".join(cal_parts)), file=sys.stderr)
                    print(
                        "Bounded execute-mode sweep: limiting tested write indices to first {} writes.".format(
                            max_writes
                        ),
                        file=sys.stderr,
                    )

        # Apply safety cap.
        cap = profile.fault_sweep.max_writes_cap
        if max_writes > cap:
            print(
                "Capping max_writes from {} to {}".format(max_writes, cap),
                file=sys.stderr,
            )
            max_writes = cap

        fault_start = args.fault_start
        fault_end = args.fault_end
        if zero_point_execute_request:
            fault_start = 0
            fault_end = 0

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
                erase_trace_file=erase_trace_file,
            ),
            quick=args.quick,
            fault_step=args.fault_step,
            fault_start=fault_start,
            fault_end=fault_end,
        )
        fault_points = plan.fault_points
        fault_types_list = plan.fault_types_list
        heuristic_summary = plan.heuristic_summary
        swap_progress_summary = getattr(plan, "swap_progress_summary", None)
        security_state_erase_summary = getattr(plan, "security_state_erase_summary", None)
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
            no_hash_bypass=effective_no_hash_bypass,
            # Allow the state evaluator in --quick runs only when the
            # fault planner actually selected the heuristic path.  The
            # profile opt-in (``quick_use_heuristic``) is necessary but
            # not sufficient; ``build_fault_plan`` has several other
            # preconditions (trace available, no explicit bounds, step 1,
            # non-exhaustive strategy) that must also hold.
            allow_state_evaluator=(not args.quick) or bool(heuristic_summary),
            profile_initial_state_name=args.initial_state or None,
        )

        sweep_wall_s = _time_mod.time() - sweep_wall_t0
        print(
            "Sweep completed: {} points in {:.1f}s ({:.0f}ms/point avg)".format(
                len(fault_points), sweep_wall_s,
                (sweep_wall_s * 1000 / len(fault_points)) if fault_points else 0,
            ),
            file=sys.stderr,
        )

        # Binary-driven terminal-error escape campaign.  Its control and
        # instruction-skip runs intentionally use the same profile inputs,
        # while the skip points come only from the emitted ELF callsites.
        terminal_error_results = None
        terminal_error_summary = None
        if getattr(profile, "terminal_error_paths", None):
            terminal_discovery = discover_terminal_error_paths(
                profile.resolve_path(repo_root, profile.bootloader_elf),
                profile.terminal_error_paths,
            )
            terminal_points = [item.callsite_address for item in terminal_discovery.candidates]
            terminal_types = ["i:0x{:X}".format(item) for item in terminal_points]
            if terminal_points and not terminal_discovery.infrastructure_errors:
                terminal_robot_vars = [
                    item for item in robot_vars
                    if not item.startswith((
                        "EVALUATION_MODE:",
                        "INSTRUCTION_SKIP_COUNT:",
                    ))
                ]
                terminal_robot_vars.append("EVALUATION_MODE:execute")
                # Terminal candidates are single-instruction experiments even
                # when the parent profile requests a wider ordinary skip.
                terminal_robot_vars.append("INSTRUCTION_SKIP_COUNT:1")
                terminal_error_results = run_runtime_sweep(
                    repo_root=repo_root,
                    renode_test=renode_test,
                    robot_suite=robot_suite,
                    profile=profile,
                    fault_points=terminal_points,
                    robot_vars=terminal_robot_vars,
                    work_dir=work_dir / "terminal_error_escape",
                    renode_remote_server_dir=args.renode_remote_server_dir,
                    include_control=True,
                    num_workers=args.workers,
                    evaluation_mode="execute",
                    max_batch_points=args.max_batch_points,
                    trace_file=None,
                    erase_trace_file=None,
                    trace_file_bin=None,
                    erase_trace_file_bin=None,
                    fault_types_list=terminal_types,
                    keep_run_artifacts=args.keep_run_artifacts,
                    no_hash_bypass=True,
                    allow_state_evaluator=False,
                    profile_initial_state_name=args.initial_state or None,
                )
                terminal_control = next(
                    (item for item in terminal_error_results if item.get("is_control")),
                    {},
                )
                terminal_faults = [
                    item for item in terminal_error_results if not item.get("is_control")
                ]
                terminal_error_summary = evaluate_terminal_error_differential(
                    terminal_discovery, terminal_control, terminal_faults
                )
            else:
                terminal_error_summary = {
                    "candidates": len(terminal_discovery.candidates),
                    "unresolved_candidates": terminal_discovery.unresolved_candidates,
                    "infrastructure_errors": terminal_discovery.infrastructure_errors,
                    "results": [],
                    "findings": [],
                }

        flash_base = 0
        if profile.memory.slots:
            flash_base = min(slot.base for slot in profile.memory.slots.values())
        clean_trace_meta = annotate_clean_trace(
            sweep_results, trace_file, erase_trace_file, flash_base,
            trace_address_map=getattr(profile.memory, "trace_address_map", None),
        )
        calibration_coverage = summarize_calibration_coverage(
            trace_file=trace_file,
            erase_trace_file=erase_trace_file,
            flash_base=flash_base,
            slots=profile.memory.slots,
            page_size=getattr(profile.memory, "page_size", 4096),
            metadata_regions=getattr(profile, "metadata_fault_regions", None),
            trace_address_map=getattr(profile.memory, "trace_address_map", None),
        )
        if clean_trace_meta is not None:
            clean_trace_meta["coverage"] = calibration_coverage

        annotate_result_checks(sweep_results, profile, repo_root=repo_root)
        validate_runtime_findings(
            results=sweep_results,
            profile=profile,
            repo_root=repo_root,
            renode_test=renode_test,
            robot_suite=robot_suite,
            robot_vars=robot_vars,
            work_dir=work_dir,
            renode_remote_server_dir=args.renode_remote_server_dir,
            no_hash_bypass=effective_no_hash_bypass,
            keep_run_artifacts=args.keep_run_artifacts,
            expected_outcome=getattr(profile.expect, "control_outcome", "success") or "success",
        )
        sweep_summary = summarize_runtime_sweep(
            sweep_results,
            total_writes=max_writes,
            profile=profile,
            calibration_coverage=calibration_coverage,
            expected_fault_points=len(fault_points),
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
            no_hash_bypass=effective_no_hash_bypass,
            explain_only=args.explain_multi_fault_plan,
            keep_run_artifacts=args.keep_run_artifacts,
            profile_initial_state_name=args.initial_state or None,
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
                    raise RuntimeError(
                        "configured partial_staging image not found: {}".format(
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
                    if not trunc_points:
                        raise RuntimeError(
                            "configured partial_staging campaign produced no truncation points"
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
                            profile_initial_state_name=args.initial_state or None,
                        )
                    )

                    partial_staging_summary = summarize_partial_staging(
                        ps_results_typed,
                        image_size=image_size,
                        expected_points=len(trunc_points),
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
        verdict = _aggregate_auxiliary_verdict(
            verdict,
            profile,
            state_fuzz_results=state_fuzz_results,
            state_fuzz_summary=state_fuzz_summary,
            fuzz_crash_results=fuzz_crash_results,
            fuzz_crash_summary=fuzz_crash_summary,
            geometry_preflight=geometry_preflight,
        )
        if terminal_error_summary is not None:
            if terminal_error_summary.get("infrastructure_errors") or terminal_error_summary.get("unresolved_candidates"):
                verdict = "INCONCLUSIVE -- terminal-error campaign infrastructure failure"
            elif terminal_error_summary.get("findings"):
                verdict = "FAIL -- terminal-error path escaped"
        if authorization_review_analysis is not None:
            if authorization_review_analysis["verdict"] == "FAIL":
                verdict = "FAIL -- authorization review analysis found a mismatch"
            elif authorization_review_analysis["verdict"] != "PASS":
                verdict = "INCONCLUSIVE -- authorization review evidence incomplete"

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
            "rc_injection_config": profile.fault_sweep.rc_injection_config.to_dict(),
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
            "boundary_campaign": (
                {
                    "name": profile.boundary_campaign.name,
                    "parameter": profile.boundary_campaign.parameter,
                    "setup_environment": profile.boundary_campaign.setup_environment,
                    "resolved_value": boundary_report_value,
                    "previous_value": profile.boundary_previous_value,
                    "follow_up": (
                        {
                            "parameter_value": profile.boundary_campaign.follow_up.parameter_value,
                            "expect": profile.boundary_campaign.follow_up.expect,
                        }
                        if profile.boundary_campaign.follow_up is not None
                        else None
                    ),
                }
                if getattr(profile, "boundary_campaign", None) is not None
                else None
            ),
            "security_policy": {
                "anti_rollback": profile.security_policy.anti_rollback,
                "minimum_version": profile.security_policy.minimum_version,
                "toctou_protection": profile.security_policy.toctou_protection,
            },
            "authorization_review_analysis": authorization_review_analysis,
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
        if geometry_preflight is not None:
            payload["summary"]["geometry_preflight"] = geometry_preflight
        if swap_progress_summary is not None:
            payload["summary"]["swap_progress_inference"] = swap_progress_summary
        if profile.persistent_state_layout is not None:
            payload["summary"]["persistent_state_layout"] = analyze_persistent_state_layout(
                profile.persistent_state_layout
            )
        if security_state_erase_summary is not None:
            payload["summary"]["security_state_erase"] = security_state_erase_summary
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
        calibration_source = calibration_source_override or "executed"
        if calibration_source_override is None and cal is None:
            if profile.fault_sweep.max_writes == "auto" and eval_mode == "state":
                calibration_source = "derived"
            else:
                calibration_source = "profile"
        payload["calibration"] = {
            "performed": cal is not None,
            "source": calibration_source,
            "writes": max_writes,
            "erases": total_erases,
            "coverage": calibration_coverage,
            "stop_reason": cal.stop_reason if cal is not None else None,
            "emulated_s": cal.emulated_s if cal is not None else None,
            "elapsed_s": cal.elapsed_s if cal is not None else None,
            "pc": cal.pc if cal is not None else None,
        }
        if control_only_calibration_fallback:
            payload["calibration"]["fallback_reason"] = control_only_calibration_fallback
        if clean_trace_meta is not None:
            payload["clean_trace"] = clean_trace_meta
        if discovery is not None:
            payload["trigger_discovery"] = discovery.to_summary()
            payload["summary"]["trigger_discovery"] = {
                "selected_strategy": discovery.selected_strategy,
                "flash_map_check": discovery.flash_map_check,
            }
        if getattr(profile, "terminal_error_paths", None):
            terminal_discovery = discover_terminal_error_paths(
                profile.resolve_path(repo_root, profile.bootloader_elf),
                profile.terminal_error_paths,
            )
            payload["terminal_error_paths"] = {
                "declarations": [item.to_dict() for item in profile.terminal_error_paths],
                "discovery": terminal_discovery.to_dict(),
            }
            payload["summary"]["terminal_error_paths"] = {
                "candidates": len(terminal_discovery.candidates),
                "unresolved_candidates": len(terminal_discovery.unresolved_candidates),
                "infrastructure_errors": len(terminal_discovery.infrastructure_errors),
            }
            if terminal_error_results is not None:
                payload["terminal_error_results"] = terminal_error_results
            if terminal_error_summary is not None:
                payload["summary"]["terminal_error_campaign"] = terminal_error_summary

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

        attach_security_aggregate(payload)
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
        allow_control_only_issues = _allow_expected_control_only_issues(profile)
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
                if allow_control_only_issues and ctrl_effective == expected_control:
                    ctrl["control_only_issue_baseline"] = True
                else:
                    print(
                        "ASSERTION FAILED: control checks reported {} issue(s)".format(
                            ctrl.get("issue_count", 0)
                        ),
                        file=sys.stderr,
                    )
                    return EXIT_ASSERTION_FAILURE

        if not is_pass_verdict(verdict) and not args.no_assert_verdict:
            return EXIT_ASSERTION_FAILURE

        return 0

    except Exception as exc:
        print("INFRASTRUCTURE FAILURE: {}".format(exc), file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return EXIT_INFRA_FAILURE
    finally:
        generated_robot_vars = locals().get("robot_vars")
        if isinstance(generated_robot_vars, list):
            _cleanup_generated_robot_files(generated_robot_vars)
        generated_overrides = locals().get("_overrides_file")
        generated_overrides_name = getattr(generated_overrides, "name", "")
        if generated_overrides_name:
            try:
                os.unlink(generated_overrides_name)
            except FileNotFoundError:
                pass
        if temp_ctx is not None:
            temp_ctx.cleanup()


def _initial_state_child_command(
    state_name: str,
    output_path: Path,
    extra_robot_vars: Optional[List[str]] = None,
) -> List[str]:
    """Rebuild the current CLI for one resolved initial-state child run."""
    filtered: List[str] = []
    argv = list(sys.argv[1:])
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in {"--output", "--initial-state"}:
            index += 2
            continue
        if token.startswith("--output=") or token.startswith("--initial-state="):
            index += 1
            continue
        filtered.append(token)
        index += 1
    filtered.extend(["--output", str(output_path), "--initial-state", state_name])
    for robot_var in extra_robot_vars or []:
        filtered.extend(["--robot-var", robot_var])
    if "--no-assert-verdict" not in filtered:
        filtered.append("--no-assert-verdict")
    if "--no-assert-control-boots" not in filtered:
        filtered.append("--no-assert-control-boots")
    return [sys.executable, str(Path(__file__).resolve())] + filtered


def _boundary_result_control(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the single clean control observation from a child report."""
    results = payload.get("runtime_sweep_results")
    if not isinstance(results, list):
        return None
    controls = [item for item in results if isinstance(item, dict) and item.get("is_control")]
    return controls[0] if len(controls) == 1 else None


def _boundary_state_value(result: Dict[str, Any], parameter: str) -> Any:
    """Resolve a declared parameter from semantic post-state telemetry."""
    state = result.get("semantic_state")
    if not isinstance(state, dict):
        return None
    current: Any = state
    for token in str(parameter).split("."):
        if not isinstance(current, dict) or token not in current:
            current = None
            break
        current = current[token]
    return current


def _boundary_acceptance_status(result: Dict[str, Any]) -> Optional[str]:
    """Read the setup/update action's explicit acceptance contract."""
    raw = result.get("boundary_acceptance_status")
    if raw is None and isinstance(result.get("signals"), dict):
        raw = result["signals"].get("boundary_acceptance_status")
    return raw if isinstance(raw, str) and raw in {"accepted", "rejected"} else None


def _boundary_observation(
    payload: Dict[str, Any],
    campaign: Any,
    value: int,
    *,
    phase: str = "candidate",
    candidate_value: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a strict boundary observation from a child control report."""
    # The runner transports the expected value into the child, and the child
    # must echo the resolved value in its signed/report payload.  Otherwise a
    # stale or mis-overridden follow-up could be reported as N-1 merely because
    # the parent intended to pass N-1 on the command line.
    metadata = payload.get("boundary_campaign") if isinstance(payload, dict) else None
    metadata_value = metadata.get("resolved_value") if isinstance(metadata, dict) else None
    metadata_value_ok = (
        isinstance(metadata, dict)
        and metadata.get("name") == campaign.name
        and isinstance(metadata_value, int)
        and not isinstance(metadata_value, bool)
        and metadata_value == value
    )
    if not metadata_value_ok:
        if phase == "follow_up":
            return {
                "resolved_value": value if candidate_value is None else candidate_value,
                "follow_up_value": value,
                "follow_up_status": "infrastructure/setup failure",
                "infrastructure_failure": True,
            }
        return {
            "resolved_value": value,
            "candidate_status": "infrastructure/setup failure",
            "infrastructure_failure": True,
        }
    control = _boundary_result_control(payload)
    if control is None:
        return {
            "resolved_value": value,
            "infrastructure_failure": True,
            "candidate_status": "infrastructure/setup failure",
        }
    outcome = str(control.get("final_boot_outcome", control.get("boot_outcome", ""))).strip().lower()
    status = _boundary_acceptance_status(control)
    state_value = _boundary_state_value(control, campaign.parameter)
    control_signals = control.get("signals") if isinstance(control.get("signals"), dict) else {}
    if phase == "follow_up":
        row = {
            "resolved_value": value if candidate_value is None else candidate_value,
            "follow_up_value": value,
            "follow_up_status": status or "infrastructure/setup failure",
            "infrastructure_failure": status is None or outcome in {
                "", "unknown", "infra_error", "timeout", "error",
                "infrastructure/setup failure", "infrastructure_failure", "setup_failure",
            },
        }
        if control_signals.get("boundary_snapshot_restore") is not None:
            row["boundary_snapshot_restore"] = control_signals["boundary_snapshot_restore"]
        return row
    row: Dict[str, Any] = {
        "resolved_value": value,
        "candidate_status": status or "infrastructure/setup failure",
    }
    if status is None or outcome in {
        "", "unknown", "infra_error", "timeout", "error",
        "infrastructure/setup failure", "infrastructure_failure", "setup_failure",
    }:
        row["infrastructure_failure"] = True
    # A rejected candidate is a valid outcome before persistence, so it does
    # not need semantic post-state telemetry.  Accepted candidates do: absent
    # state would make the persistence claim unverifiable.
    if state_value is not None:
        row["persisted_value"] = state_value
    elif status == "accepted":
        row["infrastructure_failure"] = True
    if control_signals.get("boundary_snapshot_capture") is not None:
        row["boundary_snapshot_capture"] = control_signals["boundary_snapshot_capture"]
    return row


def _is_pass_verdict(value: Any) -> bool:
    """Accept only the report protocol's PASS token or PASS plus details."""
    return is_pass_verdict(value)


def _run_initial_state_matrix(
    args: argparse.Namespace,
    profile: ProfileConfig,
) -> int:
    """Run and aggregate every declared initial state through the real CLI."""
    repo_root = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    entries: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="tardigrade_initial_states_") as td:
        temp_root = Path(td)
        for index, state in enumerate(profile.initial_states):
            child_output = temp_root / "state_{:04d}.json".format(index)
            campaign = getattr(state, "boundary_campaign", None)
            candidate_vars: List[str] = []
            candidate_state_file = temp_root / "state_{:04d}_durable.bin".format(index)
            if campaign is not None and campaign.follow_up is not None:
                candidate_vars.append(
                    "BOUNDARY_DURABLE_STATE_FILE:{}".format(candidate_state_file)
                )
            command = _initial_state_child_command(
                state.name, child_output, candidate_vars
            )
            proc = subprocess.run(
                command,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            child_payload: Dict[str, Any] = {}
            parse_error = ""
            if child_output.exists():
                try:
                    loaded = json.loads(child_output.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        child_payload = loaded
                    else:
                        parse_error = "child report was not a JSON object"
                except (OSError, ValueError) as exc:
                    parse_error = str(exc)
            else:
                parse_error = "child report was not created"

            # Boundary campaigns are intentionally runner-owned two-phase
            # relations.  The first child performs the ordinary update
            # sequence for N; its semantic post-state is handed to the
            # follow-up setup script, which performs the existing update
            # sequence for N-1.  No update execution logic is duplicated here.
            if campaign is not None:
                boundary_observation = _boundary_observation(
                    child_payload, campaign, int(state.boundary_value or 0)
                )
                if proc.returncode != 0:
                    boundary_observation["infrastructure_failure"] = True
                if campaign.follow_up is not None:
                    if candidate_state_file.is_file():
                        state_file = candidate_state_file
                        previous = state.boundary_previous_value
                        if previous is not None:
                            follow_output = temp_root / "state_{:04d}_followup.json".format(index)
                            follow_vars = [
                                "BOUNDARY_VALUE:{}".format(int(previous)),
                                "BOUNDARY_PHASE:follow_up",
                                "BOUNDARY_DURABLE_STATE_FILE:{}".format(state_file),
                            ]
                            follow_command = _initial_state_child_command(
                                state.name, follow_output, follow_vars
                            )
                            follow_proc = subprocess.run(
                                follow_command,
                                cwd=str(repo_root),
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            follow_payload: Dict[str, Any] = {}
                            if follow_output.exists():
                                try:
                                    loaded_follow = json.loads(
                                        follow_output.read_text(encoding="utf-8")
                                    )
                                    if isinstance(loaded_follow, dict):
                                        follow_payload = loaded_follow
                                except (OSError, ValueError):
                                    pass
                            follow_observation = _boundary_observation(
                                follow_payload,
                                campaign,
                                int(previous),
                                phase="follow_up",
                                candidate_value=int(state.boundary_value or 0),
                            )
                            boundary_observation.update(follow_observation)
                            if follow_proc.returncode != 0:
                                boundary_observation["infrastructure_failure"] = True
                        else:
                            boundary_observation["infrastructure_failure"] = True
                    else:
                        boundary_observation["infrastructure_failure"] = True
                child_payload["boundary_observation"] = boundary_observation
            entry: Dict[str, Any] = {
                "state": state.name,
                "description": state.description,
                "returncode": proc.returncode,
                "verdict": child_payload.get("verdict"),
                "summary": child_payload.get("summary", {}),
                "profile": child_payload.get("profile"),
                "_child_payload": child_payload,
            }
            # Preserve canonical multi-component point evidence in the
            # wrapper; the validator cannot verify a child's aggregate after
            # the private payload is discarded below without these fields.
            if isinstance(child_payload.get("summary"), dict) and isinstance(
                child_payload.get("summary", {}).get("combined"), dict
            ) and "security_issue_points" in child_payload["summary"]["combined"]:
                for evidence_key in (
                    "combined_results",
                    "control_combined_result",
                    "control_state",
                    "control_invariant_violations",
                ):
                    if evidence_key in child_payload:
                        entry[evidence_key] = child_payload[evidence_key]
            if parse_error:
                entry["error"] = parse_error
            if proc.returncode != 0:
                entry["stderr"] = (proc.stderr or proc.stdout).strip()[-4000:]
            entries.append(entry)

    missing_or_infra = [
        entry
        for entry in entries
        if (
            entry.get("returncode") != 0
            or not isinstance(entry.get("verdict"), str)
            or not entry["verdict"].strip()
        )
    ]
    nonpassing = [
        entry
        for entry in entries
        if (
            isinstance(entry.get("verdict"), str)
            and entry["verdict"].strip()
            and not _is_pass_verdict(entry["verdict"])
        )
    ]
    if missing_or_infra:
        verdict = "INCONCLUSIVE -- {}/{} initial-state runs failed infrastructure checks".format(
            len(missing_or_infra), len(entries)
        )
    elif nonpassing:
        verdict = "FAIL -- {}/{} initial-state runs did not pass".format(
            len(nonpassing), len(entries)
        )
    else:
        verdict = "PASS"

    boundary_reports: List[Dict[str, Any]] = []
    boundary_by_campaign: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        child = entry.get("_child_payload")
        boundary = child.get("boundary_campaign") if isinstance(child, dict) else None
        if not isinstance(boundary, dict) or not boundary.get("name"):
            continue
        observation = child.get("boundary_observation", {}) if isinstance(child, dict) else {}
        row = {
            "resolved_value": boundary.get("resolved_value"),
            **(observation if isinstance(observation, dict) else {}),
        }
        boundary_by_campaign.setdefault(str(boundary["name"]), []).append(row)
    for campaign in getattr(profile, "boundary_campaigns", []):
        report = aggregate_boundary_results(campaign, boundary_by_campaign.get(campaign.name, []))
        boundary_reports.append(report)
        if report.get("verdict") == "FAIL":
            verdict = "FAIL -- boundary campaign '{}' failed".format(campaign.name)
        elif report.get("verdict") == "INCONCLUSIVE" and verdict == "PASS":
            verdict = "INCONCLUSIVE -- boundary campaign '{}' lacked reliable observations".format(campaign.name)
    boundary_infra = any(
        report.get("verdict") == "INCONCLUSIVE" for report in boundary_reports
    )
    boundary_failed = any(
        report.get("verdict") == "FAIL" for report in boundary_reports
    )
    for entry in entries:
        entry.pop("_child_payload", None)

    payload: Dict[str, Any] = {
        "engine": "renode-test",
        "profile": profile.name,
        "profile_path": str(profile.profile_path) if profile.profile_path else None,
        "schema_version": profile.schema_version,
        "initial_states": True,
        "verdict": verdict,
        "expect": {
            "should_find_issues": bool(
                getattr(getattr(profile, "expect", None), "should_find_issues", False)
            ),
        },
        "summary": {
            "initial_states": {
                "requested": len(profile.initial_states),
                "completed": len(entries) - len(missing_or_infra),
                "passed": sum(
                    1
                    for entry in entries
                    if _is_pass_verdict(entry.get("verdict"))
                ),
            }
        },
        "initial_state_results": entries,
        "boundary_campaign_results": boundary_reports,
        "execution": {
            "run_utc": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        },
        "git": git_metadata(repo_root),
    }
    attach_security_aggregate(payload)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "profile": profile.name,
                "verdict": verdict,
                "summary": payload["summary"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if missing_or_infra or boundary_infra:
        return EXIT_INFRA_FAILURE
    # --no-assert-verdict suppresses assertion failures, including boundary
    # FAIL verdicts. Infrastructure remains a hard exit because it means the
    # campaign did not produce trustworthy observations.
    if (boundary_failed and not args.no_assert_verdict) or (
        nonpassing and not args.no_assert_verdict
    ):
        return EXIT_ASSERTION_FAILURE
    return 0


def main() -> int:
    args = parse_args()
    if args.initial_state:
        return _main_single()
    try:
        profile = load_profile(args.profile, strict=args.strict_profile)
    except Exception:
        return _main_single()
    if not getattr(profile, "initial_states", None):
        return _main_single()
    return _run_initial_state_matrix(args, profile)


if __name__ == "__main__":
    raise SystemExit(main())
