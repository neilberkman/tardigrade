#!/usr/bin/env python3
"""Self-test: validate the audit tool against known bootloader profiles.

Runs audit_bootloader.py against every profile in profiles/ and checks
that the verdict matches the profile's expect section.

Usage::

    python3 scripts/self_test.py
    python3 scripts/self_test.py --quick
    python3 scripts/self_test.py --profile profiles/naive_bare_copy.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import datetime as dt
from typing import Any, Dict, List, Optional, Tuple

from profile_loader import load_profile_raw

DEFAULT_SELF_TEST_RUNTIME_MANIFEST = "scripts/self_test_runtime_manifest.json"
DEFAULT_SELF_TEST_PROFILE_COST_S = 60.0
# A clean control that reaches Robot's short default timeout can be a transient
# Renode startup/host-load failure. Give one retry a bounded, larger Robot
# budget, while keeping the original attempt fail-closed for every other error.
SELF_TEST_CONTROL_TIMEOUT_RETRIES = 1
SELF_TEST_CONTROL_TIMEOUT_RETRY_MINUTES = 5


def _normalize_expect_fault_type(name: str) -> str:
    value = str(name or "").strip().lower()
    aliases = {
        "phase2_fault": "phase2",
        "phase2": "phase2",
        "power_loss": "power_loss",
    }
    return aliases.get(value, value)


def load_runtime_manifest(
    repo_root: Path,
    manifest_path: Optional[str] = None,
) -> Tuple[float, Dict[str, float]]:
    """Load per-profile runtime estimates used for self-test sharding."""
    path = Path(manifest_path or DEFAULT_SELF_TEST_RUNTIME_MANIFEST)
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    if not path.exists():
        return DEFAULT_SELF_TEST_PROFILE_COST_S, {}

    payload = json.loads(path.read_text(encoding="utf-8"))
    default_cost_s = float(payload.get("default_cost_s", DEFAULT_SELF_TEST_PROFILE_COST_S))
    if default_cost_s <= 0:
        raise ValueError("self-test runtime manifest default_cost_s must be > 0")

    raw_profiles = payload.get("profiles", {})
    if not isinstance(raw_profiles, dict):
        raise ValueError("self-test runtime manifest profiles must be an object")

    profile_costs: Dict[str, float] = {}
    for profile_name, raw_cost in raw_profiles.items():
        if isinstance(raw_cost, dict):
            raw_cost = raw_cost.get("estimated_runtime_s")
        cost_s = float(raw_cost)
        if cost_s <= 0:
            raise ValueError(
                "self-test runtime manifest cost for {} must be > 0".format(profile_name)
            )
        profile_costs[str(profile_name)] = cost_s
    return default_cost_s, profile_costs


def estimate_profile_cost(
    profile_path: Path,
    profile_costs: Dict[str, float],
    default_cost_s: float,
) -> float:
    """Return the estimated runtime cost for a self-test profile."""
    return float(profile_costs.get(profile_path.name, default_cost_s))


def partition_profiles_round_robin(
    profiles: List[Path],
    shard_total: int,
) -> List[List[Path]]:
    """Partition profiles using the legacy round-robin strategy."""
    if shard_total < 1:
        raise ValueError("shard_total must be >= 1")
    return [profiles[idx::shard_total] for idx in range(shard_total)]


def partition_profiles_by_estimated_cost(
    profiles: List[Path],
    shard_total: int,
    profile_costs: Dict[str, float],
    default_cost_s: float,
) -> List[List[Path]]:
    """Partition profiles into shards by estimated runtime cost.

    Uses a longest-processing-time-first greedy assignment so the heaviest
    profiles spread across shards instead of clustering by filename order.
    """
    if shard_total < 1:
        raise ValueError("shard_total must be >= 1")
    if shard_total == 1:
        return [list(profiles)]

    original_order = {profile.name: idx for idx, profile in enumerate(profiles)}
    sorted_profiles = sorted(
        profiles,
        key=lambda profile: (
            -estimate_profile_cost(profile, profile_costs, default_cost_s),
            original_order[profile.name],
            profile.name,
        ),
    )
    shard_profiles: List[List[Path]] = [[] for _ in range(shard_total)]
    shard_costs = [0.0] * shard_total
    for profile in sorted_profiles:
        target_idx = min(
            range(shard_total),
            key=lambda idx: (shard_costs[idx], len(shard_profiles[idx]), idx),
        )
        shard_profiles[target_idx].append(profile)
        shard_costs[target_idx] += estimate_profile_cost(
            profile, profile_costs, default_cost_s
        )

    for idx, items in enumerate(shard_profiles):
        shard_profiles[idx] = sorted(items, key=lambda profile: original_order[profile.name])
    return shard_profiles


def shard_costs_s(
    shards: List[List[Path]],
    profile_costs: Dict[str, float],
    default_cost_s: float,
) -> List[float]:
    """Compute the estimated cost of each shard."""
    return [
        sum(estimate_profile_cost(profile, profile_costs, default_cost_s) for profile in shard)
        for shard in shards
    ]


def discover_profiles(repo_root: Path) -> List[Path]:
    """Find all testable .yaml profiles (excludes skip_self_test)."""
    profiles_dir = repo_root / "profiles"
    if not profiles_dir.is_dir():
        return []
    profiles = []
    for p in sorted(profiles_dir.glob("*.yaml")):
        try:
            raw = load_profile_raw(p)
        except Exception:
            profiles.append(p)  # let main loop handle load errors
            continue
        if not raw.get("skip_self_test", False):
            profiles.append(p)
    return profiles


def write_summary(output_path: Optional[str], total: int, detailed_results: List[Dict[str, Any]]) -> None:
    """Persist a partial or final self-test summary, if requested."""
    if not output_path:
        return
    passed_count = sum(1 for item in detailed_results if item.get("passed"))
    failed_count = len(detailed_results) - passed_count
    payload = {
        "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "total_profiles": total,
        "completed_profiles": len(detailed_results),
        "passed": passed_count,
        "failed": failed_count,
        "results": detailed_results,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def build_detailed_result(
    profile: str,
    passed: bool,
    reason: str,
    exit_code: Optional[int],
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a normalized self-test result entry.

    `verdict` reflects the self-test outcome, while `audit_verdict` preserves the
    raw audit report verdict for debugging.
    """
    report = report or {}
    sweep = report.get("summary", {}).get("runtime_sweep", {})
    return {
        "profile": profile,
        "passed": passed,
        "reason": reason,
        "exit_code": exit_code,
        "verdict": "PASS" if passed else "FAIL",
        "audit_verdict": report.get("verdict"),
        "bricks": sweep.get("bricks"),
        "brick_rate": sweep.get("brick_rate"),
    }


def run_audit(
    repo_root: Path,
    profile_path: Path,
    output_path: Path,
    quick: bool,
    renode_test: str,
    extra_args: List[str],
) -> Tuple[int, Dict[str, Any], str]:
    """Run audit_bootloader.py and return (exit_code, report, stderr)."""
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "audit_bootloader.py"),
        "--profile", str(profile_path),
        "--output", str(output_path),
    ]
    if quick:
        cmd.append("--quick")
    if renode_test:
        cmd.extend(["--renode-test", renode_test])
    cmd.extend(extra_args)

    for attempt in range(SELF_TEST_CONTROL_TIMEOUT_RETRIES + 1):
        env = None
        if attempt:
            # Preserve a caller's larger budget, but never let the retry fall
            # back to the two-minute suite default that triggered it.
            env = os.environ.copy()
            raw_existing = str(
                env.get("OTA_RENODE_ROBOT_TIMEOUT_MINUTES", "") or ""
            ).strip()
            try:
                existing_minutes = float(raw_existing) if raw_existing else 0.0
            except ValueError:
                existing_minutes = 0.0
            env["OTA_RENODE_ROBOT_TIMEOUT_MINUTES"] = str(
                max(existing_minutes, float(SELF_TEST_CONTROL_TIMEOUT_RETRY_MINUTES))
            )

        proc = subprocess.run(
            cmd, cwd=str(repo_root),
            capture_output=True, text=True, check=False,
            **({"env": env} if env is not None else {}),
        )

        report: Dict[str, Any] = {}
        if output_path.exists():
            try:
                report = json.loads(output_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        # Only retry a missing-report infrastructure timeout from the clean
        # control. A report, a target assertion failure, or a fault-point
        # timeout is authoritative and must not be hidden by a rerun.
        stderr = proc.stderr or ""
        stderr_lower = stderr.lower()
        control_timeout = (
            proc.returncode >= 2
            and not report
            and "infrastructure failure" in stderr_lower
            and "timeout" in stderr_lower
            and ("clean control" in stderr_lower or "for control" in stderr_lower)
        )
        if attempt < SELF_TEST_CONTROL_TIMEOUT_RETRIES and control_timeout:
            try:
                output_path.unlink()
            except FileNotFoundError:
                pass
            print(
                "  infrastructure clean-control timeout; retrying once with "
                "a {} minute Robot budget".format(
                    SELF_TEST_CONTROL_TIMEOUT_RETRY_MINUTES
                ),
                file=sys.stderr,
            )
            continue

        return proc.returncode, report, stderr

    raise AssertionError("unreachable self-test audit retry loop")


def check_verdict(
    profile_path: Path,
    profile_raw: Dict[str, Any],
    report: Dict[str, Any],
    exit_code: int,
) -> Tuple[bool, str]:
    """Check whether the audit result matches the profile's expectations.

    Returns (passed, reason).
    """
    # audit_bootloader uses 1 for an assertion/verdict mismatch, which some
    # known-defect self-test profiles intentionally reinterpret below.  Any
    # other non-zero status is an infrastructure/process failure and must not
    # be accepted merely because a partial report happens to contain matching
    # counters.
    if exit_code < 0 or exit_code >= 2:
        return False, "Audit infrastructure failure (exit code {})".format(
            exit_code
        )

    expect = profile_raw.get("expect", {})
    should_find_issues = expect.get("should_find_issues", False)
    brick_rate_min = float(expect.get("brick_rate_min", 0.0))
    allow_semantic_only_issues = bool(expect.get("allow_semantic_only_issues", False))
    allow_control_only_issues = bool(expect.get("allow_control_only_issues", False))
    expected_control_outcome = str(expect.get("control_outcome", "success") or "success")
    required_issue_reasons = {
        str(reason).strip()
        for reason in expect.get("required_issue_reasons", [])
        if str(reason).strip()
    }
    ignored_issue_fault_types = {
        _normalize_expect_fault_type(fault_type)
        for fault_type in expect.get("ignored_issue_fault_types", [])
        if str(fault_type).strip()
    }

    verdict = report.get("verdict", "")
    summary = report.get("summary", {})
    sweep = summary.get("runtime_sweep", {})
    brick_rate = float(sweep.get("brick_rate", 0.0))
    bricks = int(sweep.get("bricks", 0))
    issue_points = int(sweep.get("issue_points", bricks))
    fault_type_issue_points = (
        sweep.get("fault_type_issue_points", {})
        if isinstance(sweep.get("fault_type_issue_points"), dict)
        else {}
    )
    issue_reasons = sweep.get("issue_reasons", {}) if isinstance(sweep.get("issue_reasons"), dict) else {}
    control = sweep.get("control", {}) if isinstance(sweep.get("control"), dict) else {}
    control_outcome = str(
        control.get("effective_outcome")
        or control.get("final_boot_outcome")
        or control.get("boot_outcome")
        or ""
    )
    coverage = sweep.get("calibration_coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    coverage_status = str(coverage.get("status", "") or "")
    coverage_reason = str(coverage.get("reason", "") or "")
    coverage_blocks_clean = coverage_status in {
        "metadata_only",
        "outside_slots_only",
        "no_nvm_activity",
    }
    control_only_issue = (
        allow_control_only_issues
        and control_outcome == expected_control_outcome
    )

    # A fault finding cannot compensate for a missing or bad clean baseline.
    # Require the reported control to match before evaluating issue counters;
    # otherwise unrelated fault points can hide an invalid campaign baseline.
    if not control:
        return False, "Clean control result is missing"
    if control_outcome != expected_control_outcome:
        return False, "Control outcome '{}' != expected '{}'".format(
            control_outcome or "missing",
            expected_control_outcome,
        )

    ignored_issue_points = 0
    if ignored_issue_fault_types and fault_type_issue_points:
        ignored_issue_points = sum(
            int(count)
            for fault_type, count in fault_type_issue_points.items()
            if _normalize_expect_fault_type(fault_type) in ignored_issue_fault_types
        )
    effective_issue_points = max(0, issue_points - ignored_issue_points)

    if should_find_issues:
        if issue_points == 0:
            if control_only_issue:
                return True, "Control exhibits expected {}, as intended".format(
                    control_outcome
                )
            if coverage_blocks_clean:
                return False, coverage_reason or "Calibration did not exercise slot data movement"
            return False, "Expected issues but found none"
        if brick_rate_min > 0 and brick_rate < brick_rate_min:
            return False, "Brick rate {:.1%} below minimum {:.1%}".format(
                brick_rate, brick_rate_min
            )
        if required_issue_reasons:
            missing = sorted(
                reason for reason in required_issue_reasons if int(issue_reasons.get(reason, 0)) <= 0
            )
            if missing:
                return False, "Missing expected issue reason(s): {}".format(", ".join(missing))
        if bricks > 0:
            return True, "Found {} bricks ({:.1%}), as expected".format(bricks, brick_rate)
        if not allow_semantic_only_issues:
            return False, (
                "Expected boot-visible issues but only found semantic/invariant issue points; "
                "set expect.allow_semantic_only_issues=true if that is intentional"
            )
        return True, "Found {} semantic/invariant issue points, as expected".format(
            issue_points
        )
    else:
        if coverage_blocks_clean:
            return False, coverage_reason or "Calibration did not exercise slot data movement"
        if effective_issue_points > 0:
            return False, "Expected no issues but found {} point(s)".format(effective_issue_points)
        return True, "No issues found, as expected"


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-test for audit_bootloader.py")
    parser.add_argument(
        "--quick", action="store_true",
        help="Pass --quick to each audit run.",
    )
    parser.add_argument(
        "--profile", action="append", default=[],
        help="Test specific profile(s) instead of all.",
    )
    parser.add_argument("--renode-test", default=os.environ.get("RENODE_TEST", "renode-test"))
    parser.add_argument(
        "--renode-remote-server-dir", default=os.environ.get("RENODE_REMOTE_SERVER_DIR"),
        help="Path to Renode remote server directory.",
    )
    parser.add_argument(
        "--fault-step", type=int, default=None,
        help="Pass --fault-step to audit runs.",
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help="Pass --workers to each audit run.",
    )
    parser.add_argument(
        "--output", default=None,
        help="Optional JSON summary output path.",
    )
    parser.add_argument(
        "--shard", default=None,
        help="Run shard N of M total (e.g. '1/4' runs the first quarter).",
    )
    parser.add_argument(
        "--runtime-manifest",
        default=DEFAULT_SELF_TEST_RUNTIME_MANIFEST,
        help="Path to the self-test runtime cost manifest used for weighted sharding.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    default_cost_s, profile_costs = load_runtime_manifest(repo_root, args.runtime_manifest)

    # Discover profiles.
    if args.profile:
        profiles = [Path(p) for p in args.profile]
    else:
        profiles = discover_profiles(repo_root)

    shard_estimate_s: Optional[float] = None
    if args.shard:
        shard_idx, shard_total = (int(x) for x in args.shard.split("/"))
        shards = partition_profiles_by_estimated_cost(
            profiles, shard_total, profile_costs, default_cost_s
        )
        profiles = shards[shard_idx - 1]
        shard_estimate_s = shard_costs_s(shards, profile_costs, default_cost_s)[shard_idx - 1]

    if not profiles:
        print("No profiles found.", file=sys.stderr)
        return 1

    print("Self-test: {} profiles".format(len(profiles)))
    if shard_estimate_s is not None:
        print(
            "Shard {} estimated runtime: {:.1f}m".format(
                args.shard, shard_estimate_s / 60.0
            )
        )
    print("=" * 60)

    results: List[Tuple[str, bool, str]] = []
    detailed_results: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="self_test_") as tmp:
        tmp_path = Path(tmp)
        current_profile_path = tmp_path / "current_profile.txt"
        for profile_path in profiles:
            name = profile_path.stem
            output_path = tmp_path / "{}_result.json".format(name)
            current_profile_path.write_text(str(profile_path), encoding="utf-8")

            print("\n--- {} ---".format(name))

            # Read raw YAML for expect section.
            try:
                profile_raw = load_profile_raw(profile_path)
            except Exception as exc:
                print("  SKIP: failed to load profile: {}".format(exc))
                results.append((name, False, "profile load error: {}".format(exc)))
                detailed_results.append(build_detailed_result(
                    profile=name,
                    passed=False,
                    reason="profile load error: {}".format(exc),
                    exit_code=None,
                ))
                write_summary(args.output, len(profiles), detailed_results)
                continue

            extra_args: List[str] = []
            if args.renode_remote_server_dir:
                extra_args.extend(["--renode-remote-server-dir", args.renode_remote_server_dir])
            if args.fault_step is not None:
                extra_args.extend(["--fault-step", str(args.fault_step)])
            if args.workers is not None:
                extra_args.extend(["--workers", str(args.workers)])

            try:
                exit_code, report, audit_stderr = run_audit(
                    repo_root=repo_root,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=args.quick,
                    renode_test=args.renode_test,
                    extra_args=extra_args,
                )
            except Exception as exc:
                print("  FAIL: audit crashed: {}".format(exc))
                results.append((name, False, "audit crash: {}".format(exc)))
                detailed_results.append(build_detailed_result(
                    profile=name,
                    passed=False,
                    reason="audit crash: {}".format(exc),
                    exit_code=None,
                ))
                write_summary(args.output, len(profiles), detailed_results)
                continue

            if not report:
                print("  FAIL: no report produced (exit={})".format(exit_code))
                if audit_stderr:
                    for line in audit_stderr.strip().splitlines()[-80:]:
                        print("    stderr: {}".format(line))
                results.append((name, False, "no report (exit={})".format(exit_code)))
                detailed_results.append(build_detailed_result(
                    profile=name,
                    passed=False,
                    reason="no report (exit={})".format(exit_code),
                    exit_code=exit_code,
                ))
                write_summary(args.output, len(profiles), detailed_results)
                continue

            passed, reason = check_verdict(profile_path, profile_raw, report, exit_code)
            status = "PASS" if passed else "FAIL"
            print("  {}: {}".format(status, reason))
            results.append((name, passed, reason))
            detailed_results.append(build_detailed_result(
                profile=name,
                passed=passed,
                reason=reason,
                exit_code=exit_code,
                report=report,
            ))
            write_summary(args.output, len(profiles), detailed_results)

        try:
            current_profile_path.unlink()
        except FileNotFoundError:
            pass

    # Summary.
    print("\n" + "=" * 60)
    total = len(results)
    passed_count = sum(1 for _, p, _ in results if p)
    failed_count = total - passed_count

    for name, passed, reason in results:
        mark = "PASS" if passed else "FAIL"
        print("  [{}] {}: {}".format(mark, name, reason))

    print("\n{}/{} passed, {} failed".format(passed_count, total, failed_count))

    if args.output:
        write_summary(args.output, total, detailed_results)
        print("wrote {}".format(Path(args.output)))

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
