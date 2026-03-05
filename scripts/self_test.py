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


def run_audit(
    repo_root: Path,
    profile_path: Path,
    output_path: Path,
    quick: bool,
    renode_test: str,
    extra_args: List[str],
) -> Tuple[int, Dict[str, Any]]:
    """Run audit_bootloader.py for a single profile and return (exit_code, report)."""
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

    proc = subprocess.run(
        cmd, cwd=str(repo_root),
        capture_output=True, text=True, check=False,
    )

    report: Dict[str, Any] = {}
    if output_path.exists():
        try:
            report = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    return proc.returncode, report


def check_verdict(
    profile_path: Path,
    profile_raw: Dict[str, Any],
    report: Dict[str, Any],
    exit_code: int,
) -> Tuple[bool, str]:
    """Check whether the audit result matches the profile's expectations.

    Returns (passed, reason).
    """
    expect = profile_raw.get("expect", {})
    should_find_issues = expect.get("should_find_issues", True)
    brick_rate_min = float(expect.get("brick_rate_min", 0.0))

    verdict = report.get("verdict", "")
    summary = report.get("summary", {})
    sweep = summary.get("runtime_sweep", {})
    brick_rate = float(sweep.get("brick_rate", 0.0))
    bricks = int(sweep.get("bricks", 0))

    if should_find_issues:
        if bricks == 0:
            return False, "Expected bricks but found none"
        if brick_rate_min > 0 and brick_rate < brick_rate_min:
            return False, "Brick rate {:.1%} below minimum {:.1%}".format(
                brick_rate, brick_rate_min
            )
        return True, "Found {} bricks ({:.1%}), as expected".format(bricks, brick_rate)
    else:
        if bricks > 0:
            return False, "Expected no bricks but found {} ({:.1%})".format(
                bricks, brick_rate
            )
        return True, "No bricks found, as expected"


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
        "--output", default=None,
        help="Optional JSON summary output path.",
    )
    parser.add_argument(
        "--shard", default=None,
        help="Run shard N of M total (e.g. '1/4' runs the first quarter).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    # Discover profiles.
    if args.profile:
        profiles = [Path(p) for p in args.profile]
    else:
        profiles = discover_profiles(repo_root)

    # Apply sharding (round-robin so slow profiles spread evenly).
    if args.shard:
        shard_idx, shard_total = (int(x) for x in args.shard.split("/"))
        profiles = profiles[shard_idx - 1::shard_total]

    if not profiles:
        print("No profiles found.", file=sys.stderr)
        return 1

    print("Self-test: {} profiles".format(len(profiles)))
    print("=" * 60)

    results: List[Tuple[str, bool, str]] = []
    detailed_results: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="self_test_") as tmp:
        for profile_path in profiles:
            name = profile_path.stem
            output_path = Path(tmp) / "{}_result.json".format(name)

            print("\n--- {} ---".format(name))

            # Read raw YAML for expect section.
            try:
                profile_raw = load_profile_raw(profile_path)
            except Exception as exc:
                print("  SKIP: failed to load profile: {}".format(exc))
                results.append((name, False, "profile load error: {}".format(exc)))
                detailed_results.append({
                    "profile": name,
                    "passed": False,
                    "reason": "profile load error: {}".format(exc),
                    "exit_code": None,
                    "verdict": None,
                    "bricks": None,
                    "brick_rate": None,
                })
                continue

            extra_args: List[str] = []
            if args.renode_remote_server_dir:
                extra_args.extend(["--renode-remote-server-dir", args.renode_remote_server_dir])
            if args.fault_step is not None:
                extra_args.extend(["--fault-step", str(args.fault_step)])

            try:
                exit_code, report = run_audit(
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
                detailed_results.append({
                    "profile": name,
                    "passed": False,
                    "reason": "audit crash: {}".format(exc),
                    "exit_code": None,
                    "verdict": None,
                    "bricks": None,
                    "brick_rate": None,
                })
                continue

            if not report:
                print("  FAIL: no report produced (exit={})".format(exit_code))
                results.append((name, False, "no report (exit={})".format(exit_code)))
                detailed_results.append({
                    "profile": name,
                    "passed": False,
                    "reason": "no report (exit={})".format(exit_code),
                    "exit_code": exit_code,
                    "verdict": None,
                    "bricks": None,
                    "brick_rate": None,
                })
                continue

            passed, reason = check_verdict(profile_path, profile_raw, report, exit_code)
            status = "PASS" if passed else "FAIL"
            print("  {}: {}".format(status, reason))
            results.append((name, passed, reason))
            sweep = report.get("summary", {}).get("runtime_sweep", {})
            detailed_results.append({
                "profile": name,
                "passed": passed,
                "reason": reason,
                "exit_code": exit_code,
                "verdict": report.get("verdict"),
                "bricks": sweep.get("bricks"),
                "brick_rate": sweep.get("brick_rate"),
            })

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
        payload = {
            "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "total_profiles": total,
            "passed": passed_count,
            "failed": failed_count,
            "results": detailed_results,
        }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print("wrote {}".format(output_path))

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
