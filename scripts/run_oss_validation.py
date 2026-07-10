#!/usr/bin/env python3
"""Run OSS validation profiles: read manifest, iterate fault points, check expectations.

Internal orchestrator for the oss-validation.yml GitHub workflow.
Not intended as a user-facing CLI -- use audit_bootloader.py for direct profile runs.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from fault_classification import _effective_boot_result


PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def validate_profile_name(value: Any) -> str:
    """Return a safe profile identifier suitable for result path names."""
    if not isinstance(value, str) or not PROFILE_NAME_RE.fullmatch(value):
        raise ValueError(
            "OSS profile name must match {}: {!r}".format(
                PROFILE_NAME_RE.pattern,
                value,
            )
        )
    return value


def _require_contained(root: Path, candidate: Path, *, label: str) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("{} escapes {}: {}".format(label, root, candidate)) from exc
    return candidate


def source_worktree_path(repo_root: Path, profile_name: str) -> Path:
    """Return the contained worktree path for a validated profile name."""
    name = validate_profile_name(profile_name)
    worktree_root = (repo_root / "results" / "oss_validation" / "worktrees").resolve()
    return _require_contained(
        worktree_root,
        worktree_root / name,
        label="source worktree",
    )


def _worktree_marker_path(source_worktree: Path) -> Path:
    return source_worktree.parent / ".{}.tardigrade-worktree.json".format(
        source_worktree.name
    )


def _read_worktree_marker(source_worktree: Path) -> Dict[str, Any] | None:
    marker = _worktree_marker_path(source_worktree)
    if not marker.is_file():
        return None
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid managed-worktree marker: {}".format(marker)) from exc
    return payload if isinstance(payload, dict) else None


def _write_worktree_marker(source_worktree: Path, source_repo: Path) -> None:
    marker = _worktree_marker_path(source_worktree)
    payload = {
        "version": 1,
        "source_repo": str(source_repo.resolve()),
        "source_worktree": str(source_worktree.resolve()),
    }
    marker.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=".{}-".format(marker.name),
        suffix=".tmp",
        dir=str(marker.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, marker)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _is_registered_worktree(source_repo: Path, source_worktree: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(source_repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    expected = source_worktree.resolve()
    for line in proc.stdout.splitlines():
        if not line.startswith("worktree "):
            continue
        if Path(line[len("worktree "):]).resolve() == expected:
            return True
    return False


class SafeTemplateDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render(value: Any, variables: Dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(SafeTemplateDict(variables))
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    return value


def is_brick(result: Dict[str, Any]) -> bool:
    outcome, _ = _effective_boot_result(result)
    outcome = str(outcome or "unknown").strip().lower()
    return outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}


def _effective_outcome_str(result: Dict[str, Any]) -> str:
    outcome, _ = _effective_boot_result(result)
    return str(outcome or "unknown").strip().lower()


def _format_outcome_span(result: Dict[str, Any]) -> str:
    initial = str(
        result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    ).strip().lower()
    final = _effective_outcome_str(result)
    return final if final == initial else "{} -> {}".format(initial, final)


def git_ref_exists(repo: Path, ref: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "{}^{{commit}}".format(ref)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def ensure_source_worktree(
    repo_root: Path,
    profile_name: str,
    source_checkout: Dict[str, Any],
    source_worktree: Path,
) -> None:
    profile_name = validate_profile_name(profile_name)
    expected_worktree = source_worktree_path(repo_root, profile_name)
    if source_worktree.resolve() != expected_worktree:
        raise ValueError(
            "source worktree must be the managed profile path {}".format(
                expected_worktree
            )
        )
    source_worktree = expected_worktree
    source_repo = _require_contained(
        repo_root,
        repo_root / str(source_checkout["repo"]),
        label="source checkout repo",
    )
    ref = str(source_checkout["ref"])
    fetch_remote = str(source_checkout.get("fetch_remote", "")).strip()

    if not source_repo.is_dir():
        raise RuntimeError("source checkout repo not found: {}".format(source_repo))

    if not git_ref_exists(source_repo, ref):
        if not fetch_remote:
            raise RuntimeError(
                "ref '{}' missing in {} and no fetch_remote configured".format(ref, source_repo)
            )
        proc = subprocess.run(
            ["git", "-C", str(source_repo), "fetch", "--quiet", fetch_remote, ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "git fetch failed for {} {}:\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                    fetch_remote, ref, proc.stdout, proc.stderr
                )
            )
        if not git_ref_exists(source_repo, ref):
            raise RuntimeError(
                "ref '{}' still missing after fetch from {}".format(ref, fetch_remote)
            )

    source_worktree.parent.mkdir(parents=True, exist_ok=True)

    if source_worktree.exists():
        marker = _read_worktree_marker(source_worktree)
        expected_marker = {
            "version": 1,
            "source_repo": str(source_repo.resolve()),
            "source_worktree": str(source_worktree.resolve()),
        }
        if marker != expected_marker:
            raise RuntimeError(
                "refusing to remove unowned worktree path: {}".format(source_worktree)
            )
        if not _is_registered_worktree(source_repo, source_worktree):
            raise RuntimeError(
                "refusing to remove path not registered as a git worktree: {}".format(
                    source_worktree
                )
            )
        proc = subprocess.run(
            ["git", "-C", str(source_repo), "worktree", "remove", "--force", str(source_worktree)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or source_worktree.exists():
            raise RuntimeError(
                "git refused to remove managed worktree {}:\n{}".format(
                    source_worktree,
                    proc.stderr,
                )
            )

    proc = subprocess.run(
        [
            "git", "-C", str(source_repo), "worktree", "add", "--detach", "--force",
            str(source_worktree), ref,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git worktree add failed for {} at {}:\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                profile_name, ref, proc.stdout, proc.stderr
            )
        )
    try:
        _write_worktree_marker(source_worktree, source_repo)
    except Exception:
        subprocess.run(
            ["git", "-C", str(source_repo), "worktree", "remove", "--force", str(source_worktree)],
            capture_output=True,
            text=True,
            check=False,
        )
        raise


def run_single_fault_point(
    repo_root: Path, renode_test: str, robot_suite: str,
    fault_at: int, robot_vars: List[str], work_dir: Path,
    total_writes: int, is_control: bool,
) -> Dict[str, Any]:
    label = "control" if is_control else "f{}".format(fault_at)
    point_dir = work_dir / label
    point_dir.mkdir(parents=True, exist_ok=True)
    result_file = point_dir / "result.json"
    bundle_dir = work_dir / ".dotnet_bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        renode_test,
        "--renode-config", str(work_dir / "renode.config"),
        str(repo_root / robot_suite),
        "--results-dir", str(point_dir / "robot"),
        "--variable", "FAULT_AT:{}".format(fault_at),
        "--variable", "TOTAL_WRITES:{}".format(total_writes),
        "--variable", "RESULT_FILE:{}".format(result_file),
    ]
    for rv in robot_vars:
        cmd.extend(["--variable", rv])

    env = os.environ.copy()
    env.setdefault("DOTNET_BUNDLE_EXTRACT_BASE_DIR", str(bundle_dir))

    try:
        proc = subprocess.run(
            cmd, cwd=str(repo_root), capture_output=True, text=True,
            check=False, env=env, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"fault_at": fault_at, "is_control": is_control,
                "boot_outcome": "infra_error", "error": "timeout"}

    if proc.returncode != 0 or not result_file.exists():
        return {"fault_at": fault_at, "is_control": is_control,
                "boot_outcome": "infra_error",
                "error": "rc={} stderr={}".format(proc.returncode, (proc.stderr or "")[-500:])}

    data = json.loads(result_file.read_text(encoding="utf-8"))
    fault_injected = data.get("fault_injected")
    if type(fault_injected) is not bool:
        nvm_state = data.get("nvm_state")
        if isinstance(nvm_state, dict):
            fault_injected = nvm_state.get("faulted")
    return {
        "fault_at": fault_at,
        "is_control": is_control,
        "fault_injected": fault_injected,
        "boot_outcome": data.get("boot_outcome", "unknown"),
        "boot_slot": data.get("boot_slot"),
        "initial_boot_outcome": data.get("initial_boot_outcome"),
        "initial_boot_slot": data.get("initial_boot_slot"),
        "final_boot_outcome": data.get("final_boot_outcome"),
        "final_boot_slot": data.get("final_boot_slot"),
        "multi_boot_analysis": data.get("multi_boot_analysis"),
    }


def run_profile(
    repo_root: Path, renode_test: str, profile: Dict[str, Any],
    variables: Dict[str, str], workers: int, skip_setup: bool,
) -> Dict[str, Any]:
    name = validate_profile_name(profile["name"])
    variables = dict(variables)
    source_checkout = render(profile.get("source_checkout"), variables)
    source_worktree: Path | None = None
    if source_checkout:
        source_worktree = source_worktree_path(repo_root, name)
        variables["source_worktree"] = str(source_worktree)
    rendered = render(profile, variables)
    robot_suite = str(rendered.get("robot_suite", "tests/generic_fault_point.robot"))
    robot_vars = [str(rv) for rv in rendered.get("robot_vars", [])]
    total_writes = int(rendered.get("total_writes", 28672))
    if total_writes <= 0:
        raise ValueError("total_writes must be positive")

    for key in ("slot_a_image_file", "slot_b_image_file", "ota_header_size",
                "evaluation_mode", "boot_mode"):
        val = rendered.get(key)
        if val is not None:
            robot_vars.append("{}:{}".format(key.upper(), val))

    source_worktree_ready = False
    if not skip_setup:
        for raw_cmd in (rendered.get("setup_commands") or []):
            cmd = str(render(raw_cmd, variables))
            if (
                source_checkout
                and source_worktree is not None
                and not source_worktree_ready
                and str(source_worktree) in cmd
            ):
                ensure_source_worktree(repo_root, name, source_checkout, source_worktree)
                source_worktree_ready = True
            print("  setup>> {}".format(cmd), file=sys.stderr)
            proc = subprocess.run(["/bin/bash", "-lc", cmd], cwd=str(repo_root), check=False)
            if proc.returncode != 0:
                raise RuntimeError("setup failed (rc={}): {}".format(proc.returncode, cmd))
    elif source_checkout and source_worktree is not None:
        ensure_source_worktree(repo_root, name, source_checkout, source_worktree)

    # Build fault point list from profile range/step.
    fault_range = str(rendered.get("fault_range", "0:{}".format(total_writes - 1)))
    fault_step = int(rendered.get("fault_step", 4000))
    if fault_step <= 0:
        raise ValueError("fault_step must be positive")
    start_s, end_s = fault_range.split(":", 1)
    start, end = int(start_s), int(end_s)
    if start < 0 or end < start or end >= total_writes:
        raise ValueError(
            "fault_range must be an inclusive subset of 0:{}; got {}".format(
                total_writes - 1,
                fault_range,
            )
        )
    fault_points = list(range(start, end + 1, fault_step))
    if end not in fault_points:
        fault_points.append(end)

    control_fault_at = max(999999, total_writes) + 1
    all_tasks = [(fp, False) for fp in fault_points] + [(control_fault_at, True)]

    temp_ctx = tempfile.TemporaryDirectory(prefix="oss_val_{}_".format(name))
    work_dir = Path(temp_ctx.name)

    def execute(task):
        fp, is_ctrl = task
        return run_single_fault_point(
            repo_root, renode_test, robot_suite, fp,
            robot_vars, work_dir, total_writes, is_ctrl)

    results: List[Dict[str, Any]] = []
    total = len(all_tasks)

    if workers <= 1:
        for i, task in enumerate(all_tasks):
            print("\r  [{}/{}] {} fault_at={}".format(i + 1, total, name, task[0]),
                  end="", flush=True, file=sys.stderr)
            results.append(execute(task))
        print("", file=sys.stderr)
    else:
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            fmap = {pool.submit(execute, t): t for t in all_tasks}
            for future in concurrent.futures.as_completed(fmap):
                completed += 1
                print("\r  [{}/{}] {} fault_at={}".format(completed, total, name, fmap[future][0]),
                      end="", flush=True, file=sys.stderr)
                results.append(future.result())
        print("", file=sys.stderr)

    temp_ctx.cleanup()

    # Evaluate against expectations.
    expect = profile.get("expect") or {}
    control = [r for r in results if r.get("is_control")]
    faulted = [r for r in results if not r.get("is_control")]
    bricks = sum(1 for r in faulted if is_brick(r))
    issues = sum(1 for r in faulted if _effective_outcome_str(r) != "success")
    incomplete_outcomes = {
        "",
        "unknown",
        "infra_error",
        "infrastructure_error",
        "timeout",
        "skipped",
    }
    incomplete_results = [
        r
        for r in results
        if (
            _effective_outcome_str(r) in incomplete_outcomes
            or r.get("error")
            or type(r.get("fault_injected")) is not bool
            or (
                not r.get("is_control")
                and r.get("fault_injected") is not True
            )
            or (
                r.get("is_control")
                and r.get("fault_injected") is not False
            )
        )
    ]
    errors = len(incomplete_results)
    brick_rate = (float(bricks) / len(faulted)) if faulted else 0.0
    issue_rate = (float(issues) / len(faulted)) if faulted else 0.0
    failures: List[str] = []

    if incomplete_results:
        failures.append(
            "{} run(s) produced incomplete or infrastructure results".format(
                len(incomplete_results)
            )
        )

    bricks_max = expect.get("bricks_max")
    if bricks_max is not None and bricks > int(bricks_max):
        failures.append("bricks={} exceeds max {}".format(bricks, bricks_max))
    bricks_min = expect.get("bricks_min")
    if bricks_min is not None and bricks < int(bricks_min):
        failures.append("bricks={} below min {}".format(bricks, bricks_min))

    issues_max = expect.get("issues_max")
    if issues_max is not None and issues > int(issues_max):
        failures.append("issues={} exceeds max {}".format(issues, issues_max))
    issues_min = expect.get("issues_min")
    if issues_min is not None and issues < int(issues_min):
        failures.append("issues={} below min {}".format(issues, issues_min))

    if expect.get("require_control_success"):
        bad = [r for r in control if _effective_outcome_str(r) != "success"]
        if bad:
            failures.append("control failed: {}".format(_format_outcome_span(bad[0])))
        if not control:
            failures.append("no control run")

    return {
        "profile": name, "passed": len(failures) == 0,
        "faulted_runs": len(faulted), "bricks": bricks,
        "brick_rate": round(brick_rate, 4), "issues": issues,
        "issue_rate": round(issue_rate, 4), "infra_errors": errors,
        "failures": failures, "results": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="OSS validation profile runner")
    p.add_argument("--manifest", default="docs/oss_validation_profiles.json")
    p.add_argument("--profile", default=None, help="Run a single profile by name")
    p.add_argument("--renode-test", default=os.environ.get("RENODE_TEST", "renode-test"))
    p.add_argument("--output", default=None, help="Output summary JSON path")
    p.add_argument("--list", action="store_true", dest="list_profiles")
    p.add_argument("--skip-setup", action="store_true")
    p.add_argument("--workers", type=int, default=1)
    args = p.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = (repo_root / manifest_path).resolve()

    profiles = json.loads(manifest_path.read_text(encoding="utf-8"))["profiles"]
    profile_names = [validate_profile_name(profile.get("name")) for profile in profiles]
    if len(set(profile_names)) != len(profile_names):
        raise ValueError("OSS validation manifest contains duplicate profile names")

    if args.list_profiles:
        for prof in profiles:
            print("{:<40s} {}".format(prof["name"], prof.get("description", "")))
        return 0

    renode_test = args.renode_test
    if not os.path.isabs(renode_test):
        resolved = shutil.which(renode_test)
        if resolved is None:
            print("ERROR: renode-test '{}' not found in PATH".format(renode_test), file=sys.stderr)
            return 2
        renode_test = resolved

    if args.profile:
        selected = [p for p in profiles if p["name"] == args.profile]
        if not selected:
            print("ERROR: profile '{}' not found".format(args.profile), file=sys.stderr)
            return 2
    else:
        selected = profiles

    all_results: List[Dict[str, Any]] = []
    for profile in selected:
        name = profile["name"]
        variables = {"repo_root": str(repo_root), "variant_name": name}
        print("--- {} ---".format(name), file=sys.stderr)
        entry = run_profile(repo_root, renode_test, profile, variables, args.workers, args.skip_setup)
        all_results.append(entry)
        status = "PASS" if entry["passed"] else "FAIL"
        print("  {} bricks={}/{} issues={}/{} {}".format(
            status, entry["bricks"], entry["faulted_runs"],
            entry["issues"], entry["faulted_runs"],
            " ".join(entry["failures"])), file=sys.stderr)

    all_passed = all(r["passed"] for r in all_results)
    summary = {
        "run_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "all_passed": all_passed,
        "profiles": [{k: v for k, v in r.items() if k != "results"} for r in all_results],
        "detailed_results": all_results,
    }

    out_path = Path(args.output) if args.output else (repo_root / "results" / "oss_validation" / "summary.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print("wrote {}".format(out_path), file=sys.stderr)

    compact = {k: v for k, v in summary.items() if k != "detailed_results"}
    print(json.dumps(compact, indent=2, sort_keys=True))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
