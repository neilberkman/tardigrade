#!/usr/bin/env python3
"""Run heuristic and exhaustive audits and compare their results.

Example:
    python3 scripts/run_heuristic_benchmark.py \
        --profile profiles/mcuboot_swap_current.yaml \
        --output-dir /tmp/mcuboot-bench \
        -- --renode-test docker://renode-patched:test --workers 2
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from compare_heuristic_vs_exhaustive import compare_results


REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit_bootloader.py"


def parse_args(argv: Sequence[str] | None = None) -> tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(
        description=(
            "Run audit_bootloader twice for the same profile: once with the "
            "normal heuristic path and once with exhaustive sweep forcing."
        )
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="Path to the profile to benchmark.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write audit outputs, logs, and comparison report.",
    )
    parser.add_argument(
        "--label",
        default=None,
        help="Optional label for the run metadata. Defaults to the profile stem.",
    )
    parser.add_argument(
        "--python",
        dest="python_exe",
        default=sys.executable,
        help="Python interpreter to use for child audit runs.",
    )
    args, audit_args = parser.parse_known_args(argv)
    # Strip leading '--' separator that parse_known_args preserves.
    if audit_args and audit_args[0] == "--":
        audit_args = audit_args[1:]
    return args, audit_args


def validate_audit_args(audit_args: Sequence[str]) -> None:
    """Reject passthrough arguments that would invalidate the comparison."""
    forbidden = {
        "--profile": "runner manages the profile path",
        "--output": "runner manages output locations",
        "--quick": "quick mode disables heuristic-vs-exhaustive comparison",
        "--fault-start": "fault-start would disable the heuristic selector",
        "--fault-end": "fault-end would disable the heuristic selector",
    }
    for idx, arg in enumerate(audit_args):
        if arg in forbidden:
            raise ValueError("unsupported audit arg '{}': {}".format(arg, forbidden[arg]))
        if arg == "--fault-step":
            if idx + 1 >= len(audit_args):
                raise ValueError("--fault-step requires a value")
            if int(audit_args[idx + 1]) != 1:
                raise ValueError("--fault-step must remain 1 for heuristic benchmarking")


def build_audit_command(
    python_exe: str,
    profile: Path,
    output_path: Path,
    audit_args: Sequence[str],
    *,
    exhaustive: bool,
) -> List[str]:
    cmd = [
        python_exe,
        str(AUDIT_SCRIPT),
        "--profile",
        str(profile),
        "--output",
        str(output_path),
    ]
    cmd.extend(audit_args)
    if exhaustive:
        # Explicitly setting fault-start disables the heuristic selector path
        # without otherwise changing the sweep range.
        cmd.extend(["--fault-start", "0"])
    return cmd


def run_audit(
    cmd: Sequence[str],
    output_path: Path,
    stdout_log: Path,
    stderr_log: Path,
) -> Dict[str, Any]:
    env = dict(os.environ)
    result = subprocess.run(
        list(cmd),
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    stdout_log.write_text(result.stdout, encoding="utf-8")
    stderr_log.write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(
            "audit_bootloader failed (exit {})\ncommand: {}\nstdout: {}\nstderr: {}".format(
                result.returncode,
                " ".join(shlex.quote(a) for a in cmd),
                stdout_log,
                stderr_log,
            )
        )
    with open(output_path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_run_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    runtime = (payload.get("summary") or {}).get("runtime_sweep") or {}
    return {
        "profile": payload.get("profile"),
        "verdict": payload.get("verdict"),
        "fault_points_tested": payload.get("fault_points_tested"),
        "issue_points": runtime.get("issue_points"),
        "bricks": runtime.get("bricks"),
        "semantic_issue_points": runtime.get("semantic_issue_points"),
        "invariant_issue_points": runtime.get("invariant_issue_points"),
        "wall_time_s": runtime.get("wall_time_s"),
        "heuristic": payload.get("heuristic"),
        "heuristic_config": payload.get("heuristic_config"),
    }


def build_report(
    heuristic_payload: Dict[str, Any],
    exhaustive_payload: Dict[str, Any],
    heuristic_output: Path,
    exhaustive_output: Path,
    heuristic_cmd: Sequence[str],
    exhaustive_cmd: Sequence[str],
) -> Dict[str, Any]:
    comparison = compare_results(
        exhaustive_payload.get("runtime_sweep_results", []),
        heuristic_payload.get("runtime_sweep_results", []),
    )
    heuristic_summary = extract_run_summary(heuristic_payload)
    exhaustive_summary = extract_run_summary(exhaustive_payload)
    heur_wall = heuristic_summary.get("wall_time_s")
    ex_wall = exhaustive_summary.get("wall_time_s")
    if heur_wall and ex_wall:
        comparison["exhaustive_over_heuristic_wall_ratio"] = round(ex_wall / heur_wall, 4)
    heur_points = heuristic_summary.get("fault_points_tested")
    ex_points = exhaustive_summary.get("fault_points_tested")
    if heur_points and ex_points:
        comparison["exhaustive_over_heuristic_point_ratio"] = round(ex_points / heur_points, 4)

    return {
        "profile": heuristic_payload.get("profile") or exhaustive_payload.get("profile"),
        "heuristic_run": heuristic_summary,
        "exhaustive_run": exhaustive_summary,
        "comparison": comparison,
        "artifacts": {
            "heuristic_audit_json": str(heuristic_output),
            "exhaustive_audit_json": str(exhaustive_output),
        },
        "commands": {
            "heuristic": " ".join(shlex.quote(a) for a in heuristic_cmd),
            "exhaustive": " ".join(shlex.quote(a) for a in exhaustive_cmd),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    args, audit_args = parse_args(argv)
    validate_audit_args(audit_args)

    profile = Path(args.profile).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    label = args.label or profile.stem
    heuristic_output = output_dir / "heuristic.audit.json"
    exhaustive_output = output_dir / "exhaustive.audit.json"
    heuristic_stdout = output_dir / "heuristic.stdout.log"
    heuristic_stderr = output_dir / "heuristic.stderr.log"
    exhaustive_stdout = output_dir / "exhaustive.stdout.log"
    exhaustive_stderr = output_dir / "exhaustive.stderr.log"
    report_output = output_dir / "comparison.json"

    heuristic_cmd = build_audit_command(
        args.python_exe,
        profile,
        heuristic_output,
        audit_args,
        exhaustive=False,
    )
    exhaustive_cmd = build_audit_command(
        args.python_exe,
        profile,
        exhaustive_output,
        audit_args,
        exhaustive=True,
    )

    print(
        "[heuristic-benchmark] running heuristic sweep for {}".format(label),
        file=sys.stderr,
        flush=True,
    )
    heuristic_payload = run_audit(
        heuristic_cmd,
        heuristic_output,
        heuristic_stdout,
        heuristic_stderr,
    )
    if heuristic_payload.get("heuristic") is None:
        raise RuntimeError(
            "heuristic run did not produce heuristic summary; check the profile sweep_strategy "
            "and forwarded audit args"
        )

    print(
        "[heuristic-benchmark] running exhaustive sweep for {}".format(label),
        file=sys.stderr,
        flush=True,
    )
    exhaustive_payload = run_audit(
        exhaustive_cmd,
        exhaustive_output,
        exhaustive_stdout,
        exhaustive_stderr,
    )

    report = build_report(
        heuristic_payload,
        exhaustive_payload,
        heuristic_output,
        exhaustive_output,
        heuristic_cmd,
        exhaustive_cmd,
    )
    report["label"] = label
    report_output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report["comparison"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
