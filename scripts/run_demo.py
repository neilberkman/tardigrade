#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Run the first-result broken-versus-recovering power-loss demo."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
BROKEN_PROFILE = Path("profiles/naive_bare_copy.yaml")
RECOVERING_PROFILE = Path("profiles/demo_mcuboot_offset_upgrade.yaml")
DEMO_FAULT_END = 64


@dataclass(frozen=True)
class DemoResult:
    """The small report subset rendered by the demo."""

    label: str
    profile: str
    report_path: Path
    points_run: int
    findings: int
    first_operation: Optional[int] = None
    first_address: Optional[str] = None
    first_boot_outcome: Optional[str] = None
    first_boot_slot: Optional[str] = None


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _points_run(runtime_summary: Mapping[str, Any]) -> int:
    if "returned_fault_points" in runtime_summary:
        return _integer(runtime_summary.get("returned_fault_points"))
    point_counts = runtime_summary.get("point_counts") or {}
    totals = point_counts.get("totals") or {}
    kinds = point_counts.get("kinds") or {}
    control = kinds.get("control") or {}
    return max(0, _integer(totals.get("run")) - _integer(control.get("run")))


def _format_address(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, int):
        return "0x{:08X}".format(value)
    text = str(value).strip()
    return text or None


def result_from_report(
    payload: Mapping[str, Any], *, label: str, report_path: Path
) -> DemoResult:
    """Extract the stable demo fields from a detailed audit report."""
    profile = str(payload.get("profile") or "unknown")
    summary = payload.get("summary") or {}
    runtime = summary.get("runtime_sweep") or {}
    findings = _integer(runtime.get("issue_points"))
    failures = runtime.get("failures") or []

    operation: Optional[int] = None
    address: Optional[str] = None
    boot_outcome: Optional[str] = None
    boot_slot: Optional[str] = None
    if findings and failures:
        first = failures[0]
        if isinstance(first, Mapping):
            raw_operation = first.get("fault_at")
            try:
                operation = int(raw_operation)
            except (TypeError, ValueError):
                operation = None
            address = _format_address(first.get("fault_address"))
            for row in payload.get("runtime_sweep_results") or []:
                if not isinstance(row, Mapping) or row.get("is_control"):
                    continue
                if _integer(row.get("fault_at"), -1) != operation:
                    continue
                boot_outcome = str(
                    row.get("initial_boot_outcome")
                    or row.get("boot_outcome")
                    or "unknown"
                )
                slot = row.get("initial_boot_slot") or row.get("boot_slot")
                boot_slot = str(slot) if slot is not None else None
                break
            if boot_outcome is None:
                boot_outcome = str(first.get("outcome") or "unknown")

    return DemoResult(
        label=label,
        profile=profile,
        report_path=report_path,
        points_run=_points_run(runtime),
        findings=findings,
        first_operation=operation,
        first_address=address,
        first_boot_outcome=boot_outcome,
        first_boot_slot=boot_slot,
    )


def smoke_test_failures(results: Sequence[DemoResult]) -> List[str]:
    """Return expectation failures for the broken/recovering pair."""
    by_label = {result.label: result for result in results}
    failures: List[str] = []
    broken = by_label.get("broken")
    recovering = by_label.get("recovering")
    if broken is None:
        failures.append("the broken profile did not produce a report")
    elif broken.findings == 0:
        failures.append("the broken profile showed no finding")
    if recovering is None:
        failures.append("the recovering profile did not produce a report")
    elif recovering.findings != 0:
        failures.append(
            "the recovering profile showed {} finding(s)".format(
                recovering.findings
            )
        )
    return failures


def smoke_test_exit_code(results: Sequence[DemoResult]) -> int:
    return 1 if smoke_test_failures(results) else 0


def _boot_description(outcome: Optional[str], slot: Optional[str]) -> str:
    descriptions = {
        "success": "booted successfully",
        "wrong_image": "booted the wrong image",
        "memory_checks_unmet": "booted with unmet memory checks",
        "no_boot": "did not boot",
        "wrong_pc": "jumped to the wrong program counter",
        "misaligned_vtor": "used a misaligned vector table",
        "hard_fault": "hard-faulted",
        "bus_fault": "bus-faulted",
        "timeout": "timed out",
        "infra_error": "hit an infrastructure error",
    }
    normalized = str(outcome or "unknown").strip().lower()
    text = descriptions.get(normalized, normalized.replace("_", " "))
    if slot:
        text += " (slot {})".format(slot)
    return text


def format_summary(results: Sequence[DemoResult], *, repo_root: Path) -> str:
    """Render the concise, plain-text first result."""
    lines = ["Tardigrade power-loss demo"]
    for result in results:
        finding_label = "finding" if result.findings == 1 else "findings"
        lines.append(
            "{} [{}]: {} points run, {} {}".format(
                result.profile,
                result.label,
                result.points_run,
                result.findings,
                finding_label,
            )
        )
        if result.findings:
            operation = (
                str(result.first_operation)
                if result.first_operation is not None
                else "unknown"
            )
            address = result.first_address or "unknown"
            lines.append(
                "  first finding: cut operation {} at {}; next boot {}".format(
                    operation,
                    address,
                    _boot_description(
                        result.first_boot_outcome, result.first_boot_slot
                    ),
                )
            )
        else:
            lines.append("  first finding: none")

    lines.append("JSON reports:")
    for result in results:
        try:
            display_path = result.report_path.relative_to(repo_root)
        except ValueError:
            display_path = result.report_path
        lines.append("  {}: {}".format(result.label, display_path))
    lines.append(
        "HTML detail: python3 scripts/render_results_html.py "
        "--input <report.json> --output <report.html>"
    )
    failures = smoke_test_failures(results)
    lines.append("Smoke test: {}".format("FAIL" if failures else "PASS"))
    for failure in failures:
        lines.append("  {}".format(failure))
    return "\n".join(lines)


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _run_profile(
    *,
    profile: Path,
    report_path: Path,
    log_path: Path,
    renode_test: str,
    workers: int,
    timeout: int,
) -> Tuple[int, Optional[str]]:
    command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "audit_bootloader.py"),
        "--profile",
        str(profile),
        "--output",
        str(report_path),
        "--renode-test",
        renode_test,
        "--quick",
        "--fault-end",
        str(DEMO_FAULT_END),
        "--strict-profile",
        "--no-assert-verdict",
        "--workers",
        str(workers),
    ]
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(
        [str(Path(sys.executable).parent), environment.get("PATH", "")]
    )
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            command,
            cwd=str(REPO_ROOT),
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout), None
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return 124, "timed out after {} seconds".format(timeout)


def _resolve_renode_test(value: str) -> str:
    requested = value or os.environ.get("RENODE_TEST", "")
    if requested:
        path = Path(requested).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        resolved = shutil.which(requested)
        if resolved:
            return resolved
        raise ValueError("renode-test is not executable: {}".format(requested))
    resolved = shutil.which("renode-test")
    if not resolved:
        raise ValueError("renode-test was not found on PATH")
    return resolved


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the broken-versus-recovering power-loss demo."
    )
    parser.add_argument(
        "--renode-test",
        default="",
        help="renode-test executable (default: RENODE_TEST or PATH)",
    )
    parser.add_argument(
        "--output-dir",
        default="results/demo",
        help="report directory (default: results/demo)",
    )
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.workers not in (1, 2):
        parser.error("--workers must be 1 or 2")
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10+ is required", file=sys.stderr)
        return 2
    try:
        renode_test = _resolve_renode_test(args.renode_test)
    except ValueError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir).expanduser()
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    runs = (
        ("broken", BROKEN_PROFILE, output_dir / "naive_bare_copy.json"),
        (
            "recovering",
            RECOVERING_PROFILE,
            output_dir / "demo_mcuboot_offset_upgrade.json",
        ),
    )
    results: List[DemoResult] = []
    execution_failures: List[str] = []
    for label, profile, report_path in runs:
        log_path = report_path.with_suffix(".log")
        print(
            "Running {} profile {} ...".format(label, profile),
            flush=True,
        )
        returncode, error = _run_profile(
            profile=profile,
            report_path=report_path,
            log_path=log_path,
            renode_test=renode_test,
            workers=args.workers,
            timeout=args.timeout,
        )
        if error:
            execution_failures.append("{}: {}".format(label, error))
        if returncode != 0:
            execution_failures.append(
                "{}: audit exited {} (see {})".format(
                    label, returncode, log_path
                )
            )
        if not report_path.is_file():
            execution_failures.append(
                "{}: report was not created (see {})".format(label, log_path)
            )
            continue
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("report root is not an object")
            results.append(
                result_from_report(
                    payload, label=label, report_path=report_path
                )
            )
        except (OSError, ValueError) as exc:
            execution_failures.append("{}: invalid report: {}".format(label, exc))

    print()
    print(format_summary(results, repo_root=REPO_ROOT))
    if execution_failures:
        print("Execution errors:", file=sys.stderr)
        for failure in execution_failures:
            print("  {}".format(failure), file=sys.stderr)
        return 2
    return smoke_test_exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
