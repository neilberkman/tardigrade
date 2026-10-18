#!/usr/bin/env python3
"""Summarize a single MCUboot zero-day canary profile report.

Reads the audit report JSON alongside the MCUboot and Zephyr commit files,
prints a human-readable summary to stdout, appends a Markdown summary table to
``GITHUB_STEP_SUMMARY`` when configured, and emits one JSON line per run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

from report_security_status import build_security_aggregate


DEFAULT_MCUBOOT_COMMIT_FILE = Path(
    "results/oss_validation/assets/mcuboot_head_commit.txt"
)
DEFAULT_ZEPHYR_COMMIT_FILE = Path(
    "results/oss_validation/assets/zephyr_head_commit.txt"
)


def _read_commit(explicit: str | None, path: Path | None) -> str:
    if explicit is not None and explicit.strip():
        return explicit.strip()
    if path is not None and path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    return "unknown"


def _normalize_profile_name(profile: str | None, report_path: Path) -> str:
    if isinstance(profile, str) and profile.strip():
        raw = profile.strip()
        if raw.endswith(".yaml") or raw.endswith(".yml") or "/" in raw:
            return Path(raw).stem
        return raw
    return report_path.stem


def _extract_security_status(payload: Mapping[str, Any]) -> str:
    sec_agg = payload.get("security_aggregate")
    if isinstance(sec_agg, Mapping):
        status = sec_agg.get("status")
        if isinstance(status, str) and status.strip():
            return status.strip()
    try:
        computed = build_security_aggregate(dict(payload))
        status = computed.get("status")
        if isinstance(status, str) and status.strip():
            return status.strip()
    except Exception:
        pass
    return "INCONCLUSIVE"


def extract_summary_record(
    report_path: Path,
    *,
    mcuboot_commit: str | None = None,
    mcuboot_commit_file: Path | None = DEFAULT_MCUBOOT_COMMIT_FILE,
    zephyr_commit: str | None = None,
    zephyr_commit_file: Path | None = DEFAULT_ZEPHYR_COMMIT_FILE,
    profile_fallback: str | None = None,
) -> dict[str, Any]:
    """Extract a normalized zero-day summary record from *report_path*."""
    resolved_mcuboot = _read_commit(mcuboot_commit, mcuboot_commit_file)
    resolved_zephyr = _read_commit(zephyr_commit, zephyr_commit_file)

    if not report_path.is_file():
        profile_name = _normalize_profile_name(profile_fallback, report_path)
        return {
            "bricks": 0,
            "issue_points": 0,
            "mcuboot_commit": resolved_mcuboot,
            "points": 0,
            "profile": profile_name,
            "security_aggregate": {"status": "INCONCLUSIVE"},
            "security_status": "INCONCLUSIVE",
            "timeouts": 0,
            "verdict": "MISSING_REPORT",
            "wall_time_s": 0.0,
            "zephyr_commit": resolved_zephyr,
        }

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"report {report_path} must contain a JSON object")

    profile_name = _normalize_profile_name(
        payload.get("profile") or profile_fallback,
        report_path,
    )
    raw_verdict = payload.get("verdict")
    verdict = (
        str(raw_verdict).replace("\u2014", "--").strip()
        if raw_verdict is not None and str(raw_verdict).strip()
        else "UNKNOWN"
    )
    security_status = _extract_security_status(payload)

    summary = payload.get("summary")
    summary_map = summary if isinstance(summary, Mapping) else {}
    runtime = summary_map.get("runtime_sweep")
    runtime_map = runtime if isinstance(runtime, Mapping) else {}
    integrity = runtime_map.get("campaign_integrity")
    integrity_map = integrity if isinstance(integrity, Mapping) else {}

    points = int(runtime_map.get("total_fault_points", 0) or 0)
    issue_points = int(runtime_map.get("issue_points", 0) or 0)
    bricks = int(runtime_map.get("bricks", 0) or 0)

    fault_timeouts = runtime_map.get("timeout_points")
    if fault_timeouts is None:
        fault_timeouts = integrity_map.get(
            "timeouts", runtime_map.get("timeouts", 0)
        )
    control_timeouts = runtime_map.get("control_timeout_points")
    if control_timeouts is None:
        control_timeouts = integrity_map.get("control_timeouts", 0)
    timeouts = int(fault_timeouts or 0) + int(control_timeouts or 0)

    raw_wall = runtime_map.get("wall_time_s")
    wall_time_s = round(float(raw_wall), 1) if raw_wall is not None else 0.0

    return {
        "bricks": bricks,
        "issue_points": issue_points,
        "mcuboot_commit": resolved_mcuboot,
        "points": points,
        "profile": profile_name,
        "security_aggregate": {"status": security_status},
        "security_status": security_status,
        "timeouts": timeouts,
        "verdict": verdict,
        "wall_time_s": wall_time_s,
        "zephyr_commit": resolved_zephyr,
    }


def format_console_summary(record: Mapping[str, Any]) -> str:
    """Format human-readable lines for the job log."""
    sec_status = record.get("security_status") or record.get(
        "security_aggregate", {}
    ).get("status", "UNKNOWN")
    lines = [
        f"MCUboot: {record['mcuboot_commit']}",
        f"Zephyr: {record['zephyr_commit']}",
        f"Profile: {record['profile']}",
        f"Verdict: {record['verdict']}",
        f"security_aggregate.status: {sec_status}",
        f"Points: {record['points']}",
        f"Issue points: {record['issue_points']}",
        f"Bricks: {record['bricks']}",
        f"Timeouts: {record['timeouts']}",
        f"Wall time: {record['wall_time_s']}s",
    ]
    return "\n".join(lines) + "\n"


def format_step_summary(record: Mapping[str, Any]) -> str:
    """Format a GitHub Actions job step summary table."""
    sec_status = record.get("security_status") or record.get(
        "security_aggregate", {}
    ).get("status", "UNKNOWN")
    lines = [
        f"## Zero-day canary summary: `{record['profile']}`",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| MCUboot commit | `{record['mcuboot_commit']}` |",
        f"| Zephyr commit | `{record['zephyr_commit']}` |",
        f"| Profile | `{record['profile']}` |",
        f"| Verdict | `{record['verdict']}` |",
        f"| `security_aggregate.status` | `{sec_status}` |",
        f"| Points | `{record['points']}` |",
        f"| Issue points | `{record['issue_points']}` |",
        f"| Bricks | `{record['bricks']}` |",
        f"| Timeouts | `{record['timeouts']}` |",
        f"| Wall time | `{record['wall_time_s']}s` |",
        "",
    ]
    return "\n".join(lines)


def write_summary_outputs(
    record: Mapping[str, Any],
    *,
    jsonl_path: Path | None = None,
    step_summary_path: Path | None = None,
) -> None:
    """Write the JSON line and append the Markdown step summary."""
    if jsonl_path is not None:
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(record), sort_keys=True) + "\n")

    if step_summary_path is not None:
        step_summary_path.parent.mkdir(parents=True, exist_ok=True)
        with step_summary_path.open("a", encoding="utf-8") as handle:
            handle.write(format_step_summary(record))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        required=True,
        type=Path,
        help="Path to the audit report JSON file",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Fallback profile name or YAML path when the report is missing",
    )
    parser.add_argument(
        "--mcuboot-commit",
        default=None,
        help="Explicit MCUboot commit hash",
    )
    parser.add_argument(
        "--mcuboot-commit-file",
        default=DEFAULT_MCUBOOT_COMMIT_FILE,
        type=Path,
        help="File containing the MCUboot commit hash",
    )
    parser.add_argument(
        "--zephyr-commit",
        default=None,
        help="Explicit Zephyr commit hash",
    )
    parser.add_argument(
        "--zephyr-commit-file",
        default=DEFAULT_ZEPHYR_COMMIT_FILE,
        type=Path,
        help="File containing the Zephyr commit hash",
    )
    parser.add_argument(
        "--jsonl",
        default=None,
        type=Path,
        help="Path to emit one JSON line per run",
    )
    parser.add_argument(
        "--step-summary",
        default=None,
        type=Path,
        help="Path to append GitHub step summary Markdown; defaults to GITHUB_STEP_SUMMARY",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    jsonl_path = args.jsonl
    if jsonl_path is None:
        jsonl_path = args.report.with_suffix(".jsonl")

    step_summary_path = args.step_summary
    if step_summary_path is None:
        env_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
        if env_summary:
            step_summary_path = Path(env_summary)

    record = extract_summary_record(
        args.report,
        mcuboot_commit=args.mcuboot_commit,
        mcuboot_commit_file=args.mcuboot_commit_file,
        zephyr_commit=args.zephyr_commit,
        zephyr_commit_file=args.zephyr_commit_file,
        profile_fallback=args.profile,
    )
    sys.stdout.write(format_console_summary(record))
    write_summary_outputs(
        record,
        jsonl_path=jsonl_path,
        step_summary_path=step_summary_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
