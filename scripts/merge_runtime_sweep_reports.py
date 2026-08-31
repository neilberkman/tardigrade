#!/usr/bin/env python3
"""Merge sliced runtime sweep reports into one recomputed audit payload."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from audit_report import summarize_runtime_sweep
from profile_loader import ProfileConfig, load_profile


def _load_payload(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected JSON object payload")
    if not isinstance(payload.get("runtime_sweep_results"), list):
        raise ValueError(f"{path}: missing runtime_sweep_results list")
    return payload


def _result_sort_key(row: Dict[str, Any]) -> Tuple[int, int, str]:
    if row.get("is_control", False):
        return (-1, -1, "control")
    fault_at = row.get("fault_at", row.get("fault_point"))
    try:
        order = int(fault_at)
    except (TypeError, ValueError):
        order = sys.maxsize
    return (0, order, str(row.get("fault_type") or ""))


def _result_identity(row: Dict[str, Any]) -> Tuple[Any, ...]:
    if row.get("is_control", False):
        return ("control",)
    fault_at = row.get("fault_at", row.get("fault_point"))
    fault_type = row.get("fault_type")
    if fault_at is not None:
        return ("fault", fault_type, int(fault_at))
    return ("row", json.dumps(row, sort_keys=True, separators=(",", ":")))


def _load_profile_if_present(profile_path: Optional[str]) -> Optional[ProfileConfig]:
    if not profile_path:
        return None
    path = Path(profile_path)
    if not path.exists():
        return None
    return load_profile(path)


def merge_runtime_sweep_payloads(
    payloads: Sequence[Dict[str, Any]],
    source_paths: Optional[Sequence[Path]] = None,
) -> Dict[str, Any]:
    if not payloads:
        raise ValueError("at least one payload is required")

    first = payloads[0]
    first_profile_path = first.get("profile_path")
    first_target_source = first.get("target_source")
    for payload in payloads[1:]:
        if payload.get("profile") != first.get("profile"):
            raise ValueError("cannot merge reports from different profiles")
        if payload.get("profile_path") != first_profile_path:
            raise ValueError("cannot merge reports with different profile paths")
        if payload.get("target_source") != first_target_source:
            raise ValueError("cannot merge reports with different target sources")

    profile = _load_profile_if_present(first_profile_path)
    merged_results: List[Dict[str, Any]] = []
    seen: set[Tuple[Any, ...]] = set()
    control_row: Optional[Dict[str, Any]] = None

    for payload in payloads:
        for row in payload.get("runtime_sweep_results", []):
            if not isinstance(row, dict):
                raise ValueError("runtime_sweep_results rows must be mappings")
            identity = _result_identity(row)
            if identity in seen:
                continue
            seen.add(identity)
            if row.get("is_control", False):
                if control_row is None:
                    control_row = row
                continue
            merged_results.append(row)

    merged_results.sort(key=_result_sort_key)
    ordered_results = ([control_row] if control_row is not None else []) + merged_results

    calibrated_writes = max(int(payload.get("calibrated_writes") or 0) for payload in payloads)
    calibrated_erases = max(int(payload.get("calibrated_erases") or 0) for payload in payloads)
    summary = summarize_runtime_sweep(
        ordered_results,
        total_writes=calibrated_writes,
        profile=profile,
    )

    merged_payload: Dict[str, Any] = {
        "engine": first.get("engine"),
        "profile": first.get("profile"),
        "profile_path": first_profile_path,
        "schema_version": first.get("schema_version"),
        "calibrated_writes": calibrated_writes,
        "calibrated_erases": calibrated_erases,
        "setup_writes": max(int(payload.get("setup_writes") or 0) for payload in payloads),
        "fault_points_tested": len(merged_results),
        "quick": any(bool(payload.get("quick")) for payload in payloads),
        "heuristic": first.get("heuristic"),
        "heuristic_config": first.get("heuristic_config"),
        "multi_fault": first.get("multi_fault"),
        "verdict": first.get("verdict"),
        "summary": {"runtime_sweep": summary},
        "expect": first.get("expect"),
        "security_policy": first.get("security_policy"),
        "runtime_sweep_results": ordered_results,
        "execution": {
            "run_utc": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "merged_reports": [str(path) for path in source_paths or []],
            "slice_count": len(payloads),
        },
        "git": first.get("git"),
    }
    if first_target_source is not None:
        merged_payload["target_source"] = first_target_source
    for key in ("contracts", "calibration", "clean_trace"):
        if key in first:
            merged_payload[key] = first.get(key)
    return merged_payload


def merge_runtime_sweep_files(paths: Iterable[Path]) -> Dict[str, Any]:
    source_paths = [Path(path) for path in paths]
    payloads = [_load_payload(path) for path in source_paths]
    return merge_runtime_sweep_payloads(payloads, source_paths=source_paths)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge sliced runtime sweep reports into one recomputed report.",
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Input report JSON files to merge",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write merged payload to this path instead of stdout",
    )
    args = parser.parse_args()

    payload = merge_runtime_sweep_files(args.inputs)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output is None:
        print(rendered)
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
