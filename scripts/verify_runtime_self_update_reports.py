#!/usr/bin/env python3
"""Verify the synthetic runtime self-update end-to-end reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def _load(path: str) -> Dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError("{}: report is not an object".format(path))
    return payload


def _controls(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if payload.get("is_control") is True:
        return [payload]
    return [
        row
        for row in payload.get("runtime_sweep_results", [])
        if isinstance(row, dict) and row.get("is_control")
    ]


def verify(positive_path: str, no_reset_path: str, hung_path: str) -> None:
    positive = _load(positive_path)
    controls = _controls(positive)
    assert len(controls) == 1, "positive report must contain one control"
    control = controls[0]
    assert control.get("boot_outcome") == "success", control
    signals = control.get("signals") or {}
    assert signals.get("phase1_stop_reason") == "success_terminal_after_reset", signals
    reset = signals.get("phase1_reset_observation") or {}
    assert reset.get("observed") is True, reset

    faults = [
        row
        for row in positive.get("runtime_sweep_results", [])
        if isinstance(row, dict) and not row.get("is_control")
    ]
    assert len(faults) == 3, "quick campaign must retain first/middle/last"
    points = [int(row["fault_at"]) for row in faults]
    assert points == sorted(points) and points[0] == 0, points
    assert all(row.get("boot_outcome") == "wrong_image" for row in faults), faults
    for row in faults:
        evidence = row.get("mram_fault_evidence") or {}
        assert evidence.get("exact") is True, evidence
        assert evidence.get("program_width") == 16, evidence

    for label, path in (("no_reset", no_reset_path), ("hung_update", hung_path)):
        report = _load(path)
        variant_controls = _controls(report)
        assert len(variant_controls) == 1, "{} report must contain one control".format(label)
        outcome = variant_controls[0].get("boot_outcome")
        assert outcome != "success", "{} unexpectedly reached success".format(label)


def main(argv: List[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: verify_runtime_self_update_reports.py POSITIVE NO_RESET HUNG",
            file=sys.stderr,
        )
        return 2
    verify(argv[1], argv[2], argv[3])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
