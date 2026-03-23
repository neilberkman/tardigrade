#!/usr/bin/env python3
"""Tests for calibration coverage classification and verdict gating."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from audit_report import compute_verdict  # noqa: E402
from self_test import check_verdict  # noqa: E402
from trace_utils import summarize_calibration_coverage  # noqa: E402


def _slot(name_base: int, size: int = 0x1000) -> SimpleNamespace:
    return SimpleNamespace(base=name_base, size=size)


def _write_trace(path: Path, rows: list[str]) -> None:
    path.write_text(
        "write_index,flash_offset,value\n" + "\n".join(rows) + ("\n" if rows else ""),
        encoding="utf-8",
    )


def _base_summary() -> dict:
    return {
        "bricks": 0,
        "issue_points": 0,
        "semantic_issue_points": 0,
        "invariant_issue_points": 0,
        "metadata_delta_issue_points": 0,
        "timeout_points": 0,
        "resilient_rollbacks": 0,
        "control": {
            "boot_outcome": "success",
            "effective_outcome": "success",
            "final_boot_outcome": "success",
            "issue_count": 0,
        },
    }


def test_summarize_calibration_coverage_detects_slot_activity() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, ["1,8448,305419896"])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "slot_activity"
    assert coverage["slot_data_writes"] == 1
    assert coverage["slot_trailer_writes"] == 0


def test_summarize_calibration_coverage_detects_metadata_only() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, ["1,12096,305419896"])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "metadata_only"
    assert coverage["slot_trailer_writes"] == 1
    assert coverage["slot_data_writes"] == 0


def test_summarize_calibration_coverage_detects_no_activity() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, [])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "no_nvm_activity"
    assert coverage["writes"] == 0
    assert coverage["erases"] == 0


def test_compute_verdict_fails_clean_profile_when_calibration_only_touches_metadata() -> None:
    summary = _base_summary()
    summary["calibration_coverage"] = {
        "status": "metadata_only",
        "reason": "Calibration touched slot trailers/metadata but never moved slot data.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "FAIL — Calibration touched slot trailers/metadata but never moved slot data."


def test_compute_verdict_preserves_control_only_opt_in() -> None:
    summary = _base_summary()
    summary["control"] = {
        "boot_outcome": "wrong_image",
        "effective_outcome": "wrong_image",
        "final_boot_outcome": "wrong_image",
        "issue_count": 0,
    }
    summary["calibration_coverage"] = {
        "status": "no_nvm_activity",
        "reason": "Calibration produced no NVM writes or erases.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="wrong_image",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected wrong_image"


def test_self_test_rejects_clean_profile_when_calibration_never_exercised_slot_data() -> None:
    passed, reason = check_verdict(
        Path("profiles/clean.yaml"),
        {"expect": {"should_find_issues": False, "control_outcome": "success"}},
        {
            "summary": {
                "runtime_sweep": {
                    **_base_summary(),
                    "calibration_coverage": {
                        "status": "no_nvm_activity",
                        "reason": "Calibration produced no NVM writes or erases.",
                    },
                }
            }
        },
        1,
    )
    assert passed is False
    assert reason == "Calibration produced no NVM writes or erases."
