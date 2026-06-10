#!/usr/bin/env python3
"""compute_verdict must surface the read-fault coverage warning on every
return path, including the security-bypass FAIL early returns (which return
before the function tail)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import compute_verdict  # noqa: E402

RF_WARNING = "read_bit_flip planned 4 fault(s) but none armed"


def _summary_with_security_bypass_and_rf_warning() -> dict:
    return {
        "bricks": 0,
        "issue_points": 2,
        "security_bypass_points": 2,
        "semantic_issue_points": 0,
        "invariant_issue_points": 0,
        "metadata_delta_issue_points": 0,
        "dos_crash_points": 0,
        "dos_recovery_points": 0,
        "timeout_points": 0,
        "resilient_rollbacks": 0,
        "control": {
            "boot_outcome": "success",
            "effective_outcome": "success",
            "final_boot_outcome": "success",
            "issue_count": 0,
        },
        "read_fault": {"requested": True, "warning": RF_WARNING},
    }


def test_security_bypass_fail_still_surfaces_read_fault_warning():
    verdict = compute_verdict(
        _summary_with_security_bypass_and_rf_warning(),
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    # The verdict is a security-bypass FAIL (early return) but must still
    # carry the read-fault coverage warning.
    assert verdict.startswith("FAIL")
    assert "security bypass" in verdict
    assert RF_WARNING in verdict


def test_pass_verdict_surfaces_read_fault_warning_at_tail():
    summary = _summary_with_security_bypass_and_rf_warning()
    summary["issue_points"] = 0
    summary["security_bypass_points"] = 0
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict.startswith("PASS")
    assert RF_WARNING in verdict
