#!/usr/bin/env python3
"""Tests for control-only broken differential expectations."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from audit_report import compute_verdict  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from self_test import check_verdict  # noqa: E402


def _control_only_summary(outcome: str) -> dict:
    return {
        "bricks": 0,
        "issue_points": 0,
        "semantic_issue_points": 0,
        "invariant_issue_points": 0,
        "metadata_delta_issue_points": 0,
        "timeout_points": 0,
        "resilient_rollbacks": 0,
        "control": {
            "boot_outcome": outcome,
            "effective_outcome": outcome,
            "final_boot_outcome": outcome,
            "issue_count": 0,
        },
    }


def test_compute_verdict_allows_control_only_issue_when_enabled():
    verdict = compute_verdict(
        _control_only_summary("wrong_image"),
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="wrong_image",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected wrong_image"


def test_compute_verdict_still_fails_without_control_only_opt_in():
    verdict = compute_verdict(
        _control_only_summary("wrong_image"),
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="wrong_image",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "FAIL — expected to find issues but found none"


def test_self_test_check_verdict_accepts_control_only_issue_when_enabled():
    passed, reason = check_verdict(
        Path("profiles/mcuboot_pr2199_move_broken.yaml"),
        {
            "expect": {
                "should_find_issues": True,
                "control_outcome": "wrong_image",
                "allow_control_only_issues": True,
            }
        },
        {"summary": {"runtime_sweep": _control_only_summary("wrong_image")}},
        0,
    )
    assert passed is True
    assert reason == "Control exhibits expected wrong_image, as intended"


def test_pr2199_move_broken_profile_opted_into_control_only_issues():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    assert profile.expect.allow_control_only_issues is True
    assert profile.expect.control_outcome == "wrong_image"
