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
from audit_bootloader import (  # noqa: E402
    _allow_expected_control_only_issues,
    _can_fallback_to_control_only_calibration,
)
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


def _control_only_summary_with_issue(outcome: str) -> dict:
    summary = _control_only_summary(outcome)
    summary["control"]["issue_count"] = 1
    return summary


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


def test_compute_verdict_allows_control_only_no_boot_when_enabled():
    verdict = compute_verdict(
        _control_only_summary("no_boot"),
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="no_boot",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected no_boot"


def test_compute_verdict_allows_expected_control_issue_count_when_enabled():
    verdict = compute_verdict(
        _control_only_summary_with_issue("wrong_image"),
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="wrong_image",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected wrong_image"


def test_compute_verdict_allows_control_only_issue_with_success_baseline_when_enabled():
    verdict = compute_verdict(
        _control_only_summary_with_issue("success"),
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="success",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected success"


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


def test_self_test_check_verdict_accepts_control_issue_with_success_baseline():
    passed, reason = check_verdict(
        Path("profiles/pr2206_broken_like.yaml"),
        {
            "expect": {
                "should_find_issues": True,
                "control_outcome": "success",
                "allow_control_only_issues": True,
            }
        },
        {"summary": {"runtime_sweep": _control_only_summary_with_issue("success")}},
        0,
    )
    assert passed is True
    assert reason == "Control exhibits expected success, as intended"


def test_pr2199_move_broken_profile_opted_into_control_only_issues():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    assert profile.expect.allow_control_only_issues is True
    assert profile.expect.control_outcome == "wrong_image"


def test_calibration_fallback_allows_control_only_no_boot_profiles():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    profile.expect.control_outcome = "no_boot"
    exc = RuntimeError(
        "Calibration did not complete cleanly (reason='budget', writes=0, erases=0). "
        "Refusing to run a partial sweep."
    )
    assert _can_fallback_to_control_only_calibration(profile, exc) is True


def test_calibration_fallback_rejects_success_profiles():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    profile.expect.control_outcome = "success"
    exc = RuntimeError(
        "Calibration did not complete cleanly (reason='budget', writes=0, erases=0). "
        "Refusing to run a partial sweep."
    )
    assert _can_fallback_to_control_only_calibration(profile, exc) is False


def test_allow_expected_control_only_issues_requires_non_success_control():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    profile.expect.control_outcome = "wrong_image"
    assert _allow_expected_control_only_issues(profile) is True


def test_allow_expected_control_only_issues_accepts_success_baseline_when_opted_in():
    profile = load_profile(ROOT / "tests" / "fixtures" / "profiles" / "control_only_issue_profile.yaml")
    profile.expect.control_outcome = "success"
    assert _allow_expected_control_only_issues(profile) is True
