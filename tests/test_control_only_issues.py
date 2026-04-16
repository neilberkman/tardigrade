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
        Path("tests/fixtures/profiles/control_only_issue_profile.yaml"),
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


def test_self_test_check_verdict_requires_declared_issue_reason():
    passed, reason = check_verdict(
        Path("profiles/mcuboot_pr2206_scratch_geom_broken.yaml"),
        {
            "expect": {
                "should_find_issues": True,
                "control_outcome": "success",
                "allow_semantic_only_issues": True,
                "required_issue_reasons": ["boot_outcome"],
            }
        },
        {
            "summary": {
                "runtime_sweep": {
                    "issue_points": 1,
                    "issue_reasons": {"semantic_assertion": 1},
                    "control": {
                        "effective_outcome": "success",
                    },
                    "calibration_coverage": {"status": "full"},
                }
            }
        },
        0,
    )
    assert passed is False
    assert reason == "Missing expected issue reason(s): boot_outcome"


def test_self_test_check_verdict_ignores_opted_out_fault_types():
    passed, reason = check_verdict(
        Path("profiles/mcuboot_head_move_nrf52_revert_phase2fault_selftest.yaml"),
        {
            "expect": {
                "should_find_issues": False,
                "ignored_issue_fault_types": ["power_loss"],
            }
        },
        {
            "summary": {
                "runtime_sweep": {
                    "issue_points": 7,
                    "fault_type_issue_points": {
                        "power_loss": 7,
                    },
                    "calibration_coverage": {"status": "full"},
                    "control": {
                        "effective_outcome": "success",
                    },
                }
            }
        },
        0,
    )
    assert passed is True
    assert reason == "No issues found, as expected"


def test_self_test_check_verdict_keeps_non_ignored_fault_type_failures():
    passed, reason = check_verdict(
        Path("profiles/mcuboot_head_move_nrf52_revert_phase2fault_selftest.yaml"),
        {
            "expect": {
                "should_find_issues": False,
                "ignored_issue_fault_types": ["power_loss"],
            }
        },
        {
            "summary": {
                "runtime_sweep": {
                    "issue_points": 8,
                    "fault_type_issue_points": {
                        "power_loss": 7,
                        "phase2": 1,
                    },
                    "calibration_coverage": {"status": "full"},
                    "control": {
                        "effective_outcome": "success",
                    },
                }
            }
        },
        0,
    )
    assert passed is False
    assert reason == "Expected no issues but found 1 point(s)"


def test_pr2199_move_profiles_use_post_boot_state_probe_oracle():
    broken = load_profile(ROOT / "profiles" / "mcuboot_pr2199_move_broken.yaml")
    fixed = load_profile(ROOT / "profiles" / "mcuboot_pr2199_move_fixed.yaml")

    assert broken.expect.control_outcome == "success"
    assert broken.expect.allow_semantic_only_issues is False
    assert broken.expect.allow_control_only_issues is True
    assert broken.fault_sweep.boot_cycles == 3
    assert broken.state_probe is not None
    assert broken.state_probe.script == "targets/mcuboot/probe.py"
    assert broken.semantic_assertions["control"]["semantic_state.slots.exec.magic_state"] == "good"
    assert broken.semantic_assertions["control"]["semantic_state.slots.exec.copy_done.state"] == "set"
    assert broken.semantic_assertions["control"]["semantic_state.slots.exec.image_ok.state"] == "unset"
    assert broken.semantic_assertions["control"]["multi_boot_analysis.final_outcome"] == "success"

    assert fixed.expect.control_outcome == "success"
    assert fixed.expect.allow_semantic_only_issues is False
    assert fixed.fault_sweep.boot_cycles == 3
    assert fixed.state_probe is not None
    assert fixed.state_probe.script == "targets/mcuboot/probe.py"
    assert fixed.semantic_assertions["control"]["semantic_state.slots.exec.magic_state"] == "unset"
    assert fixed.semantic_assertions["control"]["semantic_state.slots.exec.copy_done.state"] == "unset"
    assert fixed.semantic_assertions["control"]["semantic_state.slots.exec.image_ok.state"] == "unset"
    assert fixed.semantic_assertions["control"]["multi_boot_analysis.final_outcome"] == "success"


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
