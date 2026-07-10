#!/usr/bin/env python3
"""Unit tests for instruction-skip severity classification."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import compute_verdict, summarize_runtime_sweep
from fault_classification import (
    classify_failure_class,
    classify_instruction_skip_severity,
    is_instruction_skip_nonsecurity_wrong_image,
    result_has_issues,
    result_is_brick,
    selected_unexpected_boot_slot,
)
from finding_validator import _validate_instruction_skip
from profile_loader import ProfileError, _parse_instruction_skip_config


def _profile_stub(severity_model: str = "security"):
    slot = lambda base, size: SimpleNamespace(base=base, size=size)
    return SimpleNamespace(
        memory=SimpleNamespace(
            slots={
                "exec": slot(0x00000000, 0x40000),
                "staging": slot(0x00040000, 0x40000),
            },
            page_size=4096,
        ),
        expect=SimpleNamespace(control_outcome="success", should_find_issues=False),
        fault_sweep=SimpleNamespace(
            instruction_skip_config=SimpleNamespace(severity_model=severity_model)
        ),
    )


class ParseSeverityModelTests(unittest.TestCase):
    def test_instruction_skip_config_defaults_to_security_model(self) -> None:
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"start": "0x1000", "end": "0x1100"}]}
        )
        self.assertEqual(cfg.severity_model, "security")

    def test_instruction_skip_config_accepts_availability_model(self) -> None:
        cfg = _parse_instruction_skip_config(
            {
                "target_addresses": [{"start": "0x1000", "end": "0x1100"}],
                "severity_model": "availability",
            }
        )
        self.assertEqual(cfg.severity_model, "availability")

    def test_instruction_skip_config_rejects_unknown_severity_model(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {
                    "target_addresses": [{"start": "0x1000", "end": "0x1100"}],
                    "severity_model": "bogus",
                }
            )

    def test_example_profiles_set_security_model(self) -> None:
        profiles = {
            "nxboot_style_instruction_skip_severity.yaml": True,
            "resilient_instruction_skip_severity.yaml": False,
        }
        for relpath, should_find_issues in profiles.items():
            with self.subTest(profile=relpath):
                raw = yaml.safe_load(
                    (ROOT / "profiles" / relpath).read_text(encoding="utf-8")
                )
                cfg = ((raw.get("fault_sweep") or {}).get("instruction_skip_config") or {})
                self.assertEqual(cfg.get("severity_model"), "security")
                expect = raw.get("expect") or {}
                self.assertEqual(
                    bool(expect.get("should_find_issues", False)), should_find_issues
                )


class SeverityClassificationTests(unittest.TestCase):
    def test_default_security_model_treats_no_boot_as_dos_only(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "no_boot",
            "fault_injected": True,
        }
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "dos_crash")
        self.assertFalse(result_has_issues(result, "success"))
        self.assertFalse(result_is_brick(result))
        self.assertEqual(classify_failure_class(result), "safe_dos")

    def test_availability_model_keeps_no_boot_as_issue(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "no_boot",
            "fault_injected": True,
            "instruction_skip_severity_model": "availability",
        }
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "dos_crash")
        self.assertTrue(result_has_issues(result, "success"))
        self.assertFalse(result_is_brick(result))
        self.assertEqual(classify_failure_class(result), "safe_dos")

    def test_wrong_image_is_security_bypass(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
        }
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "security_bypass")
        self.assertTrue(result_has_issues(result, "success"))

    def test_unexpected_slot_with_bus_fault_is_security_bypass(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "bus_fault",
            "boot_slot": "staging",
            "fault_injected": True,
            "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
            "signals": {"vtor_ok": False, "expectations_met": False},
        }
        self.assertTrue(selected_unexpected_boot_slot(result))
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "security_bypass")
        self.assertTrue(result_has_issues(result, "success"))
        self.assertFalse(result_is_brick(result))
        self.assertEqual(classify_failure_class(result), "wrong_image")

    def test_unexpected_slot_with_timeout_is_security_bypass(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "success",
            "boot_slot": "staging",
            "timeout": True,
            "fault_injected": True,
            "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
            "signals": {"vtor_ok": False, "expectations_met": False},
        }
        self.assertTrue(selected_unexpected_boot_slot(result))
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "security_bypass")
        self.assertTrue(result_has_issues(result, "success"))
        self.assertEqual(classify_failure_class(result), "wrong_image")

    def test_correct_slot_with_bus_fault_stays_dos_only(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "bus_fault",
            "boot_slot": "exec",
            "fault_injected": True,
            "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
            "signals": {"vtor_ok": True},
        }
        self.assertFalse(selected_unexpected_boot_slot(result))
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "dos_crash")
        self.assertFalse(result_has_issues(result, "success"))
        self.assertEqual(classify_failure_class(result), "safe_dos")

    def test_known_good_exec_hash_is_not_security_bypass(self) -> None:
        result = {
            "fault_type": "i:0x0056:nop",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "exec",
            "signals": {
                "execution_observed": True,
                "marker_ok": False,
                "image_hash_match": "exec_image",
                "image_hash_slot": "exec",
                "otadata_expect_ok": True,
                "pc_ok": True,
                "reset_vector_offset_ok": True,
                "vtor_ok": True,
            },
        }
        self.assertTrue(is_instruction_skip_nonsecurity_wrong_image(result))
        self.assertIsNone(
            classify_instruction_skip_severity(result, expected_outcome="success")
        )
        self.assertFalse(result_has_issues(result, "success"))

    def test_vtor_handoff_skip_is_not_security_bypass_in_security_model(self) -> None:
        result = {
            "fault_type": "i:0x00ce:nop",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "signals": {
                "execution_observed": True,
                "marker_ok": True,
                "otadata_expect_ok": True,
                "pc_ok": True,
                "reset_vector_offset_ok": True,
                "vtor_ok": False,
            },
        }
        self.assertTrue(is_instruction_skip_nonsecurity_wrong_image(result))
        self.assertIsNone(
            classify_instruction_skip_severity(result, expected_outcome="success")
        )
        self.assertFalse(result_has_issues(result, "success"))

    def test_nonsecurity_wrong_image_still_counts_in_availability_model(self) -> None:
        result = {
            "fault_type": "i:0x00ce:nop",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "instruction_skip_severity_model": "availability",
            "signals": {
                "execution_observed": True,
                "marker_ok": True,
                "otadata_expect_ok": True,
                "pc_ok": True,
                "reset_vector_offset_ok": True,
                "vtor_ok": False,
            },
        }
        self.assertTrue(is_instruction_skip_nonsecurity_wrong_image(result))
        self.assertTrue(result_has_issues(result, "success"))

    def test_anti_rollback_failure_is_not_suppressed(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "fault_injected": True,
            "boot_outcome": "wrong_image",
            "boot_slot": "exec",
            "signals": {
                "anti_rollback_ok": False,
                "execution_observed": True,
                "image_hash_match": "exec_image",
                "marker_ok": False,
                "otadata_expect_ok": True,
                "pc_ok": True,
                "reset_vector_offset_ok": True,
                "vtor_ok": True,
            },
        }
        self.assertFalse(is_instruction_skip_nonsecurity_wrong_image(result))
        severity = classify_instruction_skip_severity(result, expected_outcome="success")
        self.assertEqual(severity["severity"], "security_bypass")
        self.assertTrue(result_has_issues(result, "success"))


class SeveritySummaryTests(unittest.TestCase):
    def test_crash_only_instruction_skip_passes_with_advisory(self) -> None:
        profile = _profile_stub("security")
        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "i:0x1234:nop",
                "fault_address": "0x00001234",
                "boot_outcome": "no_boot",
                "boot_slot": None,
            },
        ]
        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertEqual(summary["issue_points"], 0)
        self.assertEqual(summary["security_bypass_points"], 0)
        self.assertEqual(summary["dos_crash_points"], 1)
        verdict = compute_verdict(summary, profile.expect)
        self.assertEqual(
            verdict,
            "PASS — 0 security bypass points (1 DoS crash points, expected for glitch model)",
        )

    def test_security_bypass_still_fails(self) -> None:
        profile = _profile_stub("security")
        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "i:0x1234:nop",
                "fault_address": "0x00001234",
                "boot_outcome": "wrong_image",
                "boot_slot": "staging",
            }
        ]
        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertEqual(summary["issue_points"], 1)
        self.assertEqual(summary["security_bypass_points"], 1)
        self.assertEqual(summary["failures"][0]["severity"], "security_bypass")
        verdict = compute_verdict(summary, profile.expect)
        self.assertEqual(verdict, "FAIL — found 1 security bypass points")

    def test_unexpected_slot_bus_fault_counts_as_security_bypass(self) -> None:
        profile = _profile_stub("security")
        results = [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "i:0x1234:nop",
                "fault_address": "0x00001234",
                "boot_outcome": "bus_fault",
                "boot_slot": "staging",
                "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
                "signals": {"vtor_ok": False, "expectations_met": False},
            }
        ]
        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertEqual(summary["issue_points"], 1)
        self.assertEqual(summary["security_bypass_points"], 1)
        self.assertEqual(summary["dos_crash_points"], 0)
        self.assertEqual(summary["failures"][0]["severity"], "security_bypass")

    def test_availability_mode_counts_dos_as_issue(self) -> None:
        profile = _profile_stub("availability")
        results = [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "i:0x1234:nop",
                "fault_address": "0x00001234",
                "boot_outcome": "no_boot",
                "boot_slot": None,
            }
        ]
        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertEqual(summary["issue_points"], 1)
        self.assertEqual(summary["dos_crash_points"], 1)


class SeverityValidatorTests(unittest.TestCase):
    def test_security_model_skips_rerun_for_dos_crash(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "fault_injected": True,
        }
        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=lambda *_args, **_kwargs: self.fail("rerun should not be needed"),
            annotate_checks=lambda _items: None,
        )
        self.assertEqual(validation["stage"], "dismissed")
        self.assertEqual(validation["disposition"], "dos_only")
        self.assertEqual(validation["severity"], "dos_crash")

    def test_availability_model_skips_rerun_but_keeps_issue(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "fault_injected": True,
            "instruction_skip_severity_model": "availability",
        }
        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=lambda *_args, **_kwargs: self.fail("rerun should not be needed"),
            annotate_checks=lambda _items: None,
        )
        self.assertEqual(validation["stage"], "validated")
        self.assertEqual(validation["disposition"], "confirmed")
        self.assertEqual(validation["severity"], "dos_crash")

    def test_wrong_slot_bus_fault_requires_replay_and_can_validate(self) -> None:
        result = {
            "fault_type": "i:0x1234:nop",
            "boot_outcome": "bus_fault",
            "boot_slot": "staging",
            "fault_injected": True,
            "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
            "signals": {"vtor_ok": False, "expectations_met": False},
        }

        def rerun_point(_fault_at, fault_type, _extra_robot_vars=None):
            return {
                "fault_type": fault_type,
                "boot_outcome": "bus_fault",
                "boot_slot": "staging",
                "fault_injected": True,
                "effective_success_criteria": {"vtor_slot": "exec", "image_hash_slot": ""},
                "signals": {"vtor_ok": False, "expectations_met": False},
            }

        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=rerun_point,
            annotate_checks=lambda _items: None,
        )
        self.assertEqual(validation["stage"], "validated")
        self.assertEqual(validation["disposition"], "confirmed")
        self.assertEqual(validation["severity"], "security_bypass")


if __name__ == "__main__":
    unittest.main()
