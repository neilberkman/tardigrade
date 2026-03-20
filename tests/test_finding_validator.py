#!/usr/bin/env python3
"""Unit tests for the adversarial finding validator."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import summarize_runtime_sweep
from fault_classification import classify_failure_class, result_has_issues, result_is_brick
from finding_validator import _apply_validation, _validate_instruction_skip, _validate_write_fault


def _profile_stub():
    slot = lambda base, size: SimpleNamespace(base=base, size=size)
    return SimpleNamespace(
        memory=SimpleNamespace(
            slots={
                "exec": slot(0x00000000, 0x40000),
                "staging": slot(0x00040000, 0x40000),
            },
            page_size=4096,
        ),
        expect=SimpleNamespace(control_outcome="success"),
    )


class InstructionSkipValidationTests(unittest.TestCase):
    def test_probe_shows_later_layer_catch_dismisses_without_rerun(self) -> None:
        result = {
            "fault_type": "i:0x1234",
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "fault_injected": True,
            "signals": {
                "verification_probe_classification": "first_layer_breached_second_caught",
                "verification_defense_in_depth": "held",
                "verification_bypass_detected": True,
                "verification_bypass_labels": ["hash_validation"],
                "verification_probes": {
                    "hash_validation": {
                        "reached": True,
                        "return_value": "0x00000000",
                        "bypassed": True,
                    },
                    "slot_validation": {
                        "reached": True,
                        "return_value": "0xFFFFFFFF",
                        "bypassed": False,
                    },
                },
            },
        }

        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=lambda *_args, **_kwargs: self.fail("rerun should not be needed"),
            annotate_checks=lambda _items: None,
        )

        self.assertEqual(validation["stage"], "dismissed")
        self.assertEqual(validation["disposition"], "defense_in_depth")
        self.assertEqual(validation["glitch_models"]["nop"], "bypass")
        self.assertEqual(validation["defense_in_depth"], "held")
        self.assertEqual(
            validation["counterfactuals"]["defense_chain"],
            "first_layer_breached_second_caught",
        )

    def test_nop_reproduction_promotes_to_validated(self) -> None:
        result = {
            "fault_type": "i:0x1234",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
        }

        def rerun_point(_fault_at, fault_type, _extra_robot_vars=None):
            if fault_type.endswith(":nop"):
                return {
                    "fault_type": fault_type,
                    "boot_outcome": "wrong_image",
                    "boot_slot": "staging",
                    "fault_injected": True,
                }
            return {
                "fault_type": fault_type,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": True,
            }

        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=rerun_point,
            annotate_checks=lambda _items: None,
        )

        self.assertEqual(validation["stage"], "validated")
        self.assertEqual(validation["disposition"], "confirmed")
        self.assertEqual(validation["glitch_models"]["nop"], "bypass")
        self.assertEqual(validation["glitch_realism"], "common")
        self.assertEqual(validation["defense_in_depth"], "defeated")

    def test_only_secondary_model_reproduction_stays_candidate(self) -> None:
        result = {
            "fault_type": "i:0x1234",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
        }

        def rerun_point(_fault_at, fault_type, _extra_robot_vars=None):
            if fault_type.endswith(":branch_invert"):
                return {
                    "fault_type": fault_type,
                    "boot_outcome": "wrong_image",
                    "boot_slot": "staging",
                    "fault_injected": True,
                }
            return {
                "fault_type": fault_type,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": True,
            }

        validation = _validate_instruction_skip(
            result,
            expected_outcome="success",
            rerun_point=rerun_point,
            annotate_checks=lambda _items: None,
        )

        self.assertEqual(validation["stage"], "candidate")
        self.assertEqual(validation["disposition"], "model_specific_candidate")
        self.assertEqual(validation["glitch_models"]["nop"], "no_bypass")
        self.assertEqual(validation["glitch_models"]["branch_invert"], "bypass")
        self.assertEqual(validation["glitch_realism"], "plausible")


class WriteFaultValidationTests(unittest.TestCase):
    def test_phase1_halt_marks_harness_artifact(self) -> None:
        result = {
            "fault_type": "s",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
            "signals": {
                "phase1_stop_reason": "fault_fired",
            },
        }

        validation = _validate_write_fault(result, expected_outcome="success")
        self.assertEqual(validation["stage"], "dismissed")
        self.assertEqual(validation["disposition"], "harness_artifact")
        self.assertEqual(validation["inverse_validation"], "harness_artifact")

    def test_post_boot_rewrite_marks_self_healed(self) -> None:
        result = {
            "fault_type": "x",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
            "signals": {
                "phase1_continued_after_fault": True,
                "fault_word_changed_post_boot": True,
            },
        }

        validation = _validate_write_fault(result, expected_outcome="success")
        self.assertEqual(validation["stage"], "dismissed")
        self.assertEqual(validation["disposition"], "self_healed")
        self.assertEqual(validation["self_healing"], "healed")


class ValidationClassificationTests(unittest.TestCase):
    def test_candidate_and_dismissed_findings_are_not_reportable(self) -> None:
        candidate = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "fault_injected": True,
        }
        _apply_validation(
            candidate,
            {
                "stage": "candidate",
                "disposition": "model_specific_candidate",
                "glitch_models": {},
                "glitch_realism": "plausible",
                "defense_in_depth": "partial",
                "inverse_validation": "not_applicable",
                "self_healing": "not_applicable",
            },
        )

        dismissed = {
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "fault_injected": True,
        }
        _apply_validation(
            dismissed,
            {
                "stage": "dismissed",
                "disposition": "defense_in_depth",
                "glitch_models": {},
                "glitch_realism": "common",
                "defense_in_depth": "held",
                "inverse_validation": "not_applicable",
                "self_healing": "not_applicable",
            },
        )

        self.assertFalse(result_has_issues(candidate, "success"))
        self.assertFalse(result_is_brick(candidate))
        self.assertEqual(classify_failure_class(candidate), "candidate")

        self.assertFalse(result_has_issues(dismissed, "success"))
        self.assertFalse(result_is_brick(dismissed))
        self.assertEqual(classify_failure_class(dismissed), "defense_in_depth")


class ValidationReportingTests(unittest.TestCase):
    def test_summary_includes_validation_stages_and_evidence(self) -> None:
        profile = _profile_stub()
        validated = {
            "is_control": False,
            "fault_injected": True,
            "fault_at": 1,
            "fault_type": "i:0x1234",
            "fault_address": "0x0003FFF0",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "finding_stage": "validated",
            "glitch_models": {"nop": "bypass"},
            "glitch_realism": "common",
            "finding_validation": {
                "stage": "validated",
                "disposition": "confirmed",
                "glitch_realism": "common",
                "counterfactuals": {"multi_boot_replay": "single_boot_only"},
                "negative_evidence": ["branch inversion did not reproduce"],
                "skeptical_summary": "Validated after adversarial replay.",
            },
        }
        candidate = {
            "is_control": False,
            "fault_injected": True,
            "fault_at": 2,
            "fault_type": "i:0x1236",
            "fault_address": "0x0003FFF4",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "finding_stage": "candidate",
            "glitch_models": {"nop": "no_bypass", "branch_invert": "bypass"},
            "glitch_realism": "plausible",
            "finding_validation": {
                "stage": "candidate",
                "disposition": "model_specific_candidate",
                "glitch_realism": "plausible",
            },
        }
        dismissed = {
            "is_control": False,
            "fault_injected": True,
            "fault_at": 3,
            "fault_type": "x",
            "fault_address": "0x0003FFF8",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "finding_stage": "dismissed",
            "glitch_models": {"register_zero": "observed"},
            "glitch_realism": "plausible",
            "finding_validation": {
                "stage": "dismissed",
                "disposition": "self_healed",
                "glitch_realism": "plausible",
            },
        }

        summary = summarize_runtime_sweep(
            [
                {
                    "is_control": True,
                    "boot_outcome": "success",
                    "boot_slot": "exec",
                    "fault_injected": False,
                },
                validated,
                candidate,
                dismissed,
            ],
            total_writes=10,
            profile=profile,
        )

        self.assertEqual(summary["issue_points"], 1)
        self.assertEqual(summary["finding_stages"]["validated"], 1)
        self.assertEqual(summary["finding_stages"]["candidate"], 1)
        self.assertEqual(summary["finding_stages"]["dismissed"], 1)
        self.assertEqual(summary["validated_findings"], 1)
        self.assertEqual(summary["candidate_findings"], 1)
        self.assertEqual(summary["dismissed_findings"], 1)
        failure = summary["failures"][0]
        self.assertEqual(failure["finding_stage"], "validated")
        self.assertIn("negative_evidence", failure)
        self.assertIn("counterfactuals", failure)
        self.assertEqual(failure["skeptical_summary"], "Validated after adversarial replay.")

    def test_summary_tracks_verification_probe_outcomes(self) -> None:
        profile = _profile_stub()
        result = {
            "is_control": False,
            "fault_injected": True,
            "fault_at": "i:0x5c6",
            "fault_type": "i:0x5c6",
            "fault_address": "0x000005C6",
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "finding_stage": "dismissed",
            "finding_validation": {
                "stage": "dismissed",
                "disposition": "defense_in_depth",
                "glitch_realism": "common",
            },
            "signals": {
                "verification_probe_classification": "first_layer_breached_second_caught",
                "verification_defense_in_depth": "held",
                "verification_bypass_detected": True,
                "verification_full_bypass": False,
                "verification_bypass_labels": ["hash_validation"],
                "verification_probes": {
                    "hash_validation": {"reached": True, "bypassed": True},
                    "slot_validation": {"reached": True, "bypassed": False},
                },
            },
        }

        summary = summarize_runtime_sweep([result], total_writes=10, profile=profile)
        self.assertEqual(
            summary["verification_probe_classes"]["first_layer_breached_second_caught"],
            1,
        )
        self.assertEqual(summary["verification_bypass_points"], ["i:0x5c6"])
        self.assertEqual(summary["defense_in_depth_held"], 1)


if __name__ == "__main__":
    unittest.main()
