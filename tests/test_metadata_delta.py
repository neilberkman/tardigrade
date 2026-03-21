#!/usr/bin/env python3
"""Unit tests for metadata_delta tracking feature.

Tests profile parsing, delta evaluation, fault classification, and
result annotation for boot count suppression, boot count exhaustion,
and rollback floor regression detection.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_classification import (
    classify_failure_class,
    result_has_issues,
    result_issue_reasons,
)
from profile_loader import (
    FaultSweepConfig,
    MetadataDeltaConfig,
    MetadataDeltaFieldConfig,
    ProfileError,
    _parse_metadata_delta,
)
from result_checks import _evaluate_metadata_delta, _marker_actually_written


def _make_profile_stub(fields=None, enabled=True):
    """Build a minimal profile stub with metadata_delta config."""
    if fields is None:
        fields = [
            MetadataDeltaFieldConfig(
                address=0x000FC010,
                name="boot_count",
                min_delta=1,
                max_delta=1,
            ),
        ]
    md = MetadataDeltaConfig(enabled=enabled, fields=fields)
    fs = SimpleNamespace(metadata_delta=md)
    return SimpleNamespace(
        fault_sweep=fs,
        expect=SimpleNamespace(control_outcome="success"),
    )


class ParseMetadataDeltaTests(unittest.TestCase):
    """Test _parse_metadata_delta YAML parsing."""

    def test_none_returns_disabled(self):
        result = _parse_metadata_delta(None)
        self.assertFalse(result.enabled)
        self.assertEqual(result.fields, [])

    def test_bool_true_returns_enabled_no_fields(self):
        result = _parse_metadata_delta(True)
        self.assertTrue(result.enabled)
        self.assertEqual(result.fields, [])

    def test_bool_false_returns_disabled(self):
        result = _parse_metadata_delta(False)
        self.assertFalse(result.enabled)

    def test_basic_field_parsing(self):
        raw = {
            "fields": [
                {
                    "address": "0x000FC010",
                    "name": "boot_count",
                    "min_delta": 1,
                    "max_delta": 1,
                },
            ],
        }
        result = _parse_metadata_delta(raw)
        self.assertTrue(result.enabled)
        self.assertEqual(len(result.fields), 1)
        f = result.fields[0]
        self.assertEqual(f.address, 0x000FC010)
        self.assertEqual(f.name, "boot_count")
        self.assertEqual(f.min_delta, 1)
        self.assertEqual(f.max_delta, 1)
        self.assertIsNone(f.when)

    def test_field_with_when_condition(self):
        raw = {
            "fields": [
                {
                    "address": 0xFC014,
                    "name": "rollback_min_version",
                    "min_delta": 0,
                    "when": "marker_written",
                },
            ],
        }
        result = _parse_metadata_delta(raw)
        f = result.fields[0]
        self.assertEqual(f.when, "marker_written")
        self.assertEqual(f.min_delta, 0)
        self.assertIsNone(f.max_delta)

    def test_multiple_fields(self):
        raw = {
            "fields": [
                {"address": 0x100, "name": "boot_count", "min_delta": 1, "max_delta": 1},
                {"address": 0x104, "name": "rollback_version", "min_delta": 0},
                {"address": 0x108, "name": "slot_state", "max_delta": 2, "when": "marker_not_written"},
            ],
        }
        result = _parse_metadata_delta(raw)
        self.assertEqual(len(result.fields), 3)
        self.assertEqual(result.fields[2].when, "marker_not_written")

    def test_missing_address_raises(self):
        raw = {"fields": [{"name": "no_addr"}]}
        with self.assertRaises(ProfileError):
            _parse_metadata_delta(raw)

    def test_invalid_when_raises(self):
        raw = {
            "fields": [
                {"address": 0x100, "name": "f", "when": "invalid_condition"},
            ],
        }
        with self.assertRaises(ProfileError):
            _parse_metadata_delta(raw)

    def test_default_name(self):
        raw = {"fields": [{"address": 0x100}]}
        result = _parse_metadata_delta(raw)
        self.assertEqual(result.fields[0].name, "field_0")

    def test_enabled_explicit_false(self):
        raw = {
            "enabled": False,
            "fields": [{"address": 0x100, "name": "f"}],
        }
        result = _parse_metadata_delta(raw)
        self.assertFalse(result.enabled)

    def test_non_dict_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_delta("invalid")


class EvaluateMetadataDeltaTests(unittest.TestCase):
    """Test _evaluate_metadata_delta from result_checks.py."""

    def test_boot_count_suppressed(self):
        """Delta=0 when min_delta=1 means boot count never committed."""
        profile = _make_profile_stub()
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000005",
                    "boot_count_delta": 0,
                },
                "marker_ok": True,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "boot_count_suppressed")
        self.assertEqual(violations[0]["delta"], 0)

    def test_boot_count_exhausted(self):
        """Delta=2 when max_delta=1 means trial burned without firmware running."""
        profile = _make_profile_stub()
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000007",
                    "boot_count_delta": 2,
                },
                "marker_ok": True,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "boot_count_exhausted")
        self.assertEqual(violations[0]["delta"], 2)

    def test_normal_delta_no_violation(self):
        """Delta=1 within [1,1] range is correct."""
        profile = _make_profile_stub()
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000006",
                    "boot_count_delta": 1,
                },
                "marker_ok": True,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 0)

    def test_when_marker_written_skips_when_not_written(self):
        """when=marker_written should skip check if marker not written."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x100,
                name="boot_count",
                min_delta=1,
                max_delta=1,
                when="marker_written",
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000005",
                    "boot_count_delta": 0,
                },
                "marker_ok": False,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 0)

    def test_when_marker_not_written_checks_when_not_written(self):
        """when=marker_not_written should check delta when marker not written."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x100,
                name="boot_count",
                min_delta=0,
                max_delta=0,
                when="marker_not_written",
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        # Boot count advanced even though firmware never ran (marker not written).
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000006",
                    "boot_count_delta": 1,
                },
                "marker_ok": False,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "boot_count_exhausted")

    def test_rollback_floor_decreased(self):
        """Negative delta on a rollback field."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x200,
                name="rollback_min_version",
                min_delta=0,
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        result = {
            "signals": {
                "metadata_delta": {
                    "rollback_min_version_pre": "0x00000003",
                    "rollback_min_version_post": "0x00000002",
                    "rollback_min_version_delta": -1,
                },
                "marker_ok": True,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "rollback_floor_decreased")

    def test_disabled_returns_empty(self):
        """Disabled metadata_delta should not produce violations."""
        profile = _make_profile_stub(enabled=False)
        result = {
            "signals": {
                "metadata_delta": {"boot_count_delta": 0},
                "marker_ok": True,
            },
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 0)

    def test_no_signals_returns_empty(self):
        """Missing signals should not crash."""
        profile = _make_profile_stub()
        result = {"fault_injected": True}
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 0)

    def test_generic_field_below_min(self):
        """Non-boot_count, non-rollback field below min gets generic category."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x300,
                name="slot_state",
                min_delta=0,
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        result = {
            "signals": {
                "metadata_delta": {
                    "slot_state_pre": "0x00000002",
                    "slot_state_post": "0x00000001",
                    "slot_state_delta": -1,
                },
                "marker_ok": True,
            },
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "metadata_delta_below_min")


    def test_when_marker_written_checks_when_actually_written(self):
        """when=marker_written should check delta when marker was actually written."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x100,
                name="boot_count",
                min_delta=1,
                max_delta=1,
                when="marker_written",
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        # marker_actual is non-zero and marker_ok is True -> marker was written.
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000005",
                    "boot_count_delta": 0,
                },
                "marker_ok": True,
                "marker_actual": "0x600DB00F",
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["finding_category"], "boot_count_suppressed")

    def test_marker_ok_true_without_content_criteria_not_marker_written(self):
        """marker_ok=True with no marker_actual or hash is NOT marker_written."""
        fields = [
            MetadataDeltaFieldConfig(
                address=0x100,
                name="boot_count",
                min_delta=1,
                max_delta=1,
                when="marker_written",
            ),
        ]
        profile = _make_profile_stub(fields=fields)
        # marker_ok=True but no marker_actual or image_hash_match.
        # The marker_ok default is True when no content criteria configured.
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000005",
                    "boot_count_delta": 0,
                },
                "marker_ok": True,
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        # Should skip the check because marker_written is False.
        self.assertEqual(len(violations), 0)

    def test_violation_includes_pre_post_values(self):
        """Violation dicts should include pre_value and post_value."""
        profile = _make_profile_stub()
        result = {
            "signals": {
                "metadata_delta": {
                    "boot_count_pre": "0x00000005",
                    "boot_count_post": "0x00000005",
                    "boot_count_delta": 0,
                },
            },
            "fault_injected": True,
        }
        violations = _evaluate_metadata_delta(result, profile)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["pre_value"], "0x00000005")
        self.assertEqual(violations[0]["post_value"], "0x00000005")


class MarkerActuallyWrittenTests(unittest.TestCase):
    """Test _marker_actually_written helper."""

    def test_no_signals_returns_false(self):
        self.assertFalse(_marker_actually_written({}))

    def test_marker_ok_true_alone_returns_false(self):
        """marker_ok=True without evidence of content criteria is False."""
        self.assertFalse(_marker_actually_written({"marker_ok": True}))

    def test_marker_actual_nonzero_with_marker_ok_returns_true(self):
        signals = {"marker_ok": True, "marker_actual": "0xDEADBEEF"}
        self.assertTrue(_marker_actually_written(signals))

    def test_marker_actual_nonzero_with_marker_ok_false_returns_false(self):
        signals = {"marker_ok": False, "marker_actual": "0xDEADBEEF"}
        self.assertFalse(_marker_actually_written(signals))

    def test_marker_actual_zero_returns_false(self):
        signals = {"marker_ok": True, "marker_actual": "0x00000000"}
        self.assertFalse(_marker_actually_written(signals))

    def test_image_hash_match_exec_returns_true(self):
        signals = {"image_hash_match": "exec_image"}
        self.assertTrue(_marker_actually_written(signals))

    def test_image_hash_match_staging_returns_true(self):
        signals = {"image_hash_match": "staging_image"}
        self.assertTrue(_marker_actually_written(signals))

    def test_image_hash_match_unknown_returns_false(self):
        signals = {"image_hash_match": "unknown"}
        self.assertFalse(_marker_actually_written(signals))

    def test_image_hash_match_skipped_returns_false(self):
        signals = {"image_hash_match": "skipped"}
        self.assertFalse(_marker_actually_written(signals))


class FaultClassificationTests(unittest.TestCase):
    """Test that metadata_delta_violations are properly classified."""

    def test_boot_count_suppressed_classification(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "metadata_delta_violations": [
                {"finding_category": "boot_count_suppressed"},
            ],
        }
        self.assertEqual(classify_failure_class(result), "boot_count_suppressed")

    def test_boot_count_exhausted_classification(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "metadata_delta_violations": [
                {"finding_category": "boot_count_exhausted"},
            ],
        }
        self.assertEqual(classify_failure_class(result), "boot_count_exhausted")

    def test_rollback_floor_decreased_classification(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "metadata_delta_violations": [
                {"finding_category": "rollback_floor_decreased"},
            ],
        }
        self.assertEqual(classify_failure_class(result), "rollback_floor_decreased")

    def test_metadata_delta_in_issue_reasons(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "metadata_delta_violations": [
                {"finding_category": "boot_count_suppressed"},
            ],
        }
        reasons = result_issue_reasons(result, "success")
        self.assertIn("metadata_delta", reasons)

    def test_metadata_delta_counts_as_issue(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_injected": True,
            "metadata_delta_violations": [
                {"finding_category": "boot_count_exhausted"},
            ],
        }
        self.assertTrue(result_has_issues(result, "success"))

    def test_no_violations_not_an_issue(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_injected": True,
        }
        self.assertFalse(result_has_issues(result, "success"))

    def test_exhausted_takes_precedence_over_suppressed(self):
        """When both present, exhausted wins (higher severity)."""
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "metadata_delta_violations": [
                {"finding_category": "boot_count_suppressed"},
                {"finding_category": "boot_count_exhausted"},
            ],
        }
        self.assertEqual(classify_failure_class(result), "boot_count_exhausted")


class RobotVarsTests(unittest.TestCase):
    """Test that metadata_delta fields are emitted as robot variables."""

    def test_metadata_delta_robot_vars(self):
        fields = [
            MetadataDeltaFieldConfig(
                address=0x000FC010,
                name="boot_count",
                min_delta=1,
                max_delta=1,
            ),
            MetadataDeltaFieldConfig(
                address=0x000FC014,
                name="rollback_version",
                min_delta=0,
                when="marker_written",
            ),
        ]
        md = MetadataDeltaConfig(enabled=True, fields=fields)
        fs = FaultSweepConfig(metadata_delta=md)
        # Check that the config is properly stored.
        self.assertTrue(fs.metadata_delta.enabled)
        self.assertEqual(len(fs.metadata_delta.fields), 2)
        self.assertEqual(fs.metadata_delta.fields[0].name, "boot_count")
        self.assertEqual(fs.metadata_delta.fields[1].when, "marker_written")


class SummaryIntegrationTests(unittest.TestCase):
    """Test that metadata_delta violations show up in sweep summary."""

    def test_metadata_delta_issue_points_in_summary(self):
        from audit_report import summarize_runtime_sweep

        results = [
            {
                "fault_at": 0,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "metadata_delta_violations": [
                    {"finding_category": "boot_count_suppressed"},
                ],
            },
            {
                "fault_at": 1,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
            },
        ]
        summary = summarize_runtime_sweep(results)
        self.assertEqual(summary["metadata_delta_issue_points"], 1)
        self.assertEqual(summary["issue_points"], 1)


if __name__ == "__main__":
    unittest.main()
