#!/usr/bin/env python3
"""Unit tests for boot_target_matches_metadata and last_known_good_preserved invariants."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import FaultResult  # noqa: E402
from invariants import (  # noqa: E402
    InvariantViolation,
    check_boot_target_matches_metadata,
    check_last_known_good_preserved,
    _ALL_INVARIANTS,
    _INVARIANT_REGISTRY,
)


def _make_result(**overrides):
    """Build a FaultResult with sensible defaults, overridden by kwargs."""
    defaults = dict(
        fault_at=42,
        boot_outcome="success",
        boot_slot="A",
        nvm_state={},
        raw_log="",
        is_control=False,
    )
    defaults.update(overrides)
    return FaultResult(**defaults)


# ---------------------------------------------------------------------------
# check_boot_target_matches_metadata
# ---------------------------------------------------------------------------


class TestBootTargetMatchesMetadata(unittest.TestCase):
    """Tests for the boot_target_matches_metadata invariant."""

    def test_pass_matching_slots(self):
        """Boot slot matches metadata active_slot -- should pass."""
        result = _make_result(boot_outcome="success", boot_slot="A")
        signals = {"semantic_state": {"active_slot": "A"}}
        # Should not raise.
        check_boot_target_matches_metadata(result, result_signals=signals)

    def test_fail_mismatched_slots(self):
        """Boot slot differs from metadata active_slot -- should raise."""
        result = _make_result(boot_outcome="success", boot_slot="B")
        signals = {"semantic_state": {"active_slot": "A"}}
        with self.assertRaises(InvariantViolation) as ctx:
            check_boot_target_matches_metadata(result, result_signals=signals)
        self.assertEqual(ctx.exception.invariant_name, "boot_target_matches_metadata")
        self.assertIn("B", ctx.exception.description)
        self.assertIn("A", ctx.exception.description)

    def test_skip_non_success_boot(self):
        """Non-successful boot -- should skip (no raise)."""
        result = _make_result(boot_outcome="no_boot", boot_slot=None)
        signals = {"semantic_state": {"active_slot": "A"}}
        check_boot_target_matches_metadata(result, result_signals=signals)

    def test_skip_no_signals(self):
        """No result_signals provided -- should skip."""
        result = _make_result(boot_outcome="success", boot_slot="A")
        check_boot_target_matches_metadata(result, result_signals=None)

    def test_skip_no_semantic_state(self):
        """result_signals has no semantic_state -- should skip."""
        result = _make_result(boot_outcome="success", boot_slot="A")
        check_boot_target_matches_metadata(result, result_signals={"other": 1})

    def test_skip_no_metadata_slot(self):
        """semantic_state present but no active_slot or target_slot -- should skip."""
        result = _make_result(boot_outcome="success", boot_slot="A")
        signals = {"semantic_state": {"some_other_field": 42}}
        check_boot_target_matches_metadata(result, result_signals=signals)

    def test_skip_no_boot_slot(self):
        """boot_slot is None on the result -- should skip."""
        result = _make_result(boot_outcome="success", boot_slot=None)
        signals = {"semantic_state": {"active_slot": "A"}}
        check_boot_target_matches_metadata(result, result_signals=signals)

    def test_target_slot_fallback(self):
        """Uses target_slot when active_slot is absent -- should detect mismatch."""
        result = _make_result(boot_outcome="success", boot_slot="A")
        signals = {"semantic_state": {"target_slot": "B"}}
        with self.assertRaises(InvariantViolation) as ctx:
            check_boot_target_matches_metadata(result, result_signals=signals)
        self.assertEqual(ctx.exception.invariant_name, "boot_target_matches_metadata")

    def test_int_vs_string_normalization(self):
        """Integer slot in metadata matches string boot_slot -- should pass."""
        result = _make_result(boot_outcome="success", boot_slot="0")
        signals = {"semantic_state": {"active_slot": 0}}
        check_boot_target_matches_metadata(result, result_signals=signals)


# ---------------------------------------------------------------------------
# check_last_known_good_preserved
# ---------------------------------------------------------------------------


class TestLastKnownGoodPreserved(unittest.TestCase):
    """Tests for the last_known_good_preserved invariant."""

    def test_pass_one_slot_valid(self):
        """At least one slot has a valid image -- should pass."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slot_a_image_ok": True,
            "slot_b_image_ok": False,
        }}
        check_last_known_good_preserved(result, result_signals=signals)

    def test_fail_all_slots_corrupted(self):
        """All slots have corrupted images -- should raise."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slot_a_image_ok": False,
            "slot_b_image_ok": False,
        }}
        with self.assertRaises(InvariantViolation) as ctx:
            check_last_known_good_preserved(result, result_signals=signals)
        self.assertEqual(ctx.exception.invariant_name, "last_known_good_preserved")
        self.assertIn("corrupted", ctx.exception.description)

    def test_skip_no_signals(self):
        """No result_signals -- should skip."""
        result = _make_result(fault_at=10)
        check_last_known_good_preserved(result, result_signals=None)

    def test_skip_no_semantic_state(self):
        """result_signals with no semantic_state -- should skip."""
        result = _make_result(fault_at=10)
        check_last_known_good_preserved(result, result_signals={"other": 1})

    def test_skip_no_slot_validity_info(self):
        """semantic_state present but no slot image fields -- should skip."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {"some_field": 42}}
        check_last_known_good_preserved(result, result_signals=signals)

    def test_pass_both_slots_valid(self):
        """Both slots valid -- should pass."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slot_a_image_ok": True,
            "slot_b_image_ok": True,
        }}
        check_last_known_good_preserved(result, result_signals=signals)

    def test_hash_match_fallback(self):
        """Falls back to hash_match keys when image_ok is absent."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slot_a_hash_match": False,
            "slot_b_hash_match": False,
        }}
        with self.assertRaises(InvariantViolation) as ctx:
            check_last_known_good_preserved(result, result_signals=signals)
        self.assertEqual(ctx.exception.invariant_name, "last_known_good_preserved")

    def test_nested_slots_dict(self):
        """Uses nested 'slots' dict when top-level keys are absent."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slots": {
                "primary": {"image_ok": False},
                "secondary": {"image_ok": True},
            }
        }}
        # One valid -- should pass.
        check_last_known_good_preserved(result, result_signals=signals)

    def test_nested_slots_all_bad(self):
        """Nested 'slots' dict with all bad images -- should raise."""
        result = _make_result(fault_at=10)
        signals = {"semantic_state": {
            "slots": {
                "primary": {"hash_match": False},
                "secondary": {"hash_match": False},
            }
        }}
        with self.assertRaises(InvariantViolation) as ctx:
            check_last_known_good_preserved(result, result_signals=signals)
        self.assertEqual(ctx.exception.invariant_name, "last_known_good_preserved")

    def test_works_on_non_success_boot(self):
        """Invariant applies regardless of boot outcome (catches total corruption)."""
        result = _make_result(fault_at=10, boot_outcome="no_boot")
        signals = {"semantic_state": {
            "slot_a_image_ok": False,
            "slot_b_image_ok": False,
        }}
        with self.assertRaises(InvariantViolation):
            check_last_known_good_preserved(result, result_signals=signals)


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestRegistration(unittest.TestCase):
    """Verify both invariants are properly registered."""

    def test_in_all_invariants(self):
        fn_names = [fn.__name__ for fn in _ALL_INVARIANTS]
        self.assertIn("check_boot_target_matches_metadata", fn_names)
        self.assertIn("check_last_known_good_preserved", fn_names)

    def test_in_registry(self):
        self.assertIn("boot_target_matches_metadata", _INVARIANT_REGISTRY)
        self.assertIn("last_known_good_preserved", _INVARIANT_REGISTRY)
        self.assertIs(
            _INVARIANT_REGISTRY["boot_target_matches_metadata"],
            check_boot_target_matches_metadata,
        )
        self.assertIs(
            _INVARIANT_REGISTRY["last_known_good_preserved"],
            check_last_known_good_preserved,
        )


if __name__ == "__main__":
    unittest.main()
