#!/usr/bin/env python3
"""Tests for cross-transaction persistent-state isolation checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult
from invariants import (
    InvariantViolation,
    check_transaction_state_isolation,
    resolve_invariants,
    run_invariants,
)
from profile_loader import ProfileError, _parse_invariant_config


def _result(phase_states, *, control=False):
    state = phase_states[-1]["semantic_state"] if phase_states else {}
    return FaultResult(
        fault_at=7,
        boot_outcome="success",
        boot_slot="exec",
        nvm_state=state,
        raw_log="",
        is_control=control,
    )


def _config():
    return {
        "transaction_state_isolation": {
            "paths": ["security.header"],
            "reset_phases": ["cancel"],
        }
    }


class TransactionStateIsolationTest(unittest.TestCase):
    def test_is_registered(self):
        self.assertEqual(
            resolve_invariants(["transaction_state_isolation"]),
            [check_transaction_state_isolation],
        )

    def test_omitted_metadata_after_cancel_passes(self):
        phases = [
            {"phase_name": "transaction_a", "semantic_state": {"security": {"header": "A"}}},
            {"phase_name": "cancel", "semantic_state": {"security": {}}},
            {"phase_name": "transaction_b", "semantic_state": {"security": {}}},
        ]
        result = _result(phases)
        check_transaction_state_isolation(
            result, invariant_config=_config(), result_dict={"update_sequence": {"phase_records": phases}}
        )

    def test_changed_metadata_after_cancel_passes(self):
        phases = [
            {"phase_name": "transaction_a", "semantic_state": {"security": {"header": "A"}}},
            {"phase_name": "cancel", "semantic_state": {"security": {"header": "A"}}},
            {"phase_name": "transaction_b", "semantic_state": {"security": {"header": "B"}}},
        ]
        # A non-empty reset value is intentionally rejected even when B has a
        # changed header: reset must clear old transaction state first.
        with self.assertRaises(InvariantViolation):
            check_transaction_state_isolation(
                _result(phases), invariant_config=_config(),
                result_dict={"update_sequence": {"phase_records": phases}},
            )

    def test_reused_metadata_is_reported(self):
        phases = [
            {"phase_name": "transaction_a", "semantic_state": {"security": {"header": "A"}}},
            {"phase_name": "cancel", "semantic_state": {"security": {}}},
            {"phase_name": "transaction_b", "semantic_state": {"security": {"header": "A"}}},
        ]
        with self.assertRaises(InvariantViolation) as context:
            check_transaction_state_isolation(
                _result(phases), invariant_config=_config(),
                result_dict={"update_sequence": {"phase_records": phases}},
            )
        self.assertEqual(context.exception.details["finding_code"], "TRANSACTION_STATE_LEAK")
        self.assertTrue(context.exception.details["violations"][0]["reused"])

    def test_malformed_telemetry_fails_closed(self):
        violations = run_invariants(
            _result([{"phase_name": "transaction_b", "semantic_state": {}}]),
            [check_transaction_state_isolation],
            invariant_config=_config(),
            result_dict={},
        )
        self.assertEqual(violations[0].invariant_name, "invariant_evaluation_error")

    def test_control_is_skipped(self):
        check_transaction_state_isolation(
            _result([], control=True), invariant_config=_config(), result_dict={}
        )

    def test_profile_config_validation(self):
        _parse_invariant_config(_config())
        with self.assertRaises(ProfileError):
            _parse_invariant_config({"transaction_state_isolation": {"paths": ["x"]}})
        with self.assertRaises(ProfileError):
            _parse_invariant_config({
                "transaction_state_isolation": {
                    "paths": ["x"], "reset_phases": ["cancel"], "extra": True,
                }
            })


if __name__ == "__main__":
    unittest.main()
