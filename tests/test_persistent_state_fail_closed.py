#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic persistent-state fail-closed invariant."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult  # noqa: E402
from invariants import (  # noqa: E402
    InvariantViolation,
    check_persistent_state_fail_closed,
    resolve_invariants,
    run_invariants,
)
from profile_loader import ProfileError, _parse_invariant_config  # noqa: E402


CONFIG = {"persistent_state_fail_closed": {}}


def _result(*, boot_outcome="no_boot"):
    return FaultResult(
        fault_at=9,
        boot_outcome=boot_outcome,
        boot_slot=None,
        raw_log="",
        nvm_state={},
    )


def _signals(*, read_ok=False, write_count=0, outcome="aborted"):
    return {
        "persistent_state_operations": [
            {
                "operation": "security_metadata",
                "read_ok": read_ok,
                "write_count": write_count,
                "outcome": outcome,
            }
        ]
    }


class PersistentStateFailClosedTest(unittest.TestCase):
    def test_is_registered(self):
        self.assertEqual(
            resolve_invariants(["persistent_state_fail_closed"]),
            [check_persistent_state_fail_closed],
        )

    def test_failed_read_with_write_is_reported(self):
        with self.assertRaises(InvariantViolation) as ctx:
            check_persistent_state_fail_closed(
                _result(), CONFIG, _signals(write_count=1)
            )
        self.assertEqual(ctx.exception.invariant_name, "persistent_state_fail_closed")
        self.assertEqual(
            ctx.exception.details["finding_code"], "PERSISTENT_STATE_FAIL_CLOSED"
        )

    def test_failed_read_with_accepted_outcome_is_reported(self):
        with self.assertRaises(InvariantViolation):
            check_persistent_state_fail_closed(
                _result(boot_outcome="success"),
                CONFIG,
                _signals(outcome="committed"),
            )

    def test_failed_read_cannot_hide_successful_boot_behind_aborted_outcome(self):
        with self.assertRaises(InvariantViolation):
            check_persistent_state_fail_closed(
                _result(boot_outcome="success"),
                CONFIG,
                _signals(outcome="aborted"),
            )

    def test_state_probe_semantic_state_telemetry_is_supported(self):
        nested = {
            "semantic_state": {
                "persistent_state_operations": _signals()[
                    "persistent_state_operations"
                ]
            }
        }
        check_persistent_state_fail_closed(_result(), CONFIG, nested)

    def test_fixed_and_successful_read_pass(self):
        check_persistent_state_fail_closed(_result(), CONFIG, _signals())
        check_persistent_state_fail_closed(
            _result(boot_outcome="success"),
            CONFIG,
            _signals(read_ok=True, write_count=1, outcome="committed"),
        )

    def test_missing_or_malformed_evidence_fails_closed_as_evaluation_error(self):
        for signals in ({}, {"persistent_state_operations": []}, {
            "persistent_state_operations": [{"operation": "security_metadata"}]
        }):
            violations = run_invariants(
                _result(),
                [check_persistent_state_fail_closed],
                invariant_config=CONFIG,
                result_signals=signals,
            )
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].invariant_name, "invariant_evaluation_error")

    def test_invalid_outcome_fails_closed(self):
        violations = run_invariants(
            _result(),
            [check_persistent_state_fail_closed],
            invariant_config=CONFIG,
            result_signals=_signals(outcome="mystery"),
        )
        self.assertEqual(violations[0].invariant_name, "invariant_evaluation_error")

    def test_malformed_context_is_a_value_error(self):
        with self.assertRaises(ValueError):
            check_persistent_state_fail_closed(_result(), [], _signals())
        with self.assertRaises(ValueError):
            check_persistent_state_fail_closed(_result(), CONFIG, [])
        with self.assertRaises(ValueError):
            check_persistent_state_fail_closed(
                _result(), {"persistent_state_fail_closed": None}, _signals()
            )

    def test_profile_config_must_be_empty_mapping(self):
        self.assertEqual(
            _parse_invariant_config({"persistent_state_fail_closed": {}})[
                "persistent_state_fail_closed"
            ],
            {},
        )
        with self.assertRaises(ProfileError):
            _parse_invariant_config(
                {"persistent_state_fail_closed": {"outcomes": ["ok"]}}
            )

    def test_checked_in_example_traces_are_a_differential(self):
        vulnerable = json.loads(
            (ROOT / "examples/persistent_state_fail_closed/vulnerable_trace.json")
            .read_text(encoding="utf-8")
        )
        fixed = json.loads(
            (ROOT / "examples/persistent_state_fail_closed/fixed_trace.json")
            .read_text(encoding="utf-8")
        )
        with self.assertRaises(InvariantViolation):
            check_persistent_state_fail_closed(
                _result(boot_outcome=vulnerable["boot_outcome"]),
                CONFIG,
                {"semantic_state": vulnerable["semantic_state"]},
            )
        check_persistent_state_fail_closed(
            _result(boot_outcome=fixed["boot_outcome"]),
            CONFIG,
            {"semantic_state": fixed["semantic_state"]},
        )


if __name__ == "__main__":
    unittest.main()
