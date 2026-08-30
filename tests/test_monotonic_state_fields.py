#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic monotonic persistent-state invariant."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult  # noqa: E402
from invariants import (  # noqa: E402
    InvariantViolation,
    check_monotonic_state_fields,
    resolve_invariants,
    run_invariants,
)


def _result(nvm_state, *, is_control=False):
    return FaultResult(
        fault_at=17,
        boot_outcome="success",
        boot_slot="exec",
        raw_log="",
        nvm_state=nvm_state,
        is_control=is_control,
    )


CONFIG = {
    "monotonic_state_fields": {
        "direction": "nondecreasing",
        "paths": [
            "policy.policy_epoch",
            "policy.credential_epoch",
        ],
    }
}


class MonotonicStateFieldsTest(unittest.TestCase):
    def test_is_registered(self):
        self.assertEqual(
            resolve_invariants(["monotonic_state_fields"]),
            [check_monotonic_state_fields],
        )

    def test_nested_fields_must_not_decrease(self):
        result = _result(
            {"policy": {"policy_epoch": 7, "credential_epoch": 4}}
        )
        check_monotonic_state_fields(
            result,
            pre_state={"policy": {"policy_epoch": 7, "credential_epoch": 3}},
            invariant_config=CONFIG,
        )

        result.nvm_state["policy"]["policy_epoch"] = 6
        with self.assertRaises(InvariantViolation) as ctx:
            check_monotonic_state_fields(
                result,
                pre_state={"policy": {"policy_epoch": 7, "credential_epoch": 3}},
                invariant_config=CONFIG,
            )
        self.assertEqual(ctx.exception.invariant_name, "monotonic_state_fields")
        regression = ctx.exception.details["regressions"][0]
        self.assertEqual(regression["path"], "policy.policy_epoch")
        self.assertEqual(regression["pre_value"], 7)
        self.assertEqual(regression["post_value"], 6)

    def test_nonincreasing_direction_and_simple_path_list(self):
        result = _result({"counter": {"remaining": 8}, "other": 2})
        check_monotonic_state_fields(
            result,
            pre_state={"counter": {"remaining": 9}, "other": 2},
            invariant_config={
                "monotonic_state_fields": {
                    "direction": "nonincreasing",
                    "paths": ["counter.remaining", "other"],
                }
            },
        )

    def test_compact_path_to_direction_mapping(self):
        check_monotonic_state_fields(
            _result({"epoch": 5}),
            pre_state={"epoch": 5},
            invariant_config={
                "monotonic_state_fields": {"epoch": "nondecreasing"}
            },
        )

    def test_numeric_text_is_compared_as_a_number(self):
        with self.assertRaises(InvariantViolation):
            check_monotonic_state_fields(
                _result({"epoch": "0x09"}),
                pre_state={"epoch": "0x0a"},
                invariant_config={"monotonic_state_fields": ["epoch"]},
            )

    def test_control_run_is_skipped(self):
        check_monotonic_state_fields(
            _result({}, is_control=True),
            pre_state=None,
            invariant_config={"monotonic_state_fields": "malformed"},
        )

    def test_missing_path_and_non_numeric_value_fail_closed(self):
        result = _result({"policy": {"policy_epoch": "zero"}})
        with self.assertRaisesRegex(ValueError, "missing component"):
            check_monotonic_state_fields(
                result,
                pre_state={"policy": {"policy_epoch": 1}},
                invariant_config={"monotonic_state_fields": ["policy.missing"]},
            )

        violations = run_invariants(
            result,
            invariants=[check_monotonic_state_fields],
            pre_state={"policy": {"policy_epoch": 1}},
            invariant_config={
                "monotonic_state_fields": ["policy.policy_epoch"]
            },
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].invariant_name, "invariant_evaluation_error")

    def test_malformed_config_fails_closed(self):
        violations = run_invariants(
            _result({"counter": 1}),
            invariants=[check_monotonic_state_fields],
            pre_state={"counter": 1},
            invariant_config={"monotonic_state_fields": {"direction": "up"}},
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("requires a paths list", violations[0].description)


if __name__ == "__main__":
    unittest.main()
