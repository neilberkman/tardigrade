#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for declarative atomic persistent-state groups."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult  # noqa: E402
from invariants import (  # noqa: E402
    InvariantViolation,
    check_atomic_state_groups,
    resolve_invariants,
)


def _result(controller: str, worker: str) -> FaultResult:
    return FaultResult(
        fault_at=7,
        boot_outcome="success",
        boot_slot="exec",
        raw_log="",
        nvm_state={
            "components": {
                "controller": {"commit": {"state": controller}},
                "worker": {"commit": {"state": worker}},
            }
        },
    )


CONFIG = {
    "atomic_state_groups": [
        {
            "name": "joint_component_commit",
            "members": [
                {
                    "path": "components.controller.commit.state",
                    "before": "unset",
                    "after": "set",
                },
                {
                    "path": "components.worker.commit.state",
                    "before": "unset",
                    "after": "set",
                },
            ],
        }
    ]
}


class AtomicStateGroupsTest(unittest.TestCase):
    def test_is_registered(self) -> None:
        self.assertEqual(
            resolve_invariants(["atomic_state_groups"]),
            [check_atomic_state_groups],
        )

    def test_all_before_and_all_after_pass(self) -> None:
        check_atomic_state_groups(_result("unset", "unset"), invariant_config=CONFIG)
        check_atomic_state_groups(_result("set", "set"), invariant_config=CONFIG)

    def test_mixed_commit_is_reported(self) -> None:
        with self.assertRaises(InvariantViolation) as ctx:
            check_atomic_state_groups(
                _result("set", "unset"), invariant_config=CONFIG
            )

        self.assertEqual(ctx.exception.invariant_name, "atomic_state_groups")
        self.assertEqual(ctx.exception.details["group"], "joint_component_commit")
        self.assertEqual(ctx.exception.details["phases"], ["after", "before"])

    def test_member_specific_values_support_nonuniform_transitions(self) -> None:
        config = {
            "atomic_state_groups": [
                {
                    "name": "resource_activation",
                    "members": [
                        {
                            "path": "resources.alpha.generation",
                            "before": 1,
                            "after": 2,
                        },
                        {"path": "policy.epoch", "before": 0, "after": 5},
                    ],
                }
            ]
        }
        result = FaultResult(
            fault_at=11,
            boot_outcome="success",
            boot_slot="exec",
            raw_log="",
            nvm_state={
                "resources": {"alpha": {"generation": 2}},
                "policy": {"epoch": 0},
            },
        )

        with self.assertRaises(InvariantViolation):
            check_atomic_state_groups(result, invariant_config=config)

    def test_missing_observation_is_an_evaluation_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing component"):
            check_atomic_state_groups(
                _result("set", "set"),
                invariant_config={
                    "atomic_state_groups": [
                        {
                            "name": "bad_probe",
                            "members": [
                                {"path": "missing.value", "before": 0, "after": 1},
                                {
                                    "path": "components.worker.commit.state",
                                    "before": "unset",
                                    "after": "set",
                                },
                            ],
                        }
                    ]
                },
            )


if __name__ == "__main__":
    unittest.main()
