#!/usr/bin/env python3
"""Tests for declarative cross-component state relations."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult
from invariants import (
    InvariantViolation,
    check_state_relations,
    resolve_invariants,
    run_invariants,
)
from profile_loader import ProfileError, _parse_invariant_config
from render_results_html import render_multi_component_panel
from sweep import _evaluate_component_state_relations


def _result(state, *, control=False):
    return FaultResult(
        fault_at=4,
        boot_outcome="success",
        boot_slot="exec",
        nvm_state=state,
        raw_log="",
        is_control=control,
    )


class StateRelationsTest(unittest.TestCase):
    def test_is_registered(self):
        self.assertEqual(resolve_invariants(["state_relations"]), [check_state_relations])

    def test_equal_and_ordered_comparisons(self):
        config = {
            "state_relations": [
                {
                    "name": "same_epoch",
                    "compare": {
                        "left": {"source": "post", "path": "a.epoch"},
                        "op": "eq",
                        "right": {"source": "post", "path": "b.epoch"},
                    },
                },
                {
                    "name": "floor_not_lower",
                    "compare": {
                        "left": {"source": "post", "path": "a.version"},
                        "op": "ge",
                        "right": {"source": "pre", "path": "a.version"},
                    },
                },
            ]
        }
        check_state_relations(
            _result({"a": {"epoch": 3, "version": 4}, "b": {"epoch": 3}}),
            pre_state={"a": {"version": 2}},
            invariant_config=config,
        )
        with self.assertRaises(InvariantViolation):
            check_state_relations(
                _result({"a": {"epoch": 3, "version": 1}, "b": {"epoch": 4}}),
                pre_state={"a": {"version": 2}},
                invariant_config=config,
            )

    def test_pre_to_post_and_allowed_tuples(self):
        config = {
            "state_relations": [
                {
                    "name": "approved_pair",
                    "allowed_tuples": {
                        "fields": [
                            {"source": "post", "path": "components.controller.generation"},
                            {"source": "post", "path": "components.worker.generation"},
                        ],
                        "values": [[1, 4], [2, 5]],
                    },
                },
                {
                    "name": "advanced",
                    "compare": {
                        "left": {"source": "post", "path": "components.controller.generation"},
                        "op": "gt",
                        "right": {"source": "pre", "path": "components.controller.generation"},
                    },
                },
            ]
        }
        check_state_relations(
            _result({"components": {"controller": {"generation": 2}, "worker": {"generation": 5}}}),
            pre_state={"components": {"controller": {"generation": 1}}},
            invariant_config=config,
        )
        with self.assertRaises(InvariantViolation) as ctx:
            check_state_relations(
                _result({"components": {"controller": {"generation": 1}, "worker": {"generation": 5}}}),
                pre_state={"components": {"controller": {"generation": 0}}},
                invariant_config=config,
            )
        self.assertEqual(ctx.exception.details["component_identifiers"], ["controller", "worker"])
        self.assertEqual(ctx.exception.details["observed_tuple"], [1, 5])

    def test_strict_types_and_numeric_ordering(self):
        def compare(left, op, right):
            return {
                "state_relations": [{
                    "name": "type_test",
                    "compare": {
                        "left": {"value": left}, "op": op, "right": {"value": right}
                    },
                }]
            }

        check_state_relations(_result({}), invariant_config=compare("left", "eq", "left"))
        check_state_relations(_result({}), invariant_config=compare("0x0A", "lt", "0x0B"))
        with self.assertRaises(ValueError):
            check_state_relations(_result({}), invariant_config=compare(True, "eq", 1))
        with self.assertRaises(ValueError):
            check_state_relations(_result({}), invariant_config=compare("1", "eq", 1))
        with self.assertRaises(ValueError):
            check_state_relations(_result({}), invariant_config=compare(True, "lt", False))

    def test_when_skips_or_enables_relation(self):
        config = {
            "state_relations": [{
                "name": "only_after_activation",
                "when": {
                    "left": {"source": "post", "path": "update.activated"},
                    "op": "eq", "right": {"value": True},
                },
                "compare": {
                    "left": {"source": "post", "path": "a.version"},
                    "op": "eq", "right": {"source": "post", "path": "b.version"},
                },
            }]
        }
        check_state_relations(
            _result({"update": {"activated": False}, "a": {"version": 1}}),
            invariant_config=config,
        )
        with self.assertRaises(InvariantViolation):
            check_state_relations(
                _result({"update": {"activated": True}, "a": {"version": 1}, "b": {"version": 2}}),
                invariant_config=config,
            )

    def test_missing_and_malformed_fail_closed(self):
        config = {"state_relations": [{
            "name": "missing", "compare": {
                "left": {"source": "post", "path": "not.present"},
                "op": "eq", "right": {"value": 1},
            }
        }]}
        violations = run_invariants(
            _result({}), [check_state_relations], invariant_config=config
        )
        self.assertEqual(violations[0].invariant_name, "invariant_evaluation_error")
        with self.assertRaises(ProfileError):
            _parse_invariant_config({"state_relations": [{
                "name": "bad", "compare": {
                    "left": {"source": "post", "path": "a"},
                    "op": "eq", "right": {"value": 1},
                }, "when": {"left": {"value": True}}
            }]})
        with self.assertRaises(ProfileError):
            _parse_invariant_config({"state_relations": [{
                "name": "bad", "allowed_tuples": {
                    "fields": [{"source": "post", "path": "a"}, {"source": "post", "path": "b"}],
                    "values": [[1, 2], [1, "2"]],
                }
            }]})

    def test_multi_component_atomic_after_state_is_caught(self):
        profile = SimpleNamespace(
            invariants=["state_relations"],
            invariant_config={"state_relations": [{
                "name": "approved_pair", "allowed_tuples": {
                    "fields": [
                        {"source": "post", "path": "components.controller.generation"},
                        {"source": "post", "path": "components.worker.generation"},
                    ],
                    "values": [[1, 4], [2, 5]],
                }
            }]},
        )
        combined = {
            "fault_at": 9,
            "combined_outcome": "success",
            "per_component": {
                "controller": {"boot_outcome": "success", "semantic_state": {"generation": 1}},
                "worker": {"boot_outcome": "success", "semantic_state": {"generation": 5}},
            },
        }
        violations = _evaluate_component_state_relations(combined, profile)
        self.assertEqual(violations[0]["details"]["finding_code"], "STATE_RELATION_VIOLATION")

    def test_html_identifies_components_and_versions(self):
        html = render_multi_component_panel({
            "multi_component": True,
            "control_state": {
                "controller": {"boot_outcome": "success", "semantic_state": {"version": 1}},
                "worker": {"boot_outcome": "success", "semantic_state": {"version": 4}},
            },
            "combined_results": [],
        })
        self.assertIn("controller", html)
        self.assertIn("worker", html)
        self.assertIn(">1<", html)
        self.assertIn(">4<", html)


if __name__ == "__main__":
    unittest.main()
