#!/usr/bin/env python3
"""Unit tests for the verification bypass probe classification module."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from bypass_probe import (
    CLASSIFICATION_ALL_LAYERS_BREACHED,
    CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_HELD,
    CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_NOT_REACHED,
    CLASSIFICATION_FIRST_LAYER_BREACHED_SECOND_CAUGHT,
    CLASSIFICATION_FIRST_LAYER_HELD,
    CLASSIFICATION_FIRST_LAYER_NOT_REACHED,
    CLASSIFICATION_NO_PROBES,
    CLASSIFICATION_NOT_REACHED,
    CLASSIFICATION_PARTIAL_MULTILAYER_BYPASS,
    CLASSIFICATION_SINGLE_LAYER_BREACHED,
    DEFENSE_DEFEATED,
    DEFENSE_HELD,
    DEFENSE_NOT_APPLICABLE,
    DEFENSE_PARTIAL,
    DEFENSE_UNKNOWN,
    LAYER_BREACHED,
    LAYER_HELD,
    LAYER_NOT_REACHED,
    build_defense_in_depth_layers,
    classify_layer_status,
    classify_probe_result,
)


class ClassifyLayerStatusTests(unittest.TestCase):
    def test_held_when_reached_and_not_bypassed(self) -> None:
        probe = {"reached": True, "first_bypassed": False, "bypassed": False}
        self.assertEqual(classify_layer_status(probe), LAYER_HELD)

    def test_breached_when_first_bypassed(self) -> None:
        probe = {"reached": True, "first_bypassed": True, "bypassed": True}
        self.assertEqual(classify_layer_status(probe), LAYER_BREACHED)

    def test_breached_when_bypassed_any(self) -> None:
        probe = {"reached": True, "first_bypassed": False, "bypassed": True}
        self.assertEqual(classify_layer_status(probe), LAYER_BREACHED)

    def test_not_reached(self) -> None:
        probe = {"reached": False}
        self.assertEqual(classify_layer_status(probe), LAYER_NOT_REACHED)

    def test_empty_probe(self) -> None:
        self.assertEqual(classify_layer_status({}), LAYER_NOT_REACHED)


class ClassifyProbeResultTests(unittest.TestCase):
    def test_no_signals_returns_no_probes(self) -> None:
        result = {"boot_outcome": "success"}
        classification = classify_probe_result(result)
        self.assertEqual(classification["classification"], CLASSIFICATION_NO_PROBES)
        self.assertEqual(classification["defense_in_depth"], DEFENSE_NOT_APPLICABLE)
        self.assertFalse(classification["full_bypass"])

    def test_empty_probes_returns_no_probes(self) -> None:
        result = {"signals": {"verification_probes": {}}}
        classification = classify_probe_result(result)
        self.assertEqual(classification["classification"], CLASSIFICATION_NO_PROBES)

    def test_single_layer_breached(self) -> None:
        result = {
            "signals": {
                "verification_probe_classification": "single_layer_breached",
                "verification_defense_in_depth": "defeated",
                "verification_probes": {
                    "image_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "validate_image",
                        "first_return_value": "0x00000000",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_SINGLE_LAYER_BREACHED,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_DEFEATED)
        self.assertTrue(classification["full_bypass"])
        self.assertEqual(classification["bypassed_labels"], ["image_validation"])
        self.assertEqual(len(classification["layers"]), 1)
        self.assertEqual(classification["layers"][0]["status"], LAYER_BREACHED)

    def test_all_layers_breached(self) -> None:
        result = {
            "signals": {
                "verification_probe_classification": "all_layers_breached",
                "verification_defense_in_depth": "defeated",
                "verification_probes": {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "bootutil_img_validate",
                        "first_return_value": "0x00000000",
                        "call_count": 1,
                    },
                    "slot_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "boot_validate_slot",
                        "first_return_value": "0x00000000",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_ALL_LAYERS_BREACHED,
        )
        self.assertTrue(classification["full_bypass"])
        self.assertEqual(
            classification["bypassed_labels"],
            ["hash_validation", "slot_validation"],
        )

    def test_first_layer_breached_second_caught(self) -> None:
        result = {
            "signals": {
                "verification_probe_classification": "first_layer_breached_second_caught",
                "verification_defense_in_depth": "held",
                "verification_probes": {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "bootutil_img_validate",
                        "first_return_value": "0x00000000",
                        "call_count": 1,
                    },
                    "slot_validation": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "boot_validate_slot",
                        "first_return_value": "0xFFFFFFFF",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_BREACHED_SECOND_CAUGHT,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_HELD)
        self.assertFalse(classification["full_bypass"])
        self.assertEqual(classification["bypassed_labels"], ["hash_validation"])
        self.assertEqual(classification["layers"][0]["status"], LAYER_BREACHED)
        self.assertEqual(classification["layers"][1]["status"], LAYER_HELD)

    def test_first_layer_held(self) -> None:
        result = {
            "signals": {
                "verification_probe_classification": "first_layer_held",
                "verification_defense_in_depth": "held",
                "verification_probes": {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "bootutil_img_validate",
                        "first_return_value": "0x00000001",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_HELD,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_HELD)
        self.assertFalse(classification["full_bypass"])

    def test_offline_fallback_all_breached(self) -> None:
        """When RESC classification is absent, offline logic runs."""
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_b",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_ALL_LAYERS_BREACHED,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_DEFEATED)

    def test_offline_fallback_first_held(self) -> None:
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_HELD,
        )

    def test_offline_fallback_not_reached(self) -> None:
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": False,
                        "symbol": "func_a",
                        "call_count": 0,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_NOT_REACHED,
        )

    def test_offline_fallback_single_layer_breached(self) -> None:
        result = {
            "signals": {
                "verification_probes": {
                    "only_layer": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_only",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_SINGLE_LAYER_BREACHED,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_DEFEATED)
        self.assertTrue(classification["full_bypass"])

    def test_offline_fallback_first_layer_not_reached(self) -> None:
        """First layer not reached but second layer reached and held."""
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": False,
                        "symbol": "func_a",
                        "call_count": 0,
                    },
                    "layer_b": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_b",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_NOT_REACHED,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_UNKNOWN)
        self.assertFalse(classification["full_bypass"])

    def test_offline_fallback_first_layer_breached_following_held(self) -> None:
        """Offline fallback mirrors the RESC ordering for held later layers."""
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_b",
                        "call_count": 1,
                    },
                    "layer_c": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_c",
                        "call_count": 1,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_BREACHED_SECOND_CAUGHT,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_HELD)
        self.assertFalse(classification["full_bypass"])
        self.assertEqual(classification["bypassed_labels"], ["layer_a"])

    def test_offline_fallback_breached_plus_not_reached_no_held(self) -> None:
        """Breached + not_reached with no held layers mirrors RESC classification."""
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": False,
                        "symbol": "func_b",
                        "call_count": 0,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        self.assertEqual(
            classification["classification"],
            CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_NOT_REACHED,
        )
        self.assertEqual(classification["defense_in_depth"], DEFENSE_UNKNOWN)
        self.assertFalse(classification["full_bypass"])
        self.assertEqual(classification["bypassed_labels"], ["layer_a"])

    def test_layer_return_value_captured(self) -> None:
        result = {
            "signals": {
                "verification_probes": {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "first_return_value": "0xDEADBEEF",
                        "call_count": 3,
                    },
                },
            },
        }
        classification = classify_probe_result(result)
        layer = classification["layers"][0]
        self.assertEqual(layer["return_value"], "0xDEADBEEF")
        self.assertEqual(layer["call_count"], 3)


class BuildDefenseInDepthLayersTests(unittest.TestCase):
    def _make_result(
        self,
        fault_at,
        probe_data,
        *,
        probe_classification=None,
        probe_defense=None,
    ):
        signals = {"verification_probes": probe_data}
        if probe_classification:
            signals["verification_probe_classification"] = probe_classification
        if probe_defense:
            signals["verification_defense_in_depth"] = probe_defense
        return {
            "is_control": False,
            "fault_injected": True,
            "fault_at": fault_at,
            "fault_type": "i:0x{:X}".format(fault_at),
            "boot_outcome": "no_boot",
            "signals": signals,
        }

    def test_empty_results_returns_none(self) -> None:
        self.assertIsNone(build_defense_in_depth_layers([]))

    def test_no_probes_returns_none(self) -> None:
        results = [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "boot_outcome": "success",
            }
        ]
        self.assertIsNone(build_defense_in_depth_layers(results))

    def test_control_results_excluded(self) -> None:
        results = [
            {
                "is_control": True,
                "fault_injected": False,
                "signals": {
                    "verification_probes": {
                        "layer_a": {"reached": True, "first_bypassed": True},
                    },
                },
            }
        ]
        self.assertIsNone(build_defense_in_depth_layers(results))

    def test_single_result_all_breached(self) -> None:
        results = [
            self._make_result(
                0x1000,
                {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "validate_image",
                        "call_count": 1,
                    },
                },
                probe_classification="single_layer_breached",
                probe_defense="defeated",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertIsNotNone(layers)
        self.assertEqual(layers["total_probed_points"], 1)
        self.assertEqual(layers["full_bypass_count"], 1)
        self.assertEqual(layers["aggregate_classification"], DEFENSE_DEFEATED)
        self.assertEqual(len(layers["layers"]), 1)
        self.assertEqual(layers["layers"][0]["label"], "hash_validation")
        self.assertEqual(layers["layers"][0]["breached"], 1)
        self.assertEqual(layers["layers"][0]["held"], 0)
        self.assertAlmostEqual(layers["layers"][0]["breach_rate"], 1.0)

    def test_multi_result_defense_held(self) -> None:
        """Multiple results where inner layer breached but outer held."""
        results = [
            self._make_result(
                0x1000,
                {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "bootutil_img_validate",
                        "call_count": 1,
                    },
                    "slot_validation": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "boot_validate_slot",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_breached_second_caught",
                probe_defense="held",
            ),
            self._make_result(
                0x1002,
                {
                    "hash_validation": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "bootutil_img_validate",
                        "call_count": 1,
                    },
                    "slot_validation": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "boot_validate_slot",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_held",
                probe_defense="held",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertIsNotNone(layers)
        self.assertEqual(layers["total_probed_points"], 2)
        self.assertEqual(layers["full_bypass_count"], 0)
        self.assertEqual(layers["aggregate_classification"], DEFENSE_HELD)

        # hash_validation: 1 breached + 1 held
        hash_layer = layers["layers"][0]
        self.assertEqual(hash_layer["label"], "hash_validation")
        self.assertEqual(hash_layer["breached"], 1)
        self.assertEqual(hash_layer["held"], 1)
        self.assertAlmostEqual(hash_layer["breach_rate"], 0.5)

        # slot_validation: 0 breached + 2 held
        slot_layer = layers["layers"][1]
        self.assertEqual(slot_layer["label"], "slot_validation")
        self.assertEqual(slot_layer["breached"], 0)
        self.assertEqual(slot_layer["held"], 2)
        self.assertAlmostEqual(slot_layer["breach_rate"], 0.0)

    def test_mixed_bypass_and_defense(self) -> None:
        """Mix of full bypass and defense-held points gives partial verdict."""
        results = [
            self._make_result(
                0x1000,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
                probe_classification="single_layer_breached",
                probe_defense="defeated",
            ),
            self._make_result(
                0x1002,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_held",
                probe_defense="held",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertIsNotNone(layers)
        self.assertEqual(layers["full_bypass_count"], 1)
        # Not all points are full bypass, so aggregate is partial
        self.assertEqual(layers["aggregate_classification"], "partial")
        self.assertAlmostEqual(layers["full_bypass_rate"], 0.5)

    def test_aggregate_unknown_when_breached_plus_not_reached(self) -> None:
        """Breached + not_reached (no held) should give unknown aggregate."""
        results = [
            self._make_result(
                0x1000,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": False,
                        "symbol": "func_b",
                        "call_count": 0,
                    },
                },
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertIsNotNone(layers)
        # layer_a breached, layer_b not reached -- defense is unknown,
        # not held, because the unreached layer can't confirm it would catch.
        self.assertEqual(layers["aggregate_classification"], DEFENSE_UNKNOWN)
        self.assertEqual(layers["full_bypass_count"], 0)

    def test_unknown_point_does_not_promote_aggregate_to_held(self) -> None:
        results = [
            self._make_result(
                0x1000,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": False,
                        "symbol": "func_b",
                        "call_count": 0,
                    },
                },
            ),
            self._make_result(
                0x1002,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                    "layer_b": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_b",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_held",
                probe_defense="held",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertIsNotNone(layers)
        self.assertEqual(layers["aggregate_classification"], DEFENSE_UNKNOWN)

    def test_classification_counts(self) -> None:
        results = [
            self._make_result(
                0x1000,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
                probe_classification="single_layer_breached",
                probe_defense="defeated",
            ),
            self._make_result(
                0x1002,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_held",
                probe_defense="held",
            ),
            self._make_result(
                0x1004,
                {
                    "layer_a": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "func_a",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_held",
                probe_defense="held",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertEqual(
            layers["points_by_classification"]["first_layer_held"], 2
        )
        self.assertEqual(
            layers["points_by_classification"]["single_layer_breached"], 1
        )

    def test_layer_order_preserved(self) -> None:
        """Layer order in summary matches insertion order from first result."""
        results = [
            self._make_result(
                0x1000,
                {
                    "inner_check": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "inner_func",
                        "call_count": 1,
                    },
                    "outer_check": {
                        "reached": True,
                        "first_bypassed": False,
                        "bypassed": False,
                        "symbol": "outer_func",
                        "call_count": 1,
                    },
                },
                probe_classification="first_layer_breached_second_caught",
                probe_defense="held",
            ),
        ]
        layers = build_defense_in_depth_layers(results)
        self.assertEqual(layers["layers"][0]["label"], "inner_check")
        self.assertEqual(layers["layers"][1]["label"], "outer_check")


class ReportIntegrationTests(unittest.TestCase):
    """Verify defense_in_depth_layers integrates into summarize_runtime_sweep."""

    def _profile_stub(self):
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

    def test_summary_includes_defense_in_depth_layers(self) -> None:
        from audit_report import summarize_runtime_sweep

        profile = self._profile_stub()
        results = [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "i:0x1000",
                "boot_outcome": "no_boot",
                "signals": {
                    "verification_probe_classification": "first_layer_breached_second_caught",
                    "verification_defense_in_depth": "held",
                    "verification_bypass_detected": True,
                    "verification_full_bypass": False,
                    "verification_probes": {
                        "hash_validation": {
                            "reached": True,
                            "first_bypassed": True,
                            "bypassed": True,
                            "symbol": "bootutil_img_validate",
                            "call_count": 1,
                        },
                        "slot_validation": {
                            "reached": True,
                            "first_bypassed": False,
                            "bypassed": False,
                            "symbol": "boot_validate_slot",
                            "call_count": 1,
                        },
                    },
                },
                "finding_stage": "dismissed",
                "finding_validation": {
                    "stage": "dismissed",
                    "disposition": "defense_in_depth",
                },
            },
        ]

        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertIn("defense_in_depth_layers", summary)
        did = summary["defense_in_depth_layers"]
        self.assertEqual(did["total_probed_points"], 1)
        self.assertEqual(did["full_bypass_count"], 0)
        self.assertEqual(did["aggregate_classification"], DEFENSE_HELD)
        self.assertEqual(len(did["layers"]), 2)
        self.assertEqual(did["layers"][0]["label"], "hash_validation")
        self.assertEqual(did["layers"][0]["breached"], 1)
        self.assertEqual(did["layers"][1]["label"], "slot_validation")
        self.assertEqual(did["layers"][1]["held"], 1)

    def test_summary_omits_defense_in_depth_layers_without_probes(self) -> None:
        from audit_report import summarize_runtime_sweep

        profile = self._profile_stub()
        results = [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_at": 1,
                "fault_type": "w",
                "boot_outcome": "success",
            },
        ]

        summary = summarize_runtime_sweep(results, total_writes=10, profile=profile)
        self.assertNotIn("defense_in_depth_layers", summary)

    def test_categorize_failure_includes_per_result_layers(self) -> None:
        from audit_report import categorize_failure

        profile = self._profile_stub()
        result = {
            "is_control": False,
            "fault_injected": True,
            "fault_at": 42,
            "fault_type": "i:0x1234",
            "fault_address": "0x00001234",
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "signals": {
                "verification_probe_classification": "single_layer_breached",
                "verification_defense_in_depth": "defeated",
                "verification_full_bypass": True,
                "verification_probes": {
                    "image_validation": {
                        "reached": True,
                        "first_bypassed": True,
                        "bypassed": True,
                        "symbol": "validate_image",
                        "first_return_value": "0x00000000",
                        "call_count": 1,
                    },
                },
            },
        }

        payload = categorize_failure(result, 100, profile)
        self.assertIn("defense_in_depth_layers", payload)
        did = payload["defense_in_depth_layers"]
        self.assertEqual(did["classification"], "single_layer_breached")
        self.assertTrue(did["full_bypass"])
        self.assertEqual(did["layers"][0]["label"], "image_validation")
        self.assertEqual(did["layers"][0]["status"], LAYER_BREACHED)


if __name__ == "__main__":
    unittest.main()
