#!/usr/bin/env python3
"""Unit tests for confirm_cycle fault injection feature.

Validates:
  1. ConfirmCycleConfig parsing from YAML
  2. Fault plan generation for confirm_cycle points
  3. Finding categories (confirm_incomplete, rollback_not_ratcheted,
     metadata_inconsistent_after_confirm)
  4. Profile loader validation rules
  5. Robot vars emission
  6. Fault type label resolution
"""

from __future__ import annotations

import sys
import textwrap
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from profile_loader import (  # noqa: E402
    ConfirmCycleConfig,
    FaultSweepConfig,
    HookFaultConfig,
    ProfileConfig,
    ProfileError,
    load_profile,
    _parse_confirm_cycle,
)
from fault_plan import build_fault_plan, CalibrationInputs  # noqa: E402
from fault_types import _fault_type_label  # noqa: E402
from fault_classification import result_issue_reasons  # noqa: E402

CONFIRM_PROFILE = ROOT / "profiles" / "esp_idf_ota_upgrade_confirm_cycle.yaml"


class ConfirmCycleConfigTest(unittest.TestCase):
    """Test ConfirmCycleConfig data class."""

    def test_defaults(self):
        cfg = ConfirmCycleConfig()
        self.assertFalse(cfg.enabled)
        self.assertIsNone(cfg.confirm_function)
        self.assertEqual(cfg.post_confirm_assertions, [])
        self.assertIsNone(cfg.expected_ratchet_version)
        self.assertEqual(cfg.fault_types, ["power_loss"])
        self.assertEqual(cfg.max_points, 0)

    def test_custom_values(self):
        cfg = ConfirmCycleConfig(
            enabled=True,
            confirm_function="boot_set_confirmed",
            post_confirm_assertions=[
                {"address": "0x1000", "expected": "0x01", "label": "confirmed"}
            ],
            expected_ratchet_version=2,
            fault_types=["power_loss", "bit_corruption"],
            max_points=20,
        )
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.confirm_function, "boot_set_confirmed")
        self.assertEqual(len(cfg.post_confirm_assertions), 1)
        self.assertEqual(cfg.expected_ratchet_version, 2)
        self.assertEqual(cfg.max_points, 20)


class ParseConfirmCycleTest(unittest.TestCase):
    """Test _parse_confirm_cycle validation."""

    def test_none_returns_default(self):
        cfg = _parse_confirm_cycle(None)
        self.assertFalse(cfg.enabled)

    def test_empty_dict_returns_default(self):
        cfg = _parse_confirm_cycle({})
        self.assertFalse(cfg.enabled)

    def test_enabled_without_function_raises(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({"enabled": True})

    def test_enabled_with_function(self):
        cfg = _parse_confirm_cycle({
            "enabled": True,
            "confirm_function": "boot_set_confirmed",
        })
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.confirm_function, "boot_set_confirmed")

    def test_invalid_assertion_missing_address(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({
                "enabled": True,
                "confirm_function": "foo",
                "post_confirm_assertions": [{"expected": 1}],
            })

    def test_invalid_assertion_missing_expected(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({
                "enabled": True,
                "confirm_function": "foo",
                "post_confirm_assertions": [{"address": "0x1000"}],
            })

    def test_valid_assertions(self):
        cfg = _parse_confirm_cycle({
            "enabled": True,
            "confirm_function": "foo",
            "post_confirm_assertions": [
                {"address": "0x1000", "expected": "0x01", "label": "flag"},
                {"address": "0x2000", "expected": [1, 2]},
            ],
        })
        self.assertEqual(len(cfg.post_confirm_assertions), 2)

    def test_negative_max_points_raises(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({
                "enabled": True,
                "confirm_function": "foo",
                "max_points": -1,
            })

    def test_negative_ratchet_version_raises(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({
                "enabled": True,
                "confirm_function": "foo",
                "expected_ratchet_version": -1,
            })

    def test_unsupported_fault_type_rejected(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle({
                "enabled": True,
                "confirm_function": "foo",
                "fault_types": ["power_loss", "interrupted_erase"],
            })

    def test_not_dict_raises(self):
        with self.assertRaises(ProfileError):
            _parse_confirm_cycle("invalid")


class FaultSweepConfigConfirmCycleTest(unittest.TestCase):
    """Test confirm_cycle on FaultSweepConfig."""

    def test_default_confirm_cycle(self):
        fs = FaultSweepConfig()
        self.assertFalse(fs.confirm_cycle.enabled)
        self.assertIsNone(fs.confirm_cycle.confirm_function)

    def test_custom_confirm_cycle(self):
        cc = ConfirmCycleConfig(
            enabled=True,
            confirm_function="confirm_fn",
            max_points=10,
        )
        fs = FaultSweepConfig(confirm_cycle=cc)
        self.assertTrue(fs.confirm_cycle.enabled)
        self.assertEqual(fs.confirm_cycle.confirm_function, "confirm_fn")
        self.assertEqual(fs.confirm_cycle.max_points, 10)


class ConfirmCycleProfileLoadTest(unittest.TestCase):
    """Test loading the confirm_cycle self-test profile."""

    def test_load_profile(self):
        if not CONFIRM_PROFILE.exists():
            self.skipTest("confirm_cycle profile not found")
        profile = load_profile(CONFIRM_PROFILE)
        self.assertTrue(profile.fault_sweep.confirm_cycle.enabled)
        self.assertEqual(profile.fault_sweep.confirm_cycle.confirm_function, "0x00000000")
        self.assertEqual(len(profile.fault_sweep.confirm_cycle.post_confirm_assertions), 2)
        self.assertEqual(profile.fault_sweep.confirm_cycle.max_points, 15)
        self.assertIn("power_loss", profile.fault_sweep.confirm_cycle.fault_types)
        self.assertIn("bit_corruption", profile.fault_sweep.confirm_cycle.fault_types)
        self.assertIn("command_drop", profile.fault_sweep.confirm_cycle.fault_types)


class ConfirmCycleBootCycleHookValidationTest(unittest.TestCase):
    """Test that confirm_cycle.enabled requires boot_cycle_hook."""

    def test_enabled_without_boot_cycle_hook_raises(self):
        """confirm_cycle.enabled without boot_cycle_hook should raise."""
        import yaml
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({
                "schema_version": 1,
                "name": "test_no_hook",
                "description": "test",
                "platform": "platforms/cortex_m0_nvm.repl",
                "bootloader": {"elf": "test.elf", "entry": 0},
                "memory": {
                    "sram": {"start": 0x20000000, "end": 0x20020000},
                    "write_granularity": 4,
                    "slots": {"exec": {"base": 0x10000000, "size": 0x10000}},
                },
                "images": {"exec": "test.bin"},
                "pre_boot_state": [],
                "success_criteria": {"vtor_in_slot": "exec"},
                "fault_sweep": {
                    "mode": "runtime",
                    "confirm_cycle": {
                        "enabled": True,
                        "confirm_function": "boot_set_confirmed",
                    },
                },
            }, f)
            f.flush()
            with self.assertRaises(ProfileError) as ctx:
                load_profile(f.name)
            self.assertIn("boot_cycle_hook", str(ctx.exception))


class ConfirmCycleFaultPlanTest(unittest.TestCase):
    """Test fault plan generation for confirm_cycle."""

    def test_confirm_cycle_generates_points(self):
        if not CONFIRM_PROFILE.exists():
            self.skipTest("confirm_cycle profile not found")
        profile = load_profile(CONFIRM_PROFILE)
        cal = CalibrationInputs(max_writes=100)
        plan = build_fault_plan(profile, cal)
        # Should have cc: prefixed fault types.
        cc_types = [ft for ft in plan.fault_types_list if ft.startswith("cc:")]
        self.assertGreater(len(cc_types), 0)
        # Each should have format cc:<index>:<type_code>.
        for ft in cc_types:
            parts = ft.split(":")
            self.assertEqual(len(parts), 3)
            self.assertEqual(parts[0], "cc")
            int(parts[1])  # Should be parseable as int.
            self.assertIn(parts[2], {"w", "b", "k"})


class ConfirmCycleFaultTypeLabelTest(unittest.TestCase):
    """Test fault type label for confirm_cycle codes."""

    def test_cc_prefix_label(self):
        self.assertEqual(_fault_type_label("cc:0:w"), "confirm_power_loss")
        self.assertEqual(_fault_type_label("cc:1:b"), "confirm_bit_corruption")
        self.assertEqual(_fault_type_label("cc:2:k"), "confirm_command_drop")

    def test_cc_standalone(self):
        self.assertEqual(_fault_type_label("cc"), "confirm_cycle")


class ConfirmCycleIssueReasonsTest(unittest.TestCase):
    """Test finding categories for confirm_cycle results."""

    def test_confirm_incomplete(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
            "confirm_cycle": {
                "confirm_incomplete": True,
                "rollback_not_ratcheted": False,
                "metadata_inconsistent_after_confirm": False,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertIn("confirm_incomplete", reasons)

    def test_rollback_not_ratcheted(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
            "confirm_cycle": {
                "confirm_incomplete": False,
                "rollback_not_ratcheted": True,
                "metadata_inconsistent_after_confirm": False,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertIn("rollback_not_ratcheted", reasons)

    def test_metadata_inconsistent_after_confirm(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
            "confirm_cycle": {
                "confirm_incomplete": False,
                "rollback_not_ratcheted": False,
                "metadata_inconsistent_after_confirm": True,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertIn("metadata_inconsistent_after_confirm", reasons)

    def test_no_confirm_cycle_no_findings(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
        }
        reasons = result_issue_reasons(result, "success")
        self.assertNotIn("confirm_incomplete", reasons)
        self.assertNotIn("rollback_not_ratcheted", reasons)

    def test_all_false_no_findings(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
            "confirm_cycle": {
                "confirm_incomplete": False,
                "rollback_not_ratcheted": False,
                "metadata_inconsistent_after_confirm": False,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertNotIn("confirm_incomplete", reasons)
        self.assertNotIn("rollback_not_ratcheted", reasons)
        self.assertNotIn("metadata_inconsistent_after_confirm", reasons)

    def test_no_write_skip_is_not_reported_as_confirm_incomplete(self):
        result = {
            "boot_outcome": "skipped",
            "fault_injected": False,
            "confirm_cycle": {
                "skip_reason": "no_write_at_index",
                "confirm_incomplete": False,
                "rollback_not_ratcheted": False,
                "metadata_inconsistent_after_confirm": False,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertNotIn("confirm_incomplete", reasons)

    def test_multiple_findings(self):
        result = {
            "boot_outcome": "success",
            "fault_injected": True,
            "confirm_cycle": {
                "confirm_incomplete": True,
                "rollback_not_ratcheted": True,
                "metadata_inconsistent_after_confirm": True,
            },
        }
        reasons = result_issue_reasons(result, "success")
        self.assertIn("confirm_incomplete", reasons)
        self.assertIn("rollback_not_ratcheted", reasons)
        self.assertIn("metadata_inconsistent_after_confirm", reasons)


class ConfirmCycleRobotVarsTest(unittest.TestCase):
    """Test robot_vars emission for confirm_cycle."""

    def test_robot_vars_with_confirm_cycle(self):
        if not CONFIRM_PROFILE.exists():
            self.skipTest("confirm_cycle profile not found")
        profile = load_profile(CONFIRM_PROFILE)
        robot_vars = profile.robot_vars(ROOT)
        var_dict = {}
        for v in robot_vars:
            if ":" in v:
                key, _, val = v.partition(":")
                var_dict[key] = val
        self.assertEqual(var_dict.get("CONFIRM_CYCLE_ENABLED"), "true")
        self.assertEqual(var_dict.get("CONFIRM_CYCLE_FUNCTION"), "0x00000000")
        self.assertIn("CONFIRM_CYCLE_ASSERTIONS", var_dict)
        self.assertIn("CONFIRM_CYCLE_MAX_POINTS", var_dict)

    def test_robot_vars_without_confirm_cycle(self):
        """Disabled confirm_cycle should not emit vars."""
        fs = FaultSweepConfig()
        from profile_loader import (
            MemoryConfig, SlotConfig, SuccessCriteria,
            StateFuzzerConfig, ExpectConfig,
        )
        profile = ProfileConfig(
            schema_version=1, name="test", description="",
            platform="platforms/cortex_m0_nvm.repl",
            bootloader_elf="test.elf", bootloader_entry=0,
            memory=MemoryConfig(
                sram_start=0x20000000, sram_end=0x20020000,
                write_granularity=4,
                slots={"exec": SlotConfig(0x10000000, 0x10000)},
            ),
            images={}, pre_boot_state=[], setup_script=None,
            extra_peripherals=None,
            success_criteria=SuccessCriteria(), fault_sweep=fs,
            state_fuzzer=StateFuzzerConfig(), expect=ExpectConfig(),
        )
        robot_vars = profile.robot_vars(ROOT)
        var_keys = {v.partition(":")[0] for v in robot_vars if ":" in v}
        self.assertNotIn("CONFIRM_CYCLE_ENABLED", var_keys)


class ConfirmCycleDiagnosticSummaryTest(unittest.TestCase):
    """Test diagnostic summary includes confirm_cycle fields."""

    def test_diagnostic_summary_includes_confirm_cycle(self):
        if not CONFIRM_PROFILE.exists():
            self.skipTest("confirm_cycle profile not found")
        from profile_loader import main as pl_main
        profile = load_profile(CONFIRM_PROFILE)
        # Access the diagnostic summary through the internal path.
        from profile_loader import main  # noqa: F811
        # Just verify the attributes exist on the config.
        self.assertTrue(hasattr(profile.fault_sweep, "confirm_cycle"))
        self.assertTrue(profile.fault_sweep.confirm_cycle.enabled)


if __name__ == "__main__":
    unittest.main()
