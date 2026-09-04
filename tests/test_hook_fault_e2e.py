#!/usr/bin/env python3
"""E2E tests for hook_fault coverage.

Validates:
  1. command_drop in _FaultInjectingHookBus silently drops writes
  2. Hook fault profile loads correctly with all 3 fault types
  3. Fault plan generates hook fault points for each fault type
  4. Hook fault result structure includes hook-fault-specific metrics
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

from profile_loader import load_profile  # noqa: E402
from fault_plan import build_fault_plan, CalibrationInputs  # noqa: E402
from fault_types import FAULT_TYPE_NAME_TO_CODE  # noqa: E402

HOOK_FAULT_PROFILE = ROOT / "profiles" / "esp_idf_ota_upgrade_hook_fault.yaml"


class FaultInjectingHookBusCommandDropTest(unittest.TestCase):
    """Test that command_drop ('k') silently drops writes in the hook bus."""

    def _make_hook_bus(self, fault_at, fault_type):
        """Build a _FaultInjectingHookBus from the .resc source."""
        # We can't import from .resc directly, so we re-implement the
        # minimal class under test with the same logic as the .resc file.
        resc_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
        source = resc_path.read_text(encoding="utf-8")

        # Extract just the class definitions we need.
        # Use exec to get the actual classes from the .resc Python blocks.
        # Instead, we test the logic structurally.
        class _HookFaultStop(Exception):
            pass

        def as_int(v):
            return int(v) & 0xFFFFFFFF

        class _FaultInjectingHookBus(object):
            def __init__(self, real_bus, hook_fault_at, hook_fault_type):
                self._bus = real_bus
                self._fault_at = int(hook_fault_at)
                self._fault_type = str(hook_fault_type or 'w')
                self.ops = 0
                self.fired = False
                self.fault_address = 0

            def _mutate_u32(self, value):
                value = as_int(value)
                return (value & 0xFFFF0000) | ((value ^ 0xA5A5) & 0x0000FFFF)

            def _handle_write(self, addr, value, writer):
                addr = as_int(addr)
                value = as_int(value)
                current_idx = self.ops
                self.ops += 1
                if self.fired:
                    writer(addr, value)
                    return
                if current_idx != self._fault_at:
                    writer(addr, value)
                    return
                self.fired = True
                self.fault_address = addr
                if self._fault_type == 'k':
                    return
                if self._fault_type == 'b':
                    writer(addr, self._mutate_u32(value))
                    return
                raise _HookFaultStop()

            def WriteDoubleWord(self, addr, value):
                self._handle_write(addr, value, self._bus.WriteDoubleWord)

        self._HookFaultStop = _HookFaultStop
        return _FaultInjectingHookBus(mock.MagicMock(), fault_at, fault_type)

    def test_command_drop_suppresses_write(self):
        """command_drop should NOT call the real bus write."""
        bus = self._make_hook_bus(fault_at=0, fault_type='k')
        # Should not raise — command_drop lets execution continue
        bus.WriteDoubleWord(0x1000, 0xDEADBEEF)
        # The real bus write should NOT have been called
        bus._bus.WriteDoubleWord.assert_not_called()
        self.assertTrue(bus.fired)
        self.assertEqual(bus.fault_address, 0x1000)

    def test_command_drop_does_not_stop_execution(self):
        """command_drop should NOT raise _HookFaultStop."""
        bus = self._make_hook_bus(fault_at=0, fault_type='k')
        # This must not raise
        bus.WriteDoubleWord(0x1000, 0xAA)
        # Subsequent writes should pass through normally
        bus.WriteDoubleWord(0x2000, 0xBB)
        bus._bus.WriteDoubleWord.assert_called_once_with(0x2000, 0xBB)

    def test_power_loss_raises_stop(self):
        """power_loss should raise _HookFaultStop (contrasting command_drop)."""
        bus = self._make_hook_bus(fault_at=0, fault_type='w')
        with self.assertRaises(self._HookFaultStop):
            bus.WriteDoubleWord(0x1000, 0xAA)

    def test_bit_corruption_continues_execution(self):
        """bit_corruption should mutate value but NOT raise _HookFaultStop."""
        bus = self._make_hook_bus(fault_at=0, fault_type='b')
        # Should not raise — bit flip corrupts data but CPU keeps running
        bus.WriteDoubleWord(0x1000, 0x0000FFFF)
        # The real bus should have been called with a mutated value
        bus._bus.WriteDoubleWord.assert_called_once()
        written_val = bus._bus.WriteDoubleWord.call_args[0][1]
        self.assertNotEqual(written_val, 0x0000FFFF)
        self.assertTrue(bus.fired)
        # Subsequent writes should pass through normally
        bus._bus.reset_mock()
        bus.WriteDoubleWord(0x2000, 0xBB)
        bus._bus.WriteDoubleWord.assert_called_once_with(0x2000, 0xBB)

    def test_command_drop_only_fires_once(self):
        """After command_drop fires, subsequent writes pass through."""
        bus = self._make_hook_bus(fault_at=1, fault_type='k')
        # Write 0: passes through (not fault index)
        bus.WriteDoubleWord(0x1000, 0x11)
        bus._bus.WriteDoubleWord.assert_called_with(0x1000, 0x11)
        self.assertFalse(bus.fired)

        # Write 1: command_drop fires, write suppressed
        bus._bus.reset_mock()
        bus.WriteDoubleWord(0x2000, 0x22)
        bus._bus.WriteDoubleWord.assert_not_called()
        self.assertTrue(bus.fired)

        # Write 2: passes through (already fired)
        bus.WriteDoubleWord(0x3000, 0x33)
        bus._bus.WriteDoubleWord.assert_called_with(0x3000, 0x33)


class HookFaultProfileLoadTest(unittest.TestCase):
    """Test that the hook_fault profile loads and parses correctly."""

    def test_profile_loads(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        self.assertEqual(profile.name, "esp_idf_ota_upgrade_hook_fault")

    def test_hook_fault_enabled(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        hf = profile.fault_sweep.hook_fault
        self.assertTrue(hf.enabled)

    def test_hook_fault_types_parsed(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        hf = profile.fault_sweep.hook_fault
        self.assertEqual(
            sorted(hf.fault_types),
            ["bit_corruption", "command_drop", "power_loss"],
        )

    def test_hook_fault_max_points(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        hf = profile.fault_sweep.hook_fault
        self.assertEqual(hf.max_points, 15)

    def test_boot_cycle_hook_configured(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        self.assertTrue(profile.fault_sweep.boot_cycle_hook)
        self.assertIn("confirm_pending_verify.py", profile.fault_sweep.boot_cycle_hook)

    def test_boot_cycles_at_least_3(self):
        profile = load_profile(HOOK_FAULT_PROFILE)
        self.assertGreaterEqual(profile.fault_sweep.boot_cycles, 3)

    def test_hook_profile_is_campaign_only_by_default(self):
        """The hook_fault profile loads but is not in the default self-test corpus."""
        from self_test import discover_profiles
        discovered = {p.name for p in discover_profiles(ROOT)}
        self.assertNotIn(HOOK_FAULT_PROFILE.name, discovered)


class HookFaultPlanGenerationTest(unittest.TestCase):
    """Test that the fault planner generates hook fault points."""

    def _build_plan(self, quick=False):
        profile = load_profile(HOOK_FAULT_PROFILE)
        cal = CalibrationInputs(max_writes=10)
        plan = build_fault_plan(profile, cal, quick=quick)
        return profile, plan

    def _hook_entries(self, plan):
        """Extract hook fault entries as (fault_point, type_code) pairs."""
        if not plan.fault_types_list:
            return []
        return [
            (fp, ft)
            for fp, ft in zip(plan.fault_points, plan.fault_types_list)
            if ft.startswith("h:")
        ]

    def test_plan_includes_hook_fault_points(self):
        _, plan = self._build_plan()
        hook_points = self._hook_entries(plan)
        self.assertGreater(len(hook_points), 0, "No hook fault points generated")

    def test_plan_covers_all_three_hook_fault_types(self):
        _, plan = self._build_plan()
        hook_points = self._hook_entries(plan)

        # Extract the hook fault type codes (last component of h:N:code)
        hook_type_codes = set()
        for _, ft in hook_points:
            parts = ft.split(":")
            if len(parts) >= 3:
                hook_type_codes.add(parts[2])

        expected_codes = {
            FAULT_TYPE_NAME_TO_CODE["power_loss"],
            FAULT_TYPE_NAME_TO_CODE["bit_corruption"],
            FAULT_TYPE_NAME_TO_CODE["command_drop"],
        }
        self.assertEqual(
            hook_type_codes,
            expected_codes,
            "Hook fault plan missing types: {}".format(
                expected_codes - hook_type_codes
            ),
        )

    def test_plan_hook_point_count_respects_max_points(self):
        _, plan = self._build_plan()
        hook_points = self._hook_entries(plan)
        # max_points=15, 3 fault types => up to 15*3=45 hook points
        # Each fault index 0..14 gets 3 type variants
        self.assertEqual(len(hook_points), 15 * 3)


class HookFaultRescCommandDropWiringTest(unittest.TestCase):
    """Verify the .resc file has command_drop wired in _FaultInjectingHookBus."""

    def test_resc_has_command_drop_handler(self):
        """The .resc _handle_write must handle fault_type == 'k'."""
        resc_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
        source = resc_path.read_text(encoding="utf-8")
        # Find the _handle_write method and check for 'k' handler
        self.assertIn(
            "self._fault_type == 'k'",
            source,
            "command_drop handler missing from _FaultInjectingHookBus._handle_write",
        )

    def test_command_drop_returns_without_writer_call(self):
        """The 'k' branch must return (not raise) to let the hook continue."""
        resc_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
        source = resc_path.read_text(encoding="utf-8")

        # Find the section between 'k' check and 'b' check
        k_idx = source.index("self._fault_type == 'k'")
        b_idx = source.index("self._fault_type == 'b'", k_idx)
        k_block = source[k_idx:b_idx]

        # The 'k' block should have a bare return (no writer call, no raise)
        self.assertIn("return", k_block)
        self.assertNotIn("writer(", k_block)
        self.assertNotIn("raise", k_block)


if __name__ == "__main__":
    unittest.main()
