#!/usr/bin/env python3
"""Guardrails for continue-after-fault write semantics."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESC_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


class TestContinueAfterFaultWiring(unittest.TestCase):
    def test_resc_stops_only_on_immediate_stop_faults(self) -> None:
        source = RESC_PATH.read_text(encoding="utf-8")
        self.assertIn("def fault_requires_immediate_stop():", source)
        self.assertIn(
            "if stop_on_fault and (fault_requires_immediate_stop() or was_otp_fault_injected()):",
            source,
        )
        self.assertIn(
            "return (bool(b['data'].FaultEverFired) and int(getattr(b['data'], 'WriteFaultMode', 0)) == 0) or was_controller_fault_injected()",
            source,
        )
        self.assertIn(
            "return (bool(b['data'].Nvm.FaultEverFired) and int(getattr(b['data'].Nvm, 'WriteFaultMode', 0)) == 0) or was_controller_fault_injected()",
            source,
        )

    def test_bit_corruption_is_not_power_loss(self) -> None:
        source = RESC_PATH.read_text(encoding="utf-8")
        self.assertIn("is_power_loss_fault = fault_type in ('w', 'e', 'a')", source)
        self.assertIn(
            "is_non_power_write_fault = fault_type in ('b', 's', 'g', 'x', 'r', 'd', 'l', 'k')",
            source,
        )

    def test_arm_fault_sets_write_mode_for_all_write_backends(self) -> None:
        source = RESC_PATH.read_text(encoding="utf-8")
        self.assertIn("b['data'].WriteFaultMode = write_fault_mode", source)
        self.assertIn("b['data'].Nvm.WriteFaultMode = write_fault_mode", source)

    def test_execute_path_only_restarts_if_phase1_stopped_on_fault(self) -> None:
        source = RESC_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "phase1_stopped_on_fault = phase1_status is not None and phase1_status.get('reason') == 'fault_fired'",
            source,
        )
        self.assertIn("if phase1_stopped_on_fault and is_power_loss_fault:", source)
        self.assertIn(
            "elif phase1_stopped_on_fault and is_non_power_write_fault:",
            source,
        )
        self.assertIn(
            "elif backend['kind'] == 'slow' and fault_injected and is_power_loss_fault and phase1_stopped_on_fault:",
            source,
        )

    def test_fault_result_records_post_boot_word_change_signal(self) -> None:
        source = RESC_PATH.read_text(encoding="utf-8")
        self.assertIn("signals['fault_snapshot_word'] = fmt_u32(_snapshot_word)", source)
        self.assertIn("signals['fault_final_word'] = fmt_u32(_final_word)", source)
        self.assertIn(
            "signals['fault_word_changed_post_boot'] = bool(_final_word != _snapshot_word)",
            source,
        )


class TestPeripheralImmediateStopContract(unittest.TestCase):
    def test_interface_exposes_immediate_stop_property(self) -> None:
        source = (ROOT / "peripherals" / "ITardigradeFaultInjectable.cs").read_text(
            encoding="utf-8"
        )
        self.assertIn("bool FaultRequiresImmediateStop { get; }", source)
        self.assertIn("bool DriverErrorFired { get; set; }", source)

    def test_fault_tracker_only_blocks_power_loss_write_faults(self) -> None:
        source = (ROOT / "peripherals" / "FaultTracker.cs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "public bool WriteFaultRequiresImmediateStop => FaultFired && WriteFaultMode == 0;",
            source,
        )
        self.assertIn(
            "public bool FaultRequiresImmediateStop => EraseFaultFired || WriteFaultRequiresImmediateStop;",
            source,
        )
        self.assertIn(
            "public bool AnyFaultFired => FaultRequiresImmediateStop;",
            source,
        )

    def test_all_fast_peripherals_forward_immediate_stop_property(self) -> None:
        expected = "public bool FaultRequiresImmediateStop => tracker.FaultRequiresImmediateStop;"
        for relpath in (
            "peripherals/NRF52NVMC.cs",
            "peripherals/STM32F4FastFlash.cs",
            "peripherals/STM32H7FastFlash.cs",
            "peripherals/STM32F4FlashController.cs",
            "peripherals/STM32H7FlashController.cs",
        ):
            with self.subTest(relpath=relpath):
                source = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn(expected, source)


if __name__ == "__main__":
    unittest.main()
