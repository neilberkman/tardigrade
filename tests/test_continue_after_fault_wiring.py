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
        self.assertIn("fault_base = _base_fault_type_code(fault_type)", source)
        self.assertIn("is_power_loss_fault = fault_base in ('w', 'e', 'a')", source)
        self.assertIn(
            "is_non_power_write_fault = fault_base in ('b', 's', 'g', 'x', 'r', 'd', 'l', 'k')",
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

    def test_robot_loader_includes_all_fast_backends(self) -> None:
        source = (ROOT / "tests" / "ota_fault_point.robot").read_text(
            encoding="utf-8"
        )
        for filename in (
            "NRF52NVMC.cs",
            "STM32F4FastFlash.cs",
            "STM32H7FastFlash.cs",
        ):
            with self.subTest(filename=filename):
                self.assertIn(
                    'include "${{ROOT}}/peripherals/{}"'.format(filename),
                    source,
                )

    def test_fast_backends_persist_non_power_faults_to_live_flash(self) -> None:
        expected_writes = {
            "peripherals/NRF52NVMC.cs": (
                "ApplyWriteFaultAtOffset(faultedCurrent, wenSnapshot, current, off, len);",
                "Flash.WriteBytes(0, faultedCurrent, 0, len);",
            ),
            "peripherals/STM32F4FastFlash.cs": (
                "ApplyWriteFaultAtOffset(faultedCurrent, preFaultSnapshot, current, changedOffset, flashLen);",
                "Flash.WriteBytes(0, faultedCurrent, 0, flashLen);",
            ),
            "peripherals/STM32H7FastFlash.cs": (
                "ApplyWriteFaultAtOffset(faultedCurrent, preFaultSnapshot, current,\n                            faultOffset, flashLen, faultWriteIndex);",
                "flash.WriteBytes(0, faultedCurrent, 0, flashLen);",
            ),
        }
        for relpath, snippets in expected_writes.items():
            with self.subTest(relpath=relpath):
                source = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn("if(WriteFaultMode == 0)", source)
                for snippet in snippets:
                    self.assertIn(snippet, source)

    def test_h7_dual_bank_view_supports_context_aware_reads(self) -> None:
        source = (ROOT / "peripherals" / "STM32H7FastFlash.cs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "public byte[] ReadBytes(long offset, int count, IPeripheral context)",
            source,
        )

    def test_h7_fast_fault_uses_triggering_word_index_after_full_diff(self) -> None:
        source = (ROOT / "peripherals" / "STM32H7FastFlash.cs").read_text(
            encoding="utf-8"
        )
        self.assertIn("ulong faultWriteIndex = 0;", source)
        self.assertIn("faultWriteIndex = tracker.TotalWordWrites;", source)
        self.assertIn("ApplyWriteFaultAtOffset(faultedCurrent, preFaultSnapshot, current,", source)
        self.assertIn("faultOffset, flashLen, faultWriteIndex);", source)
        self.assertIn("BuildFaultSeedForWrite(off, writeIndex)", source)
        self.assertIn("((writeIndex & 1UL) == 0UL)", source)


if __name__ == "__main__":
    unittest.main()
