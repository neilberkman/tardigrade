#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static guardrails for the AN521 Renode peripheral map."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Mps2An521PlatformTest(unittest.TestCase):
    def setUp(self):
        self.platform = (ROOT / "platforms/mps2_an521.repl").read_text(
            encoding="utf-8"
        )
        self.nvm = (ROOT / "peripherals/An521NvmInterceptor.cs").read_text(
            encoding="utf-8"
        )
        self.mpc = (ROOT / "peripherals/Sse200MpcStub.cs").read_text(
            encoding="utf-8"
        )
        self.watchdog = (ROOT / "peripherals/CMSDKAPBWatchdog.cs").read_text(
            encoding="utf-8"
        )

    def test_official_an521_register_blocks_are_mapped(self):
        for address, name in (
            ("0x50080000", "spctrl"),
            ("0x40080000", "spctrl"),
            ("0x58007000", "mpc_code_sram1"),
            ("0x58008000", "mpc_code_sram2"),
            ("0x58009000", "mpc_code_sram3"),
        ):
            with self.subTest(address=address):
                self.assertIn(address, self.platform)
                self.assertIn(name, self.platform)

    def test_trustzone_nvic_alias_is_registered(self):
        self.assertIn(
            "sysbus new Bus.BusPointRegistration { address: 0xE000E000; cpu: cpu }",
            self.platform,
        )
        self.assertIn(
            'sysbus new Bus.BusMultiRegistration { address: 0xE002E000; size: 0x1000; region: "NonSecure"; cpu: cpu }',
            self.platform,
        )

    def test_nonsecure_data_alias_uses_compatible_mapped_registration(self):
        ssram2 = self.platform.split("ssram2: Memory.MappedMemory @ {", 1)[1].split(
            "    size: 0x400000", 1
        )[0]
        self.assertIn("sysbus 0x38000000", ssram2)
        self.assertIn("sysbus 0x28000000", ssram2)
        self.assertNotIn("BusMultiRegistration", ssram2)

    def test_mpc_register_values_match_an521_granularity(self):
        self.assertIn("case 0x10: return MaximumBlockWordIndex;", self.mpc)
        self.assertIn("case 0x14: return BlockConfiguration;", self.mpc)
        self.assertIn("BlockConfiguration { get; set; } = 8U", self.mpc)
        self.assertIn("MaximumBlockWordIndex { get; set; } = 511U", self.mpc)

    def test_mpc_lut_is_indexed_and_bounds_checked(self):
        self.assertIn("lutWords.TryGetValue(blockIndex", self.mpc)
        self.assertIn("lutWords[blockIndex] = value;", self.mpc)
        self.assertIn("if(blockIndex <= MaximumBlockWordIndex)", self.mpc)
        self.assertIn("lutWords.Clear();", self.mpc)

    def test_old_mislabeled_timer_tag_is_gone(self):
        self.assertNotIn('Tag <0x50080000 0x1000> "S32K_TIMER"', self.platform)

    def test_cmsdk_watchdogs_replace_an521_register_placeholders(self):
        for address, name in (
            ("0x40081000", "watchdogNs"),
            ("0x50081000", "watchdogSecure"),
        ):
            with self.subTest(address=address):
                self.assertIn(address, self.platform)
                self.assertIn(name, self.platform)
        self.assertIn("Tardigrade.CMSDKAPBWatchdog", self.platform)
        self.assertIn("ClockFrequency: 25000000", self.platform)
        self.assertIn('Tag <0x40081000 0x1000> "CMSDK_WATCHDOG_NS"', self.platform)
        self.assertIn('Tag <0x50081000 0x1000> "CMSDK_WATCHDOG_S"', self.platform)

    def test_cmsdk_watchdog_register_and_two_stage_semantics(self):
        for fragment in (
            "LoadOffset = 0x000",
            "ValueOffset = 0x004",
            "ControlOffset = 0x008",
            "InterruptClearOffset = 0x00C",
            "RawInterruptStatusOffset = 0x010",
            "MaskedInterruptStatusOffset = 0x014",
            "LockOffset = 0xC00",
            "UnlockValue = 0x1ACCE551",
            "if(!rawInterrupt)",
            "machine.RequestReset()",
            "watchdogTimer.Limit = loadValue",
            "resetOutputActive",
            "IntegrationResetBit",
            "PeripheralId0Offset",
            "ComponentId3Offset",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.watchdog)

    def test_nvm_uses_secure_backing_and_nonsecure_interceptor_alias(self):
        self.assertIn("ssram1: Memory.MappedMemory @ {", self.platform)
        self.assertIn("address: 0x10000000;", self.platform)
        self.assertIn(
            "faultFlash: Miscellaneous.An521NvmInterceptor @ {",
            self.platform,
        )
        self.assertIn("BackingMemory: ssram1", self.platform)
        self.assertNotIn("faultFlash: Miscellaneous.NRF52NVMC", self.platform)

    def test_nvm_ranges_leave_executable_ns_primary_window(self):
        ns_primary_start = 0x00100000
        ns_primary_size = 0x7F000
        interceptor_low = (0x00000000, 0x100000)
        interceptor_high = (0x0017F000, 0x281000)

        self.assertEqual(ns_primary_start + ns_primary_size, interceptor_high[0])
        self.assertEqual(interceptor_low[0] + interceptor_low[1], ns_primary_start)
        self.assertEqual(interceptor_high[0] + interceptor_high[1], 0x400000)
        self.assertEqual(interceptor_low[0] + interceptor_low[1], ns_primary_start)
        self.assertLess(ns_primary_start, interceptor_high[0])
        self.assertEqual(self.platform.count("Bus.BusRangeRegistration"), 8)
        self.assertIn("size: 0x7F000", self.platform)
        self.assertIn("size: 0x281000", self.platform)

    def test_secure_primary_trailer_uses_interceptor(self):
        self.assertIn("address: 0x100FF000;", self.platform)
        self.assertIn("size: 0x001000;", self.platform)
        self.assertIn("offset: 0x0FF000", self.platform)
        self.assertIn("address: 0x10100000;", self.platform)
        self.assertIn("offset: 0x100000", self.platform)

    def test_official_code_aliases_are_intercepted_without_overlap(self):
        for address in ("0x00400000", "0x10400000"):
            with self.subTest(address=address):
                self.assertIn("address: {};".format(address), self.platform)
        self.assertIn("address >= 0x00400000", self.nvm)
        self.assertIn("address >= 0x10400000", self.nvm)
        ranges = [
            (0x00000000, 0x00100000),
            (0x0017F000, 0x00400000),
            (0x00400000, 0x00800000),
            (0x100FF000, 0x10100000),
            (0x10400000, 0x10800000),
        ]
        for previous, current in zip(ranges, ranges[1:]):
            self.assertLessEqual(previous[1], current[0])

    def test_mpc_boundary_enforcement_is_explicitly_unavailable(self):
        probe = (ROOT / "targets/tf_m_bl2/probe.py").read_text(encoding="utf-8")
        self.assertIn('"security_boundary":', probe)
        self.assertIn('"status": "unavailable"', probe)

    def test_nvm_counts_traces_and_handles_required_fault_modes(self):
        for fragment in (
            "tracker.RecordWriteAndCheckFault",
            "FaultFlashSnapshot = (byte[])flashShadow.Clone()",
            "case 1:",
            "case 2:",
            "case 4:",
            "case 5:",
            "case 6:",
            "DriverErrorFired = true",
            "WriteResult(aligned, offset, width, result)",
            "SetHookAtMemoryAccess",
            "TryResolveAlias",
            "TrackingStartAddress",
            "MemoryOperation.MemoryWrite",
            "FaultAtWordWrite != ulong.MaxValue",
            "ICPUWithHooks",
            "AddHook(trackingStartAddress",
            "if(!trackingStarted)",
            "preserve earlier boot writes normally",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.nvm)

    def test_nvm_avoids_imemory_fast_path(self):
        """Primitive callbacks plus the CPU hook cover direct aliases."""
        self.assertIn("IBytePeripheral", self.nvm)
        self.assertIn("IDoubleWordPeripheral", self.nvm)
        self.assertNotIn("IMemory,", self.nvm)

    def test_nvm_uses_exact_instruction_gate_before_memory_hook(self):
        self.assertIn("AddHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart)", self.nvm)
        self.assertIn(
            "cpu.SetHookAtMemoryAccess(enabled && trackingStarted ? (MemoryAccessHook)OnMemoryWrite : null);",
            self.nvm,
        )
        self.assertIn("RemoveTrackingStartHook", self.nvm)

    def test_nvm_rejects_unsupported_write_modes_explicitly(self):
        self.assertIn("value < 0 || value > 6", self.nvm)
        self.assertIn("Unsupported AN521 write fault mode", self.nvm)

    def test_nvm_reset_clears_stale_memory_hook_before_gate(self):
        self.assertIn(
            "Always reconcile this hook, including the gated/reset",
            self.nvm,
        )
        self.assertIn("trackingStarted = trackingStartAddress == 0", self.nvm)

    def test_nvm_reapplies_same_gate_after_cpu_reset_clears_hook(self):
        self.assertIn(
            "Reconcile even when the value is unchanged",
            self.nvm,
        )
        self.assertIn(
            "if(startHookInstalled)",
            self.nvm,
        )
        for prop in ("TrackingStarted", "StartHookInstalled", "MemoryAccessHookInstalled"):
            with self.subTest(prop=prop):
                self.assertIn("public bool {} =>".format(prop), self.nvm)

    def test_nvm_counter_only_calibration_keeps_cpu_hook_armed(self):
        self.assertIn(
            "var trackingRequested = trackingStartAddress != 0 || trackingStarted;",
            self.nvm,
        )
        self.assertIn(
            "var enabled = trackingRequested || tracker.WriteTraceEnabled ||",
            self.nvm,
        )

    def test_nvm_resolves_cpu_alias_from_virtual_not_relative_physical_address(self):
        self.assertIn("ulong virtualAddress", self.nvm)
        self.assertIn("TryResolveAlias((long)virtualAddress", self.nvm)
        self.assertNotIn("TryResolveAlias((long)physicalAddress", self.nvm)

    def test_nvm_rejects_cross_word_and_out_of_range_accesses(self):
        self.assertIn("(offset & 3) + width > 4", self.nvm)
        self.assertIn("offset > BackingMemory.Size - width", self.nvm)
        self.assertIn("offset > BackingMemory.Size - count", self.nvm)

    def test_nvm_trace_rows_carry_replayable_widths(self):
        self.assertIn("public bool WriteTraceWidthExplicit => true;", self.nvm)
        self.assertIn(
            "tracker.RecordWriteAndCheckFault(\n                traceOffset, traceValue, traceWidth)",
            self.nvm,
        )
        self.assertIn("traceValue = (ulong)result;", self.nvm)
        self.assertIn("traceValue = (ulong)newWord;", self.nvm)
        self.assertIn("traceWidth = 4;", self.nvm)

    def test_nrf_wen_trace_rows_are_explicit_aligned_words(self):
        nrf = (ROOT / "peripherals/NRF52NVMC.cs").read_text(encoding="utf-8")
        self.assertIn("public bool WriteTraceWidthExplicit => true;", nrf)
        self.assertIn("tracker.RecordWriteAndCheckFault(off, val32, 4)", nrf)
        self.assertIn("&& (WriteTraceEnabled", nrf)


if __name__ == "__main__":
    unittest.main()
