#!/usr/bin/env python3
"""Generic unit tests for read-fault address translation and accounting.

These tests use only synthetic / fake emulator backends. They do not
import any real firmware images, real memory maps, real symbols, or
product-specific constants. Backend bus bases are passed in
explicitly to mirror what the harness obtains from the emulator's
peripheral mapping at runtime.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from read_fault_translation import (  # noqa: E402
    CPU_PATH_OUTCOMES,
    READ_FAULT_SKIP_REASONS,
    ReadFaultStats,
    classify_cpu_path_outcome,
    cpu_path_capability_warning,
    pick_target_address_in_regions,
    read_fault_warning,
    translate_bus_address_to_backend_offset,
)


# ---------------------------------------------------------------------------
# Fake backend helper
# ---------------------------------------------------------------------------


class FakeBackend(object):
    """Minimal stand-in for an emulator-mapped peripheral.

    Carries only what the translation helper needs: bus base and size.
    Tests never reach for firmware/target-specific concepts.
    """

    def __init__(self, bus_base, size):
        self.bus_base = bus_base
        self.size = size


# ---------------------------------------------------------------------------
# translate_bus_address_to_backend_offset
# ---------------------------------------------------------------------------


class TranslateBusAddressTest(unittest.TestCase):
    def test_in_range_at_nonzero_base(self):
        backend = FakeBackend(bus_base=0x4000_0000, size=0x10000)
        offset, reason = translate_bus_address_to_backend_offset(
            0x4000_1234, backend.bus_base, backend.size
        )
        self.assertIsNone(reason)
        self.assertEqual(offset, 0x1234)

    def test_at_lower_bound(self):
        backend = FakeBackend(bus_base=0x8000_0000, size=0x1000)
        offset, reason = translate_bus_address_to_backend_offset(
            0x8000_0000, backend.bus_base, backend.size
        )
        self.assertIsNone(reason)
        self.assertEqual(offset, 0)

    def test_at_upper_bound_excluded(self):
        backend = FakeBackend(bus_base=0x8000_0000, size=0x1000)
        offset, reason = translate_bus_address_to_backend_offset(
            0x8000_1000, backend.bus_base, backend.size
        )
        self.assertIsNone(offset)
        self.assertEqual(reason, "address_outside_backend_mapping")
        self.assertIn(reason, READ_FAULT_SKIP_REASONS)

    def test_below_base_rejected(self):
        backend = FakeBackend(bus_base=0x2000_0000, size=0x1000)
        offset, reason = translate_bus_address_to_backend_offset(
            0x1000_0000, backend.bus_base, backend.size
        )
        self.assertIsNone(offset)
        self.assertEqual(reason, "address_outside_backend_mapping")

    def test_above_top_rejected(self):
        backend = FakeBackend(bus_base=0x2000_0000, size=0x1000)
        offset, reason = translate_bus_address_to_backend_offset(
            0x2010_0000, backend.bus_base, backend.size
        )
        self.assertIsNone(offset)
        self.assertEqual(reason, "address_outside_backend_mapping")

    def test_no_base_returns_unsupported(self):
        offset, reason = translate_bus_address_to_backend_offset(
            0x1000, None, 0x1000
        )
        self.assertIsNone(offset)
        self.assertEqual(reason, "backend_unsupported")

    def test_no_size_returns_unsupported(self):
        offset, reason = translate_bus_address_to_backend_offset(
            0x1000, 0, None
        )
        self.assertIsNone(offset)
        self.assertEqual(reason, "backend_unsupported")


# ---------------------------------------------------------------------------
# pick_target_address_in_regions
# ---------------------------------------------------------------------------


class PickTargetAddressTest(unittest.TestCase):
    def test_picks_inside_single_region(self):
        regions = [(0x4000_0000, 0x4000_1000)]
        addr, reason = pick_target_address_in_regions(regions, fault_index=0, granularity=4)
        self.assertIsNone(reason)
        self.assertEqual(addr, 0x4000_0000)

    def test_advances_with_index(self):
        regions = [(0x4000_0000, 0x4000_1000)]
        addr, reason = pick_target_address_in_regions(regions, fault_index=4, granularity=4)
        self.assertIsNone(reason)
        self.assertEqual(addr, 0x4000_0010)

    def test_aligns_down(self):
        regions = [(0x4000_0000, 0x4000_1000)]
        addr, reason = pick_target_address_in_regions(regions, fault_index=1, granularity=8)
        self.assertIsNone(reason)
        self.assertEqual(addr & 7, 0)

    def test_spans_multiple_regions(self):
        regions = [
            (0x4000_0000, 0x4000_0010),
            (0x5000_0000, 0x5000_0100),
        ]
        addr, reason = pick_target_address_in_regions(regions, fault_index=8, granularity=2)
        self.assertIsNone(reason)
        self.assertGreaterEqual(addr, 0x5000_0000)
        self.assertLess(addr, 0x5000_0100)

    def test_no_regions_skips_with_reason(self):
        addr, reason = pick_target_address_in_regions([], fault_index=0, granularity=4)
        self.assertIsNone(addr)
        self.assertEqual(reason, "no_regions_configured")

    def test_zero_size_region_rejected(self):
        addr, reason = pick_target_address_in_regions(
            [(0x1000, 0x1000)], fault_index=0, granularity=4
        )
        self.assertIsNone(addr)
        self.assertEqual(reason, "no_regions_configured")


# ---------------------------------------------------------------------------
# In-range arms / out-of-range skips
# ---------------------------------------------------------------------------


class InRangeArmAndOutOfRangeSkipTest(unittest.TestCase):
    """End-to-end of the helper composition the harness uses to arm a
    read fault: pick a target address inside configured regions and
    translate it to a backend-relative offset.
    """

    def test_in_range_arm(self):
        backend = FakeBackend(bus_base=0x4000_0000, size=0x1_0000)
        regions = [(0x4000_0100, 0x4000_0200)]
        target, region_reason = pick_target_address_in_regions(
            regions, fault_index=8, granularity=4
        )
        self.assertIsNone(region_reason)
        self.assertGreaterEqual(target, regions[0][0])
        self.assertLess(target, regions[0][1])

        offset, addr_reason = translate_bus_address_to_backend_offset(
            target, backend.bus_base, backend.size
        )
        self.assertIsNone(addr_reason)
        self.assertEqual(offset, target - backend.bus_base)

    def test_out_of_range_skips_with_precise_reason(self):
        backend = FakeBackend(bus_base=0x4000_0000, size=0x1_0000)
        # Region entirely outside the backend mapping.
        regions = [(0x8000_0000, 0x8000_1000)]
        target, region_reason = pick_target_address_in_regions(
            regions, fault_index=0, granularity=4
        )
        self.assertIsNone(region_reason)

        offset, addr_reason = translate_bus_address_to_backend_offset(
            target, backend.bus_base, backend.size
        )
        self.assertIsNone(offset)
        self.assertEqual(addr_reason, "address_outside_backend_mapping")


# ---------------------------------------------------------------------------
# ReadFaultStats accounting
# ---------------------------------------------------------------------------


class ReadFaultStatsTest(unittest.TestCase):
    def test_counts_planned_armed_fired_skipped(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_planned()
        stats.record_armed()
        stats.record_fired()
        stats.record_skipped("address_outside_backend_mapping")
        stats.record_skipped("address_outside_backend_mapping")
        stats.record_skipped("probability_gate")
        d = stats.as_dict()
        self.assertEqual(d["planned"], 2)
        self.assertEqual(d["armed"], 1)
        self.assertEqual(d["fired"], 1)
        self.assertEqual(d["skipped"], 3)
        self.assertEqual(d["skip_reasons"]["address_outside_backend_mapping"], 2)
        self.assertEqual(d["skip_reasons"]["probability_gate"], 1)

    def test_merge(self):
        a = ReadFaultStats()
        b = ReadFaultStats()
        a.record_planned()
        a.record_armed()
        b.record_planned()
        b.record_planned()
        b.record_skipped("backend_unsupported")
        a.merge(b)
        d = a.as_dict()
        self.assertEqual(d["planned"], 3)
        self.assertEqual(d["armed"], 1)
        self.assertEqual(d["skipped"], 1)
        self.assertEqual(d["skip_reasons"]["backend_unsupported"], 1)

    def test_round_trip_dict(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_skipped("probability_gate")
        restored = ReadFaultStats.from_dict(stats.as_dict())
        self.assertEqual(restored.as_dict(), stats.as_dict())

    def test_warning_when_requested_but_nothing_armed(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_skipped("address_outside_backend_mapping")
        warning = read_fault_warning(stats, requested=True)
        self.assertIsNotNone(warning)
        self.assertIn("none armed", warning)

    def test_warning_when_requested_but_nothing_fired(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        warning = read_fault_warning(stats, requested=True)
        self.assertIsNotNone(warning)
        self.assertIn("none fired", warning)

    def test_no_warning_when_armed_and_fired(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        stats.record_fired()
        self.assertIsNone(read_fault_warning(stats, requested=True))

    def test_no_warning_when_not_requested(self):
        stats = ReadFaultStats()
        self.assertIsNone(read_fault_warning(stats, requested=False))

    def test_warning_when_requested_but_not_planned(self):
        stats = ReadFaultStats()
        warning = read_fault_warning(stats, requested=True)
        self.assertIsNotNone(warning)
        self.assertIn("no fault was planned", warning)


# ---------------------------------------------------------------------------
# CPU-path interceptability classification
# ---------------------------------------------------------------------------


class FakeReadFaultPeripheral(object):
    """Synthetic stand-in for a Renode peripheral that exposes the
    read-fault hook surface. Tests drive its counters directly to model
    different emulator behaviors without spinning up a real CPU.
    """

    def __init__(self, supports_cpu_intercept=True, has_fast_mapping=False):
        self.ReadFaultEnabled = False
        self.ReadFaultAddress = 0
        self.ReadFaultSeed = 0
        self.ReadFaultBitFlips = 1
        self.ReadFaultFired = False
        self.ReadFaultSkipCount = 0
        self.ReadFaultTotalReads = 0
        # Test-only hooks:
        self._supports_cpu_intercept = supports_cpu_intercept
        self._has_fast_mapping = has_fast_mapping
        self._fast_path_disabled = False

    def cpu_read_simulation(self, hits_target=False, n_reads=1):
        """Simulate the CPU performing read(s) through the mapping.

        If the backend has a fast mapping AND it is still enabled, those
        reads bypass the hook entirely (counter stays at 0). Otherwise
        the hook observes them, and may fire if any hit the target.
        """
        if self._has_fast_mapping and not self._fast_path_disabled:
            return  # bypassed, no hook activity
        if not self.ReadFaultEnabled:
            return
        self.ReadFaultTotalReads += int(n_reads)
        if hits_target:
            self.ReadFaultFired = True

    def DisableFastMapping(self):
        self._fast_path_disabled = True

    def host_side_read(self):
        """Monitor/host-side read that does not run through the CPU mapping.

        These do not increment the read-fault counters even if the hook is
        installed, because they are issued from the harness itself rather
        than executed by the CPU.
        """
        return 0


class ClassifyCpuPathOutcomeTest(unittest.TestCase):
    def test_not_armed(self):
        self.assertEqual(
            classify_cpu_path_outcome(armed=False, fired=False, total_reads=0),
            "not_armed",
        )
        self.assertEqual(
            classify_cpu_path_outcome(armed=False, fired=True, total_reads=10),
            "not_armed",
        )

    def test_fired_means_validated(self):
        self.assertEqual(
            classify_cpu_path_outcome(armed=True, fired=True, total_reads=5),
            "fired",
        )

    def test_armed_with_reads_but_not_target(self):
        self.assertEqual(
            classify_cpu_path_outcome(armed=True, fired=False, total_reads=42),
            "armed_but_not_triggered",
        )

    def test_zero_reads_means_non_interceptable(self):
        self.assertEqual(
            classify_cpu_path_outcome(armed=True, fired=False, total_reads=0),
            "cpu_path_not_interceptable",
        )

    def test_outcomes_are_in_known_set(self):
        for outcome in (
            "not_armed",
            "fired",
            "armed_but_not_triggered",
            "cpu_path_not_interceptable",
        ):
            self.assertIn(outcome, CPU_PATH_OUTCOMES)


class CpuPathBackendBehaviorTest(unittest.TestCase):
    """End-to-end with the synthetic peripheral, exercising arming +
    CPU-side simulation + classification.
    """

    def _arm(self, periph, address):
        periph.ReadFaultEnabled = True
        periph.ReadFaultAddress = address
        periph.ReadFaultFired = False
        periph.ReadFaultTotalReads = 0

    def _disarm_and_classify(self, periph):
        periph.ReadFaultEnabled = False
        return classify_cpu_path_outcome(
            armed=True,
            fired=bool(periph.ReadFaultFired),
            total_reads=int(periph.ReadFaultTotalReads),
        )

    def test_arming_succeeds_but_cpu_path_fire_unsupported(self):
        periph = FakeReadFaultPeripheral(has_fast_mapping=True)
        self._arm(periph, address=0x100)
        # CPU executes a read that hits the target via the fast path,
        # bypassing the hook.
        periph.cpu_read_simulation(hits_target=True, n_reads=1)
        outcome = self._disarm_and_classify(periph)
        self.assertEqual(outcome, "cpu_path_not_interceptable")

    def test_arming_succeeds_and_cpu_path_fire_supported(self):
        periph = FakeReadFaultPeripheral(has_fast_mapping=False)
        self._arm(periph, address=0x100)
        periph.cpu_read_simulation(hits_target=True, n_reads=1)
        outcome = self._disarm_and_classify(periph)
        self.assertEqual(outcome, "fired")

    def test_armed_cpu_reads_through_hook_without_target(self):
        periph = FakeReadFaultPeripheral(has_fast_mapping=False)
        self._arm(periph, address=0x100)
        # CPU reads happen but do not hit the targeted address.
        periph.cpu_read_simulation(hits_target=False, n_reads=8)
        outcome = self._disarm_and_classify(periph)
        # Hook is interceptable (we observed reads); just no fire.
        self.assertEqual(outcome, "armed_but_not_triggered")

    def test_host_side_read_does_not_count_as_cpu_path_success(self):
        periph = FakeReadFaultPeripheral(has_fast_mapping=False)
        self._arm(periph, address=0x100)
        # Monitor/host-side read: does not run through CPU, hook does
        # not see it.
        _ = periph.host_side_read()
        outcome = self._disarm_and_classify(periph)
        self.assertEqual(outcome, "cpu_path_not_interceptable")

    def test_remediation_disables_fast_mapping_then_succeeds(self):
        periph = FakeReadFaultPeripheral(has_fast_mapping=True)
        # First attempt: fast path bypasses hook.
        self._arm(periph, address=0x100)
        periph.cpu_read_simulation(hits_target=True, n_reads=1)
        first = self._disarm_and_classify(periph)
        self.assertEqual(first, "cpu_path_not_interceptable")
        # Remediation: disable fast mapping, retry.
        periph.DisableFastMapping()
        self._arm(periph, address=0x100)
        periph.cpu_read_simulation(hits_target=True, n_reads=1)
        second = self._disarm_and_classify(periph)
        self.assertEqual(second, "fired")


class ReadFaultStatsCpuPathTest(unittest.TestCase):
    def test_validated_counter_tracks_fired_and_armed_but_not_triggered(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        stats.record_cpu_path_validated()
        stats.record_fired()
        stats.record_planned()
        stats.record_armed()
        stats.record_cpu_path_validated()
        d = stats.as_dict()
        self.assertEqual(d["cpu_path_validated"], 2)
        self.assertEqual(d["cpu_path_unsupported"], 0)
        self.assertEqual(d["fired"], 1)

    def test_unsupported_counter_blocks_validated_coverage_warning(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        stats.record_cpu_path_unsupported()
        stats.record_skipped("cpu_path_not_interceptable")
        warning = cpu_path_capability_warning(stats)
        self.assertIsNotNone(warning)
        self.assertIn("non-interceptable", warning)

    def test_no_warning_when_validated(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        stats.record_cpu_path_validated()
        stats.record_fired()
        self.assertIsNone(cpu_path_capability_warning(stats))

    def test_no_warning_when_armed_zero(self):
        stats = ReadFaultStats()
        stats.record_planned()
        self.assertIsNone(cpu_path_capability_warning(stats))

    def test_round_trip_includes_cpu_path_counters(self):
        stats = ReadFaultStats()
        stats.record_planned()
        stats.record_armed()
        stats.record_cpu_path_unsupported()
        roundtrip = ReadFaultStats.from_dict(stats.as_dict())
        self.assertEqual(roundtrip.cpu_path_validated, 0)
        self.assertEqual(roundtrip.cpu_path_unsupported, 1)

    def test_skip_reason_in_known_set(self):
        self.assertIn("cpu_path_not_interceptable", READ_FAULT_SKIP_REASONS)


if __name__ == "__main__":
    unittest.main()
