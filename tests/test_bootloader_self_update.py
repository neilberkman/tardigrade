#!/usr/bin/env python3
"""Unit tests for bootloader self-update fault injection features."""

from __future__ import annotations

import struct
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import (  # noqa: E402
    BootloaderRegionConfig,
    MetadataFaultRegion,
    classify_fault_region,
    validate_bootloader_vector_table,
)
from profile_loader import (  # noqa: E402
    ProfileConfig,
    ProfileError,
    _parse_bootloader_region,
    load_profile,
)
from write_trace_heuristic import classify_trace, summarize_classification  # noqa: E402


# ---------------------------------------------------------------------------
# BootloaderRegionConfig
# ---------------------------------------------------------------------------


class TestBootloaderRegionConfig(unittest.TestCase):
    """Tests for BootloaderRegionConfig dataclass."""

    def test_end_property(self):
        r = BootloaderRegionConfig(base=0x0, size=0x10000)
        self.assertEqual(r.end, 0x10000)

    def test_contains_inside(self):
        r = BootloaderRegionConfig(base=0x0, size=0x10000)
        self.assertTrue(r.contains(0x0))
        self.assertTrue(r.contains(0x5000))
        self.assertTrue(r.contains(0xFFFF))

    def test_contains_outside(self):
        r = BootloaderRegionConfig(base=0x0, size=0x10000)
        self.assertFalse(r.contains(0x10000))  # end is exclusive
        self.assertFalse(r.contains(0x20000))

    def test_contains_nonzero_base(self):
        r = BootloaderRegionConfig(base=0x08000000, size=0x4000)
        self.assertTrue(r.contains(0x08000000))
        self.assertTrue(r.contains(0x08003FFF))
        self.assertFalse(r.contains(0x08004000))
        self.assertFalse(r.contains(0x07FFFFFF))


# ---------------------------------------------------------------------------
# validate_bootloader_vector_table
# ---------------------------------------------------------------------------


class TestValidateBootloaderVectorTable(unittest.TestCase):
    """Tests for bootloader integrity vector table validation."""

    def _make_vector_table(self, sp, reset_vector):
        """Build 8 bytes: SP (little-endian u32) + reset vector (LE u32)."""
        return struct.pack("<II", sp, reset_vector)

    def test_valid_vector_table(self):
        data = self._make_vector_table(0x20004000, 0x00000101)
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertTrue(valid)
        self.assertEqual(reason, "ok")

    def test_sp_outside_sram(self):
        # SP points to flash, not SRAM
        data = self._make_vector_table(0x08000000, 0x00000101)
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        self.assertIn("initial SP", reason)
        self.assertIn("not in SRAM", reason)

    def test_reset_vector_outside_bootloader(self):
        # Reset vector points beyond bootloader region
        data = self._make_vector_table(0x20004000, 0x00020000)
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        self.assertIn("reset vector", reason)
        self.assertIn("not in bootloader region", reason)

    def test_region_too_small(self):
        valid, reason = validate_bootloader_vector_table(
            b"\x00\x00\x00", region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        self.assertIn("region too small", reason)

    def test_custom_sram_range(self):
        data = self._make_vector_table(0x40001000, 0x00000101)
        # Default SRAM range doesn't include 0x4xxxxxxx
        valid, _ = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)

        # But with custom SRAM range it passes
        valid, reason = validate_bootloader_vector_table(
            data,
            region_base=0x0,
            region_size=0x10000,
            sram_start=0x40000000,
            sram_end=0x40010000,
        )
        self.assertTrue(valid)

    def test_initial_sp_at_sram_end_is_valid(self):
        data = self._make_vector_table(0x20010000, 0x00000101)
        valid, reason = validate_bootloader_vector_table(
            data,
            region_base=0x0,
            region_size=0x10000,
            sram_start=0x20000000,
            sram_end=0x20010000,
        )
        self.assertTrue(valid)
        self.assertEqual(reason, "ok")

    def test_even_reset_vector_is_rejected(self):
        data = self._make_vector_table(0x20004000, 0x00000100)
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        self.assertIn("Thumb bit", reason)

    def test_erased_flash_detected(self):
        """Erased flash (all 0xFF) should fail validation."""
        data = b"\xFF" * 8
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        # 0xFFFFFFFF is not a valid SRAM address in the default range

    def test_zeroed_flash_detected(self):
        """Zeroed flash (all 0x00) should fail validation."""
        data = b"\x00" * 8
        valid, reason = validate_bootloader_vector_table(
            data, region_base=0x0, region_size=0x10000
        )
        self.assertFalse(valid)
        # SP=0x00000000 is not in SRAM range 0x20000000-0x30000000


# ---------------------------------------------------------------------------
# classify_fault_region with bootloader_region
# ---------------------------------------------------------------------------


class TestClassifyFaultRegionWithBootloaderRegion(unittest.TestCase):
    """Tests for classify_fault_region with bootloader_region parameter."""

    def setUp(self):
        self.regions = [
            MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000),
        ]
        self.bl_region = BootloaderRegionConfig(base=0x0, size=0x10000)

    def test_bootloader_region_takes_priority(self):
        result = classify_fault_region(
            0x5000, self.regions, bootloader_region=self.bl_region
        )
        self.assertEqual(result, "bootloader_region")

    def test_metadata_still_classified(self):
        result = classify_fault_region(
            0xE0500, self.regions, bootloader_region=self.bl_region
        )
        self.assertEqual(result, "metadata:trailer")

    def test_data_classification(self):
        result = classify_fault_region(
            0x50000, self.regions, bootloader_region=self.bl_region
        )
        self.assertEqual(result, "data")

    def test_no_metadata_regions_with_bootloader(self):
        """bootloader_region alone enables classification."""
        result = classify_fault_region(
            0x5000, [], bootloader_region=self.bl_region
        )
        self.assertEqual(result, "bootloader_region")

    def test_outside_bootloader_no_metadata(self):
        result = classify_fault_region(
            0x50000, [], bootloader_region=self.bl_region
        )
        self.assertEqual(result, "data")

    def test_none_when_no_regions_at_all(self):
        result = classify_fault_region(0x5000, [])
        self.assertIsNone(result)

    def test_none_bootloader_region(self):
        """Backward compat: no bootloader_region falls back to old behavior."""
        result = classify_fault_region(0xE0500, self.regions)
        self.assertEqual(result, "metadata:trailer")


# ---------------------------------------------------------------------------
# Profile schema: bootloader_region parsing
# ---------------------------------------------------------------------------


class TestParseBootloaderRegion(unittest.TestCase):
    """Tests for _parse_bootloader_region."""

    def test_none_returns_none(self):
        self.assertIsNone(_parse_bootloader_region(None))

    def test_valid_region(self):
        raw = {"base": 0x0, "size": 0x10000}
        result = _parse_bootloader_region(raw)
        self.assertEqual(result.base, 0x0)
        self.assertEqual(result.size, 0x10000)

    def test_hex_strings(self):
        raw = {"base": "0x08000000", "size": "0x4000"}
        result = _parse_bootloader_region(raw)
        self.assertEqual(result.base, 0x08000000)
        self.assertEqual(result.size, 0x4000)

    def test_missing_base_raises(self):
        with self.assertRaises(ProfileError):
            _parse_bootloader_region({"size": 0x10000})

    def test_missing_size_raises(self):
        with self.assertRaises(ProfileError):
            _parse_bootloader_region({"base": 0x0})

    def test_zero_size_raises(self):
        with self.assertRaises(ProfileError):
            _parse_bootloader_region({"base": 0x0, "size": 0})

    def test_negative_size_raises(self):
        with self.assertRaises(ProfileError):
            _parse_bootloader_region({"base": 0x0, "size": -1})

    def test_not_dict_raises(self):
        with self.assertRaises(ProfileError):
            _parse_bootloader_region("not a dict")


class TestProfileLoadBootloaderRegion(unittest.TestCase):
    """Test bootloader_region in full profile loading."""

    def _write_profile(self, tempdir, body):
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_profile_without_bootloader_region(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: no_bl_region
                platform: platforms/test.repl
                bootloader:
                    elf: {elf}
                    entry: 0x0
                memory:
                    sram:
                        start: 0x20000000
                        end: 0x20010000
                    slots:
                        exec:
                            base: 0x0
                            size: 0x40000
            """)
            profile = load_profile(path)
            self.assertIsNone(profile.bootloader_region)

    def test_profile_with_bootloader_region(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: with_bl_region
                platform: platforms/test.repl
                bootloader:
                    elf: {elf}
                    entry: 0x0
                memory:
                    sram:
                        start: 0x20000000
                        end: 0x20010000
                    slots:
                        exec:
                            base: 0x10000
                            size: 0x40000
                bootloader_region:
                    base: 0x0
                    size: 0x10000
            """)
            profile = load_profile(path)
            self.assertIsNotNone(profile.bootloader_region)
            self.assertEqual(profile.bootloader_region.base, 0x0)
            self.assertEqual(profile.bootloader_region.size, 0x10000)

    def test_profile_bootloader_integrity_success_criteria(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: bl_integrity
                platform: platforms/test.repl
                bootloader:
                    elf: {elf}
                    entry: 0x0
                memory:
                    sram:
                        start: 0x20000000
                        end: 0x20010000
                    slots:
                        exec:
                            base: 0x10000
                            size: 0x40000
                bootloader_region:
                    base: 0x0
                    size: 0x10000
                success_criteria:
                    vtor_in_slot: exec
                    bootloader_integrity: true
            """)
            profile = load_profile(path)
            self.assertTrue(profile.success_criteria.bootloader_integrity)

    def test_profile_bootloader_integrity_defaults_false(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: no_bl_integrity
                platform: platforms/test.repl
                bootloader:
                    elf: {elf}
                    entry: 0x0
                memory:
                    sram:
                        start: 0x20000000
                        end: 0x20010000
                    slots:
                        exec:
                            base: 0x0
                            size: 0x40000
            """)
            profile = load_profile(path)
            self.assertFalse(profile.success_criteria.bootloader_integrity)


# ---------------------------------------------------------------------------
# Write-trace heuristic: Tier 0 classification
# ---------------------------------------------------------------------------


class TestWriteTraceHeuristicTier0(unittest.TestCase):
    """Tests for Tier 0 (bootloader region) in write-trace heuristic."""

    def test_bootloader_region_writes_always_selected(self):
        """Writes in bootloader region are Tier 0 -- all selected."""
        # Trace: 10 writes, first 5 in bootloader region, rest in bulk data
        trace = [
            (i + 1, i * 4) for i in range(5)  # offsets 0..16 -- in bootloader region
        ] + [
            (i + 6, 0x20000 + i * 4) for i in range(5)  # offsets in bulk data
        ]
        slot_ranges = {"exec": (0x10000, 0x50000)}
        # Bootloader region at 0x0 to 0x100 (bus addresses)
        bl_region = (0x0, 0x100)

        result = classify_trace(
            trace,
            slot_ranges,
            flash_base=0,
            page_size=4096,
            tier3_step=100,
            bootloader_region=bl_region,
        )
        # All 5 bootloader writes (fault points 0-4) must be in the result
        for fp in range(5):
            self.assertIn(fp, result)

    def test_no_bootloader_region_backward_compat(self):
        """Without bootloader_region, behavior is unchanged."""
        trace = [(i + 1, 0x20000 + i * 4) for i in range(100)]
        slot_ranges = {"exec": (0x10000, 0x50000)}

        result_without = classify_trace(
            trace, slot_ranges, flash_base=0, page_size=4096
        )
        result_with_none = classify_trace(
            trace, slot_ranges, flash_base=0, page_size=4096,
            bootloader_region=None,
        )
        self.assertEqual(result_without, result_with_none)

    def test_bootloader_region_with_flash_base_offset(self):
        """Bootloader region works with non-zero flash base."""
        flash_base = 0x08000000
        bl_base = 0x08000000
        bl_end = 0x08004000

        trace = [
            (1, 0x00000100),  # flash offset 0x100 -- bootloader region
            (2, 0x00010000),  # flash offset 0x10000 -- slot data
        ]
        slot_ranges = {"exec": (0x08010000, 0x08050000)}

        result = classify_trace(
            trace, slot_ranges, flash_base=flash_base, page_size=4096,
            bootloader_region=(bl_base, bl_end),
        )
        # Fault point 0 (bootloader write) should be selected
        self.assertIn(0, result)

    def test_summarize_includes_bootloader_writes(self):
        """summarize_classification includes bootloader_region_writes count."""
        trace = [
            (1, 0x50),      # in bootloader region
            (2, 0x100),     # in bootloader region
            (3, 0x20000),   # bulk data
        ]
        slot_ranges = {"exec": (0x10000, 0x50000)}
        bl_region = (0x0, 0x1000)

        fp = classify_trace(
            trace, slot_ranges, bootloader_region=bl_region
        )
        summary = summarize_classification(
            trace, fp, slot_ranges, bootloader_region=bl_region
        )
        self.assertEqual(summary["bootloader_region_writes"], 2)

    def test_summarize_without_bootloader_region(self):
        """summarize_classification omits bootloader_region_writes when not set."""
        trace = [(1, 0x20000)]
        slot_ranges = {"exec": (0x10000, 0x50000)}
        fp = classify_trace(trace, slot_ranges)
        summary = summarize_classification(trace, fp, slot_ranges)
        self.assertNotIn("bootloader_region_writes", summary)


# ---------------------------------------------------------------------------
# audit_bootloader: check_bootloader_integrity
# ---------------------------------------------------------------------------


class TestCheckBootloaderIntegrity(unittest.TestCase):
    """Tests for check_bootloader_integrity in audit_bootloader."""

    def test_valid_integrity(self):
        from audit_report import check_bootloader_integrity

        bl_region = BootloaderRegionConfig(base=0x0, size=0x10000)
        data = struct.pack("<II", 0x20004000, 0x00000101)
        data += b"\x00" * (0x10000 - 8)
        valid, reason = check_bootloader_integrity(
            data, bl_region, sram_start=0x20000000, sram_end=0x30000000
        )
        self.assertTrue(valid)
        self.assertEqual(reason, "ok")

    def test_corrupted_vector_table(self):
        from audit_report import check_bootloader_integrity

        bl_region = BootloaderRegionConfig(base=0x0, size=0x10000)
        # All 0xFF -- erased flash
        data = b"\xFF" * 0x10000
        valid, reason = check_bootloader_integrity(
            data, bl_region, sram_start=0x20000000, sram_end=0x30000000
        )
        self.assertFalse(valid)


# ---------------------------------------------------------------------------
# enrich_results_with_fault_regions (with bootloader_region)
# ---------------------------------------------------------------------------


class TestEnrichResultsWithBootloaderRegion(unittest.TestCase):
    """Tests for enrich_results_with_fault_regions with bootloader_region."""

    def test_bootloader_region_enrichment(self):
        from audit_report import enrich_results_with_fault_regions

        bl_region = BootloaderRegionConfig(base=0x0, size=0x10000)
        results = [
            {"fault_at": 1, "fault_address": "0x00005000", "fault_injected": True},
            {"fault_at": 2, "fault_address": "0x00050000", "fault_injected": True},
        ]
        enrich_results_with_fault_regions(results, [], bootloader_region=bl_region)
        self.assertEqual(results[0]["fault_region"], "bootloader_region")
        self.assertEqual(results[1]["fault_region"], "data")

    def test_no_enrichment_without_either(self):
        from audit_report import enrich_results_with_fault_regions

        results = [
            {"fault_at": 1, "fault_address": "0x00005000", "fault_injected": True},
        ]
        enrich_results_with_fault_regions(results, [])
        self.assertNotIn("fault_region", results[0])


if __name__ == "__main__":
    unittest.main()
