#!/usr/bin/env python3
"""Unit tests for metadata fault region classification and profile parsing."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import MetadataFaultRegion, classify_fault_region, FaultResult  # noqa: E402
from profile_loader import (  # noqa: E402
    ProfileConfig,
    ProfileError,
    _parse_metadata_fault_regions,
    load_profile,
)
from audit_bootloader import (  # noqa: E402
    enrich_results_with_fault_regions,
    compute_region_breakdown,
    summarize_runtime_sweep,
    result_is_brick,
    result_has_issues,
)


class TestMetadataFaultRegion(unittest.TestCase):
    """Tests for MetadataFaultRegion dataclass."""

    def test_contains_inside(self):
        r = MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000)
        self.assertTrue(r.contains(0xE0000))
        self.assertTrue(r.contains(0xE0500))
        self.assertTrue(r.contains(0xE0FFF))

    def test_contains_outside(self):
        r = MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000)
        self.assertFalse(r.contains(0xDFFFF))
        self.assertFalse(r.contains(0xE1000))  # end is exclusive
        self.assertFalse(r.contains(0xF0000))

    def test_contains_at_boundary(self):
        r = MetadataFaultRegion(name="header", start=0x10000, end=0x10100)
        self.assertTrue(r.contains(0x10000))   # start is inclusive
        self.assertFalse(r.contains(0x10100))  # end is exclusive


class TestClassifyFaultRegion(unittest.TestCase):
    """Tests for classify_fault_region function."""

    def setUp(self):
        self.regions = [
            MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000),
            MetadataFaultRegion(name="header", start=0x10000, end=0x10100),
        ]

    def test_empty_regions_returns_none(self):
        self.assertIsNone(classify_fault_region(0x50000, []))

    def test_hit_trailer(self):
        self.assertEqual(
            classify_fault_region(0xE0500, self.regions),
            "metadata:trailer",
        )

    def test_hit_header(self):
        self.assertEqual(
            classify_fault_region(0x10050, self.regions),
            "metadata:header",
        )

    def test_miss_returns_data(self):
        self.assertEqual(classify_fault_region(0x50000, self.regions), "data")

    def test_address_zero(self):
        self.assertEqual(classify_fault_region(0, self.regions), "data")

    def test_single_region(self):
        regions = [MetadataFaultRegion(name="status", start=0x100, end=0x200)]
        self.assertEqual(classify_fault_region(0x150, regions), "metadata:status")
        self.assertEqual(classify_fault_region(0x50, regions), "data")

    def test_first_matching_region_wins(self):
        """If regions overlap, the first match wins."""
        regions = [
            MetadataFaultRegion(name="first", start=0x100, end=0x300),
            MetadataFaultRegion(name="second", start=0x200, end=0x400),
        ]
        self.assertEqual(classify_fault_region(0x250, regions), "metadata:first")


class TestFaultResultRegionField(unittest.TestCase):
    """Tests for fault_region field on FaultResult."""

    def test_default_none(self):
        r = FaultResult(
            fault_at=1, boot_outcome="success", boot_slot="exec",
            nvm_state={}, raw_log="",
        )
        self.assertIsNone(r.fault_region)

    def test_set_region(self):
        r = FaultResult(
            fault_at=1, boot_outcome="success", boot_slot="exec",
            nvm_state={}, raw_log="", fault_region="metadata:trailer",
        )
        self.assertEqual(r.fault_region, "metadata:trailer")


class TestParseMetadataFaultRegions(unittest.TestCase):
    """Tests for _parse_metadata_fault_regions profile parser."""

    def test_none_returns_empty(self):
        self.assertEqual(_parse_metadata_fault_regions(None), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(_parse_metadata_fault_regions([]), [])

    def test_valid_regions(self):
        raw = [
            {"name": "trailer", "start": 0xE0000, "end": 0xE1000},
            {"name": "header", "start": "0x10000", "end": "0x10100"},
        ]
        regions = _parse_metadata_fault_regions(raw)
        self.assertEqual(len(regions), 2)
        self.assertEqual(regions[0].name, "trailer")
        self.assertEqual(regions[0].start, 0xE0000)
        self.assertEqual(regions[0].end, 0xE1000)
        self.assertEqual(regions[1].name, "header")
        self.assertEqual(regions[1].start, 0x10000)
        self.assertEqual(regions[1].end, 0x10100)

    def test_not_list_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions("not a list")

    def test_entry_not_dict_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions(["not a dict"])

    def test_missing_name_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"start": 0, "end": 1}])

    def test_empty_name_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"name": "", "start": 0, "end": 1}])

    def test_duplicate_name_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([
                {"name": "trailer", "start": 0, "end": 1},
                {"name": "trailer", "start": 2, "end": 3},
            ])

    def test_missing_start_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"name": "x", "end": 1}])

    def test_missing_end_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"name": "x", "start": 0}])

    def test_end_lte_start_raises(self):
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"name": "x", "start": 0x100, "end": 0x100}])
        with self.assertRaises(ProfileError):
            _parse_metadata_fault_regions([{"name": "x", "start": 0x200, "end": 0x100}])

    def test_hex_string_addresses(self):
        regions = _parse_metadata_fault_regions([
            {"name": "test", "start": "0xFF00", "end": "0xFFFF"},
        ])
        self.assertEqual(regions[0].start, 0xFF00)
        self.assertEqual(regions[0].end, 0xFFFF)


class TestProfileLoadMetadataFaultRegions(unittest.TestCase):
    """Test metadata_fault_regions in full profile loading."""

    def _write_profile(self, tempdir, body):
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_profile_without_regions(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: no_regions
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
            self.assertEqual(profile.metadata_fault_regions, [])

    def test_profile_with_regions(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: with_regions
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
                metadata_fault_regions:
                    - name: trailer
                      start: 0x3F000
                      end: 0x40000
                    - name: header
                      start: 0x0
                      end: 0x100
            """)
            profile = load_profile(path)
            self.assertEqual(len(profile.metadata_fault_regions), 2)
            self.assertEqual(profile.metadata_fault_regions[0].name, "trailer")
            self.assertEqual(profile.metadata_fault_regions[0].start, 0x3F000)
            self.assertEqual(profile.metadata_fault_regions[1].name, "header")

    def test_robot_vars_include_regions(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: robot_vars_test
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
                metadata_fault_regions:
                    - name: trailer
                      start: 0xE0000
                      end: 0xE1000
            """)
            profile = load_profile(path)
            robot_vars = profile.robot_vars(tempdir)
            region_vars = [v for v in robot_vars if "METADATA_FAULT_REGIONS" in v]
            self.assertEqual(len(region_vars), 1)
            self.assertIn("trailer,0xE0000,0xE1000", region_vars[0])

    def test_robot_vars_absent_when_no_regions(self):
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            elf = tempdir / "boot.elf"
            elf.write_bytes(b"\x00")
            path = self._write_profile(tempdir, f"""
                schema_version: 1
                name: no_robot_vars
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
            robot_vars = profile.robot_vars(tempdir)
            region_vars = [v for v in robot_vars if "METADATA_FAULT_REGIONS" in v]
            self.assertEqual(len(region_vars), 0)


class TestEnrichResultsWithFaultRegions(unittest.TestCase):
    """Tests for enrich_results_with_fault_regions."""

    def setUp(self):
        self.regions = [
            MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000),
            MetadataFaultRegion(name="header", start=0x10000, end=0x10100),
        ]

    def test_enriches_results(self):
        results = [
            {"fault_at": 1, "fault_address": "0x000E0500", "fault_injected": True},
            {"fault_at": 2, "fault_address": "0x00050000", "fault_injected": True},
            {"fault_at": 3, "fault_address": "0x00010050", "fault_injected": True},
        ]
        enrich_results_with_fault_regions(results, self.regions)
        self.assertEqual(results[0]["fault_region"], "metadata:trailer")
        self.assertEqual(results[1]["fault_region"], "data")
        self.assertEqual(results[2]["fault_region"], "metadata:header")

    def test_skips_control_results(self):
        results = [
            {"fault_at": 1, "fault_address": "0x000E0500", "is_control": True},
        ]
        enrich_results_with_fault_regions(results, self.regions)
        self.assertNotIn("fault_region", results[0])

    def test_noop_with_empty_regions(self):
        results = [
            {"fault_at": 1, "fault_address": "0x000E0500", "fault_injected": True},
        ]
        enrich_results_with_fault_regions(results, [])
        self.assertNotIn("fault_region", results[0])

    def test_handles_int_address(self):
        results = [
            {"fault_at": 1, "fault_address": 0xE0500, "fault_injected": True},
        ]
        enrich_results_with_fault_regions(results, self.regions)
        self.assertEqual(results[0]["fault_region"], "metadata:trailer")


class TestComputeRegionBreakdown(unittest.TestCase):
    """Tests for compute_region_breakdown."""

    def test_breakdown_counts(self):
        results = [
            # metadata:trailer, brick
            {"fault_at": 1, "fault_region": "metadata:trailer",
             "fault_injected": True, "boot_outcome": "no_boot", "boot_slot": None},
            # metadata:trailer, success
            {"fault_at": 2, "fault_region": "metadata:trailer",
             "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
            # data, success
            {"fault_at": 3, "fault_region": "data",
             "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
            # data, wrong_image (issue but not brick)
            {"fault_at": 4, "fault_region": "data",
             "fault_injected": True, "boot_outcome": "wrong_image", "boot_slot": "exec"},
        ]
        breakdown = compute_region_breakdown(results, "success")
        self.assertEqual(breakdown["metadata:trailer"]["total"], 2)
        self.assertEqual(breakdown["metadata:trailer"]["bricks"], 1)
        self.assertEqual(breakdown["metadata:trailer"]["issues"], 1)
        self.assertEqual(breakdown["metadata:trailer"]["recoveries"], 1)
        self.assertEqual(breakdown["data"]["total"], 2)
        self.assertEqual(breakdown["data"]["bricks"], 0)
        self.assertEqual(breakdown["data"]["issues"], 1)
        self.assertEqual(breakdown["data"]["recoveries"], 1)

    def test_skips_control_and_unfired(self):
        results = [
            {"fault_at": 1, "fault_region": "data", "is_control": True,
             "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
            {"fault_at": 2, "fault_region": "data", "fault_injected": False,
             "boot_outcome": "success", "boot_slot": "exec"},
        ]
        breakdown = compute_region_breakdown(results, "success")
        self.assertEqual(breakdown, {})

    def test_skips_none_region(self):
        results = [
            {"fault_at": 1, "fault_region": None, "fault_injected": True,
             "boot_outcome": "success", "boot_slot": "exec"},
        ]
        breakdown = compute_region_breakdown(results, "success")
        self.assertEqual(breakdown, {})

    def test_empty_results(self):
        self.assertEqual(compute_region_breakdown([], "success"), {})


class TestSummarizeWithRegions(unittest.TestCase):
    """Test that summarize_runtime_sweep includes region_breakdown."""

    def test_summary_includes_region_breakdown(self):
        regions = [
            MetadataFaultRegion(name="trailer", start=0xE0000, end=0xE1000),
        ]
        results = [
            {"fault_at": 1, "fault_address": "0x000E0500",
             "fault_injected": True, "boot_outcome": "no_boot", "boot_slot": None},
            {"fault_at": 2, "fault_address": "0x00050000",
             "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
        ]
        summary = summarize_runtime_sweep(
            results, total_writes=100, metadata_regions=regions
        )
        self.assertIn("region_breakdown", summary)
        self.assertIn("metadata:trailer", summary["region_breakdown"])
        self.assertIn("data", summary["region_breakdown"])
        self.assertEqual(summary["region_breakdown"]["metadata:trailer"]["bricks"], 1)
        self.assertEqual(summary["region_breakdown"]["data"]["bricks"], 0)

    def test_summary_omits_breakdown_when_no_regions(self):
        results = [
            {"fault_at": 1, "fault_address": "0x00050000",
             "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertNotIn("region_breakdown", summary)

    def test_summary_uses_profile_regions(self):
        """If metadata_regions not passed, falls back to profile."""
        regions = [
            MetadataFaultRegion(name="status", start=0x1000, end=0x2000),
        ]
        # Build a minimal but structurally valid fake profile.
        from profile_loader import MemoryConfig, SlotConfig, SuccessCriteria
        from profile_loader import FaultSweepConfig, StateFuzzerConfig, ExpectConfig
        fake = type("FP", (), {
            "metadata_fault_regions": regions,
            "expect": ExpectConfig(),
            "memory": MemoryConfig(
                sram_start=0x20000000, sram_end=0x20010000,
                write_granularity=4,
                slots={"exec": SlotConfig(base=0x0, size=0x40000)},
            ),
        })()
        results = [
            {"fault_at": 1, "fault_address": "0x00001500",
             "fault_injected": True, "boot_outcome": "no_boot", "boot_slot": None},
        ]
        summary = summarize_runtime_sweep(
            results, total_writes=100, profile=fake
        )
        self.assertIn("region_breakdown", summary)
        self.assertEqual(
            summary["region_breakdown"]["metadata:status"]["bricks"], 1
        )


class TestSummarySkipReasons(unittest.TestCase):
    """Test that summarize_runtime_sweep surfaces skip_reason counts."""

    def test_skip_reasons_populated(self):
        results = [
            {"fault_at": 1, "fault_injected": True,
             "boot_outcome": "success", "boot_slot": "exec"},
            {"fault_at": 2, "fault_injected": False,
             "boot_outcome": "skipped", "boot_slot": None,
             "skip_reason": "fast_path_no_read_intercept"},
            {"fault_at": 3, "fault_injected": False,
             "boot_outcome": "skipped", "boot_slot": None,
             "skip_reason": "fast_path_no_read_intercept"},
            {"fault_at": 4, "fault_injected": False,
             "boot_outcome": "skipped", "boot_slot": None,
             "skip_reason": "probability_gate"},
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertEqual(summary["discarded_no_fault_fired"], 3)
        self.assertIn("skip_reasons", summary)
        self.assertEqual(
            summary["skip_reasons"]["fast_path_no_read_intercept"], 2
        )
        self.assertEqual(summary["skip_reasons"]["probability_gate"], 1)

    def test_skip_reasons_absent_when_all_injected(self):
        results = [
            {"fault_at": 1, "fault_injected": True,
             "boot_outcome": "success", "boot_slot": "exec"},
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertNotIn("skip_reasons", summary)

    def test_skip_reasons_unknown_when_no_reason_field(self):
        results = [
            {"fault_at": 1, "fault_injected": False,
             "boot_outcome": "skipped", "boot_slot": None},
        ]
        summary = summarize_runtime_sweep(results, total_writes=100)
        self.assertIn("skip_reasons", summary)
        self.assertEqual(summary["skip_reasons"]["unknown"], 1)


if __name__ == "__main__":
    unittest.main()
