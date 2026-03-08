#!/usr/bin/env python3
"""Unit tests for partial staging image generation and classification."""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from partial_staging import (  # noqa: E402
    PartialStagingConfig,
    PartialStagingResult,
    TruncationPoint,
    classify_partial_staging_outcome,
    generate_partial_image,
    generate_truncation_points,
    parse_partial_staging_config,
    summarize_partial_staging,
    write_partial_image_to_temp,
)


class TestTruncationPoints(unittest.TestCase):
    """Test heuristic truncation point generation."""

    def test_heuristic_includes_key_points(self):
        points = generate_truncation_points(
            image_size=0x10000,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        labels = {p.label: p.offset for p in points}

        # Must include empty (0) and complete (image_size).
        self.assertIn(0, offsets)
        self.assertIn(0x10000, offsets)

        # Must include structural points.
        self.assertIn("empty", labels)
        self.assertIn("one_byte", labels)
        self.assertIn("mid_header", labels)
        self.assertIn("end_header", labels)
        self.assertIn("half", labels)
        self.assertIn("complete", labels)
        self.assertIn("last_byte_missing", labels)

    def test_heuristic_points_sorted(self):
        points = generate_truncation_points(
            image_size=0x20000,
            strategy="heuristic",
            header_size=64,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        self.assertEqual(offsets, sorted(offsets))

    def test_heuristic_no_duplicates(self):
        points = generate_truncation_points(
            image_size=0x10000,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        self.assertEqual(len(offsets), len(set(offsets)))

    def test_exhaustive_includes_all_sector_boundaries(self):
        image_size = 0x4000  # 16KB
        sector_size = 0x1000  # 4KB
        points = generate_truncation_points(
            image_size=image_size,
            strategy="exhaustive",
            header_size=32,
            sector_size=sector_size,
        )
        offsets = [p.offset for p in points]
        # Every sector boundary should be present.
        for boundary in range(sector_size, image_size, sector_size):
            self.assertIn(boundary, offsets)

    def test_explicit_offsets(self):
        points = generate_truncation_points(
            image_size=0x10000,
            strategy="explicit",
            explicit_offsets=[0, 100, 5000, 0x10000],
        )
        offsets = [p.offset for p in points]
        self.assertEqual(offsets, [0, 100, 5000, 0x10000])

    def test_explicit_clamps_to_image_size(self):
        points = generate_truncation_points(
            image_size=1000,
            strategy="explicit",
            explicit_offsets=[500, 2000],
        )
        offsets = [p.offset for p in points]
        self.assertIn(500, offsets)
        self.assertIn(1000, offsets)  # clamped from 2000
        self.assertNotIn(2000, offsets)

    def test_empty_image_returns_empty(self):
        points = generate_truncation_points(image_size=0, strategy="heuristic")
        self.assertEqual(points, [])

    def test_tiny_image(self):
        points = generate_truncation_points(
            image_size=2,
            strategy="heuristic",
            header_size=0,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        self.assertIn(0, offsets)
        self.assertIn(2, offsets)

    def test_header_larger_than_image(self):
        """Header size exceeding image size should not crash."""
        points = generate_truncation_points(
            image_size=16,
            strategy="heuristic",
            header_size=64,
            sector_size=4096,
        )
        # Should still produce at least empty + complete.
        offsets = [p.offset for p in points]
        self.assertIn(0, offsets)
        self.assertIn(16, offsets)

    def test_trailer_points_included(self):
        points = generate_truncation_points(
            image_size=0x10000,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
            trailer_size=256,
        )
        labels = {p.label for p in points}
        self.assertIn("trailer_start", labels)
        self.assertIn("mid_trailer", labels)

    def test_no_trailer_omits_trailer_points(self):
        points = generate_truncation_points(
            image_size=0x10000,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
            trailer_size=0,
        )
        labels = {p.label for p in points}
        self.assertNotIn("trailer_start", labels)
        self.assertNotIn("mid_trailer", labels)


class TestGeneratePartialImage(unittest.TestCase):
    """Test partial image generation."""

    def test_full_truncation_returns_all_fill(self):
        original = bytes(range(256))
        result = generate_partial_image(original, 0, fill=0xFF)
        self.assertEqual(len(result), 256)
        self.assertTrue(all(b == 0xFF for b in result))

    def test_full_image_returns_original(self):
        original = bytes(range(256))
        result = generate_partial_image(original, 256, fill=0xFF)
        self.assertEqual(result, original)

    def test_beyond_size_returns_original(self):
        original = bytes(range(256))
        result = generate_partial_image(original, 1000, fill=0xFF)
        self.assertEqual(result, original)

    def test_partial_keeps_prefix(self):
        original = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = generate_partial_image(original, 4, fill=0xFF)
        self.assertEqual(len(result), 8)
        self.assertEqual(result[:4], b"\x01\x02\x03\x04")
        self.assertEqual(result[4:], b"\xFF\xFF\xFF\xFF")

    def test_zero_fill(self):
        original = b"\xAA" * 16
        result = generate_partial_image(original, 8, fill=0x00)
        self.assertEqual(result[:8], b"\xAA" * 8)
        self.assertEqual(result[8:], b"\x00" * 8)

    def test_single_byte_truncation(self):
        original = b"\xDE\xAD\xBE\xEF"
        result = generate_partial_image(original, 1, fill=0xFF)
        self.assertEqual(result, b"\xDE\xFF\xFF\xFF")


class TestWritePartialImageToTemp(unittest.TestCase):
    """Test temp file writing."""

    def test_creates_file_with_correct_content(self):
        original = b"\x01\x02\x03\x04" * 64
        path = write_partial_image_to_temp(original, 128, fill=0xFF, label="test")
        try:
            self.assertTrue(os.path.exists(path))
            with open(path, "rb") as f:
                data = f.read()
            self.assertEqual(len(data), len(original))
            self.assertEqual(data[:128], original[:128])
            self.assertTrue(all(b == 0xFF for b in data[128:]))
        finally:
            os.unlink(path)


class TestClassifyOutcome(unittest.TestCase):
    """Test outcome classification for partial staging results."""

    def test_complete_image_success(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="staging",
            truncation_offset=1000,
            image_size=1000,
        )
        self.assertEqual(result, "complete_image_ok")

    def test_complete_image_brick(self):
        result = classify_partial_staging_outcome(
            boot_outcome="no_boot",
            boot_slot=None,
            truncation_offset=1000,
            image_size=1000,
        )
        self.assertEqual(result, "brick")

    def test_partial_boots_exec_is_safe(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="exec",
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "safe_fallback")

    def test_partial_boots_primary_is_safe(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="primary",
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "safe_fallback")

    def test_partial_no_boot_is_brick(self):
        result = classify_partial_staging_outcome(
            boot_outcome="no_boot",
            boot_slot=None,
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "brick")

    def test_partial_hard_fault_is_brick(self):
        result = classify_partial_staging_outcome(
            boot_outcome="hard_fault",
            boot_slot=None,
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "brick")

    def test_partial_boots_staging_is_bad(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="staging",
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "partial_image_booted")

    def test_partial_boots_secondary_is_bad(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="secondary",
            truncation_offset=500,
            image_size=1000,
        )
        self.assertEqual(result, "partial_image_booted")

    def test_empty_slot_boots_exec_is_safe(self):
        result = classify_partial_staging_outcome(
            boot_outcome="success",
            boot_slot="exec",
            truncation_offset=0,
            image_size=1000,
        )
        self.assertEqual(result, "safe_fallback")

    def test_empty_slot_no_boot_is_brick(self):
        result = classify_partial_staging_outcome(
            boot_outcome="no_boot",
            boot_slot=None,
            truncation_offset=0,
            image_size=1000,
        )
        self.assertEqual(result, "brick")

    def test_wrong_pc_is_brick(self):
        result = classify_partial_staging_outcome(
            boot_outcome="wrong_pc",
            boot_slot=None,
            truncation_offset=100,
            image_size=1000,
        )
        self.assertEqual(result, "brick")

    def test_slot_a_names_all_safe(self):
        for name in ["exec", "primary", "slot_a", "slot0", "a"]:
            result = classify_partial_staging_outcome(
                boot_outcome="success",
                boot_slot=name,
                truncation_offset=500,
                image_size=1000,
            )
            self.assertEqual(result, "safe_fallback", msg="slot {} not safe".format(name))

    def test_slot_b_names_all_bad(self):
        for name in ["staging", "secondary", "slot_b", "slot1", "b"]:
            result = classify_partial_staging_outcome(
                boot_outcome="success",
                boot_slot=name,
                truncation_offset=500,
                image_size=1000,
            )
            self.assertEqual(
                result, "partial_image_booted", msg="slot {} not bad".format(name)
            )


class TestSummarize(unittest.TestCase):
    """Test partial staging summary computation."""

    def _make_result(self, offset, label, classification, outcome="success", slot=None):
        return PartialStagingResult(
            truncation_point=TruncationPoint(
                offset=offset, label=label, description="test"
            ),
            boot_outcome=outcome,
            boot_slot=slot,
            classification=classification,
        )

    def test_all_safe(self):
        results = [
            self._make_result(0, "empty", "safe_fallback"),
            self._make_result(500, "half", "safe_fallback"),
            self._make_result(1000, "complete", "complete_image_ok"),
        ]
        summary = summarize_partial_staging(results)
        self.assertEqual(summary["total_points"], 3)
        self.assertEqual(summary["safe_fallback"], 2)
        self.assertEqual(summary["complete_image_ok"], 1)
        self.assertEqual(summary["issue_count"], 0)
        self.assertEqual(summary["issues"], [])

    def test_mixed_results(self):
        results = [
            self._make_result(0, "empty", "brick", outcome="no_boot"),
            self._make_result(500, "half", "safe_fallback"),
            self._make_result(999, "near_end", "partial_image_booted", slot="staging"),
            self._make_result(1000, "complete", "complete_image_ok"),
        ]
        summary = summarize_partial_staging(results)
        self.assertEqual(summary["total_points"], 4)
        self.assertEqual(summary["brick"], 1)
        self.assertEqual(summary["partial_image_booted"], 1)
        self.assertEqual(summary["safe_fallback"], 1)
        self.assertEqual(summary["issue_count"], 2)
        self.assertEqual(len(summary["issues"]), 2)

    def test_empty_results(self):
        summary = summarize_partial_staging([])
        self.assertEqual(summary["total_points"], 0)
        self.assertEqual(summary["issue_count"], 0)

    def test_issue_rate(self):
        results = [
            self._make_result(0, "empty", "brick", outcome="no_boot"),
            self._make_result(500, "half", "brick", outcome="no_boot"),
            self._make_result(750, "three_q", "safe_fallback"),
            self._make_result(1000, "complete", "complete_image_ok"),
        ]
        summary = summarize_partial_staging(results)
        self.assertAlmostEqual(summary["issue_rate"], 0.5)


class TestParseConfig(unittest.TestCase):
    """Test YAML config parsing for partial_staging."""

    def test_minimal_config(self):
        raw = {
            "staging_slot": "staging",
            "fill_pattern": "0xFF",
            "header_size": 32,
        }
        images = {"staging": "path/to/staging.bin"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        config = parse_partial_staging_config(raw, images, slots)
        self.assertIsNotNone(config)
        self.assertEqual(config.staging_image_path, "path/to/staging.bin")
        self.assertEqual(config.fill_pattern, 0xFF)
        self.assertEqual(config.header_size, 32)
        self.assertEqual(config.truncation_points, "heuristic")

    def test_none_returns_none(self):
        config = parse_partial_staging_config(None, {}, {})
        self.assertIsNone(config)

    def test_unknown_slot_raises(self):
        raw = {"staging_slot": "nonexistent"}
        with self.assertRaises(ValueError):
            parse_partial_staging_config(raw, {}, {})

    def test_no_staging_image_raises(self):
        raw = {"staging_slot": "staging"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        with self.assertRaises(ValueError):
            parse_partial_staging_config(raw, {}, slots)

    def test_explicit_offsets(self):
        raw = {
            "staging_slot": "staging",
            "truncation_points": "explicit",
            "offsets": [0, 100, 5000],
        }
        images = {"staging": "staging.bin"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        config = parse_partial_staging_config(raw, images, slots)
        self.assertEqual(config.truncation_points, "explicit")
        self.assertEqual(config.explicit_offsets, [0, 100, 5000])

    def test_custom_staging_image(self):
        raw = {
            "staging_slot": "staging",
            "staging_image": "custom/image.bin",
        }
        images = {"staging": "default.bin"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        config = parse_partial_staging_config(raw, images, slots)
        self.assertEqual(config.staging_image_path, "custom/image.bin")

    def test_fill_pattern_zero(self):
        raw = {
            "staging_slot": "staging",
            "fill_pattern": "0x00",
        }
        images = {"staging": "staging.bin"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        config = parse_partial_staging_config(raw, images, slots)
        self.assertEqual(config.fill_pattern, 0x00)

    def test_invalid_fill_pattern_raises(self):
        raw = {
            "staging_slot": "staging",
            "fill_pattern": "0xAA",
        }
        images = {"staging": "staging.bin"}

        class MockSlot:
            base = 0x10000
            size = 0x38000

        slots = {"staging": MockSlot()}
        with self.assertRaises(ValueError):
            parse_partial_staging_config(raw, images, slots)


class TestTruncationPointAsDict(unittest.TestCase):
    """Test TruncationPoint serialization."""

    def test_as_dict(self):
        point = TruncationPoint(offset=0x100, label="test", description="A test point")
        d = point.as_dict
        self.assertEqual(d["offset"], 0x100)
        self.assertEqual(d["label"], "test")
        self.assertEqual(d["description"], "A test point")


class TestPartialStagingConfigValidation(unittest.TestCase):
    """Test PartialStagingConfig validation."""

    def test_invalid_fill_raises(self):
        with self.assertRaises(ValueError):
            PartialStagingConfig(
                staging_image_path="test.bin",
                staging_slot_name="staging",
                truncation_points="heuristic",
                fill_pattern=0xAA,
                header_size=32,
                sector_size=4096,
                trailer_size=0,
            )

    def test_negative_header_raises(self):
        with self.assertRaises(ValueError):
            PartialStagingConfig(
                staging_image_path="test.bin",
                staging_slot_name="staging",
                truncation_points="heuristic",
                fill_pattern=0xFF,
                header_size=-1,
                sector_size=4096,
                trailer_size=0,
            )

    def test_zero_sector_raises(self):
        with self.assertRaises(ValueError):
            PartialStagingConfig(
                staging_image_path="test.bin",
                staging_slot_name="staging",
                truncation_points="heuristic",
                fill_pattern=0xFF,
                header_size=32,
                sector_size=0,
                trailer_size=0,
            )

    def test_negative_trailer_raises(self):
        with self.assertRaises(ValueError):
            PartialStagingConfig(
                staging_image_path="test.bin",
                staging_slot_name="staging",
                truncation_points="heuristic",
                fill_pattern=0xFF,
                header_size=32,
                sector_size=4096,
                trailer_size=-1,
            )


class TestEdgeCases(unittest.TestCase):
    """Edge case tests for robustness."""

    def test_sector_equals_image_size(self):
        """When sector size equals image size, should not crash."""
        points = generate_truncation_points(
            image_size=4096,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        self.assertIn(0, offsets)
        self.assertIn(4096, offsets)

    def test_sector_larger_than_image(self):
        """When sector size exceeds image size, should not crash."""
        points = generate_truncation_points(
            image_size=1024,
            strategy="heuristic",
            header_size=32,
            sector_size=4096,
        )
        offsets = [p.offset for p in points]
        self.assertIn(0, offsets)
        self.assertIn(1024, offsets)

    def test_exhaustive_small_image(self):
        """Exhaustive on a tiny image should not produce too many points."""
        points = generate_truncation_points(
            image_size=8,
            strategy="exhaustive",
            header_size=0,
            sector_size=4,
        )
        # Should have sector boundary at 4, plus heuristic points.
        offsets = [p.offset for p in points]
        self.assertIn(4, offsets)

    def test_generate_partial_image_negative_offset(self):
        """Negative truncation offset should behave like zero."""
        original = b"\xAA\xBB\xCC\xDD"
        result = generate_partial_image(original, -1, fill=0xFF)
        self.assertEqual(result, b"\xFF\xFF\xFF\xFF")


class TestProfileIntegration(unittest.TestCase):
    """Test integration with profile loader."""

    def test_parse_from_profile_yaml(self):
        """Verify partial_staging config can be parsed from a profile-like dict."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")

        raw_yaml = textwrap.dedent("""
            staging_slot: staging
            truncation_points: heuristic
            fill_pattern: 0xFF
            header_size: 32
            sector_size: 4096
            trailer_size: 256
        """)
        raw = yaml.safe_load(raw_yaml)

        class MockSlot:
            base = 0x10000
            size = 0x38000

        config = parse_partial_staging_config(
            raw,
            images={"staging": "firmware.bin"},
            slots={"staging": MockSlot()},
        )
        self.assertIsNotNone(config)
        self.assertEqual(config.header_size, 32)
        self.assertEqual(config.trailer_size, 256)
        self.assertEqual(config.fill_pattern, 0xFF)
        self.assertEqual(config.truncation_points, "heuristic")


if __name__ == "__main__":
    unittest.main()
