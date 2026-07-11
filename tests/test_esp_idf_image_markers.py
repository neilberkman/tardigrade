#!/usr/bin/env python3
"""Focused checks for ESP-IDF OTA fixture boot sentinels."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

import yaml

from examples.esp_idf_ota import gen_esp_idf_images as images


ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / "profiles"
FIXTURE_DIR = ROOT / "examples" / "esp_idf_ota"


def _thumb_mov_imm32(blob: bytes, offset: int) -> tuple[int, int]:
    """Decode the immediate and destination from this fixture's MOVW/MOVT."""
    hw1, hw2 = struct.unpack_from("<HH", blob, offset)
    imm4 = hw1 & 0xF
    i = (hw1 >> 10) & 1
    imm3 = (hw2 >> 12) & 0x7
    imm8 = hw2 & 0xFF
    rd = (hw2 >> 8) & 0xF
    return (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8, rd


class TestEspIdfImageMarkers(unittest.TestCase):
    def test_slot_sentinels_are_nonzero_and_distinct(self) -> None:
        self.assertNotEqual(images.SLOT0_MARKER, 0)
        self.assertNotEqual(images.SLOT1_MARKER, 0)
        self.assertNotEqual(images.SLOT0_MARKER, images.SLOT1_MARKER)
        self.assertEqual(
            images.SLOT_MARKERS,
            (images.SLOT0_MARKER, images.SLOT1_MARKER),
        )

    def test_firmware_writes_each_slot_sentinel(self) -> None:
        for slot_id, (slot_base, expected) in enumerate(
            (
                (images.SLOT0_BASE, images.SLOT0_MARKER),
                (images.SLOT1_BASE, images.SLOT1_MARKER),
            )
        ):
            with self.subTest(slot=slot_id):
                firmware = images.make_slot_firmware(slot_base, slot_id)
                low, low_rd = _thumb_mov_imm32(firmware, 0x48)
                high, high_rd = _thumb_mov_imm32(firmware, 0x4C)
                self.assertEqual((high << 16) | low, expected)
                self.assertEqual((low_rd, high_rd), (1, 1))
                self.assertEqual(firmware[0x50:0x52], struct.pack("<H", 0x6001))

    def test_tracked_slot_images_match_generator(self) -> None:
        for slot_id, slot_base in enumerate((images.SLOT0_BASE, images.SLOT1_BASE)):
            with self.subTest(slot=slot_id):
                expected = images.make_slot_firmware(slot_base, slot_id)
                actual = (FIXTURE_DIR / "slot{}.bin".format(slot_id)).read_bytes()
                self.assertEqual(actual, expected)

    def test_esp_profiles_use_sentinel_for_expected_slot(self) -> None:
        expected_by_slot = {
            "exec": images.SLOT0_MARKER,
            "staging": images.SLOT1_MARKER,
        }
        checked = 0
        for path in sorted(PROFILE_DIR.glob("esp_idf*.yaml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8"))
            criteria = profile.get("success_criteria", {})
            if criteria.get("marker_address") != images.MARKER_ADDR:
                continue
            slot = criteria.get("vtor_in_slot")
            with self.subTest(profile=path.name):
                self.assertIn(slot, expected_by_slot)
                self.assertEqual(criteria.get("marker_value"), expected_by_slot[slot])
            checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
