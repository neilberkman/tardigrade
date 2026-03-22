#!/usr/bin/env python3
"""Regression coverage for the nRF52 Renode platform stubs."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NRF52PlatformTests(unittest.TestCase):
    def test_nrf52_platforms_seed_uicr_words_needed_by_systeminit(self) -> None:
        for relpath in (
            "platforms/cortex_m4_flash.repl",
            "platforms/cortex_m4_flash_fast.repl",
        ):
            with self.subTest(platform=relpath):
                text = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn("WriteDoubleWord 0x10001200 0x12", text)
                self.assertIn("WriteDoubleWord 0x10001204 0x12", text)
                self.assertIn("SystemInit programs them to 0x12", text)


if __name__ == "__main__":
    unittest.main()
