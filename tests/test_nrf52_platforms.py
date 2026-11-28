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
                self.assertIn("ficr: Memory.ArrayMemory @ sysbus 0x10000000", text)
                self.assertIn("uicr: Memory.ArrayMemory @ sysbus 0x10001000", text)
                self.assertIn("clock: Memory.ArrayMemory @ sysbus 0x40000000", text)
                self.assertIn("wdt0: Memory.ArrayMemory @ sysbus 0x40010000", text)
                self.assertIn("WriteDoubleWord 0x10001200 0x12", text)
                self.assertIn("WriteDoubleWord 0x10001204 0x12", text)
                self.assertIn("SystemInit programs them to 0x12", text)

    def test_nrf52_nvmc_flushes_wen_writes_on_ready_reads_and_config_transitions(
        self,
    ) -> None:
        source = (ROOT / "peripherals" / "NRF52NVMC.cs").read_text(encoding="utf-8")
        self.assertIn("private void FlushWenWrites(bool keepWenOpen)", source)
        self.assertIn("private bool wenFlushedAnyInWindow;", source)
        self.assertIn(
            'Registers.Ready.Define(this, 1)\n'
            '                .WithFlag(0, FieldMode.Read, name: "READY",',
            source,
        )
        self.assertIn(
            "if(configValue == 1 && wenWriteOffsets.Count > 0)\n"
            "                        {\n"
            "                            FlushWenWrites(keepWenOpen: true);\n"
            "                        }",
            source,
        )
        self.assertIn(
            "if(oldConfig == 1)\n"
            "                    {\n"
            "                        if(val != 1)\n"
            "                        {\n"
            "                            FlushWenWrites(keepWenOpen: false);\n"
            "                        }\n"
            "                        else if(wenWriteOffsets.Count > 0)\n"
            "                        {\n"
            "                            FlushWenWrites(keepWenOpen: true);\n"
            "                        }\n"
            "                    }",
            source,
        )


if __name__ == "__main__":
    unittest.main()
