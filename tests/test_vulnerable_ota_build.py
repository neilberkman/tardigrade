#!/usr/bin/env python3
"""Regression checks for the vulnerable OTA firmware link layout."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"
SOURCE = ROOT / "examples" / "vulnerable_ota" / "firmware.c"


class VulnerableOtaBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [tool for tool in ("arm-none-eabi-nm", "arm-none-eabi-readelf") if not shutil.which(tool)]
        if missing:
            raise unittest.SkipTest("missing ARM ELF tools: {}".format(", ".join(missing)))
        if not ELF.exists():
            raise unittest.SkipTest("firmware ELF fixture not present")

    def test_copy_routine_is_emitted_in_ramfunc_section(self) -> None:
        nm = subprocess.check_output(
            ["arm-none-eabi-nm", "-n", str(ELF)], text=True
        )
        symbols = {}
        for line in nm.splitlines():
            fields = line.split()
            if len(fields) == 3:
                symbols[fields[2]] = int(fields[0], 16)

        self.assertIn("copy_staging_to_active", symbols)
        self.assertGreaterEqual(symbols["copy_staging_to_active"], 0x20000000)
        self.assertLess(symbols["copy_staging_to_active"], 0x20020000)
        self.assertLess(symbols["_sramfunc"], symbols["_eramfunc"])

        sections = subprocess.check_output(
            ["arm-none-eabi-readelf", "-SW", str(ELF)], text=True
        )
        ramfunc = re.search(
            r"^\s*\[\s*\d+\]\s+\.ramfunc\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)",
            sections,
            re.MULTILINE,
        )
        self.assertIsNotNone(ramfunc)
        self.assertEqual(int(ramfunc.group(1), 16), 0x20000000)
        self.assertGreater(int(ramfunc.group(2), 16), 0)

    def test_copy_routine_is_protected_from_compiler_inlining(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            '__attribute__((noinline, section(".ramfunc")))',
            source,
        )


if __name__ == "__main__":
    unittest.main()
