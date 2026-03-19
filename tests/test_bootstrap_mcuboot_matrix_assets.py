#!/usr/bin/env python3
"""Regression coverage for bootstrap_mcuboot_matrix_assets.sh."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh"


class BootstrapMcubootMatrixAssetsScriptTests(unittest.TestCase):
    def test_script_has_valid_bash_syntax(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_script_builds_seccounter_assets(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("oss_mcuboot_head_move_nrf52_seccounter.elf", text)
        self.assertIn("zephyr_head_move_nrf52_seccounter_v1.bin", text)
        self.assertIn("zephyr_head_move_nrf52_seccounter_v2.bin", text)
        self.assertIn("CONFIG_MCUBOOT_HW_DOWNGRADE_PREVENTION=y", text)
        self.assertIn("--security-counter 1", text)
        self.assertIn("--security-counter 2", text)
        self.assertIn("results/oss_validation/build/bootstrap_mcuboot_matrix_assets", text)


if __name__ == "__main__":
    unittest.main()
