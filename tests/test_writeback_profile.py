#!/usr/bin/env python3
"""Unit tests for writeback durability model profile configuration."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, WritebackConfig, load_profile


class WritebackProfileParsingTest(unittest.TestCase):
    """Profile YAML parsing of durability_model and writeback block."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_writeback
                description: test writeback durability model
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 8
                  slots:
                    exec: {{ base: 0x10000000, size: 0x38000 }}
                    staging: {{ base: 0x10038000, size: 0x38000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_writeback_config_defaults(self):
        """durability_model: writeback with no options produces correct defaults."""
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      evaluation_mode: execute
                      durability_model: writeback
                """),
            )
            profile = load_profile(path)
            self.assertEqual(profile.fault_sweep.durability_model, "writeback")
            wb = profile.fault_sweep.writeback
            self.assertIsNotNone(wb)
            self.assertEqual(wb.buffer_capacity, "auto")
            self.assertEqual(wb.domains, "auto")
            self.assertEqual(wb.barriers, [])
            self.assertFalse(wb.erase_flushes_domain)

    def test_writeback_requires_execute_evaluation(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      evaluation_mode: state
                      durability_model: writeback
                """),
            )
            with self.assertRaisesRegex(ProfileError, "writeback.*evaluation_mode.*execute"):
                load_profile(path)

    def test_writeback_config_rejects_custom_domains(self):
        """Custom domains are rejected until per-region buffering is implemented."""
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      evaluation_mode: execute
                      durability_model: writeback
                      writeback:
                        buffer_capacity: 4
                        domains: [slot_data, slot_trailer]
                        barriers:
                          - {type: erase, address: 0x10038000}
                        erase_flushes_domain: true
                """),
            )
            with self.assertRaisesRegex(ProfileError, "custom domains are not supported"):
                load_profile(path)

    def test_writeback_config_explicit_options(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    fault_sweep:
                      evaluation_mode: execute
                      durability_model: writeback
                      writeback:
                        buffer_capacity: 4
                        barriers:
                          - {type: erase, address: 0x10038000}
                        erase_flushes_domain: true
                """),
            )
            profile = load_profile(path)
            wb = profile.fault_sweep.writeback
            self.assertEqual(wb.buffer_capacity, 4)
            self.assertEqual(wb.domains, "auto")
            self.assertEqual(len(wb.barriers), 1)
            self.assertEqual(wb.barriers[0]["type"], "erase")
            self.assertEqual(wb.barriers[0]["address"], 0x10038000)
            self.assertTrue(wb.erase_flushes_domain)

    def test_direct_model_default(self):
        """No durability_model in profile -> direct model, writeback is None."""
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            self.assertEqual(profile.fault_sweep.durability_model, "direct")
            self.assertIsNone(profile.fault_sweep.writeback)


if __name__ == "__main__":
    unittest.main()
