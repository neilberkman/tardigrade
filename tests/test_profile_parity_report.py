#!/usr/bin/env python3
"""Tests for the profile parity report helper."""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from profile_parity_report import build_report, render_table  # noqa: E402


class ProfileParityReportTests(unittest.TestCase):
    def _write_profile(self, root: Path, name: str, body: str) -> None:
        (root / "profiles" / name).write_text(textwrap.dedent(body), encoding="utf-8")

    def test_build_report_groups_profiles_by_target_and_features(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "profiles").mkdir()
            (repo / "docs").mkdir()

            self._write_profile(
                repo,
                "mcuboot_guard.yaml",
                """
                schema_version: 1
                name: mcuboot_guard
                bootloader:
                  elf: results/oss_validation/assets/oss_mcuboot_head.elf
                state_probe:
                  script: targets/mcuboot/probe.py
                invariant_providers:
                  - targets/mcuboot/invariants.py
                invariants:
                  - mcuboot_no_partial_magic
                fault_sweep:
                  fault_types: [power_loss, interrupted_erase]
                """,
            )
            self._write_profile(
                repo,
                "esp_idf_upgrade.yaml",
                """
                schema_version: 1
                name: esp_idf_ota_upgrade
                bootloader:
                  elf: examples/esp_idf_ota/esp_idf_ota.elf
                state_probe:
                  script: targets/esp_idf/probe.py
                semantic_assertions:
                  control:
                    semantic_state.target: esp_idf
                fault_sweep:
                  fault_types: [instruction_skip]
                skip_self_test: true
                """,
            )
            self._write_profile(
                repo,
                "rustboot_findings.yaml",
                """
                schema_version: 1
                name: rustboot_nrf52840_update
                bootloader:
                  elf: results/oss_validation/assets/rustboot_nrf52840.elf
                state_probe:
                  script: targets/rustboot/probe.py
                fault_sweep:
                  multi_fault:
                    enabled: true
                  phase2_fault:
                    enabled: true
                security_policy:
                  anti_rollback: true
                """,
            )

            (repo / "docs" / "oss_validation_profiles.json").write_text(
                json.dumps(
                    {
                        "profiles": [
                            {"name": "mcuboot_swap_current_guard"},
                            {"name": "rustboot_erase_guard"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = build_report(repo)

            mcuboot = report["targets"]["mcuboot"]
            self.assertEqual(mcuboot["target_class"], "upstream")
            self.assertTrue(mcuboot["claimable"])
            self.assertEqual(mcuboot["profiles_total"], 1)
            self.assertEqual(mcuboot["semantic_profiles"], 1)
            self.assertEqual(mcuboot["invariant_profiles"], 1)
            self.assertEqual(mcuboot["self_test_profiles"], 1)
            self.assertEqual(mcuboot["oss_validation_profiles"], 1)
            self.assertEqual(mcuboot["features"]["power_loss"], 1)
            self.assertEqual(mcuboot["features"]["interrupted_erase"], 1)

            esp_idf = report["targets"]["esp_idf"]
            self.assertEqual(esp_idf["target_class"], "reference")
            self.assertFalse(esp_idf["claimable"])
            self.assertEqual(esp_idf["profiles_total"], 1)
            self.assertEqual(esp_idf["self_test_profiles"], 0)
            self.assertEqual(esp_idf["skip_self_test_profiles"], 1)
            self.assertEqual(esp_idf["features"]["instruction_skip"], 1)

            rustboot = report["targets"]["rustboot"]
            self.assertEqual(rustboot["target_class"], "upstream")
            self.assertTrue(rustboot["claimable"])
            self.assertEqual(rustboot["profiles_total"], 1)
            self.assertEqual(rustboot["oss_validation_profiles"], 1)
            self.assertEqual(rustboot["features"]["multi_fault"], 1)
            self.assertEqual(rustboot["features"]["phase2_fault"], 1)
            self.assertEqual(rustboot["features"]["security_policy"], 1)

            self.assertEqual(report["totals"]["profiles_total"], 3)
            self.assertEqual(report["totals"]["oss_validation_profiles"], 2)
            self.assertEqual(report["claimable_totals"]["profiles_total"], 2)
            self.assertEqual(report["claimable_totals"]["semantic_profiles"], 2)
            self.assertEqual(report["claimable_totals"]["oss_validation_profiles"], 2)
            self.assertEqual(
                report["claimable_totals"]["features"]["instruction_skip"], 0
            )

    def test_render_table_includes_expected_columns(self) -> None:
        report = {
            "targets": {
                "mcuboot": {
                    "target_class": "upstream",
                    "claimable": True,
                    "profiles_total": 2,
                    "semantic_profiles": 1,
                    "invariant_profiles": 1,
                    "self_test_profiles": 1,
                    "skip_self_test_profiles": 1,
                    "oss_validation_profiles": 1,
                    "features": {
                        "power_loss": 2,
                        "interrupted_erase": 1,
                        "bit_corruption": 0,
                        "instruction_skip": 0,
                        "multi_fault": 1,
                        "phase2_fault": 0,
                        "security_policy": 0,
                    },
                }
            }
        }
        table = render_table(report)
        self.assertIn("target", table)
        self.assertIn("class", table)
        self.assertIn("claim", table)
        self.assertIn("mcuboot", table)
        self.assertIn("upstream", table)
        self.assertIn("multi", table)


if __name__ == "__main__":
    unittest.main()
