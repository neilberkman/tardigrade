#!/usr/bin/env python3
"""Unit tests for multi-phase update_sequence support."""

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, load_profile  # noqa: E402
from sweep import validate_runtime_fault_mode_compat  # noqa: E402


class UpdateSequenceSchemaTest(unittest.TestCase):
    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def _write_image(self, tempdir: Path, name: str, fill: int) -> Path:
        path = tempdir / name
        path.write_bytes(bytes([fill]) * 8192)
        return path

    def test_update_sequence_infers_fault_phase_start_images_and_robot_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            v1 = self._write_image(tempdir, "v1.bin", 0x11)
            v2 = self._write_image(tempdir, "v2.bin", 0x22)
            v3 = self._write_image(tempdir, "v3.bin", 0x33)
            hook = tempdir / "confirm.py"
            hook.write_text("pass\n", encoding="utf-8")

            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: multi_phase
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x2000 }}
                    staging: {{ base: 0x10002000, size: 0x2000 }}
                images:
                  exec: {v1}
                success_criteria:
                  vtor_in_slot: exec
                  image_hash: true
                  expected_image: staging
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  fault_types: [power_loss]
                update_sequence:
                  - name: initial_upgrade
                    images:
                      staging: {v2}
                    pre_boot_state:
                      - {{ address: 0x10003FF0, u32: 0x12345678 }}
                    success_criteria:
                      vtor_in_slot: exec
                      image_hash: true
                      expected_image: staging
                    boot_cycles: 2
                    boot_cycle_hook: {hook}
                    fault_injection: false
                  - name: second_upgrade_faulted
                    images:
                      staging: {v3}
                    pre_boot_state:
                      - {{ address: 0x10003FF0, u32: 0x87654321 }}
                    success_criteria:
                      vtor_in_slot: exec
                      image_hash: true
                      expected_image: staging
                    boot_cycles: 3
                    fault_injection: true
                    fault_types: [power_loss, bit_corruption]
                expect:
                  should_find_issues: false
                """,
            )

            profile = load_profile(profile_path)
            self.assertTrue(profile.has_update_sequence)
            self.assertEqual(profile.faulted_update_phase.name, "second_upgrade_faulted")
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertEqual(profile.fault_sweep.fault_types, ["power_loss", "bit_corruption"])
            self.assertEqual(profile.images["exec"], str(v2))
            self.assertEqual(profile.images["staging"], str(v3))

            robot_vars = profile.robot_vars(ROOT)
            seq_var = next(v for v in robot_vars if v.startswith("UPDATE_SEQUENCE_FILE:"))
            seq_path = Path(seq_var.split(":", 1)[1])
            payload = json.loads(seq_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["fault_phase_index"], 1)
            self.assertEqual(payload["phases"][0]["start_images"]["exec"], str(v1))
            self.assertEqual(payload["phases"][0]["start_images"]["staging"], str(v2))
            self.assertEqual(payload["phases"][1]["start_images"]["exec"], str(v2))
            self.assertEqual(payload["phases"][1]["start_images"]["staging"], str(v3))
            self.assertEqual(payload["phases"][1]["fault_types"], ["power_loss", "bit_corruption"])
            self.assertEqual(payload["phases"][0]["boot_cycle_hook"], str(hook))

    def test_update_sequence_requires_single_fault_phase(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            image = self._write_image(tempdir, "img.bin", 0x5A)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: bad_multi_phase
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x2000 }}
                    staging: {{ base: 0x10002000, size: 0x2000 }}
                images:
                  exec: {image}
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                update_sequence:
                  - name: phase_a
                    fault_injection: true
                  - name: phase_b
                    fault_injection: true
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)

    def test_update_sequence_fault_phase_must_be_last(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            image = self._write_image(tempdir, "img.bin", 0x6B)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: bad_order
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x2000 }}
                    staging: {{ base: 0x10002000, size: 0x2000 }}
                images:
                  exec: {image}
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                update_sequence:
                  - name: faulted
                    fault_injection: true
                  - name: trailing_clean
                    fault_injection: false
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)

    def test_clean_phase_requires_expected_image(self) -> None:
        """Clean phases feeding into subsequent phases must declare expected_image."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            v1 = self._write_image(tempdir, "v1.bin", 0x44)
            v2 = self._write_image(tempdir, "v2.bin", 0x55)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: missing_expected_image
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x2000 }}
                    staging: {{ base: 0x10002000, size: 0x2000 }}
                images:
                  exec: {v1}
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                update_sequence:
                  - name: initial_upgrade
                    images:
                      staging: {v2}
                    fault_injection: false
                  - name: faulted_upgrade
                    fault_injection: true
                """,
            )
            with self.assertRaises(ProfileError) as cm:
                load_profile(profile_path)
            self.assertIn("expected_image", str(cm.exception))

    def test_update_sequence_requires_execute_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            v1 = self._write_image(tempdir, "v1.bin", 0x44)
            v2 = self._write_image(tempdir, "v2.bin", 0x55)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: multi_phase_state_mode
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: faultFlash
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x2000 }}
                    staging: {{ base: 0x10002000, size: 0x2000 }}
                images:
                  exec: {v1}
                success_criteria:
                  vtor_in_slot: exec
                fault_sweep:
                  mode: runtime
                update_sequence:
                  - name: initial_upgrade
                    images:
                      staging: {v2}
                    success_criteria:
                      vtor_in_slot: exec
                      expected_image: staging
                    fault_injection: false
                  - name: faulted_upgrade
                    fault_injection: true
                """,
            )
            profile = load_profile(profile_path)
            with self.assertRaises(RuntimeError):
                validate_runtime_fault_mode_compat(profile, "state")


if __name__ == "__main__":
    unittest.main()
