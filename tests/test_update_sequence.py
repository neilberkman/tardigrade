#!/usr/bin/env python3
"""Unit tests for multi-phase update_sequence support."""

from __future__ import annotations

import hashlib
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
            setup = tempdir / "phase_setup.resc"
            setup.write_text("# phase setup\n", encoding="utf-8")

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
                    setup_script: {setup}
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
            self.assertEqual(payload["phases"][0]["setup_script"], str(setup))
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

    def test_update_sequence_phase_can_disable_inherited_boot_cycle_hook(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            v1 = self._write_image(tempdir, "v1.bin", 0x11)
            v2 = self._write_image(tempdir, "v2.bin", 0x22)
            hook = tempdir / "confirm.py"
            hook.write_text("pass\n", encoding="utf-8")

            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: disable_phase_hook
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
                  expected_image: staging
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  boot_cycles: 3
                  boot_cycle_hook: {hook}
                  fault_types: [power_loss]
                update_sequence:
                  - name: clean_without_confirm
                    boot_cycle_hook:
                    images:
                      staging: {v2}
                    success_criteria:
                      vtor_in_slot: exec
                      expected_image: exec
                    fault_injection: false
                  - name: faulted
                    images:
                      staging: {v1}
                    success_criteria:
                      vtor_in_slot: exec
                      expected_image: staging
                    fault_injection: true
                expect:
                  should_find_issues: false
                """,
            )

            profile = load_profile(profile_path)
            payload = profile.update_sequence_runtime_payload(ROOT)
            assert payload is not None
            self.assertEqual(payload["phases"][0]["boot_cycle_hook"], "")
            self.assertEqual(payload["phases"][1]["boot_cycle_hook"], str(hook))

    def test_success_criteria_overrides_accept_fault_families(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            v1 = self._write_image(tempdir, "v1.bin", 0x11)
            v2 = self._write_image(tempdir, "v2.bin", 0x22)

            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: family_override_keys
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
                  staging: {v2}
                success_criteria:
                  vtor_in_slot: staging
                  image_hash: true
                  expected_image: staging
                success_criteria_overrides:
                  metadata_fault:
                    vtor_in_slot: any
                    image_hash: false
                  phase2_fault:
                    vtor_in_slot: staging
                    image_hash: false
                  hook_fault:
                    vtor_in_slot: any
                    image_hash: false
                fault_sweep:
                  mode: runtime
                  evaluation_mode: execute
                  boot_cycles: 3
                  boot_cycle_hook: {tempdir / "hook.py"}
                  fault_types: [power_loss]
                  phase2_fault:
                    enabled: true
                    fault_types: [power_loss]
                  hook_fault:
                    enabled: true
                    fault_types: [power_loss]
                  metadata_fault:
                    enabled: true
                    fault_types: [power_loss]
                update_sequence:
                  - name: clean
                    images:
                      staging: {v2}
                    success_criteria:
                      vtor_in_slot: staging
                      image_hash: true
                      expected_image: staging
                    fault_injection: false
                  - name: faulted
                    images:
                      staging: {v1}
                    success_criteria:
                      vtor_in_slot: staging
                      image_hash: true
                      expected_image: staging
                    fault_injection: true
                expect:
                  should_find_issues: false
                """,
            )
            (tempdir / "hook.py").write_text("pass\n", encoding="utf-8")

            profile = load_profile(profile_path)
            self.assertEqual(
                profile.success_criteria_overrides["metadata_fault"]["vtor_in_slot"],
                "any",
            )
            self.assertFalse(profile.success_criteria_overrides["metadata_fault"]["image_hash"])
            self.assertEqual(
                profile.success_criteria_overrides["phase2_fault"]["vtor_in_slot"],
                "staging",
            )
            self.assertFalse(profile.success_criteria_overrides["hook_fault"]["image_hash"])

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

    def test_mram_image_hash_digests_use_zero_fill_padding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            image = tempdir / "img.bin"
            image.write_bytes(b"\xA5" * 512)
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: mram_digest_padding
                platform: platforms/cortex_m4_flash_fast.repl
                flash_backend: mram
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x3000 }}
                    staging: {{ base: 0x10003000, size: 0x3000 }}
                images:
                  exec: {image}
                success_criteria:
                  vtor_in_slot: exec
                  image_hash: true
                  expected_image: exec
                fault_sweep:
                  mode: runtime
                """,
            )

            profile = load_profile(profile_path)
            digests = profile._compute_image_digests(ROOT, {"exec": str(image)})
            robot_vars = profile.robot_vars(ROOT)
            padded_size = 0x3000 - 4096
            raw = image.read_bytes()
            zero_padded = raw + (b"\x00" * (padded_size - len(raw)))
            ff_padded = raw + (b"\xFF" * (padded_size - len(raw)))
            zero_digest = hashlib.sha256(zero_padded).hexdigest()

            self.assertEqual(digests["exec"], zero_digest)
            self.assertNotEqual(digests["exec"], hashlib.sha256(ff_padded).hexdigest())
            self.assertIn(f"IMAGE_EXEC_SHA256:{zero_digest}", robot_vars)
            self.assertIn(f"EXPECTED_EXEC_SHA256:{zero_digest}", robot_vars)


if __name__ == "__main__":
    unittest.main()
