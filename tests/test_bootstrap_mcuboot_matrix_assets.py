#!/usr/bin/env python3
"""Regression coverage for bootstrap_mcuboot_matrix_assets.sh."""

from __future__ import annotations

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh"
ASSETS = ROOT / "results" / "oss_validation" / "assets"

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile  # noqa: E402


PR_DIFFERENTIAL_PROFILES = [
    "mcuboot_pr2205_scratch_broken.yaml",
    "mcuboot_pr2205_scratch_fixed.yaml",
    "mcuboot_pr2206_scratch_broken.yaml",
    "mcuboot_pr2206_scratch_fixed.yaml",
    "mcuboot_pr2206_scratch_geom_broken.yaml",
    "mcuboot_pr2206_scratch_geom_fixed.yaml",
    "mcuboot_pr2214_offset_broken.yaml",
    "mcuboot_pr2214_offset_fixed.yaml",
    "mcuboot_pr2214_offset_geom_broken.yaml",
    "mcuboot_pr2214_offset_geom_fixed.yaml",
]


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
        self.assertIn("CONFIG_MCUBOOT_DOWNGRADE_PREVENTION=y", text)
        self.assertIn("CONFIG_MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER=y", text)
        self.assertIn("--security-counter 1", text)
        self.assertIn("--security-counter 2", text)
        self.assertIn("results/oss_validation/build/bootstrap_mcuboot_matrix_assets", text)

    def test_script_builds_pr_differential_assets(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for sha in (
            "c21c3909",
            "bbd0ee1e",
            "e35461d2",
            "08985c96",
            "429e2fea",
            "90fd59d2",
        ):
            self.assertIn(sha, text)
        for asset in (
            "pr2205_scratch_broken",
            "pr2205_scratch_fixed",
            "pr2206_scratch_broken",
            "pr2206_scratch_fixed",
            "pr2206_scratch_geom_broken",
            "pr2206_scratch_geom_fixed",
            "pr2214_offset_broken",
            "pr2214_offset_fixed",
            "zephyr_slot0_padded.bin",
            "zephyr_slot1_padded.bin",
            "zephyr_slot1_max.bin",
            "zephyr_slot1_scratch_geom_max.bin",
            "zephyr_slot1_offset_geom_full.bin",
        ):
            self.assertIn(asset, text)
        self.assertIn("build_pr_differential_assets", text)
        self.assertIn("build_shared_nrf52_test_app", text)
        self.assertIn("CONFIG_BOOT_SWAP_USING_SCRATCH=y", text)
        self.assertIn("CONFIG_BOOT_SWAP_USING_OFFSET=y", text)
        self.assertIn("CONFIG_BOOT_PREFER_SWAP_OFFSET=y", text)
        self.assertIn("PR_DIFF_GEOM_ALIGN=\"32\"", text)
        self.assertIn("--align \"${PR_DIFF_GEOM_ALIGN}\"", text)
        self.assertIn("-DCONFIG_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}", text)
        self.assertIn("CONFIG_MINIMAL_LIBC=y", text)
        self.assertIn("CONFIG_PICOLIBC=n", text)
        self.assertIn('restore_mcuboot_module_yml', text)
        self.assertIn('patch_mcuboot_module_yml', text)
        self.assertIn('update --narrow -o=--depth=1 zephyr mcuboot hal_nordic cmsis', text)

    def test_pr_differential_profiles_load_and_reference_existing_assets(self) -> None:
        for relpath in PR_DIFFERENTIAL_PROFILES:
            profile_path = ROOT / "profiles" / relpath
            with self.subTest(profile=relpath):
                profile = load_profile(profile_path)
                self.assertTrue((ROOT / profile.bootloader_elf).exists(), profile.bootloader_elf)
                self.assertTrue((ROOT / profile.images["exec"]).exists(), profile.images["exec"])
                self.assertTrue((ROOT / profile.images["staging"]).exists(), profile.images["staging"])

    def test_pr_differential_assets_are_tracked(self) -> None:
        tracked = subprocess.check_output(
            ["git", "ls-files", "results/oss_validation/assets"],
            cwd=ROOT,
            text=True,
        ).splitlines()
        tracked_set = set(tracked)
        for relpath in (
            "results/oss_validation/assets/oss_mcuboot_pr2205_scratch_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2205_scratch_fixed.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_fixed.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_fixed.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf",
            "results/oss_validation/assets/zephyr_slot0_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_max.bin",
            "results/oss_validation/assets/zephyr_slot1_scratch_geom_max.bin",
            "results/oss_validation/assets/zephyr_slot1_offset_geom_full.bin",
        ):
            self.assertIn(relpath, tracked_set)

    def test_pr2214_geom_profiles_intentionally_share_offset_elfs(self) -> None:
        broken = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2214_offset_geom_broken.yaml").read_text(encoding="utf-8")
        )
        fixed = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2214_offset_geom_fixed.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            broken["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_broken.elf",
        )
        self.assertEqual(
            fixed["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf",
        )

    def test_pr_differential_elfs_are_stripped(self) -> None:
        readelf = shutil.which("arm-none-eabi-readelf")
        if not readelf:
            self.skipTest("arm-none-eabi-readelf not installed")
        for name in (
            "oss_mcuboot_pr2205_scratch_broken.elf",
            "oss_mcuboot_pr2205_scratch_fixed.elf",
            "oss_mcuboot_pr2206_scratch_broken.elf",
            "oss_mcuboot_pr2206_scratch_fixed.elf",
            "oss_mcuboot_pr2206_scratch_geom_broken.elf",
            "oss_mcuboot_pr2206_scratch_geom_fixed.elf",
            "oss_mcuboot_pr2214_offset_broken.elf",
            "oss_mcuboot_pr2214_offset_fixed.elf",
        ):
            with self.subTest(elf=name):
                proc = subprocess.run(
                    [readelf, "-S", str(ASSETS / name)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn(".debug_", proc.stdout)
                self.assertNotIn(".zdebug_", proc.stdout)


if __name__ == "__main__":
    unittest.main()
