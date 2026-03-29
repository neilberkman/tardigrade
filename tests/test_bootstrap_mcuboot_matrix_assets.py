#!/usr/bin/env python3
"""Regression coverage for bootstrap_mcuboot_matrix_assets.sh."""

from __future__ import annotations

import shutil
import subprocess
import sys
import unittest
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh"
GEOM_SCRIPT = ROOT / "scripts" / "bootstrap_mcuboot_geometry_assets.sh"
HEAD_MATRIX_SCRIPT = ROOT / "scripts" / "build_mcuboot_head_matrix.sh"
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
    def assert_no_imgtool_pad_header(self, text: str) -> None:
        self.assertNotRegex(
            text,
            re.compile(r"imgtool\.py sign[\s\S]*--pad-header"),
        )

    def test_script_has_valid_bash_syntax(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(SCRIPT), str(GEOM_SCRIPT)],
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
            "pr2214_offset_geom_broken",
            "pr2214_offset_geom_fixed",
            "zephyr_head_scratch_stm32f4_pr2206_slot1.bin",
            "zephyr_head_offset_stm32f4_slot1.bin",
            "zephyr_slot0_padded.bin",
            "zephyr_slot1_padded.bin",
            "zephyr_slot1_max.bin",
            "zephyr_slot1_scratch_geom_max.bin",
            "zephyr_slot1_scratch_geom_pr2206_boundary.bin",
            "zephyr_slot1_offset_geom_full.bin",
        ):
            self.assertIn(asset, text)
        self.assertIn("build_pr_differential_assets", text)
        self.assertIn("build_shared_nrf52_test_app", text)
        self.assertIn("write_stm32f4_pr2205_overlay", text)
        self.assertIn("write_stm32f4_pr2206_overlay", text)
        self.assertIn("stm32f4_pr2205_scratch.dts", text)
        self.assertIn("stm32f4_pr2206_scratch.dts", text)
        self.assertIn("write-block-size = <8>;", text)
        self.assertIn("nucleo_f429zi", text)
        self.assertIn("slot0_partition: partition@8000", text)
        self.assertIn("slot0_partition: partition@20000", text)
        self.assertIn("CONFIG_BOOT_SWAP_USING_SCRATCH=y", text)
        self.assertIn("CONFIG_BOOT_SWAP_USING_OFFSET=y", text)
        self.assertIn("CONFIG_BOOT_PREFER_SWAP_OFFSET=y", text)
        self.assertIn("PR_DIFF_GEOM_ALIGN=\"32\"", text)
        self.assertIn("PR_DIFF_GEOM_TRAILER_RESERVE=\"0x30a0\"", text)
        self.assertIn("PR_DIFF_GEOM_SIGN_OVERHEAD=\"0x400\"", text)
        self.assertIn("PR2206_GEOM_WRITE_BLOCK_SIZE=\"8\"", text)
        self.assertIn("PR2206_BOOT_MAX_IMG_SECTORS=\"2725\"", text)
        self.assertIn("PR2206_GEOM_TRAILER_RESERVE '0x%x'", text)
        self.assertIn('PR_DIFF_STM32F4_OFFSET_BASE="${ASSETS_DIR}/zephyr_head_offset_stm32f4_slot1.bin"', text)
        self.assertIn("make_offset_slot_image", text)
        self.assertIn(
            'PR_DIFF_STM32F4_SCRATCH_BASE="${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot1.bin"', text
        )
        self.assertIn('PR_DIFF_STM32F4_PR2206_PRIMARY_SLOT_SIZE="0x18000"', text)
        self.assertIn('PR_DIFF_STM32F4_PR2206_STAGING_SLOT_SIZE="0x18000"', text)
        self.assertIn('PR2206_GEOM_TRAILER_RESERVE="${PR2206_GEOM_TRAILER_RESERVE}"', text)
        self.assertIn("PR_DIFF_BASE_IMAGE=\"${ASSETS_DIR}/zephyr_slot1_padded.bin\"", text)
        self.assertIn('ih_size = struct.unpack_from("<I", base, 0x0C)[0]', text)
        self.assertIn("payload = base[0x200:0x200 + ih_size]", text)
        self.assertIn('path.write_bytes((b"\\x00" * 0x200) + body)', text)
        self.assertNotIn('payload = app_bin.read_bytes()', text)
        self.assertIn("local align=\"${5:-${PR_DIFF_GEOM_ALIGN}}\"", text)
        self.assertIn("--align \"${align}\"", text)
        self.assertIn('-DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}"', text)
        self.assert_no_imgtool_pad_header(text)
        self.assertNotIn("--confirm", text)
        self.assertIn("scratch_with_geom_partition.dts", text)
        self.assertIn("stm32f4_pr2206_scratch.dts", text)
        self.assertIn("offset_with_geom_partition.dts", text)
        self.assertIn("slot0_partition: partition@8000", text)
        self.assertIn("slot1_partition: partition@108000", text)
        self.assertIn("slot1_partition: partition@78000", text)
        self.assertIn("slot1_partition: partition@82000", text)
        self.assertIn("scratch_partition: partition@d0000", text)
        self.assertIn("storage_partition: partition@f8000", text)
        self.assertIn("scratch_partition: partition@120000", text)
        self.assertIn("storage_partition: partition@140000", text)
        self.assertIn("MCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}", text)
        self.assertIn("\"${ASSETS_DIR}/zephyr_slot1_max.bin\" \"8\"", text)
        self.assertIn("return (slot_size - 0x200 - geom_trailer_reserve - geom_sign_overhead) & ~0x1F", text)
        self.assertIn("\"0x18000\"", text)
        self.assertIn("zephyr_head_scratch_stm32f4_pr2206_slot1.bin", text)
        self.assertIn("zephyr_head_offset_stm32f4_slot1.bin", text)
        self.assertIn("zephyr_slot1_offset_geom_full_offsetslot.bin", text)
        self.assertIn("CONFIG_MINIMAL_LIBC=y", text)
        self.assertIn("CONFIG_PICOLIBC=n", text)
        self.assertIn('restore_mcuboot_module_yml', text)
        self.assertIn('patch_mcuboot_module_yml', text)
        self.assertIn('update --narrow -o=--depth=1 zephyr mcuboot hal_nordic hal_stm32 cmsis', text)
        self.assertIn('fetch --quiet mcu-tools "+refs/pull/${pr}/head:refs/pull/${pr}"', text)

    def test_geometry_script_restores_header_gap_for_geom_payloads(self) -> None:
        text = GEOM_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('path.write_bytes((b"\\x00" * 0x200) + body)', text)
        self.assertIn("0x18000", text)
        self.assertIn("0x76000", text)
        self.assertIn("zephyr_head_scratch_stm32f4_pr2206_slot1.bin", text)
        self.assertIn("zephyr_head_offset_stm32f4_slot1.bin", text)
        self.assertIn("zephyr_slot1_offset_geom_full_offsetslot.bin", text)
        self.assertIn('"0x1E000"', text)
        self.assert_no_imgtool_pad_header(text)

    def test_head_matrix_script_signs_pr2206_head_images_with_align_32(self) -> None:
        text = HEAD_MATRIX_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('local align="${6:-8}"', text)
        self.assertIn('--align "${align}"', text)
        self.assertIn('slot1_partition: partition@80000', text)
        self.assertIn('reg = <0x20000 0x60000>;', text)
        self.assertIn('sign_image "offset_stm32f4" "0x60000" "1.0.0+0" "zephyr_head_offset_stm32f4_slot0.bin"', text)
        self.assertIn(
            'sign_image "offset_stm32f4" "0x60000" "1.1.0+0" "zephyr_head_offset_stm32f4_slot1.bin" "36864"',
            text,
        )
        self.assertIn("zephyr_head_offset_stm32f4_slot1_offsetslot.bin", text)
        self.assertIn(
            'sign_image "scratch_stm32f4_pr2206" "0x18000" "1.0.0+0" "zephyr_head_scratch_stm32f4_pr2206_slot0.bin" "" "32"',
            text,
        )
        self.assertIn(
            'sign_image "scratch_stm32f4_pr2206" "0x18000" "1.1.0+0" "zephyr_head_scratch_stm32f4_pr2206_slot1.bin" "36864" "32"',
            text,
        )

    def test_upgrade_differential_profiles_hash_exec_slot(self) -> None:
        for relpath in PR_DIFFERENTIAL_PROFILES:
            with self.subTest(profile=relpath):
                profile = yaml.safe_load((ROOT / "profiles" / relpath).read_text(encoding="utf-8"))
                success = profile.get("success_criteria", {})
                if success.get("expected_image") == "staging":
                    self.assertEqual(success.get("image_hash_slot"), "exec")

    def test_pr_differential_profiles_load_and_reference_existing_assets(self) -> None:
        bootstrap_matrix = (ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh").read_text(encoding="utf-8")
        bootstrap_geom = (ROOT / "scripts" / "bootstrap_mcuboot_geometry_assets.sh").read_text(encoding="utf-8")
        head_matrix = (ROOT / "scripts" / "build_mcuboot_head_matrix.sh").read_text(encoding="utf-8")
        generated_assets = {
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin",
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot1.bin",
            "results/oss_validation/assets/zephyr_slot1_scratch_geom_pr2206_boundary.bin",
        }
        for relpath in PR_DIFFERENTIAL_PROFILES:
            profile_path = ROOT / "profiles" / relpath
            with self.subTest(profile=relpath):
                profile = load_profile(profile_path)
                self.assertTrue((ROOT / profile.bootloader_elf).exists(), profile.bootloader_elf)
                for image_key in ("exec", "staging"):
                    image_path = profile.images[image_key]
                    asset_path = ROOT / image_path
                    if asset_path.exists():
                        continue
                    self.assertIn(image_path, generated_assets)
                    asset_name = Path(image_path).name
                    self.assertTrue(
                        asset_name in bootstrap_matrix or asset_name in bootstrap_geom or asset_name in head_matrix,
                        image_path,
                    )

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
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_fixed.elf",
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_slot0.bin",
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_slot1.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot0.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot1.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot1_offsetslot.bin",
            "results/oss_validation/assets/zephyr_slot0_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_max.bin",
            "results/oss_validation/assets/zephyr_slot1_scratch_geom_max.bin",
            "results/oss_validation/assets/zephyr_slot1_offset_geom_full.bin",
            "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin",
        ):
            self.assertIn(relpath, tracked_set)

    def test_pr2214_geom_profiles_use_geom_offset_elfs(self) -> None:
        broken = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2214_offset_geom_broken.yaml").read_text(encoding="utf-8")
        )
        fixed = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2214_offset_geom_fixed.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            broken["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_broken.elf",
        )
        self.assertEqual(
            fixed["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_fixed.elf",
        )
        self.assertEqual(broken["platform"], "platforms/stm32f4.repl")
        self.assertEqual(fixed["platform"], "platforms/stm32f4.repl")
        self.assertEqual(broken["bootloader"]["entry"], 0x08000000)
        self.assertEqual(fixed["bootloader"]["entry"], 0x08000000)
        self.assertEqual(broken["memory"]["slots"]["exec"], {"base": 0x0800C000, "size": 0x76000})
        self.assertEqual(fixed["memory"]["slots"]["exec"], {"base": 0x0800C000, "size": 0x76000})
        self.assertEqual(broken["memory"]["slots"]["staging"], {"base": 0x08082000, "size": 0x76000})
        self.assertEqual(fixed["memory"]["slots"]["staging"], {"base": 0x08082000, "size": 0x76000})
        self.assertEqual(
            broken["images"]["exec"], "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot0.bin"
        )
        self.assertEqual(
            fixed["images"]["exec"], "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot0.bin"
        )
        self.assertEqual(
            broken["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        self.assertEqual(
            fixed["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        self.assertEqual(len(broken["pre_boot_state"]), 7)
        self.assertEqual(len(fixed["pre_boot_state"]), 7)
        self.assertEqual(broken["pre_boot_state"], fixed["pre_boot_state"])
        self.assertEqual(broken["pre_boot_state"][0], {"address": 0x08081FF0, "u32": 0x676523FB})
        self.assertEqual(broken["pre_boot_state"][-1], {"address": 0x08081BD4, "u32": 0x00000001})
        self.assertEqual(broken["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(fixed["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(broken["fault_sweep"]["max_writes"], "auto")
        self.assertEqual(fixed["fault_sweep"]["max_writes"], "auto")
        self.assertNotIn("quick_use_heuristic", broken["fault_sweep"])
        self.assertNotIn("quick_use_heuristic", fixed["fault_sweep"])
        self.assertEqual(broken["expect"]["control_outcome"], "no_boot")
        self.assertTrue(broken["expect"]["allow_control_only_issues"])
        self.assertEqual(fixed["expect"]["control_outcome"], "success")
        self.assertEqual(broken["semantic_assertions"]["control"]["multi_boot_analysis.final_outcome"], "no_boot")
        self.assertEqual(fixed["semantic_assertions"]["control"]["multi_boot_analysis.final_outcome"], "success")
        self.assertEqual(broken["success_criteria"], {})
        self.assertEqual(fixed["success_criteria"], {})
        self.assertTrue(broken.get("skip_self_test", False))
        self.assertTrue(fixed.get("skip_self_test", False))

    def test_pr2214_offset_profiles_use_stm32f4_offset_layout(self) -> None:
        broken = yaml.safe_load((ROOT / "profiles" / "mcuboot_pr2214_offset_broken.yaml").read_text(encoding="utf-8"))
        fixed = yaml.safe_load((ROOT / "profiles" / "mcuboot_pr2214_offset_fixed.yaml").read_text(encoding="utf-8"))
        self.assertEqual(broken["platform"], "platforms/stm32f4.repl")
        self.assertEqual(fixed["platform"], "platforms/stm32f4.repl")
        self.assertEqual(broken["bootloader"]["entry"], 0x08000000)
        self.assertEqual(fixed["bootloader"]["entry"], 0x08000000)
        self.assertEqual(broken["memory"]["slots"]["exec"], {"base": 0x0800C000, "size": 0x76000})
        self.assertEqual(fixed["memory"]["slots"]["exec"], {"base": 0x0800C000, "size": 0x76000})
        self.assertEqual(broken["memory"]["slots"]["staging"], {"base": 0x08082000, "size": 0x76000})
        self.assertEqual(fixed["memory"]["slots"]["staging"], {"base": 0x08082000, "size": 0x76000})
        self.assertEqual(
            broken["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        self.assertEqual(
            fixed["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        self.assertEqual(len(broken["pre_boot_state"]), 7)
        self.assertEqual(len(fixed["pre_boot_state"]), 7)
        self.assertEqual(broken["pre_boot_state"], fixed["pre_boot_state"])
        self.assertEqual(broken["pre_boot_state"][0]["address"], 0x08081FF0)
        self.assertEqual(broken["pre_boot_state"][-1]["address"], 0x08081BD4)
        self.assertEqual(broken["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(fixed["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(broken["fault_sweep"]["max_writes"], "auto")
        self.assertEqual(fixed["fault_sweep"]["max_writes"], "auto")
        self.assertEqual(broken["expect"]["control_outcome"], "no_boot")
        self.assertTrue(broken["expect"]["allow_control_only_issues"])
        self.assertEqual(fixed["expect"]["control_outcome"], "success")
        self.assertEqual(broken["success_criteria"], {})
        self.assertEqual(fixed["success_criteria"], {})

    def test_pr2206_geom_profiles_use_geom_scratch_elfs(self) -> None:
        broken = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2206_scratch_geom_broken.yaml").read_text(encoding="utf-8")
        )
        fixed = yaml.safe_load(
            (ROOT / "profiles" / "mcuboot_pr2206_scratch_geom_fixed.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            broken["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_broken.elf",
        )
        self.assertEqual(
            fixed["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2206_scratch_geom_fixed.elf",
        )
        self.assertEqual(broken["platform"], "platforms/stm32f4.repl")
        self.assertEqual(fixed["platform"], "platforms/stm32f4.repl")
        self.assertEqual(broken["bootloader"]["entry"], 0x08000000)
        self.assertEqual(fixed["bootloader"]["entry"], 0x08000000)
        self.assertEqual(broken["memory"]["slots"]["exec"], {"base": 0x08008000, "size": 0x18000})
        self.assertEqual(fixed["memory"]["slots"]["exec"], {"base": 0x08008000, "size": 0x18000})
        self.assertEqual(broken["memory"]["slots"]["staging"], {"base": 0x08108000, "size": 0x18000})
        self.assertEqual(fixed["memory"]["slots"]["staging"], {"base": 0x08108000, "size": 0x18000})
        self.assertEqual(
            broken["images"]["exec"], "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin"
        )
        self.assertEqual(
            fixed["images"]["exec"], "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin"
        )
        self.assertEqual(
            broken["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_scratch_geom_pr2206_boundary.bin"
        )
        self.assertEqual(
            fixed["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_scratch_geom_pr2206_boundary.bin"
        )
        self.assertEqual(broken["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(fixed["fault_sweep"]["boot_cycles"], 3)
        self.assertEqual(broken["fault_sweep"]["run_duration"], "20.0")
        self.assertEqual(fixed["fault_sweep"]["run_duration"], "20.0")
        self.assertEqual(broken["fault_sweep"]["max_writes"], 1)
        self.assertEqual(fixed["fault_sweep"]["max_writes"], 1)
        self.assertNotIn("quick_use_heuristic", broken["fault_sweep"])
        self.assertNotIn("quick_use_heuristic", fixed["fault_sweep"])
        self.assertNotIn("sweep_hash_bypass_symbols", broken["fault_sweep"])
        self.assertNotIn("sweep_hash_bypass_symbols", fixed["fault_sweep"])
        self.assertEqual(broken["expect"]["control_outcome"], "success")
        self.assertTrue(broken["expect"]["allow_control_only_issues"])
        self.assertEqual(fixed["expect"]["control_outcome"], "no_boot")
        self.assertEqual(broken["semantic_assertions"]["control"]["multi_boot_analysis.status"], "converged")
        self.assertEqual(fixed["semantic_assertions"]["control"]["multi_boot_analysis.status"], "converged")
        self.assertEqual(broken["semantic_assertions"]["control"]["multi_boot_analysis.final_outcome"], "success")
        self.assertEqual(fixed["semantic_assertions"]["control"]["multi_boot_analysis.final_outcome"], "no_boot")
        self.assertEqual(broken["success_criteria"]["expected_image"], "staging")
        self.assertEqual(fixed["success_criteria"], {})
        self.assertFalse(broken.get("skip_self_test", False))
        self.assertFalse(fixed.get("skip_self_test", False))

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
            "oss_mcuboot_pr2214_offset_geom_broken.elf",
            "oss_mcuboot_pr2214_offset_geom_fixed.elf",
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
