#!/usr/bin/env python3
"""Regression coverage for bootstrap_mcuboot_matrix_assets.sh."""

from __future__ import annotations

import fnmatch
import io
import os
import shutil
import struct
import subprocess
import sys
import unittest
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import yaml


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh"
HEAD_MATRIX_SCRIPT = ROOT / "scripts" / "build_mcuboot_head_matrix.sh"
ASSETS = ROOT / "results" / "oss_validation" / "assets"

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile  # noqa: E402


PR_DIFFERENTIAL_PROFILES = [
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
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_zephyr_init_resolves_ref_after_clone_and_verifies_checkout(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('ZEPHYR_INIT_REF="v3.7.0"', text)
        self.assertIn('ZEPHYR_INIT_REF="${ZEPHYR_REF}"', text)
        self.assertIn('--mr "${ZEPHYR_INIT_REF}"', text)
        self.assertIn("checkout_zephyr_ref \"${ZEPHYR_WS}/zephyr\" \"${ZEPHYR_REF}\"", text)
        self.assertIn('git -C "${repo}" fetch --quiet origin -- "${ref}"', text)
        self.assertIn("'+refs/heads/*:refs/remotes/origin/*'", text)
        self.assertIn("Direct Zephyr SHA fetch failed", text)
        self.assertIn('git -C "${repo}" checkout --detach --quiet FETCH_HEAD', text)
        self.assertIn('git -C "${repo}" cat-file -e "${ref}^{commit}"', text)
        self.assertIn('[[ "${resolved,,}" != "${ref,,}" ]]', text)
        self.assertIn('verify_zephyr_checkout "${ZEPHYR_WS}/zephyr"', text)

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
            "36940db938a8f4a1e919496793ed439850a221c2",
            "25e2761c669035c991dff115f03e34f1505bd97a",
            "33094fc5a50096c8cbb3d2f443c4162a0ff08ea8",
            "b893d34f564f454f454f3643b05b1e18fb457e5c",
            "429e2fea24518f178cd4d33928cb66fcb0205803",
            "90fd59d2f9e45c24d0833dd391dcdc932b3b1908",
        ):
            self.assertIn(sha, text)
        for asset in (
            "pr2199_move_broken",
            "pr2199_move_fixed",
            "head_offset",
            "pr2214_offset_nrf52_broken",
            "pr2214_offset_nrf52_fixed",
            "pr2214_offset_geom_broken",
            "pr2214_offset_geom_fixed",
            "zephyr_head_scratch_stm32f4_pr2206_slot1.bin",
            "zephyr_slot0_padded.bin",
            "zephyr_slot1_padded.bin",
            "zephyr_slot1_max.bin",
            "zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin",
            "zephyr_slot1_offset_geom_full.bin",
        ):
            self.assertIn(asset, text)
        self.assertNotIn('build_pr_bootloader_variant "pr2214_offset_broken"', text)
        self.assertNotIn('build_pr_bootloader_variant "pr2214_offset_fixed"', text)
        self.assertIn("build_pr_differential_assets", text)
        self.assertIn("build_pr2214_offset_staging_image", text)
        self.assertIn("build_pr2214_offset_geom_images", text)
        self.assertIn("build_pr2214_offset_nrf52_elfs", text)
        self.assertIn("build_swaptable_nrf52_elfs", text)
        self.assertIn("build_shared_nrf52_test_app", text)
        self.assertIn("build_shared_stm32f4_pr2206_test_app", text)
        self.assertIn("build_shared_stm32f4_pr2214_geom_test_app", text)
        self.assertIn("write_nrf52_pr2214_overlay", text)
        self.assertIn("nrf52_pr2214_offset.dts", text)
        self.assertIn("write-block-size = <8>;", text)
        self.assertIn("nucleo_f429zi", text)
        self.assertIn("nrf52840dk/nrf52840", text)
        self.assertIn("slot0_partition: partition@8000", text)
        self.assertIn("slot0_partition: partition@20000", text)
        self.assertIn("slot0_partition: partition@c000", text)
        self.assertIn("reg = <0x0c000 0x75000>;", text)
        self.assertIn("slot1_partition: partition@81000", text)
        self.assertIn("reg = <0x81000 0x76000>;", text)
        self.assertIn("storage_partition: partition@f7000", text)
        self.assertIn("reg = <0xf7000 0x09000>;", text)
        self.assertIn('PR2214_SWAP_0X74000_PAYLOAD_SIZE="0x73CB0"', text)
        self.assertIn('PR2214_PRIMARY_SLOT_SIZE="0x75000"', text)
        self.assertIn('PR2214_STAGING_SLOT_SIZE="0x76000"', text)
        self.assertIn('PR2214_SECTOR_SIZE="0x1000"', text)
        self.assertIn('"1.2.0+0"', text)
        self.assertIn('out_commit="${ASSETS_DIR}/oss_mcuboot_${name}_commit.txt"', text)
        self.assertIn('git -C "${src}" rev-parse --verify HEAD^{commit} > "${out_commit}"', text)
        self.assertIn("CONFIG_BOOT_SWAP_USING_OFFSET=y", text)
        self.assertIn("CONFIG_BOOT_PREFER_SWAP_OFFSET=y", text)
        self.assertIn("PR_DIFF_GEOM_ALIGN=\"32\"", text)
        self.assertIn("PR_DIFF_GEOM_TRAILER_RESERVE=\"0x30a0\"", text)
        self.assertIn("PR_DIFF_GEOM_SIGN_OVERHEAD=\"0x400\"", text)
        self.assertIn('PR_DIFF_STM32F4_OFFSET_GEOM_APP="${stm32f4_pr2214_geom_app_bin}"', text)
        self.assertIn("make_offset_slot_image", text)
        self.assertIn("PR_DIFF_BASE_IMAGE=\"${ASSETS_DIR}/zephyr_slot1_padded.bin\"", text)
        self.assertIn('ih_size = struct.unpack_from("<I", base, 0x0C)[0]', text)
        self.assertIn("payload = base[0x200:0x200 + ih_size]", text)
        self.assertIn('path.write_bytes((b"\\x00" * 0x200) + body)', text)
        self.assertNotIn('payload = app_bin.read_bytes()', text)
        self.assertIn("local align=\"${5:-${PR_DIFF_GEOM_ALIGN}}\"", text)
        self.assertIn("--align \"${align}\"", text)
        self.assert_no_imgtool_pad_header(text)
        self.assertNotIn("--confirm", text)
        self.assertIn("scratch_with_geom_partition.dts", text)
        self.assertIn("offset_with_geom_partition.dts", text)
        self.assertIn("slot0_partition: partition@8000", text)
        self.assertIn("slot1_partition: partition@108000", text)
        self.assertIn("slot1_partition: partition@78000", text)
        self.assertIn("reg = <0x108000 0x38000>;", text)
        self.assertIn("scratch_partition: partition@d0000", text)
        self.assertIn("storage_partition: partition@f8000", text)
        self.assertIn("scratch_partition: partition@120000", text)
        self.assertIn("storage_partition: partition@140000", text)
        self.assertIn("MCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}", text)
        self.assertIn("\"${ASSETS_DIR}/zephyr_slot1_max.bin\" \"8\"", text)
        self.assertIn("return (slot_size - 0x200 - geom_trailer_reserve - geom_sign_overhead) & ~0x1F", text)
        self.assertIn("\"0x18000\"", text)
        self.assertIn("zephyr_head_scratch_stm32f4_pr2206_slot1.bin", text)
        self.assertIn("zephyr_slot1_offset_geom_full_offsetslot.bin", text)
        self.assertIn("CONFIG_MINIMAL_LIBC=y", text)
        self.assertIn("CONFIG_PICOLIBC=n", text)
        self.assertIn("\"${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot0.bin\" \"\" \"32\"", text)
        self.assertIn("\"${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot1.bin\" \"36864\" \"32\"", text)
        self.assertIn('restore_mcuboot_module_yml', text)
        self.assertIn('patch_mcuboot_module_yml', text)
        self.assertIn("west_projects=(zephyr mcuboot hal_nordic hal_stm32 cmsis)", text)
        self.assertIn('update --narrow -o=--depth=1 "${west_projects[@]}"', text)
        self.assertIn('fetch --quiet mcu-tools "+refs/pull/${pr}/head:refs/pull/${pr}"', text)

    def test_head_matrix_script_signs_pr2206_head_images_with_align_32(self) -> None:
        text = HEAD_MATRIX_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("f84b9d3fd019fb1945e532924bee7a9c03c77373", text)
        self.assertIn("git -C \"${MCUBOOT_REPO}\" restore --worktree", text)
        self.assertIn("-DCONFIG_BOOTLOADER_SRAM_SIZE=64", text)
        self.assertIn("-DCONFIG_WARN_DEPRECATED=n", text)
        self.assertIn("-DCONFIG_USE_SEGGER_RTT=n", text)
        self.assertIn("-DCONFIG_MINIMAL_LIBC=y", text)
        self.assertIn("-DCONFIG_PICOLIBC=n", text)
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

    def test_head_matrix_stm32f4_scratch_layout_is_mirrored_and_sector_aligned(self) -> None:
        text = HEAD_MATRIX_SCRIPT.read_text(encoding="utf-8")
        expected_dts = (
            'reg = <0x0 0x08000>;',
            'slot0_partition: partition@8000',
            'reg = <0x08000 0x38000>;',
            'slot1_partition: partition@108000',
            'reg = <0x108000 0x38000>;',
            'scratch_partition: partition@40000',
            'reg = <0x40000 0x20000>;',
            'storage_partition: partition@60000',
            'reg = <0x60000 0xA0000>;',
        )
        for snippet in expected_dts:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, text)
        self.assertIn(
            'sign_image "scratch_stm32f4" "0x38000" "1.0.0+0" "zephyr_head_scratch_stm32f4_mirrored_slot0.bin"',
            text,
        )
        self.assertIn(
            'sign_image "scratch_stm32f4" "0x38000" "1.1.0+0" "zephyr_head_scratch_stm32f4_mirrored_slot1.bin" "36864"',
            text,
        )
        self.assertNotIn('reg = <0x20000 0x58000>;', text)
        self.assertNotIn('reg = <0x78000 0x58000>;', text)

        for name in (
            "mcuboot_head_scratch_stm32f4_upgrade.yaml",
            "mcuboot_head_scratch_stm32f4_fast_upgrade.yaml",
        ):
            with self.subTest(profile=name):
                profile = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(
                    profile["memory"]["slots"],
                    {
                        "exec": {"base": 0x08008000, "size": 0x38000},
                        "staging": {"base": 0x08108000, "size": 0x38000},
                    },
                )
                self.assertEqual(
                    profile["memory"]["erase_regions"],
                    [
                        {"base": 0x08000000, "size": 0x10000, "sector_size": 0x4000},
                        {"base": 0x08010000, "size": 0x10000, "sector_size": 0x10000},
                        {"base": 0x08020000, "size": 0xE0000, "sector_size": 0x20000},
                        {"base": 0x08100000, "size": 0x10000, "sector_size": 0x4000},
                        {"base": 0x08110000, "size": 0x10000, "sector_size": 0x10000},
                        {"base": 0x08120000, "size": 0xE0000, "sector_size": 0x20000},
                    ],
                )
                self.assertEqual(
                    profile["memory"]["postmortem_partitions"],
                    [{"name": "scratch", "base": 0x08040000, "size": 0x20000}],
                )
                self.assertIn("Mirrored-bank non-uniform sectors", profile["description"])
                self.assertEqual(profile["success_criteria"]["marker_address"], 0x08008014)
                self.assertTrue(
                    profile["images"]["exec"].endswith(
                        "zephyr_head_scratch_stm32f4_mirrored_slot0.bin"
                    )
                )
                self.assertTrue(
                    profile["images"]["staging"].endswith(
                        "zephyr_head_scratch_stm32f4_mirrored_slot1.bin"
                    )
                )

    def test_head_matrix_signs_with_application_rom_start_offset(self) -> None:
        text = HEAD_MATRIX_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("--header-size 0x200", text)
        self.assertIn("s/^CONFIG_ROM_START_OFFSET=//p", text)
        self.assertIn('local app_config="${BUILD_TMP}/hello_${name}/zephyr/.config"', text)
        self.assertIn('header_size="$(app_rom_start_offset "${app_config}")"', text)
        self.assertRegex(
            text,
            re.compile(
                r'"\$\{IMGTOOL_PY\}" sign[\s\S]*?--header-size "\$\{header_size\}"[\s\S]*?'
                r'check_mcuboot_image_vectors\.py" \\\n\s+--image "\$\{out\}" '
                r'--app-config "\$\{app_config\}"'
            ),
        )

    def test_zero_day_matrix_assets_are_rebuilt_and_uploaded(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "mcuboot-head-zero-day.yml").read_text(
                encoding="utf-8"
            )
        )
        upload = next(
            step
            for step in workflow["jobs"]["build"]["steps"]
            if step.get("name") == "Upload current-head assets"
        )
        upload_globs = [
            line.strip() for line in upload["with"]["path"].splitlines() if line.strip()
        ]
        text = HEAD_MATRIX_SCRIPT.read_text(encoding="utf-8")
        produced = {
            "oss_mcuboot_head_{}.elf".format(name)
            for name in re.findall(r'^build_mcuboot "([a-z0-9_]+)"', text, re.M)
        }
        produced |= set(
            re.findall(r'^sign_image "[^"]+" "[^"]+" "[^"]+" "([^"]+\.bin)"', text, re.M)
        )
        produced |= set(
            re.findall(
                r'^make_offset_slot_image \\\n\s+"[^"]+" \\\n\s+"\$\{ASSETS_DIR\}/([^"]+)"',
                text,
                re.M,
            )
        )

        matrix = workflow["jobs"]["sweep"]["strategy"]["matrix"]["include"]
        self.assertTrue(matrix)
        for entry in matrix:
            profile = load_profile(ROOT / entry["profile"])
            for asset in (profile.bootloader_elf, *profile.images.values()):
                with self.subTest(profile=entry["profile"], asset=asset):
                    # A sweep asset that the build never rewrites would fall back
                    # to the stale tracked copy without any error.
                    self.assertIn(Path(asset).name, produced)
                    self.assertTrue(
                        any(fnmatch.fnmatch(asset, pattern) for pattern in upload_globs),
                        asset,
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
        head_matrix = (ROOT / "scripts" / "build_mcuboot_head_matrix.sh").read_text(encoding="utf-8")
        generated_assets = {
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin",
            "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot1.bin",
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
                        asset_name in bootstrap_matrix or asset_name in head_matrix,
                        image_path,
                    )

    def test_head_matrix_uses_bootstrap_public_mcuboot_remote(self) -> None:
        bootstrap = (ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh").read_text(
            encoding="utf-8"
        )
        head_matrix = (ROOT / "scripts" / "build_mcuboot_head_matrix.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('MCUBOOT_REMOTE="${MCUBOOT_REMOTE:-upstream}"', head_matrix)
        self.assertIn("remote add upstream", bootstrap)
        self.assertIn("https://github.com/mcu-tools/mcuboot.git", bootstrap)
        self.assertIn('rev-parse FETCH_HEAD', head_matrix)
        self.assertIn('checkout --quiet --detach "${MCUBOOT_FETCHED_COMMIT}"', head_matrix)
        self.assertIn("ZEPHYR_MAJOR", head_matrix)
        self.assertIn("ZEPHYR_MAJOR < 4", head_matrix)

    def test_bootstrap_supports_current_head_without_historical_builds(self) -> None:
        bootstrap = (ROOT / "scripts" / "bootstrap_mcuboot_matrix_assets.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('BOOTSTRAP_SCOPE="${MCUBOOT_BOOTSTRAP_SCOPE:-full}"', bootstrap)
        self.assertIn('if [[ "${BOOTSTRAP_SCOPE}" == "head" ]]', bootstrap)
        self.assertIn('if [[ "${BOOTSTRAP_SCOPE}" == "full" ]]', bootstrap)
        self.assertIn('"${ASSETS_DIR}/zephyr_head_commit.txt"', bootstrap)
        self.assertIn("west_projects+=(cmsis_6)", bootstrap)

    def test_bootstrap_rejects_unknown_scope_before_mutating_workspace(self) -> None:
        proc = subprocess.run(
            [str(SCRIPT)],
            cwd=ROOT,
            env={**os.environ, "MCUBOOT_BOOTSTRAP_SCOPE": "unknown"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("must be 'full' or 'head'", proc.stderr)

    def test_script_builds_stm32f4_move_slot_images_from_rom_start_offset(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("app_rom_start_offset()", text)
        self.assertIn("CONFIG_ROM_START_OFFSET=", text)
        self.assertIn('header_size="$(app_rom_start_offset "${app_config}")"', text)
        self.assertIn('--header-size "${header_size}"', text)
        self.assertIn("write_stm32f4_move_overlays()", text)
        self.assertIn("build_shared_stm32f4_move_test_app()", text)
        self.assertIn("build_stm32f4_move_images()", text)
        self.assertIn("stm32f4_disco", text)
        self.assertIn('"${ASSETS_DIR}/zephyr_stm32f4_slot0.bin"', text)
        self.assertIn('"${ASSETS_DIR}/zephyr_stm32f4_slot1.bin"', text)
        for name, expected_ver in (
            ("zephyr_stm32f4_slot0.bin", (1, 0, 0, 0)),
            ("zephyr_stm32f4_slot1.bin", (2, 0, 0, 0)),
        ):
            data = (ASSETS / name).read_bytes()
            magic, _load, hdr_size, _prot, _img_size, _flags, maj, minor, rev, build = (
                struct.unpack_from("<IIHHIIBBHI", data, 0)
            )
            self.assertEqual(magic, 0x96F3B83D)
            self.assertEqual(hdr_size, 0x200)
            self.assertEqual((maj, minor, rev, build), expected_ver)
            sp, reset = struct.unpack_from("<II", data, hdr_size)
            self.assertTrue(0x20000000 < sp <= 0x20040000, f"{name}: sp=0x{sp:08x}")
            self.assertTrue(0x08020200 <= reset < 0x08080000, f"{name}: reset=0x{reset:08x}")
            self.assertEqual(reset & 1, 1)

    def test_pr_differential_assets_are_tracked(self) -> None:
        tracked = subprocess.check_output(
            ["git", "ls-files", "results/oss_validation/assets"],
            cwd=ROOT,
            text=True,
        ).splitlines()
        tracked_set = set(tracked)
        for relpath in (
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_broken_commit.txt",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_fixed.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_fixed_commit.txt",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_broken_commit.txt",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_fixed.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_fixed_commit.txt",
            "results/oss_validation/assets/zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot0.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot1.bin",
            "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot1_offsetslot.bin",
            "results/oss_validation/assets/zephyr_slot0_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_padded.bin",
            "results/oss_validation/assets/zephyr_slot1_max.bin",
            "results/oss_validation/assets/zephyr_slot1_offset_geom_full.bin",
            "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin",
        ):
            self.assertIn(relpath, tracked_set)
        for retired in (
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_broken.elf",
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf",
        ):
            self.assertNotIn(retired, tracked_set)
            self.assertFalse((ROOT / retired).exists())

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
        self.assertEqual(broken["memory"]["slots"]["exec"], {"base": 0x08008000, "size": 0x18000})
        self.assertEqual(fixed["memory"]["slots"]["exec"], {"base": 0x08008000, "size": 0x18000})
        self.assertEqual(broken["memory"]["slots"]["staging"], {"base": 0x08108000, "size": 0x38000})
        self.assertEqual(fixed["memory"]["slots"]["staging"], {"base": 0x08108000, "size": 0x38000})
        self.assertEqual(
            broken["images"]["exec"], "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin"
        )
        self.assertEqual(
            fixed["images"]["exec"], "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot0.bin"
        )
        self.assertEqual(
            broken["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        self.assertEqual(
            fixed["images"]["staging"], "results/oss_validation/assets/zephyr_slot1_offset_geom_full_offsetslot.bin"
        )
        full_bytes = (ASSETS / "zephyr_slot1_offset_geom_full.bin").read_bytes()
        offset_bytes = (ASSETS / "zephyr_slot1_offset_geom_full_offsetslot.bin").read_bytes()
        self.assertEqual(len(full_bytes), 0x8000)
        self.assertEqual(offset_bytes[:0x4000], b"\xff" * 0x4000)
        self.assertEqual(offset_bytes[0x4000:], full_bytes)
        sp, reset = struct.unpack_from("<II", full_bytes, 0x200)
        self.assertTrue(0x20000000 < sp <= 0x20040000, f"sp=0x{sp:08x}")
        self.assertTrue(0x08008200 <= reset < 0x08020000, f"reset=0x{reset:08x}")
        for profile in (broken, fixed):
            self.assertEqual(
                profile["update_trigger"],
                {"type": "mcuboot_trailer_magic", "slot": "staging", "max_align": 32},
            )
            self.assertNotIn("pre_boot_state", profile)
            self.assertEqual(
                profile["success_criteria"],
                {"vtor_in_slot": "exec", "marker_address": 0x08008014, "marker_value": 0x00000102},
            )
        self.assertEqual(broken["fault_sweep"]["max_writes"], 0)
        self.assertEqual(fixed["fault_sweep"]["max_writes"], "auto")
        self.assertNotIn("quick_use_heuristic", broken["fault_sweep"])
        self.assertNotIn("quick_use_heuristic", fixed["fault_sweep"])
        self.assertEqual(broken["expect"]["control_outcome"], "wrong_image")
        self.assertTrue(broken["expect"]["allow_control_only_issues"])
        self.assertEqual(fixed["expect"]["control_outcome"], "success")
        self.assertTrue(broken.get("skip_self_test", False))
        self.assertTrue(fixed.get("skip_self_test", False))

    def test_pr2214_offset_profiles_use_nrf52_sector_plus_one_layout(self) -> None:
        broken = yaml.safe_load((ROOT / "profiles" / "mcuboot_pr2214_offset_broken.yaml").read_text(encoding="utf-8"))
        fixed = yaml.safe_load((ROOT / "profiles" / "mcuboot_pr2214_offset_fixed.yaml").read_text(encoding="utf-8"))
        self.assertEqual(
            broken["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_broken.elf",
        )
        self.assertEqual(
            fixed["bootloader"]["elf"],
            "results/oss_validation/assets/oss_mcuboot_pr2214_offset_nrf52_fixed.elf",
        )
        for profile in (broken, fixed):
            self.assertEqual(profile["platform"], "platforms/cortex_m4_flash_fast.repl")
            self.assertEqual(profile["bootloader"]["entry"], 0x00000000)
            self.assertEqual(profile["memory"]["slots"]["exec"], {"base": 0x0000C000, "size": 0x75000})
            self.assertEqual(profile["memory"]["slots"]["staging"], {"base": 0x00081000, "size": 0x76000})
            self.assertEqual(
                profile["images"]["staging"],
                "results/oss_validation/assets/zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin",
            )
            self.assertEqual(profile["update_trigger"], {"type": "mcuboot_trailer_magic", "slot": "staging"})
            self.assertNotIn("pre_boot_state", profile)
            self.assertEqual(
                profile["success_criteria"],
                {"vtor_in_slot": "exec", "marker_address": 0x0000C014, "marker_value": 0x00000201},
            )
        self.assertEqual(broken["expect"]["control_outcome"], "wrong_image")
        self.assertTrue(broken["expect"]["allow_control_only_issues"])
        self.assertEqual(fixed["expect"]["control_outcome"], "success")
        # The broken revision never moves image data, so its campaign is the
        # control boot alone; the fixed revision sweeps the full swap.
        self.assertEqual(broken["fault_sweep"]["max_writes"], 0)
        self.assertEqual(fixed["fault_sweep"]["max_writes"], "auto")

    def test_pr2214_offset_staging_image_hits_find_last_idx_boundary(self) -> None:
        # docs/mcuboot-pr2214-swap-offset.md derives these numbers.
        sector = 0x1000
        primary_sectors = 0x75000 // sector
        secondary_sectors = 0x76000 // sector
        # boot_trailer_sz(4) for MIN_SECTOR_COUNT=118, two status states per
        # sector and BOOT_MAX_ALIGN=8: 118 * 2 * 4 + 8 * 4 + 16.
        trailer_sectors = -(-(118 * 2 * 4 + 8 * 4 + 16) // sector)
        first_trailer_idx = primary_sectors - trailer_sectors

        data = (ASSETS / "zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin").read_bytes()
        self.assertEqual(set(data[:sector]), {0xFF})
        magic, _load, hdr_size, protect_tlv_size, img_size = struct.unpack_from("<IIHHI", data, sector)
        self.assertEqual(magic, 0x96F3B83D)
        tlv_magic, tlv_tot = struct.unpack_from("<HH", data, sector + hdr_size + img_size + protect_tlv_size)
        self.assertEqual(tlv_magic, 0x6907)
        swap_size = hdr_size + img_size + protect_tlv_size + tlv_tot
        self.assertEqual(swap_size, 0x74000)
        self.assertEqual(len(data), sector + swap_size)
        # Version 1.2.0 is the success marker at exec base + 0x14.
        self.assertEqual(struct.unpack_from("<I", data, sector + 0x14)[0], 0x00000201)

        sectors_used = -(-swap_size // sector)
        self.assertGreaterEqual(sectors_used, first_trailer_idx)  # 429e2fea aborts
        self.assertLess(sectors_used - 1, first_trailer_idx)  # 90fd59d2 swaps
        # The image ends before the secondary trailer sector, so validation
        # accepts it on both revisions.
        self.assertLessEqual(sector + swap_size, (secondary_sectors - trailer_sectors) * sector)

    def test_pr_differential_elfs_are_stripped(self) -> None:
        readelf = shutil.which("arm-none-eabi-readelf")
        if not readelf:
            self.skipTest("arm-none-eabi-readelf not installed")
        for name in (
            "oss_mcuboot_head_offset.elf",
            "oss_mcuboot_pr2199_move_broken.elf",
            "oss_mcuboot_pr2199_move_fixed.elf",
            "oss_mcuboot_pr2214_offset_geom_broken.elf",
            "oss_mcuboot_pr2214_offset_geom_fixed.elf",
            "oss_mcuboot_pr2214_offset_nrf52_broken.elf",
            "oss_mcuboot_pr2214_offset_nrf52_fixed.elf",
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
                self.assertIn(".symtab", proc.stdout)

    def test_pr2214_profile_elfs_match_upstream_boot_swap_tables(self) -> None:
        upstream_table = (
            b"\x04\x01\x04\x03\x04\x02"  # ANY, GOOD, ANY, UNSET, ANY -> TEST
            b"\x04\x01\x04\x01\x04\x03"  # ANY, GOOD, ANY, SET, ANY -> PERM
            b"\x01\x03\x03\x04\x01\x04"  # GOOD, UNSET, UNSET, ANY, SET -> REVERT
        )
        expected_table_by_commit = {
            "429e2fea24518f178cd4d33928cb66fcb0205803": upstream_table,
            "90fd59d2f9e45c24d0833dd391dcdc932b3b1908": upstream_table,
        }
        tracked = set(
            subprocess.check_output(
                ["git", "ls-files", "results/oss_validation/assets"],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
        profile_paths = sorted((ROOT / "profiles").glob("mcuboot_pr2214_*.yaml"))
        self.assertEqual(len(profile_paths), 4)

        for profile_path in profile_paths:
            with self.subTest(profile=profile_path.name):
                raw_profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
                elf_rel = raw_profile["bootloader"]["elf"]
                elf_path = ROOT / elf_rel
                commit_rel = str(Path(elf_rel).with_name(f"{Path(elf_rel).stem}_commit.txt"))
                commit_path = ROOT / commit_rel

                self.assertIn(elf_rel, tracked)
                self.assertIn(commit_rel, tracked)
                self.assertTrue(elf_path.is_file(), f"missing ELF {elf_rel}")
                self.assertTrue(commit_path.is_file(), f"missing commit file {commit_rel}")

                commit_sha = commit_path.read_text(encoding="utf-8").strip()
                self.assertIn(commit_sha, expected_table_by_commit)

                elf_bytes = elf_path.read_bytes()
                self.assertIn(commit_sha[:12].encode("ascii"), elf_bytes)

                elf = ELFFile(io.BytesIO(elf_bytes))
                swap_table_bytes = None
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    symbols = section.get_symbol_by_name("boot_swap_tables")
                    if not symbols:
                        continue
                    sym = symbols[0]
                    target_sec = elf.get_section(sym["st_shndx"])
                    offset = sym["st_value"] - target_sec["sh_addr"]
                    swap_table_bytes = target_sec.data()[offset : offset + sym["st_size"]]
                    break

                self.assertIsNotNone(swap_table_bytes, f"boot_swap_tables symbol missing in {elf_rel}")
                self.assertEqual(
                    swap_table_bytes,
                    expected_table_by_commit[commit_sha],
                    f"boot_swap_tables mismatch in {elf_rel} for commit {commit_sha}",
                )

    def test_all_tracked_mcuboot_elfs_match_upstream_swap_tables(self) -> None:
        import check_mcuboot_swap_tables as swap_check

        results = swap_check.check_assets(repo_root=ROOT)
        self.assertGreaterEqual(len(results), 25)
        for res in results:
            with self.subTest(elf=res.elf_path.name):
                self.assertTrue(res.ok, res.message)
                self.assertEqual(res.location, ".symtab", res.message)


if __name__ == "__main__":
    unittest.main()

