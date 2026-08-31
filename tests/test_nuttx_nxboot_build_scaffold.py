#!/usr/bin/env python3
"""Unit tests for the public NuttX nxboot build scaffold."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

from examples.nxboot_style.gen_nxboot_images import wrap_nxboot_image  # noqa: E402
from targets.nuttx_nxboot.build_public_target import (  # noqa: E402
    NXBOOT_SECTOR_SIZE,
    build_env,
    ensure_host_tools,
    normalize_generated_config,
    package_images,
    verify_nxboot_support,
)
from targets.nuttx_nxboot.generate_runtime_profile import (  # noqa: E402
    render_runtime_profile,
)
from profile_loader import load_profile  # noqa: E402


class NuttxNxbootBuildScaffoldTest(unittest.TestCase):
    def test_wrap_nxboot_image_preserves_payload(self) -> None:
        payload = bytes(range(64))
        image = wrap_nxboot_image(payload, (1, 2, 3), header_size=0x400, platform_id=0x42)
        self.assertEqual(image[0x400:], payload)
        self.assertEqual(len(image), 0x400 + len(payload))

    def test_package_images_writes_primary_and_update(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_pkg_"))
        try:
            app_bin = temp_dir / "app.bin"
            app_bin.write_bytes(b"\xAA" * 128)
            out = temp_dir / "out"
            written = package_images(app_bin, out, 0x400, 0x42)
            self.assertEqual(len(written), 2)
            for path in written:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 0x400)
        finally:
            shutil.rmtree(temp_dir)

    def test_package_images_sector_boundary_layout_only_pads_update(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_sector_pkg_"))
        try:
            app_bin = temp_dir / "app.bin"
            app_bin.write_bytes(b"\xAA" * 128)
            out = temp_dir / "out"
            written = package_images(
                app_bin, out, 0x400, 0x42, image_layout="sector_boundary"
            )
            self.assertEqual([path.name for path in written], [
                "nxboot-primary-v1-h400-sector-boundary.img",
                "nxboot-update-v2-h400-sector-boundary.img",
            ])
            primary, update = written
            self.assertNotEqual(primary.stat().st_size, update.stat().st_size)
            self.assertEqual(update.stat().st_size % NXBOOT_SECTOR_SIZE, 0)
            self.assertEqual(primary.read_bytes()[0x400:], b"\xAA" * 128)
        finally:
            shutil.rmtree(temp_dir)

    def test_package_images_rejects_sector_layout_larger_than_slot(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_oversize_pkg_"))
        try:
            app_bin = temp_dir / "app.bin"
            app_bin.write_bytes(b"\xAA" * (0x80000 - 0x400))
            with self.assertRaisesRegex(ValueError, "exceed the nxboot slot"):
                package_images(
                    app_bin,
                    temp_dir / "out",
                    0x400,
                    0x42,
                    image_layout="sector_boundary",
                )
        finally:
            shutil.rmtree(temp_dir)

    def test_normalize_generated_config_persists_apps_dir_and_base_defconfig(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_cfg_"))
        try:
            config = temp_dir / ".config"
            config.write_text("CONFIG_FOO=y\n")
            changed = normalize_generated_config(config, "../../../nuttx-apps", "nucleo-h743zi:nxboot-loader")
            self.assertTrue(changed)
            text = config.read_text()
            self.assertIn('CONFIG_APPS_DIR="../../../nuttx-apps"\n', text)
            self.assertIn('CONFIG_BASE_DEFCONFIG="nucleo-h743zi:nxboot-loader"\n', text)

            changed_again = normalize_generated_config(
                config, "../../../nuttx-apps", "nucleo-h743zi:nxboot-loader"
            )
            self.assertFalse(changed_again)
        finally:
            shutil.rmtree(temp_dir)

    def test_build_env_prefixes_nuttx_tools(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_env_"))
        try:
            tools_dir = temp_dir / "tools"
            tools_dir.mkdir(parents=True)
            env = build_env(temp_dir)
            self.assertTrue(env["PATH"].split(":")[0].endswith("/tools"))
            self.assertEqual(Path(env["PATH"].split(":")[0]), tools_dir.resolve())
        finally:
            shutil.rmtree(temp_dir)

    def test_ensure_host_tools_requires_kconfig_tweak(self) -> None:
        with mock.patch("targets.nuttx_nxboot.build_public_target.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "kconfig-tweak"):
                ensure_host_tools()

    def test_render_runtime_profile_builds_real_nuttx_shape(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_profile_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400.img").write_bytes(b"U")

            rendered = render_runtime_profile(
                build_dir,
                fault_max_writes=64,
                boot_cycles=3,
                run_duration="8.0",
            )
            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(rendered)
            profile = load_profile(profile_path)

            self.assertEqual(profile.platform, "platforms/nucleo_h753zi_tardigrade.repl")
            self.assertEqual(profile.flash_backend, "faultFlash")
            self.assertEqual(profile.bootloader_entry, 0x08000000)
            self.assertEqual(profile.success_criteria.vtor_in_slot, "exec")
            self.assertEqual(profile.success_criteria.vector_table_offset, 0x400)
            self.assertFalse(profile.success_criteria.image_hash)
            self.assertEqual(profile.fault_sweep.max_writes, 64)
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertEqual(profile.fault_sweep.expected_rollback_at_cycle, 1)
            self.assertEqual(profile.fault_sweep.run_duration, "8.0")
            self.assertEqual(profile.fault_sweep.calibration_time_slice, "0.1")
            self.assertEqual(profile.memory.page_size, 0x20000)
            self.assertEqual(
                [(region.base, region.size, region.sector_size) for region in profile.memory.erase_regions],
                [
                    (0x08000000, 0x100000, 0x20000),
                    (0x08100000, 0x100000, 0x20000),
                ],
            )
            self.assertEqual(
                profile.semantic_assertions["control"]["semantic_state.roles.next_boot"],
                "none",
            )
            robot_vars = profile.robot_vars(ROOT)
            self.assertIn(
                "PLATFORM_REPL:{}".format((ROOT / "platforms/nucleo_h753zi_tardigrade.repl").resolve()),
                robot_vars,
            )
            self.assertIn(
                "EXTRA_PERIPHERALS:{}".format((ROOT / "peripherals/STM32H7FlashController.cs").resolve()),
                robot_vars,
            )
            self.assertIn("EXPECTED_ROLLBACK_AT_CYCLE:1", robot_vars)
            self.assertIn("CALIBRATION_TIME_SLICE:0.1", robot_vars)
            self.assertIn("successful_rollback", profile.invariants)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_baseline_uses_campaign_default_boot_cycles(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_baseline_default_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400.img").write_bytes(b"U")

            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(render_runtime_profile(build_dir))
            profile = load_profile(profile_path)

            self.assertEqual(profile.fault_sweep.boot_cycles, 2)
            self.assertEqual(profile.fault_sweep.expected_rollback_at_cycle, 1)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_sector_boundary_resume_campaign_requires_distinct_images(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_campaign_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400-sector-boundary.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400-sector-boundary.img").write_bytes(b"U")

            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(
                render_runtime_profile(
                    build_dir,
                    campaign="sector_boundary_resume",
                    name="nuttx_nxboot_sector_boundary_resume",
                )
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.fault_sweep.fault_types, ["swap_progress"])
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertTrue(profile.fault_sweep.expected_rollback_at_cycle == 1)
            self.assertIn("sector-boundary", profile.images["staging"])
            self.assertIn("successful_rollback", profile.invariants)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_profile_rejects_oversized_image(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_oversize_profile_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400.img").write_bytes(
                b"U" * (0x80000 + 1)
            )
            with self.assertRaisesRegex(
                ValueError, "larger than the declared nxboot slot"
            ):
                render_runtime_profile(build_dir)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_profile_rejects_unsupported_campaign(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_bad_campaign_"))
        try:
            with self.assertRaisesRegex(
                ValueError, "unsupported NuttX nxboot campaign"
            ):
                render_runtime_profile(temp_dir / "build", campaign="not-a-campaign")
        finally:
            shutil.rmtree(temp_dir)

    def test_named_campaign_respects_explicit_single_boot(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_single_boot_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400-sector-boundary.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400-sector-boundary.img").write_bytes(b"U")
            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(
                render_runtime_profile(
                    build_dir,
                    campaign="sector_boundary_resume",
                    boot_cycles=1,
                )
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.fault_sweep.boot_cycles, 1)
            self.assertIsNone(profile.fault_sweep.expected_rollback_at_cycle)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_metadata_erase_resume_campaign_has_distinct_faults(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_metadata_campaign_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400.img").write_bytes(b"U")

            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(
                render_runtime_profile(
                    build_dir,
                    campaign="metadata_erase_resume",
                    name="nuttx_nxboot_metadata_erase_resume",
                )
            )
            profile = load_profile(profile_path)
            self.assertEqual(
                profile.fault_sweep.fault_types,
                ["swap_progress", "interrupted_erase"],
            )
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertIn("nxboot_confirmed_has_recovery", profile.invariants)
        finally:
            shutil.rmtree(temp_dir)

    def test_render_sector_boundary_writeback_campaign(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_nxboot_writeback_campaign_"))
        try:
            build_dir = temp_dir / "build"
            images_dir = build_dir / "images"
            images_dir.mkdir(parents=True)
            (build_dir / "nxboot-loader.elf").write_bytes(b"ELF")
            (images_dir / "nxboot-primary-v1-h400-sector-boundary.img").write_bytes(b"P")
            (images_dir / "nxboot-update-v2-h400-sector-boundary.img").write_bytes(b"U")

            profile_path = temp_dir / "profile.yaml"
            profile_path.write_text(
                render_runtime_profile(
                    build_dir,
                    campaign="sector_boundary_writeback",
                    name="nuttx_nxboot_sector_boundary_writeback",
                )
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.fault_sweep.fault_types, ["power_loss"])
            self.assertEqual(profile.fault_sweep.boot_cycles, 3)
            self.assertEqual(profile.fault_sweep.durability_model, "writeback")
            self.assertEqual(profile.fault_sweep.writeback.buffer_capacity, "auto")
            self.assertFalse(profile.fault_sweep.writeback.erase_flushes_domain)
            self.assertEqual(profile.fault_sweep.writeback.barriers, [])
            self.assertNotIn("barriers:", profile_path.read_text())
            self.assertIn("sector-boundary", profile.images["staging"])
        finally:
            shutil.rmtree(temp_dir)

    def test_verify_nxboot_support_passes_on_upstream(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_upstream_"))
        try:
            kconfig = temp_dir / "arch" / "arm" / "src" / "stm32h7" / "Kconfig"
            kconfig.parent.mkdir(parents=True)
            kconfig.write_text('config STM32_APP_FORMAT_NXBOOT\n\tbool "NuttX nxboot"\n')
            # Should not raise.
            verify_nxboot_support(temp_dir)
        finally:
            shutil.rmtree(temp_dir)

    def test_verify_nxboot_support_fails_on_old_tree(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="nuttx_old_"))
        try:
            kconfig = temp_dir / "arch" / "arm" / "src" / "stm32h7" / "Kconfig"
            kconfig.parent.mkdir(parents=True)
            kconfig.write_text('config STM32_APP_FORMAT_MCUBOOT\n\tbool "MCUboot"\n')
            with self.assertRaises(RuntimeError):
                verify_nxboot_support(temp_dir)
        finally:
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    unittest.main()
