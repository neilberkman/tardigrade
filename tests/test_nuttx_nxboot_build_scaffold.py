#!/usr/bin/env python3
"""Unit tests for the public NuttX nxboot build scaffold."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from examples.nxboot_style.gen_nxboot_images import wrap_nxboot_image  # noqa: E402
from targets.nuttx_nxboot.build_public_target import (  # noqa: E402
    normalize_generated_config,
    package_images,
    patch_cmakelists,
    patch_make_defs,
    patch_progmem,
    patch_stm32h7_kconfig,
)


class NuttxNxbootBuildScaffoldTest(unittest.TestCase):
    def test_wrap_nxboot_image_preserves_payload(self) -> None:
        payload = bytes(range(64))
        image = wrap_nxboot_image(payload, (1, 2, 3), header_size=0x400, platform_id=0x42)
        self.assertEqual(image[0x400:], payload)
        self.assertEqual(len(image), 0x400 + len(payload))

    def test_patch_stm32h7_kconfig_is_idempotent(self) -> None:
        original = (
            'config STM32_OTA_SCRATCH_DEVPATH\n\tstring "Scratch partition device path"\n\tdefault "/dev/otascratch"\n'
            'config STM32_OTA_PRIMARY_SLOT_OFFSET\n\thex "MCUboot application image primary slot offset"\n\tdefault "0x40000"\n'
            'config STM32_OTA_SECONDARY_SLOT_OFFSET\n\thex "MCUboot application image secondary slot offset"\n\tdefault "0x100000"\n'
            'config STM32_OTA_SCRATCH_OFFSET\n\thex "MCUboot scratch partition offset"\n\tdefault "0x1c0000"\n'
            'config STM32_OTA_SLOT_SIZE\n\thex "MCUboot application image slot size (in bytes)"\n\tdefault "0xc0000"\n'
            'config STM32_OTA_SCRATCH_SIZE\n\thex "MCUboot scratch partition size (in bytes)"\n\tdefault "0x40000"\n'
            'endchoice # Application Image Format\n'
        )
        patched, changed = patch_stm32h7_kconfig(original)
        self.assertTrue(changed)
        self.assertIn('config STM32_APP_FORMAT_NXBOOT', patched)
        self.assertIn('config STM32_OTA_TERTIARY_SLOT_DEVPATH', patched)
        again, changed_again = patch_stm32h7_kconfig(patched)
        self.assertFalse(changed_again)
        self.assertEqual(again, patched)

    def test_patch_make_defs_is_idempotent(self) -> None:
        original = (
            "ifeq ($(CONFIG_STM32_APP_FORMAT_MCUBOOT),y)\n"
            "  ifeq ($(CONFIG_MCUBOOT_BOOTLOADER),y)\n"
            "    LDSCRIPT = flash-mcuboot-loader.ld\n"
            "  else\n"
            "    LDSCRIPT = flash-mcuboot-app.ld\n"
            "  endif\n"
            "else\n"
            "  LDSCRIPT = flash.ld\n"
            "endif\n"
        )
        patched, changed = patch_make_defs(original)
        self.assertTrue(changed)
        self.assertIn("flash-nxboot-loader.ld", patched)
        again, changed_again = patch_make_defs(patched)
        self.assertFalse(changed_again)
        self.assertEqual(again, patched)

    def test_patch_cmakelists_is_idempotent(self) -> None:
        original = (
            'if(CONFIG_STM32_APP_FORMAT_MCUBOOT)\n'
            '  if(CONFIG_MCUBOOT_BOOTLOADER)\n'
            '    set_property(GLOBAL PROPERTY LD_SCRIPT "${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-loader.ld")\n'
            '  else()\n'
            '    set_property(GLOBAL PROPERTY LD_SCRIPT "${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-app.ld")\n'
            '  endif()\n'
            'else()\n'
            '  set_property(GLOBAL PROPERTY LD_SCRIPT "${NUTTX_BOARD_DIR}/scripts/flash.ld")\n'
            'endif()\n'
        )
        patched, changed = patch_cmakelists(original)
        self.assertTrue(changed)
        self.assertIn("flash-nxboot-app.ld", patched)
        again, changed_again = patch_cmakelists(patched)
        self.assertFalse(changed_again)
        self.assertEqual(again, patched)

    def test_patch_progmem_is_idempotent(self) -> None:
        original = (
            "  {\n"
            "    .offset  = CONFIG_STM32_OTA_SECONDARY_SLOT_OFFSET,\n"
            "    .size    = CONFIG_STM32_OTA_SLOT_SIZE,\n"
            "    .devpath = CONFIG_STM32_OTA_SECONDARY_SLOT_DEVPATH\n"
            "  },\n"
            "  {\n"
            "    .offset  = CONFIG_STM32_OTA_SCRATCH_OFFSET,\n"
            "    .size    = CONFIG_STM32_OTA_SCRATCH_SIZE,\n"
            "    .devpath = CONFIG_STM32_OTA_SCRATCH_DEVPATH\n"
            "  }\n"
        )
        patched, changed = patch_progmem(original)
        self.assertTrue(changed)
        self.assertIn("CONFIG_STM32_OTA_TERTIARY_SLOT_OFFSET", patched)
        again, changed_again = patch_progmem(patched)
        self.assertFalse(changed_again)
        self.assertEqual(again, patched)

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


if __name__ == "__main__":
    unittest.main()
