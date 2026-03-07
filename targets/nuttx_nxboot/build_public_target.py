#!/usr/bin/env python3
"""Prepare a public NuttX checkout for the real nucleo-h743zi nxboot target."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from examples.nxboot_style.gen_nxboot_images import wrap_nxboot_image


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nucleo_h743zi"


KCONFIG_CHOICE_INSERT = """
config STM32_APP_FORMAT_NXBOOT
\tbool "NuttX nxboot format"
\tselect STM32_HAVE_OTA_PARTITION
\tdepends on EXPERIMENTAL
\t---help---
\t\tThe NuttX nxboot support of loading the firmware images.

comment "NXboot support depends on CONFIG_EXPERIMENTAL"
\tdepends on !EXPERIMENTAL

"""


def _insert_before(text: str, needle: str, block: str) -> tuple[str, bool]:
    if block.strip() in text:
        return text, False
    marker = text.find(needle)
    if marker < 0:
        raise RuntimeError(f"Could not find insertion point: {needle!r}")
    return text[:marker] + block + text[marker:], True


def _replace_once(text: str, old: str, new: str) -> tuple[str, bool]:
    if new in text:
        return text, False
    if old not in text:
        raise RuntimeError(f"Could not find expected block to replace:\n{old}")
    return text.replace(old, new, 1), True


def patch_stm32h7_kconfig(text: str) -> tuple[str, bool]:
    changed = False
    text, did = _insert_before(text, 'endchoice # Application Image Format', KCONFIG_CHOICE_INSERT)
    changed = changed or did

    replacements = [
        (
            'config STM32_OTA_SCRATCH_DEVPATH\n\tstring "Scratch partition device path"\n\tdefault "/dev/otascratch"\n',
            'config STM32_OTA_SCRATCH_DEVPATH\n\tstring "Scratch partition device path"\n\tdefault "/dev/otascratch"\n\tdepends on STM32_APP_FORMAT_MCUBOOT\n',
        ),
        (
            'config STM32_OTA_PRIMARY_SLOT_OFFSET\n\thex "MCUboot application image primary slot offset"\n\tdefault "0x40000"\n',
            'config STM32_OTA_PRIMARY_SLOT_OFFSET\n\thex "Application image primary slot offset"\n\tdefault "0x40000"\n',
        ),
        (
            'config STM32_OTA_SECONDARY_SLOT_OFFSET\n\thex "MCUboot application image secondary slot offset"\n\tdefault "0x100000"\n',
            'config STM32_OTA_SECONDARY_SLOT_OFFSET\n\thex "Application image secondary slot offset"\n\tdefault "0x0c0000" if STM32_APP_FORMAT_NXBOOT\n\tdefault "0x100000"\n',
        ),
        (
            'config STM32_OTA_SLOT_SIZE\n\thex "MCUboot application image slot size (in bytes)"\n\tdefault "0xc0000"\n',
            'config STM32_OTA_SLOT_SIZE\n\thex "Application image slot size (in bytes)"\n\tdefault "0x80000" if STM32_APP_FORMAT_NXBOOT\n\tdefault "0xc0000"\n',
        ),
        (
            'config STM32_OTA_SCRATCH_SIZE\n\thex "MCUboot scratch partition size (in bytes)"\n\tdefault "0x40000"\n',
            'config STM32_OTA_SCRATCH_SIZE\n\thex "MCUboot scratch partition size (in bytes)"\n\tdefault "0x40000"\n\tdepends on STM32_APP_FORMAT_MCUBOOT\n',
        ),
    ]

    tertiary_block = (
        'config STM32_OTA_TERTIARY_SLOT_DEVPATH\n'
        '\tstring "Application image tertiary slot device path"\n'
        '\tdefault "/dev/ota2"\n'
        '\tdepends on STM32_APP_FORMAT_NXBOOT\n\n'
    )
    text, did = _insert_before(text, 'config STM32_OTA_SCRATCH_DEVPATH', tertiary_block)
    changed = changed or did

    tertiary_offset_block = (
        'config STM32_OTA_TERTIARY_SLOT_OFFSET\n'
        '\thex "Application image tertiary slot offset"\n'
        '\tdefault "0x140000"\n'
        '\tdepends on STM32_APP_FORMAT_NXBOOT\n\n'
    )
    text, did = _insert_before(text, 'config STM32_OTA_SCRATCH_OFFSET', tertiary_offset_block)
    changed = changed or did

    for old, new in replacements:
        text, did = _replace_once(text, old, new)
        changed = changed or did

    return text, changed


def patch_make_defs(text: str) -> tuple[str, bool]:
    old = (
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
    new = (
        "ifeq ($(CONFIG_STM32_APP_FORMAT_MCUBOOT),y)\n"
        "  ifeq ($(CONFIG_MCUBOOT_BOOTLOADER),y)\n"
        "    LDSCRIPT = flash-mcuboot-loader.ld\n"
        "  else\n"
        "    LDSCRIPT = flash-mcuboot-app.ld\n"
        "  endif\n"
        "else ifeq ($(CONFIG_STM32_APP_FORMAT_NXBOOT),y)\n"
        "  ifeq ($(CONFIG_NXBOOT_BOOTLOADER),y)\n"
        "    LDSCRIPT = flash-nxboot-loader.ld\n"
        "  else\n"
        "    LDSCRIPT = flash-nxboot-app.ld\n"
        "  endif\n"
        "else\n"
        "  LDSCRIPT = flash.ld\n"
        "endif\n"
    )
    return _replace_once(text, old, new)


def patch_cmakelists(text: str) -> tuple[str, bool]:
    old = (
        "if(CONFIG_STM32_APP_FORMAT_MCUBOOT)\n"
        "  if(CONFIG_MCUBOOT_BOOTLOADER)\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-loader.ld\")\n"
        "  else()\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-app.ld\")\n"
        "  endif()\n"
        "else()\n"
        "  set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash.ld\")\n"
        "endif()\n"
    )
    new = (
        "if(CONFIG_STM32_APP_FORMAT_MCUBOOT)\n"
        "  if(CONFIG_MCUBOOT_BOOTLOADER)\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-loader.ld\")\n"
        "  else()\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-mcuboot-app.ld\")\n"
        "  endif()\n"
        "elseif(CONFIG_STM32_APP_FORMAT_NXBOOT)\n"
        "  if(CONFIG_NXBOOT_BOOTLOADER)\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-nxboot-loader.ld\")\n"
        "  else()\n"
        "    set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash-nxboot-app.ld\")\n"
        "  endif()\n"
        "else()\n"
        "  set_property(GLOBAL PROPERTY LD_SCRIPT \"${NUTTX_BOARD_DIR}/scripts/flash.ld\")\n"
        "endif()\n"
    )
    return _replace_once(text, old, new)


def patch_progmem(text: str) -> tuple[str, bool]:
    old = (
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
    new = (
        "  {\n"
        "    .offset  = CONFIG_STM32_OTA_SECONDARY_SLOT_OFFSET,\n"
        "    .size    = CONFIG_STM32_OTA_SLOT_SIZE,\n"
        "    .devpath = CONFIG_STM32_OTA_SECONDARY_SLOT_DEVPATH\n"
        "  },\n"
        "#ifdef CONFIG_STM32_APP_FORMAT_NXBOOT\n"
        "  {\n"
        "    .offset  = CONFIG_STM32_OTA_TERTIARY_SLOT_OFFSET,\n"
        "    .size    = CONFIG_STM32_OTA_SLOT_SIZE,\n"
        "    .devpath = CONFIG_STM32_OTA_TERTIARY_SLOT_DEVPATH\n"
        "  }\n"
        "#else\n"
        "  {\n"
        "    .offset  = CONFIG_STM32_OTA_SCRATCH_OFFSET,\n"
        "    .size    = CONFIG_STM32_OTA_SCRATCH_SIZE,\n"
        "    .devpath = CONFIG_STM32_OTA_SCRATCH_DEVPATH\n"
        "  }\n"
        "#endif\n"
    )
    return _replace_once(text, old, new)


def _write_if_changed(path: Path, new_text: str) -> bool:
    current = path.read_text()
    if current == new_text:
        return False
    path.write_text(new_text)
    return True


def _ensure_config_value(text: str, key: str, value: str) -> tuple[str, bool]:
    line = f'{key}="{value}"'
    changed = False
    lines = text.splitlines()
    new_lines: list[str] = []
    found = False
    for current in lines:
        if current.startswith(f"{key}="):
            found = True
            if current != line:
                new_lines.append(line)
                changed = True
            else:
                new_lines.append(current)
            continue
        new_lines.append(current)
    if not found:
        if new_lines and new_lines[-1] != "":
            new_lines.append("")
        new_lines.append(line)
        changed = True
    return "\n".join(new_lines) + "\n", changed


def normalize_generated_config(config_path: Path, apps_dir: str, base_defconfig: str) -> bool:
    text = config_path.read_text()
    text, changed_apps = _ensure_config_value(text, "CONFIG_APPS_DIR", apps_dir)
    text, changed_base = _ensure_config_value(text, "CONFIG_BASE_DEFCONFIG", base_defconfig)
    if not (changed_apps or changed_base):
        return False
    config_path.write_text(text)
    return True


def install_board_fixtures(nuttx_root: Path) -> list[Path]:
    board_root = nuttx_root / "boards" / "arm" / "stm32h7" / "nucleo-h743zi"
    if not board_root.exists():
        raise RuntimeError(f"Board root not found: {board_root}")
    written: list[Path] = []
    mapping = {
        FIXTURES / "configs" / "nxboot-loader.defconfig": board_root / "configs" / "nxboot-loader" / "defconfig",
        FIXTURES / "configs" / "nxboot-app.defconfig": board_root / "configs" / "nxboot-app" / "defconfig",
        FIXTURES / "scripts" / "flash-nxboot-loader.ld": board_root / "scripts" / "flash-nxboot-loader.ld",
        FIXTURES / "scripts" / "flash-nxboot-app.ld": board_root / "scripts" / "flash-nxboot-app.ld",
    }
    for src, dst in mapping.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        src_bytes = src.read_bytes()
        if dst.exists() and dst.read_bytes() == src_bytes:
            continue
        dst.write_bytes(src_bytes)
        written.append(dst)
    return written


def patch_nuttx_tree(nuttx_root: Path) -> list[Path]:
    changed: list[Path] = []
    targets = [
        (nuttx_root / "arch" / "arm" / "src" / "stm32h7" / "Kconfig", patch_stm32h7_kconfig),
        (nuttx_root / "boards" / "arm" / "stm32h7" / "nucleo-h743zi" / "scripts" / "Make.defs", patch_make_defs),
        (nuttx_root / "boards" / "arm" / "stm32h7" / "nucleo-h743zi" / "src" / "CMakeLists.txt", patch_cmakelists),
        (nuttx_root / "boards" / "arm" / "stm32h7" / "nucleo-h743zi" / "src" / "stm32_progmem.c", patch_progmem),
    ]
    for path, patch_fn in targets:
        patched, did_change = patch_fn(path.read_text())
        if _write_if_changed(path, patched):
            changed.append(path)
        elif did_change:
            changed.append(path)
    changed.extend(install_board_fixtures(nuttx_root))
    return changed


def package_images(app_bin: Path, output_dir: Path, header_size: int, platform_id: int) -> list[Path]:
    payload = app_bin.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)
    primary = output_dir / "nxboot-primary-v1-h400.img"
    update = output_dir / "nxboot-update-v2-h400.img"
    primary.write_bytes(
        wrap_nxboot_image(payload, (1, 0, 0), header_size=header_size, platform_id=platform_id)
    )
    update.write_bytes(
        wrap_nxboot_image(payload, (2, 0, 0), header_size=header_size, platform_id=platform_id)
    )
    return [primary, update]


def build_env(nuttx_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    tools_dir = str((nuttx_root / "tools").resolve())
    existing_path = env.get("PATH", "")
    if existing_path:
        env["PATH"] = tools_dir + os.pathsep + existing_path
    else:
        env["PATH"] = tools_dir
    return env


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, env=env)


def build_variant(nuttx_root: Path, apps_root: Path, variant: str, jobs: int) -> None:
    apps_arg = os.path.relpath(apps_root, nuttx_root)
    env = build_env(nuttx_root)
    _run(
        [
            str(nuttx_root / "tools" / "configure.sh"),
            "-a",
            apps_arg,
            "-l",
            f"nucleo-h743zi:{variant}",
        ],
        cwd=nuttx_root,
        env=env,
    )
    normalize_generated_config(nuttx_root / ".config", apps_arg, f"nucleo-h743zi:{variant}")
    _run(["make", "olddefconfig"], cwd=nuttx_root, env=env)
    _run(["make", f"-j{jobs}"], cwd=nuttx_root, env=env)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nuttx-root", type=Path, required=True)
    parser.add_argument("--apps-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--header-size", type=lambda x: int(x, 0), default=0x400)
    parser.add_argument("--platform-id", type=lambda x: int(x, 0), default=0x0)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--package-only", type=Path, default=None, metavar="APP_BIN")
    args = parser.parse_args()

    changed = patch_nuttx_tree(args.nuttx_root)
    for path in changed:
        print(f"prepared {path}")

    if args.package_only is not None:
        for path in package_images(args.package_only, args.output_dir, args.header_size, args.platform_id):
            print(f"wrote {path}")
        return 0

    if args.prepare_only:
        return 0

    if args.apps_root is None:
        raise SystemExit("--apps-root is required unless --prepare-only or --package-only is used")

    build_variant(args.nuttx_root, args.apps_root, "nxboot-loader", args.jobs)
    loader_elf = args.output_dir / "nxboot-loader.elf"
    loader_bin = args.output_dir / "nxboot-loader.bin"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.nuttx_root / "nuttx", loader_elf)
    shutil.copyfile(args.nuttx_root / "nuttx.bin", loader_bin)

    _run(["make", "distclean"], cwd=args.nuttx_root)
    build_variant(args.nuttx_root, args.apps_root, "nxboot-app", args.jobs)
    app_elf = args.output_dir / "nxboot-app.elf"
    app_bin = args.output_dir / "nxboot-app.bin"
    shutil.copyfile(args.nuttx_root / "nuttx", app_elf)
    shutil.copyfile(args.nuttx_root / "nuttx.bin", app_bin)
    for path in package_images(app_bin, args.output_dir / "images", args.header_size, args.platform_id):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
