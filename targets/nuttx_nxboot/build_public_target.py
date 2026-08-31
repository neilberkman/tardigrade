#!/usr/bin/env python3
"""Build the real nucleo-h743zi nxboot target from upstream NuttX.

Requires NuttX with nxboot board support (apache/nuttx PR #18509, merged
2026-03-11).  Legacy local-patching support has been removed.
"""

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


NXBOOT_SECTOR_SIZE = 0x20000
NXBOOT_SLOT_SIZE = 0x80000


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


def verify_nxboot_support(nuttx_root: Path) -> None:
    """Verify the NuttX tree has upstream nxboot board support."""
    kconfig = nuttx_root / "arch" / "arm" / "src" / "stm32h7" / "Kconfig"
    if not kconfig.exists() or "STM32_APP_FORMAT_NXBOOT" not in kconfig.read_text():
        raise RuntimeError(
            "NuttX tree missing nxboot support. Use NuttX master from after "
            "2026-03-11 (PR #18509)."
        )


def _next_sector_image_payload(payload: bytes, header_size: int) -> bytes:
    """Pad a real app payload to the next STM32H7 erase-sector boundary."""
    total = int(header_size) + len(payload)
    target = ((total // NXBOOT_SECTOR_SIZE) + 1) * NXBOOT_SECTOR_SIZE
    if target > NXBOOT_SLOT_SIZE:
        raise ValueError(
            "sector-boundary image would exceed the nxboot slot: "
            "0x{:X} > 0x{:X}".format(target, NXBOOT_SLOT_SIZE)
        )
    return payload + (b"\xFF" * (target - total))


def package_images(
    app_bin: Path,
    output_dir: Path,
    header_size: int,
    platform_id: int,
    image_layout: str = "baseline",
) -> list[Path]:
    if image_layout not in {"baseline", "sector_boundary"}:
        raise ValueError("unsupported nxboot image layout: {}".format(image_layout))
    payload = app_bin.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = "" if image_layout == "baseline" else "-sector-boundary"
    primary = output_dir / "nxboot-primary-v1-h400{}.img".format(suffix)
    update = output_dir / "nxboot-update-v2-h400{}.img".format(suffix)
    update_payload = (
        payload
        if image_layout == "baseline"
        else _next_sector_image_payload(payload, header_size)
    )
    primary.write_bytes(
        wrap_nxboot_image(payload, (1, 0, 0), header_size=header_size, platform_id=platform_id)
    )
    update.write_bytes(
        wrap_nxboot_image(
            update_payload,
            (2, 0, 0),
            header_size=header_size,
            platform_id=platform_id,
        )
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


def ensure_host_tools() -> None:
    if shutil.which("kconfig-tweak") is None:
        raise RuntimeError(
            "kconfig-tweak not found on PATH; install kconfig-frontends or provide "
            "kconfig-tweak before building NuttX."
        )


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, env=env)


def build_variant(nuttx_root: Path, apps_root: Path, variant: str, jobs: int) -> None:
    apps_arg = os.path.relpath(apps_root, nuttx_root)
    ensure_host_tools()
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
    parser.add_argument(
        "--image-layout",
        choices=("baseline", "sector_boundary"),
        default="baseline",
        help=(
            "Package the ordinary pair or a real-app pair whose update image "
            "ends at the next STM32H7 erase-sector boundary."
        ),
    )
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--package-only", type=Path, default=None, metavar="APP_BIN")
    args = parser.parse_args()
    args.nuttx_root = args.nuttx_root.resolve()
    if args.apps_root is not None:
        args.apps_root = args.apps_root.resolve()
    args.output_dir = args.output_dir.resolve()

    verify_nxboot_support(args.nuttx_root)

    if args.package_only is not None:
        for path in package_images(
            args.package_only,
            args.output_dir,
            args.header_size,
            args.platform_id,
            args.image_layout,
        ):
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
    for path in package_images(
        app_bin,
        args.output_dir / "images",
        args.header_size,
        args.platform_id,
        args.image_layout,
    ):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
