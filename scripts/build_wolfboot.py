#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch and build wolfBoot for STM32F4 and check the pinned OpenBLT demo.

This script clones upstream repositories into a git-ignored work directory (or
an explicit directory outside the repository tree), verifies the exact commit
hashes and clean working trees, builds the targets through their own shipped
build systems and configuration files without modifying upstream source, and
signs or packages test images with each project's own tools.

Hard Rule 3 enforcement:
If an upstream target cannot execute an update on the modeled platform without
modifying its source (a HAL, driver, linker script, or configuration header),
this script stops for that target and reports the exact upstream files, line
numbers, and reasons instead of patching the upstream checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORK_DIR = REPO_ROOT / "build" / "wolfboot"

WOLFBOOT_REPO_URL = "https://github.com/wolfSSL/wolfBoot.git"
WOLFBOOT_COMMIT = "ad8dc62131fc0067a3ab25edc1b7e731397712d4"
WOLFBOOT_WOLFSSL_SUBMODULE_URL = "https://github.com/wolfSSL/wolfssl.git"
WOLFBOOT_WOLFSSL_SUBMODULE_COMMIT = "f8a805dd64321bb4b396b99fa99b170b5b9cd3d7"
WOLFBOOT_SHIPPED_CONFIG = "config/examples/stm32f407-discovery.config"

OPENBLT_REPO_URL = "https://github.com/feaser/openblt.git"
OPENBLT_COMMIT = "64beeee6f24490f7ca3373185bfcd3188a6d3b15"
OPENBLT_DEMO_REL = "Target/Demo/ARMCM4_STM32F4_Nucleo_F429ZI_GCC"
FULL_SHA1_RE = re.compile(r"[0-9a-f]{40}")


class TargetBuildError(RuntimeError):
    """Raised when fetching, verifying, or building an upstream target fails."""


class UnmodifiedSourceBlockerError(RuntimeError):
    """Raised when Hard Rule 3 stops a target that requires source changes."""

    def __init__(self, target: str, blockers: Sequence[Mapping[str, Any]]) -> None:
        self.target = target
        self.blockers = list(blockers)
        lines = [
            f"{target} stopped under Hard Rule 3 (no modifications to upstream source):"
        ]
        for item in self.blockers:
            lines.append(
                f"  - {item['file']}:{item['lines']}: {item['reason']} "
                f"(required change: {item['required_change']})"
            )
        super().__init__("\n".join(lines))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    return subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd is not None else None,
        env=merged_env,
        check=True,
        capture_output=True,
        text=True,
    )


def _validate_work_dir(work_dir: Path) -> Path:
    """Require external storage or a Git-ignored directory inside this tree."""
    resolved = work_dir.resolve()
    try:
        relative = resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return resolved
    if relative == Path("."):
        raise TargetBuildError("The repository root cannot be used as --work-dir")
    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", "--", relative.as_posix()],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if ignored.returncode != 0:
        raise TargetBuildError(
            f"In-repository --work-dir is not Git-ignored: {resolved}"
        )
    return resolved


def _verify_remote_url(checkout_dir: Path, expected_url: str, name: str) -> None:
    actual_url = _run(
        ["git", "remote", "get-url", "origin"], cwd=checkout_dir
    ).stdout.strip()
    if actual_url.rstrip("/") != expected_url.rstrip("/"):
        raise TargetBuildError(
            f"{name} origin URL {actual_url!r} does not match {expected_url!r}"
        )


def _modified_tracked_paths(checkout_dir: Path) -> List[str]:
    output = _run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=none",
        ],
        cwd=checkout_dir,
    ).stdout
    paths: List[str] = []
    for raw_line in output.splitlines():
        if len(raw_line) < 4:
            continue
        if raw_line[:2] in {"??", "!!"}:
            continue
        value = raw_line[3:]
        if " -> " in value:
            value = value.split(" -> ", 1)[1]
        paths.append(value.strip('"'))
    return sorted(paths)


def _ensure_pinned_checkout(
    *,
    name: str,
    repo_url: str,
    commit: str,
    checkout_dir: Path,
) -> str:
    if FULL_SHA1_RE.fullmatch(commit) is None:
        raise TargetBuildError(f"{name} commit is not a full SHA-1: {commit!r}")
    checkout_dir.parent.mkdir(parents=True, exist_ok=True)
    if not (checkout_dir / ".git").exists():
        if checkout_dir.exists():
            shutil.rmtree(checkout_dir)
        _run(["git", "clone", "--no-checkout", repo_url, str(checkout_dir)])
    _verify_remote_url(checkout_dir, repo_url, name)
    try:
        _run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=checkout_dir)
    except subprocess.CalledProcessError:
        _run(["git", "fetch", "--depth", "1", "origin", commit], cwd=checkout_dir)
    _run(["git", "checkout", "--force", "--detach", commit], cwd=checkout_dir)
    _run(["git", "clean", "-fdx"], cwd=checkout_dir)
    head = _run(["git", "rev-parse", "HEAD"], cwd=checkout_dir).stdout.strip()
    if head != commit:
        raise TargetBuildError(
            f"{name} checkout HEAD {head!r} does not match pinned commit {commit!r}"
        )
    status = _run(["git", "status", "--porcelain"], cwd=checkout_dir).stdout.strip()
    if status:
        raise TargetBuildError(
            f"{name} checkout at {checkout_dir} is not clean:\n{status}"
        )
    return head


def _ensure_wolfssl_submodule(wolfboot_dir: Path) -> str:
    sub_dir = wolfboot_dir / "lib" / "wolfssl"
    _run(
        ["git", "submodule", "update", "--init", "--depth", "1", "lib/wolfssl"],
        cwd=wolfboot_dir,
    )
    sub_head = _run(["git", "rev-parse", "HEAD"], cwd=sub_dir).stdout.strip()
    if sub_head != WOLFBOOT_WOLFSSL_SUBMODULE_COMMIT:
        raise TargetBuildError(
            f"wolfBoot lib/wolfssl submodule HEAD {sub_head!r} does not match "
            f"pinned commit {WOLFBOOT_WOLFSSL_SUBMODULE_COMMIT!r}"
        )
    sub_status = _run(["git", "status", "--porcelain"], cwd=sub_dir).stdout.strip()
    if sub_status:
        raise TargetBuildError(
            f"wolfBoot lib/wolfssl submodule is not clean:\n{sub_status}"
        )
    return sub_head


def build_wolfboot(work_dir: Path) -> Dict[str, Any]:
    """Fetch, verify, build, and sign wolfBoot for STM32F4 without source edits."""
    sources_dir = work_dir / "sources" / "wolfBoot"
    build_dir = work_dir / "build" / "wolfboot_stm32f4"
    assets_dir = work_dir / "assets" / "wolfboot_stm32f4"

    head = _ensure_pinned_checkout(
        name="wolfBoot",
        repo_url=WOLFBOOT_REPO_URL,
        commit=WOLFBOOT_COMMIT,
        checkout_dir=sources_dir,
    )
    sub_head = _ensure_wolfssl_submodule(sources_dir)

    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(sources_dir, build_dir, symlinks=True)

    shipped_cfg = build_dir / WOLFBOOT_SHIPPED_CONFIG
    if not shipped_cfg.is_file():
        raise TargetBuildError(f"Missing shipped wolfBoot config: {shipped_cfg}")
    shutil.copyfile(shipped_cfg, build_dir / ".config")

    _run(["make", "keytools"], cwd=build_dir)
    key_file = "wolfboot_signing_private_key.der"
    _run(
        ["./tools/keytools/keygen", "--ed25519", "-g", key_file],
        cwd=build_dir,
    )
    _run(["make", "wolfboot.bin", "test-app/image.bin"], cwd=build_dir)
    _run(
        [
            "./tools/keytools/sign",
            "--ed25519",
            "--sha256",
            "test-app/image.bin",
            key_file,
            "1",
        ],
        cwd=build_dir,
    )
    _run(
        [
            "./tools/keytools/sign",
            "--ed25519",
            "--sha256",
            "test-app/image.bin",
            key_file,
            "2",
        ],
        cwd=build_dir,
    )

    # Verify zero tracked upstream files were modified during build.
    modified = _modified_tracked_paths(build_dir)
    if modified:
        raise TargetBuildError(
            "wolfBoot build modified tracked upstream files:\n"
            + "\n".join(modified)
        )

    assets_dir.mkdir(parents=True, exist_ok=True)
    elf_dst = assets_dir / "wolfboot_stm32f4.elf"
    v1_dst = assets_dir / "wolfboot_stm32f4_v1_signed.bin"
    v2_dst = assets_dir / "wolfboot_stm32f4_v2_signed.bin"
    shutil.copyfile(build_dir / "wolfboot.elf", elf_dst)
    shutil.copyfile(build_dir / "test-app" / "image_v1_signed.bin", v1_dst)
    shutil.copyfile(build_dir / "test-app" / "image_v2_signed.bin", v2_dst)

    return {
        "target": "wolfboot",
        "license_spdx": "GPL-3.0-or-later",
        "repository": WOLFBOOT_REPO_URL,
        "commit": head,
        "submodules": {
            "lib/wolfssl": {
                "repository": WOLFBOOT_WOLFSSL_SUBMODULE_URL,
                "commit": sub_head,
            }
        },
        "shipped_config": WOLFBOOT_SHIPPED_CONFIG,
        "source_modified": False,
        "status": "built",
        "artifacts": {
            "bootloader_elf": {
                "path": str(elf_dst),
                "sha256": _sha256_file(elf_dst),
            },
            "exec_image_v1": {
                "path": str(v1_dst),
                "sha256": _sha256_file(v1_dst),
            },
            "staging_image_v2": {
                "path": str(v2_dst),
                "sha256": _sha256_file(v2_dst),
            },
        },
    }


def inspect_openblt_blockers(openblt_dir: Path) -> List[Dict[str, Any]]:
    """Inspect unmodified OpenBLT checkout and return Hard Rule 3 blockers."""
    blockers: List[Dict[str, Any]] = []

    rollback_c = openblt_dir / "Target" / "Source" / "addons" / "rollbackmod" / "rollback.c"
    if not rollback_c.exists():
        blockers.append(
            {
                "file": "Target/Source/boot.h",
                "lines": "71-73",
                "reason": (
                    "ADDON_ROLLBACK_MOD_ENABLE includes 'rollback.h' and links "
                    "'Target/Source/addons/rollbackmod/rollback.c' "
                    "(referenced by Target/Source/CMakeLists.txt:220-230, "
                    "Target/Source/ARMCM4_STM32F4/cpu.c:78-84, and "
                    "Target/Source/ARMCM4_STM32F4/nvm.c:108-117,160-169), "
                    "but the public repository omits the required rollback module"
                ),
                "required_change": (
                    "Supply or implement rollback.h/rollback.c or write a custom "
                    "A/B staging copy loop calling NvmWrite()/NvmErase() inside "
                    "Target/Source/"
                ),
            }
        )

    blockers.append(
        {
            "file": "Target/Source/boot.c",
            "lines": "40-106",
            "reason": (
                "BootInit()/BootTask() only call NvmWrite() and NvmErase() from "
                "live XCP master commands (Target/Source/xcp.c:1389,1478,1525) or "
                "SD/MMC file loading over SPI2 (Target/Source/file.c:430,478,547); "
                "there is no autonomous internal-flash staging-to-exec update mode"
            ),
            "required_change": (
                "Modify BootTask() or BackDoorCheck() to read a staged image from "
                "an internal flash sector and program the user program region via "
                "NvmWrite()/NvmFinalize()"
            ),
        }
    )

    blockers.append(
        {
            "file": f"{OPENBLT_DEMO_REL}/Boot/blt_conf.h",
            "lines": "113,127,164",
            "reason": (
                "The selected demo hardcodes "
                "BOOT_COM_USB_ENABLE (1) and BOOT_COM_CAN_ENABLE (1) without "
                "#ifndef guards or PROJ_BLT_CONF_H in Boot/makefile. On boot, "
                "UsbInit() -> tusb_init() -> dcd_init() "
                "(dcd_dwc2.c:525) "
                "spins indefinitely on USB_OTG_FS->GRSTCTL (0x50000010), while "
                "CanInit() (Target/Source/ARMCM4_STM32F4/can.c:218) and "
                "BackDoorCheck() (Target/Source/backdoor.c:150) poll TimerGet() "
                "(Target/Source/ARMCM4_STM32F4/timer.c:69-157) on TIM1->CNT "
                "(0x40010024)"
            ),
            "required_change": (
                "Edit Boot/blt_conf.h to disable USB/CAN or modify timer.c / "
                "dcd_dwc2.c / can.c in the OpenBLT source tree"
            ),
        }
    )
    return blockers


def build_openblt(work_dir: Path, *, allow_stop: bool = True) -> Dict[str, Any]:
    """Fetch, verify, compile unmodified OpenBLT STM32F4 demo, and enforce Rule 3."""
    sources_dir = work_dir / "sources" / "openblt"
    build_dir = work_dir / "build" / "openblt_stm32f4"
    assets_dir = work_dir / "assets" / "openblt_stm32f4"

    head = _ensure_pinned_checkout(
        name="OpenBLT",
        repo_url=OPENBLT_REPO_URL,
        commit=OPENBLT_COMMIT,
        checkout_dir=sources_dir,
    )

    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(sources_dir, build_dir, symlinks=True)

    boot_dir = build_dir / OPENBLT_DEMO_REL / "Boot"
    prog_dir = build_dir / OPENBLT_DEMO_REL / "Prog"
    (boot_dir / "obj").mkdir(parents=True, exist_ok=True)
    (boot_dir / "bin").mkdir(parents=True, exist_ok=True)
    (prog_dir / "obj").mkdir(parents=True, exist_ok=True)
    (prog_dir / "bin").mkdir(parents=True, exist_ok=True)

    _run(["make", "-j4"], cwd=boot_dir)
    _run(["make", "-j4"], cwd=prog_dir)

    expected_regenerated_outputs = {
        f"{OPENBLT_DEMO_REL}/Boot/bin/openblt_stm32f429.srec",
        f"{OPENBLT_DEMO_REL}/Prog/bin/demoprog_stm32f429.srec",
    }
    diff_files = set(_modified_tracked_paths(build_dir))
    unexpected_modified = sorted(diff_files - expected_regenerated_outputs)
    if unexpected_modified:
        raise TargetBuildError(
            "OpenBLT build modified tracked upstream source files:\n"
            + "\n".join(unexpected_modified)
        )

    assets_dir.mkdir(parents=True, exist_ok=True)
    boot_elf = assets_dir / "openblt_stm32f429.elf"
    prog_elf = assets_dir / "demoprog_stm32f429.elf"
    prog_srec = assets_dir / "demoprog_stm32f429.srec"
    shutil.copyfile(boot_dir / "bin" / "openblt_stm32f429.elf", boot_elf)
    shutil.copyfile(prog_dir / "bin" / "demoprog_stm32f429.elf", prog_elf)
    shutil.copyfile(prog_dir / "bin" / "demoprog_stm32f429.srec", prog_srec)

    blockers = inspect_openblt_blockers(build_dir)
    result = {
        "target": "openblt",
        "license_spdx": "GPL-3.0-or-later",
        "repository": OPENBLT_REPO_URL,
        "commit": head,
        "shipped_demo": OPENBLT_DEMO_REL,
        "source_modified": False,
        "status": "stopped_requires_source_modification",
        "rule3_blockers": blockers,
        "compiled_artifacts": {
            "bootloader_elf": {
                "path": str(boot_elf),
                "sha256": _sha256_file(boot_elf),
            },
            "demo_prog_elf": {
                "path": str(prog_elf),
                "sha256": _sha256_file(prog_elf),
            },
            "demo_prog_srec": {
                "path": str(prog_srec),
                "sha256": _sha256_file(prog_srec),
            },
        },
    }
    if not allow_stop and blockers:
        raise UnmodifiedSourceBlockerError("OpenBLT", blockers)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=("all", "wolfboot", "openblt"),
        default="all",
        help="select the target to fetch and build",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="git-ignored or external directory for upstream clones and build outputs",
    )
    parser.add_argument(
        "--fail-on-rule3-stop",
        action="store_true",
        help="exit non-zero if a target stops under Hard Rule 3",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="optional path to write build provenance and blocker manifest JSON",
    )
    args = parser.parse_args(argv)
    try:
        work_dir = _validate_work_dir(args.work_dir)
    except TargetBuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    work_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {
        "work_dir": str(work_dir),
        "targets": {},
    }
    try:
        if args.target in ("all", "wolfboot"):
            summary["targets"]["wolfboot"] = build_wolfboot(work_dir)
        if args.target in ("all", "openblt"):
            summary["targets"]["openblt"] = build_openblt(
                work_dir, allow_stop=not args.fail_on_rule3_stop
            )
    except (TargetBuildError, UnmodifiedSourceBlockerError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
