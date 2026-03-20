#!/usr/bin/env python3
"""Boot external qemu_arm64 U-Boot on Renode and stop at a shell prompt.

This stays license-clean for tardigrade: it does not vendor any U-Boot bits.
It expects the caller to point at an externally built qemu_arm64 U-Boot ELF.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Sequence


AUTOBOOT_MARKER = "Hit any key to stop autoboot"
PROMPT_MARKER = "=> "
HELP_MARKER = "help"


class UartWaitTimeout(TimeoutError):
    def __init__(self, marker: str, partial_output: str):
        super().__init__(f"timed out waiting for UART marker: {marker!r}")
        self.marker = marker
        self.partial_output = partial_output


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_renode_repo() -> Path | None:
    env = os.environ.get("RENODE_REPO")
    if env:
        path = Path(env).expanduser()
        if path.exists():
            return path
    sibling = repo_root().parent / "renode"
    if sibling.exists():
        return sibling
    return None


def default_uboot_elf() -> Path | None:
    env = os.environ.get("UBOOT_QEMU_ARM64_ELF")
    if env:
        path = Path(env).expanduser()
        if path.exists():
            return path
    sibling = repo_root().parent / "uboot-fault-lab" / "u-boot" / "u-boot"
    if sibling.exists():
        return sibling
    return None


def resolve_renode_binary(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    which = shutil.which("renode")
    if which:
        candidates.append(Path(which))
    local = Path.home() / ".local" / "bin" / "renode"
    candidates.append(local)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit("renode binary not found; pass --renode-bin or add it to PATH")


def resolve_renode_platform(explicit_platform: str | None, explicit_repo: str | None) -> Path:
    if explicit_platform:
        platform = Path(explicit_platform).expanduser()
        if platform.exists():
            return platform
        raise SystemExit(f"Renode platform not found: {platform}")

    local_platform = repo_root() / "platforms" / "qemu_virt_a53.repl"
    if local_platform.exists():
        return local_platform

    repo_candidate: Path | None = None
    if explicit_repo:
        repo_candidate = Path(explicit_repo).expanduser()
    else:
        repo_candidate = default_renode_repo()

    if repo_candidate is None:
        raise SystemExit("could not find a Renode repo checkout; pass --renode-repo or --renode-platform")

    platform = repo_candidate / "platforms" / "cpus" / "cortex-a53-gicv2.repl"
    if not platform.exists():
        raise SystemExit(f"Renode platform not found: {platform}")
    return platform


def resolve_uboot_elf(explicit: str | None) -> Path:
    if explicit:
        elf = Path(explicit).expanduser()
        if elf.exists():
            return elf
        raise SystemExit(f"U-Boot ELF not found: {elf}")
    candidate = default_uboot_elf()
    if candidate is None:
        raise SystemExit("could not find qemu_arm64 U-Boot ELF; pass --u-boot-elf")
    return candidate


def load_dts_template() -> str:
    return (repo_root() / "scripts" / "uboot_qemu_arm64_renode.dts").read_text(encoding="utf-8")


def render_resc(platform_path: Path, fw_cfg_cs_path: Path, dtb_path: Path, elf_path: Path, pty_link: Path) -> str:
    cfi_cs_path = repo_root() / "peripherals" / "CFIFlash.cs"
    pl061_cs_path = repo_root() / "peripherals" / "PL061Stub.cs"
    return textwrap.dedent(
        f"""\
        include @{cfi_cs_path}
        include @{fw_cfg_cs_path}
        include @{pl061_cs_path}

        mach create
        machine LoadPlatformDescription @{platform_path}
        emulation CreateUartPtyTerminal "u0" "{pty_link}" true
        connector Connect sysbus.uart0 u0
        sysbus LoadELF @{elf_path}
        sysbus LoadBinary @{dtb_path} 0x40000000
        start
        """
    )


def compile_dtb(dts_text: str, dtb_path: Path, dtc_binary: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".dts", prefix="uboot_qemu_arm64_", delete=False) as handle:
        handle.write(dts_text)
        dts_path = Path(handle.name)
    try:
        proc = subprocess.run(
            [dtc_binary, "-I", "dts", "-O", "dtb", "-o", str(dtb_path), str(dts_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise SystemExit(
                "dtc failed while compiling the Renode-friendly DTB:\n"
                f"{proc.stdout}{proc.stderr}"
            )
    finally:
        dts_path.unlink(missing_ok=True)


def wait_for_path(path: Path, timeout_s: float) -> Path:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if path.exists():
            return path
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for PTY link: {path}")


def read_until(fd: int, marker: str, timeout_s: float) -> str:
    deadline = time.time() + timeout_s
    chunks: list[bytes] = []
    needle = marker.encode("latin1")
    while time.time() < deadline:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            time.sleep(0.05)
            continue
        if not chunk:
            time.sleep(0.05)
            continue
        chunks.append(chunk)
        joined = b"".join(chunks)
        if needle in joined:
            return joined.decode("latin1", "replace")
    raise UartWaitTimeout(marker, b"".join(chunks).decode("latin1", "replace"))


def terminate_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_session(args: argparse.Namespace) -> int:
    renode_bin = resolve_renode_binary(args.renode_bin)
    platform_path = resolve_renode_platform(args.renode_platform, args.renode_repo)
    elf_path = resolve_uboot_elf(args.u_boot_elf)
    dtc_binary = args.dtc or shutil.which("dtc")
    if not dtc_binary:
        raise SystemExit("dtc not found; install device-tree-compiler or pass --dtc")

    with tempfile.TemporaryDirectory(prefix="uboot_qemu_arm64_renode_") as temp_dir:
        temp_root = Path(temp_dir)
        dtb_path = temp_root / "renode-qemu-arm64-minimal.dtb"
        pty_link = temp_root / "uart0.pty"
        resc_path = temp_root / "boot.resc"
        renode_log_path = temp_root / "renode.log"

        compile_dtb(load_dts_template(), dtb_path, dtc_binary)
        resc_path.write_text(
            render_resc(
                platform_path=platform_path,
                fw_cfg_cs_path=repo_root() / "peripherals" / "QEMUFwCfg.cs",
                dtb_path=dtb_path,
                elf_path=elf_path,
                pty_link=pty_link,
            ),
            encoding="utf-8",
        )

        with renode_log_path.open("w", encoding="utf-8") as renode_log:
            proc = subprocess.Popen(
                [str(renode_bin), "--console", "--disable-gui", "--execute", f"i @{resc_path}"],
                stdin=subprocess.PIPE,
                stdout=renode_log,
                stderr=subprocess.STDOUT,
                text=True,
            )

            try:
                wait_for_path(pty_link, timeout_s=args.timeout)
                # Opening the PTY too early on macOS can miss the console stream.
                time.sleep(1.0)
                slave = Path(os.readlink(pty_link))
                fd = os.open(slave, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                try:
                    banner = read_until(fd, AUTOBOOT_MARKER, timeout_s=args.timeout)
                    os.write(fd, b"\n")
                    prompt = read_until(fd, PROMPT_MARKER, timeout_s=args.timeout)
                    os.write(fd, b"help\n")
                    help_text = read_until(fd, PROMPT_MARKER, timeout_s=args.timeout)
                finally:
                    os.close(fd)
            except (TimeoutError, OSError) as exc:
                terminate_process(proc)
                log_text = renode_log_path.read_text(encoding="utf-8", errors="replace")
                partial_uart = ""
                if isinstance(exc, UartWaitTimeout):
                    partial_uart = exc.partial_output
                raise SystemExit(
                    "Renode U-Boot bringup failed.\n"
                    f"Reason: {exc}\n\n"
                    f"Partial UART:\n{partial_uart}\n\n"
                    f"Renode log:\n{log_text}"
                ) from exc
            finally:
                terminate_process(proc)

        if not renode_log_path.exists():
            log_text = ""
        else:
            log_text = renode_log_path.read_text(encoding="utf-8", errors="replace")

        if "Errors during compilation or loading" in log_text:
            raise SystemExit(f"Renode failed to load the bringup script:\n{log_text}")

        if "No QEMU firmware device" in banner:
            print("warning: fw_cfg probe still failed", file=sys.stderr)

        print("U-Boot reached shell prompt on Renode.")
        print(f"Renode platform: {platform_path}")
        print(f"U-Boot ELF: {elf_path}")
        print()
        print("Banner:")
        print(banner.rstrip())
        print()
        print("Prompt:")
        print(prompt.rstrip())
        print()
        print("Help excerpt:")
        print(help_text.rstrip())
        if HELP_MARKER not in help_text:
            raise SystemExit("U-Boot help output was not observed after reaching the prompt")
        return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--u-boot-elf", dest="u_boot_elf", help="Path to an externally built qemu_arm64 U-Boot ELF")
    parser.add_argument("--renode-bin", help="Path to the renode binary")
    parser.add_argument("--renode-repo", help="Path to a Renode repo checkout (used to locate the A53 platform file)")
    parser.add_argument("--renode-platform", help="Explicit path to cortex-a53-gicv2.repl")
    parser.add_argument("--dtc", help="Path to the dtc binary")
    parser.add_argument("--timeout", type=float, default=20.0, help="Timeout for PTY creation and UART milestones")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return run_session(args)


if __name__ == "__main__":
    raise SystemExit(main())
