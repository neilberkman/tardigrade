#!/usr/bin/env python3
"""Boot external OP-TEE vexpress on Renode and wait for an init marker."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Sequence


DEFAULT_MARKERS = (
    "Primary CPU initializing",
    "Primary CPU switching to normal world boot",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_renode_binary(explicit: str | None) -> Path:
    candidates = []
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


def resolve_elf(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if path.exists():
            return path
        raise SystemExit(f"OP-TEE ELF not found: {path}")
    env = os.environ.get("OPTEE_VEXPRESS_ELF")
    if env:
        path = Path(env).expanduser()
        if path.exists():
            return path
    raise SystemExit("pass --elf or set OPTEE_VEXPRESS_ELF")


def render_resc(elf_path: Path, pty_link: Path) -> str:
    root = repo_root()
    includes = [
        root / "peripherals" / "CFIFlash.cs",
        root / "peripherals" / "ARM_SP804PrimeCellTimer.cs",
    ]
    lines = [f"include @{path}" for path in includes]
    lines.extend(
        [
            "",
            "mach create",
            f"machine LoadPlatformDescription @{root / 'platforms' / 'qemu_vexpress_a9.repl'}",
            f'emulation CreateUartPtyTerminal "u0" "{pty_link}" true',
            "connector Connect sysbus.uart0 u0",
            f"sysbus LoadELF @{elf_path}",
            "start",
        ]
    )
    return "\n".join(lines) + "\n"


def wait_for_path(path: Path, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for PTY link: {path}")


def read_until_any(fd: int, markers: Sequence[str], timeout_s: float) -> tuple[str, str]:
    deadline = time.time() + timeout_s
    needles = [(marker, marker.encode("latin1")) for marker in markers]
    chunks: list[bytes] = []
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
        for marker, needle in needles:
            if needle in joined:
                return marker, joined.decode("latin1", "replace")
    raise SystemExit(
        "timed out waiting for OP-TEE init marker\n\n"
        + b"".join(chunks).decode("latin1", "replace")
    )


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
    elf_path = resolve_elf(args.elf)
    markers = tuple(args.marker) if args.marker else DEFAULT_MARKERS

    with tempfile.TemporaryDirectory(prefix="optee_vexpress_renode_") as temp_dir:
        temp_root = Path(temp_dir)
        pty_link = temp_root / "uart0.pty"
        resc_path = temp_root / "boot.resc"
        resc_path.write_text(render_resc(elf_path, pty_link), encoding="utf-8")
        proc = subprocess.Popen(
            [str(renode_bin), "--console", "--disable-gui", "--execute", f"i @{resc_path}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            wait_for_path(pty_link, args.timeout)
            time.sleep(1.0)
            slave = Path(os.readlink(pty_link))
            fd = os.open(slave, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                marker, output = read_until_any(fd, markers, args.timeout)
            finally:
                os.close(fd)
        finally:
            terminate_process(proc)

        print("OP-TEE reached a boot marker on Renode.")
        print(f"ELF: {elf_path}")
        print(f"Marker: {marker}")
        print()
        print(output.rstrip())
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", help="Path to tee.elf")
    parser.add_argument("--marker", action="append", help="UART marker to wait for; may be provided multiple times")
    parser.add_argument("--renode-bin", help="Path to renode")
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    return run_session(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
