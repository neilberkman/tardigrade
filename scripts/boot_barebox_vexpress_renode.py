#!/usr/bin/env python3
"""Boot external barebox vexpress-ca9 on Renode and wait for a shell prompt."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Sequence


PROMPT_MARKER = "barebox@V2P-CA9:/"


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


def resolve_image(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if path.exists():
            return path
        raise SystemExit(f"barebox image not found: {path}")
    env = os.environ.get("BAREBOX_VEXPRESS_IMG")
    if env:
        path = Path(env).expanduser()
        if path.exists():
            return path
    raise SystemExit("pass --image or set BAREBOX_VEXPRESS_IMG")


def render_resc(image_path: Path, pty_link: Path) -> str:
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
            f"sysbus LoadBinary @{image_path} 0x80000000",
            "cpu PC 0x80000000",
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


def read_until(fd: int, marker: str, timeout_s: float) -> str:
    deadline = time.time() + timeout_s
    needle = marker.encode("latin1")
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
        if needle in joined:
            return joined.decode("latin1", "replace")
    raise SystemExit(
        f"timed out waiting for UART marker {marker!r}\n\n"
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
    image_path = resolve_image(args.image)

    with tempfile.TemporaryDirectory(prefix="barebox_vexpress_renode_") as temp_dir:
        temp_root = Path(temp_dir)
        pty_link = temp_root / "uart0.pty"
        resc_path = temp_root / "boot.resc"
        resc_path.write_text(render_resc(image_path, pty_link), encoding="utf-8")
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
                banner = read_until(fd, PROMPT_MARKER, args.timeout)
            finally:
                os.close(fd)
        finally:
            terminate_process(proc)

        print("barebox reached shell prompt on Renode.")
        print(f"Image: {image_path}")
        print()
        print(banner.rstrip())
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="Path to barebox-vexpress-ca9.img")
    parser.add_argument("--renode-bin", help="Path to renode")
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    return run_session(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
