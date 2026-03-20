#!/usr/bin/env python3
"""Boot external OP-TEE vexpress on Renode and wait for an init marker."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Mapping, Sequence

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


DEFAULT_MARKERS = (
    "Primary CPU initializing",
    "Primary CPU switching to normal world boot",
)
DEFAULT_DTB_LOAD_ADDR = 0x40000000
SMALL_PAGE_SIZE = 4 * 1024


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


def resolve_dtc_binary(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    which = shutil.which("dtc")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit("dtc binary not found; pass --dtc-bin or add it to PATH")


def resolve_dtb_source(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if path.exists():
            return path
        raise SystemExit(f"DTB source not found: {path}")
    return repo_root() / "scripts" / "optee_qemu_virt_arm32_renode.dts"


def compile_dtb(dtc_bin: Path, dts_path: Path, dtb_path: Path) -> None:
    subprocess.run(
        [str(dtc_bin), "-I", "dts", "-O", "dtb", "-o", str(dtb_path), str(dts_path)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def get_name(obj: object) -> str:
    name = getattr(obj, "name", "")
    try:
        return name.decode()
    except (AttributeError, UnicodeDecodeError):
        return str(name)


def get_symbol_value(elffile: ELFFile, name: str) -> int:
    local_hits = 0
    found = None
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            symbol_name = get_name(symbol)
            if symbol_name != name:
                continue
            bind = symbol["st_info"]["bind"]
            if bind == "STB_GLOBAL":
                return int(symbol["st_value"])
            if bind == "STB_LOCAL":
                found = int(symbol["st_value"])
                local_hits += 1
    if found is None or local_hits > 1:
        raise SystemExit(f"unable to resolve unique symbol {name!r} from tee.elf")
    return found


def resolve_symbol_values(elf_path: Path, names: Sequence[str]) -> dict[str, int]:
    with elf_path.open("rb") as stream:
        elffile = ELFFile(stream)
        return {name: get_symbol_value(elffile, name) for name in names}


def get_sections(elffile: ELFFile, pad_to: int, dump_names: re.Pattern[str]) -> bytes:
    last_end = 0
    blob = bytearray()
    for section in elffile.iter_sections():
        section_name = get_name(section)
        if (
            section["sh_type"] == "SHT_NOBITS"
            or not (section["sh_flags"] & SH_FLAGS.SHF_ALLOC)
            or not dump_names.match(section_name)
        ):
            continue
        if last_end == 0:
            blob = bytearray(section.data())
        else:
            if section["sh_addr"] > last_end:
                blob += bytearray(section["sh_addr"] - last_end)
            blob += section.data()
        last_end = int(section["sh_addr"]) + int(section["sh_size"])
    if pad_to > last_end:
        blob += bytearray(pad_to - last_end)
    return bytes(blob)


def get_pageable_bin(elffile: ELFFile) -> bytes:
    return get_sections(elffile, 0, re.compile(r"^\..*_(pageable|init)$"))


def get_reloc_bin(elffile: ELFFile) -> bytes:
    link_address = get_symbol_value(elffile, "__text_start")
    addrs: list[int] = []
    expected_type = ENUM_RELOC_TYPE_ARM["R_ARM_RELATIVE"]
    for section in elffile.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        for relocation in section.iter_relocations():
            reloc_type = relocation["r_info_type"]
            if reloc_type == 0:
                continue
            if reloc_type != expected_type:
                raise SystemExit(f"unexpected relocation type 0x{reloc_type:x} in tee.elf")
            addrs.append(int(relocation["r_offset"]) - link_address)
    addrs.sort()
    return b"".join(struct.pack("<I", address) for address in addrs)


def get_hashes_bin(elffile: ELFFile) -> bytes:
    pageable_bin = get_pageable_bin(elffile)
    if len(pageable_bin) % SMALL_PAGE_SIZE != 0:
        raise SystemExit("OP-TEE pageable area size is not 4K-aligned")
    digests = bytearray()
    for offset in range(0, len(pageable_bin), SMALL_PAGE_SIZE):
        digests += hashlib.sha256(pageable_bin[offset : offset + SMALL_PAGE_SIZE]).digest()
    return bytes(digests)


def round_up(value: int, multiple: int) -> int:
    if value == 0:
        return 0
    return (((value - 1) // multiple) + 1) * multiple


def build_optee_embdata(elf_path: Path) -> tuple[int, bytes]:
    with elf_path.open("rb") as stream:
        elffile = ELFFile(stream)
        hashes_bin = get_hashes_bin(elffile)
        reloc_bin = get_reloc_bin(elffile)

        num_entries = 2
        hashes_offset = 2 * 4 + num_entries * (2 * 4)
        hashes_padding = round_up(len(hashes_bin), 8) - len(hashes_bin)
        reloc_offset = hashes_offset + len(hashes_bin) + hashes_padding
        reloc_padding = round_up(len(reloc_bin), 8) - len(reloc_bin)
        total_len = reloc_offset + len(reloc_bin) + reloc_padding

        embdata = bytearray(
            struct.pack(
                "<IIIIII",
                total_len,
                num_entries,
                hashes_offset,
                len(hashes_bin),
                reloc_offset,
                len(reloc_bin),
            )
        )
        embdata += hashes_bin
        embdata += bytearray(hashes_padding)
        embdata += reloc_bin
        embdata += bytearray(reloc_padding)
        return get_symbol_value(elffile, "__data_end"), bytes(embdata)


def make_monitor_string(script: str) -> str:
    hook = f"exec({script!r})"
    return hook.replace('"', '\\"')


def render_va2pa_compat_hook(symbols: Mapping[str, int]) -> str:
    static_memory_map = symbols["static_memory_map"]
    script = "\n".join(
        [
            "addr = self.GetRegister(0).RawValue",
            "out_ptr = self.GetRegister(1).RawValue",
            f"count = int(machine.SystemBus.ReadDoubleWord(0x{static_memory_map:X}, self))",
            f"map_ptr = machine.SystemBus.ReadDoubleWord(0x{static_memory_map + 8:X}, self)",
            "translated = 0",
            "found = False",
            "for index in range(count):",
            "    entry = map_ptr + index * 24",
            "    pa = machine.SystemBus.ReadDoubleWord(entry + 8, self)",
            "    va = machine.SystemBus.ReadDoubleWord(entry + 12, self)",
            "    size = machine.SystemBus.ReadDoubleWord(entry + 16, self)",
            "    if size == 0:",
            "        continue",
            "    if addr >= va and addr < va + size:",
            "        if pa != 0:",
            "            translated = (pa + (addr - va)) & 0xFFFFFFFF",
            "            found = True",
            "        break",
            "if not found:",
            "    registered = machine.SystemBus.WhatIsAt(addr, self)",
            "    if registered is not None:",
            "        translated = addr & 0xFFFFFFFF",
            "        found = True",
            "if found:",
            "    machine.SystemBus.WriteDoubleWord(out_ptr, translated, self)",
            "    self.SetCompatRegister32(0, 1)",
            "else:",
            "    self.SetCompatRegister32(0, 0)",
            "self.PC = self.LR",
        ]
    )
    return make_monitor_string(script)


def render_resc(
    elf_path: Path,
    dtb_path: Path,
    embdata_path: Path,
    embdata_load_addr: int,
    pty_link: Path,
    dtb_load_addr: int,
    symbols: Mapping[str, int],
) -> str:
    root = repo_root()
    includes = [
        root / "peripherals" / "CFIFlash.cs",
        root / "peripherals" / "ARM_SP804PrimeCellTimer.cs",
        root / "peripherals" / "QEMUFwCfg.cs",
        root / "peripherals" / "PL061Stub.cs",
        root / "peripherals" / "QEMUVirtARMv7A.cs",
    ]
    lines = [f"include @{path}" for path in includes]
    lines.extend(
        [
            "",
            "mach create",
            f"machine LoadPlatformDescription @{root / 'platforms' / 'qemu_virt_a15.repl'}",
            f'emulation CreateUartPtyTerminal "u0" "{pty_link}" true',
            "connector Connect sysbus.uart1 u0",
            f"sysbus LoadBinary @{dtb_path} 0x{dtb_load_addr:X}",
            f"sysbus LoadELF @{elf_path}",
            f"sysbus LoadBinary @{embdata_path} 0x{embdata_load_addr:X}",
            "sysbus.cpu SetRegister 0 0x0",
            "sysbus.cpu SetRegister 1 0x0",
            f"sysbus.cpu SetRegister 2 0x{dtb_load_addr:X}",
            f'sysbus.cpu AddHook 0x{symbols["arch_va2pa_helper"] & ~1:X} "{render_va2pa_compat_hook(symbols)}"',
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
    dts_path = resolve_dtb_source(args.dts)
    dtc_bin = resolve_dtc_binary(args.dtc_bin)
    markers = tuple(args.marker) if args.marker else DEFAULT_MARKERS

    with tempfile.TemporaryDirectory(prefix="optee_vexpress_renode_") as temp_dir:
        temp_root = Path(temp_dir)
        pty_link = temp_root / "uart0.pty"
        resc_path = temp_root / "boot.resc"
        dtb_path = temp_root / "optee-qemu-virt.dtb"
        embdata_path = temp_root / "optee-boot-embdata.bin"
        embdata_load_addr, embdata_blob = build_optee_embdata(elf_path)
        symbols = resolve_symbol_values(elf_path, ("arch_va2pa_helper", "static_memory_map"))
        compile_dtb(dtc_bin, dts_path, dtb_path)
        embdata_path.write_bytes(embdata_blob)
        resc_path.write_text(
            render_resc(
                elf_path,
                dtb_path,
                embdata_path,
                embdata_load_addr,
                pty_link,
                args.dtb_load_addr,
                symbols,
            ),
            encoding="utf-8",
        )
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
    parser.add_argument("--dts", help="Path to qemu-virt arm32 DTS")
    parser.add_argument("--dtc-bin", help="Path to dtc")
    parser.add_argument("--dtb-load-addr", type=lambda value: int(value, 0), default=DEFAULT_DTB_LOAD_ADDR)
    parser.add_argument("--marker", action="append", help="UART marker to wait for; may be provided multiple times")
    parser.add_argument("--renode-bin", help="Path to renode")
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    return run_session(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
