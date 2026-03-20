#!/usr/bin/env python3
"""Boot external OP-TEE vexpress on Renode and wait for an init marker."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import select
import shutil
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Sequence

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


DEFAULT_MARKERS = (
    "OPTEE_STAGE:1",
    "OPTEE_STAGE:2",
    "OPTEE_STAGE:3",
    "OPTEE_STAGE:4",
    "OPTEE_STAGE:10",
    "OPTEE_STAGE:11",
    "OPTEE_STAGE:12",
    "OPTEE_STAGE:13",
    "OPTEE_STAGE:14",
    "OPTEE_STAGE:15",
    "OPTEE_STAGE:16",
    "OPTEE_STAGE:17",
    "OPTEE_STAGE:18",
    "OPTEE_STAGE:19",
)
DEFAULT_DTB_LOAD_ADDR = 0x7FE00000
SMALL_PAGE_SIZE = 4 * 1024
OPTEE_STAGE_EARLY_INITCALLS = 1
OPTEE_STAGE_SERVICE_INITCALLS = 2
OPTEE_STAGE_DRIVER_INITCALLS = 3
OPTEE_STAGE_BOOT_THREAD = 4
OPTEE_STAGE_BOOT_EARLY = 10
OPTEE_STAGE_CONSOLE_INIT = 11
OPTEE_STAGE_BOOT_RUNTIME = 12
OPTEE_STAGE_BOOT_FINAL = 13
OPTEE_STAGE_PL011_INIT = 14
OPTEE_STAGE_PL011_FLUSH = 15
OPTEE_STAGE_REGISTER_SERIAL_CONSOLE = 16
OPTEE_STAGE_PHYS_TO_VIRT_IO = 17
OPTEE_STAGE_IO_PA_OR_VA_RETURN = 18
OPTEE_STAGE_PL011_POST_IO = 19
OPTEE_STAGE_CONFIGURE_CONSOLE_FROM_DT = 20
OPTEE_STAGE_PL011_PUTC = 21
OPTEE_STAGE_ARCH_VA2PA = 22
OPTEE_STAGE_VIRT_TO_PHYS = 23
OPTEE_STAGE_CORE_MMU_DUPLICATE_MAP = 24
OPTEE_STAGE_ASSERT_BREAK = 25
MIN_STARTUP_TIMEOUT = 45.0


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
    values = get_symbol_values(elffile, name)
    if not values:
        raise SystemExit(f"unable to resolve unique symbol {name!r} from tee.elf")
    if len(values) == 1:
        return values[0]
    if name in {"fdt32_ld"}:
        return max(values)
    raise SystemExit(f"unable to resolve unique symbol {name!r} from tee.elf")


def get_symbol_values(elffile: ELFFile, name: str) -> list[int]:
    local_hits: list[int] = []
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            symbol_name = get_name(symbol)
            if symbol_name != name:
                continue
            bind = symbol["st_info"]["bind"]
            if bind in ("STB_GLOBAL", "STB_WEAK"):
                return [int(symbol["st_value"])]
            if bind == "STB_LOCAL":
                local_hits.append(int(symbol["st_value"]))
    return sorted(set(local_hits))


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


def hook_address(symbol_value: int) -> int:
    return symbol_value & ~0x1


def find_marker_in_output(output: bytes, markers: Sequence[str]) -> str | None:
    patterns = [
        (
            marker,
            re.compile(rb"(?<![0-9A-Za-z_:])" + re.escape(marker.encode("latin1")) + rb"(?![0-9A-Za-z_])"),
        )
        for marker in sorted(markers, key=len, reverse=True)
    ]
    for marker, pattern in patterns:
        if pattern.search(output):
            return marker
    return None


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


def render_resc(
    elf_path: Path,
    dtb_path: Path,
    embdata_path: Path,
    embdata_load_addr: int,
    pty_link: Path,
    dtb_load_addr: int,
    symbols: Mapping[str, int],
    fdt32_ld_hooks: Sequence[int],
    fdt64_ld_hooks: Sequence[int],
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
    fdt32_hook_lines = [
        f'sysbus.cpu AddHook 0x{hook_address(address):X} "self.ReturnFdt32LoadTranslatedOrContinue(0)"'
        for address in fdt32_ld_hooks
    ]
    fdt64_hook_lines = [
        f'sysbus.cpu AddHook 0x{hook_address(address):X} "self.ReturnFdt64LoadTranslatedOrContinue(0)"'
        for address in fdt64_ld_hooks
    ]
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
            f'sysbus.cpu OpteeStaticMemoryMapAddress 0x{symbols["static_memory_map"]:X}',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["arch_va2pa_helper"]):X} "self.AnnounceBootStage({OPTEE_STAGE_ARCH_VA2PA}); self.ReturnArchVa2PaHelperResultOrContinue(0, 1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["virt_to_phys"]):X} "self.AnnounceBootStage({OPTEE_STAGE_VIRT_TO_PHYS}); self.ReturnTranslatedPhysicalAddressOrContinue(0)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["core_mmu_map_region"]) + 0xD4:X} "self.AnnounceBootStage({OPTEE_STAGE_CORE_MMU_DUPLICATE_MAP}); self.SkipCoreMmuDuplicateMapOrContinue(0x{hook_address(symbols["core_mmu_map_region"]) + 0x124:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["_assert_break"]):X} "self.AnnounceBootStage({OPTEE_STAGE_ASSERT_BREAK}); self.ReturnFromFunctionIfMmuEnabled()"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["boot_init_primary_early"]):X} "self.AnnounceBootStage({OPTEE_STAGE_BOOT_EARLY})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["plat_console_init"]):X} "self.AnnounceBootStage({OPTEE_STAGE_CONSOLE_INIT}); self.ReturnFromFunctionIfMmuEnabled()"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["boot_init_primary_runtime"]):X} "self.AnnounceBootStage({OPTEE_STAGE_BOOT_RUNTIME})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["boot_init_primary_final"]):X} "self.AnnounceBootStage({OPTEE_STAGE_BOOT_FINAL})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["pl011_init"]):X} "self.AnnounceBootStage({OPTEE_STAGE_PL011_INIT})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["pl011_init"]) + 0x18:X} "self.AnnounceBootStage({OPTEE_STAGE_PL011_POST_IO})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["pl011_flush"]):X} "self.AnnounceBootStage({OPTEE_STAGE_PL011_FLUSH}); self.ReturnFromFunctionIfMmuEnabled()"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["pl011_putc"]):X} "self.AnnounceBootStage({OPTEE_STAGE_PL011_PUTC}); self.EmitCompatCharAndReturnIfMmuEnabled(1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["register_serial_console"]):X} "self.AnnounceBootStage({OPTEE_STAGE_REGISTER_SERIAL_CONSOLE})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["phys_to_virt_io"]):X} "self.AnnounceBootStage({OPTEE_STAGE_PHYS_TO_VIRT_IO}); self.ReturnVirtualAddressForPhysicalOrContinue(0)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["io_pa_or_va"]) + 0x30:X} "self.AnnounceBootStage({OPTEE_STAGE_IO_PA_OR_VA_RETURN})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["configure_console_from_dt"]):X} "self.AnnounceBootStage({OPTEE_STAGE_CONFIGURE_CONSOLE_FROM_DT}); self.ReturnCompatValue32IfMmuEnabled(0)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_open_into"]):X} "self.TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled(0); self.TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled(1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_open_into"]) + 0x6E:X} "self.CompleteFdtOpenIntoHeaderFixupIfMmuEnabled(0x{hook_address(symbols["fdt_open_into"]) + 0x84:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_move"]):X} "self.TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled(0); self.TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled(1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_move"]) + 0x20:X} "self.CompleteCompatMemmoveFromRegistersIfMmuEnabled(5, 4, 2, 0x{hook_address(symbols["fdt_move"]) + 0x24:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["memcpy"]):X} "self.ReturnTranslatedMemcpyOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["memmove"]):X} "self.ReturnTranslatedMemmoveOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["memset"]):X} "self.ReturnTranslatedMemsetOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["memchr"]):X} "self.ReturnTranslatedMemchrOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["memcmp"]):X} "self.ReturnTranslatedMemcmpOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["strchr"]):X} "self.ReturnTranslatedStrchrOrContinue(0, 1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["strlen"]):X} "self.ReturnTranslatedStrlenOrContinue(0)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["strnlen"]):X} "self.ReturnTranslatedStrnlenOrContinue(0, 1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["strcmp"]):X} "self.ReturnTranslatedStrcmpOrContinue(0, 1)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["strncmp"]):X} "self.ReturnTranslatedStrncmpOrContinue(0, 1, 2)"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_packblocks_"]) + 0x10:X} "self.StoreRegister32ToTranslatedMemoryAndJump(5, 12, 0, 0x{hook_address(symbols["fdt_packblocks_"]) + 0x12:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_packblocks_"]) + 0x1C:X} "self.StoreRegister32ToTranslatedMemoryAndJump(5, 32, 0, 0x{hook_address(symbols["fdt_packblocks_"]) + 0x1E:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_splice_struct_"]) + 0x20:X} "self.StoreRegister32ToTranslatedMemoryAndJump(4, 36, 0, 0x{hook_address(symbols["fdt_splice_struct_"]) + 0x22:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_splice_struct_"]) + 0x30:X} "self.StoreRegister32ToTranslatedMemoryAndJump(4, 12, 0, 0x{hook_address(symbols["fdt_splice_struct_"]) + 0x32:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_add_property_"]) + 0xE8:X} "self.StoreRegister32ToTranslatedMemoryAndJump(3, 0, 2, 0x{hook_address(symbols["fdt_add_property_"]) + 0xEA:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_add_property_"]) + 0xEE:X} "self.StoreRegister32ToTranslatedMemoryAndJump(3, 8, 0, 0x{hook_address(symbols["fdt_add_property_"]) + 0xF0:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_add_property_"]) + 0xF6:X} "self.StoreRegister32ToTranslatedMemoryAndJump(3, 4, 0, 0x{hook_address(symbols["fdt_add_property_"]) + 0xF8:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_add_subnode_namelen"]) + 0x86:X} "self.StoreRegister32ToTranslatedMemoryWithRegisterOffsetAndJump(4, 9, 0, 3, 0x{hook_address(symbols["fdt_add_subnode_namelen"]) + 0x8A:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_add_subnode_namelen"]) + 0xA2:X} "self.StoreRegister32ToTranslatedMemoryAndJump(5, 4, 3, 0x{hook_address(symbols["fdt_add_subnode_namelen"]) + 0xA4:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_cells"]) + 0x22:X} "self.LoadTranslatedMemoryValue32IntoRegisterAndJump(3, 0, 0, 0x{hook_address(symbols["fdt_cells"]) + 0x24:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_next_tag"]) + 0x1A:X} "self.LoadTranslatedMemoryValue32IntoRegisterAndJump(0, 0, 7, 0x{hook_address(symbols["fdt_next_tag"]) + 0x1E:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_next_tag"]) + 0x54:X} "self.LoadTranslatedMemoryValue8IntoRegisterAndJump(0, 0, 3, 0x{hook_address(symbols["fdt_next_tag"]) + 0x56:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["fdt_next_tag"]) + 0x82:X} "self.LoadTranslatedMemoryValue32IntoRegisterAndJump(0, 0, 1, 0x{hook_address(symbols["fdt_next_tag"]) + 0x84:X})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["call_early_initcalls"]):X} "self.AnnounceBootStage({OPTEE_STAGE_EARLY_INITCALLS})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["call_service_initcalls"]):X} "self.AnnounceBootStage({OPTEE_STAGE_SERVICE_INITCALLS})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["call_driver_initcalls"]):X} "self.AnnounceBootStage({OPTEE_STAGE_DRIVER_INITCALLS})"',
            f'sysbus.cpu AddHook 0x{hook_address(symbols["thread_init_boot_thread"]):X} "self.AnnounceBootStage({OPTEE_STAGE_BOOT_THREAD})"',
            "start",
        ]
    )
    insertion_index = lines.index(
        f'sysbus.cpu AddHook 0x{hook_address(symbols["call_early_initcalls"]):X} "self.AnnounceBootStage({OPTEE_STAGE_EARLY_INITCALLS})"'
    )
    lines[insertion_index:insertion_index] = fdt32_hook_lines
    lines[insertion_index + len(fdt32_hook_lines):insertion_index + len(fdt32_hook_lines)] = fdt64_hook_lines
    return "\n".join(lines) + "\n"


def maybe_open_uart_fd(path: Path | None) -> int | None:
    if path is None or not path.exists():
        return None
    try:
        slave = Path(os.readlink(path))
    except OSError:
        return None
    try:
        return os.open(slave, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return None


def read_until_any_stream(stdout_fd: int, markers: Sequence[str], timeout_s: float, pty_path: Path | None = None) -> tuple[str, str]:
    deadline = time.time() + timeout_s
    chunks: list[bytes] = []
    uart_fd = None
    while time.time() < deadline:
        if uart_fd is None:
            uart_fd = maybe_open_uart_fd(pty_path)
        fds = [stdout_fd]
        if uart_fd is not None:
            fds.append(uart_fd)
        timeout = max(0.0, min(0.25, deadline - time.time()))
        readable, _, _ = select.select(fds, [], [], timeout)
        if not readable:
            continue
        for fd in readable:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            chunks.append(chunk)
            joined = b"".join(chunks)
            marker = find_marker_in_output(joined, markers)
            if marker is not None:
                if uart_fd is not None:
                    os.close(uart_fd)
                return marker, joined.decode("latin1", "replace")
    if uart_fd is not None:
        os.close(uart_fd)
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
        symbols = resolve_symbol_values(
            elf_path,
            (
                "arch_va2pa_helper",
                "virt_to_phys",
                "core_mmu_map_region",
                "_assert_break",
                "static_memory_map",
                "boot_init_primary_early",
                "plat_console_init",
                "boot_init_primary_runtime",
                "boot_init_primary_final",
                "pl011_init",
                "pl011_flush",
                "pl011_putc",
                "register_serial_console",
                "phys_to_virt_io",
                "io_pa_or_va",
                "configure_console_from_dt",
                "fdt_open_into",
                "fdt_move",
                "memcpy",
                "memmove",
                "memset",
                "memchr",
                "memcmp",
                "strchr",
                "strlen",
                "strnlen",
                "strcmp",
                "strncmp",
                "fdt_packblocks_",
                "fdt_splice_struct_",
                "fdt_add_property_",
                "fdt_add_subnode_namelen",
                "fdt_cells",
                "fdt_next_tag",
                "call_early_initcalls",
                "call_service_initcalls",
                "call_driver_initcalls",
                "thread_init_boot_thread",
            ),
        )
        with elf_path.open("rb") as stream:
            fdt32_ld_hooks = get_symbol_values(ELFFile(stream), "fdt32_ld")
        with elf_path.open("rb") as stream:
            fdt64_ld_hooks = get_symbol_values(ELFFile(stream), "fdt64_ld")
        if not fdt32_ld_hooks:
            raise SystemExit("unable to resolve any 'fdt32_ld' symbol from tee.elf")
        if not fdt64_ld_hooks:
            raise SystemExit("unable to resolve any 'fdt64_ld' symbol from tee.elf")
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
                fdt32_ld_hooks,
                fdt64_ld_hooks,
            ),
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [str(renode_bin), "--console", "--disable-gui", "--execute", f"i @{resc_path}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            if proc.stdout is None:
                raise SystemExit("failed to capture Renode stdout")
            marker, output = read_until_any_stream(
                proc.stdout.fileno(),
                markers,
                max(args.timeout, MIN_STARTUP_TIMEOUT),
                pty_link,
            )
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
