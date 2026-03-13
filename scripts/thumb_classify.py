"""Classify Thumb halfwords as code vs literal pool data.

Used by fault_plan.py to exclude literal pool entries from instruction-skip
fault points.  NOP'ing a literal pool entry is a data-corruption fault model,
not an instruction-skip model.
"""

from __future__ import annotations

import logging
import sys
from typing import List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# capstone is optional — graceful fallback to "assume all code"
try:
    from capstone import (  # type: ignore[import-untyped]
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        CS_OP_MEM,
        Cs,
    )
    from capstone.arm import ARM_REG_PC  # type: ignore[import-untyped]

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


def _load_segments(elf_path: str) -> List[Tuple[int, int, bytes]]:
    """Load PT_LOAD segments from an ELF file.

    Returns list of (vaddr, vaddr_end, data) tuples.
    """
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

    segments: List[Tuple[int, int, bytes]] = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD" and seg.header.p_filesz > 0:
                vaddr = seg.header.p_vaddr
                data = seg.data()
                segments.append((vaddr, vaddr + len(data), data))
    return segments


def _read_region(
    segments: List[Tuple[int, int, bytes]], start: int, end: int
) -> Optional[bytes]:
    """Read bytes for address range [start, end) from loaded segments."""
    length = end - start
    if length <= 0:
        return None
    buf = bytearray(length)
    filled = 0
    for seg_start, seg_end, seg_data in segments:
        # Overlap between [start, end) and [seg_start, seg_end)
        overlap_start = max(start, seg_start)
        overlap_end = min(end, seg_end)
        if overlap_start >= overlap_end:
            continue
        src_offset = overlap_start - seg_start
        dst_offset = overlap_start - start
        chunk = seg_data[src_offset : src_offset + (overlap_end - overlap_start)]
        buf[dst_offset : dst_offset + len(chunk)] = chunk
        filled += len(chunk)
    if filled == 0:
        return None
    return bytes(buf)


def _try_mapping_symbols(
    elf_path: str, regions: List[Tuple[int, int]]
) -> Optional[Set[int]]:
    """Use ARM ELF mapping symbols ($t/$d) to find data regions.

    Returns set of data addresses, or None if no mapping symbols found.
    """
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

    data_addrs: Set[int] = set()
    found_any = False

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return None

        # Collect all $t (Thumb code) and $d (data) symbols
        mapping_syms: List[Tuple[int, str]] = []
        for sym in symtab.iter_symbols():
            name = sym.name
            if name in ("$t", "$t.0") or name.startswith("$t."):
                mapping_syms.append((sym.entry.st_value, "code"))
                found_any = True
            elif name in ("$d", "$d.0") or name.startswith("$d."):
                mapping_syms.append((sym.entry.st_value, "data"))
                found_any = True

    if not found_any:
        return None

    mapping_syms.sort(key=lambda x: x[0])

    # For each region, walk mapping symbols to find data ranges
    for region_start, region_end in regions:
        # Find the mapping type active at region_start by scanning
        # all symbols up to and including region_start.
        current_type = "code"  # default assumption
        sym_idx = 0
        while sym_idx < len(mapping_syms) and mapping_syms[sym_idx][0] <= region_start:
            current_type = mapping_syms[sym_idx][1]
            sym_idx += 1

        addr = region_start
        while addr < region_end:
            # Check if we hit a new mapping symbol
            while sym_idx < len(mapping_syms) and mapping_syms[sym_idx][0] <= addr:
                current_type = mapping_syms[sym_idx][1]
                sym_idx += 1

            if current_type == "data":
                data_addrs.add(addr)
            addr += 2

    return data_addrs


def find_literal_pools(
    elf_path: str, regions: List[Tuple[int, int]]
) -> Set[int]:
    """Return set of addresses that are literal pool entries (DATA, not CODE).

    Scans target regions for PC-relative loads (ldr rN, [pc, #imm]) and marks
    their targets as literal pool data.  Also marks any halfword that doesn't
    decode as a valid Thumb instruction.

    Tries ARM ELF mapping symbols first (authoritative); falls back to
    capstone disassembly if mapping symbols are absent.

    Args:
        elf_path: Path to ELF file.
        regions: List of (start, end) address tuples to scan.

    Returns:
        Set of addresses that should NOT be used as instruction-skip fault
        points because they contain data, not instructions.
    """
    # Try mapping symbols first (authoritative, no capstone needed)
    try:
        mapping_result = _try_mapping_symbols(elf_path, regions)
        if mapping_result is not None:
            logger.info(
                "Literal pool detection: used ELF mapping symbols, "
                "found %d data halfwords",
                len(mapping_result),
            )
            return mapping_result
    except Exception as exc:
        logger.debug("Mapping symbol scan failed: %s", exc)

    if not HAS_CAPSTONE:
        print(
            "WARNING: capstone not installed — literal pool filtering "
            "disabled. Install with: pip install capstone",
            file=sys.stderr,
        )
        return set()

    return _capstone_classify(elf_path, regions)


def _capstone_classify(
    elf_path: str, regions: List[Tuple[int, int]]
) -> Set[int]:
    """Use capstone disassembly to find literal pool entries."""
    literal_addrs: Set[int] = set()
    segment_map = _load_segments(elf_path)

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    for region_start, region_end in regions:
        code_bytes = _read_region(segment_map, region_start, region_end)
        if not code_bytes:
            continue

        decoded_addrs: Set[int] = set()

        for insn in md.disasm(code_bytes, region_start):
            # Track which addresses are valid instructions
            for offset in range(insn.size):
                decoded_addrs.add(insn.address + offset)

            # Find PC-relative loads: ldr/ldrb/ldrh/ldrd/vldr rN, [pc, #imm]
            mnem = insn.mnemonic
            if (mnem.startswith("ldr") or mnem == "vldr") and len(insn.operands) >= 2:
                op_mem = insn.operands[-1]  # memory operand is last
                if op_mem.type == CS_OP_MEM and op_mem.mem.base == ARM_REG_PC:
                    # Thumb PC-relative: target = (PC+4 & ~3) + disp
                    pc_val = (insn.address + 4) & ~3
                    target = pc_val + op_mem.mem.disp
                    # Mark the literal: 4 bytes for ldr, 8 bytes for ldrd/vldr.d
                    literal_size = 8 if mnem in ("ldrd", "vldr") else 4
                    for off in range(0, literal_size, 2):
                        literal_addrs.add(target + off)

        # Any halfword in the region that wasn't decoded = data
        for addr in range(region_start, region_end, 2):
            if addr not in decoded_addrs:
                literal_addrs.add(addr)

    logger.info(
        "Literal pool detection: capstone found %d data halfwords",
        len(literal_addrs),
    )
    return literal_addrs
