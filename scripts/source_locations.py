# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Resolve observed addresses in the matching executable."""

from __future__ import annotations

from bisect import bisect_right
import fnmatch
from functools import cached_property
import os
from pathlib import Path
import re
import struct
from urllib.parse import quote

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


DEFAULT_DRIVER_FILE_SEGMENTS = frozenset({
    "drivers",
    "hal",
    "nrfx",
    "cmsis",
})

DEFAULT_DRIVER_FILE_PATTERN = re.compile(
    r"^(?:soc_flash|flash_nrf|flash_stm32|nrfx_nvmc|stm32[a-z0-9_]*_hal_flash|"
    r"hal_flash|flash_map|flash_driver|nvm_driver|mram_driver)(?:[._].*|$)",
    re.IGNORECASE,
)

DEFAULT_DRIVER_SYMBOL_PATTERN = re.compile(
    r"^(?:"
    r"nvmc_[a-z0-9_]+|"
    r"nrfx_nvmc_[a-z0-9_]+|"
    r"flash_nrf_[a-z0-9_]+|"
    r"nrf_flash_[a-z0-9_]+|"
    r"_?flash_stm32_[a-z0-9_]+|"
    r"stm32_flash_[a-z0-9_]+|"
    r"HAL_FLASH(?:Ex)?_[A-Za-z0-9_]+|"
    r"FLASH_(?:Program|PageErase|Erase_Sector|MassErase|FlushCaches|WaitForLastOperation)[A-Za-z0-9_]*|"
    r"flash_area_(?:write|erase|read|align|erased_val|get_sectors|get_sector|open|close|get_device|get_device_id)|"
    r"z_impl_flash_[a-z0-9_]+|"
    r"flash_get_page_info[a-z0-9_]*|"
    r"flash_page_foreach|"
    r"flash_(?:write|erase|read|program)(?:_(?:word|words|dword|hword|byte|bytes|page|sector|range|block))?|"
    r"(?:hal|drv)_flash_[a-z0-9_]+|"
    r"flash_(?:hal|drv)_[a-z0-9_]+|"
    r"(?:mram|nvm)_(?:hal|drv)_[a-z0-9_]+|"
    r"spi_flash_[a-z0-9_]+|"
    r"esp_rom_spiflash_[a-z0-9_]+|"
    r"(?:write|program)_(?:dword|word|hword|byte|bytes|page|range)|"
    r"erase_(?:sector|page|block|mass)"
    r")$"
)


def _strip_clone_suffix(name: str) -> str:
    return name.split(".", 1)[0] if name else ""


def is_driver_frame(frame: dict, driver_functions=()) -> bool:
    """Return whether a resolved call-chain frame belongs to the flash driver layer."""
    if not isinstance(frame, dict):
        return False
    fn = str(frame.get("function") or "").strip()
    base_fn = _strip_clone_suffix(fn)
    for pattern in driver_functions or ():
        pat = str(pattern or "").strip()
        if not pat:
            continue
        if fn and (fn == pat or base_fn == pat or fnmatch.fnmatchcase(fn, pat) or fnmatch.fnmatchcase(base_fn, pat)):
            return True
        if frame.get("file") and fnmatch.fnmatchcase(str(frame["file"]), pat):
            return True
    if base_fn and DEFAULT_DRIVER_SYMBOL_PATTERN.match(base_fn):
        return True
    for path_key in ("file", "cu_file"):
        raw_path = frame.get(path_key)
        if not raw_path:
            continue
        norm = str(raw_path).replace("\\", "/")
        parts = [p.lower() for p in norm.split("/") if p]
        if any(seg in DEFAULT_DRIVER_FILE_SEGMENTS for seg in parts[:-1]):
            return True
        if parts and DEFAULT_DRIVER_FILE_PATTERN.match(parts[-1]):
            return True
    return False


def select_caller_frame(call_chain):
    """Return the first frame outside the flash driver layer (without internal 'driver' key)."""
    if not call_chain:
        return None
    for frame in call_chain:
        if not frame.get("driver") and (
            frame.get("function") or frame.get("resolution") == "dwarf"
        ):
            return {k: v for k, v in frame.items() if k not in ("driver", "cu_file")}
    for frame in call_chain:
        if not frame.get("driver"):
            return {k: v for k, v in frame.items() if k not in ("driver", "cu_file")}
    return {k: v for k, v in call_chain[0].items() if k not in ("driver", "cu_file")}


def parse_call_context(call_context):
    """Parse an encoded 'pc@lr@sp@r7@r11@stack_hex' string or dict."""
    if not call_context:
        return None
    if isinstance(call_context, dict):
        try:
            lr = int(str(call_context.get("lr", 0) or 0), 0)
            sp = int(str(call_context.get("sp", 0) or 0), 0)
            r7 = int(str(call_context.get("r7", call_context.get("fp", 0)) or 0), 0)
            r11 = int(str(call_context.get("r11", 0) or 0), 0)
            raw_hex = str(call_context.get("stack_hex", call_context.get("stack", "")) or "").strip()
            stack_bytes = bytes.fromhex(raw_hex) if raw_hex else b""
            return {
                "lr": lr & 0xFFFFFFFF,
                "sp": sp & 0xFFFFFFFF,
                "r7": r7 & 0xFFFFFFFF,
                "r11": r11 & 0xFFFFFFFF,
                "stack_base": sp & ~3,
                "stack_bytes": stack_bytes,
            }
        except Exception:
            return None
    text = str(call_context).strip()
    if "@" not in text:
        return None
    parts = text.split("@")
    if len(parts) < 2:
        return None
    try:
        pc_val = int(parts[0], 0) if parts[0] else 0
        lr_val = int(parts[1], 0) if len(parts) > 1 and parts[1] else 0
        sp_val = int(parts[2], 0) if len(parts) > 2 and parts[2] else 0
        r7_val = int(parts[3], 0) if len(parts) > 3 and parts[3] else 0
        r11_val = int(parts[4], 0) if len(parts) > 4 and parts[4] else 0
        stack_hex = parts[5].strip() if len(parts) > 5 else ""
        stack_bytes = bytes.fromhex(stack_hex) if stack_hex else b""
        return {
            "pc": pc_val & 0xFFFFFFFF,
            "lr": lr_val & 0xFFFFFFFF,
            "sp": sp_val & 0xFFFFFFFF,
            "r7": r7_val & 0xFFFFFFFF,
            "r11": r11_val & 0xFFFFFFFF,
            "stack_base": sp_val & ~3,
            "stack_bytes": stack_bytes,
        }
    except Exception:
        return None


def _sign_extend_31(val: int) -> int:
    val &= 0x7FFFFFFF
    return val - 0x80000000 if (val & 0x40000000) else val


def _decode_thumb_modified_imm(hw1: int, hw2: int) -> int:
    i = (hw1 >> 10) & 1
    imm3 = (hw2 >> 12) & 7
    imm8 = hw2 & 0xFF
    imm12 = (i << 11) | (imm3 << 8) | imm8
    if (imm12 >> 10) == 0:
        mode = (imm12 >> 8) & 3
        if mode == 0:
            return imm8
        if mode == 1:
            return (imm8 << 16) | imm8
        if mode == 2:
            return (imm8 << 24) | (imm8 << 8)
        return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8
    rot = (imm12 >> 7) & 0x1F
    val = 0x80 | (imm12 & 0x7F)
    return ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF


def _analyze_thumb_prologue(code: bytes, start_addr: int, target_pc: int):
    """Decode Thumb-1/Thumb-2 prologue up to target_pc to determine frame size and saved LR."""
    limit = min(len(code), max(0, target_pc - start_addr))
    off = 0
    pushed_bytes = 0
    lr_offset_from_cfa = None
    sub_bytes = 0
    while off + 2 <= limit and off < 32:
        hw1 = struct.unpack_from("<H", code, off)[0]
        is_32 = (hw1 & 0xF800) in (0xE800, 0xF000, 0xF800)
        if is_32:
            if off + 4 > limit:
                break
            hw2 = struct.unpack_from("<H", code, off + 2)[0]
            # stmdb sp!, {reglist} (PUSH.W)
            if hw1 == 0xE92D and pushed_bytes == 0:
                reglist = hw2 & 0x5FFF
                pushed_bytes = bin(reglist).count("1") * 4
                if reglist & (1 << 14):
                    lr_offset_from_cfa = -4
            # sub.w sp, sp, #imm12
            elif hw1 in (0xF1AD, 0xF5AD) and (hw2 & 0x8F00) == 0x0D00:
                sub_bytes += _decode_thumb_modified_imm(hw1, hw2)
            # subw sp, sp, #imm12
            elif hw1 in (0xF2AD, 0xF6AD) and (hw2 & 0x8F00) == 0x0D00:
                i = (hw1 >> 10) & 1
                imm3 = (hw2 >> 12) & 7
                imm8 = hw2 & 0xFF
                sub_bytes += (i << 11) | (imm3 << 8) | imm8
            # vpush {d8..} / vstmdb sp!, {s16..}
            elif (hw1 & 0xFFBF) == 0xED2D and (hw2 & 0x0E00) == 0x0A00:
                sub_bytes += (hw2 & 0xFF) * 4
            # Stop at branch / call / pop.w
            elif (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) in (0xD000, 0xC000, 0x9000, 0x8000):
                break
            elif hw1 == 0xE8BD or (hw1 == 0xF85D and (hw2 & 0xF000) == 0xF000):
                break
            off += 4
        else:
            # 16-bit PUSH {reglist, lr}
            if (hw1 & 0xFE00) == 0xB400 and pushed_bytes == 0:
                reglist = hw1 & 0x00FF
                m = (hw1 >> 8) & 1
                pushed_bytes = (bin(reglist).count("1") + m) * 4
                if m:
                    lr_offset_from_cfa = -4
            # 16-bit SUB sp, #imm7*4
            elif (hw1 & 0xFF80) == 0xB080:
                sub_bytes += (hw1 & 0x7F) * 4
            # Stop at ADD sp, #imm7*4, POP, BX, BLX, B, CBZ/CBNZ
            elif (
                (hw1 & 0xFF80) == 0xB000
                or (hw1 & 0xFE00) == 0xBC00
                or (hw1 & 0xFF00) == 0x4700
                or (hw1 & 0xF800) == 0xE000
                or (hw1 & 0xF500) == 0xB100
            ):
                break
            off += 2
    return pushed_bytes + sub_bytes, lr_offset_from_cfa

class SourceLocations:
    def __init__(self, elf, root):
        self.elf = elf
        self.root = root.resolve()

    @cached_property
    def index(self):
        ranges = []
        symbols = {}
        functions = []
        if self.elf and self.elf.is_file():
            try:
                with self.elf.open("rb") as stream:
                    elf = ELFFile(stream)
                    thumb = elf["e_machine"] == "EM_ARM"
                    objects = {}
                    table = elf.get_section_by_name(".symtab")
                    if table:
                        for symbol in table.iter_symbols():
                            start, size = symbol["st_value"], symbol["st_size"]
                            kind = symbol["st_info"]["type"]
                            if kind == "STT_FUNC" and symbol["st_shndx"] != "SHN_UNDEF":
                                symbols[symbol.name] = start
                                if thumb:
                                    start &= ~1
                                if size:
                                    functions.append((start, start + size, symbol.name))
                            elif kind == "STT_OBJECT" and start and size:
                                objects[symbol.name] = (start, size)
                    if elf.has_dwarf_info() and elf.get_section_by_name(".debug_line"):
                        ranges = sorted(self._line_ranges(elf.get_dwarf_info(), objects))
            except (ELFError, OSError):
                pass
        functions.sort()
        return [r[0] for r in ranges], ranges, symbols, [f[0] for f in functions], functions

    def resolve_pc(self, value):
        """Return observed PC, source, and the evidence used for resolution."""
        if value is None or isinstance(value, bool):
            return None
        try:
            pc = int(str(value), 0)
        except ValueError:
            return None
        if not 0 <= pc <= 0xFFFFFFFFFFFFFFFF:
            return None
        result = {"pc": f"0x{pc:08X}", "resolution": "address_only"}
        starts, ranges, _, function_starts, functions = self.index
        # Executable PC samples are instruction addresses. ELF Thumb symbols
        # were normalized when building the function index.
        index = bisect_right(function_starts, pc) - 1
        if index >= 0:
            start, end, name = functions[index]
            if start <= pc < end:
                result.update(function=name, resolution="symbol_table")
        index = bisect_right(starts, pc) - 1
        if index >= 0:
            _, end, path, line, is_code = ranges[index]
            if pc < end and is_code:
                if path.is_relative_to(self.root):
                    path = path.relative_to(self.root)
                elif path.is_absolute():
                    path = Path(path.name)
                result.update(file=str(path), line=line, resolution="dwarf")
        return result

    @cached_property
    def unwind_index(self):
        cfi_entries = []
        exidx_entries = []
        code_segments = []
        cu_ranges = []
        if self.elf and self.elf.is_file():
            try:
                with self.elf.open("rb") as stream:
                    elf = ELFFile(stream)
                    for sec in elf.iter_sections():
                        sh_flags = int(sec["sh_flags"] or 0)
                        sh_addr = int(sec["sh_addr"] or 0)
                        sh_size = int(sec["sh_size"] or 0)
                        if (sh_flags & 0x4) and sh_size > 0 and sec["sh_type"] != "SHT_NOBITS":
                            try:
                                data = sec.data()
                                if data:
                                    code_segments.append((sh_addr, sh_addr + len(data), data))
                            except Exception:
                                pass
                    if not code_segments:
                        for seg in elf.iter_segments():
                            if seg["p_type"] == "PT_LOAD" and int(seg["p_filesz"] or 0) > 0:
                                try:
                                    vaddr = int(seg["p_vaddr"])
                                    data = seg.data()
                                    if data:
                                        code_segments.append((vaddr, vaddr + len(data), data))
                                except Exception:
                                    pass
                    if elf.has_dwarf_info():
                        dwarf = elf.get_dwarf_info()
                        for entries_fn in (
                            (dwarf.CFI_entries if dwarf.has_CFI() else None),
                            (dwarf.EH_CFI_entries if dwarf.has_EH_CFI() else None),
                        ):
                            if entries_fn is None:
                                continue
                            try:
                                for entry in entries_fn():
                                    if not hasattr(entry, "header") or "initial_location" not in entry.header:
                                        continue
                                    start = int(entry["initial_location"]) & ~1
                                    end = start + int(entry["address_range"])
                                    if end <= start:
                                        continue
                                    ra_reg = int(entry.cie["return_address_register"])
                                    table = list(entry.get_decoded().table)
                                    cfi_entries.append((start, end, ra_reg, table))
                            except Exception:
                                pass
                        try:
                            for unit in dwarf.iter_CUs():
                                top = unit.get_top_DIE()
                                name_attr = top.attributes.get("DW_AT_name")
                                if not name_attr:
                                    continue
                                cu_name = os.fsdecode(name_attr.value)
                                low_attr = top.attributes.get("DW_AT_low_pc")
                                high_attr = top.attributes.get("DW_AT_high_pc")
                                if low_attr and high_attr:
                                    low = int(low_attr.value) & ~1
                                    high = int(high_attr.value)
                                    if high_attr.form != "DW_FORM_addr":
                                        high = low + high
                                    if high > low:
                                        cu_ranges.append((low, high, cu_name))
                        except Exception:
                            pass
                    exidx_sec = elf.get_section_by_name(".ARM.exidx")
                    if exidx_sec and int(exidx_sec["sh_size"] or 0) >= 8:
                        raw = exidx_sec.data()
                        base_addr = int(exidx_sec["sh_addr"] or 0)
                        parsed = []
                        has_real = False
                        for off in range(0, len(raw) - 7, 8):
                            w0, w1 = struct.unpack_from("<II", raw, off)
                            fn_start = ((base_addr + off + _sign_extend_31(w0)) & 0xFFFFFFFF) & ~1
                            parsed.append((fn_start, w1))
                            if w1 != 1 and (w1 & 0x80000000) != 0:
                                has_real = True
                        if has_real:
                            parsed.sort()
                            for i, (fn_start, w1) in enumerate(parsed):
                                fn_end = parsed[i + 1][0] if i + 1 < len(parsed) else fn_start + 0x10000
                                if w1 != 1 and (w1 & 0x80000000) != 0 and fn_end > fn_start:
                                    opcodes = ((w1 >> 16) & 0xFF, (w1 >> 8) & 0xFF, w1 & 0xFF)
                                    exidx_entries.append((fn_start, fn_end, opcodes))
            except (ELFError, OSError):
                pass
        cfi_entries.sort(key=lambda item: item[0])
        exidx_entries.sort(key=lambda item: item[0])
        code_segments.sort(key=lambda item: item[0])
        cu_ranges.sort(key=lambda item: item[0])
        return (
            [e[0] for e in cfi_entries], cfi_entries,
            [e[0] for e in exidx_entries], exidx_entries,
            code_segments,
            [c[0] for c in cu_ranges], cu_ranges,
        )

    def _read_code(self, addr: int, size: int) -> bytes | None:
        _, _, _, _, code_segments, _, _ = self.unwind_index
        for seg_start, seg_end, data in code_segments:
            if seg_start <= addr and addr + size <= seg_end:
                off = addr - seg_start
                return data[off:off + size]
        return None

    def _cu_file_for_pc(self, pc: int) -> str | None:
        _, _, _, _, _, cu_starts, cu_ranges = self.unwind_index
        idx = bisect_right(cu_starts, pc) - 1
        if idx >= 0:
            low, high, cu_name = cu_ranges[idx]
            if low <= pc < high:
                return cu_name
        return None

    def _return_address_to_callsite(self, ret_addr) -> int | None:
        if ret_addr is None:
            return None
        val = int(ret_addr) & 0xFFFFFFFF
        if val == 0 or (val & 0xF0000000) == 0xF0000000:
            return None
        ret_pc = val & ~1
        if ret_pc >= 4:
            prev4 = self._read_code(ret_pc - 4, 4)
            if prev4 is not None:
                hw1, hw2 = struct.unpack_from("<HH", prev4, 0)
                if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xC000) == 0xC000:
                    return ret_pc - 4
        return max(0, ret_pc - 2)

    def _unwind_step(self, pc: int, regs: dict, stack_base: int, stack_bytes: bytes, depth: int):
        def read_stack_u32(addr: int) -> int | None:
            if not stack_bytes or addr < stack_base or (addr & 3) != 0:
                return None
            off = addr - stack_base
            if off < 0 or off + 4 > len(stack_bytes):
                return None
            return struct.unpack_from("<I", stack_bytes, off)[0]

        cfi_starts, cfi_entries, exidx_starts, exidx_entries, _, _, _ = self.unwind_index

        # 1. DWARF .debug_frame / .eh_frame CFI tables
        idx = bisect_right(cfi_starts, pc) - 1
        if idx >= 0:
            start, end, ra_reg, table = cfi_entries[idx]
            if start <= pc < end and table:
                chosen_row = table[0]
                for row in table:
                    if (int(row["pc"]) & ~1) <= pc:
                        chosen_row = row
                    else:
                        break
                cfa_rule = chosen_row.get("cfa")
                if cfa_rule is not None and getattr(cfa_rule, "reg", None) in regs:
                    cfa = (int(regs[cfa_rule.reg]) + int(cfa_rule.offset or 0)) & 0xFFFFFFFF
                    ret_addr = None
                    if ra_reg in chosen_row:
                        rule = chosen_row[ra_reg]
                        rtype = getattr(rule, "type", None)
                        if rtype == "OFFSET":
                            ret_addr = read_stack_u32((cfa + int(rule.arg)) & 0xFFFFFFFF)
                            if ret_addr is None and depth == 0:
                                ret_addr = regs.get(ra_reg)
                        elif rtype == "REGISTER":
                            ret_addr = regs.get(int(rule.arg))
                        elif rtype in ("SAME_VALUE", "UNDEFINED"):
                            ret_addr = regs.get(ra_reg) if depth == 0 else None
                    elif depth == 0:
                        ret_addr = regs.get(ra_reg)
                    new_regs = {k: v for k, v in regs.items() if k != 14}
                    new_regs[13] = cfa
                    for reg_num in (7, 11):
                        if reg_num in chosen_row and getattr(chosen_row[reg_num], "type", None) == "OFFSET":
                            saved = read_stack_u32((cfa + int(chosen_row[reg_num].arg)) & 0xFFFFFFFF)
                            if saved is not None:
                                new_regs[reg_num] = saved
                    return ret_addr, new_regs

        # 2. ARM .ARM.exidx unwind entries
        idx = bisect_right(exidx_starts, pc) - 1
        if idx >= 0:
            start, end, opcodes = exidx_entries[idx]
            if start <= pc < end and 13 in regs:
                vsp = int(regs[13]) & 0xFFFFFFFF
                ret_addr = None
                i = 0
                while i < len(opcodes):
                    op = opcodes[i]
                    i += 1
                    if (op & 0xC0) == 0x00:
                        vsp = (vsp + ((op & 0x3F) << 2) + 4) & 0xFFFFFFFF
                    elif (op & 0xC0) == 0x40:
                        vsp = (vsp - ((op & 0x3F) << 2) - 4) & 0xFFFFFFFF
                    elif (op & 0xF0) == 0x80 and i < len(opcodes):
                        op2 = opcodes[i]
                        i += 1
                        mask = (((op & 0x0F) << 8) | op2) << 4
                        for r in range(4, 16):
                            if mask & (1 << r):
                                val = read_stack_u32(vsp)
                                vsp = (vsp + 4) & 0xFFFFFFFF
                                if r in (14, 15) and val is not None:
                                    ret_addr = val
                    elif (op & 0xF0) == 0x90:
                        reg_num = op & 0x0F
                        if reg_num in regs:
                            vsp = int(regs[reg_num]) & 0xFFFFFFFF
                    elif (op & 0xF8) == 0xA0:
                        cnt = (op & 7) + 1
                        vsp = (vsp + cnt * 4) & 0xFFFFFFFF
                    elif (op & 0xF8) == 0xA8:
                        cnt = (op & 7) + 1
                        vsp = (vsp + cnt * 4) & 0xFFFFFFFF
                        ret_addr = read_stack_u32(vsp)
                        vsp = (vsp + 4) & 0xFFFFFFFF
                    elif op == 0xB0:
                        break
                    elif op == 0xB1 and i < len(opcodes):
                        op2 = opcodes[i]
                        i += 1
                        cnt = bin(op2 & 0x0F).count("1")
                        vsp = (vsp + cnt * 4) & 0xFFFFFFFF
                if ret_addr is None and depth == 0:
                    ret_addr = regs.get(14)
                new_regs = {k: v for k, v in regs.items() if k != 14}
                new_regs[13] = vsp
                return ret_addr, new_regs

        # 3. Thumb function prologue frame info from .symtab + executable code
        _, _, _, function_starts, functions = self.index
        fn_idx = bisect_right(function_starts, pc) - 1
        if fn_idx >= 0:
            fn_start, fn_end, _ = functions[fn_idx]
            if fn_start <= pc < fn_end:
                code = self._read_code(fn_start, min(64, fn_end - fn_start))
                if code:
                    cfa_off, lr_off = _analyze_thumb_prologue(code, fn_start, pc)
                    if lr_off is None:
                        # Leaf function (or before push in prologue): LR holds return address at depth 0
                        if depth == 0:
                            sp = regs.get(13)
                            new_regs = {k: v for k, v in regs.items() if k != 14}
                            if sp is not None:
                                new_regs[13] = (int(sp) + cfa_off) & 0xFFFFFFFF
                            return regs.get(14), new_regs
                        return None, {}
                    if 13 in regs and stack_bytes:
                        cfa = (int(regs[13]) + cfa_off) & 0xFFFFFFFF
                        ret_addr = read_stack_u32((cfa + lr_off) & 0xFFFFFFFF)
                        new_regs = {k: v for k, v in regs.items() if k != 14}
                        new_regs[13] = cfa
                        if ret_addr is not None:
                            return ret_addr, new_regs
                        if depth == 0 and regs.get(14):
                            return regs.get(14), new_regs

        # 4. LR-only fallback when unwind tables / frame info or stack are unavailable
        if depth == 0 and regs.get(14):
            return regs.get(14), {}
        return None, {}

    def resolve_call_chain(self, pc, call_context=None, driver_functions=()):
        """Resolve an operation/cut PC and optional call context into (call_chain, caller_source)."""
        first = self.resolve_pc(pc)
        if first is None:
            return [], None

        def annotate(loc: dict) -> dict:
            frame = dict(loc)
            if "file" not in frame:
                try:
                    cu_file = self._cu_file_for_pc(int(frame["pc"], 0))
                    if cu_file:
                        frame["cu_file"] = cu_file
                except Exception:
                    pass
            frame["driver"] = is_driver_frame(frame, driver_functions)
            frame.pop("cu_file", None)
            return frame

        chain = [annotate(first)]

        # Pre-parsed list of PCs or frame dicts
        if isinstance(call_context, (list, tuple)):
            for item in call_context:
                loc = item if isinstance(item, dict) and "pc" in item else self.resolve_pc(item)
                if loc is None:
                    continue
                if loc.get("pc") == chain[-1].get("pc") and len(chain) == 1:
                    continue
                chain.append(annotate(loc))
            return chain, select_caller_frame(chain)

        parsed = parse_call_context(call_context)
        if not parsed:
            return chain, select_caller_frame(chain)

        regs = {}
        if parsed.get("sp"):
            regs[13] = parsed["sp"]
        if parsed.get("lr"):
            regs[14] = parsed["lr"]
        if parsed.get("r7"):
            regs[7] = parsed["r7"]
        if parsed.get("r11"):
            regs[11] = parsed["r11"]
        stack_base = parsed.get("stack_base", 0)
        stack_bytes = parsed.get("stack_bytes", b"")

        curr_pc = int(str(first["pc"]), 0) & ~1
        seen = {(curr_pc, regs.get(13))}
        for depth in range(16):
            ret_addr, next_regs = self._unwind_step(curr_pc, regs, stack_base, stack_bytes, depth)
            callsite = self._return_address_to_callsite(ret_addr)
            if callsite is None:
                break
            state_key = (callsite, next_regs.get(13))
            if state_key in seen:
                break
            seen.add(state_key)
            loc = self.resolve_pc(callsite)
            if loc is None:
                break
            # Stop if we unwound outside any known function/code on depth > 0
            if depth > 0 and loc.get("resolution") == "address_only" and self._read_code(callsite, 2) is None:
                break
            chain.append(annotate(loc))
            if not next_regs or 13 not in next_regs:
                break
            curr_pc = callsite
            regs = next_regs

        return chain, select_caller_frame(chain)

    def _line_ranges(self, dwarf, objects=()):
        for unit in dwarf.iter_CUs():
            program = dwarf.line_program_for_CU(unit)
            if program is None:
                continue
            attribute = unit.get_top_DIE().attributes.get("DW_AT_comp_dir")
            directory = Path(os.fsdecode(attribute.value)) if attribute else Path(".")
            previous = None
            files = {}
            base = 0 if program["version"] >= 5 else 1

            def source_file(file_id):
                if file_id not in files:
                    file = program["file_entry"][file_id - base]
                    folder = directory
                    if file.dir_index >= base:
                        folder /= os.fsdecode(program["include_directory"][file.dir_index - base])
                    name = Path(os.fsdecode(file.name))
                    path = folder / name
                    # A relocatable ELF may sit beside its original source.
                    if not path.is_file() and not name.is_absolute() and (self.elf.parent / name).is_file():
                        path = self.elf.parent / name
                    files[file_id] = path
                return files[file_id]

            for entry in program.get_entries():
                state = entry.state
                if state is None:
                    continue
                if previous and previous.line and previous.address < state.address:
                    yield previous.address, state.address, source_file(previous.file), previous.line, True
                previous = None if state.end_sequence else state
            for die in (unit.iter_DIEs() if objects else ()):
                attrs = die.attributes
                name = os.fsdecode(attrs["DW_AT_name"].value) if "DW_AT_name" in attrs else None
                if (die.tag == "DW_TAG_variable" and name in objects
                        and "DW_AT_decl_file" in attrs and "DW_AT_decl_line" in attrs):
                    start, size = objects[name]
                    yield start, start + size, source_file(attrs["DW_AT_decl_file"].value), attrs["DW_AT_decl_line"].value, False

    def lookup(self, row):
        signals = row.get("signals") or {}
        rc = row.get("rc_injection") or signals.get("rc_injection") or {}
        starts, ranges, symbols, _, _ = self.index
        candidates = (signals.get("skip_address"), row.get("fault_pc"), row.get("firmware_address"),
                      symbols.get(rc.get("applied_symbol") or row.get("firmware_symbol") or row.get("symbol")
                                  or signals.get("rc_injection_symbol")), rc.get("applied_return_address"),
                      row.get("fault_address"), signals.get("pc"), row.get("pc"),
                      signals.get("vector_reset"), signals.get("vector_base"))
        for value in candidates:
            if value is None:
                continue
            try:
                address = int(str(value), 0)
            except ValueError:
                continue
            for probe in (address, address & ~1):
                index = bisect_right(starts, probe) - 1
                if index >= 0:
                    _, end, path, line, _ = ranges[index]
                    if probe < end:
                        return self.uri(path), line
        return None

    def uri(self, path):
        path = Path(path)
        if path.is_absolute():
            try:
                path = path.relative_to(self.root)
            except ValueError:
                return path.as_uri()
        return quote(path.as_posix(), safe="/")
