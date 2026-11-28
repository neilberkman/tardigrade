# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Recovery-code coverage scope resolution, attribution, sharding, and merging.

Kept compatible with both Python 3 on the host and IronPython 2.7 inside
Renode 1.16.1 so pure helpers can be shared across host and emulator.
"""

from __future__ import division

import binascii
import copy
import fnmatch
import hashlib
import os
import re


class RecoveryCoverageError(ValueError):
    pass


SUPPORTED_COVERAGE_MECHANISMS = (
    "oneshot_address_hooks",
    "block_begin_hook",
    "execution_tracing",
)

SUPPORTED_STATE_SEARCH_ORDERS = (
    "breadth_first",
    "coverage_guided",
    "best_first",
)

_CLONE_SUFFIX_RE = re.compile(
    r"\.(?:constprop|isra|part|cold|ipa|modref| artificial)(?:\.\d+)+$"
)

try:
    _string_types = (basestring,)
except NameError:
    _string_types = (str,)

try:
    _integer_types = (int, long)
except NameError:
    _integer_types = (int,)


def _is_int(value):
    return isinstance(value, _integer_types) and not isinstance(value, bool)


def _fmt_u32(address):
    return "0x{:08X}".format(int(address) & 0xFFFFFFFF)


def _parse_pc(value):
    if _is_int(value):
        return int(value) & ~1
    text = str(value).strip()
    if not text:
        raise RecoveryCoverageError("empty PC address")
    return int(text, 0) & ~1


def _strip_clone_suffixes(name):
    stripped = str(name)
    while True:
        updated = _CLONE_SUFFIX_RE.sub("", stripped)
        if updated == stripped:
            return stripped
        stripped = updated


def _is_glob(pattern):
    return any(ch in pattern for ch in ("*", "?", "["))


def _match_function_query(query, symbol_name):
    query = str(query).strip()
    symbol_name = str(symbol_name)
    if _is_glob(query):
        return fnmatch.fnmatchcase(symbol_name, query) or fnmatch.fnmatchcase(
            _strip_clone_suffixes(symbol_name), query
        )
    if symbol_name == query or _strip_clone_suffixes(symbol_name) == query:
        return True
    return query in symbol_name


def _normalize_source_path(path_text, repo_root=None, elf_dir=None):
    raw = str(path_text).replace("\\", "/").strip()
    while raw.startswith("./"):
        raw = raw[2:]
    if not raw:
        return raw
    if os.path.isabs(raw):
        candidates = []
        if repo_root is not None:
            candidates.append(os.path.abspath(str(repo_root)))
        if elf_dir is not None:
            candidates.append(os.path.abspath(str(elf_dir)))
        raw_abs = os.path.abspath(raw)
        for root in candidates:
            root_prefix = root.rstrip("/\\") + os.sep
            if raw_abs.startswith(root_prefix):
                rel = os.path.relpath(raw_abs, root).replace("\\", "/")
                if not rel.startswith(".."):
                    return rel
        return os.path.basename(raw)
    return raw


def _match_source_file_query(query, candidate_path):
    query_norm = str(query).replace("\\", "/").strip()
    while query_norm.startswith("./"):
        query_norm = query_norm[2:]
    cand_norm = str(candidate_path).replace("\\", "/").strip()
    while cand_norm.startswith("./"):
        cand_norm = cand_norm[2:]
    cand_base = os.path.basename(cand_norm)
    if _is_glob(query_norm):
        return fnmatch.fnmatchcase(cand_norm, query_norm) or fnmatch.fnmatchcase(
            cand_base, query_norm
        )
    if cand_norm == query_norm or cand_base == query_norm:
        return True
    if cand_norm.endswith("/" + query_norm):
        return True
    return False


def normalize_address_ranges(address_ranges):
    if not address_ranges:
        return []
    parsed = []
    for index, item in enumerate(address_ranges):
        if isinstance(item, (tuple, list)) and len(item) == 2:
            raw_start, raw_end = item
        elif isinstance(item, dict):
            if "start" not in item or "end" not in item:
                raise RecoveryCoverageError(
                    "address_ranges[{}]: start and end are required".format(index)
                )
            raw_start = item["start"]
            raw_end = item["end"]
        else:
            raise RecoveryCoverageError(
                "address_ranges[{}]: expected mapping with start and end".format(
                    index
                )
            )
        if isinstance(raw_start, bool) or isinstance(raw_end, bool):
            raise RecoveryCoverageError(
                "address_ranges[{}]: start and end must be integers".format(index)
            )
        try:
            start = (
                int(raw_start, 0)
                if isinstance(raw_start, _string_types)
                else int(raw_start)
            )
            end = (
                int(raw_end, 0)
                if isinstance(raw_end, _string_types)
                else int(raw_end)
            )
        except (TypeError, ValueError) as exc:
            raise RecoveryCoverageError(
                "address_ranges[{}]: malformed integer bound: {}".format(
                    index, exc
                )
            )
        if start < 0 or end < start or end > 0xFFFFFFFF:
            raise RecoveryCoverageError(
                "address_ranges[{}]: expected 0 <= start <= end <= 0xFFFFFFFF".format(
                    index
                )
            )
        parsed.append({"start": int(start), "end": int(end)})
    return parsed


def _merge_half_open_intervals(intervals):
    cleaned = sorted(
        (int(start) & ~1, max((int(start) & ~1) + 2, (int(end) + 1) & ~1))
        for start, end in intervals
        if int(end) > int(start)
    )
    if not cleaned:
        return []
    merged = [list(cleaned[0])]
    for start, end in cleaned[1:]:
        if start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(item[0], item[1]) for item in merged]


def _intervals_overlap(a_start, a_end, b_start, b_end):
    return int(a_start) < int(b_end) and int(b_start) < int(a_end)


def _address_in_intervals(address, intervals):
    addr = int(address) & ~1
    for start, end in intervals:
        if start <= addr < end:
            return True
        if addr < start:
            break
    return False


def _clip_to_intervals(span_start, span_end, intervals):
    out = []
    for start, end in intervals:
        if end <= span_start:
            continue
        if start >= span_end:
            break
        lo = max(int(span_start) & ~1, int(start) & ~1)
        hi = min((int(span_end) + 1) & ~1, int(end) & ~1)
        if hi > lo:
            out.append((lo, hi))
    return out


def _extract_elf_functions_and_lines(elf_path, repo_root=None):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RecoveryCoverageError(
            "recovery_coverage ELF analysis requires pyelftools: {}".format(exc)
        )

    elf_path_str = str(elf_path)
    if not os.path.isfile(elf_path_str):
        raise RecoveryCoverageError(
            "bootloader ELF does not exist: {}".format(elf_path_str)
        )
    elf_dir = os.path.dirname(os.path.abspath(elf_path_str))

    functions = []
    line_spans = []
    has_debug_line = False

    try:
        with open(elf_path_str, "rb") as stream:
            elf = ELFFile(stream)
            symtab = elf.get_section_by_name(".symtab")
            raw_funcs = []
            if symtab is not None:
                for symbol in symtab.iter_symbols():
                    if not symbol.name or symbol["st_info"]["type"] != "STT_FUNC":
                        continue
                    if symbol["st_shndx"] == "SHN_UNDEF":
                        continue
                    start = int(symbol["st_value"]) & ~1
                    size = int(symbol["st_size"])
                    raw_funcs.append((str(symbol.name), start, size))
            raw_funcs.sort(key=lambda item: (item[1], item[0]))
            seen_func_ranges = set()
            for idx, (name, start, size) in enumerate(raw_funcs):
                end = start + size if size > 0 else None
                if end is None:
                    for _other_name, next_start, _next_size in raw_funcs[idx + 1 :]:
                        if next_start > start:
                            end = next_start
                            break
                if end is None or end <= start:
                    continue
                key = (name, start, end)
                if key in seen_func_ranges:
                    continue
                seen_func_ranges.add(key)
                functions.append(
                    {
                        "name": name,
                        "start": int(start),
                        "end": int(end),
                        "size": int(end - start),
                    }
                )

            if elf.has_dwarf_info() and elf.get_section_by_name(".debug_line") is not None:
                dwarf = elf.get_dwarf_info()
                for cu in dwarf.iter_CUs():
                    program = dwarf.line_program_for_CU(cu)
                    if program is None:
                        continue
                    top_die = cu.get_top_DIE()
                    comp_dir_attr = top_die.attributes.get("DW_AT_comp_dir")
                    comp_dir = (
                        os.fsdecode(comp_dir_attr.value)
                        if comp_dir_attr is not None
                        else ""
                    )
                    base = 0 if program["version"] >= 5 else 1
                    file_cache = {}

                    def resolve_file(file_id):
                        if file_id in file_cache:
                            return file_cache[file_id]
                        entry = program["file_entry"][file_id - base]
                        name_text = os.fsdecode(entry.name)
                        folder = comp_dir
                        if entry.dir_index >= base:
                            inc_dir = os.fsdecode(
                                program["include_directory"][entry.dir_index - base]
                            )
                            folder = (
                                os.path.join(folder, inc_dir)
                                if folder and not os.path.isabs(inc_dir)
                                else inc_dir
                            )
                        combined = (
                            os.path.join(folder, name_text)
                            if folder and not os.path.isabs(name_text)
                            else name_text
                        )
                        if not os.path.isfile(combined):
                            sibling = os.path.join(elf_dir, os.path.basename(name_text))
                            if os.path.isfile(sibling):
                                combined = sibling
                        normalized = _normalize_source_path(
                            combined, repo_root=repo_root, elf_dir=elf_dir
                        )
                        file_cache[file_id] = normalized
                        return normalized

                    previous = None
                    for entry in program.get_entries():
                        state = entry.state
                        if state is None:
                            continue
                        if (
                            previous is not None
                            and previous.line
                            and int(previous.line) > 0
                            and (int(previous.address) & ~1) < (int(state.address) & ~1)
                        ):
                            span_start = int(previous.address) & ~1
                            span_end = int(state.address) & ~1
                            if span_end > span_start:
                                line_spans.append(
                                    {
                                        "start": span_start,
                                        "end": span_end,
                                        "file": resolve_file(previous.file),
                                        "line": int(previous.line),
                                    }
                                )
                        previous = None if state.end_sequence else state
                has_debug_line = len(line_spans) > 0
    except RecoveryCoverageError:
        raise
    except Exception as exc:
        raise RecoveryCoverageError(
            "failed to read ELF '{}': {}".format(elf_path_str, exc)
        )

    return functions, line_spans, has_debug_line


_THUMB_BRANCH_MNEMONICS = frozenset(
    (
        "b",
        "bl",
        "blx",
        "bx",
        "bxj",
        "beq",
        "bne",
        "bcs",
        "bhs",
        "bcc",
        "blo",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "bal",
        "cbz",
        "cbnz",
        "tbb",
        "tbh",
    )
)


def _decode_thumb_insn_pure(code_bytes, offset, pc):
    """Pure-Python Thumb-1/Thumb-2 decoder for instruction size, branch/call targets, and PC-relative literal loads."""
    if offset + 2 > len(code_bytes):
        return 2, False, None, ()
    hw1 = int(code_bytes[offset]) | (int(code_bytes[offset + 1]) << 8)
    top5 = (hw1 >> 11) & 0x1F
    if top5 in (0b11101, 0b11110, 0b11111):
        if offset + 4 > len(code_bytes):
            return 2, False, None, ()
        hw2 = int(code_bytes[offset + 2]) | (int(code_bytes[offset + 3]) << 8)
        # 32-bit B.W / BL / BLX / B<cond>.W
        if (hw1 & 0xF800) == 0xF000 and (hw2 & 0x8000) == 0x8000:
            sub = hw2 & 0xD000
            if sub in (0x9000, 0xD000, 0xC000):
                s_bit = (hw1 >> 10) & 1
                imm10 = hw1 & 0x3FF
                j1 = (hw2 >> 13) & 1
                j2 = (hw2 >> 11) & 1
                imm11 = hw2 & 0x7FF
                i1 = (~(j1 ^ s_bit)) & 1
                i2 = (~(j2 ^ s_bit)) & 1
                disp = (
                    (s_bit << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | (imm10 << 12)
                    | (imm11 << 1)
                )
                if sub == 0xC000:
                    disp &= ~2
                if s_bit:
                    disp -= 1 << 25
                base_pc = ((pc + 4) & ~3) if sub == 0xC000 else (pc + 4)
                return 4, True, (base_pc + disp) & ~1, ()
            if sub == 0x8000 and ((hw1 >> 6) & 0xF) not in (0xE, 0xF):
                s_bit = (hw1 >> 10) & 1
                imm6 = hw1 & 0x3F
                j1 = (hw2 >> 13) & 1
                j2 = (hw2 >> 11) & 1
                imm11 = hw2 & 0x7FF
                disp = (
                    (s_bit << 20)
                    | (j2 << 19)
                    | (j1 << 18)
                    | (imm6 << 12)
                    | (imm11 << 1)
                )
                if s_bit:
                    disp -= 1 << 21
                return 4, True, (pc + 4 + disp) & ~1, ()
        # TBB / TBH
        if (hw1 & 0xFFF0) == 0xE8D0 and (hw2 & 0xFFE0) == 0xF000:
            return 4, True, None, ()
        # LDM.W / POP.W writing PC
        if (hw1 & 0xFFD0) in (0xE890, 0xE910) and (hw2 & 0x8000) != 0:
            return 4, True, None, ()
        # LDR.W Rt, [PC, #+-imm12]
        if (hw1 & 0xFF7F) == 0xF85F:
            u_bit = (hw1 >> 7) & 1
            imm12 = hw2 & 0xFFF
            lit_addr = ((pc + 4) & ~3) + (imm12 if u_bit else -imm12)
            writes_pc = (hw2 & 0xF000) == 0xF000
            return 4, writes_pc, None, (lit_addr & ~1, (lit_addr + 2) & ~1)
        # LDR.W PC, [Rn, ...]
        if (hw1 & 0xFF70) == 0xF850 and (hw2 & 0xF000) == 0xF000:
            return 4, True, None, ()
        # LDRD Rt, Rt2, [PC, #+-imm8*4]
        if (hw1 & 0xFF7F) == 0xE95F:
            u_bit = (hw1 >> 7) & 1
            imm = (hw2 & 0xFF) << 2
            lit_addr = ((pc + 4) & ~3) + (imm if u_bit else -imm)
            return (
                4,
                False,
                None,
                tuple((lit_addr + off) & ~1 for off in (0, 2, 4, 6)),
            )
        return 4, False, None, ()

    # 16-bit instructions
    # LDR Rt, [PC, #imm8*4]
    if (hw1 & 0xF800) == 0x4800:
        imm = (hw1 & 0xFF) << 2
        lit_addr = ((pc + 4) & ~3) + imm
        return 2, False, None, (lit_addr & ~1, (lit_addr + 2) & ~1)
    # B<cond> (excluding UDF 0xDE.. and SVC 0xDF..)
    if (hw1 & 0xF000) == 0xD000 and (hw1 & 0x0F00) not in (0x0E00, 0x0F00):
        imm8 = hw1 & 0xFF
        if imm8 & 0x80:
            imm8 -= 0x100
        return 2, True, (pc + 4 + (imm8 << 1)) & ~1, ()
    # Unconditional B
    if (hw1 & 0xF800) == 0xE000:
        imm11 = hw1 & 0x7FF
        if imm11 & 0x400:
            imm11 -= 0x800
        return 2, True, (pc + 4 + (imm11 << 1)) & ~1, ()
    # CBZ / CBNZ
    if (hw1 & 0xF500) == 0xB100:
        i_bit = (hw1 >> 9) & 1
        imm5 = (hw1 >> 3) & 0x1F
        disp = (i_bit << 6) | (imm5 << 1)
        return 2, True, (pc + 4 + disp) & ~1, ()
    # BX / BLX (register)
    if (hw1 & 0xFF00) == 0x4700:
        return 2, True, None, ()
    # POP {..., PC}
    if (hw1 & 0xFF00) == 0xBD00:
        return 2, True, None, ()
    # ADD PC, Rm / MOV PC, Rm
    if (hw1 & 0xFE87) == 0x4487:
        return 2, True, None, ()
    return 2, False, None, ()


def _discover_basic_blocks(elf_path, active_intervals, forced_leaders=()):
    """Partition active code intervals into basic blocks excluding literal pools."""
    literal_addrs = set()
    segments = []
    if elf_path and os.path.isfile(str(elf_path)):
        try:
            from thumb_classify import (
                _load_segments,
                _read_region,
                find_literal_pools,
            )

            literal_addrs = set(
                find_literal_pools(str(elf_path), list(active_intervals))
            )
            segments = _load_segments(str(elf_path))
        except Exception:
            segments = []

    # Discover PC-relative literal pool targets in pure Python so literal pools
    # are excluded even when ELF mapping symbols ($t/$d) and Capstone are absent.
    if segments:
        from thumb_classify import _read_region

        for iv_start, iv_end in active_intervals:
            c_start = int(iv_start) & ~1
            c_end = int(iv_end) & ~1
            raw = _read_region(segments, c_start, c_end)
            if not raw:
                continue
            off = 0
            while off < len(raw):
                pc = c_start + off
                if pc in literal_addrs:
                    off += 2
                    continue
                sz, _is_br, _tgt, lit_pcs = _decode_thumb_insn_pure(
                    raw, off, pc
                )
                for l_pc in lit_pcs:
                    if c_start <= l_pc < c_end:
                        literal_addrs.add(l_pc)
                off += sz

    md = None
    try:
        from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
        md.detail = True
    except Exception:
        try:
            from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            md.detail = True
        except Exception:
            md = None

    forced_set = set(int(addr) & ~1 for addr in forced_leaders)
    blocks = []

    for interval_start, interval_end in active_intervals:
        cursor = int(interval_start) & ~1
        limit = int(interval_end) & ~1
        while cursor < limit:
            if cursor in literal_addrs:
                cursor += 2
                continue
            chunk_start = cursor
            while cursor < limit and cursor not in literal_addrs:
                cursor += 2
            chunk_end = cursor

            leaders = set([chunk_start])
            for addr in forced_set:
                if chunk_start <= addr < chunk_end and addr not in literal_addrs:
                    leaders.add(addr)

            insn_map = {}
            if segments:
                from thumb_classify import _read_region

                code_bytes = _read_region(segments, chunk_start, chunk_end)
                if code_bytes:
                    if md is not None:
                        sub_cursor = chunk_start
                        while sub_cursor < chunk_end:
                            disassembled_any = False
                            for insn in md.disasm(
                                code_bytes[sub_cursor - chunk_start :],
                                sub_cursor,
                            ):
                                disassembled_any = True
                                insn_addr = int(insn.address) & ~1
                                insn_size = max(2, int(insn.size))
                                insn_map[insn_addr] = insn_size
                                base_mnem = (
                                    str(insn.mnemonic)
                                    .lower()
                                    .strip()
                                    .split(".", 1)[0]
                                )
                                op_str = str(insn.op_str).lower().strip()
                                is_branch_or_call = (
                                    base_mnem in _THUMB_BRANCH_MNEMONICS
                                    or base_mnem.startswith("it")
                                    or (
                                        base_mnem.startswith(("pop", "ldm"))
                                        and "pc" in op_str
                                    )
                                    or (
                                        base_mnem.startswith(
                                            ("ldr", "mov", "add", "sub")
                                        )
                                        and op_str.startswith("pc,")
                                    )
                                )
                                if is_branch_or_call:
                                    next_pc = insn_addr + insn_size
                                    if (
                                        chunk_start <= next_pc < chunk_end
                                        and next_pc not in literal_addrs
                                    ):
                                        leaders.add(next_pc)
                                    for op in (
                                        getattr(insn, "operands", ()) or ()
                                    ):
                                        if getattr(op, "type", None) == 2:
                                            target = int(op.imm) & ~1
                                            if (
                                                chunk_start
                                                <= target
                                                < chunk_end
                                                and target not in literal_addrs
                                            ):
                                                leaders.add(target)
                                sub_cursor = insn_addr + insn_size
                            if not disassembled_any:
                                sz, is_br, tgt, _lits = _decode_thumb_insn_pure(
                                    code_bytes,
                                    sub_cursor - chunk_start,
                                    sub_cursor,
                                )
                                insn_map[sub_cursor] = sz
                                if is_br:
                                    next_pc = sub_cursor + sz
                                    if (
                                        chunk_start <= next_pc < chunk_end
                                        and next_pc not in literal_addrs
                                    ):
                                        leaders.add(next_pc)
                                    if (
                                        tgt is not None
                                        and chunk_start <= tgt < chunk_end
                                        and tgt not in literal_addrs
                                    ):
                                        leaders.add(tgt)
                                sub_cursor += sz
                    else:
                        off = 0
                        while off < len(code_bytes):
                            insn_addr = chunk_start + off
                            sz, is_br, tgt, _lits = _decode_thumb_insn_pure(
                                code_bytes, off, insn_addr
                            )
                            insn_map[insn_addr] = sz
                            if is_br:
                                next_pc = insn_addr + sz
                                if (
                                    chunk_start <= next_pc < chunk_end
                                    and next_pc not in literal_addrs
                                ):
                                    leaders.add(next_pc)
                                if (
                                    tgt is not None
                                    and chunk_start <= tgt < chunk_end
                                    and tgt not in literal_addrs
                                ):
                                    leaders.add(tgt)
                            off += sz

            # Snap any forced leader that landed on the second halfword of a
            # 32-bit Thumb-2 instruction back to that instruction's start PC.
            if insn_map:
                valid_starts = sorted(insn_map)
                snapped_leaders = set([chunk_start])
                for leader in leaders:
                    if leader in insn_map:
                        snapped_leaders.add(leader)
                    else:
                        prev_starts = [a for a in valid_starts if a <= leader]
                        if prev_starts:
                            snapped_leaders.add(prev_starts[-1])
                leaders = snapped_leaders

            ordered_leaders = sorted(
                addr for addr in leaders if chunk_start <= addr < chunk_end
            )
            for idx, bb_start in enumerate(ordered_leaders):
                bb_end = (
                    ordered_leaders[idx + 1]
                    if idx + 1 < len(ordered_leaders)
                    else chunk_end
                )
                if bb_end > bb_start:
                    blocks.append(
                        {
                            "pc": int(bb_start),
                            "start": int(bb_start),
                            "end": int(bb_end),
                            "size": int(bb_end - bb_start),
                        }
                    )

    blocks.sort(key=lambda item: (item["start"], item["end"]))
    return blocks, literal_addrs


def build_recovery_coverage_scope(
    elf_path=None,
    functions=(),
    source_files=(),
    address_ranges=(),
    mechanism="oneshot_address_hooks",
    repo_root=None,
):
    """Resolve configured functions, source files, or address ranges into a coverage scope."""
    mechanism = str(mechanism or "oneshot_address_hooks").strip().lower()
    if mechanism not in SUPPORTED_COVERAGE_MECHANISMS:
        raise RecoveryCoverageError(
            "unsupported recovery_coverage mechanism {!r}; expected one of {}".format(
                mechanism, list(SUPPORTED_COVERAGE_MECHANISMS)
            )
        )

    function_queries = []
    for item in functions or ():
        text = str(item or "").strip()
        if not text:
            raise RecoveryCoverageError(
                "recovery_coverage.functions entries must be non-empty strings"
            )
        if text not in function_queries:
            function_queries.append(text)

    source_queries = []
    for item in source_files or ():
        text = str(item or "").strip()
        if not text:
            raise RecoveryCoverageError(
                "recovery_coverage.source_files entries must be non-empty strings"
            )
        if text not in source_queries:
            source_queries.append(text)

    normalized_ranges = normalize_address_ranges(address_ranges)

    if not function_queries and not source_queries and not normalized_ranges:
        raise RecoveryCoverageError(
            "recovery_coverage requires at least one of functions, source_files, or address_ranges"
        )

    if (function_queries or source_queries) and not elf_path:
        raise RecoveryCoverageError(
            "recovery_coverage functions and source_files require bootloader.elf"
        )

    elf_functions = []
    line_spans = []
    has_debug_line = False
    if elf_path and os.path.isfile(str(elf_path)):
        elf_functions, line_spans, has_debug_line = _extract_elf_functions_and_lines(
            elf_path, repo_root=repo_root
        )
    elif function_queries or source_queries:
        raise RecoveryCoverageError(
            "bootloader ELF does not exist: {}".format(elf_path)
        )

    if function_queries and not elf_functions:
        raise RecoveryCoverageError(
            "bootloader ELF '{}' has no STT_FUNC symbols in .symtab".format(elf_path)
        )

    if source_queries and not has_debug_line:
        raise RecoveryCoverageError(
            "bootloader ELF '{}' has no DWARF .debug_line information; "
            "source_files cannot be resolved".format(elf_path)
        )

    selected_intervals = []
    matched_function_keys = set()

    for query in function_queries:
        matches = [
            fn for fn in elf_functions if _match_function_query(query, fn["name"])
        ]
        if not matches:
            available = sorted(set(fn["name"] for fn in elf_functions))
            raise RecoveryCoverageError(
                "recovery_coverage.functions: no function symbols matching {!r} in {}. "
                "Available function symbols: {}".format(
                    query,
                    elf_path,
                    ", ".join(available[:40]),
                )
            )
        base_names = set(_strip_clone_suffixes(fn["name"]) for fn in matches)
        for fn in elf_functions:
            if fn in matches or _strip_clone_suffixes(fn["name"]) in base_names:
                matched_function_keys.add((fn["name"], fn["start"], fn["end"]))
                selected_intervals.append((fn["start"], fn["end"]))

    matched_source_files = set()
    for query in source_queries:
        matched_spans = [
            span
            for span in line_spans
            if _match_source_file_query(query, span["file"])
        ]
        if not matched_spans:
            available_files = sorted(set(span["file"] for span in line_spans))
            raise RecoveryCoverageError(
                "recovery_coverage.source_files: no DWARF line table entries matching {!r} in {}. "
                "Available source files: {}".format(
                    query,
                    elf_path,
                    ", ".join(available_files),
                )
            )
        for span in matched_spans:
            matched_source_files.add(span["file"])
            selected_intervals.append((span["start"], span["end"]))

    for item in normalized_ranges:
        start = int(item["start"]) & ~1
        end = max(start + 2, (int(item["end"]) + 2) & ~1)
        selected_intervals.append((start, end))

    active_intervals = _merge_half_open_intervals(selected_intervals)
    if not active_intervals:
        raise RecoveryCoverageError(
            "configured recovery_coverage scope produced no valid address intervals"
        )

    # Determine in-scope functions: any explicitly matched function plus any
    # ELF function overlapping the active intervals.
    scope_functions = []
    seen_fn_keys = set()
    for fn in elf_functions:
        key = (fn["name"], fn["start"], fn["end"])
        overlaps = any(
            _intervals_overlap(fn["start"], fn["end"], iv_start, iv_end)
            for iv_start, iv_end in active_intervals
        )
        if key in matched_function_keys or overlaps:
            if key not in seen_fn_keys:
                seen_fn_keys.add(key)
                scope_functions.append(dict(fn))

    # For any explicit address_range interval not covered by any ELF function,
    # synthesize a range function entry so raw address_ranges always report per-function items.
    for iv_start, iv_end in active_intervals:
        overlapped = any(
            _intervals_overlap(fn["start"], fn["end"], iv_start, iv_end)
            for fn in scope_functions
        )
        if not overlapped:
            synth_name = "range_{}_{}".format(_fmt_u32(iv_start), _fmt_u32(iv_end - 1))
            scope_functions.append(
                {
                    "name": synth_name,
                    "start": int(iv_start),
                    "end": int(iv_end),
                    "size": int(iv_end - iv_start),
                    "synthetic_range": True,
                }
            )

    scope_functions.sort(key=lambda item: (item["start"], item["end"], item["name"]))

    # Disambiguate display names if two distinct static functions share the same symbol name.
    name_counts = {}
    for fn in scope_functions:
        name_counts[fn["name"]] = name_counts.get(fn["name"], 0) + 1
    for fn in scope_functions:
        if name_counts.get(fn["name"], 0) > 1:
            fn["id"] = "{}@{}".format(fn["name"], _fmt_u32(fn["start"]))
        else:
            fn["id"] = fn["name"]

    # Collect forced basic-block leaders from function entries.
    forced_leaders = set()
    for fn in scope_functions:
        forced_leaders.add(int(fn["start"]) & ~1)

    basic_blocks, literal_addrs = _discover_basic_blocks(
        elf_path, active_intervals, forced_leaders=forced_leaders
    )
    if not basic_blocks:
        raise RecoveryCoverageError(
            "configured recovery_coverage scope contains no executable instructions"
        )

    # Associate each basic block with its containing function(s).
    for bb in basic_blocks:
        bb_funcs = [
            fn["id"]
            for fn in scope_functions
            if _intervals_overlap(bb["start"], bb["end"], fn["start"], fn["end"])
        ]
        bb["functions"] = bb_funcs

    for fn in scope_functions:
        fn_pcs = sorted(
            set(
                bb["pc"]
                for bb in basic_blocks
                if _intervals_overlap(bb["start"], bb["end"], fn["start"], fn["end"])
            )
        )
        if not fn_pcs and fn["start"] not in literal_addrs:
            fn_pcs = [int(fn["start"]) & ~1]
        fn["probe_pcs"] = fn_pcs
        fn["basic_block_count"] = len(fn_pcs)

    scope_functions = [fn for fn in scope_functions if fn.get("probe_pcs")]
    if not scope_functions:
        raise RecoveryCoverageError(
            "configured recovery_coverage scope contains no executable functions or ranges"
        )

    # Build in-scope source line entries when DWARF .debug_line is available.
    scope_lines = []
    if has_debug_line:
        line_map = {}
        for span in line_spans:
            if source_queries and not (function_queries or normalized_ranges):
                if span["file"] not in matched_source_files:
                    continue
            clipped = _clip_to_intervals(
                span["start"], span["end"], active_intervals
            )
            if not clipped:
                continue
            key = (span["file"], int(span["line"]))
            entry = line_map.get(key)
            if entry is None:
                entry = {
                    "file": span["file"],
                    "line": int(span["line"]),
                    "spans": [],
                    "probe_pcs": set(),
                    "functions": set(),
                }
                line_map[key] = entry
            for c_start, c_end in clipped:
                entry["spans"].append((c_start, c_end))
                for bb in basic_blocks:
                    if _intervals_overlap(bb["start"], bb["end"], c_start, c_end):
                        entry["probe_pcs"].add(bb["pc"])
                        for fn_id in bb.get("functions") or ():
                            entry["functions"].add(fn_id)

        for (file_name, line_no), entry in sorted(line_map.items()):
            pcs = sorted(entry["probe_pcs"])
            if not pcs:
                continue
            fn_names = sorted(entry["functions"])
            min_addr = min(s for s, _e in entry["spans"])
            max_addr = max(e for _s, e in entry["spans"])
            scope_lines.append(
                {
                    "id": "{}:{}".format(file_name, line_no),
                    "file": file_name,
                    "line": int(line_no),
                    "function": fn_names[0] if fn_names else None,
                    "functions": fn_names,
                    "start_address": _fmt_u32(min_addr),
                    "end_address": _fmt_u32(max_addr),
                    "probe_pcs": pcs,
                }
            )

    line_info_available = bool(has_debug_line and scope_lines)
    if line_info_available:
        line_info_notice = None
    elif elf_path:
        line_info_notice = (
            "ELF lacks DWARF line information (.debug_line); "
            "reporting coverage per function only."
        )
    else:
        line_info_notice = (
            "No ELF DWARF line information available; "
            "reporting coverage per function/range only."
        )

    probe_pcs = sorted(set(bb["pc"] for bb in basic_blocks))

    return {
        "enabled": True,
        "mechanism": mechanism,
        "elf_path": str(elf_path) if elf_path else None,
        "line_info_available": line_info_available,
        "line_info_notice": line_info_notice,
        "granularity": (
            "function_and_line" if line_info_available else "function_only"
        ),
        "configured_functions": function_queries,
        "configured_source_files": source_queries,
        "configured_address_ranges": [
            {"start": _fmt_u32(item["start"]), "end": _fmt_u32(item["end"])}
            for item in normalized_ranges
        ],
        "active_intervals": [
            {"start": int(start), "end": int(end)}
            for start, end in active_intervals
        ],
        "probe_pcs": probe_pcs,
        "basic_blocks": basic_blocks,
        "functions": [
            {
                "id": fn["id"],
                "name": fn["name"],
                "start": int(fn["start"]),
                "end": int(fn["end"]),
                "start_address": _fmt_u32(fn["start"]),
                "end_address": _fmt_u32(fn["end"]),
                "size_bytes": int(fn["size"]),
                "probe_pcs": list(fn["probe_pcs"]),
                "basic_block_count": int(fn["basic_block_count"]),
            }
            for fn in scope_functions
        ],
        "lines": scope_lines,
    }


def _unpack_basic_block_bounds(bb):
    if isinstance(bb, dict):
        start = int(bb.get("start", bb.get("pc", 0))) & ~1
        end = int(bb.get("end", start + max(2, int(bb.get("size", 2)))))
        pc = int(bb.get("pc", start)) & ~1
        return pc, start, end
    if isinstance(bb, (tuple, list)) and len(bb) >= 2:
        start = int(bb[0]) & ~1
        end = int(bb[1])
        return start, start, end
    pc = _parse_pc(bb)
    return pc, pc, pc + 2


def resolve_executed_probe_pcs(scope, executed_pcs=(), executed_blocks=()):
    """Map raw recorded PCs or (start, size) blocks to canonical scope probe PCs."""
    if not isinstance(scope, dict):
        return ()
    probe_set = set(int(pc) & ~1 for pc in (scope.get("probe_pcs") or ()))
    basic_blocks = scope.get("basic_blocks") or ()
    matched = set()

    for raw_pc in executed_pcs or ():
        pc = _parse_pc(raw_pc)
        if pc in probe_set:
            matched.add(pc)
            continue
        for bb in basic_blocks:
            bb_pc, bb_start, bb_end = _unpack_basic_block_bounds(bb)
            if bb_start <= pc < bb_end:
                matched.add(bb_pc)
                break

    for item in executed_blocks or ():
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            b_start = _parse_pc(item[0])
            b_size = max(2, int(item[1]))
        elif isinstance(item, dict):
            b_start = _parse_pc(item.get("pc", item.get("start", 0)))
            b_size = max(2, int(item.get("size", 2)))
        else:
            b_start = _parse_pc(item)
            b_size = 2
        b_end = b_start + b_size
        for bb in basic_blocks:
            bb_pc, bb_start, bb_end = _unpack_basic_block_bounds(bb)
            if _intervals_overlap(b_start, b_end, bb_start, bb_end):
                matched.add(bb_pc)

    return tuple(sorted(matched))


def coverage_signature_hex(units):
    digest = hashlib.sha256()
    digest.update(b"tardigrade-recovery-coverage-v1\0")
    for unit in sorted(set(int(u) & ~1 for u in (units or ()))):
        digest.update("{:08X};".format(unit & 0xFFFFFFFF).encode("ascii"))
    return binascii.hexlify(digest.digest()).decode("ascii")


def _format_point_descriptor(result, boot_index=None):
    rss = result.get("recovery_state_search")
    if isinstance(rss, dict):
        chain = rss.get("chain") or {}
        chain_text = chain.get("text") or "state:{}".format(
            rss.get("state_identity", "")
        )
        cuts = list(chain.get("cuts") or [])
        first_op = None
        if cuts and isinstance(cuts[0], dict):
            first_op = cuts[0].get("operation") or cuts[0].get("fault_type")
        raw_op = str(
            result.get("operation_kind") or first_op or ""
        ).strip().lower()
        op_kind = (
            "erase"
            if raw_op in ("erase", "e", "a", "interrupted_erase", "multi_sector_atomicity")
            else "program"
        )
        return {
            "kind": "state",
            "boot_index": int(boot_index) if boot_index is not None else None,
            "label": str(chain_text),
            "state_identity": rss.get("state_identity"),
            "generation": int(rss.get("generation", 1)),
            "chain": str(chain_text),
            "cuts": copy.deepcopy(cuts),
            "fault_type": str(result.get("fault_type") or "rs"),
            "fault_at": int(result.get("fault_at", 0) or 0),
            "operation_kind": op_kind,
        }

    p2_chain = result.get("phase2_fault_chain")
    if isinstance(p2_chain, dict) and p2_chain.get("cuts"):
        cuts = p2_chain["cuts"]
        label = " -> ".join(
            "{}[{}]".format(cut.get("fault_type", "w"), cut.get("fault_at", 0))
            for cut in cuts
        )
        first_ft = str(cuts[0].get("fault_type") or cuts[0].get("operation") or "w").strip().lower()
        op_kind = (
            "erase"
            if first_ft in ("erase", "e", "a", "interrupted_erase", "multi_sector_atomicity")
            else "program"
        )
        return {
            "kind": "point",
            "boot_index": int(boot_index) if boot_index is not None else None,
            "label": label,
            "fault_type": str(result.get("fault_type") or "pc"),
            "fault_at": int(result.get("fault_at", 0) or 0),
            "operation_kind": op_kind,
            "fault_address": result.get("fault_address"),
        }

    p2 = result.get("phase2_fault")
    if isinstance(p2, dict) and "p1_fault_at" in p2 and "p2_fault_at" in p2:
        p1_ft = str(p2.get("p1_fault_type", "w"))
        p2_ft = str(p2.get("p2_fault_type", "w"))
        label = "p2:{}:{}:{}:{}".format(
            p2.get("p1_fault_at", 0),
            p2.get("p2_fault_at", 0),
            p1_ft,
            p2_ft,
        )
        p1_base = p1_ft.split(":", 1)[0].strip().lower()
        op_kind = (
            "erase"
            if p1_base in ("erase", "e", "a", "interrupted_erase", "multi_sector_atomicity")
            else "program"
        )
        return {
            "kind": "point",
            "boot_index": int(boot_index) if boot_index is not None else None,
            "label": label,
            "fault_type": str(result.get("fault_type") or "p2"),
            "fault_at": int(result.get("fault_at", 0) or 0),
            "operation_kind": op_kind,
            "fault_address": result.get("fault_address"),
        }

    raw_op_kind = str(result.get("operation_kind") or "").strip().lower()
    raw_ft = result.get("fault_type")
    if raw_ft:
        ft = str(raw_ft)
    elif raw_op_kind in ("erase", "e", "a", "interrupted_erase", "multi_sector_atomicity"):
        ft = "e"
    else:
        ft = "w"
    ft_base = ft.split(":", 1)[0].strip().lower()
    if raw_op_kind in ("erase", "program"):
        op_kind = raw_op_kind
    elif ft_base in ("e", "a", "interrupted_erase", "multi_sector_atomicity"):
        op_kind = "erase"
    else:
        op_kind = "program"
    fp = int(result.get("fault_at", 0) or 0)
    return {
        "kind": "point",
        "boot_index": int(boot_index) if boot_index is not None else None,
        "label": "{}@{}".format(ft, fp),
        "fault_type": ft,
        "fault_at": fp,
        "operation_kind": op_kind,
        "fault_address": result.get("fault_address"),
    }


def extract_result_coverage_pcs(result, scope=None):
    """Extract canonical executed probe PCs from one runtime result."""
    if not isinstance(result, dict):
        return ()
    cov = result.get("recovery_coverage")
    raw_pcs = ()
    raw_blocks = ()
    if isinstance(cov, dict):
        raw_pcs = cov.get("executed_pcs") or ()
        raw_blocks = cov.get("executed_blocks") or ()
    elif isinstance(result.get("signals"), dict):
        raw_pcs = result["signals"].get("recovery_coverage_pcs") or ()
    if scope is not None:
        return resolve_executed_probe_pcs(
            scope, executed_pcs=raw_pcs, executed_blocks=raw_blocks
        )
    return tuple(sorted(set(_parse_pc(pc) for pc in raw_pcs)))


def _is_control_result(result):
    if not isinstance(result, dict):
        return False
    if result.get("is_control", False):
        return True
    try:
        return int(result.get("fault_at", 0) or 0) < 0
    except (TypeError, ValueError):
        return False


def summarize_recovery_coverage(results, scope, state_search_summary=None):
    """Build per-function, per-line, and coverage-vs-boots attribution report."""
    if not isinstance(scope, dict) or not scope.get("enabled"):
        return None

    results = list(results or ())
    control_results = [r for r in results if _is_control_result(r)]
    cut_results = [
        r
        for r in results
        if isinstance(r, dict)
        and not _is_control_result(r)
        and r.get("fault_injected") is True
    ]

    # Audit rows can be sorted by fault point after the search. Recover the
    # visit order for known states while retaining other points in their slots.
    if isinstance(state_search_summary, dict):
        visit_order = {
            visit["state_identity"]: visit["boot_index"]
            for visit in state_search_summary.get("coverage_by_boot") or ()
        }
        ranked = []
        for slot, row in enumerate(cut_results):
            state = (row.get("recovery_state_search") or {}).get("state_identity")
            if state in visit_order:
                ranked.append((visit_order[state], slot))
        ordered = [cut_results[slot] for _, slot in sorted(ranked)]
        for (_, slot), row in zip(ranked, ordered):
            cut_results[slot] = row

    control_pcs = set()
    control_recorded = False
    for ctrl in control_results:
        if isinstance(ctrl.get("recovery_coverage"), dict):
            control_recorded = True
        control_pcs.update(extract_result_coverage_pcs(ctrl, scope=scope))

    cut_boot_records = []
    all_cut_pcs = set()
    first_reached_by_pc = {}
    cut_count_by_pc = {}
    consecutive_no_new = 0
    max_consecutive_no_new = 0
    boots_with_new = 0
    overhead_samples = []
    boot_wall_samples = []

    for ctrl in control_results:
        cov_meta = ctrl.get("recovery_coverage")
        if (
            isinstance(cov_meta, dict)
            and cov_meta.get("recording_overhead_s") is not None
        ):
            overhead_samples.append(
                float(cov_meta.get("recording_overhead_s") or 0.0)
            )
        if (
            isinstance(cov_meta, dict)
            and cov_meta.get("boot_wall_time_s") is not None
        ):
            boot_wall_samples.append(
                float(cov_meta.get("boot_wall_time_s") or 0.0)
            )

    scope_functions = scope.get("functions") or ()
    scope_lines = scope.get("lines") or ()
    line_info_available = bool(scope.get("line_info_available"))

    for boot_index, result in enumerate(cut_results, start=1):
        boot_pcs = set(extract_result_coverage_pcs(result, scope=scope))
        new_pcs = boot_pcs - all_cut_pcs
        if new_pcs:
            consecutive_no_new = 0
            boots_with_new += 1
        else:
            consecutive_no_new += 1
            if consecutive_no_new > max_consecutive_no_new:
                max_consecutive_no_new = consecutive_no_new

        descriptor = _format_point_descriptor(result, boot_index=boot_index)
        for pc in sorted(boot_pcs):
            cut_count_by_pc[pc] = cut_count_by_pc.get(pc, 0) + 1
            if pc not in first_reached_by_pc:
                first_reached_by_pc[pc] = descriptor
        all_cut_pcs.update(boot_pcs)

        cov_meta = result.get("recovery_coverage")
        rec_overhead_s = None
        if isinstance(cov_meta, dict) and cov_meta.get("recording_overhead_s") is not None:
            rec_overhead_s = float(cov_meta.get("recording_overhead_s") or 0.0)
            overhead_samples.append(rec_overhead_s)
        signals = result.get("signals") or {}
        if isinstance(signals, dict) and signals.get("emulation_ms") is not None:
            boot_wall_samples.append(float(signals.get("emulation_ms") or 0.0) / 1000.0)
        elif (
            isinstance(cov_meta, dict)
            and cov_meta.get("boot_wall_time_s") is not None
        ):
            boot_wall_samples.append(
                float(cov_meta.get("boot_wall_time_s") or 0.0)
            )

        cum_funcs = sum(
            1
            for fn in scope_functions
            if any(pc in all_cut_pcs for pc in (fn.get("probe_pcs") or ()))
        )
        cum_lines = (
            sum(
                1
                for ln in scope_lines
                if any(pc in all_cut_pcs for pc in (ln.get("probe_pcs") or ()))
            )
            if line_info_available
            else 0
        )

        boot_entry = {
            "boot_index": boot_index,
            "label": descriptor["label"],
            "kind": descriptor["kind"],
            "fault_at": descriptor.get("fault_at"),
            "fault_type": descriptor.get("fault_type"),
            "operation_kind": descriptor.get("operation_kind"),
            "boot_executed_units": len(boot_pcs),
            "new_units": len(new_pcs),
            "cumulative_units": len(all_cut_pcs),
            "cumulative_functions": cum_funcs,
            "consecutive_boots_without_new_coverage": consecutive_no_new,
        }
        if line_info_available:
            boot_entry["cumulative_lines"] = cum_lines
        if descriptor.get("state_identity") is not None:
            boot_entry["state_identity"] = descriptor["state_identity"]
            boot_entry["generation"] = descriptor["generation"]
            boot_entry["chain"] = descriptor["chain"]
        if rec_overhead_s is not None:
            boot_entry["recording_overhead_s"] = round(rec_overhead_s, 6)
        cut_boot_records.append(boot_entry)

    # Attribute coverage to each function in scope.
    functions_report = []
    fn_by_control = []
    fn_only_under_cut = []
    fn_never_by_cut = []
    fn_never_any = 0

    for fn in scope_functions:
        fn_pcs = [int(pc) & ~1 for pc in (fn.get("probe_pcs") or ())]
        ctrl_hit_pcs = [pc for pc in fn_pcs if pc in control_pcs]
        cut_hit_pcs = [pc for pc in fn_pcs if pc in all_cut_pcs]
        exec_by_ctrl = len(ctrl_hit_pcs) > 0
        exec_by_cut = len(cut_hit_pcs) > 0
        exec_only_cut = bool(exec_by_cut and not exec_by_ctrl)
        never_by_cut = not exec_by_cut

        first_reached = None
        cut_exec_count = 0
        if exec_by_cut:
            reaching_records = [
                first_reached_by_pc[pc]
                for pc in cut_hit_pcs
                if pc in first_reached_by_pc
            ]
            if reaching_records:
                first_reached = min(
                    reaching_records,
                    key=lambda item: int(item.get("boot_index") or 0),
                )
            cut_exec_count = max(
                cut_count_by_pc.get(pc, 0) for pc in cut_hit_pcs
            )

        # Also track the first cut that reached a basic block inside this
        # function that the clean control did NOT execute!
        cut_only_pcs = [pc for pc in cut_hit_pcs if pc not in control_pcs]
        first_cut_only_reached = None
        if cut_only_pcs:
            cut_only_records = [
                first_reached_by_pc[pc]
                for pc in cut_only_pcs
                if pc in first_reached_by_pc
            ]
            if cut_only_records:
                first_cut_only_reached = min(
                    cut_only_records,
                    key=lambda item: int(item.get("boot_index") or 0),
                )

        if exec_only_cut:
            status = "executed_only_under_cut"
            cut_status = "executed_only_under_cut"
        elif exec_by_ctrl and exec_by_cut:
            status = "executed_by_control"
            cut_status = "executed_by_control_and_cut"
        elif exec_by_ctrl:
            status = "executed_by_control"
            cut_status = "executed_by_control_only"
        else:
            status = "never_executed_by_cut"
            cut_status = "never_executed"
            fn_never_any += 1

        fn_entry = {
            "id": fn["id"],
            "name": fn["name"],
            "start_address": fn["start_address"],
            "end_address": fn["end_address"],
            "size_bytes": int(fn["size_bytes"]),
            "status": status,
            "classification": status,
            "cut_status": cut_status,
            "executed_by_control": exec_by_ctrl,
            "executed_by_cut": exec_by_cut,
            "executed_only_under_cut": exec_only_cut,
            "never_executed_by_cut": never_by_cut,
            "cut_execution_count": int(cut_exec_count),
            "first_reached_by": copy.deepcopy(first_reached),
            "first_cut_only_block_reached_by": copy.deepcopy(
                first_cut_only_reached
            ),
            "total_basic_blocks": len(fn_pcs),
            "control_basic_blocks": len(ctrl_hit_pcs),
            "cut_basic_blocks": len(cut_hit_pcs),
            "cut_only_basic_blocks": len(cut_only_pcs),
            "uncovered_basic_blocks": len(
                [pc for pc in fn_pcs if pc not in all_cut_pcs]
            ),
            "uncovered_block_addresses": [
                _fmt_u32(pc) for pc in fn_pcs if pc not in all_cut_pcs
            ],
        }
        functions_report.append(fn_entry)
        if exec_by_ctrl:
            fn_by_control.append(fn["id"])
        if exec_only_cut:
            fn_only_under_cut.append(
                {
                    "function": fn["id"],
                    "start_address": fn["start_address"],
                    "first_reached_by": copy.deepcopy(first_reached),
                }
            )
        if never_by_cut:
            fn_never_by_cut.append(fn["id"])

    # Attribute coverage to each source line in scope when DWARF line info exists.
    lines_report = []
    line_summary = None
    if line_info_available:
        ln_by_control = []
        ln_only_under_cut = []
        ln_never_by_cut = []
        ln_never_any = 0

        for ln in scope_lines:
            ln_pcs = [int(pc) & ~1 for pc in (ln.get("probe_pcs") or ())]
            ctrl_hit_pcs = [pc for pc in ln_pcs if pc in control_pcs]
            cut_hit_pcs = [pc for pc in ln_pcs if pc in all_cut_pcs]
            exec_by_ctrl = len(ctrl_hit_pcs) > 0
            exec_by_cut = len(cut_hit_pcs) > 0
            exec_only_cut = bool(exec_by_cut and not exec_by_ctrl)
            never_by_cut = not exec_by_cut

            first_reached = None
            cut_exec_count = 0
            if exec_by_cut:
                reaching_records = [
                    first_reached_by_pc[pc]
                    for pc in cut_hit_pcs
                    if pc in first_reached_by_pc
                ]
                if reaching_records:
                    first_reached = min(
                        reaching_records,
                        key=lambda item: int(item.get("boot_index") or 0),
                    )
                cut_exec_count = max(
                    cut_count_by_pc.get(pc, 0) for pc in cut_hit_pcs
                )

            if exec_only_cut:
                status = "executed_only_under_cut"
                cut_status = "executed_only_under_cut"
            elif exec_by_ctrl and exec_by_cut:
                status = "executed_by_control"
                cut_status = "executed_by_control_and_cut"
            elif exec_by_ctrl:
                status = "executed_by_control"
                cut_status = "executed_by_control_only"
            else:
                status = "never_executed_by_cut"
                cut_status = "never_executed"
                ln_never_any += 1

            ln_entry = {
                "id": ln["id"],
                "file": ln["file"],
                "line": int(ln["line"]),
                "function": ln.get("function"),
                "functions": list(ln.get("functions") or ()),
                "start_address": ln["start_address"],
                "end_address": ln["end_address"],
                "status": status,
                "classification": status,
                "cut_status": cut_status,
                "executed_by_control": exec_by_ctrl,
                "executed_by_cut": exec_by_cut,
                "executed_only_under_cut": exec_only_cut,
                "never_executed_by_cut": never_by_cut,
                "cut_execution_count": int(cut_exec_count),
                "first_reached_by": copy.deepcopy(first_reached),
            }
            lines_report.append(ln_entry)
            if exec_by_ctrl:
                ln_by_control.append(ln["id"])
            if exec_only_cut:
                ln_only_under_cut.append(
                    {
                        "line_id": ln["id"],
                        "file": ln["file"],
                        "line": int(ln["line"]),
                        "function": ln.get("function"),
                        "first_reached_by": copy.deepcopy(first_reached),
                    }
                )
            if never_by_cut:
                ln_never_by_cut.append(ln["id"])

        line_summary = {
            "total": len(lines_report),
            "executed_by_control_count": len(ln_by_control),
            "executed_by_cut_count": sum(
                1 for item in lines_report if item["executed_by_cut"]
            ),
            "executed_only_under_cut_count": len(ln_only_under_cut),
            "never_executed_by_cut_count": len(ln_never_by_cut),
            "never_executed_count": ln_never_any,
            "executed_by_control": ln_by_control,
            "executed_only_under_cut": ln_only_under_cut,
            "never_executed_by_cut": ln_never_by_cut,
        }

    total_probe_pcs = len(scope.get("probe_pcs") or ())
    total_overhead_s = sum(overhead_samples)
    mean_overhead_s = (
        total_overhead_s / len(overhead_samples) if overhead_samples else 0.0
    )
    max_overhead_s = max(overhead_samples) if overhead_samples else 0.0
    mean_boot_wall_s = (
        sum(boot_wall_samples) / len(boot_wall_samples)
        if boot_wall_samples
        else 0.0
    )
    overhead_fraction = (
        mean_overhead_s / mean_boot_wall_s
        if mean_boot_wall_s > 0.0 and overhead_samples
        else 0.0
    )

    report = {
        "enabled": True,
        "mechanism": str(scope.get("mechanism") or "oneshot_address_hooks"),
        "granularity": (
            "function_and_line" if line_info_available else "function_only"
        ),
        "line_info_available": line_info_available,
        "line_info_notice": scope.get("line_info_notice"),
        "configured_scope": {
            "functions": list(scope.get("configured_functions") or ()),
            "source_files": list(scope.get("configured_source_files") or ()),
            "address_ranges": list(scope.get("configured_address_ranges") or ()),
            "total_probe_pcs": total_probe_pcs,
            "total_basic_blocks": len(scope.get("basic_blocks") or ()),
            "total_functions": len(functions_report),
            "total_lines": len(lines_report),
        },
        "control_recorded": control_recorded,
        "cut_boots_recorded": len(cut_boot_records),
        "basic_block_summary": {
            "total": total_probe_pcs,
            "executed_by_control_count": len(control_pcs),
            "executed_by_cut_count": len(all_cut_pcs),
            "executed_only_under_cut_count": len(all_cut_pcs - control_pcs),
            "never_executed_by_cut_count": total_probe_pcs - len(all_cut_pcs),
        },
        "function_summary": {
            "total": len(functions_report),
            "executed_by_control_count": len(fn_by_control),
            "executed_by_cut_count": sum(
                1 for item in functions_report if item["executed_by_cut"]
            ),
            "executed_only_under_cut_count": len(fn_only_under_cut),
            "never_executed_by_cut_count": len(fn_never_by_cut),
            "never_executed_count": fn_never_any,
            "executed_by_control": fn_by_control,
            "executed_only_under_cut": fn_only_under_cut,
            "never_executed_by_cut": fn_never_by_cut,
        },
        "line_summary": line_summary,
        "functions": functions_report,
        "lines": lines_report,
        "coverage_by_boot": cut_boot_records,
        "boots_reaching_new_coverage": boots_with_new,
        "max_consecutive_boots_without_new_coverage": max_consecutive_no_new,
        "recording_overhead": {
            "mechanism": str(scope.get("mechanism") or "oneshot_address_hooks"),
            "boots_measured": len(overhead_samples),
            "total_recording_overhead_s": round(total_overhead_s, 6),
            "mean_recording_overhead_s": round(mean_overhead_s, 6),
            "max_recording_overhead_s": round(max_overhead_s, 6),
            "mean_boot_emulation_s": round(mean_boot_wall_s, 6),
            "overhead_ratio": round(overhead_fraction, 6),
        },
    }
    if isinstance(state_search_summary, dict):
        report["state_search"] = {
            "order": state_search_summary.get("order", "breadth_first"),
            "max_boots_without_new_coverage": state_search_summary.get(
                "max_boots_without_new_coverage"
            ),
            "stopped_reason": state_search_summary.get("stopped_reason"),
            "states_booted": state_search_summary.get("states_booted"),
            "coverage_units_reached": state_search_summary.get(
                "coverage_units_reached", len(all_cut_pcs)
            ),
            "boots_reaching_new_coverage": state_search_summary.get(
                "boots_reaching_new_coverage", boots_with_new
            ),
            "states_excluded_by_coverage_plateau": state_search_summary.get(
                "states_excluded_by_coverage_plateau", 0
            ),
        }
    return report


def partition_first_cuts_for_shard(first_cuts, shard_count, shard_index):
    """Deterministically split canonical first cuts across shards."""
    if not _is_int(shard_count) or int(shard_count) < 1:
        raise RecoveryCoverageError("shard_count must be a positive integer")
    if not _is_int(shard_index) or not (0 <= int(shard_index) < int(shard_count)):
        raise RecoveryCoverageError(
            "shard_index must satisfy 0 <= shard_index < shard_count"
        )
    shard_count = int(shard_count)
    shard_index = int(shard_index)
    canonical = tuple(first_cuts or ())
    return tuple(
        cut for idx, cut in enumerate(canonical) if (idx % shard_count) == shard_index
    )


def merge_sharded_coverage_results(shard_batches, scope, control_results=()):
    """Deterministically merge sharded state-search results and recompute global coverage.

    Each entry in ``shard_batches`` is ``(shard_index, results_list)`` or a
    ``results_list`` in canonical shard order.  Duplicate persistent states
    booted independently by different shards are deduplicated by
    ``state_identity`` (first canonical shard wins; later chains attach to
    ``equivalent_chains``), and global coverage attribution and the
    coverage-against-boots curve are recomputed from the merged sequence.
    """
    normalized_batches = []
    for idx, batch in enumerate(shard_batches or ()):
        if (
            isinstance(batch, dict)
            and "shard_index" in batch
            and "results" in batch
        ):
            normalized_batches.append(
                (int(batch["shard_index"]), list(batch["results"] or ()))
            )
        elif (
            isinstance(batch, (tuple, list))
            and len(batch) == 2
            and _is_int(batch[0])
        ):
            normalized_batches.append((int(batch[0]), list(batch[1] or ())))
        else:
            normalized_batches.append((idx, list(batch or ())))
    normalized_batches.sort(key=lambda item: item[0])

    merged_results = [copy.deepcopy(r) for r in (control_results or ())]
    seen_identities = {}
    states_deduplicated_across_shards = 0

    for shard_index, results in normalized_batches:
        for result in results:
            if not isinstance(result, dict):
                continue
            if _is_control_result(result):
                if not any(_is_control_result(r) for r in merged_results):
                    merged_results.append(copy.deepcopy(result))
                continue
            rss = result.get("recovery_state_search")
            identity = (
                rss.get("state_identity") if isinstance(rss, dict) else None
            )
            if identity and identity in seen_identities:
                states_deduplicated_across_shards += 1
                existing = seen_identities[identity]
                existing_rss = existing.setdefault("recovery_state_search", {})
                equiv = existing_rss.setdefault("equivalent_chains", [])
                new_chain = copy.deepcopy((rss or {}).get("chain"))
                if new_chain and not any(
                    item.get("cuts") == new_chain.get("cuts") for item in equiv
                ):
                    equiv.append(new_chain)
                for extra_chain in (rss or {}).get("equivalent_chains") or ():
                    if not any(
                        item.get("cuts") == extra_chain.get("cuts")
                        for item in equiv
                    ):
                        equiv.append(copy.deepcopy(extra_chain))
                continue
            cloned = copy.deepcopy(result)
            if isinstance(cloned.get("recovery_state_search"), dict):
                cloned["recovery_state_search"]["shard_index"] = shard_index
            if identity:
                seen_identities[identity] = cloned
            merged_results.append(cloned)

    report = summarize_recovery_coverage(merged_results, scope)
    if isinstance(report, dict):
        report["sharding"] = {
            "shards_merged": len(normalized_batches),
            "states_deduplicated_across_shards": states_deduplicated_across_shards,
            "merged_cut_boots": report.get("cut_boots_recorded", 0),
        }
    return merged_results, report


def describe_coverage_sizing(scope, first_cuts=(), order="breadth_first", max_boots_without_new_coverage=None):
    """Return plan-only static sizing metadata for recovery coverage and state search."""
    if not isinstance(scope, dict) or not scope.get("enabled"):
        return {"enabled": False}
    if order not in SUPPORTED_STATE_SEARCH_ORDERS:
        raise RecoveryCoverageError(
            "unsupported state_search order {!r}".format(order)
        )
    return {
        "enabled": True,
        "mechanism": scope.get("mechanism", "oneshot_address_hooks"),
        "granularity": scope.get("granularity", "function_only"),
        "line_info_available": bool(scope.get("line_info_available")),
        "total_functions": len(scope.get("functions") or ()),
        "total_lines": len(scope.get("lines") or ()),
        "total_basic_blocks": len(scope.get("basic_blocks") or ()),
        "total_probe_pcs": len(scope.get("probe_pcs") or ()),
        "selected_first_cuts": len(tuple(first_cuts or ())),
        "order": str(order),
        "max_boots_without_new_coverage": (
            int(max_boots_without_new_coverage)
            if max_boots_without_new_coverage is not None
            else None
        ),
        "max_oneshot_hooks_per_boot": len(scope.get("probe_pcs") or ()),
    }
