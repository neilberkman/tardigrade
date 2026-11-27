# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Resolve observed addresses in the matching executable."""

from __future__ import annotations

import os
from bisect import bisect_right
from functools import cached_property
from pathlib import Path
from urllib.parse import quote

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

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
