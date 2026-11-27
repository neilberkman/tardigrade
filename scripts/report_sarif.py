# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""SARIF 2.1.0 serialization of distinct runtime audit findings."""

from __future__ import annotations

import os
from bisect import bisect_right
from collections import defaultdict
from functools import cached_property
from itertools import chain
from pathlib import Path
from urllib.parse import quote

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from report_points import reproduction

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"


class SourceLocations:
    def __init__(self, elf, root):
        self.elf = elf
        self.root = root.resolve()

    @cached_property
    def index(self):
        ranges = []
        symbols = {}
        if self.elf and self.elf.is_file():
            try:
                with self.elf.open("rb") as stream:
                    elf = ELFFile(stream)
                    if elf.has_dwarf_info(strict=True):
                        table = elf.get_section_by_name(".symtab")
                        if table:
                            symbols = {s.name: s["st_value"] for s in table.iter_symbols()
                                       if s["st_info"]["type"] == "STT_FUNC"}
                        ranges = sorted(self._line_ranges(elf.get_dwarf_info()))
            except (ELFError, OSError):
                pass
        return [r[0] for r in ranges], ranges, symbols

    def _line_ranges(self, dwarf):
        for unit in dwarf.iter_CUs():
            program = dwarf.line_program_for_CU(unit)
            if program is None:
                continue
            attribute = unit.get_top_DIE().attributes.get("DW_AT_comp_dir")
            directory = Path(os.fsdecode(attribute.value)) if attribute else Path(".")
            previous = None
            files = {}
            base = 0 if program["version"] >= 5 else 1
            for entry in program.get_entries():
                state = entry.state
                if state is None:
                    continue
                if previous and previous.line and previous.address < state.address:
                    file_id = previous.file
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
                    yield previous.address, state.address, files[file_id], previous.line
                previous = None if state.end_sequence else state

    def lookup(self, row):
        signals = row.get("signals") or {}
        rc = row.get("rc_injection") or signals.get("rc_injection") or {}
        starts, ranges, symbols = self.index
        candidates = (signals.get("skip_address"), row.get("fault_pc"), row.get("firmware_address"),
                      symbols.get(rc.get("applied_symbol") or row.get("firmware_symbol") or row.get("symbol")
                                  or signals.get("rc_injection_symbol")), rc.get("applied_return_address"),
                      row.get("fault_address"), signals.get("pc"), row.get("pc"))
        for value in candidates:
            if value is None:
                continue
            try:
                address = int(str(value), 0)
            except ValueError:
                continue
            index = bisect_right(starts, address) - 1
            if index >= 0:
                _, end, path, line = ranges[index]
                if address < end:
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


def sarif_run(run, root):
    sources = {}
    groups = defaultdict(list)
    for point in chain(run.points(), run.additional_findings()):
        if not point.findings:
            continue
        elf = point.elf or run.elf
        if elf not in sources:
            sources[elf] = SourceLocations(elf, root)
        source = sources[elf]
        location = source.lookup(point.row)
        if not location:
            location = (source.uri(run.profile_path), 1)
        seen = set()
        for finding in point.findings:
            key = (finding.rule, finding.subject, location, point.component or "")
            if key not in seen:
                groups[key].append((point, finding))
                seen.add(key)
    rule_ids = sorted({key[0] for key in groups})
    rules = [{"id": rule, "shortDescription": {"text": rule.replace("_", " ")}} for rule in rule_ids]
    results = []
    for (rule, _, (uri, line), component), entries in sorted(groups.items()):
        message = entries[0][1].message
        points = [{"name": point.name, "kind": point.kind, "reproduction": point.selector or reproduction(point.row)}
                  for point, _ in entries]
        properties = {"profile": run.name, "points": points}
        if component:
            properties["component"] = component
        results.append({
            "ruleId": rule, "level": "error",
            "message": {"text": f"{message} ({len(points)} affected point(s))"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
            "properties": properties,
        })
    aggregate = run.data.get("security_aggregate") or {}
    incomplete = aggregate.get("inconclusive_reasons") or []
    if not incomplete and (run.data.get("error") or str(run.data.get("verdict", "")).startswith("INCONCLUSIVE")):
        incomplete = [run.data.get("error") or run.data["verdict"]]
    invocation = {"executionSuccessful": not incomplete}
    if incomplete:
        invocation["toolExecutionNotifications"] = [{"message": {"text": reason}} for reason in incomplete]
    return {"tool": {"driver": {"name": "Tardigrade", "rules": rules}},
            "automationDetails": {"id": f"{run.name}/"}, "invocations": [invocation], "results": results}


def sarif_report(runs, root):
    return {"version": "2.1.0", "$schema": SARIF_SCHEMA, "runs": [sarif_run(run, root) for run in runs]}
