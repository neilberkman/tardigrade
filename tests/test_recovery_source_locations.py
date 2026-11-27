# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

from elftools.elf.elffile import ELFFile
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_sarif import SourceLocations


@pytest.mark.parametrize(("asset", "evidence"), [
    ("phase2_mram_parity/firmware.elf", "dwarf"),
    ("naive_copy/bootloader_bare_copy.elf", "symbol_table"),
])
def test_recovery_pc_resolves_inside_function(asset, evidence):
    elf = ROOT / "examples" / asset
    with elf.open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        function = next(s for s in table.iter_symbols()
                        if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] >= 8)
        pc = (function["st_value"] & ~1) + 2
    locations = SourceLocations(elf, ROOT)
    observed = locations.resolve_pc(hex(pc))
    assert observed["function"] == function.name
    assert observed["resolution"] == evidence
    if evidence == "dwarf":
        assert Path(observed["file"]).name == "firmware.c" and observed["line"] > 0
    else:
        assert "file" not in observed and "line" not in observed
    assert locations.resolve_pc(0xFFFFFFFE) == {"pc": "0xFFFFFFFE", "resolution": "address_only"}
