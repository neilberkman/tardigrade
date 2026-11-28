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


def test_call_chain_unwinding_dwarf_prologue_and_lr_fallback():
    import struct

    # 1. DWARF .debug_frame unwinding on phase2_mram_parity/firmware.elf
    dwarf_elf = ROOT / "examples/phase2_mram_parity/firmware.elf"
    dwarf_loc = SourceLocations(dwarf_elf, ROOT)
    # HardFault_Handler at 0x1000001C is a leaf function; LR points into Reset_Handler (0x10000065 -> callsite 0x10000060).
    dwarf_ctx = "0x1000001C@0x10000065@0x20007F00@0x00000000@0x00000000@"
    chain, caller = dwarf_loc.resolve_call_chain("0x1000001C", dwarf_ctx)
    assert [frame["function"] for frame in chain] == ["HardFault_Handler", "Reset_Handler"]
    assert all(frame["resolution"] == "dwarf" for frame in chain)
    assert caller["function"] == "HardFault_Handler"

    # Extending driver_functions via profile list skips HardFault_Handler and reports Reset_Handler.
    chain_ext, caller_ext = dwarf_loc.resolve_call_chain(
        "0x1000001C", dwarf_ctx, driver_functions=("HardFault_Handler",)
    )
    assert [frame["function"] for frame in chain_ext] == ["HardFault_Handler", "Reset_Handler"]
    assert caller_ext["function"] == "Reset_Handler"

    # 2. Thumb prologue stack-walk unwinding on oss_mcuboot_pr3011_move_broken.elf
    # (.debug_frame absent; .ARM.exidx is EXIDX_CANTUNWIND; .symtab + .text present).
    mcu_elf = ROOT / "results/oss_validation/assets/oss_mcuboot_pr3011_move_broken.elf"
    mcu_loc = SourceLocations(mcu_elf, ROOT)
    # Frame 0: nvmc_word_write (0x00003D72, leaf, cfa_off=0)
    # Frame 1: nrfx_nvmc_word_write (LR=0x00003DCF -> 0x00003DCA, push {r4, lr}, cfa_off=8, lr at sp+4)
    # Frame 2: flash_nrf_write (saved LR=0x000024D7 -> 0x000024D2, stmdb sp!, {r3..r9, lr}, cfa_off=32, lr at sp+36)
    # Frame 3: boot_write_magic (saved LR=0x00003E1B -> 0x00003E16, stmdb sp!, {r4..r7, lr}; sub sp, #12, cfa_off=32, lr at sp+68)
    # Frame 4: fixup_revert (saved LR=0x00001379 -> 0x00001374)
    stack = bytearray(96)
    struct.pack_into("<I", stack, 4, 0x000024D7)
    struct.pack_into("<I", stack, 36, 0x00003E1B)
    struct.pack_into("<I", stack, 68, 0x00001379)
    mcu_ctx = f"0x00003D72@0x00003DCF@0x2003FE00@0x00000000@0x00000000@{stack.hex()}"
    mcu_chain, mcu_caller = mcu_loc.resolve_call_chain("0x00003D72", mcu_ctx)
    assert [frame["function"] for frame in mcu_chain[:5]] == [
        "nvmc_word_write",
        "nrfx_nvmc_word_write",
        "flash_nrf_write",
        "boot_write_magic",
        "fixup_revert",
    ]
    # Default driver detection skips nvmc_word_write, nrfx_nvmc_word_write, and flash_nrf_write.
    assert mcu_caller["function"] == "boot_write_magic"

    # Frame 3 = boot_write_trailer (0x000056FF -> 0x000056FA, stmdb sp!, {r4..r8, lr}; sub sp, #16, cfa_off=40, lr at sp+76)
    # Frame 4 = swap_status_init (0x00004D99 -> 0x00004D94)
    stack_trailer = bytearray(96)
    struct.pack_into("<I", stack_trailer, 4, 0x000024D7)
    struct.pack_into("<I", stack_trailer, 36, 0x000056FF)
    struct.pack_into("<I", stack_trailer, 76, 0x00004D99)
    trailer_ctx = f"0x00003D72@0x00003DCF@0x2003FE00@0x00000000@0x00000000@{stack_trailer.hex()}"
    trailer_chain, trailer_caller = mcu_loc.resolve_call_chain("0x00003D72", trailer_ctx)
    assert [frame["function"] for frame in trailer_chain[:5]] == [
        "nvmc_word_write",
        "nrfx_nvmc_word_write",
        "flash_nrf_write",
        "boot_write_trailer",
        "swap_status_init",
    ]
    assert trailer_caller["function"] == "boot_write_trailer"

    # 3. LR-only fallback when no stack snapshot is available.
    lr_only_chain, lr_only_caller = mcu_loc.resolve_call_chain("0x00003D72", "0x00003D72@0x00003E1B")
    assert [frame["function"] for frame in lr_only_chain] == [
        "nvmc_word_write",
        "boot_write_magic",
    ]
    assert lr_only_caller["function"] == "boot_write_magic"
