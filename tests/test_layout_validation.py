import os
import struct
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from layout_validation import (  # noqa: E402
    LayoutValidationError,
    parse_elf_load_intervals,
    validate_load_plan,
)


def _elf_bytes(segments, elf_class=1, byte_order="<"):
    """Build a minimal ELF containing the requested program headers."""

    endian_id = 1 if byte_order == "<" else 2
    ident = b"\x7fELF" + bytes([elf_class, endian_id, 1]) + (b"\x00" * 9)
    if elf_class == 1:
        ehsize = 52
        phentsize = 32
        header = struct.pack(
            byte_order + "HHIIIIIHHHHHH",
            2, 40, 1, 0, ehsize, 0, 0, ehsize, phentsize,
            len(segments), 0, 0, 0,
        )
        ph_format = byte_order + "IIIIIIII"
    else:
        ehsize = 64
        phentsize = 56
        header = struct.pack(
            byte_order + "HHIQQQIHHHHHH",
            2, 62, 1, 0, ehsize, 0, 0, ehsize, phentsize,
            len(segments), 0, 0, 0,
        )
        ph_format = byte_order + "IIQQQQQQ"

    payload_offset = ehsize + phentsize * len(segments)
    headers = []
    payload = bytearray()
    for segment in segments:
        filesz = segment.get("filesz", 4)
        memsz = segment.get("memsz", filesz)
        offset = payload_offset + len(payload)
        if elf_class == 1:
            headers.append(struct.pack(
                ph_format, segment.get("type", 1), offset,
                segment.get("vaddr", 0), segment.get("paddr", segment.get("vaddr", 0)),
                filesz, memsz, 5, 4,
            ))
        else:
            headers.append(struct.pack(
                ph_format, segment.get("type", 1), 5, offset,
                segment.get("vaddr", 0), segment.get("paddr", segment.get("vaddr", 0)),
                filesz, memsz, 4,
            ))
        payload.extend(b"X" * filesz)
    return ident + header + b"".join(headers) + bytes(payload)


def _write(path, data):
    path.write_bytes(data)
    return str(path)


def _plan(tmp_path, boot_start=0x1000, boot_size=0x100):
    elf = _write(
        tmp_path / "boot.elf",
        _elf_bytes([{"vaddr": boot_start, "memsz": boot_size, "filesz": 8}]),
    )
    image = _write(tmp_path / "a.bin", b"A" * 0x80)
    return {
        "version": 1,
        "nvm": {"base": 0x1000, "size": 0x4000},
        "bootloader": {"elf": elf},
        "slots": {
            "A": {"base": 0x2000, "size": 0x1000, "write_full": False},
            "B": {"base": 0x3000, "size": 0x1000, "write_full": False},
        },
        "metadata": [{"name": "state", "base": 0x4000, "size": 0x100}],
        "loads": [{"name": "A image", "path": image, "address": 0x2000, "slot": "A"}],
    }


@pytest.mark.parametrize("elf_class,byte_order", [(1, "<"), (1, ">"), (2, "<"), (2, ">")])
def test_parses_both_elf_classes_and_endiannesses(tmp_path, elf_class, byte_order):
    path = _write(
        tmp_path / "boot.elf",
        _elf_bytes(
            [{"vaddr": 0x2000, "paddr": 0x1000, "filesz": 0x20, "memsz": 0x80}],
            elf_class=elf_class,
            byte_order=byte_order,
        ),
    )

    intervals = parse_elf_load_intervals(path)

    assert [(item["kind"], item["start"], item["end"]) for item in intervals] == [
        ("vma", 0x2000, 0x2080),
        ("lma", 0x1000, 0x1020),
    ]


def test_rejects_actual_binary_overlap_with_bootloader(tmp_path):
    plan = _plan(tmp_path, boot_start=0x1FF0, boot_size=0x30)

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "load A image [0x2000, 0x2080)" in message
    assert "bootloader PT_LOAD[0] VMA [0x1ff0, 0x2020)" in message


def test_exact_adjacency_is_allowed(tmp_path):
    plan = _plan(tmp_path, boot_start=0x1F00, boot_size=0x100)

    normalized = validate_load_plan(plan)

    assert normalized["loads"][0]["start"] == 0x2000


def test_normalizes_foreign_filesystem_size_integer(tmp_path, monkeypatch):
    class ForeignInteger:
        def __str__(self):
            return "128"

    plan = _plan(tmp_path, boot_start=0x1F00, boot_size=0x100)
    monkeypatch.setattr(os.path, "getsize", lambda _path: ForeignInteger())

    normalized = validate_load_plan(plan)

    assert normalized["loads"][0]["end"] - normalized["loads"][0]["start"] == 128


def test_rejects_binary_spill_from_declared_slot(tmp_path):
    plan = _plan(tmp_path)
    plan["loads"][0]["address"] = 0x2FC0

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "load A image [0x2fc0, 0x3040)" in message
    assert "slot A [0x2000, 0x3000)" in message


def test_rejects_slot_metadata_collision(tmp_path):
    plan = _plan(tmp_path)
    plan["metadata"][0].update({"base": 0x2FF0, "size": 0x20})

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "slot A [0x2000, 0x3000)" in message
    assert "metadata state [0x2ff0, 0x3010)" in message


def test_full_slot_write_is_checked_against_bootloader(tmp_path):
    plan = _plan(tmp_path, boot_start=0x2F00, boot_size=0x200)
    plan["slots"]["A"]["write_full"] = True
    plan["loads"] = []

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "slot A full write [0x2000, 0x3000)" in message
    assert "bootloader PT_LOAD[0] VMA [0x2f00, 0x3100)" in message


def test_metadata_write_is_checked_against_bootloader(tmp_path):
    plan = _plan(tmp_path, boot_start=0x3FF0, boot_size=0x30)
    plan["loads"] = []

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "metadata state [0x4000, 0x4100)" in message
    assert "bootloader PT_LOAD[0] VMA [0x3ff0, 0x4020)" in message


def test_rejects_malformed_and_no_load_elf(tmp_path):
    malformed = _write(tmp_path / "malformed.elf", b"not an elf")
    with pytest.raises(LayoutValidationError, match="truncated|invalid magic"):
        parse_elf_load_intervals(malformed)

    no_load = _write(
        tmp_path / "no-load.elf",
        _elf_bytes([{"type": 4, "vaddr": 0x1000}]),
    )
    with pytest.raises(LayoutValidationError, match="no PT_LOAD"):
        parse_elf_load_intervals(no_load)


def test_rejects_out_of_bounds_load_with_named_intervals(tmp_path):
    plan = _plan(tmp_path)
    plan["loads"][0]["address"] = 0x4FC0

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "load A image [0x4fc0, 0x5040)" in message
    assert "nvm [0x1000, 0x5000)" in message


def test_rejects_address_overflow_with_named_intervals(tmp_path):
    plan = _plan(tmp_path)
    plan["loads"][0]["address"] = (1 << 64) - 0x40

    with pytest.raises(LayoutValidationError) as error:
        validate_load_plan(plan)

    message = str(error.value)
    assert "load A image [0xffffffffffffffc0, 0x10000000000000040)" in message
    assert "64-bit address space [0x0, 0x10000000000000000)" in message
