#!/usr/bin/env python3
"""Unit tests for slot-hash extent resolution across MCUboot header, erase-sector, and 4096 fallback paths."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import struct
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNTIME_SCRIPT = SCRIPTS / "run_runtime_fault_sweep.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import (  # noqa: E402
    MCUBOOT_IMAGE_MAGIC,
    MCUBOOT_TLV_INFO_MAGIC,
    MCUBOOT_TLV_PROT_INFO_MAGIC,
    load_profile,
    resolve_slot_hash_extent as loader_resolve_slot_hash_extent,
)


def _load_state_evaluator():
    module_path = ROOT / "targets" / "mcuboot" / "state_evaluator.py"
    spec = importlib.util.spec_from_file_location("test_state_evaluator_extent", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load {}".format(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_functions(*names: str, globals_dict=None):
    tree = ast.parse(RUNTIME_SCRIPT.read_text(encoding="utf-8"), filename=str(RUNTIME_SCRIPT))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in set(names)
    ]
    module = ast.Module(body=selected, type_ignores=[])
    namespace = dict(globals_dict or {})
    exec(compile(module, str(RUNTIME_SCRIPT), "exec"), namespace, namespace)
    return namespace


def _build_synthetic_mcuboot_image(
    *,
    hdr_size: int = 0x200,
    img_size: int = 0x2400,
    prot_tlv_size: int = 12,
    unprot_tlv_size: int = 0x150,
    fill_byte: int = 0x5A,
) -> bytes:
    total_size = hdr_size + img_size + prot_tlv_size + unprot_tlv_size
    buf = bytearray([fill_byte & 0xFF] * total_size)
    struct.pack_into(
        "<IIHHII",
        buf,
        0,
        MCUBOOT_IMAGE_MAGIC,
        0x08020000,
        hdr_size,
        prot_tlv_size,
        img_size,
        0,
    )
    # Vector table at hdr_size
    struct.pack_into("<II", buf, hdr_size, 0x20010000, 0x08020201)
    prot_off = hdr_size + img_size
    if prot_tlv_size > 0:
        struct.pack_into("<HH", buf, prot_off, MCUBOOT_TLV_PROT_INFO_MAGIC, prot_tlv_size)
    unprot_off = prot_off + prot_tlv_size
    struct.pack_into("<HH", buf, unprot_off, MCUBOOT_TLV_INFO_MAGIC, unprot_tlv_size)
    return bytes(buf)


class SlotHashExtentTest(unittest.TestCase):
    def test_mcuboot_header_path_ignores_64kib_trailer_status_below_4096_window(self) -> None:
        slot_base = 0x08004000
        slot_size = 0x18000  # Two 16 KiB sectors + one 64 KiB trailer sector
        image_bytes = _build_synthetic_mcuboot_image(
            hdr_size=0x200,
            img_size=0x2400,
            prot_tlv_size=12,
            unprot_tlv_size=0x150,
        )
        expected_extent = 0x200 + 0x2400 + 12 + 0x150
        self.assertEqual(len(image_bytes), expected_extent)
        expected_digest = hashlib.sha256(image_bytes).hexdigest()

        slot_flash = bytearray([0xFF] * slot_size)
        slot_flash[: len(image_bytes)] = image_bytes
        # Write swap status bytes inside the 64 KiB trailer sector well below slot_size - 4096 (0x17000).
        slot_flash[0x8000] = 0x01
        slot_flash[0x8004] = 0x02
        slot_flash[0x14FE0] = 0x03
        # Also write trailer fields in the last 4096 bytes.
        slot_flash[slot_size - 24] = 0x01
        slot_flash[slot_size - 16 : slot_size] = struct.pack(
            "<IIII", 0xF395C277, 0x7FEFD260, 0x0F505235, 0x8079B62C
        )

        logs: list[str] = []
        ns = _runtime_functions(
            "resolve_slot_hash_extent",
            "compute_slot_hash",
            "_program_bytes_hex",
            "_compact_differing_byte_ranges",
            "analyze_fault_snapshot",
            globals_dict={
                "slot_ranges": {"exec": (slot_base, slot_base + slot_size)},
                "read_flash_bytes": lambda addr, size: bytes(
                    slot_flash[addr - slot_base : addr - slot_base + size]
                ),
                "postmortem_layout": {"erase_regions": [], "partitions": []},
                "backend": {"kind": "fast", "data": SimpleNamespace(PageSize=4096, EraseFill=0xFF)},
                "log": logs.append,
                "flash_geometry": lambda: (slot_base, slot_size),
                "success_image_hash_slot": "exec",
                "image_exec_path": "",
                "image_staging_path": "",
                "image_tertiary_path": "",
                "image_recovery_path": "",
                "fmt_u32": lambda v: "0x{:08X}".format(int(v) & 0xFFFFFFFF),
                "os": __import__("os"),
            },
        )

        extent, path_name = ns["resolve_slot_hash_extent"](slot_base, slot_size)
        self.assertEqual(path_name, "mcuboot_header")
        self.assertEqual(extent, expected_extent)

        runtime_digest = ns["compute_slot_hash"]("exec")
        self.assertEqual(runtime_digest, expected_digest)
        self.assertTrue(
            any("path=mcuboot_header" in entry and "extent=0x275C" in entry for entry in logs),
            logs,
        )

        loader_extent, loader_path = loader_resolve_slot_hash_extent(
             bytes(slot_flash), slot_size, slot_base=slot_base
        )
        self.assertEqual(loader_path, "mcuboot_header")
        self.assertEqual(loader_extent, expected_extent)

        evaluator = _load_state_evaluator()
        eval_extent, eval_path = evaluator.resolve_slot_hash_extent(
            bytes(slot_flash), slot_size=slot_size, slot_base=slot_base
        )
        self.assertEqual(eval_path, "mcuboot_header")
        self.assertEqual(eval_extent, expected_extent)
        self.assertEqual(
            evaluator._hash_slot_bytes(
                bytes(slot_flash),
                slot_size=slot_size,
                page_size=4096,
                pad_byte=0xFF,
                slot_base=slot_base,
            ),
            expected_digest,
        )

        with tempfile.TemporaryDirectory() as td:
            img_path = Path(td) / "staging.bin"
            img_path.write_bytes(image_bytes)
            ns["image_staging_path"] = str(img_path)
            snap_analysis = ns["analyze_fault_snapshot"](bytes(slot_flash), boot_slot="exec")
            self.assertEqual(snap_analysis["identity_slot_extent"], expected_extent)
            self.assertEqual(snap_analysis["identity_slot_extent_path"], "mcuboot_header")
            self.assertEqual(snap_analysis["identity_slot_sha256"], expected_digest)
            self.assertTrue(snap_analysis["closest_declared_image"]["exact"])

    def test_last_erase_sector_path_reserves_64kib_trailer_sector_when_no_mcuboot_header(self) -> None:
        slot_base = 0x08008000
        slot_size = 0x18000  # 96 KiB: 2 x 16 KiB data sectors + 1 x 64 KiB trailer sector
        data_extent = 0x8000  # 32 KiB after reserving the 64 KiB last erase sector
        erase_regions = [
            {"base": 0x08000000, "size": 0x10000, "sector_size": 0x4000},
            {"base": 0x08010000, "size": 0x10000, "sector_size": 0x10000},
        ]

        # Build a non-MCUboot (raw vector-table) image occupying the first 24 KiB.
        raw_image = bytearray([0x33] * 0x6000)
        struct.pack_into("<II", raw_image, 0, 0x20010000, slot_base + 0x101)
        expected_slot_data = bytes(raw_image) + (b"\xFF" * (data_extent - len(raw_image)))
        expected_digest = hashlib.sha256(expected_slot_data).hexdigest()

        slot_flash = bytearray([0xFF] * slot_size)
        slot_flash[: len(raw_image)] = raw_image
        # Write swap status bytes in the 64 KiB trailer sector at offsets 0x8000 and 0x14FC0,
        # both below slot_size - 4096 (0x17000).
        slot_flash[0x8000] = 0x01
        slot_flash[0x8008] = 0x02
        slot_flash[0x14FC0] = 0x03

        # Confirm the old (slot_size - 4096) hash would have been perturbed by those status bytes.
        old_extent_digest = hashlib.sha256(bytes(slot_flash[: slot_size - 4096])).hexdigest()
        clean_old_extent_digest = hashlib.sha256(
            bytes(raw_image) + (b"\xFF" * ((slot_size - 4096) - len(raw_image)))
        ).hexdigest()
        self.assertNotEqual(old_extent_digest, clean_old_extent_digest)

        logs: list[str] = []
        ns = _runtime_functions(
            "resolve_slot_hash_extent",
            "compute_slot_hash",
            globals_dict={
                "slot_ranges": {"exec": (slot_base, slot_base + slot_size)},
                "read_flash_bytes": lambda addr, size: bytes(
                    slot_flash[addr - slot_base : addr - slot_base + size]
                ),
                "postmortem_layout": {"erase_regions": erase_regions, "partitions": []},
                "backend": {"kind": "fast", "data": SimpleNamespace(PageSize=0x10000)},
                "log": logs.append,
            },
        )

        extent, path_name = ns["resolve_slot_hash_extent"](slot_base, slot_size)
        self.assertEqual(path_name, "last_erase_sector")
        self.assertEqual(extent, data_extent)
        self.assertEqual(ns["compute_slot_hash"]("exec"), expected_digest)
        self.assertTrue(
            any("path=last_erase_sector" in entry and "extent=0x8000" in entry for entry in logs),
            logs,
        )

        evaluator = _load_state_evaluator()
        eval_extent, eval_path = evaluator.resolve_slot_hash_extent(
            bytes(slot_flash),
            slot_size=slot_size,
            slot_base=slot_base,
            erase_regions=erase_regions,
        )
        self.assertEqual(eval_path, "last_erase_sector")
        self.assertEqual(eval_extent, data_extent)
        self.assertEqual(
            evaluator._hash_slot_bytes(
                bytes(slot_flash),
                slot_size=slot_size,
                slot_base=slot_base,
                erase_regions=erase_regions,
                pad_byte=0xFF,
            ),
            expected_digest,
        )

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            image_file = tempdir / "raw_app.bin"
            image_file.write_bytes(raw_image)
            profile_file = tempdir / "profile.yaml"
            profile_file.write_text(
                textwrap.dedent(
                    f"""\
                    schema_version: 1
                    name: synthetic_64k_trailer
                    platform: platforms/stm32f4.repl
                    bootloader:
                      elf: examples/vulnerable_ota/firmware.elf
                      entry: 0x08000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      erase_regions:
                        - {{ base: 0x08000000, size: 0x10000, sector_size: 0x4000 }}
                        - {{ base: 0x08010000, size: 0x10000, sector_size: 0x10000 }}
                        - {{ base: 0x08020000, size: 0x20000, sector_size: 0x20000 }}
                      slots:
                        exec: {{ base: 0x08008000, size: 0x18000 }}
                        staging: {{ base: 0x08020000, size: 0x18000 }}
                    images:
                      exec: {image_file}
                      staging: {image_file}
                    success_criteria:
                      vtor_in_slot: exec
                      image_hash: true
                      expected_image: staging
                    fault_sweep:
                      mode: runtime
                    """
                ),
                encoding="utf-8",
            )
            profile = load_profile(profile_file)
            digests = profile._compute_image_digests(ROOT, {"staging": str(image_file)})
            self.assertEqual(digests["staging"], expected_digest)

    def test_fallback_4096_path_when_neither_header_nor_sector_geometry_available(self) -> None:
        slot_base = 0x10002000
        slot_size = 0x6000
        expected_extent = slot_size - 4096
        raw_image = bytearray([0x77] * expected_extent)
        struct.pack_into("<II", raw_image, 0, 0x20004000, slot_base + 0x81)
        expected_digest = hashlib.sha256(raw_image).hexdigest()

        slot_flash = bytearray([0xFF] * slot_size)
        slot_flash[: len(raw_image)] = raw_image
        slot_flash[slot_size - 16] = 0x01

        logs: list[str] = []
        ns = _runtime_functions(
            "resolve_slot_hash_extent",
            "compute_slot_hash",
            globals_dict={
                "slot_ranges": {"exec": (slot_base, slot_base + slot_size)},
                "read_flash_bytes": lambda addr, size: bytes(
                    slot_flash[addr - slot_base : addr - slot_base + size]
                ),
                "postmortem_layout": {"erase_regions": [], "partitions": []},
                "backend": {"kind": "mram", "data": SimpleNamespace(WordSize=4)},
                "log": logs.append,
            },
        )

        extent, path_name = ns["resolve_slot_hash_extent"](slot_base, slot_size)
        self.assertEqual(path_name, "fallback_4096")
        self.assertEqual(extent, expected_extent)
        self.assertEqual(ns["compute_slot_hash"]("exec"), expected_digest)
        self.assertTrue(
            any("path=fallback_4096" in entry and "extent=0x5000" in entry for entry in logs),
            logs,
        )

        loader_extent, loader_path = loader_resolve_slot_hash_extent(
            bytes(slot_flash), slot_size, slot_base=slot_base
        )
        self.assertEqual(loader_path, "fallback_4096")
        self.assertEqual(loader_extent, expected_extent)

        evaluator = _load_state_evaluator()
        eval_extent, eval_path = evaluator.resolve_slot_hash_extent(
            bytes(slot_flash), slot_size=slot_size, slot_base=slot_base
        )
        self.assertEqual(eval_path, "fallback_4096")
        self.assertEqual(eval_extent, expected_extent)
        self.assertEqual(
            evaluator._hash_slot_bytes(
                bytes(slot_flash),
                slot_size=slot_size,
                slot_base=slot_base,
                pad_byte=0xFF,
            ),
            expected_digest,
        )


if __name__ == "__main__":
    unittest.main()
