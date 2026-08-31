#!/usr/bin/env python3
"""Pure tests for bounded postmortem evidence helpers."""

from __future__ import annotations

import ast
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"


def _load_helpers():
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"))
    wanted = {
        "to_py_bytes",
        "region_dump",
        "streamed_region_dump",
        "evaluate_slot_header",
        "_normalise_erase_regions",
        "summarize_slot_sectors",
    }
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    namespace = {
        "struct": struct,
        "sram_start": 0x20000000,
        "sram_end": 0x20040000,
        "fmt_u32": lambda value: "0x{:08X}".format(int(value) & 0xFFFFFFFF),
        "fmt_u8": lambda value: "0x{:02X}".format(int(value) & 0xFF),
        "POSTMORTEM_MAX_RAW_BYTES": 4096,
        "POSTMORTEM_PARTITION_CHUNK_BYTES": 65536,
        "POSTMORTEM_PARTITION_TAIL_BYTES": 512,
        "base64": __import__("base64"),
        "hashlib": __import__("hashlib"),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNTIME), "exec"), namespace)
    return namespace


class PostmortemEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helpers = _load_helpers()

    def test_vector_evaluation_uses_configured_offset(self):
        evaluate = self.helpers["evaluate_slot_header"]
        vector = struct.pack("<II", 0x20001000, 0x08001001)
        result = evaluate(0x08000000, 0x20000, vector, vector_table_offset=0x200)
        self.assertTrue(result["valid"])
        self.assertEqual(result["vector_table_offset"], 0x200)
        self.assertEqual(result["vector_table_address"], "0x08000200")

    def test_region_dump_caps_raw_evidence_but_keeps_full_hash(self):
        dump = self.helpers["region_dump"](b"\x00" * 10000, 0x08000000)
        self.assertEqual(dump["size"], 10000)
        self.assertEqual(dump["raw_base64_bytes"], 4096)
        self.assertTrue(dump["raw_base64_truncated"])
        self.assertEqual(len(dump["raw_base64"]), 4 * ((4096 + 2) // 3))

    def test_to_py_bytes_normalises_character_and_numeric_iteration(self):
        convert = self.helpers["to_py_bytes"]

        class CharacterIterable(object):
            def __iter__(self):
                return iter("\x00\xffA")

        self.assertIsInstance(convert(CharacterIterable()), bytearray)
        self.assertEqual(list(convert(CharacterIterable())), [0, 255, 65])
        self.assertEqual(list(convert(b"\x00\xffA")), [0, 255, 65])
        self.assertEqual(list(convert(bytearray([0, 255, 65]))), [0, 255, 65])
        self.assertEqual(list(convert([0, 255, 65])), [0, 255, 65])

    def test_streamed_partition_dump_bounds_reads_and_keeps_complete_hash(self):
        streamed = self.helpers["streamed_region_dump"]
        source = b"\xff\x00\xff\x01\x80\xff\x7f\xff"
        calls = []
        convert = self.helpers["to_py_bytes"]

        def read_span(address, size, snapshot_bytes=None):
            calls.append((address, size))
            offset = address - 0x08000000
            # Emulate IronPython 2/CLR reads that yield one-character strings.
            character_chunk = "".join(
                chr(value) for value in source[offset:offset + size]
            )
            return convert(character_chunk)

        self.helpers["read_flash_span"] = read_span
        dump = streamed(
            0x08000000,
            len(source),
            chunk_size=17,
        )
        self.assertTrue(dump["read_complete"])
        self.assertEqual(dump["size"], len(source))
        self.assertEqual(dump["requested_size"], len(source))
        self.assertEqual(dump["sha256"], __import__("hashlib").sha256(source).hexdigest())
        self.assertEqual(dump["non_ff_count"], 4)
        self.assertEqual(
            [item["offset"] for item in dump["non_ff_preview"]],
            [1, 3, 4, 6],
        )
        self.assertEqual(
            dump["raw_base64"],
            __import__("base64").b64encode(source).decode("ascii"),
        )
        self.assertLessEqual(max(size for _address, size in calls), 17)

    def test_streamed_partition_dump_normalises_signed_ff_and_keeps_tail(self):
        streamed = self.helpers["streamed_region_dump"]
        source = b"\xff\x00\xff\x7f\xff\x01\xff"

        class ClrLikeBytes(object):
            def __init__(self, values):
                self.values = values

            def __iter__(self):
                return iter(self.values)

            def __len__(self):
                return len(self.values)

        def read_span(address, size, snapshot_bytes=None):
            offset = address - 0x08000000
            values = []
            for value in source[offset:offset + size]:
                # Exercise both CLR signed bytes (-1 for 0xFF) and
                # IronPython character bytes in one streamed read.
                values.append(-1 if value == 0xFF else chr(value))
            return ClrLikeBytes(values)

        self.helpers["read_flash_span"] = read_span
        dump = streamed(
            0x08000000,
            len(source),
            raw_limit=3,
            chunk_size=3,
            tail_limit=4,
        )

        self.assertTrue(dump["read_complete"])
        self.assertEqual(dump["non_ff_count"], 3)
        self.assertEqual(
            [item["offset"] for item in dump["non_ff_preview"]],
            [1, 3, 5],
        )
        self.assertEqual(
            dump["sha256"], __import__("hashlib").sha256(source).hexdigest()
        )
        self.assertEqual(
            dump["raw_base64"],
            __import__("base64").b64encode(source[:3]).decode("ascii"),
        )
        self.assertEqual(dump["tail_hex"], source[-4:].hex())
        self.assertEqual(
            dump["tail_base64"],
            __import__("base64").b64encode(source[-4:]).decode("ascii"),
        )
        self.assertEqual(dump["tail_base64_bytes"], 4)
        self.assertTrue(dump["tail_base64_truncated"])
        self.assertEqual(dump["tail_offset"], 3)
        self.assertEqual(dump["tail_address"], "0x08000003")
        self.assertEqual(dump["tail_source"], "streamed_read_suffix")
        self.assertEqual(dump["tail_provenance"]["offset"], 3)
        self.assertEqual(dump["tail_provenance"]["limit"], 4)
        self.assertEqual(dump["tail_provenance"]["size"], 4)

    def test_streamed_partition_dump_omits_digest_when_read_is_truncated(self):
        streamed = self.helpers["streamed_region_dump"]
        self.helpers["read_flash_span"] = lambda _address, _size, snapshot_bytes=None: b"\xFF" * 3
        dump = streamed(0x08000000, 10, chunk_size=4)
        self.assertFalse(dump["read_complete"])
        self.assertEqual(dump["size"], 3)
        self.assertIsNone(dump["sha256"])

    def test_sector_summary_reports_nonuniform_declared_geometry(self):
        summarize = self.helpers["summarize_slot_sectors"]
        data = b"\xFF" * 0x14000
        result = summarize(
            data,
            0x20000,
            slot_base=0x08000000,
            erase_regions=[
                {"base": 0x08000000, "size": 0x4000, "sector_size": 0x4000},
                {"base": 0x08004000, "size": 0x10000, "sector_size": 0x10000},
            ],
            geometry_provenance="profile_declared",
        )
        self.assertEqual(result["geometry_source"], "profile_declared")
        self.assertFalse(result["geometry_approximate"])
        self.assertEqual([item["size"] for item in result["map"]], [0x4000, 0x10000])

    def test_sector_summary_preserves_modeled_backend_provenance(self):
        summarize = self.helpers["summarize_slot_sectors"]
        result = summarize(
            b"\xFF" * 0x4000,
            0x20000,
            slot_base=0x08000000,
            erase_regions=[
                {"base": 0x08000000, "size": 0x4000, "sector_size": 0x4000}
            ],
            geometry_provenance="modeled_backend",
        )
        self.assertEqual(result["geometry_source"], "modeled_backend")
        self.assertEqual(result["map"][0]["geometry_source"], "modeled_backend")

    def test_sector_summary_marks_uniform_page_fallback_as_approximate(self):
        summarize = self.helpers["summarize_slot_sectors"]
        result = summarize(b"\xFF" * 0x3000, 0x2000, slot_base=0x1000)
        self.assertEqual(result["geometry_source"], "fallback_page_size")
        self.assertTrue(result["geometry_approximate"])
        self.assertEqual(result["count"], 2)


if __name__ == "__main__":
    unittest.main()
