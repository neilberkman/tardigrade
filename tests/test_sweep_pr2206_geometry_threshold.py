#!/usr/bin/env python3
"""Tests for the PR2206/PR2214 threshold helper."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from sweep_pr2206_geometry_threshold import load_base_payload  # noqa: E402


class LoadBasePayloadTests(unittest.TestCase):
    def test_load_signed_image_extracts_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "signed.bin"
            payload = b"PAYLOAD"
            image = bytearray(0x200 + len(payload))
            struct.pack_into("<I", image, 0x0, 0x96F3B83D)
            struct.pack_into("<I", image, 0x0C, len(payload))
            image[0x200 : 0x200 + len(payload)] = payload
            path.write_bytes(image)
            self.assertEqual(load_base_payload(path), payload)

    def test_load_raw_mcuboot_app_strips_reserved_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "raw.bin"
            payload = b"\xAA\xBB\xCC\xDD"
            path.write_bytes((b"\x00" * 0x200) + payload)
            self.assertEqual(load_base_payload(path), payload)

    def test_load_plain_binary_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plain.bin"
            payload = b"\x11\x22\x33\x44"
            path.write_bytes(payload)
            self.assertEqual(load_base_payload(path), payload)


if __name__ == "__main__":
    unittest.main()
