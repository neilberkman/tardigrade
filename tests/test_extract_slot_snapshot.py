#!/usr/bin/env python3
"""Tests for extracting slot baselines from persisted flash snapshots."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from extract_slot_snapshot import (  # noqa: E402
    extract_flash_span,
    extract_slot_bytes,
    extract_slots,
    flash_base_for_profile,
    parse_span,
    span_to_pre_boot_state,
)


class ExtractSlotSnapshotTest(unittest.TestCase):
    def _fake_profile(self):
        return SimpleNamespace(
            bootloader_entry=0x10000000,
            memory=SimpleNamespace(
                slots={
                    "exec": SimpleNamespace(base=0x10001000, size=0x1000),
                    "staging": SimpleNamespace(base=0x10003000, size=0x1000),
                }
            ),
        )

    def test_extract_slot_bytes_uses_profile_flash_base(self) -> None:
        profile = self._fake_profile()
        self.assertEqual(flash_base_for_profile(profile), 0x10000000)

        snapshot = bytes([0xAA]) * 0x1000 + bytes([0x11]) * 0x1000 + bytes([0xBB]) * 0x1000 + bytes([0x22]) * 0x1000
        self.assertEqual(extract_slot_bytes(profile, snapshot, "exec"), bytes([0x11]) * 0x1000)
        self.assertEqual(extract_slot_bytes(profile, snapshot, "staging"), bytes([0x22]) * 0x1000)

    def test_extract_slots_writes_selected_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._fake_profile()
            snapshot_path = tempdir / "snapshot.bin"
            out_dir = tempdir / "out"
            snapshot_path.write_bytes(
                bytes([0x00]) * 0x1000
                + bytes([0xE1]) * 0x1000
                + bytes([0x00]) * 0x1000
                + bytes([0x52]) * 0x1000
            )
            outputs = extract_slots(
                profile=profile,
                snapshot_path=snapshot_path,
                output_dir=out_dir,
                slots=["staging"],
                prefix="captured",
            )
            self.assertEqual(len(outputs), 1)
            output_path = out_dir / "captured_staging.bin"
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), bytes([0x52]) * 0x1000)
            self.assertEqual(outputs[0], output_path)

    def test_extract_slot_bytes_rejects_too_small_snapshot(self) -> None:
        profile = self._fake_profile()
        with self.assertRaises(ValueError):
            extract_slot_bytes(profile, bytes([0x00]) * 0x2000, "staging")

    def test_parse_span_accepts_hex_range(self) -> None:
        self.assertEqual(parse_span("0x10000200:0x40"), (0x10000200, 0x40))

    def test_extract_flash_span_reads_boundary_region(self) -> None:
        profile = self._fake_profile()
        snapshot = (
            bytes([0xAA]) * 0x1000
            + bytes([0x11]) * 0x1000
            + bytes([0xBB]) * 0x1000
            + bytes([0x22]) * 0x1000
        )
        span = extract_flash_span(profile, snapshot, 0x10002FF0, 0x20)
        self.assertEqual(span, bytes([0xBB]) * 0x10 + bytes([0x22]) * 0x10)

    def test_span_to_pre_boot_state_omits_erased_words(self) -> None:
        entries = span_to_pre_boot_state(
            0x08081F60,
            (
                b"\x34\x50\x00\x00"
                + b"\xFF\xFF\xFF\xFF"
                + b"\x02\x00\x00\x00"
                + b"\xFF\xFF\xFF\xFF"
            ),
        )
        self.assertEqual(
            entries,
            [
                (0x08081F60, 0x00005034),
                (0x08081F68, 0x00000002),
            ],
        )
