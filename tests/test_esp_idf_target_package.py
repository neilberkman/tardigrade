#!/usr/bin/env python3
"""Unit tests for the ESP-IDF target-side adapter."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from targets.esp_idf.invariants import (  # noqa: E402
    check_esp_idf_active_entry_maps_to_valid_slot,
    check_esp_idf_otadata_crc_integrity,
    check_esp_idf_pending_verify_gets_aborted,
    check_esp_idf_seq_not_zero,
)
from targets.esp_idf.probe import (  # noqa: E402
    _esp_otadata_crc,
    collect_state,
)


# ---- CRC reference values computed by gen_esp_idf_images.py ----
CRC_SEQ_1 = 0x4743989A
CRC_SEQ_2 = 0x55F63774

# OTA state constants
OTA_NEW = 0x00000000
OTA_PENDING_VERIFY = 0x00000001
OTA_VALID = 0x00000002
OTA_INVALID = 0x00000003
OTA_ABORTED = 0x00000004

OTADATA_BASE = 0x000F8000
OTADATA_SECTOR_SIZE = 0x1000


class _FakeBus:
    def __init__(self) -> None:
        self._bytes: dict[int, int] = {}

    def write_u32(self, addr: int, value: int) -> None:
        for i, b in enumerate(struct.pack("<I", value)):
            self._bytes[addr + i] = b

    def write_entry(self, sector_addr: int, ota_seq: int, ota_state: int, crc: int) -> None:
        self.write_u32(sector_addr + 0, ota_seq)
        # seq_label at +4 is left as 0xFF (erased)
        self.write_u32(sector_addr + 24, ota_state)
        self.write_u32(sector_addr + 28, crc)

    def ReadBytes(self, addr: int, size: int):
        return bytes([self._bytes.get(addr + i, 0xFF) for i in range(size)])


class _FakeMonitor:
    def __init__(self, variables=None):
        self._variables = dict(variables or {})

    def GetVariable(self, name: str):
        if name in self._variables:
            return self._variables[name]
        raise KeyError(name)


class TestCrcComputation(unittest.TestCase):
    def test_crc_seq_1(self) -> None:
        self.assertEqual(_esp_otadata_crc(1), CRC_SEQ_1)

    def test_crc_seq_2(self) -> None:
        self.assertEqual(_esp_otadata_crc(2), CRC_SEQ_2)


class TestProbe(unittest.TestCase):
    def _make_env(self, entry0=None, entry1=None):
        bus = _FakeBus()
        if entry0:
            bus.write_entry(OTADATA_BASE, *entry0)
        if entry1:
            bus.write_entry(OTADATA_BASE + OTADATA_SECTOR_SIZE, *entry1)
        monitor = _FakeMonitor()
        return bus, monitor

    def test_upgrade_state(self) -> None:
        """Upgrade: entry 0=seq1/VALID, entry 1=seq2/NEW -> active=1, slot=staging."""
        bus, monitor = self._make_env(
            entry0=(1, OTA_VALID, CRC_SEQ_1),
            entry1=(2, OTA_NEW, CRC_SEQ_2),
        )
        state = collect_state(bus=bus, monitor=monitor)

        self.assertEqual(state["target"], "esp_idf")
        self.assertEqual(state["active_entry"], 1)
        self.assertEqual(state["active_seq"], 2)
        self.assertEqual(state["target_slot"], "staging")
        self.assertTrue(state["entries"]["sector0"]["selectable"])
        self.assertTrue(state["entries"]["sector1"]["selectable"])
        self.assertEqual(state["entries"]["sector0"]["ota_state"], "valid")
        self.assertEqual(state["entries"]["sector1"]["ota_state"], "new")

    def test_rollback_state(self) -> None:
        """Rollback: entry 0=seq1/VALID, entry 1=seq2/PENDING_VERIFY."""
        bus, monitor = self._make_env(
            entry0=(1, OTA_VALID, CRC_SEQ_1),
            entry1=(2, OTA_PENDING_VERIFY, CRC_SEQ_2),
        )
        state = collect_state(bus=bus, monitor=monitor)

        self.assertEqual(state["active_entry"], 1)
        self.assertEqual(state["target_slot"], "staging")
        self.assertTrue(state["flags"]["has_pending_verify"])
        self.assertTrue(state["flags"]["has_valid_fallback"])

    def test_aborted_entry_not_selectable(self) -> None:
        """ABORTED entry should not be selectable."""
        bus, monitor = self._make_env(
            entry0=(1, OTA_VALID, CRC_SEQ_1),
            entry1=(2, OTA_ABORTED, CRC_SEQ_2),
        )
        state = collect_state(bus=bus, monitor=monitor)

        self.assertFalse(state["entries"]["sector1"]["selectable"])
        self.assertEqual(state["active_entry"], 0)
        self.assertEqual(state["target_slot"], "exec")

    def test_bad_crc_not_selectable(self) -> None:
        """Entry with wrong CRC should not be selectable."""
        bus, monitor = self._make_env(
            entry0=(1, OTA_VALID, CRC_SEQ_1),
            entry1=(2, OTA_NEW, 0xDEADBEEF),  # bad CRC
        )
        state = collect_state(bus=bus, monitor=monitor)

        self.assertFalse(state["entries"]["sector1"]["crc_valid"])
        self.assertFalse(state["entries"]["sector1"]["selectable"])
        self.assertEqual(state["active_entry"], 0)
        self.assertTrue(state["flags"]["crc_mismatch_any"])

    def test_both_erased(self) -> None:
        """Both entries erased -> no active entry."""
        bus, monitor = self._make_env()  # no entries written
        state = collect_state(bus=bus, monitor=monitor)

        self.assertEqual(state["active_entry"], -1)
        self.assertIsNone(state["target_slot"])
        self.assertTrue(state["flags"]["both_erased"])

    def test_replica_fields_for_builtin_invariants(self) -> None:
        """Probe exposes replica0_valid/replica1_valid for built-in invariants."""
        bus, monitor = self._make_env(
            entry0=(1, OTA_VALID, CRC_SEQ_1),
            entry1=(2, OTA_NEW, CRC_SEQ_2),
        )
        state = collect_state(bus=bus, monitor=monitor)

        self.assertTrue(state["replica0_valid"])
        self.assertTrue(state["replica1_valid"])
        self.assertEqual(state["replica0_seq"], 1)
        self.assertEqual(state["replica1_seq"], 2)


class TestInvariants(unittest.TestCase):
    def _result(self, nvm_state, boot_outcome="success", is_control=False,
                boot_slot=None, fault_at=1):
        return SimpleNamespace(
            nvm_state=nvm_state,
            boot_outcome=boot_outcome,
            is_control=is_control,
            boot_slot=boot_slot,
            fault_at=fault_at,
        )

    def test_crc_integrity_passes_when_one_valid(self) -> None:
        state = {
            "entries": {
                "sector0": {"crc_valid": True, "erased": False},
                "sector1": {"crc_valid": False, "erased": False},
            }
        }
        # Should not raise
        check_esp_idf_otadata_crc_integrity(self._result(state, is_control=False))

    def test_crc_integrity_fails_when_both_corrupt(self) -> None:
        state = {
            "entries": {
                "sector0": {
                    "crc_valid": False, "erased": False,
                    "ota_seq_hex": "0x00000001",
                    "crc_stored": "0xAAAAAAAA", "crc_expected": "0x4743989A",
                    "ota_seq": 1,
                },
                "sector1": {
                    "crc_valid": False, "erased": False,
                    "ota_seq_hex": "0x00000002",
                    "crc_stored": "0xBBBBBBBB", "crc_expected": "0x55F63774",
                    "ota_seq": 2,
                },
            }
        }
        with self.assertRaises(InvariantViolation) as ctx:
            check_esp_idf_otadata_crc_integrity(self._result(state, is_control=False))
        self.assertEqual(ctx.exception.invariant_name, "esp_idf_otadata_crc_integrity")

    def test_crc_integrity_skips_erased(self) -> None:
        """If one entry is erased, skip the check (only one sector has data)."""
        state = {
            "entries": {
                "sector0": {"crc_valid": False, "erased": False,
                            "ota_seq_hex": "0x01", "crc_stored": "0x00",
                            "crc_expected": "0x00", "ota_seq": 1},
                "sector1": {"crc_valid": False, "erased": True},
            }
        }
        # Should not raise -- only one sector has data
        check_esp_idf_otadata_crc_integrity(self._result(state, is_control=False))

    def test_pending_verify_violation(self) -> None:
        state = {
            "entries": {
                "sector0": {"ota_state": "valid", "erased": False},
                "sector1": {"ota_state": "pending_verify", "erased": False},
            }
        }
        with self.assertRaises(InvariantViolation) as ctx:
            check_esp_idf_pending_verify_gets_aborted(self._result(state))
        self.assertEqual(ctx.exception.invariant_name, "esp_idf_pending_verify_gets_aborted")

    def test_pending_verify_passes_when_aborted(self) -> None:
        state = {
            "entries": {
                "sector0": {"ota_state": "valid", "erased": False},
                "sector1": {"ota_state": "aborted", "erased": False},
            }
        }
        # Should not raise
        check_esp_idf_pending_verify_gets_aborted(self._result(state))

    def test_pending_verify_skips_on_brick(self) -> None:
        """Don't check pending_verify if the device bricked."""
        state = {
            "entries": {
                "sector0": {"ota_state": "valid", "erased": False},
                "sector1": {"ota_state": "pending_verify", "erased": False},
            }
        }
        # Should not raise -- device didn't boot
        check_esp_idf_pending_verify_gets_aborted(
            self._result(state, boot_outcome="no_boot"))

    def test_active_slot_mismatch_with_both_selectable(self) -> None:
        state = {
            "target_slot": "staging",
            "active_entry": 1,
            "active_seq": 2,
            "boot_slot": "exec",
            "flags": {
                "both_selectable": True,
                "neither_selectable": False,
            },
        }
        with self.assertRaises(InvariantViolation) as ctx:
            check_esp_idf_active_entry_maps_to_valid_slot(
                self._result(state, boot_slot="exec"))
        self.assertEqual(ctx.exception.invariant_name,
                         "esp_idf_active_entry_maps_to_valid_slot")

    def test_active_slot_match_passes(self) -> None:
        state = {
            "target_slot": "staging",
            "active_entry": 1,
            "active_seq": 2,
            "boot_slot": "staging",
            "flags": {
                "both_selectable": True,
                "neither_selectable": False,
            },
        }
        # Should not raise
        check_esp_idf_active_entry_maps_to_valid_slot(
            self._result(state, boot_slot="staging"))

    def test_seq_zero_violation(self) -> None:
        # ota_seq=0 with valid CRC is pathological
        crc_zero = _esp_otadata_crc(0)
        state = {
            "entries": {
                "sector0": {
                    "ota_seq": 0, "crc_valid": True, "erased": False,
                },
                "sector1": {"ota_seq": 1, "crc_valid": True, "erased": False},
            }
        }
        with self.assertRaises(InvariantViolation) as ctx:
            check_esp_idf_seq_not_zero(self._result(state))
        self.assertEqual(ctx.exception.invariant_name, "esp_idf_seq_not_zero")

    def test_seq_zero_passes_for_normal(self) -> None:
        state = {
            "entries": {
                "sector0": {"ota_seq": 1, "crc_valid": True, "erased": False},
                "sector1": {"ota_seq": 2, "crc_valid": True, "erased": False},
            }
        }
        # Should not raise
        check_esp_idf_seq_not_zero(self._result(state))


if __name__ == "__main__":
    unittest.main()
