#!/usr/bin/env python3
"""Unit tests for the rustBoot target-side adapter."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from targets.rustboot.invariants import (  # noqa: E402
    _find_regression,
    check_rustboot_swap_flags_consistent,
)
from targets.rustboot.probe import (  # noqa: E402
    RUSTBOOT_MAGIC,
    _flags_monotonic,
    collect_state,
)

BOOT_BASE = 0x0002F000
BOOT_SIZE = 0x00028000
UPDATE_BASE = 0x00058000
UPDATE_SIZE = 0x00028000
SWAP_BASE = 0x00057000
SWAP_SIZE = 0x00001000
SECTOR_SIZE = 0x00001000


class _FakeBus:
    def __init__(self) -> None:
        self._bytes: dict[int, int] = {}

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, value in enumerate(data):
            self._bytes[addr + i] = value

    def write_u32(self, addr: int, value: int) -> None:
        self.write_bytes(addr, struct.pack("<I", value))

    def write_trailer(self, part_base: int, part_size: int, state: int) -> None:
        part_end = part_base + part_size
        flag_bytes = (part_size // SECTOR_SIZE + 1) // 2
        self.write_bytes(part_end - 5 - flag_bytes, b"\xFF" * flag_bytes)
        self.write_bytes(part_end - 5, bytes([state]))
        self.write_u32(part_end - 4, RUSTBOOT_MAGIC)

    def ReadBytes(self, addr: int, size: int):
        return bytes(self._bytes.get(addr + i, 0xFF) for i in range(size))


class _FakeMonitor:
    def GetVariable(self, name: str):
        return ""


class RustbootProbeTests(unittest.TestCase):
    def test_collect_state_uses_checked_in_layout_defaults(self) -> None:
        bus = _FakeBus()
        monitor = _FakeMonitor()
        bus.write_trailer(BOOT_BASE, BOOT_SIZE, 0x10)
        bus.write_trailer(UPDATE_BASE, UPDATE_SIZE, 0x70)
        bus.write_bytes(SWAP_BASE, b"swap")

        state = collect_state(
            bus=bus,
            monitor=monitor,
            context={"stage": "control", "boot_slot": "exec"},
        )

        self.assertEqual(state["target"], "rustboot")
        self.assertEqual(state["boot"]["base"], "0x0002F000")
        self.assertEqual(state["update"]["base"], "0x00058000")
        self.assertEqual(state["swap"]["base"], "0x00057000")
        self.assertEqual(state["boot"]["state"], "testing")
        self.assertEqual(state["update"]["state"], "updating")
        self.assertTrue(state["flags"]["boot_magic_valid"])
        self.assertTrue(state["flags"]["update_magic_valid"])
        self.assertTrue(state["flags"]["boot_flags_monotonic"])
        self.assertTrue(state["flags"]["update_flags_monotonic"])
        self.assertTrue(state["flags"]["swap_occupied"])

    def test_flags_monotonic_accepts_partial_progress(self) -> None:
        self.assertTrue(_flags_monotonic([{"nibble": 0x00}, {"nibble": 0x0F}]))
        self.assertTrue(
            _flags_monotonic(
                [{"nibble": 0x03}, {"nibble": 0x0F}, {"nibble": 0x0F}]
            )
        )

    def test_flags_monotonic_rejects_regression(self) -> None:
        self.assertFalse(_flags_monotonic([{"nibble": 0x0F}, {"nibble": 0x00}]))
        self.assertIn(
            "sector 1",
            _find_regression(
                [
                    {"sector": 0, "nibble": 0x0F, "state": "new"},
                    {"sector": 1, "nibble": 0x00, "state": "updated"},
                ]
            ),
        )


class RustbootInvariantTests(unittest.TestCase):
    def test_swap_flag_invariant_reports_regression(self) -> None:
        result = SimpleNamespace(
            nvm_state={
                "flags": {"boot_flags_monotonic": False, "update_flags_monotonic": True},
                "boot": {
                    "sector_flags": [
                        {"sector": 0, "nibble": 0x0F, "state": "new"},
                        {"sector": 1, "nibble": 0x00, "state": "updated"},
                    ]
                },
                "update": {"sector_flags": []},
            },
            boot_outcome="success",
            fault_at=7,
        )

        with self.assertRaises(InvariantViolation) as ctx:
            check_rustboot_swap_flags_consistent(result)

        self.assertEqual(ctx.exception.invariant_name, "rustboot_swap_flags_consistent")
        self.assertEqual(ctx.exception.details["violating_partitions"], ["boot"])


class RustbootGenerateRuntimeProfileTests(unittest.TestCase):
    def test_synthetic_build_dir_renders_valid_baseline_and_state_search_profiles(
        self,
    ) -> None:
        import shutil
        import tempfile

        if str(ROOT / "scripts") not in sys.path:
            sys.path.insert(0, str(ROOT / "scripts"))
        from profile_loader import load_profile
        from targets.rustboot.generate_runtime_profile import (
            main as gen_main,
            render_runtime_profile,
            write_runtime_profile,
        )

        temp_dir = Path(tempfile.mkdtemp(prefix="rustboot_synth_"))
        try:
            build_dir = temp_dir / "build"
            build_dir.mkdir(parents=True, exist_ok=True)
            (build_dir / "rustboot_nrf52840.elf").write_bytes(b"\x7fELF" + b"\x00" * 60)
            (build_dir / "rustboot_boot_v1.bin").write_bytes(b"\xAA" * 4352)
            (build_dir / "rustboot_update_v2.bin").write_bytes(b"\xBB" * 8448)

            out_yaml = build_dir / "rustboot_nrf52840_update.yaml"
            rendered = render_runtime_profile(build_dir)
            written = write_runtime_profile(out_yaml, rendered)
            loaded = load_profile(written, strict=True)
            self.assertEqual(loaded.platform, "platforms/cortex_m4_flash_fast.repl")
            self.assertEqual(loaded.flash_backend, "faultFlash")
            self.assertEqual(loaded.memory.slots["exec"].base, 0x0002F000)
            self.assertEqual(loaded.memory.slots["staging"].base, 0x00058000)
            self.assertEqual(loaded.fault_sweep.fault_types, ["power_loss"])
            self.assertTrue(loaded.expect.should_find_issues)

            rc_ss = gen_main(
                [
                    "--build-dir",
                    str(build_dir),
                    "--state-search",
                    "--state-search-max-cuts",
                    "3",
                ]
            )
            self.assertEqual(rc_ss, 0)
            ss_yaml = build_dir / "rustboot_nrf52840_state_search.yaml"
            loaded_ss = load_profile(ss_yaml, strict=True)
            self.assertTrue(loaded_ss.fault_sweep.include_erase_fault_points)
            self.assertTrue(loaded_ss.fault_sweep.torn_word_explicit)
            self.assertEqual(loaded_ss.fault_sweep.torn_word_seed, 20261127)
            self.assertTrue(loaded_ss.fault_sweep.phase2_fault.enabled)
            self.assertEqual(
                loaded_ss.fault_sweep.phase2_fault.first_fault_types,
                ["power_loss", "interrupted_erase"],
            )
            self.assertEqual(
                loaded_ss.fault_sweep.phase2_fault.fault_types,
                ["power_loss", "interrupted_erase"],
            )
            ss = loaded_ss.fault_sweep.phase2_fault.state_search
            self.assertTrue(ss.enabled)
            self.assertEqual(ss.max_cuts, 3)
            self.assertEqual(ss.max_new_states, 64)
            self.assertEqual(ss.cross_check_every, 4)
            self.assertEqual(len(ss.address_ranges), 3)
            self.assertTrue(loaded_ss.expect.should_find_issues)

            with self.assertRaisesRegex(ValueError, "Refusing to write"):
                write_runtime_profile(ROOT / "profiles" / "forbidden.yaml", rendered)
        finally:
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    unittest.main()
