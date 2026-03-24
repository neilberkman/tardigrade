#!/usr/bin/env python3
"""Tests for automatic update-trigger discovery."""

from __future__ import annotations

import csv
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import yaml  # noqa: F401
except Exception:  # pragma: no cover - local env may omit pyyaml
    HAVE_PYYAML = False
else:
    HAVE_PYYAML = True

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ASSETS = ROOT / "results" / "oss_validation" / "assets"

import sys

sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile  # noqa: E402
from trigger_discovery import (  # noqa: E402
    TriggerStrategy,
    _build_mcuboot_strategies,
    _clone_for_strategy,
    _detect_mcuboot_swap_algorithm,
    discover_update_trigger,
    should_auto_discover_trigger,
    validate_compiled_flash_map,
    validate_swap_sector_geometry,
)


def _write_trace(path: Path, rows: list[dict[str, int]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["write_index", "flash_offset", "value"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_erase_trace(path: Path, rows: list[dict[str, int]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["erase_index", "flash_offset", "writes_at_this_point", "erase_size"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class TriggerDiscoveryTests(unittest.TestCase):
    def test_detect_mcuboot_swap_algorithm_from_elf_symbols(self) -> None:
        profile = SimpleNamespace(
            name="mcuboot_auto",
            bootloader_elf="dummy.elf",
            resolve_path=lambda _root, path: path,
        )
        with mock.patch(
            "trigger_discovery._read_elf_symbol_names",
            return_value=({"boot_swap_offset", "boot_status_source"}, None),
        ):
            detected = _detect_mcuboot_swap_algorithm(profile, ROOT)
        self.assertEqual(detected["status"], "detected")
        self.assertEqual(detected["algorithm"], "offset")
        self.assertIn("boot_swap_offset", detected["symbols"])

    def test_offset_swap_symbols_prioritize_offset_trigger_strategies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            staging = tempdir / "staging.bin"
            staging.write_bytes(b"\xAA" * 256)
            profile = SimpleNamespace(
                images={"staging": str(staging)},
                memory=SimpleNamespace(
                    slots={
                        "exec": SimpleNamespace(base=0x0800C000, size=0x76000),
                        "staging": SimpleNamespace(base=0x08082000, size=0x76000),
                    }
                ),
                resolve_path=lambda _root, path: path,
                update_trigger=None,
            )
            strategies = _build_mcuboot_strategies(
                profile,
                tempdir,
                swap_algorithm={"algorithm": "offset"},
            )
        names = [strategy.name for strategy in strategies[:3]]
        self.assertEqual(names[0], "no_trigger")
        self.assertTrue(names[1].startswith("offset_image_swap_metadata_align"))
        self.assertTrue(names[2].startswith("offset_image_align"))

    def test_validate_swap_sector_geometry_detects_partial_sector_layout(self) -> None:
        profile = SimpleNamespace(
            name="mcuboot_geom",
            bootloader_entry=0x08000000,
            bootloader_elf="mcuboot.elf",
            platform="platforms/stm32f4.repl",
            memory=SimpleNamespace(
                slots={
                    "exec": SimpleNamespace(base=0x0800C000, size=0x76000),
                    "staging": SimpleNamespace(base=0x08082000, size=0x76000),
                }
            ),
        )
        check = validate_swap_sector_geometry(profile)
        self.assertEqual(check["status"], "mismatch")
        self.assertIn("erase-sector layout", check["reason"])
        self.assertTrue(any(seg["partial"] for seg in check["exec_segments"]))
        self.assertTrue(any(seg["partial"] for seg in check["staging_segments"]))

    def test_validate_swap_sector_geometry_accepts_uniform_layout(self) -> None:
        profile = SimpleNamespace(
            name="mcuboot_uniform",
            bootloader_entry=0x10000000,
            bootloader_elf="mcuboot.elf",
            platform="platforms/cortex_m4_flash_fast.repl",
            memory=SimpleNamespace(
                page_size=0x1000,
                write_granularity=4,
                slots={
                    "exec": SimpleNamespace(base=0x10000000, size=0x4000),
                    "staging": SimpleNamespace(base=0x10004000, size=0x4000),
                }
            ),
        )
        check = validate_swap_sector_geometry(profile)
        self.assertEqual(check["status"], "match")
        self.assertEqual(len(check["exec_segments"]), len(check["staging_segments"]))

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_loader_accepts_update_trigger_auto(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: auto_trigger
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x1000 }
                    staging: { base: 0x10001000, size: 0x1000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                update_trigger: auto
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertIsNone(profile.update_trigger)
            self.assertTrue(profile.auto_update_trigger)
            self.assertTrue(should_auto_discover_trigger(profile, "execute"))

    def test_validate_compiled_flash_map_matches_known_profile(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_head_offset_stm32f4_revert.yaml")
        check = validate_compiled_flash_map(profile, ROOT)
        if check["status"] == "unavailable":
            self.skipTest(check["reason"])
        self.assertEqual(check["status"], "match")
        self.assertEqual(len(check["checked_slots"]), 2)

    def test_validate_compiled_flash_map_detects_mismatch(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_head_offset_stm32f4_revert.yaml")
        profile.memory.slots["staging"].base += 0x2000
        check = validate_compiled_flash_map(profile, ROOT)
        if check["status"] == "unavailable":
            self.skipTest(check["reason"])
        self.assertEqual(check["status"], "mismatch")
        self.assertTrue(any("staging" in item for item in check["mismatches"]))

    def test_discovery_uses_compiled_flash_map_when_profile_geometry_mismatches(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_head_offset_stm32f4_revert.yaml")
        preflight = validate_compiled_flash_map(profile, ROOT)
        if preflight["status"] == "unavailable":
            self.skipTest(preflight["reason"])
        profile.update_trigger = None
        profile.auto_update_trigger = True
        profile.pre_boot_state = []
        original_staging_base = int(profile.memory.slots["staging"].base)
        profile.memory.slots["staging"].base += 0x2000

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            slot_trace = tempdir / "slot.csv"
            _write_trace(
                slot_trace,
                [
                    {
                        "write_index": 0,
                        "flash_offset": (original_staging_base - int(profile.bootloader_entry)) + 4,
                        "value": 0x12345678,
                    }
                ],
            )

            def fake_run_single_point(*, profile, **_kwargs):
                self.assertEqual(
                    int(profile.memory.slots["staging"].base),
                    original_staging_base,
                )
                return {
                    "total_writes": 1,
                    "total_erases": 0,
                    "trace_file": str(slot_trace),
                    "erase_trace_file": None,
                    "trace_file_bin": None,
                    "erase_trace_file_bin": None,
                    "calibration_stop_reason": "vtor_captured",
                }

            with mock.patch(
                "trigger_discovery.run_single_point",
                side_effect=fake_run_single_point,
            ):
                result = discover_update_trigger(
                    profile,
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/audit.robot",
                    work_dir=tempdir,
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                    robot_vars_factory=lambda _candidate: [],
                )

        self.assertTrue(result.succeeded)
        self.assertIsNotNone(result.geometry_override)
        self.assertEqual(result.geometry_override["status"], "applied")
        self.assertEqual(
            int(result.selected_profile.memory.slots["staging"].base),
            original_staging_base,
        )

    def test_offset_strategy_uses_real_next_erase_boundary(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_pr2214_offset_fixed.yaml")
        strategy = TriggerStrategy(
            name="offset_image_swap_metadata_align8",
            trigger_fields={
                "max_align": 8,
                "swap_type": 0x02,
                "image_num": 0x00,
                "swap_size": 0x1234,
            },
            use_offset_image=True,
            max_align=8,
        )
        candidate, error = _clone_for_strategy(profile, ROOT, strategy)
        self.assertIsNone(error)
        assert candidate is not None
        self.assertEqual(candidate.image_load_addresses["staging"], 0x080A0000)
        self.assertTrue(candidate.images["staging"].endswith("zephyr_slot1_offset_geom_full.bin"))

    def test_discovery_selects_first_strategy_with_slot_activity(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        if not (ASSETS / "zephyr_slot0_padded.bin").exists():
            self.skipTest("required discovery asset missing")
        profile = load_profile(ROOT / "profiles" / "mcuboot_offset_upgrade.yaml")
        profile.update_trigger = None
        profile.auto_update_trigger = True
        profile.pre_boot_state = []

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            empty_trace = tempdir / "empty.csv"
            slot_trace = tempdir / "slot.csv"
            _write_trace(empty_trace, [])
            _write_trace(
                slot_trace,
                [
                    {
                        "write_index": 0,
                        "flash_offset": profile.memory.slots["staging"].base + 4,
                        "value": 0x12345678,
                    }
                ],
            )

            def fake_run_single_point(*, profile, **_kwargs):
                trigger = getattr(profile, "update_trigger", None)
                if trigger is None:
                    return {
                        "total_writes": 0,
                        "total_erases": 0,
                        "trace_file": str(empty_trace),
                        "erase_trace_file": None,
                        "trace_file_bin": None,
                        "erase_trace_file_bin": None,
                        "calibration_stop_reason": "budget",
                    }
                return {
                    "total_writes": 1,
                    "total_erases": 0,
                    "trace_file": str(slot_trace),
                    "erase_trace_file": None,
                    "trace_file_bin": None,
                    "erase_trace_file_bin": None,
                    "calibration_stop_reason": "vtor_captured",
                    "calibration_exec_hash": "deadbeef",
                    "calibration_elapsed_s": 1.0,
                    "calibration_emulated_s": 1.0,
                    "calibration_pc": "0x00000000",
                    "setup_writes": 0,
                    "total_i2c_transactions": 0,
                    "total_otp_blows": 0,
                }

            with mock.patch("trigger_discovery.run_single_point", side_effect=fake_run_single_point):
                result = discover_update_trigger(
                    profile,
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    work_dir=tempdir,
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                    robot_vars_factory=lambda candidate: candidate.robot_vars(ROOT),
                )

        self.assertTrue(result.succeeded)
        self.assertEqual(result.selected_strategy, "trailer_magic_swap_metadata_align8")
        self.assertEqual(result.attempts[0].coverage["status"], "no_nvm_activity")
        self.assertEqual(result.attempts[1].coverage["status"], "slot_activity")

    def test_discovery_selects_named_metadata_activity(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "esp_idf_fault_single_sector.yaml")
        profile.update_trigger = None
        profile.auto_update_trigger = True

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            metadata_trace = tempdir / "metadata.csv"
            _write_trace(
                metadata_trace,
                [{"write_index": 1, "flash_offset": 0xF8000, "value": 0x12345678}],
            )

            def fake_run_single_point(*args, **kwargs):
                return {
                    "total_writes": 1,
                    "total_erases": 0,
                    "trace_file": str(metadata_trace),
                    "erase_trace_file": None,
                    "trace_file_bin": None,
                    "erase_trace_file_bin": None,
                    "calibration_stop_reason": "vtor_captured",
                    "calibration_exec_hash": "deadbeef",
                    "calibration_elapsed_s": 1.0,
                    "calibration_emulated_s": 1.0,
                    "calibration_pc": "0x00000000",
                    "setup_writes": 0,
                    "total_i2c_transactions": 0,
                    "total_otp_blows": 0,
                }

            with mock.patch("trigger_discovery.run_single_point", side_effect=fake_run_single_point):
                result = discover_update_trigger(
                    profile,
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    work_dir=tempdir,
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                    robot_vars_factory=lambda candidate: candidate.robot_vars(ROOT),
                )

        self.assertTrue(result.succeeded)
        self.assertEqual(result.attempts[0].coverage["status"], "named_metadata_only")
        self.assertTrue(result.attempts[0].selected)

    def test_discovery_accepts_erase_only_slot_activity(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_head_offset_stm32f4_upgrade.yaml")
        profile.update_trigger = None
        profile.auto_update_trigger = True

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            erase_trace = tempdir / "erase.csv"
            flash_base = profile.bootloader_entry
            staging_base = profile.memory.slots["staging"].base - flash_base
            _write_erase_trace(
                erase_trace,
                [
                    {
                        "erase_index": 1,
                        "flash_offset": staging_base,
                        "writes_at_this_point": 0,
                        "erase_size": 0x20000,
                    }
                ],
            )

            def fake_run_single_point(*args, **kwargs):
                return {
                    "total_writes": 0,
                    "total_erases": 1,
                    "trace_file": None,
                    "erase_trace_file": str(erase_trace),
                    "trace_file_bin": None,
                    "erase_trace_file_bin": None,
                    "calibration_stop_reason": "vtor_captured",
                    "calibration_exec_hash": "deadbeef",
                    "calibration_elapsed_s": 1.0,
                    "calibration_emulated_s": 1.0,
                    "calibration_pc": "0x08022C94",
                    "setup_writes": 0,
                    "total_i2c_transactions": 0,
                    "total_otp_blows": 0,
                    "boot_outcome": "success",
                    "signals": {"expectations_met": True},
                }

            with mock.patch(
                "trigger_discovery.run_single_point",
                side_effect=fake_run_single_point,
            ):
                result = discover_update_trigger(
                    profile,
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    work_dir=tempdir,
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                    robot_vars_factory=lambda candidate: candidate.robot_vars(ROOT),
                )

        self.assertTrue(result.succeeded)
        selected = next(attempt for attempt in result.attempts if attempt.selected)
        self.assertEqual(selected.coverage["status"], "slot_activity")

    def test_discovery_rejects_slot_activity_when_control_boots_wrong_image(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles" / "mcuboot_head_offset_stm32f4_upgrade.yaml")
        profile.update_trigger = None
        profile.auto_update_trigger = True

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            erase_trace = tempdir / "erase.csv"
            flash_base = profile.bootloader_entry
            staging_base = profile.memory.slots["staging"].base - flash_base
            _write_erase_trace(
                erase_trace,
                [
                    {
                        "erase_index": 1,
                        "flash_offset": staging_base,
                        "writes_at_this_point": 0,
                        "erase_size": 0x20000,
                    }
                ],
            )

            def fake_run_single_point(*args, **kwargs):
                return {
                    "total_writes": 0,
                    "total_erases": 1,
                    "trace_file": None,
                    "erase_trace_file": str(erase_trace),
                    "trace_file_bin": None,
                    "erase_trace_file_bin": None,
                    "calibration_stop_reason": "vtor_captured",
                    "calibration_exec_hash": "deadbeef",
                    "calibration_elapsed_s": 1.0,
                    "calibration_emulated_s": 1.0,
                    "calibration_pc": "0x08022C94",
                    "setup_writes": 0,
                    "total_i2c_transactions": 0,
                    "total_otp_blows": 0,
                    "boot_outcome": "wrong_image",
                    "signals": {"expectations_met": False, "image_hash_match": "exec_image"},
                }

            with mock.patch(
                "trigger_discovery.run_single_point",
                side_effect=fake_run_single_point,
            ):
                result = discover_update_trigger(
                    profile,
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    work_dir=tempdir,
                    renode_remote_server_dir="",
                    keep_run_artifacts=False,
                    robot_vars_factory=lambda candidate: candidate.robot_vars(ROOT),
                )

        self.assertFalse(result.succeeded)
        self.assertTrue(all(not attempt.selected for attempt in result.attempts))


if __name__ == "__main__":
    unittest.main()
