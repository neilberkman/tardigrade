#!/usr/bin/env python3
"""Tests for automatic update-trigger discovery."""

from __future__ import annotations

import csv
import hashlib
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
    _read_elf_symbol_names,
    _calibration_boot_evidence_is_success,
    _image_digest_for_evidence,
    _trace_less_content_evidence,
    _validate_trace_artifacts,
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
    @staticmethod
    def _evidence_data(**signals):
        return {
            "total_writes": 1,
            "total_erases": 0,
            "calibration_stop_reason": "vtor_captured",
            "calibration_boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {
                "expectations_met": True,
                "vtor_final": "0x0000C000",
                "vtor_aligned": True,
                "pc": "0x0000C100",
                **signals,
            },
        }

    @staticmethod
    def _content_profile(tempdir: Path, *, marker_value=0x12345678,
                          baseline_word=0, target_word=None, image_hash=False):
        target_word = marker_value if target_word is None else target_word
        exec_image = tempdir / "exec.bin"
        staging_image = tempdir / "staging.bin"
        exec_data = bytearray(b"baseline image".ljust(0x40, b"\x00"))
        staging_data = bytearray(b"target image".ljust(0x40, b"\x00"))
        exec_data[0x14:0x18] = int(baseline_word).to_bytes(4, "little")
        staging_data[0x14:0x18] = int(target_word).to_bytes(4, "little")
        exec_image.write_bytes(exec_data)
        staging_image.write_bytes(staging_data)
        return SimpleNamespace(
            success_criteria=SimpleNamespace(
                vtor_in_slot="exec",
                marker_address=0xC014,
                marker_value=marker_value,
                image_hash=image_hash,
                image_hash_slot="exec" if image_hash else None,
                expected_image="staging",
            ),
            memory=SimpleNamespace(
                slots={
                    "exec": SimpleNamespace(base=0xC000, size=0x2000),
                    "staging": SimpleNamespace(base=0xE000, size=0x2000),
                }
            ),
            images={"exec": str(exec_image), "staging": str(staging_image)},
            flash_backend="faultFlash",
        )

    def test_trace_less_exact_marker_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            evidence = _trace_less_content_evidence(
                profile,
                self._evidence_data(marker_ok=True, marker_actual="0x12345678"),
                ROOT,
            )
        self.assertEqual(evidence["kind"], "exact_marker")

    def test_trace_less_marker_requires_nonzero_exact_configured_value(self) -> None:
        for signals in (
            {"marker_ok": False, "marker_actual": "0x12345678"},
            {"marker_ok": True},
            {"marker_ok": True, "marker_actual": "0x00000000"},
            {"marker_ok": True, "marker_actual": "0x87654321"},
        ):
            with self.subTest(signals=signals), tempfile.TemporaryDirectory() as td:
                profile = self._content_profile(Path(td))
                self.assertIsNone(
                    _trace_less_content_evidence(profile, self._evidence_data(**signals), ROOT)
                )

        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), marker_value=0)
            self.assertIsNone(
                _trace_less_content_evidence(
                    profile,
                    self._evidence_data(marker_ok=True, marker_actual="0x00000000"),
                    ROOT,
                )
            )

    def test_trace_less_marker_rejects_baseline_already_containing_marker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), baseline_word=0x12345678)
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_marker_rejects_target_without_marker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), target_word=0x87654321)
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_marker_rejects_address_outside_exec_slot_or_short_images(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            profile.success_criteria.marker_address = 0x1000
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

            profile = self._content_profile(Path(td))
            Path(profile.images["staging"]).write_bytes(b"short")
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_exact_expected_hash_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), image_hash=True)
            profile.success_criteria.marker_address = None
            profile.success_criteria.marker_value = None
            expected = _image_digest_for_evidence(profile, ROOT, "staging")
            data = self._evidence_data()
            data["calibration_exec_hash"] = expected
            self.assertEqual(_trace_less_content_evidence(profile, data, ROOT)["kind"], "exact_expected_image_hash")

    def test_trace_less_hash_rejects_wrong_or_unknown_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), image_hash=True)
            profile.success_criteria.marker_address = None
            profile.success_criteria.marker_value = None
            expected = _image_digest_for_evidence(profile, ROOT, "staging")
            for observed in ("0" * 64, "unknown", "expected_image", None):
                with self.subTest(observed=observed):
                    data = self._evidence_data()
                    data["calibration_exec_hash"] = observed
                    self.assertIsNone(
                        _trace_less_content_evidence(profile, data, ROOT)
                    )

    def test_trace_less_hash_rejects_identical_exec_and_target_images(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), image_hash=True)
            profile.success_criteria.marker_address = None
            profile.success_criteria.marker_value = None
            exec_path = Path(profile.images["exec"])
            staging_path = Path(profile.images["staging"])
            staging_path.write_bytes(exec_path.read_bytes())
            target_hash = _image_digest_for_evidence(profile, ROOT, "staging")
            data = self._evidence_data()
            data["calibration_exec_hash"] = target_hash
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_hash_rejects_conflicting_runtime_hash_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), image_hash=True)
            profile.success_criteria.marker_address = None
            profile.success_criteria.marker_value = None
            target_hash = _image_digest_for_evidence(profile, ROOT, "staging")
            data = self._evidence_data()
            data["calibration_exec_hash"] = target_hash
            data["signals"]["image_hash_actual"] = "0" * 64
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_without_content_evidence_fails_closed(self) -> None:
        profile = SimpleNamespace(
            success_criteria=SimpleNamespace(
                marker_address=None,
                marker_value=None,
                image_hash=False,
                expected_image=None,
            ),
            images={},
        )
        self.assertIsNone(
            _trace_less_content_evidence(profile, self._evidence_data(), ROOT)
        )

    def test_trace_less_requires_explicit_expected_boot_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            valid = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            for mutation in (
                {"signals": {}},
                {"calibration_boot_outcome": "wrong_image"},
                {"boot_slot": "staging"},
            ):
                with self.subTest(mutation=mutation):
                    candidate = dict(valid)
                    candidate.update(mutation)
                    self.assertIsNone(_trace_less_content_evidence(profile, candidate, ROOT))

    def test_trace_less_rejects_conflicting_boot_outcomes(self) -> None:
        data = self._evidence_data()
        data["final_boot_outcome"] = "wrong_image"
        self.assertFalse(_calibration_boot_evidence_is_success(data))
        self.assertIsNone(
            _trace_less_content_evidence(
                SimpleNamespace(),
                data,
                ROOT,
            )
        )

    def test_trace_less_rejects_sticky_success_when_final_vtor_is_outside_slot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            data["signals"]["vtor_final"] = "0x00010000"
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_rejects_misaligned_final_vtor_even_if_sticky_was_aligned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            data["signals"]["vtor_final"] = "0x0000C001"
            data["signals"]["vtor_aligned"] = True
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_rejects_missing_or_malformed_final_vtor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            for value in (None, "not-an-address"):
                with self.subTest(value=value):
                    data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
                    if value is None:
                        del data["signals"]["vtor_final"]
                    else:
                        data["signals"]["vtor_final"] = value
                    self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_rejects_missing_or_malformed_final_pc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            for value in (None, "not-an-address"):
                with self.subTest(value=value):
                    data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
                    if value is None:
                        del data["signals"]["pc"]
                    else:
                        data["signals"]["pc"] = value
                    self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_rejects_final_pc_outside_target_slot_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
            data["signals"]["pc"] = "0x00000000"
            self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_trace_less_rejects_non_integer_or_negative_counters(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td))
            for field_name, value in (
                ("total_writes", True),
                ("total_writes", 1.5),
                ("total_writes", "1"),
                ("total_writes", -1),
                ("total_erases", False),
                ("total_erases", 2.5),
                ("total_erases", "2"),
                ("total_erases", -1),
            ):
                with self.subTest(field_name=field_name, value=value):
                    data = self._evidence_data(marker_ok=True, marker_actual="0x12345678")
                    data[field_name] = value
                    self.assertIsNone(_trace_less_content_evidence(profile, data, ROOT))

    def test_malformed_trace_path_is_rejected(self) -> None:
        self.assertIn(
            "must be a string path",
            _validate_trace_artifacts({"trace_file": {"path": "bad"}}),
        )

    def test_malformed_trace_content_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            trace = Path(td) / "trace.csv"
            trace.write_text("not,a,valid,trace\n", encoding="utf-8")
            error = _validate_trace_artifacts({"trace_file": str(trace)})
        self.assertIn("missing required columns", error)

    def test_trace_less_combined_marker_and_hash_requires_both(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile = self._content_profile(Path(td), image_hash=True)
            expected = _image_digest_for_evidence(profile, ROOT, "staging")
            marker = {"marker_ok": True, "marker_actual": "0x12345678"}
            data = self._evidence_data(**marker)
            data["calibration_exec_hash"] = expected
            self.assertEqual(
                _trace_less_content_evidence(profile, data, ROOT)["kind"],
                "exact_marker_and_expected_image_hash",
            )
            # The runtime's hash-only evaluation does not produce marker
            # evidence, so the combined criterion remains fail-closed.
            marker.pop("marker_ok")
            data = self._evidence_data(**marker)
            data["calibration_exec_hash"] = expected
            self.assertIsNone(
                _trace_less_content_evidence(profile, data, ROOT)
            )

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

    def test_detect_mcuboot_swap_algorithm_from_profile_when_elf_is_stripped(self) -> None:
        profile = SimpleNamespace(
            name="mcuboot_offset_upgrade",
            bootloader_elf="results/oss_validation/assets/oss_mcuboot_head_offset.elf",
            resolve_path=lambda _root, path: path,
        )
        with mock.patch(
            "trigger_discovery._read_elf_symbol_names",
            return_value=(None, "ELF has no .symtab"),
        ):
            detected = _detect_mcuboot_swap_algorithm(profile, ROOT)
        self.assertEqual(detected["status"], "heuristic")
        self.assertEqual(detected["algorithm"], "offset")
        self.assertEqual(detected["source"], "profile_name_or_path")

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

    def test_move_swap_symbols_prioritize_trailer_trigger_strategies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            staging = tempdir / "staging.bin"
            staging.write_bytes(b"\xAA" * 256)
            exec_image = tempdir / "exec.bin"
            exec_image.write_bytes(b"\x00" * 256)
            profile = SimpleNamespace(
                images={"exec": str(exec_image), "staging": str(staging)},
                memory=SimpleNamespace(
                    slots={
                        "exec": SimpleNamespace(base=0x0800C000, size=0x76000),
                        "staging": SimpleNamespace(base=0x08082000, size=0x76000),
                    }
                ),
                resolve_path=lambda _root, path: path,
                update_trigger=None,
                success_criteria=SimpleNamespace(expected_image=None, marker_address=None, marker_value=None),
            )
            strategies = _build_mcuboot_strategies(
                profile,
                tempdir,
                swap_algorithm={"algorithm": "move"},
            )
        names = [strategy.name for strategy in strategies[:5]]
        self.assertEqual(names[0], "no_trigger")
        self.assertTrue(names[1].startswith("trailer_magic_swap_metadata_align"))
        self.assertTrue(names[2].startswith("trailer_magic_align"))
        self.assertTrue(names[3].startswith("offset_image_swap_metadata_align"))
        self.assertTrue(names[4].startswith("offset_image_align"))

    def test_upgrade_marker_prefers_triggered_strategies_before_no_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            exec_image = tempdir / "exec.bin"
            staging = tempdir / "staging.bin"
            exec_data = bytearray(256)
            staging_data = bytearray(256)
            exec_data[0x14:0x18] = (0x00000001).to_bytes(4, "little")
            staging_data[0x14:0x18] = (0x00000101).to_bytes(4, "little")
            exec_image.write_bytes(exec_data)
            staging.write_bytes(staging_data)
            profile = SimpleNamespace(
                images={"exec": str(exec_image), "staging": str(staging)},
                memory=SimpleNamespace(
                    slots={
                        "exec": SimpleNamespace(base=0x0000C000, size=0x76000),
                        "staging": SimpleNamespace(base=0x00082000, size=0x76000),
                    }
                ),
                resolve_path=lambda _root, path: path,
                update_trigger=None,
                success_criteria=SimpleNamespace(
                    expected_image=None,
                    marker_address=0x0000C014,
                    marker_value=0x00000101,
                ),
            )
            strategies = _build_mcuboot_strategies(
                profile,
                tempdir,
                swap_algorithm={"algorithm": "move"},
            )
        names = [strategy.name for strategy in strategies]
        self.assertTrue(names[0].startswith("trailer_magic_swap_metadata_align"))
        self.assertTrue(names[1].startswith("trailer_magic_align"))
        self.assertEqual(names[-1], "no_trigger")

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

    def test_validate_compiled_flash_map_keeps_sector_advisory_separate(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        profile = load_profile(ROOT / "profiles/mcuboot_pr2214_offset_fixed.yaml")
        check = validate_compiled_flash_map(profile, ROOT)
        if check["status"] == "unavailable":
            self.skipTest(check["reason"])
        self.assertEqual(check["status"], "match")
        self.assertEqual(
            [slot["status"] for slot in check["checked_slots"]],
            ["match", "match"],
        )
        self.assertEqual(check["sector_geometry"]["status"], "mismatch")
        self.assertIn("sector geometry advisory", check["reason"])

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
        self.assertEqual(result.selected_strategy, "offset_image_swap_metadata_align8")
        self.assertEqual(result.attempts[0].name, "offset_image_swap_metadata_align8")
        self.assertEqual(result.attempts[0].coverage["status"], "slot_activity")

    def test_discovery_selects_exact_target_boot_without_a_trace(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        if not (ASSETS / "zephyr_slot0_padded.bin").exists():
            self.skipTest("required discovery asset missing")
        profile = load_profile(ROOT / "profiles" / "mcuboot_offset_upgrade.yaml")
        profile.update_trigger = None
        profile.auto_update_trigger = True
        profile.pre_boot_state = []

        def fake_run_single_point(*, profile, **kwargs):
            self.assertFalse(
                any(
                    value.startswith("CALIBRATION_TRACE_PHASE1:")
                    for value in kwargs["robot_vars"]
                )
            )
            return {
                "total_writes": 17,
                "total_erases": 2,
                "trace_file": None,
                "erase_trace_file": None,
                "trace_file_bin": None,
                "erase_trace_file_bin": None,
                "calibration_stop_reason": "vtor_captured",
                "calibration_boot_outcome": "success",
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {
                    "expectations_met": True,
                    "vtor_final": "0x0000C000",
                    "vtor_aligned": True,
                    "pc": "0x0000C100",
                    "marker_ok": True,
                    "marker_actual": "0x{:08X}".format(
                        int(profile.success_criteria.marker_value)
                    ),
                },
                "calibration_elapsed_s": 1.0,
                "calibration_emulated_s": 1.0,
                "calibration_pc": "0x0000C100",
                "setup_writes": 0,
                "total_i2c_transactions": 0,
                "total_otp_blows": 0,
            }

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
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
        self.assertEqual(result.selected_strategy, "offset_image_swap_metadata_align8")
        self.assertIsNotNone(result.selected_calibration)
        self.assertIsNone(result.selected_calibration.trace_file)
        self.assertEqual(
            result.attempts[0].coverage["status"],
            "verified_target_boot",
        )
        self.assertEqual(
            result.attempts[0].coverage["trace_less_evidence"]["kind"],
            "exact_marker",
        )

    def test_discovery_reports_malformed_calibration_without_aborting(self) -> None:
        if not HAVE_PYYAML:
            self.skipTest("PyYAML not installed")
        if not (ASSETS / "zephyr_slot0_padded.bin").exists():
            self.skipTest("required discovery asset missing")

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            malformed_trace = tempdir / "malformed.csv"
            malformed_trace.write_text("not,a,valid,trace\n", encoding="utf-8")
            cases = (
                {"total_writes": True},
                {"setup_writes": "0"},
                {"trace_file": {"path": "not-a-string"}},
                {"trace_file": str(malformed_trace)},
            )
            for mutation in cases:
                with self.subTest(mutation=mutation):
                    profile = load_profile(
                        ROOT / "profiles" / "mcuboot_offset_upgrade.yaml"
                    )
                    profile.update_trigger = None
                    profile.auto_update_trigger = True
                    profile.pre_boot_state = []

                    def fake_run_single_point(**_kwargs):
                        data = self._evidence_data(
                            marker_ok=True,
                            marker_actual="0x{:08X}".format(
                                int(profile.success_criteria.marker_value)
                            ),
                        )
                        data.update(
                            {
                                "trace_file": None,
                                "erase_trace_file": None,
                                "trace_file_bin": None,
                                "erase_trace_file_bin": None,
                                "setup_writes": 0,
                                "total_i2c_transactions": 0,
                                "total_otp_blows": 0,
                            }
                        )
                        data.update(mutation)
                        return data

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
                    self.assertGreater(len(result.attempts), 0)
                    self.assertTrue(all(attempt.error for attempt in result.attempts))
                    self.assertTrue(
                        all(
                            attempt.coverage.get("status") == "unavailable"
                            for attempt in result.attempts
                        )
                    )

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


    def test_detect_swap_algorithm_config_boot_swap_using_symbols(self) -> None:
        """CONFIG_BOOT_SWAP_USING_* symbols should be recognized."""
        profile = SimpleNamespace(
            name="mcuboot_auto",
            bootloader_elf="dummy.elf",
            resolve_path=lambda _root, path: path,
        )
        for algorithm, symbol in [
            ("move", "CONFIG_BOOT_SWAP_USING_MOVE"),
            ("offset", "CONFIG_BOOT_SWAP_USING_OFFSET"),
            ("scratch", "CONFIG_BOOT_SWAP_USING_SCRATCH"),
        ]:
            with self.subTest(algorithm=algorithm):
                with mock.patch(
                    "trigger_discovery._read_elf_symbol_names",
                    return_value=({symbol, "main"}, None),
                ):
                    detected = _detect_mcuboot_swap_algorithm(profile, ROOT)
                self.assertEqual(detected["status"], "detected")
                self.assertEqual(detected["algorithm"], algorithm)

    def test_detect_swap_algorithm_prefer_swap_symbols(self) -> None:
        """CONFIG_BOOT_PREFER_SWAP_* symbols should be recognized."""
        profile = SimpleNamespace(
            name="mcuboot_auto",
            bootloader_elf="dummy.elf",
            resolve_path=lambda _root, path: path,
        )
        with mock.patch(
            "trigger_discovery._read_elf_symbol_names",
            return_value=({"CONFIG_BOOT_PREFER_SWAP_MOVE", "main"}, None),
        ):
            detected = _detect_mcuboot_swap_algorithm(profile, ROOT)
        self.assertEqual(detected["status"], "detected")
        self.assertEqual(detected["algorithm"], "move")

    def test_read_elf_symbol_names_nm_fallback(self) -> None:
        """nm fallback produces symbol names from real ELF."""
        elf_path = str(ROOT / "results" / "oss_validation" / "assets" / "oss_mcuboot_head_move_nrf52.elf")
        if not Path(elf_path).exists():
            self.skipTest("test ELF not available")
        # Force the nm fallback by disabling pyelftools
        with mock.patch("trigger_discovery.ELFFile", None):
            symbols, error = _read_elf_symbol_names(elf_path)
        self.assertIsNotNone(symbols)
        self.assertIn("main", symbols)
        # Should contain MCUboot swap config symbols
        self.assertTrue(
            any("SWAP_USING_MOVE" in s for s in symbols),
            "Expected CONFIG_BOOT_SWAP_USING_MOVE in symbols",
        )

    def test_resolve_flash_map_from_real_elf(self) -> None:
        """Flash map extraction works on real MCUboot ELF without pyelftools."""
        from trigger_discovery import _resolve_mcuboot_flash_map
        elf_path = str(ROOT / "results" / "oss_validation" / "assets" / "oss_mcuboot_head_move_nrf52.elf")
        if not Path(elf_path).exists():
            self.skipTest("test ELF not available")
        # Force the toolchain fallback by disabling pyelftools
        with mock.patch("trigger_discovery.ELFFile", None):
            entries, error = _resolve_mcuboot_flash_map(elf_path)
        self.assertIsNotNone(entries, "flash map extraction failed: {}".format(error))
        self.assertEqual(len(entries), 4)
        by_id = {e["area_id"]: e for e in entries}
        # exec slot should be area_id 1, starting at 0xC000
        self.assertIn(1, by_id)
        self.assertEqual(by_id[1]["off"], 0xC000)
        self.assertEqual(by_id[1]["size"], 0x76000)
        # staging slot should be area_id 2
        self.assertIn(2, by_id)
        self.assertEqual(by_id[2]["off"], 0x82000)


if __name__ == "__main__":
    unittest.main()
