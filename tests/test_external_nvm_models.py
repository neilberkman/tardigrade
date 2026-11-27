#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the external SPI NOR flash and I2C EEPROM models,
platform attachment, Robot suite wiring, profile loader validation,
and recovery-state computation across all command and fault outcomes.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import (  # noqa: E402
    FaultSweepConfig,
    _is_mram_backend,
    _validate_torn_word_backend,
    load_profile,
)
from trigger_discovery import validate_compiled_flash_map  # noqa: E402
from recovery_search import (  # noqa: E402
    RecoveryStateExplorer,
    select_first_cut_operations,
)
from recovery_state import (  # noqa: E402
    PersistentState,
    RecoveryStateComputer,
    apply_completed_operation,
    apply_interrupted_operation,
    merge_operation_traces,
)


class TestExternalNvmModelContracts(unittest.TestCase):
    def setUp(self) -> None:
        self.spi_nor_path = ROOT / "peripherals" / "SPINORFlash.cs"
        self.i2c_eeprom_path = ROOT / "peripherals" / "I2CEEPROM.cs"
        self.spi_nor_src = self.spi_nor_path.read_text(encoding="utf-8")
        self.i2c_eeprom_src = self.i2c_eeprom_path.read_text(encoding="utf-8")

    def test_spi_nor_cites_datasheets_and_implements_jedec_commands(self) -> None:
        self.assertIn("Winbond W25Q16JV", self.spi_nor_src)
        for iface in (
            "ISPIPeripheral",
            "IGPIOReceiver",
            "IMemory",
            "ITardigradeFaultInjectable",
        ):
            self.assertIn(iface, self.spi_nor_src)

        required_opcodes = {
            "CMD_WRSR1 = 0x01": "0x01",
            "CMD_PP = 0x02": "0x02",
            "CMD_READ = 0x03": "0x03",
            "CMD_WRDI = 0x04": "0x04",
            "CMD_RDSR1 = 0x05": "0x05",
            "CMD_WREN = 0x06": "0x06",
            "CMD_FAST_READ = 0x0B": "0x0B",
            "CMD_RDSR3 = 0x15": "0x15",
            "CMD_SE = 0x20": "0x20",
            "CMD_RDSR2 = 0x35": "0x35",
            "CMD_BE32K = 0x52": "0x52",
            "CMD_RDSFDP = 0x5A": "0x5A",
            "CMD_CE_ALT = 0x60": "0x60",
            "CMD_RDID = 0x9F": "0x9F",
            "CMD_CE = 0xC7": "0xC7",
            "CMD_BE64K = 0xD8": "0xD8",
        }
        for label, opcode in required_opcodes.items():
            with self.subTest(opcode=label):
                self.assertIn(opcode, self.spi_nor_src)

        # Page size 256 with in-page wrap and NOR 1->0 bit-clear physics.
        self.assertIn("PageBufferSize = 256", self.spi_nor_src)
        self.assertIn("SectorEraseSize = 4096", self.spi_nor_src)
        self.assertIn("Block32EraseSize = 32768", self.spi_nor_src)
        self.assertIn("Block64EraseSize = 65536", self.spi_nor_src)
        self.assertIn("PageProgramWrapCount++", self.spi_nor_src)
        self.assertIn("ulong intendedVal = oldVal & rawVal;", self.spi_nor_src)
        # Program/erase busy time and WIP bit 0 / WEL bit 1.
        self.assertIn("SR1_WIP = 0x01", self.spi_nor_src)
        self.assertIn("SR1_WEL = 0x02", self.spi_nor_src)
        self.assertIn("ProgramBusyTimeUs", self.spi_nor_src)
        self.assertIn("SectorEraseBusyTimeUs", self.spi_nor_src)
        self.assertIn("Block32EraseBusyTimeUs", self.spi_nor_src)
        self.assertIn("Block64EraseBusyTimeUs", self.spi_nor_src)
        self.assertIn("ChipEraseBusyTimeUs", self.spi_nor_src)

    def test_i2c_eeprom_cites_datasheet_and_implements_24_series_contract(self) -> None:
        self.assertIn("Microchip 24LC256", self.i2c_eeprom_src)
        self.assertIn("DS20001203Y", self.i2c_eeprom_src)
        for iface in (
            "II2CPeripheral",
            "IMemory",
            "ITardigradeFaultInjectable",
        ):
            self.assertIn(iface, self.i2c_eeprom_src)

        self.assertIn("DefaultMemorySize = 32768", self.i2c_eeprom_src)
        self.assertIn("DefaultPageBufferSize = 64", self.i2c_eeprom_src)
        self.assertIn("PageWrapCount++", self.i2c_eeprom_src)
        self.assertIn("public bool AckPoll()", self.i2c_eeprom_src)
        self.assertIn("WriteCycleTimeUs", self.i2c_eeprom_src)
        self.assertIn("BusyPollsPerWrite", self.i2c_eeprom_src)
        self.assertIn("SequentialReadByteCount++", self.i2c_eeprom_src)

    def test_platforms_attach_to_existing_renode_spi_and_i2c_controllers(self) -> None:
        for repl_name in (
            "nrf52840_external_nvm.repl",
            "nrf52840_mcuboot_spi_nor.repl",
        ):
            repl = (ROOT / "platforms" / repl_name).read_text(encoding="utf-8")
            self.assertIn("spi2: SPI.NRF52840_SPI @ sysbus 0x40023000", repl)
            self.assertIn("twi0: I2C.NRF52840_I2C @ sysbus 0x40003000", repl)
            self.assertIn("gpio0: GPIOPort.NRF52840_GPIO @ sysbus 0x50000500", repl)
            self.assertIn("22 -> spiNor@0", repl)
            self.assertIn("spiNor: SPI.SPINORFlash @ { spi2; sysbus 0x60000000 }", repl)
            self.assertIn("i2cEeprom: I2C.I2CEEPROM @ { twi0 0x50; sysbus 0x61000000 }", repl)
            self.assertIn("size: 0x200000", repl)
            self.assertIn("jedecCapacityId: 0x15", repl)

    def test_public_target_build_is_pinned_and_records_active_west_manifest(self) -> None:
        build_script = (
            ROOT / "targets" / "zephyr_external_nvm" / "build_public_targets.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("36940db938a8f4a1e919496793ed439850a221c2", build_script)
        self.assertIn("fb2cf0ec3da3687b93f28e556ab682bdd4b85223", build_script)
        self.assertIn('"${WEST}" init', build_script)
        self.assertIn('"${WEST}" manifest --freeze --active-only', build_script)
        self.assertIn(
            'git -C "${MCUBOOT_DIR}" fetch --depth 1 "${MCUBOOT_REPOSITORY}" "${PINNED_MCUBOOT_COMMIT}"',
            build_script,
        )
        self.assertIn("refusing unverifiable source provenance", build_script)
        self.assertNotIn('ACTUAL_ZEPHYR_COMMIT="${PINNED_ZEPHYR_COMMIT}"', build_script)

        for overlay_name in (
            "mcuboot_spi_nor/mcuboot.overlay",
            "spi_nor_nvs/app.overlay",
        ):
            overlay = (
                ROOT / "targets" / "zephyr_external_nvm" / overlay_name
            ).read_text(encoding="utf-8")
            self.assertIn("jedec-id = [ef 40 15]", overlay)
            self.assertIn("size = <0x1000000>", overlay)

    def test_robot_suites_and_ci_include_new_peripherals(self) -> None:
        for robot_name in (
            "ota_fault_point.robot",
            "erase_fault_points.robot",
            "write_trace_widths.robot",
            "generic_fault_point.robot",
            "audit.robot",
            "external_nvm_peripherals.robot",
        ):
            text = (ROOT / "tests" / robot_name).read_text(encoding="utf-8")
            self.assertIn("SPINORFlash.cs", text, robot_name)
            self.assertIn("I2CEEPROM.cs", text, robot_name)

        ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("tests/external_nvm_peripherals.robot", ci_text)


class TestExternalNvmProfileLoaderAndStateSearch(unittest.TestCase):
    def test_profile_loader_accepts_external_nvm_backends_and_torn_word(self) -> None:
        for backend_name in ("spiNor", "i2cEeprom"):
            self.assertFalse(
                _is_mram_backend(
                    "platforms/nrf52840_external_nvm.repl",
                    backend_name,
                )
            )
            fs = FaultSweepConfig(
                torn_word="partial_bits",
                torn_word_explicit=True,
                torn_word_seed=7,
                fault_types=["power_loss"],
            )
            _validate_torn_word_backend(
                fs,
                "platforms/nrf52840_external_nvm.repl",
                backend_name,
            )

    def test_external_nvm_profiles_load_with_pinned_target_source_provenance(self) -> None:
        expected_profiles = {
            "mcuboot_zephyr_spi_nor_upgrade.yaml": (
                "spiNor",
                "mcuboot",
                "fb2cf0ec3da3687b93f28e556ab682bdd4b85223",
            ),
            "mcuboot_zephyr_spi_nor_state_search.yaml": (
                "spiNor",
                "mcuboot",
                "fb2cf0ec3da3687b93f28e556ab682bdd4b85223",
            ),
            "zephyr_spi_nor_nvs_sweep.yaml": (
                "spiNor",
                "zephyr",
                "36940db938a8f4a1e919496793ed439850a221c2",
            ),
            "zephyr_i2c_eeprom_storage_sweep.yaml": (
                "i2cEeprom",
                "zephyr",
                "36940db938a8f4a1e919496793ed439850a221c2",
            ),
        }
        for filename, (backend, source_name, revision) in expected_profiles.items():
            with self.subTest(profile=filename):
                cfg = load_profile(ROOT / "profiles" / filename)
                self.assertEqual(cfg.flash_backend, backend)
                self.assertIsNotNone(cfg.target_source)
                self.assertEqual(cfg.target_source.name, source_name)
                self.assertEqual(cfg.target_source.revision, revision)

                if filename.startswith("mcuboot_"):
                    self.assertEqual(cfg.memory.slots["staging"].compiled_offset, 0)
                    geometry = validate_compiled_flash_map(cfg, ROOT)
                    self.assertEqual(geometry["status"], "match", geometry)

    def test_spi_nor_page_program_and_erase_fault_outcomes_in_recovery_state(self) -> None:
        # Simulate a 4 KiB SPI NOR sector erase (0x20) followed by a 16-byte
        # Page Program (0x02) split into four 4-byte chunks at 0x1000..0x100C.
        initial_bytes = bytearray(b"\xAA" * 4096 + b"\xFF" * 4096)
        initial_state = PersistentState.from_bytes(
            bytes(initial_bytes),
            name="nvm",
            base_address=0x60000000,
        )
        erase_trace = [
            {
                "erase_index": 1,
                "offset": 0,
                "writes_at_this_point": 0,
                "erase_size": 4096,
            }
        ]
        write_trace = [
            {"write_index": 1, "offset": 0x0000, "value": 0x11223344, "width": 4},
            {"write_index": 2, "offset": 0x0004, "value": 0x55667788, "width": 4},
            {"write_index": 3, "offset": 0x0008, "value": 0x99AABBCC, "width": 4},
            {"write_index": 4, "offset": 0x000C, "value": 0xDDEEFF00, "width": 4},
        ]
        ops = merge_operation_traces(write_trace, erase_trace)
        self.assertEqual(len(ops), 5)
        self.assertEqual(ops[0]["kind"], "erase")

        # 1. Erase cut outcomes: untouched, half/fixed, partial_bits, erased.
        untouched_erase = apply_interrupted_operation(
            initial_state, ops[0], fault_type="interrupted_erase", torn_word_mode="untouched"
        )
        self.assertEqual(untouched_erase.read("nvm", 0, 4), b"\xAA\xAA\xAA\xAA")

        half_erase = apply_interrupted_operation(
            initial_state, ops[0], fault_type="interrupted_erase", torn_word_mode="half"
        )
        self.assertEqual(half_erase.read("nvm", 0, 4), b"\xFF\xFF\xFF\xFF")
        self.assertEqual(half_erase.read("nvm", 2048, 4), b"\xAA\xAA\xAA\xAA")

        partial_erase = apply_interrupted_operation(
            initial_state,
            ops[0],
            fault_type="interrupted_erase",
            torn_word_mode="partial_bits",
            corruption_seed=42,
        )
        partial_erase_word = partial_erase.read("nvm", 0, 4)
        self.assertNotEqual(partial_erase_word, b"\xAA\xAA\xAA\xAA")
        self.assertNotEqual(partial_erase_word, b"\xFF\xFF\xFF\xFF")

        # 2. Page Program cut outcomes after sector erase completes:
        after_erase = apply_completed_operation(initial_state, ops[0])
        computer = RecoveryStateComputer(
            after_erase,
            ops[1:],
            fault_type="power_loss",
            backend_kind="flash",
            torn_word_mode="fixed",
        )
        cut_states = list(computer.iter_cut_states())
        self.assertEqual(len(cut_states), 4)

        # Cut at chunk 0 (before page program commits any bytes) -> all 16 bytes remain 0xFF.
        self.assertEqual(cut_states[0][1].read("nvm", 0, 16), b"\xFF" * 16)
        # Cut at chunk 2 (mid-page program) -> first 8 bytes programmed, last 8 bytes remain 0xFF.
        self.assertEqual(
            cut_states[2][1].read("nvm", 0, 16),
            b"\x44\x33\x22\x11\x88\x77\x66\x55" + (b"\xFF" * 8),
        )

    def test_state_search_explorer_deduplicates_external_nvm_cut_states(self) -> None:
        initial_state = PersistentState.from_bytes(
            b"\xFF" * 4096,
            name="nvm",
            base_address=0x00100000,
        )
        calibration_ops = merge_operation_traces(
            [
                {"write_index": 1, "offset": 0, "value": 0x11223344, "width": 4},
                {"write_index": 2, "offset": 4, "value": 0x55667788, "width": 4},
            ],
            [],
        )
        selected, _ = select_first_cut_operations(
            calibration_ops, {"mode": "all", "fault_types": ["power_loss"]}
        )

        booted_identities = []

        def fake_boot_state(state, chain, generation):
            booted_identities.append(state.identity_hex())
            recovery_ops = merge_operation_traces(
                [
                    {"write_index": 1, "offset": 0, "value": 0x11223344, "width": 4},
                    {"write_index": 2, "offset": 4, "value": 0x55667788, "width": 4},
                ],
                [],
            )
            return (
                {
                    "fault_at": 0,
                    "fault_type": "rs",
                    "fault_injected": True,
                    "boot_outcome": "boot_ok",
                    "boot_slot": "exec",
                    "fault_class": "clean_recovery",
                    "signals": {},
                },
                recovery_ops,
                state,
            )

        explorer = RecoveryStateExplorer(
            initial_state,
            calibration_ops,
            first_cuts=selected,
            max_cuts=2,
            max_new_states=20,
            max_wall_time_s=60.0,
            clock=lambda: 0.0,
            boot_state=fake_boot_state,
            flash_base=0x00100000,
            address_ranges=({"start": 0x00100000, "end": 0x00101000},),
            backend_kind="fast",
            torn_word_mode="fixed",
        )
        results, summary = explorer.run()
        self.assertEqual(summary["stopped_reason"], "complete")
        self.assertEqual(summary["states_booted"], 2)
        self.assertGreaterEqual(summary["states_reused"], 1)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
