# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tardigrade export-repro / scripts/export_repro.py."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import zlib

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import export_repro  # noqa: E402
from export_repro import (  # noqa: E402
    ExportReproError,
    classify_target_license,
    export_reproducer,
    resolve_export_target,
    resolve_platform_and_peripherals,
    verify_exported_state_against_emulator,
)
from recovery_checkpoint import SnapshotWriter  # noqa: E402
from recovery_state import PersistentState  # noqa: E402


PR3011_PROFILE = ROOT / "profiles/mcuboot_pr3011_move_broken.yaml"
MRAM_STATE_SEARCH_PROFILE = (
    ROOT / "examples/phase2_mram_parity/profile_deferred_state_search_16_uncorrectable.yaml"
)
ZEPHYR_NVS_PROFILE = ROOT / "profiles/zephyr_spi_nor_nvs_broken.yaml"
WOLFBOOT_PROFILE = ROOT / "profiles/wolfboot_stm32f4_power_loss_erase.yaml"
ERASE_BEFORE_PROGRAM_PROFILE = ROOT / "examples/erase_before_program/profile.yaml"


def _make_pr3011_report_with_explanation(
    tmp_path: Path,
    *,
    renode_version: str = "1.17.0",
) -> Path:
    report = {
        "profile": "mcuboot_pr3011_move_broken",
        "profile_path": str(PR3011_PROFILE),
        "verdict": "FAIL",
        "renode_version": f"Renode v{renode_version}",
        "target_source": {
            "name": "MCUboot swap-move status recovery without trailer swap_size",
            "repository": "https://github.com/mcu-tools/mcuboot",
            "revision": "238fb14f6fffa1ab8e8cf0fb1e9be69ff3ee5513",
        },
        "control_result": {
            "is_control": True,
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "recoverable",
            "actual_writes": 389,
            "signals": {"total_ms": 100},
        },
        "runtime_sweep_results": [
            {
                "fault_at": 3,
                "fault_requested": 3,
                "fault_type": "p2",
                "fault_injected": True,
                "fault_address": "0x00033FF0",
                "boot_outcome": "wrong_image",
                "boot_slot": "exec",
                "fault_class": "wrong_image",
                "actual_writes": 389,
                "signals": {
                    "vtor": "0x0000C200",
                    "marker_ok": True,
                    "matched_image": "exec",
                    "image_hash_match": "exec_image",
                },
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 0,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": True,
                    "p1_fault_address": "0x00033FE8",
                    "p2_fault_address": "0x00033FF0",
                },
                "failure_explanation": {
                    "point": "power_loss[3] -> power_loss[0]",
                    "fault_class": "wrong_image",
                    "boot_outcome": "wrong_image",
                    "boot_slot": "exec",
                    "message": (
                        "power_loss[3] -> power_loss[0] yielded wrong_image (boot_slot=exec); "
                        "clean control reached success (boot_slot=exec)."
                    ),
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 3,
                            "fault_type": "power_loss",
                            "address": "0x00033FE8",
                        },
                        {
                            "cut": 2,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x00033FF0",
                        },
                    ],
                },
            },
            {
                "fault_at": 99,
                "fault_requested": 99,
                "fault_type": "p2",
                "fault_injected": False,
                "skip_reason": "phase2_no_write_at_index",
                "boot_outcome": "skipped",
                "boot_slot": None,
                "fault_class": "skipped",
                "actual_writes": 4,
                "signals": {},
                "phase2_fault": {
                    "p1_fault_at": 99,
                    "p2_fault_at": 50,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": False,
                },
            },
            {
                "fault_at": 7,
                "fault_requested": 7,
                "fault_type": "w",
                "fault_injected": False,
                "infrastructure_error": True,
                "error_kind": "runfor_watchdog",
                "error": "RunFor watchdog expired",
                "boot_outcome": "infra_error",
                "boot_slot": None,
                "fault_class": "infrastructure_error",
                "actual_writes": 0,
                "signals": {},
            },
            {
                "fault_at": 8,
                "fault_requested": 8,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "timeout",
                "boot_slot": None,
                "fault_class": "incomplete",
                "actual_writes": 8,
                "signals": {"phase2_stop_reason": "wall_timeout(60s)"},
            },
        ],
    }
    path = tmp_path / "pr3011_report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _make_mram_report_with_snapshot(tmp_path: Path) -> tuple[Path, str, bytes]:
    mram_bytes = bytearray(0x4000)
    mram_bytes[0x0100:0x0108] = b"1LAVTGRT"
    mram_bytes[0x0108:0x0110] = b"DLO1TGRT"
    mram_bytes[0x0110:0x0118] = b"\x00" * 8
    mram_bytes[0x0118:0x0120] = b"ENODGORP"
    state_obj = PersistentState.from_bytes(
        mram_bytes,
        name="nvm",
        base_address=0x10100000,
        uncorrectable_words=(("nvm", 0x0108), ("nvm", 0x0110)),
    )
    state_id = state_obj.identity_hex().lower()
    compressed_b64 = base64.b64encode(zlib.compress(bytes(mram_bytes), level=1)).decode("ascii")
    report = {
        "profile": "phase2_mram_deferred_state_search_16_uncorrectable",
        "profile_path": str(MRAM_STATE_SEARCH_PROFILE),
        "verdict": "FAIL",
        "renode_version": "Renode v1.17.0.40905",
        "control_result": {
            "is_control": True,
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "recoverable",
            "actual_writes": 8,
            "signals": {"total_ms": 25},
        },
        "runtime_sweep_results": [
            {
                "fault_at": 2,
                "fault_requested": 2,
                "fault_type": "rs",
                "fault_injected": True,
                "fault_address": "0x10100100",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "actual_writes": 1,
                "mram_torn_word": "uncorrectable_read",
                "signals": {"total_ms": 40},
                "_pre_recovery_state": {
                    "base_address": "0x10100000",
                    "size": len(mram_bytes),
                    "zlib_b64": compressed_b64,
                    "uncorrectable_words": ["0x10100108", "0x10100110"],
                },
                "recovery_state_search": {
                    "generation": 2,
                    "state_identity": state_id,
                    "reused": False,
                    "cut_count": 2,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 2,
                            "fault_type": "power_loss",
                            "address": "0x10100110",
                            "offset": 0x0110,
                            "size": 16,
                        },
                        {
                            "cut": 2,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                            "offset": 0x0100,
                            "size": 16,
                        },
                    ],
                    "chain": {
                        "cut_count": 2,
                        "text": "write[2]@0x10100110 -> write[0]@0x10100100",
                    },
                },
                "failure_explanation": {
                    "point": "write[2]@0x10100110 -> write[0]@0x10100100",
                    "fault_class": "unrecoverable",
                    "boot_outcome": "no_boot",
                    "boot_slot": None,
                    "state_identity": state_id,
                    "message": (
                        "write[2]@0x10100110 -> write[0]@0x10100100 yielded no_boot; "
                        "clean control reached success (boot_slot=exec)."
                    ),
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 2,
                            "fault_type": "power_loss",
                            "address": "0x10100110",
                        },
                        {
                            "cut": 2,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                        },
                    ],
                    "state_comparison": {
                        "status": "compared",
                        "ranges": [
                            {
                                "address": "0x10100100",
                                "size": 16,
                                "failing_hex": bytes(mram_bytes[0x0100:0x0110]).hex(),
                                "passing_hex": "11" * 16,
                            }
                        ],
                        "uncorrectable_only_in_failing": ["0x10100108", "0x10100110"],
                    },
                },
            }
        ],
    }
    path = tmp_path / "mram_report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path, state_id, bytes(mram_bytes)


def test_resolve_platform_and_peripherals_bundles_only_needed_sources(tmp_path):
    # 1. MCUboot PR 3011 fast internal flash platform -> only NRF52NVMC/UARTE/TraceReplayEngine + base files
    pr3011_report = _make_pr3011_report_with_explanation(tmp_path)
    t_pr3011 = resolve_export_target(report=pr3011_report, point="3,0", repo_root=ROOT)
    repls, periphs = resolve_platform_and_peripherals(t_pr3011, ROOT)
    assert [p.name for p in repls] == ["cortex_m4_flash_fast.repl"]
    assert [p.name for p in periphs] == [
        "ITardigradeFaultInjectable.cs",
        "NVMemoryController.cs",
        "FaultTracker.cs",
        "NRF52NVMC.cs",
        "NRF52UARTE.cs",
        "TraceReplayEngine.cs",
    ]

    # 2. MRAM 16b tracked platform -> only MappedMRAMTracker.cs + its base files
    mram_report, state_id, _ = _make_mram_report_with_snapshot(tmp_path)
    t_mram = resolve_export_target(report=mram_report, state=state_id[:12], repo_root=ROOT)
    repls_mram, periphs_mram = resolve_platform_and_peripherals(t_mram, ROOT)
    assert [p.name for p in repls_mram] == ["cortex_m0_mram_tracked_16.repl"]
    assert [p.name for p in periphs_mram] == [
        "ITardigradeFaultInjectable.cs",
        "NVMemoryController.cs",
        "FaultTracker.cs",
        "MappedMRAMTracker.cs",
    ]

    # 3. Zephyr SPI NOR external NVM platform -> SPINORFlash.cs + dependencies
    t_spinor = resolve_export_target(
        reproduction=json.dumps({"FAULT_POINTS_CSV": "11", "FAULT_TYPE_CSV": "w"}),
        profile=ZEPHYR_NVS_PROFILE,
        repo_root=ROOT,
    )
    repls_spinor, periphs_spinor = resolve_platform_and_peripherals(t_spinor, ROOT)
    assert [p.name for p in repls_spinor] == ["nrf52840_external_nvm.repl"]
    assert "SPINORFlash.cs" in [p.name for p in periphs_spinor]
    assert "STM32F4FlashController.cs" not in [p.name for p in periphs_spinor]


def test_export_directory_and_archive_layout_for_mram_state_search(tmp_path):
    report_path, state_id, mram_bytes = _make_mram_report_with_snapshot(tmp_path)
    out_dir = tmp_path / "mram_bundle"

    exported_path = export_reproducer(
        report=report_path,
        state=state_id[:12],
        output=out_dir,
        repo_root=ROOT,
    )
    assert exported_path == out_dir.resolve()

    # Verify required bundle layout
    assert (out_dir / "README.md").is_file()
    assert (out_dir / "run.sh").is_file()
    assert (out_dir / "Dockerfile").is_file()
    assert (out_dir / "reproduce.resc").is_file()
    assert (out_dir / "reproduce_recovery.py").is_file()
    assert (out_dir / "platforms/cortex_m0_mram_tracked_16.repl").is_file()
    assert [p.name for p in sorted((out_dir / "peripherals").iterdir())] == [
        "FaultTracker.cs",
        "ITardigradeFaultInjectable.cs",
        "MappedMRAMTracker.cs",
        "NVMemoryController.cs",
    ]
    assert (out_dir / "firmware/firmware_deferred.elf").is_file()
    assert (out_dir / "state/persistent_state.bin").is_file()
    assert (out_dir / "state/persistent_state.json").is_file()

    # Check reconstructed persistent state binary and marks
    assert (out_dir / "state/persistent_state.bin").read_bytes() == mram_bytes
    state_meta = json.loads((out_dir / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert state_meta["report_outcome"] == "no_boot"
    assert state_meta["expected_outcome"] == "success"
    assert state_meta["renode_version"] == "1.17.0"
    ps = state_meta["persistent_state"]
    assert ps["backend_kind"] == "mram"
    assert ps["state_identity"] == state_id
    assert ps["uncorrectable_offsets"] == [0x0108, 0x0110]
    assert ps["uncorrectable_words"] == ["0x10100108", "0x10100110"]

    # Check README contents: explanation, cut chain, commit, and exact Renode version
    readme_text = (out_dir / "README.md").read_text(encoding="utf-8")
    assert "write[2]@0x10100110 -> write[0]@0x10100100" in readme_text
    assert "`no_boot`" in readme_text
    assert "`success`" in readme_text
    assert "`1.17.0`" in readme_text
    assert state_id in readme_text
    assert "yielded no_boot; clean control reached success" in readme_text

    # Also test exporting directly as a .tar.gz archive
    archive_out = tmp_path / "mram_repro.tar.gz"
    arc_path = export_reproducer(
        report=report_path,
        point=state_id[:12],
        output=archive_out,
        repo_root=ROOT,
    )
    assert arc_path == archive_out.resolve()
    assert archive_out.is_file()
    with tarfile.open(archive_out, "r:gz") as tf:
        members = set(tf.getnames())
    assert "mram_repro/README.md" in members
    assert "mram_repro/run.sh" in members
    assert "mram_repro/reproduce.resc" in members
    assert "mram_repro/reproduce_recovery.py" in members
    assert "mram_repro/state/persistent_state.bin" in members
    assert "mram_repro/state/persistent_state.json" in members
    assert "mram_repro/platforms/cortex_m0_mram_tracked_16.repl" in members
    assert "mram_repro/peripherals/MappedMRAMTracker.cs" in members


def test_export_reconstructs_state_via_renode_and_verifies_explanation(tmp_path):
    report_path = _make_pr3011_report_with_explanation(tmp_path, renode_version="1.16.1")
    fake_runner = tmp_path / "fake-renode-test"
    fake_runner.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "vars_map = {}\n"
        "args = sys.argv[1:]\n"
        "for i, arg in enumerate(args):\n"
        "    if arg == '--variable' and i + 1 < len(args) and ':' in args[i + 1]:\n"
        "        k, v = args[i + 1].split(':', 1)\n"
        "        vars_map[k] = v\n"
        "expected = json.loads(pathlib.Path(vars_map['DEBUG_EXPECTED_STATE_FILE']).read_text())\n"
        "export_path = pathlib.Path(expected['export_state_file'])\n"
        "flash_bytes = bytearray(b'\\xff' * 0x100000)\n"
        "flash_bytes[0x33FE8:0x33FF0] = b'SWAPSTAT'\n"
        "flash_bytes[0x33FF0:0x33FF8] = b'\\xff' * 8\n"
        "bin_path = pathlib.Path(str(export_path) + '.bin')\n"
        "bin_path.write_bytes(bytes(flash_bytes))\n"
        "export_path.write_text(json.dumps({\n"
        "    'backend_kind': 'fast',\n"
        "    'flash_backend': 'faultFlash',\n"
        "    'base_address': '0x00000000',\n"
        "    'size': len(flash_bytes),\n"
        "    'binary_file': str(bin_path),\n"
        "    'uncorrectable_offsets': [],\n"
        "    'uncorrectable_words': [],\n"
        "    'persistent_values': {},\n"
        "}))\n"
        "pathlib.Path(vars_map['RESULT_FILE']).write_text(json.dumps({\n"
        "    'fault_at': 3,\n"
        "    'fault_requested': 3,\n"
        "    'fault_type': 'p2',\n"
        "    'fault_injected': True,\n"
        "    'boot_outcome': 'wrong_image',\n"
        "    'boot_slot': 'exec',\n"
        "    'fault_class': 'wrong_image',\n"
        "    'phase2_fault': {'p1_injected': True, 'p2_injected': True},\n"
        "    'debug_session': {'stop_at': 'recovery-reset', 'verified_checks': ['cut_replay']},\n"
        "}))\n",
        encoding="utf-8",
    )
    fake_runner.chmod(0o755)

    out_dir = tmp_path / "pr3011_bundle"
    export_reproducer(
        report=report_path,
        point="3,0",
        output=out_dir,
        renode_test=str(fake_runner),
        repo_root=ROOT,
    )
    state_meta = json.loads((out_dir / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert state_meta["report_outcome"] == "wrong_image"
    assert state_meta["expected_outcome"] == "success"
    assert state_meta["renode_version"] == "1.16.1"
    assert state_meta["upstream_commit"] == "238fb14f6fffa1ab8e8cf0fb1e9be69ff3ee5513"
    assert (out_dir / "platforms/cortex_m4_flash_fast.repl").is_file()
    assert [p.name for p in sorted((out_dir / "peripherals").iterdir())] == [
        "FaultTracker.cs",
        "ITardigradeFaultInjectable.cs",
        "NRF52NVMC.cs",
        "NRF52UARTE.cs",
        "NVMemoryController.cs",
        "TraceReplayEngine.cs",
    ]
    assert (out_dir / "firmware/oss_mcuboot_pr3011_move_broken.elf").is_file()
    assert (out_dir / "state/persistent_state.bin").read_bytes()[0x33FE8:0x33FF0] == b"SWAPSTAT"
    readme = (out_dir / "README.md").read_text(encoding="utf-8")
    assert "238fb14f6fffa1ab8e8cf0fb1e9be69ff3ee5513" in readme
    assert "1.16.1" in readme
    assert "power_loss[3] -> power_loss[0]" in readme


def test_export_recovers_state_from_checkpoint_file(tmp_path):
    mram_bytes = bytearray([0xA5]) * 0x4000
    state_obj = PersistentState.from_bytes(
        mram_bytes,
        name="nvm",
        base_address=0x10100000,
        uncorrectable_words=(("nvm", 0x0100),),
    )
    state_id = state_obj.identity_hex().lower()
    writer = SnapshotWriter()
    writer.reference(state_obj)
    ckpt_path = tmp_path / "mram_ckpt.checkpoint.json"
    ckpt_payload = {
        "version": 1,
        "final": False,
        "profile": "phase2_mram_deferred_state_search_16_uncorrectable",
        "profile_path": str(MRAM_STATE_SEARCH_PROFILE),
        "chunks": writer.chunks,
        "snapshots": writer.states,
        "runtime_sweep_results": [
            {
                "fault_at": 0,
                "fault_requested": 0,
                "fault_type": "rs",
                "fault_injected": True,
                "fault_address": "0x10100100",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "recovery_state_search": {
                    "generation": 1,
                    "state_identity": state_id,
                    "cut_count": 1,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                        }
                    ],
                    "chain": {"cut_count": 1, "text": "write[0]@0x10100100"},
                },
            }
        ],
    }
    ckpt_path.write_text(json.dumps(ckpt_payload), encoding="utf-8")

    out_dir = tmp_path / "ckpt_bundle"
    export_reproducer(
        report=ckpt_path,
        state=state_id[:12],
        output=out_dir,
        repo_root=ROOT,
    )
    state_meta = json.loads((out_dir / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert state_meta["persistent_state"]["state_identity"] == state_id
    assert (out_dir / "state/persistent_state.bin").read_bytes() == bytes(mram_bytes)


def test_license_filtering_omits_gpl_binaries_and_generates_fetch_script(tmp_path):
    # Build a synthetic wolfBoot report with an embedded flash state containing non-0xFF code bytes
    flash_bytes = bytearray(b"\xff" * 0x100000)
    # Put non-0xFF bytes in bootloader sector 0 (0x0..0x4000) and app slots (0x20000..0x9F000)
    flash_bytes[0x0000:0x0100] = b"GPL_BOOTLOADER_BYTES" * 12 + b"1234567890123456"
    flash_bytes[0x20100:0x20120] = b"GPL_APP_IMAGE_BYTES_HERE_1234567"
    # Put swap/trailer metadata near end of exec slot (0x7FFF0, in the last page of the 0x20000..0x80000 slot)
    flash_bytes[0x7FFF0:0x80000] = b"TRAILER_METADATA"
    compressed_b64 = base64.b64encode(zlib.compress(bytes(flash_bytes), level=1)).decode("ascii")

    wolf_report = {
        "profile": "wolfboot_stm32f4_power_loss_erase",
        "profile_path": str(WOLFBOOT_PROFILE),
        "verdict": "FAIL",
        "target_source": {
            "name": "wolfboot",
            "repository": "https://github.com/wolfSSL/wolfBoot.git",
            "revision": "ad8dc62131fc0067a3ab25edc1b7e731397712d4",
        },
        "runtime_sweep_results": [
            {
                "fault_at": 1,
                "fault_requested": 1,
                "fault_type": "e",
                "fault_injected": True,
                "fault_address": "0x0807FFF0",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "_pre_recovery_state": {
                    "base_address": "0x08000000",
                    "size": len(flash_bytes),
                    "zlib_b64": compressed_b64,
                    "uncorrectable_words": [],
                },
            }
        ],
    }
    report_path = tmp_path / "wolfboot_report.json"
    report_path.write_text(json.dumps(wolf_report), encoding="utf-8")

    target = resolve_export_target(report=report_path, point="e[1]", repo_root=ROOT)
    decision = classify_target_license(target, wolf_report, {}, ROOT)
    assert decision.redistributable is False
    assert "GPL" in decision.license_spdx
    assert decision.fetch_and_build_script is not None

    out_dir = tmp_path / "wolfboot_bundle"
    export_reproducer(
        report=report_path,
        point="e[1]",
        output=out_dir,
        repo_root=ROOT,
    )

    # Ensure NO .elf or .bin files were written to firmware/
    fw_files = list((out_dir / "firmware").iterdir())
    assert all(f.suffix not in {".elf", ".bin"} for f in fw_files), fw_files
    assert (out_dir / "fetch_and_build.sh").is_file()
    fetch_text = (out_dir / "fetch_and_build.sh").read_text(encoding="utf-8")
    assert "https://github.com/wolfSSL/wolfBoot.git" in fetch_text
    assert "ad8dc62131fc0067a3ab25edc1b7e731397712d4" in fetch_text

    # Verify code bytes in persistent_state.bin were scrubbed to 0xFF while trailer metadata remained
    exported_state = (out_dir / "state/persistent_state.bin").read_bytes()
    assert exported_state[0x0000:0x0100] == b"\xff" * 0x100
    assert exported_state[0x20100:0x20120] == b"\xff" * 0x20
    assert exported_state[0x7FFF0:0x80000] == b"TRAILER_METADATA"
    meta = json.loads((out_dir / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert meta["license"]["redistributable"] is False
    assert len(meta["persistent_state"]["scrubbed_code_regions"]) >= 2


def test_license_filtering_refuses_prohibited_license_without_pinned_upstream(tmp_path):
    base_profile = yaml.safe_load(ERASE_BEFORE_PROGRAM_PROFILE.read_text(encoding="utf-8"))
    base_profile["license"] = "GPL-3.0-only"
    base_profile["platform"] = str((ROOT / base_profile["platform"]).resolve())
    base_profile["bootloader"]["elf"] = str((ROOT / base_profile["bootloader"]["elf"]).resolve())
    for k, rel in list((base_profile.get("images") or {}).items()):
        base_profile["images"][k] = str((ROOT / rel).resolve())
    gpl_profile_path = tmp_path / "unpinned_gpl_profile.yaml"
    gpl_profile_path.write_text(yaml.safe_dump(base_profile), encoding="utf-8")

    report = {
        "profile": "unpinned_gpl",
        "profile_path": str(gpl_profile_path),
        "verdict": "FAIL",
        "runtime_sweep_results": [
            {
                "fault_at": 0,
                "fault_requested": 0,
                "fault_type": "w",
                "fault_injected": True,
                "fault_address": "0x10008000",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
            }
        ],
    }
    report_path = tmp_path / "unpinned_gpl_report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ExportReproError, match="forbids redistribution and no pinned upstream source"):
        export_reproducer(
            report=report_path,
            point="0",
            output=tmp_path / "should_fail",
            repo_root=ROOT,
        )


def test_refusals_for_unreconstructible_points(tmp_path):
    report_path = _make_pr3011_report_with_explanation(tmp_path)

    # 1. Clean control point
    with pytest.raises(ExportReproError, match="cannot export clean control point"):
        export_reproducer(
            report=report_path,
            point="control",
            output=tmp_path / "out_ctrl",
            repo_root=ROOT,
        )

    # 2. Skipped point
    with pytest.raises(ExportReproError, match="skipped in report"):
        export_reproducer(
            report=report_path,
            point="99,50",
            output=tmp_path / "out_skip",
            repo_root=ROOT,
        )

    # 3. Infrastructure error point
    with pytest.raises(ExportReproError, match="infrastructure error"):
        export_reproducer(
            report=report_path,
            point="7",
            output=tmp_path / "out_infra",
            repo_root=ROOT,
        )

    # 4. Initial boot timeout point
    with pytest.raises(ExportReproError, match="initial boot timed out"):
        export_reproducer(
            report=report_path,
            point="8",
            output=tmp_path / "out_timeout",
            repo_root=ROOT,
        )

    # 5. Unknown point selector
    with pytest.raises(ExportReproError, match="did not match any point"):
        export_reproducer(
            report=report_path,
            point="999,999",
            output=tmp_path / "out_unknown",
            repo_root=ROOT,
        )

    # 6. Single-boot non-reset fault (e.g. brownout 'b') has no recovery reset state
    with pytest.raises(ExportReproError, match="continues in the initial boot without a recovery reset"):
        export_reproducer(
            reproduction=json.dumps({"FAULT_POINTS_CSV": "2", "FAULT_TYPE_CSV": "b"}),
            profile=ERASE_BEFORE_PROGRAM_PROFILE,
            output=tmp_path / "out_brownout",
            repo_root=ROOT,
        )

    # 7. State-mode evaluation profile
    state_mode_profile = yaml.safe_load(ERASE_BEFORE_PROGRAM_PROFILE.read_text(encoding="utf-8"))
    state_mode_profile["platform"] = str((ROOT / state_mode_profile["platform"]).resolve())
    state_mode_profile["bootloader"]["elf"] = str((ROOT / state_mode_profile["bootloader"]["elf"]).resolve())
    for k, rel in list((state_mode_profile.get("images") or {}).items()):
        state_mode_profile["images"][k] = str((ROOT / rel).resolve())
    state_mode_profile.setdefault("fault_sweep", {})["evaluation_mode"] = "state"
    sm_profile_path = tmp_path / "state_mode.yaml"
    sm_profile_path.write_text(yaml.safe_dump(state_mode_profile), encoding="utf-8")
    sm_report = {
        "profile": "state_mode",
        "profile_path": str(sm_profile_path),
        "verdict": "FAIL",
        "runtime_sweep_results": [
            {
                "fault_at": 0,
                "fault_requested": 0,
                "fault_type": "w",
                "fault_injected": True,
                "boot_outcome": "no_boot",
            }
        ],
    }
    sm_report_path = tmp_path / "sm_report.json"
    sm_report_path.write_text(json.dumps(sm_report), encoding="utf-8")
    with pytest.raises(ExportReproError, match="evaluation_mode 'state'"):
        export_reproducer(
            report=sm_report_path,
            point="0",
            output=tmp_path / "out_sm",
            repo_root=ROOT,
        )

    # 8. State mismatch refusal when embedded state disagrees with failure_explanation
    bad_mram_report_path, state_id, _ = _make_mram_report_with_snapshot(tmp_path)
    bad_data = json.loads(bad_mram_report_path.read_text(encoding="utf-8"))
    bad_data["runtime_sweep_results"][0]["failure_explanation"]["state_comparison"]["ranges"][0][
        "failing_hex"
    ] = "deadbeef" * 4
    bad_mram_report_path.write_text(json.dumps(bad_data), encoding="utf-8")
    with pytest.raises(ExportReproError, match="rebuilt bytes at 0x10100100"):
        export_reproducer(
            report=bad_mram_report_path,
            state=state_id[:12],
            output=tmp_path / "out_bad_mram",
            repo_root=ROOT,
        )

    # 9. Final checkpoint without snapshot
    final_ckpt = tmp_path / "final.checkpoint.json"
    final_ckpt.write_text(json.dumps({"version": 1, "final": True}), encoding="utf-8")
    with pytest.raises(ExportReproError, match="checkpoint .* is final"):
        export_reproducer(
            report=final_ckpt,
            state="601330377439",
            output=tmp_path / "out_final",
            repo_root=ROOT,
        )

    # 10. Auxiliary non-runtime campaigns
    aux_report = {
        "profile": "erase_before_program",
        "profile_path": str(ERASE_BEFORE_PROGRAM_PROFILE),
        "verdict": "FAIL",
        "runtime_sweep_results": [],
        "partial_staging_results": [
            {
                "classification": "wrong_image",
                "truncation_point": {"offset": 256},
                "boot_outcome": "wrong_image",
            }
        ],
        "state_fuzz_results": [
            {
                "finding": True,
                "issue_reasons": ["no_boot"],
                "scenario_index": 0,
                "mode": "corrupt",
                "crc_mode": "valid",
                "field_values": {"magic": 0},
                "blob_sha256": "abc123",
            }
        ],
        "fuzz_crash_results": [
            {
                "security_finding": True,
                "crash_file": "crash.bin",
                "sha256": "def456",
                "generated_profile": "gen.yaml",
                "verdict": "FAIL",
            }
        ],
        "authorization_review_analysis": {
            "findings": [
                {
                    "id": "auth_1",
                    "severity": "high",
                    "sequence": "stage -> install",
                    "message": "missing check",
                    "evidence": {"field": "sig", "model_digest": "789abc"},
                }
            ]
        },
    }
    aux_report_path = tmp_path / "aux_report.json"
    aux_report_path.write_text(json.dumps(aux_report), encoding="utf-8")
    for aux_selector, expected_msg in (
        ("staging prefix 256", "cannot export partial-staging truncation finding"),
        ("state fuzz scenario 0", "cannot export state-fuzz scenario finding"),
        ("gen.yaml", "cannot export fuzz-crash regression finding"),
        ("stage -> install", "cannot export static authorization-review finding"),
    ):
        with pytest.raises(ExportReproError, match=expected_msg):
            export_reproducer(
                report=aux_report_path,
                point=aux_selector,
                profile=ERASE_BEFORE_PROGRAM_PROFILE,
                output=tmp_path / "out_aux",
                repo_root=ROOT,
            )


def test_export_zephyr_spi_nor_nvs_broken_and_cli_main(tmp_path, capsys):
    nvs_report = {
        "profile": "zephyr_spi_nor_nvs_broken",
        "profile_path": str(ZEPHYR_NVS_PROFILE),
        "verdict": "FAIL",
        "renode_version": "Renode v1.17.0",
        "control_result": {
            "is_control": True,
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "recoverable",
            "actual_writes": 38,
            "signals": {"total_ms": 20},
        },
        "runtime_sweep_results": [
            {
                "fault_at": 11,
                "fault_requested": 11,
                "fault_type": "w",
                "fault_injected": True,
                "fault_address": "0x60000FD8",
                "boot_outcome": "wrong_image",
                "boot_slot": "exec",
                "fault_class": "wrong_image",
                "actual_writes": 12,
                "signals": {"vtor": "0x00000000", "marker_ok": False},
                "failure_explanation": {
                    "point": "power_loss[11]",
                    "fault_class": "wrong_image",
                    "boot_outcome": "wrong_image",
                    "boot_slot": "exec",
                    "message": (
                        "power_loss[11] yielded wrong_image (boot_slot=exec); "
                        "clean control reached success (boot_slot=exec)."
                    ),
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 11,
                            "fault_type": "power_loss",
                            "address": "0x60000FD8",
                        }
                    ],
                },
            }
        ],
    }
    report_path = tmp_path / "zephyr_nvs_report.json"
    report_path.write_text(json.dumps(nvs_report), encoding="utf-8")

    out_dir = tmp_path / "nvs_bundle"
    rc = export_repro.main(
        [str(report_path), "w[11]", str(out_dir)],
        prog="tardigrade export-repro",
    )
    assert rc == 0
    assert str(out_dir.resolve()) in capsys.readouterr().out
    assert (out_dir / "firmware/zephyr_spi_nor_nvs_broken.elf").is_file()
    assert (out_dir / "fetch_and_build.sh").is_file()
    assert (out_dir / "platforms/nrf52840_external_nvm.repl").is_file()
    assert (out_dir / "peripherals/SPINORFlash.cs").is_file()
    readme = (out_dir / "README.md").read_text(encoding="utf-8")
    assert "1c128d59b5e1561dafdc1c7b246b8eb1d9857a97" in readme
    assert "power_loss[11]" in readme
    assert "wrong_image" in readme


def test_export_state_matches_emulator_in_all_specified_bytes_and_rejects_diff(tmp_path):
    # 1. MRAM state-search export without embedded _pre_recovery_state:
    # Offline reconstruction must include the Robot suite default staging image
    # (examples/vulnerable_ota/firmware.bin at 0x10102000) and match the emulator capture
    # across all 16,384 bytes (SHA-256 254cdf8b..., state_identity 601330377439...).
    emu_mram = bytearray(0x4000)
    slot_bin = (ROOT / "examples/phase2_mram_parity/slot.bin").read_bytes()
    vuln_bin = (ROOT / "examples/vulnerable_ota/firmware.bin").read_bytes()
    emu_mram[0 : len(slot_bin)] = slot_bin
    emu_mram[0x2000 : 0x2000 + len(vuln_bin)] = vuln_bin
    emu_mram[0x0100:0x0110] = bytes.fromhex("314c415654475254314c415654475254")
    emu_mram[0x0118:0x0120] = bytes.fromhex("4f4c443154415445")
    emu_mram[0x0138:0x0140] = bytes.fromhex("3145544147455250")
    emu_mram_bytes = bytes(emu_mram)
    emu_mram_sha = hashlib.sha256(emu_mram_bytes).hexdigest().lower()
    assert emu_mram_sha == "254cdf8b0e9094bb0cb741ca34c317af008afe7a19ab4e2e8ba15e642a8d99d4"
    emu_mram_id = (
        PersistentState.from_bytes(
            emu_mram_bytes,
            name="nvm",
            base_address=0x10100000,
            uncorrectable_words=(("nvm", 0x0100), ("nvm", 0x0110)),
        )
        .identity_hex()
        .lower()
    )
    assert emu_mram_id == "601330377439036885f5929df921e7c6de4d7f4a9e990de02ec0b58ccbf7d0fd"

    mram_offline_report = {
        "profile": "phase2_mram_deferred_state_search_16_uncorrectable",
        "profile_path": str(MRAM_STATE_SEARCH_PROFILE),
        "verdict": "FAIL",
        "renode_version": "Renode v1.17.0",
        "runtime_sweep_results": [
            {
                "fault_at": 2,
                "fault_requested": 2,
                "fault_type": "rs",
                "fault_injected": True,
                "fault_address": "0x10100100",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "fault_snapshot": {
                    "sha256": emu_mram_sha,
                    "size": 0x4000,
                    "uncorrectable_words": ["0x10100100", "0x10100110"],
                    "identity_slot": "exec",
                    "identity_slot_base": "0x10100000",
                    "identity_slot_extent": 4096,
                    "closest_declared_image": {
                        "name": "exec",
                        "exact": False,
                        "ranges_truncated": False,
                        "differing_ranges": [
                            {
                                "address": "0x10100100",
                                "offset": 256,
                                "size": 16,
                                "actual_hex": "314c415654475254314c415654475254",
                            },
                            {
                                "address": "0x10100118",
                                "offset": 280,
                                "size": 8,
                                "actual_hex": "4f4c443154415445",
                            },
                            {
                                "address": "0x10100138",
                                "offset": 312,
                                "size": 8,
                                "actual_hex": "3145544147455250",
                            },
                        ],
                    },
                },
                "recovery_state_search": {
                    "generation": 2,
                    "state_identity": emu_mram_id,
                    "cut_count": 2,
                    "cuts": [
                        {"cut": 1, "operation": "write", "operation_index": 2, "fault_type": "power_loss", "address": "0x10100110"},
                        {"cut": 2, "operation": "write", "operation_index": 0, "fault_type": "power_loss", "address": "0x10100100"},
                    ],
                    "chain": {"cut_count": 2, "text": "write[2]@0x10100110 -> write[0]@0x10100100"},
                },
                "failure_explanation": {
                    "state_comparison": {
                        "status": "compared_persistent_state",
                        "ranges": [
                            {"address": "0x10100108", "failing_hex": "31", "passing_hex": "4f"},
                            {"address": "0x1010010A", "failing_hex": "4156", "passing_hex": "4431"},
                            {"address": "0x10100118", "failing_hex": "4f4c4431", "passing_hex": "454e4f44"},
                        ],
                        "uncorrectable_only_in_failing": ["0x10100100"],
                        "uncorrectable_only_in_passing": [],
                    }
                },
            }
        ],
    }
    mram_rep_path = tmp_path / "mram_offline_report.json"
    mram_rep_path.write_text(json.dumps(mram_offline_report), encoding="utf-8")
    mram_out = tmp_path / "mram_offline_bundle"
    export_reproducer(
        report=mram_rep_path,
        state="601330377439",
        output=mram_out,
        renode_test="",
        repo_root=ROOT,
    )
    mram_check = verify_exported_state_against_emulator(
        mram_out,
        emu_mram_bytes,
        emulator_uncorrectable_words=("0x10100100", "0x10100110"),
    )
    assert mram_check == {
        "total_bytes": 16384,
        "verified_bytes": 16384,
        "unspecified_bytes": 0,
        "fully_specified": True,
        "byte_identical": True,
    }
    assert "Specification Status**: `fully_specified`" in (mram_out / "README.md").read_text(encoding="utf-8")

    # Mutating any specified byte (e.g. staging slot 0x10102002 or uncorrectable word 0x10100100) must fail
    for bad_off, expected_addr in ((0x2002, "0x10102002"), (0x0100, "0x10100100")):
        corrupted = bytearray(emu_mram_bytes)
        corrupted[bad_off] ^= 0xFF
        with pytest.raises(ExportReproError, match=expected_addr):
            verify_exported_state_against_emulator(mram_out, bytes(corrupted))

    with pytest.raises(ExportReproError, match="uncorrectable words"):
        verify_exported_state_against_emulator(
            mram_out,
            emu_mram_bytes,
            emulator_uncorrectable_words=("0x10100100",),
        )

    # 2. MCUboot PR 3011 flash pair (3,0) offline reconstruction vs emulator state
    pr3011_trace_report = {
        "profile": "mcuboot_pr3011_move_broken",
        "profile_path": str(PR3011_PROFILE),
        "verdict": "FAIL",
        "renode_version": "Renode v1.17.0",
        "runtime_sweep_results": [
            {
                "fault_at": 2,
                "fault_requested": 2,
                "fault_type": "p2:2:6:w:w",
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_window": {
                    "before": {"kind": "write", "sequence": 6, "write_index": 2, "flash_offset": 0x0EBFD0, "address": "0x000EBFD0", "value": "0x00009150", "width": 4},
                    "at": {"kind": "write", "sequence": 7, "write_index": 3, "flash_offset": 0x0EBFF0, "address": "0x000EBFF0", "value": "0xF395C277", "width": 4},
                    "after": {"kind": "write", "sequence": 8, "write_index": 4, "flash_offset": 0x0EBFF4, "address": "0x000EBFF4", "value": "0x7FEFD260", "width": 4},
                },
                "phase2_fault": {
                    "p1_fault_at": 2,
                    "p2_fault_at": 6,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": True,
                    "p2_write_trace": [
                        {"write_index": 1, "flash_offset": 0x0EBFE8, "address": "0x000F7FE8", "value": "0xFFFFFF01", "width": 4},
                        {"write_index": 2, "flash_offset": 0x0EBFD0, "address": "0x000F7FD0", "value": "0x00009150", "width": 4},
                        {"write_index": 3, "flash_offset": 0x0EBFF0, "address": "0x000F7FF0", "value": "0xF395C277", "width": 4},
                    ],
                },
            },
            {
                "fault_at": 3,
                "fault_requested": 3,
                "fault_type": "p2:3:0:w:w",
                "fault_injected": True,
                "boot_outcome": "wrong_image",
                "boot_slot": "exec",
                "fault_class": "wrong_image",
                "fault_window": {
                    "before": {"kind": "write", "sequence": 7, "write_index": 3, "flash_offset": 0x0EBFF0, "address": "0x000EBFF0", "value": "0xF395C277", "width": 4},
                    "at": {"kind": "write", "sequence": 8, "write_index": 4, "flash_offset": 0x0EBFF4, "address": "0x000EBFF4", "value": "0x7FEFD260", "width": 4},
                    "after": {"kind": "write", "sequence": 9, "write_index": 5, "flash_offset": 0x0EBFF8, "address": "0x000EBFF8", "value": "0x0F505235", "width": 4},
                },
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 0,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": True,
                    "p2_erase_trace": [
                        {"erase_index": 1, "address": "0x00081000", "flash_offset": 0x075000, "erase_size": 4096, "writes_at_this_point": 0},
                        {"erase_index": 2, "address": "0x00080000", "flash_offset": 0x074000, "erase_size": 4096, "writes_at_this_point": 0},
                        {"erase_index": 3, "address": "0x0007F000", "flash_offset": 0x073000, "erase_size": 4096, "writes_at_this_point": 0},
                        {"erase_index": 4, "address": "0x0007E000", "flash_offset": 0x072000, "erase_size": 4096, "writes_at_this_point": 0},
                    ],
                    "p2_write_trace": [
                        {"write_index": 1, "address": "0x00081FD8", "flash_offset": 0x075FD8, "value": "0xFFFFFF04", "width": 4},
                    ],
                },
                "failure_explanation": {
                    "state_comparison": {
                        "status": "compared_persistent_state",
                        "ranges": [
                            {"address": "0x000F7FF4", "failing_hex": "ffffffffffffffffffffffff", "passing_hex": "60d2ef7f3552500f2cb67980"}
                        ],
                    }
                },
            },
        ],
    }
    pr3011_rep_path = tmp_path / "pr3011_trace_report.json"
    pr3011_rep_path.write_text(json.dumps(pr3011_trace_report), encoding="utf-8")
    pr3011_out = tmp_path / "pr3011_trace_bundle"
    export_reproducer(
        report=pr3011_rep_path,
        point="3,0",
        output=pr3011_out,
        renode_test="",
        repo_root=ROOT,
    )
    pr3011_bytes = (pr3011_out / "state/persistent_state.bin").read_bytes()
    pr3011_meta = json.loads((pr3011_out / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert pr3011_meta["persistent_state"]["sha256"] == "eabbd83c1f83b3de1c2bc90c00f6a2be970d2278734ce21955b642b1eb377963"
    assert pr3011_meta["persistent_state"]["state_identity"] == "326eb2db288a994384a9e941349658266463ef0075511e43589ba46f4dac0edb"
    assert pr3011_meta["persistent_state"]["fully_specified"] is True
    assert pr3011_bytes[0x075FE0:0x075FE4] == b"\xff\xff\xff\xff"
    assert pr3011_bytes[0x075FF0:0x076000] == b"\xff" * 16
    assert pr3011_bytes[0x0EBFD0:0x0EBFD4] == bytes.fromhex("50910000")
    assert pr3011_bytes[0x0EBFE8:0x0EBFEC] == bytes.fromhex("01ffffff")
    assert pr3011_bytes[0x0EBFF0:0x0EBFF4] == bytes.fromhex("77c295f3")

    bad_pr3011 = bytearray(pr3011_bytes)
    bad_pr3011[0x0EBFD0:0x0EBFD4] = b"\xff\xff\xff\xff"
    with pytest.raises(ExportReproError, match="0x000F7FD0"):
        verify_exported_state_against_emulator(pr3011_out, bytes(bad_pr3011))

    # 3. Zephyr SPI NOR NVS (w[11]) offline reconstruction with full pre-cut trace vs emulator state
    nvs_writes = [
        (1, 0x0F98, "0x00000001"),
        (2, 0x0FC8, "0x0F980010"),
        (3, 0x0FCC, "0xA1FF0004"),
        (4, 0x0F9C, "0x00000002"),
        (5, 0x0FC0, "0x0F9C0010"),
        (6, 0x0FC4, "0x2EFF0004"),
        (7, 0x0FA0, "0x00000003"),
        (8, 0x0FB8, "0x0FA00010"),
        (9, 0x0FBC, "0xEEFF0004"),
        (10, 0x0FA4, "0x00000004"),
        (11, 0x0FB0, "0x0FA40010"),
        (12, 0x0FB4, "0x61FF0004"),
    ]
    nvs_rows = []
    for wi, f_off, val_hex in nvs_writes:
        op_dict = {
            "kind": "write",
            "sequence": wi,
            "write_index": wi,
            "flash_offset": f_off,
            "address": f"0x{0x60000000 + f_off:08X}",
            "value": val_hex,
            "width": 4,
        }
        row_entry = {
            "fault_at": wi - 1,
            "fault_requested": wi - 1,
            "fault_type": "w",
            "fault_injected": True,
            "fault_address": op_dict["address"],
            "boot_outcome": "wrong_image" if wi == 12 else "success",
            "boot_slot": "exec",
            "fault_class": "wrong_image" if wi == 12 else "recoverable",
            "fault_window": {"at": op_dict},
        }
        if wi == 12:
            row_entry["fault_snapshot"] = {
                "sha256": "3d373f57177338269caead18875df67b17169641bf61721b0f11f86206686dc7",
                "size": 0x200000,
            }
            row_entry["failure_explanation"] = {
                "state_comparison": {
                    "status": "compared_persistent_state",
                    "ranges": [{"address": "0x60000FB0", "failing_hex": "1000a40f", "passing_hex": "ffffffff"}],
                }
            }
        nvs_rows.append(row_entry)

    nvs_full_report = {
        "profile": "zephyr_spi_nor_nvs_broken",
        "profile_path": str(ZEPHYR_NVS_PROFILE),
        "verdict": "FAIL",
        "renode_version": "Renode v1.17.0",
        "runtime_sweep_results": nvs_rows,
    }
    nvs_full_path = tmp_path / "nvs_full_report.json"
    nvs_full_path.write_text(json.dumps(nvs_full_report), encoding="utf-8")
    nvs_full_out = tmp_path / "nvs_full_bundle"
    export_reproducer(
        report=nvs_full_path,
        point="w[11]",
        output=nvs_full_out,
        renode_test="",
        repo_root=ROOT,
    )
    nvs_bytes = (nvs_full_out / "state/persistent_state.bin").read_bytes()
    nvs_meta = json.loads((nvs_full_out / "state/persistent_state.json").read_text(encoding="utf-8"))
    assert nvs_meta["persistent_state"]["sha256"] == "3d373f57177338269caead18875df67b17169641bf61721b0f11f86206686dc7"
    assert nvs_meta["persistent_state"]["state_identity"] == "5f961248207f8b9a1c800b3788212a5c32c7abf6909d877e698068a2505e8b01"
    assert nvs_meta["persistent_state"]["fully_specified"] is True

    bad_nvs = bytearray(nvs_bytes)
    bad_nvs[0x0F98] ^= 0xFF
    with pytest.raises(ExportReproError, match="0x60000F98"):
        verify_exported_state_against_emulator(nvs_full_out, bytes(bad_nvs))

    # 4. Partially specified bundle (e.g. non-redistributable GPL scrubbed code regions):
    # verification ignores differences in unspecified regions and fails on any difference in specified regions.
    emu_wolf = bytearray(b"\xff" * 0x100000)
    emu_wolf[0x0000:0x0020] = b"LIVE_WOLFBOOT_CODE_IN_EMULATOR!!"
    emu_wolf[0x7FFF0:0x80000] = b"TRAILER_METADATA"
    wolf_compressed = base64.b64encode(zlib.compress(bytes(emu_wolf), level=1)).decode("ascii")
    wolf_rep = {
        "profile": "wolfboot_stm32f4_power_loss_erase",
        "profile_path": str(WOLFBOOT_PROFILE),
        "verdict": "FAIL",
        "target_source": {
            "name": "wolfboot",
            "repository": "https://github.com/wolfSSL/wolfBoot.git",
            "revision": "ad8dc62131fc0067a3ab25edc1b7e731397712d4",
        },
        "runtime_sweep_results": [
            {
                "fault_at": 1,
                "fault_requested": 1,
                "fault_type": "e",
                "fault_injected": True,
                "fault_address": "0x0807FFF0",
                "boot_outcome": "no_boot",
                "_pre_recovery_state": {
                    "base_address": "0x08000000",
                    "size": len(emu_wolf),
                    "zlib_b64": wolf_compressed,
                    "uncorrectable_words": [],
                },
            }
        ],
    }
    wolf_rep_path = tmp_path / "wolf_spec.json"
    wolf_rep_path.write_text(json.dumps(wolf_rep), encoding="utf-8")
    wolf_out = tmp_path / "wolf_spec_bundle"
    export_reproducer(report=wolf_rep_path, point="e[1]", output=wolf_out, repo_root=ROOT)
    wolf_readme = (wolf_out / "README.md").read_text(encoding="utf-8")
    assert "partially_specified" in wolf_readme
    assert "Unspecified region" in wolf_readme
    wolf_check = verify_exported_state_against_emulator(wolf_out, bytes(emu_wolf))
    assert wolf_check["fully_specified"] is False
    assert wolf_check["unspecified_bytes"] > 0
    assert wolf_check["verified_bytes"] + wolf_check["unspecified_bytes"] == len(emu_wolf)

    bad_wolf = bytearray(emu_wolf)
    bad_wolf[0x7FFF0] ^= 0xFF
    with pytest.raises(ExportReproError, match="0x0807FFF0"):
        verify_exported_state_against_emulator(wolf_out, bytes(bad_wolf))
