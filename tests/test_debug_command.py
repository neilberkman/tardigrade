# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tardigrade debug / scripts/debug_point.py."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import debug_point  # noqa: E402
from debug_point import (  # noqa: E402
    DebugError,
    build_debug_robot_vars,
    format_gdb_command,
    normalize_stop_at,
    resolve_debug_target,
    run_debug,
    validate_port,
)
from renode_runner import prepare_renode_command  # noqa: E402
from report_formats import saved_run  # noqa: E402
from report_sarif import sarif_report  # noqa: E402


MRAM_FIXTURE = ROOT / "tests/fixtures/report_formats_mram.json"
MRAM_STATE_SEARCH_PROFILE = (
    ROOT / "examples/phase2_mram_parity/profile_deferred_state_search_16_uncorrectable.yaml"
)
PR3011_PROFILE = ROOT / "profiles/mcuboot_pr3011_move_broken.yaml"
ERASE_BEFORE_PROGRAM_PROFILE = ROOT / "examples/erase_before_program/profile.yaml"


def _make_pr3011_report(tmp_path: Path) -> Path:
    report = {
        "profile": "mcuboot_pr3011_move_broken",
        "profile_path": str(PR3011_PROFILE),
        "verdict": "FAIL",
        "control_result": {
            "is_control": True,
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "slot0",
            "fault_class": "recoverable",
            "actual_writes": 120,
            "signals": {"total_ms": 100},
        },
        "runtime_sweep_results": [
            {
                "fault_at": 3,
                "fault_requested": 3,
                "fault_type": "p2",
                "fault_injected": True,
                "fault_address": "0x00023DE8",
                "boot_outcome": "wrong_image",
                "boot_slot": "slot0",
                "fault_class": "wrong_image",
                "actual_writes": 4,
                "signals": {"total_ms": 250},
                "phase2_fault": {
                    "p1_fault_at": 3,
                    "p2_fault_at": 0,
                    "p1_fault_type": "w",
                    "p2_fault_type": "w",
                    "p1_injected": True,
                    "p2_injected": True,
                    "p1_fault_address": "0x00024FF0",
                    "p2_fault_address": "0x00023DE8",
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


def _make_mram_state_search_report(tmp_path: Path) -> tuple[Path, str]:
    state_id_1 = "2674d6013d02a89660b6fc4ca3c97de4d4d3230dd13726c31c55767b56b17be7"
    state_id_2 = "2674d69999999999999999999999999999999999999999999999999999999999"
    report = {
        "profile": "phase2_mram_parity_deferred_state_search_16_uncorrectable",
        "profile_path": str(MRAM_STATE_SEARCH_PROFILE),
        "verdict": "FAIL",
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
                "signals": {"total_ms": 80},
                "recovery_state_search": {
                    "generation": 2,
                    "state_identity": state_id_1,
                    "reused": False,
                    "cut_count": 2,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 2,
                            "fault_type": "power_loss",
                            "address": "0x10100110",
                            "offset": 272,
                            "size": 16,
                        },
                        {
                            "cut": 2,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                            "offset": 256,
                            "size": 16,
                        },
                    ],
                    "chain": {
                        "cut_count": 2,
                        "text": "write[2]@0x10100110 -> write[0]@0x10100100",
                    },
                    "equivalent_chains": [
                        {
                            "cut_count": 2,
                            "text": "write[3]@0x10100120 -> write[0]@0x10100100",
                            "cuts": [
                                {
                                    "cut": 1,
                                    "operation": "write",
                                    "operation_index": 3,
                                    "fault_type": "power_loss",
                                    "address": "0x10100120",
                                },
                                {
                                    "cut": 2,
                                    "operation": "write",
                                    "operation_index": 0,
                                    "fault_type": "power_loss",
                                    "address": "0x10100100",
                                },
                            ],
                        }
                    ],
                },
            },
            {
                "fault_at": 1,
                "fault_requested": 1,
                "fault_type": "rs",
                "fault_injected": True,
                "fault_address": "0x10100100",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "actual_writes": 1,
                "signals": {"total_ms": 75},
                "recovery_state_search": {
                    "generation": 2,
                    "state_identity": state_id_2,
                    "reused": False,
                    "cut_count": 2,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 1,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                            "offset": 256,
                            "size": 16,
                        },
                        {
                            "cut": 2,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                            "offset": 256,
                            "size": 16,
                        },
                    ],
                    "chain": {
                        "cut_count": 2,
                        "text": "write[1]@0x10100100 -> write[0]@0x10100100",
                    },
                },
            },
        ],
    }
    path = tmp_path / "mram_state_search.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path, state_id_1


def test_normalize_stop_at_and_invalid_value():
    assert normalize_stop_at("recovery-reset") == "recovery-reset"
    assert normalize_stop_at("recovery_reset") == "recovery-reset"
    assert normalize_stop_at("reset-vector") == "recovery-reset"
    assert normalize_stop_at("cut") == "cut"
    assert normalize_stop_at("at-cut") == "cut"
    assert normalize_stop_at("first-fault") == "first-fault"
    assert normalize_stop_at("fault") == "first-fault"
    with pytest.raises(DebugError, match="unsupported --stop-at value"):
        normalize_stop_at("after-boot")


def test_format_gdb_command_and_port_validation():
    elf = Path("/tmp/test firmware/bootloader.elf")
    cmd = format_gdb_command("arm-none-eabi-gdb", elf, 3333)
    assert cmd == "arm-none-eabi-gdb '/tmp/test firmware/bootloader.elf' -ex \"target remote :3333\""
    assert validate_port(3333) == 3333
    ephemeral = validate_port(0)
    assert 1024 <= ephemeral <= 65535
    with pytest.raises(DebugError, match="--port must be an integer"):
        validate_port(-1)
    with pytest.raises(DebugError, match="--port must be an integer"):
        validate_port(70000)
    with pytest.raises(DebugError, match="--port must be an integer"):
        validate_port(True)


def test_resolve_two_cut_pair_from_report_with_multiple_selector_syntaxes(tmp_path):
    report_path = _make_pr3011_report(tmp_path)
    for selector in (
        "power_loss[3] → power_loss[0]",
        "power_loss[3] -> power_loss[0]",
        "3,0",
        "3:0",
        "[3, 0]",
        "w[3] -> w[0]",
        "p2:3:0:w:w",
    ):
        target = resolve_debug_target(
            report=report_path,
            point=selector,
            stop_at="recovery-reset",
            repo_root=ROOT,
        )
        assert target.profile_path == PR3011_PROFILE.resolve()
        assert target.elf_path.name == "oss_mcuboot_pr3011_move_broken.elf"
        assert target.fault_at == 3
        assert target.fault_type_code == "p2:3:0:w:w"
        assert target.cuts == ((3, "w"), (0, "w"))
        assert not target.is_control
        assert target.expected_outcome == "wrong_image"


def test_resolve_state_search_by_state_prefix_and_by_point_chain(tmp_path):
    report_path, state_id = _make_mram_state_search_report(tmp_path)
    target_by_state = resolve_debug_target(
        report=report_path,
        state="2674d6013d02",
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert target_by_state.state_identity == state_id
    assert target_by_state.state_search_gated is True
    assert target_by_state.fault_type_code == "p2:2:0:w:w"
    assert target_by_state.cuts == ((2, "w"), (0, "w"))
    assert target_by_state.expected_outcome == "no_boot"

    # Also selectable via --point using the chain text, equivalent chain, or state prefix
    for point_sel in (
        "write[2]@0x10100110 -> write[0]@0x10100100",
        "write[3]@0x10100120 -> write[0]@0x10100100",
        "2,0",
        "2674d6013d02",
    ):
        target = resolve_debug_target(
            report=report_path,
            point=point_sel,
            stop_at="first-fault",
            repo_root=ROOT,
        )
        assert target.state_identity == state_id
        assert target.cuts == ((2, "w"), (0, "w"))

    # Ambiguous state prefix '2674d6' matches both states in report
    with pytest.raises(DebugError, match="ambiguous state identifier '2674d6'"):
        resolve_debug_target(
            report=report_path,
            state="2674d6",
            repo_root=ROOT,
        )


def test_resolve_from_sarif_report_and_reproduction_blocks(tmp_path):
    sarif_path = tmp_path / "mram.sarif"
    fixture_data = json.loads(MRAM_FIXTURE.read_text(encoding="utf-8"))
    run_obj = saved_run(
        fixture_data,
        MRAM_FIXTURE,
        ROOT,
        profile_path=ERASE_BEFORE_PROGRAM_PROFILE,
    )
    sarif_doc = sarif_report([run_obj], ROOT)
    sarif_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    # 1. Resolve single-cut state-search finding directly from SARIF report file with --point
    target_single = resolve_debug_target(
        report=sarif_path,
        point="power_loss[2]",
        stop_at="cut",
        repo_root=ROOT,
    )
    assert target_single.fault_at == 2
    assert target_single.fault_type_code == "w"
    assert target_single.cuts == ((2, "w"),)
    assert target_single.state_identity == "940ff1ef6542c953390ab3a04047ee18476fd48fe7238a94542bfa72f2df6543"

    # 2. Resolve 2-cut state-search finding from SARIF report file via --state or --point
    target_state = resolve_debug_target(
        report=sarif_path,
        state="601330377439",
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert target_state.state_identity == "601330377439036885f5929df921e7c6de4d7f4a9e990de02ec0b58ccbf7d0fd"
    assert target_state.state_search_gated is True
    assert target_state.fault_type_code == "p2:2:0:w:w"
    assert target_state.cuts == ((2, "w"), (0, "w"))

    # 3. Resolve from an inline 2-cut pair SARIF reproduction block (--reproduction)
    pair_repro = {
        "fault_sweep": {
            "include_erase_fault_points": True,
            "phase2_fault": {
                "pairs": [[1, 0]],
                "first_fault_types": ["interrupted_erase"],
                "fault_types": ["power_loss"],
            },
        }
    }
    target_repro = resolve_debug_target(
        reproduction=json.dumps(pair_repro),
        profile=ERASE_BEFORE_PROGRAM_PROFILE,
        stop_at="cut",
        repo_root=ROOT,
    )
    assert target_repro.fault_type_code == "p2:1:0:e:w"
    assert target_repro.cuts == ((1, "e"), (0, "w"))
    assert target_repro.include_erase_fault_points is True

    # 4. Resolve from an inline 3-cut chain SARIF reproduction block (--reproduction)
    chain_repro = {
        "fault_sweep": {
            "phase2_fault": {
                "chains": [
                    [[0, "power_loss"], [1, "interrupted_erase"], [0, "power_loss"]]
                ]
            }
        }
    }
    target_chain = resolve_debug_target(
        reproduction=json.dumps(chain_repro),
        profile=ERASE_BEFORE_PROGRAM_PROFILE,
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert target_chain.fault_type_code == "pc:0:w:1:e:0:w"
    assert target_chain.cuts == ((0, "w"), (1, "e"), (0, "w"))

    # 5. Resolve from a single SARIF result dict passed via --reproduction
    results = sarif_doc["runs"][0]["results"]
    repro_file = tmp_path / "sarif_result.json"
    repro_file.write_text(json.dumps(results[0]), encoding="utf-8")
    target_from_result = resolve_debug_target(
        reproduction=repro_file,
        point="2,0",
        profile=ERASE_BEFORE_PROGRAM_PROFILE,
        repo_root=ROOT,
    )
    assert target_from_result.fault_type_code == "p2:2:0:w:w"


def test_refusals_for_invalid_points_and_unsupported_campaigns(tmp_path):
    report_path = _make_pr3011_report(tmp_path)

    # Missing report and reproduction
    with pytest.raises(DebugError, match="either --report or --reproduction is required"):
        resolve_debug_target(repo_root=ROOT)

    # Missing point and state on a report
    with pytest.raises(DebugError, match="a point \\(--point\\) or state \\(--state\\) identifier is required"):
        resolve_debug_target(report=report_path, repo_root=ROOT)

    # Non-existent point
    with pytest.raises(DebugError, match="did not match any point in report"):
        resolve_debug_target(report=report_path, point="999,999", repo_root=ROOT)

    # Skipped point
    with pytest.raises(DebugError, match="skipped in report \\(phase2_no_write_at_index\\)"):
        resolve_debug_target(report=report_path, point="99,50", repo_root=ROOT)

    # Infrastructure error point
    with pytest.raises(DebugError, match="report recorded an infrastructure error"):
        resolve_debug_target(report=report_path, point="7", repo_root=ROOT)

    # Initial boot timeout point
    with pytest.raises(DebugError, match="initial boot timed out in report"):
        resolve_debug_target(report=report_path, point="8", repo_root=ROOT)

    # --stop-at cut on clean control
    with pytest.raises(DebugError, match="cannot use --stop-at cut on a clean control point"):
        resolve_debug_target(
            report=report_path,
            point="control",
            stop_at="cut",
            repo_root=ROOT,
        )

    # Single-boot non-reset fault with --stop-at recovery-reset
    with pytest.raises(DebugError, match="continues in the initial boot without a recovery reset"):
        resolve_debug_target(
            reproduction=json.dumps({"FAULT_POINTS_CSV": "2", "FAULT_TYPE_CSV": "b"}),
            profile=ERASE_BEFORE_PROGRAM_PROFILE,
            stop_at="recovery-reset",
            repo_root=ROOT,
        )

    # Auxiliary non-runtime campaigns in report
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
        ("staging prefix 256", "cannot debug partial-staging truncation finding"),
        ("state fuzz scenario 0", "cannot debug state-fuzz scenario finding"),
        ("gen.yaml", "cannot debug fuzz-crash regression finding"),
        ("stage -> install", "cannot debug static authorization-review finding"),
    ):
        with pytest.raises(DebugError, match=expected_msg):
            resolve_debug_target(
                report=aux_report_path,
                point=aux_selector,
                profile=ERASE_BEFORE_PROGRAM_PROFILE,
                repo_root=ROOT,
            )

    # Auxiliary reproduction blocks passed directly to --reproduction
    for raw_repro, expected_msg in (
        ({"crash_file": "c.bin", "sha256": "abc"}, "cannot debug fuzz_crash reproduction block"),
        ({"scenario_index": 0, "blob_sha256": "abc"}, "cannot debug state_fuzz reproduction block"),
        ({"sequence": ["a", "b"], "model_digest": "abc"}, "cannot debug authorization_review reproduction block"),
        ({"fault_sweep": {"partial_staging": {"fractions": [0.5]}}}, "cannot debug partial_staging reproduction block"),
    ):
        with pytest.raises(DebugError, match=expected_msg):
            resolve_debug_target(
                reproduction=json.dumps(raw_repro),
                profile=ERASE_BEFORE_PROGRAM_PROFILE,
                repo_root=ROOT,
            )


def test_build_debug_robot_vars_and_docker_port_forwarding(tmp_path):
    report_path, state_id = _make_mram_state_search_report(tmp_path)
    target = resolve_debug_target(
        report=report_path,
        state="2674d6013d02",
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    ready_file = tmp_path / "ready.json"
    robot_vars, base_vars = build_debug_robot_vars(
        target,
        stop_at="recovery-reset",
        port=4567,
        ready_file=ready_file,
        timeout_s=180,
        repo_root=ROOT,
    )
    try:
        var_map = dict(item.split(":", 1) for item in robot_vars if ":" in item)
        assert var_map["DEBUG_MODE"] == "true"
        assert var_map["DEBUG_STOP_AT"] == "recovery-reset"
        assert var_map["DEBUG_GDB_PORT"] == "4567"
        assert var_map["DEBUG_READY_FILE"] == str(ready_file)
        assert var_map["DEBUG_TIMEOUT_S"] == "180"
        assert var_map["DEBUG_EXPECTED_STATE_ID"] == state_id
        assert var_map["DEBUG_STATE_SEARCH_GATED"] == "true"
        assert var_map["FAULT_POINTS_CSV"] == "2"
        assert var_map["FAULT_TYPE_CSV"] == "p2:2:0:w:w"

        raw_cmd = [
            "docker://rv-canary:22.04",
            "--renode-config",
            str(tmp_path / "renode.config"),
            str(ROOT / "tests/ota_fault_point.robot"),
        ]
        for rv in robot_vars:
            raw_cmd.extend(["--variable", rv])
        docker_cmd = prepare_renode_command("docker://rv-canary:22.04", raw_cmd, ROOT, {})
        assert "-p" in docker_cmd
        p_idx = docker_cmd.index("-p")
        assert docker_cmd[p_idx + 1] == "4567:4567"
    finally:
        debug_point._cleanup_generated_robot_vars(base_vars)

    pr3011_report = _make_pr3011_report(tmp_path)
    pr3011_target = resolve_debug_target(
        report=pr3011_report,
        point="3,0",
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    pr3011_vars, pr3011_base = build_debug_robot_vars(
        pr3011_target,
        stop_at="recovery-reset",
        port=4568,
        ready_file=ready_file,
        timeout_s=180,
        repo_root=ROOT,
    )
    try:
        pr3011_map = dict(item.split(":", 1) for item in pr3011_vars if ":" in item)
        if "HASH_BYPASS_ADDRS" in pr3011_map and pr3011_map["HASH_BYPASS_ADDRS"]:
            for entry in pr3011_map["HASH_BYPASS_ADDRS"].split(","):
                sym_name, addr_str = entry.split("=", 1)
                assert sym_name == "bootutil_img_validate"
                assert int(addr_str, 0) > 0
    finally:
        debug_point._cleanup_generated_robot_vars(pr3011_base)


def test_run_debug_handshake_prints_gdb_command_and_annotates_result(tmp_path, capsys):
    report_path, state_id = _make_mram_state_search_report(tmp_path)
    target = resolve_debug_target(
        report=report_path,
        state="2674d6013d02",
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    fake_renode = tmp_path / "fake-renode-test"
    fake_renode.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "vars_map = {}\n"
        "args = sys.argv[1:]\n"
        "for i, arg in enumerate(args):\n"
        "    if arg == '--variable' and i + 1 < len(args) and ':' in args[i + 1]:\n"
        "        k, v = args[i + 1].split(':', 1)\n"
        "        vars_map[k] = v\n"
        "ready_path = pathlib.Path(vars_map['DEBUG_READY_FILE'])\n"
        "ready_path.write_text(json.dumps({\n"
        "    'ready': True,\n"
        "    'port': int(vars_map['DEBUG_GDB_PORT']),\n"
        "    'stop_at': vars_map['DEBUG_STOP_AT'],\n"
        "    'pc': '0x10000044',\n"
        "    'sp': '0x20002000',\n"
        "    'lr': '0xFFFFFFFF',\n"
        "    'vtor': '0x00000000',\n"
        "    'state_identity': vars_map.get('DEBUG_EXPECTED_STATE_ID'),\n"
        "}))\n"
        "res_path = pathlib.Path(vars_map['RESULT_FILE'])\n"
        "res_path.write_text(json.dumps({\n"
        "    'fault_at': 2,\n"
        "    'fault_requested': 2,\n"
        "    'fault_type': vars_map['FAULT_TYPE_CSV'],\n"
        "    'fault_injected': True,\n"
        "    'fault_address': '0x10100100',\n"
        "    'boot_outcome': 'no_boot',\n"
        "    'boot_slot': None,\n"
        "    'fault_class': 'unrecoverable',\n"
        "    'actual_writes': 1,\n"
        "    'signals': {},\n"
        "    'debug_session': {\n"
        "        'stop_at': vars_map['DEBUG_STOP_AT'],\n"
        "        'port': int(vars_map['DEBUG_GDB_PORT']),\n"
        "        'initial_pc': '0x10000044',\n"
        "        'state_identity': vars_map.get('DEBUG_EXPECTED_STATE_ID'),\n"
        "    },\n"
        "}))\n",
        encoding="utf-8",
    )
    fake_renode.chmod(0o755)

    out_json = tmp_path / "debug_result.json"
    result = run_debug(
        target,
        stop_at="recovery-reset",
        port=3456,
        gdb="arm-none-eabi-gdb",
        renode_test=str(fake_renode),
        timeout=30,
        output=out_json,
        repo_root=ROOT,
    )
    captured = capsys.readouterr()
    expected_cmd = format_gdb_command("arm-none-eabi-gdb", target.elf_path, 3456)
    assert captured.out.strip() == expected_cmd
    assert f"state_identity={state_id}" in captured.err
    assert "verdict: boot_outcome=no_boot boot_slot=None fault_class=unrecoverable" in captured.err
    assert result["boot_outcome"] == "no_boot"
    assert result["gdb_command"] == expected_cmd
    assert out_json.is_file()


def test_run_debug_surfaces_ready_file_error_cleanly(tmp_path):
    report_path = _make_pr3011_report(tmp_path)
    target = resolve_debug_target(
        report=report_path,
        point="3,0",
        stop_at="first-fault",
        repo_root=ROOT,
    )
    fake_renode = tmp_path / "fake-renode-error"
    fake_renode.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "vars_map = {}\n"
        "args = sys.argv[1:]\n"
        "for i, arg in enumerate(args):\n"
        "    if arg == '--variable' and i + 1 < len(args) and ':' in args[i + 1]:\n"
        "        k, v = args[i + 1].split(':', 1)\n"
        "        vars_map[k] = v\n"
        "ready_path = pathlib.Path(vars_map['DEBUG_READY_FILE'])\n"
        "ready_path.write_text(json.dumps({\n"
        "    'ready': False,\n"
        "    'error': \"no fault occurred during boot for --stop-at first-fault (boot completed with outcome 'wrong_image')\",\n"
        "}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_renode.chmod(0o755)

    with pytest.raises(RuntimeError, match="no fault occurred during boot for --stop-at first-fault"):
        run_debug(
            target,
            stop_at="first-fault",
            port=3457,
            renode_test=str(fake_renode),
            timeout=30,
            repo_root=ROOT,
        )


def test_runtime_sweep_debug_helpers():
    import re
    from fault_inject import decode_multi_fault_sequence, decode_multi_fault_stage_types

    source = (ROOT / "scripts/run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    m_parse = re.search(
        r"(def _debug_parse_cuts\(.*?\n)(?=\ndef _debug_cut_is_reset_boundary)",
        source,
        re.S,
    )
    m_reset = re.search(
        r"(def _debug_cut_is_reset_boundary\(.*?\n)(?=\ndef _debug_apply_snapshot_in_place)",
        source,
        re.S,
    )
    assert m_parse is not None
    assert m_reset is not None
    ns: dict[str, Any] = {
        "decode_multi_fault_stages_local": lambda ft: (
            decode_multi_fault_sequence(ft),
            decode_multi_fault_stage_types(ft),
        ),
        "_base_fault_type_code": lambda code: str(code or "w").split(":", 1)[0],
    }
    exec(m_parse.group(1), ns)
    exec(m_reset.group(1), ns)
    parse_cuts = ns["_debug_parse_cuts"]
    is_reset = ns["_debug_cut_is_reset_boundary"]

    assert parse_cuts(-1, "control") == []
    assert parse_cuts(4, "w") == [(4, "w")]
    assert parse_cuts(3, "p2:3:0:w:e") == [(3, "w"), (0, "e")]
    assert parse_cuts(0, "pc:0:w:1:e:2:w") == [(0, "w"), (1, "e"), (2, "w")]
    assert parse_cuts(5, "c:5:1") == [(5, "w"), (1, "e")]
    assert parse_cuts(2, "mf:2@w:1@e") == [(2, "w"), (1, "e")]

    assert is_reset("w") is True
    assert is_reset("e") is True
    assert is_reset("a") is True
    assert is_reset("t") is True
    assert is_reset("op") is True
    assert is_reset("b") is False
    assert is_reset("f") is False
    assert is_reset("i:0x1000:nop") is False
    assert is_reset("m:w") is False
    assert is_reset("nv:0") is False


def test_resolve_from_state_search_checkpoint_and_verify_rebuilt_state(tmp_path):
    from recovery_checkpoint import SnapshotWriter
    from recovery_state import PersistentState

    base_bytes = bytearray(b"\xff" * 4096)
    base_bytes[0:4] = b"\x31\x4c\x41\x56"
    state_booted = PersistentState.from_bytes(
        base_bytes,
        name="nvm",
        base_address=0x10100000,
        uncorrectable_words=(("nvm", 256),),
    )
    sid_booted = state_booted.identity_hex()

    frontier_bytes = bytearray(base_bytes)
    frontier_bytes[16:20] = b"\x00\x00\x00\x00"
    state_frontier = PersistentState.from_bytes(
        frontier_bytes,
        name="nvm",
        base_address=0x10100000,
        uncorrectable_words=(("nvm", 256), ("nvm", 272)),
    )
    sid_frontier = state_frontier.identity_hex()

    snap_only_bytes = bytearray(base_bytes)
    snap_only_bytes[32:36] = b"\xaa\xbb\xcc\xdd"
    state_snap_only = PersistentState.from_bytes(
        snap_only_bytes,
        name="nvm",
        base_address=0x10100000,
    )
    sid_snap_only = state_snap_only.identity_hex()

    writer = SnapshotWriter()
    for st in (state_booted, state_frontier, state_snap_only):
        writer.reference(st)
    snapshots, chunks = writer.states, writer.chunks
    checkpoint = {
        "version": 1,
        "inputs": {
            "profile": "phase2_mram_parity_deferred_state_search_16_uncorrectable",
            "profile_path": str(MRAM_STATE_SEARCH_PROFILE),
        },
        "results": [
            {
                "fault_at": 2,
                "fault_requested": 2,
                "fault_type": "rs",
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "actual_writes": 1,
                "signals": {},
                "recovery_state_search": {
                    "generation": 1,
                    "state_identity": sid_booted,
                    "reused": False,
                    "cut_count": 1,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 2,
                            "fault_type": "power_loss",
                            "address": "0x10100110",
                            "offset": 272,
                            "size": 16,
                        }
                    ],
                    "chain": {
                        "cut_count": 1,
                        "text": "write[2]@0x10100110",
                    },
                },
            }
        ],
        "recovery_traces": [
            [
                {
                    "kind": "write",
                    "write_index": 1,
                    "offset": 256,
                    "width": 16,
                    "value": 0,
                }
            ]
        ],
        "pending_visits": [[0, 0, sid_frontier]],
        "computed_frontier": [],
        "trace_queue": [],
        "snapshots": snapshots,
        "chunks": chunks,
    }
    ckpt_path = tmp_path / "search.checkpoint.json"
    ckpt_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    # 1. Booted state in checkpoint
    t_booted = resolve_debug_target(
        report=ckpt_path,
        state=sid_booted[:12],
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert t_booted.state_identity == sid_booted
    assert t_booted.cuts == ((2, "w"),)
    assert t_booted.checkpoint_snapshot is not None
    assert t_booted.pre_recovery_state is not None

    # 2. Unbooted pending_visits state in checkpoint reconstructs 2-cut chain + snapshot
    t_frontier = resolve_debug_target(
        report=ckpt_path,
        state=sid_frontier[:12],
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert t_frontier.state_identity == sid_frontier
    assert t_frontier.cuts == ((2, "w"), (0, "w"))
    assert t_frontier.fault_type_code == "p2:2:0:w:w"
    assert t_frontier.checkpoint_snapshot is not None

    # 3. Snapshot-only state in checkpoint works for recovery-reset/first-fault, refused for --stop-at cut
    t_snap = resolve_debug_target(
        report=ckpt_path,
        state=sid_snap_only[:12],
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert t_snap.state_identity == sid_snap_only
    assert t_snap.cuts == ()
    assert t_snap.checkpoint_snapshot is not None
    with pytest.raises(DebugError, match="cannot use --stop-at cut on checkpoint state"):
        resolve_debug_target(
            report=ckpt_path,
            state=sid_snap_only[:12],
            stop_at="cut",
            repo_root=ROOT,
        )

    # 4. Final checkpoint is refused with clear error
    final_ckpt = tmp_path / "final.checkpoint.json"
    final_ckpt.write_text(json.dumps({"version": 1, "final": True}), encoding="utf-8")
    with pytest.raises(DebugError, match="state-search checkpoint .* is final"):
        resolve_debug_target(
            report=final_ckpt,
            state=sid_booted[:12],
            repo_root=ROOT,
        )


def test_debug_state_verification_matches_failure_explanation_and_checkpoint_snapshots(tmp_path):
    import binascii
    import hashlib
    import re
    from recovery_checkpoint import SnapshotWriter, restore_snapshots
    from recovery_search import first_persistent_difference
    from recovery_state import PersistentState

    source = (ROOT / "scripts/run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    m_block = re.search(
        r"(def _debug_snapshot_from_persistent_state\(.*?\n)(?=\ndef _debug_apply_snapshot_in_place)",
        source,
        re.S,
    )
    assert m_block is not None
    ns: dict[str, Any] = {
        "PersistentState": PersistentState,
        "restore_snapshots": restore_snapshots,
        "first_persistent_difference": first_persistent_difference,
        "to_clr_bytes": lambda b: bytes(bytearray(b)),
        "to_py_bytes": lambda b: bytearray(b),
        "fmt_u32": lambda v: f"0x{int(v) & 0xFFFFFFFF:08X}",
        "base64": __import__("base64"),
        "binascii": binascii,
        "hashlib": hashlib,
        "json": json,
        "os": __import__("os"),
        "debug_expected_state_file": "",
    }
    exec(m_block.group(1), ns)
    verify_fn = ns["_debug_verify_rebuilt_state"]
    snap_from_state = ns["_debug_snapshot_from_persistent_state"]
    load_payload_fn = ns["_debug_load_expected_state_payload"]

    raw_nvm = bytearray(b"\xff" * 256)
    raw_nvm[16:20] = b"\xde\xad\xbe\xef"
    state = PersistentState.from_bytes(
        raw_nvm,
        name="nvm",
        base_address=0x08000000,
        uncorrectable_words=(("nvm", 32),),
        persistent_values={"otp": bytearray(b"\x12\x34\x56\x78")},
    )
    snap = snap_from_state(state)
    assert snap["uncorrectable_offsets"] == [32]
    assert snap["uncorrectable_addresses"] == ["0x08000020"]
    assert snap["persistent_values"]["otp"] == b"\x12\x34\x56\x78"

    writer = SnapshotWriter()
    writer.reference(state)
    snapshots, chunks = writer.states, writer.chunks
    expected_payload = {
        "state_identity": state.identity_hex(),
        "checkpoint_snapshot": {
            "version": 1,
            "snapshots": snapshots,
            "chunks": chunks,
        },
        "expected_explanation": {
            "fault_snapshot": {
                "sha256": hashlib.sha256(bytes(raw_nvm)).hexdigest(),
                "uncorrectable_words": ["0x08000020"],
                "closest_declared_image": {
                    "ranges_truncated": False,
                    "differing_ranges": [
                        {
                            "address": "0x08000010",
                            "size": 4,
                            "bytes_truncated": False,
                            "actual_hex": "deadbeef",
                            "expected_hex": "ffffffff",
                        }
                    ],
                },
            },
            "state_comparison": {
                "status": "compared_persistent_state",
                "ranges": [
                    {
                        "address": "0x08000010",
                        "failing_hex": "deadbeef",
                        "passing_hex": "ffffffff",
                    }
                ],
                "uncorrectable_only_in_failing": ["0x08000020"],
                "uncorrectable_only_in_passing": ["0x08000040"],
                "persistent_values": [
                    {
                        "name": "otp",
                        "failing_hex": "12345678",
                        "passing_hex": "00000000",
                    }
                ],
            },
        },
    }
    payload_file = tmp_path / "debug_expected_state.json"
    payload_file.write_text(json.dumps(expected_payload), encoding="utf-8")
    loaded_payload, preloaded = load_payload_fn(str(payload_file))
    assert preloaded is not None
    assert preloaded.identity_hex() == state.identity_hex()

    verified_id = verify_fn(
        state,
        expected_state_id=state.identity_hex()[:12],
        expected_payload=loaded_payload,
        preloaded_state=preloaded,
    )
    assert verified_id == state.identity_hex()

    # Mutating a byte described by failure_explanation.state_comparison must fail verification
    bad_nvm = bytearray(raw_nvm)
    bad_nvm[16] = 0x00
    bad_state = PersistentState.from_bytes(
        bad_nvm,
        name="nvm",
        base_address=0x08000000,
        uncorrectable_words=(("nvm", 32),),
        persistent_values={"otp": bytearray(b"\x12\x34\x56\x78")},
    )
    with pytest.raises(RuntimeError, match="does not match expected state"):
        verify_fn(bad_state, expected_payload=loaded_payload)
    comparison_only_payload = {
        "expected_explanation": {
            "state_comparison": loaded_payload["expected_explanation"]["state_comparison"]
        }
    }
    with pytest.raises(RuntimeError, match="do not match failure_explanation state_comparison"):
        verify_fn(bad_state, expected_payload=comparison_only_payload)


def test_resolve_external_nvm_and_shard_edge_targets(tmp_path):
    spi_nor_profile = ROOT / "profiles/mcuboot_zephyr_spi_nor_state_search.yaml"
    i2c_eeprom_profile = ROOT / "profiles/zephyr_i2c_eeprom_storage_sweep.yaml"

    for ext_prof, expected_backend in (
        (spi_nor_profile, "spiNor"),
        (i2c_eeprom_profile, "i2cEeprom"),
    ):
        target = resolve_debug_target(
            reproduction=json.dumps({"FAULT_POINTS_CSV": "1", "FAULT_TYPE_CSV": "w"}),
            profile=ext_prof,
            stop_at="recovery-reset",
            repo_root=ROOT,
        )
        assert target.profile.flash_backend == expected_backend
        assert target.cuts == ((1, "w"),)
        ready_file = tmp_path / f"ready_{expected_backend}.json"
        robot_vars, base_vars = build_debug_robot_vars(
            target,
            stop_at="recovery-reset",
            port=3344,
            ready_file=ready_file,
            timeout_s=60,
            repo_root=ROOT,
        )
        try:
            var_map = dict(item.split(":", 1) for item in robot_vars if ":" in item)
            assert var_map["FLASH_BACKEND"] == expected_backend
        finally:
            debug_point._cleanup_generated_robot_vars(base_vars)

    # Single-shard report with an unbooted peer_edge state
    peer_sid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    shard_report = {
        "profile": "mcuboot_zephyr_spi_nor_swap_move",
        "profile_path": str(spi_nor_profile),
        "verdict": "PASS",
        "runtime_sweep_results": [
            {
                "fault_at": 4,
                "fault_requested": 4,
                "fault_type": "rs",
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_class": "recoverable",
                "actual_writes": 10,
                "signals": {},
                "recovery_state_search": {
                    "generation": 1,
                    "state_identity": "1111111111111111111111111111111111111111111111111111111111111111",
                    "reused": False,
                    "cut_count": 1,
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 4,
                            "fault_type": "power_loss",
                            "address": "0x20041000",
                        }
                    ],
                },
                "shard_expansion": {
                    "edges": [],
                    "peer_edges": [
                        [
                            {
                                "cut": 2,
                                "operation": "erase",
                                "operation_index": 1,
                                "fault_type": "interrupted_erase",
                                "address": "0x20042000",
                            },
                            peer_sid,
                        ]
                    ],
                },
            }
        ],
    }
    shard_path = tmp_path / "shard0.json"
    shard_path.write_text(json.dumps(shard_report), encoding="utf-8")
    peer_target = resolve_debug_target(
        report=shard_path,
        state=peer_sid[:12],
        stop_at="recovery-reset",
        repo_root=ROOT,
    )
    assert peer_target.state_identity == peer_sid
    assert peer_target.cuts == ((4, "w"), (1, "e"))
    assert peer_target.fault_type_code == "p2:4:1:w:e"


