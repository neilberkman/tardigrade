# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import ast
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import ProfileError, load_profile  # noqa: E402
from audit_report import summarize_runtime_sweep  # noqa: E402
from replay_cross_check import (  # noqa: E402
    ReplayCrossCheckError,
    first_pre_cut_trace_difference,
    format_replay_cross_check_error,
    replay_cross_check_selected,
)
from recovery_search import first_persistent_difference  # noqa: E402
from recovery_state import (  # noqa: E402
    PersistentState,
    apply_completed_operation,
    apply_interrupted_operation,
    merge_operation_traces,
)


RUNTIME_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


def _runtime_functions(*names):
    tree = ast.parse(RUNTIME_PATH.read_text(encoding="utf-8"))
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in functions} == set(names)
    namespace = {}
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), str(RUNTIME_PATH), "exec"),
        namespace,
    )
    return namespace


def _flash_outcome_profile(tmp_path):
    path = tmp_path / "flash-outcomes.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            name: replay_check_flash_outcomes
            platform: platforms/cortex_m4_flash_fast.repl
            bootloader:
              elf: examples/recovery_vector_fault/firmware.elf
              entry: 0x10000000
            memory:
              sram: { start: 0x20000000, end: 0x20002000 }
              write_granularity: 4
              page_size: 0x1000
              slots:
                exec: { base: 0x10000000, size: 0x1000 }
                staging: { base: 0x10001000, size: 0x1000 }
            flash_backend: faultFlash
            success_criteria:
              vtor_in_slot: exec
            fault_sweep:
              fault_types: [power_loss]
              evaluation_mode: execute
              trace_replay_cross_check_every: 1
              torn_word_seed: 37
              torn_word: [fixed, untouched, programmed, partial_bits]
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return load_profile(path)


def _partial_bits_cut(profile):
    draw = _runtime_functions("_mram_torn_word_for_point")[
        "_mram_torn_word_for_point"
    ]
    choices = profile.fault_sweep.torn_word_choices
    seed = profile.fault_sweep.torn_word_seed
    cut = next(
        index
        for index in range(100)
        if draw(index, choices, seed) == "partial_bits"
    )
    return cut, seed


def test_sample_selection_is_stable_across_batches_and_zero_disables():
    points = [0, 1, 99, 100, 101, 200]
    assert [point for point in points if replay_cross_check_selected(point, 100)] == [
        0,
        100,
        200,
    ]
    assert not any(replay_cross_check_selected(point, 0) for point in points)
    with pytest.raises(ReplayCrossCheckError, match="non-negative"):
        replay_cross_check_selected(0, -1)


def test_pre_cut_write_divergence_names_the_first_different_operation():
    expected = [
        (1, 0x10, 0x11111111, 4),
        (2, 0x14, 0x22222222, 4),
        (3, 0x18, 0x33333333, 4),
    ]
    observed = [
        (1, 0x10, 0x11111111, 4),
        (2, 0x24, 0x22222222, 4),
    ]
    difference = first_pre_cut_trace_difference(
        "write", 2, expected, observed
    )
    assert difference["kind"] == "pre_cut_execution_diverged"
    assert difference["operation"] == "write"
    assert difference["sequence_position"] == 1
    assert difference["expected"]["offset"] == "0x14"
    assert difference["observed"]["offset"] == "0x24"


def test_pre_cut_erase_prefix_is_compared():
    writes = [(1, 0x10, 1, 4), (2, 0x14, 2, 4)]
    expected_erases = [(0x100, 1, 0x1000), (0x200, 2, 0x1000)]
    observed_erases = [(0x180, 1, 0x1000)]
    difference = first_pre_cut_trace_difference(
        "erase",
        1,
        writes,
        writes,
        expected_erases,
        observed_erases,
    )
    assert difference["operation"] == "erase"
    assert difference["expected"]["offset"] == "0x100"
    assert difference["observed"]["offset"] == "0x180"


def test_mismatch_reporting_names_cut_address_and_both_values():
    error = format_replay_cross_check_error(
        "write",
        17,
        "w",
        {
            "kind": "bytes",
            "address": "0x0000C123",
            "expected": "0xAA",
            "observed": "0xBB",
        },
    )
    assert "write cut 17 (w)" in error
    assert "0x0000C123" in error
    assert "replay=0xAA" in error
    assert "live=0xBB" in error

    divergence = format_replay_cross_check_error(
        "write",
        18,
        "w",
        {
            "kind": "pre_cut_execution_diverged",
            "operation": "write",
            "sequence_position": 3,
            "expected": {"offset": "0x10"},
            "observed": {"offset": "0x20"},
        },
    )
    assert "live pre-cut execution diverged from calibration" in divergence
    assert "calibration={'offset': '0x10'}" in divergence
    assert "live={'offset': '0x20'}" in divergence


def test_profile_cross_check_interval_defaults_and_validates(tmp_path):
    base = textwrap.dedent(
        """
        schema_version: 1
        name: replay_check_config
        platform: platforms/cortex_m4_flash_fast.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 4
          page_size: 0x1000
          slots:
            exec: { base: 0x10000000, size: 0x1000 }
            staging: { base: 0x10001000, size: 0x1000 }
        flash_backend: faultFlash
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          fault_types: [power_loss]
          evaluation_mode: execute
        """
    ).lstrip()
    default_path = tmp_path / "default.yaml"
    default_path.write_text(base)
    default = load_profile(default_path)
    assert default.fault_sweep.trace_replay_cross_check_every == 100
    assert "TRACE_REPLAY_CROSS_CHECK_EVERY:100" in default.robot_vars(ROOT)

    disabled_path = tmp_path / "disabled.yaml"
    disabled_path.write_text(
        base.replace("fault_sweep:\n", "fault_sweep:\n  trace_replay_cross_check_every: 0\n", 1)
    )
    assert load_profile(disabled_path).fault_sweep.trace_replay_cross_check_every == 0

    invalid_path = tmp_path / "invalid.yaml"
    invalid_path.write_text(
        base.replace("fault_sweep:\n", "fault_sweep:\n  trace_replay_cross_check_every: -1\n", 1)
    )
    with pytest.raises(ProfileError, match="trace_replay_cross_check_every"):
        load_profile(invalid_path)


def test_flash_list_program_cross_check_keeps_the_selected_partial_bits_state(tmp_path):
    profile = _flash_outcome_profile(tmp_path)
    cut, seed = _partial_bits_cut(profile)
    assert profile.fault_sweep.torn_word_choices[-1] == ("partial_bits", 1)

    previous = bytes.fromhex("f0ccaa55")
    operation = {
        "kind": "write",
        "write_index": cut + 1,
        "offset": 0,
        "value": 0x1180C000,
        "width": 4,
    }
    replay_state = apply_interrupted_operation(
        PersistentState.from_bytes(previous, base_address=0x1000),
        operation,
        backend_kind="flash",
        torn_word_mode="partial_bits",
        corruption_seed=seed,
    )
    replay_snapshot = replay_state.materialize()["nvm"]
    assert replay_snapshot not in (previous, bytes.fromhex("00c08011"))

    namespace = _runtime_functions(
        "_evaluate_replay_cross_check_live_cut",
        "_run_replay_cross_check_live_cut",
    )
    peripheral = type("Flash", (), {"TornWordMode": "partial_bits"})()

    def run_execute_fault(fault_at, fault_type, **kwargs):
        assert fault_at == cut
        assert fault_type == "w"
        assert peripheral.TornWordMode == "partial_bits"
        expected = kwargs["replay_cross_check_expected"]
        status = namespace["_evaluate_replay_cross_check_live_cut"](
            fault_at,
            fault_type,
            expected,
            True,
            replay_snapshot,
            (),
            {"writes": [], "erases": []},
            kwargs["replay_cross_check_mode"],
        )
        return {"trace_replay_cross_check": status}

    namespace.update(
        {
            "PersistentState": PersistentState,
            "_writeback_snapshot_reconstruction_status": None,
            "trace_replay_cross_check_every": 1,
            "replay_cross_check_selected": replay_cross_check_selected,
            "_replay_storage_geometry": lambda: (0x1000, 4, 4, 0xFF),
            "run_execute_fault": run_execute_fault,
            "_replay_cross_check_expected_traces": lambda: ([], []),
            "_base_fault_type_code": lambda value: value,
            "first_pre_cut_trace_difference": first_pre_cut_trace_difference,
            "first_persistent_difference": first_persistent_difference,
            "format_replay_cross_check_error": format_replay_cross_check_error,
            "reset_verification_probes": lambda: None,
            "log": lambda _message: None,
            "_time": __import__("time"),
        }
    )
    status = namespace["_run_replay_cross_check_live_cut"](
        cut, "w", replay_snapshot, (), "python"
    )
    assert status["matched"] is True


def test_flash_list_erase_cross_check_computes_the_selected_partial_bits_state(tmp_path):
    profile = _flash_outcome_profile(tmp_path)
    cut, seed = _partial_bits_cut(profile)
    baseline = b"\x00" * ((cut + 1) * 4)
    erases = [(index * 4, 0, 4) for index in range(cut + 1)]
    namespace = _runtime_functions("_computed_erase_cross_check_state")
    namespace.update(
        {
            "_replay_cross_check_expected_traces": lambda: ([], erases),
            "merge_operation_traces": merge_operation_traces,
            "reload_images_cached": lambda: None,
            "_hash_bypass_active": False,
            "apply_hash_bypass": lambda: None,
            "_clear_mram_uncorrectable_words": lambda: None,
            "_replay_storage_geometry": lambda: (
                0x1000,
                len(baseline),
                4,
                0xFF,
            ),
            "_replay_storage_read_bytes": lambda _offset, _size: baseline,
            "to_py_bytes": bytes,
            "PersistentState": PersistentState,
            "apply_completed_operation": apply_completed_operation,
            "apply_interrupted_operation": apply_interrupted_operation,
            "backend": {
                "kind": "fast",
                "data": type("Flash", (), {"ProgramUnitSize": 4})(),
            },
            "torn_word_explicit": True,
            "torn_word": "partial_bits",
            "torn_word_seed": seed,
            "mram_torn_word": "half",
            "mram_torn_word_seed": 0,
        }
    )
    computed = namespace["_computed_erase_cross_check_state"](
        cut, "interrupted_erase"
    )

    operations = merge_operation_traces(
        [],
        [
            {
                "erase_index": index + 1,
                "offset": offset,
                "writes_at_this_point": writes_at,
                "erase_size": size,
            }
            for index, (offset, writes_at, size) in enumerate(erases)
        ],
    )
    expected = PersistentState.from_bytes(baseline, base_address=0x1000)
    for operation in operations:
        if operation["operation_index"] == cut:
            expected = apply_interrupted_operation(
                expected,
                operation,
                fault_type="interrupted_erase",
                backend_kind="fast",
                torn_word_mode="partial_bits",
                corruption_seed=seed,
                program_unit=4,
            )
            break
        expected = apply_completed_operation(expected, operation)

    assert computed.materialize() == expected.materialize()
    target = computed.materialize()["nvm"][cut * 4 : (cut + 1) * 4]
    assert target not in (b"\x00" * 4, b"\xFF" * 4)


def test_summary_counts_checks_and_excludes_mismatch_verdict_from_totals():
    passed = {
        "fault_at": 0,
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "fault_class": "recovered",
        "signals": {},
        "trace_replay_cross_check": {"checked": True, "matched": True},
    }
    mismatch = {
        "fault_at": 100,
        "fault_type": "w",
        "fault_injected": True,
        "boot_outcome": "infra_error",
        "boot_slot": None,
        "fault_class": "infrastructure_error",
        "signals": {},
        "infrastructure_error": True,
        "error_kind": "trace_replay_cross_check_mismatch",
        "trace_replay_cross_check": {"checked": True, "matched": False},
    }
    summary = summarize_runtime_sweep(
        [passed, mismatch],
        expected_fault_points=2,
        expected_control_points=0,
    )
    assert summary["point_counts"]["trace_replay_cross_checks"] == {
        "run": 2,
        "passed": 1,
        "failed": 1,
    }
    program_counts = summary["point_counts"]["kinds"]["single_cut_program"]
    assert {
        field: program_counts[field]
        for field in (
            "requested",
            "run",
            "evaluated",
            "infrastructure_error",
            "issues",
        )
    } == {
        "requested": 2,
        "run": 2,
        "evaluated": 1,
        "infrastructure_error": 1,
        "issues": 0,
    }
    assert summary["total_fault_points"] == 1
    assert summary["infrastructure_error_points"] == 1
    assert summary["incomplete_fault_points"] == 1
    assert summary["campaign_complete"] is False
    assert "infra_error" not in summary["failure_outcomes"]


def test_runtime_forced_mismatch_becomes_cross_check_failure():
    runtime_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
    tree = ast.parse(runtime_path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_evaluate_replay_cross_check_live_cut"
    )
    namespace = {
        "_base_fault_type_code": lambda value: value,
        "_replay_cross_check_expected_traces": lambda: ([(1, 0, 0x11, 1)], []),
        "first_pre_cut_trace_difference": first_pre_cut_trace_difference,
        "first_persistent_difference": first_persistent_difference,
        "format_replay_cross_check_error": format_replay_cross_check_error,
    }
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(runtime_path), "exec"),
        namespace,
    )
    expected = PersistentState.from_bytes(b"\xFF\xFF", base_address=0x1000)
    status = namespace["_evaluate_replay_cross_check_live_cut"](
        0,
        "w",
        expected,
        True,
        b"\xFE\xFF",
        (),
        {"writes": [(1, 0, 0x11, 1)], "erases": []},
        "python",
    )
    assert status["matched"] is False
    assert status["error_kind"] == "persistent_state_mismatch"
    assert status["first_difference"]["address"] == "0x00001000"
    assert "replay=0xFF" in status["error"]
    assert "live=0xFE" in status["error"]


def test_runtime_wires_checks_into_native_python_erase_and_writeback_paths():
    runtime_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
    tree = ast.parse(runtime_path.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    def calls(function_name, called_name):
        return any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == called_name
            for node in ast.walk(functions[function_name])
        )

    assert calls("run_trace_replay_fault_native", "_run_replay_cross_check_live_cut")
    assert calls("run_trace_replay_fault", "_run_replay_cross_check_live_cut")
    assert calls("_dispatch_fault_point", "_run_execute_erase_with_replay_cross_check")
    assert calls("run_execute_fault", "writeback_strip_uncommitted_from_snapshot")
