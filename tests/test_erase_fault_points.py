#!/usr/bin/env python3
"""Unit tests for opt-in erase fault points and operation_kind reporting."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_report import categorize_failure, summarize_runtime_sweep  # noqa: E402
from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from fault_types import operation_kind_for_fault_type  # noqa: E402
from profile_loader import ProfileError, load_profile  # noqa: E402


def _write_profile(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def test_operation_kind_for_fault_type_classification() -> None:
    for code in ("w", "w:sp", "w:ss:0", "b", "b:42", "s", "g", "x", "d", "l", "r", "k", "op", "power_loss", "m:w", "h:0:w", "p2:0:1:w:w"):
        assert operation_kind_for_fault_type(code) == "program", code
    for code in ("e", "a", "interrupted_erase", "multi_sector_atomicity", "m:e", "h:0:e", "p2:0:1:w:e", "cc:0:e"):
        assert operation_kind_for_fault_type(code) == "erase", code
    for code in ("control", "", None, "i", "i:0x1000", "f", "t", "nv:0", "tb:0x10:0x20:1", "in"):
        assert operation_kind_for_fault_type(code) is None, code


def test_include_erase_fault_points_defaults_off_and_preserves_fault_plan(tmp_path: Path) -> None:
    prof_off_path = _write_profile(
        tmp_path,
        "off",
        """
        schema_version: 1
        name: erase_opt_off
        platform: platforms/cortex_m0_nvm_flash.repl
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
        flash_backend: nvm_ctrl
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          fault_types: [power_loss]
          sweep_strategy: exhaustive
        """,
    )
    prof_on_path = _write_profile(
        tmp_path,
        "on",
        """
        schema_version: 1
        name: erase_opt_on
        platform: platforms/cortex_m0_nvm_flash.repl
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
        flash_backend: nvm_ctrl
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          fault_types: [power_loss]
          include_erase_fault_points: true
          sweep_strategy: exhaustive
        """,
    )
    prof_off = load_profile(prof_off_path, strict=True)
    prof_on = load_profile(prof_on_path, strict=True)

    assert prof_off.fault_sweep.include_erase_fault_points is False
    assert prof_on.fault_sweep.include_erase_fault_points is True
    assert "INCLUDE_ERASE_FAULT_POINTS:false" in prof_off.robot_vars(ROOT)
    assert "INCLUDE_ERASE_FAULT_POINTS:true" in prof_on.robot_vars(ROOT)

    cal = CalibrationInputs(max_writes=4, total_erases=2)
    plan_off = build_fault_plan(prof_off, cal)
    assert plan_off.fault_points == [0, 1, 2, 3]
    assert plan_off.fault_types_list is None

    plan_on = build_fault_plan(prof_on, cal)
    assert plan_on.fault_points == [0, 1, 2, 3, 0, 1]
    assert plan_on.fault_types_list == ["w", "w", "w", "w", "e", "e"]


def test_include_erase_fault_points_works_on_mram_backend_and_deduplicates(tmp_path: Path) -> None:
    prof_mram_path = _write_profile(
        tmp_path,
        "mram_erases",
        """
        schema_version: 1
        name: mram_erases_on
        platform: platforms/cortex_m0_self_update.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x00000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 16
          slots:
            exec: { base: 0x10100000, size: 0x1000 }
            staging: { base: 0x10101000, size: 0x1000 }
        flash_backend: mramTracker
        success_criteria:
          pc_in_slot: exec
        fault_sweep:
          fault_types: [power_loss, interrupted_erase]
          include_erase_fault_points: true
          mram_torn_word: uncorrectable
          evaluation_mode: execute
          sweep_strategy: exhaustive
        """,
    )
    prof = load_profile(prof_mram_path, strict=True)
    plan = build_fault_plan(prof, CalibrationInputs(max_writes=2, total_erases=2))
    assert plan.fault_points == [0, 1, 0, 1]
    assert plan.fault_types_list == ["w", "w", "e", "e"]

    # Erase-only firmware (0 writes, 2 erases) still plans both erase points.
    plan_erase_only = build_fault_plan(prof, CalibrationInputs(max_writes=0, total_erases=2))
    assert plan_erase_only.fault_points == [0, 1]
    assert plan_erase_only.fault_types_list == ["e", "e"]


def test_include_erase_fault_points_validation_and_torn_word_rules(tmp_path: Path) -> None:
    # Non-boolean include_erase_fault_points rejected.
    bad_bool = _write_profile(
        tmp_path,
        "bad_bool",
        """
        schema_version: 1
        name: bad_bool
        platform: platforms/cortex_m0_nvm_flash.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 4
          slots:
            exec: { base: 0x10000000, size: 0x1000 }
            staging: { base: 0x10001000, size: 0x1000 }
        flash_backend: nvm_ctrl
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          include_erase_fault_points: "maybe"
        """,
    )
    with pytest.raises(ProfileError, match="include_erase_fault_points"):
        load_profile(bad_bool, strict=True)

    # Torn-word modes (untouched, erased) accepted on flash backends when
    # include_erase_fault_points is true, while uncorrectable is rejected on
    # fast flash controllers lacking ECC read traps.
    fast_erased = _write_profile(
        tmp_path,
        "fast_erased",
        """
        schema_version: 1
        name: fast_erased
        platform: platforms/cortex_m0_mapped_faultctrl.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 4
          slots:
            exec: { base: 0x10000000, size: 0x1000 }
            staging: { base: 0x10001000, size: 0x1000 }
        flash_backend: faultFlash
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          include_erase_fault_points: true
          mram_torn_word: untouched
        """,
    )
    prof_fast = load_profile(fast_erased, strict=True)
    assert prof_fast.fault_sweep.mram_torn_word == "untouched"

    fast_uncorr = _write_profile(
        tmp_path,
        "fast_uncorr",
        """
        schema_version: 1
        name: fast_uncorr
        platform: platforms/cortex_m0_mapped_faultctrl.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 4
          slots:
            exec: { base: 0x10000000, size: 0x1000 }
            staging: { base: 0x10001000, size: 0x1000 }
        flash_backend: faultFlash
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          evaluation_mode: execute
          include_erase_fault_points: true
          mram_torn_word: uncorrectable
        """,
    )
    with pytest.raises(ProfileError, match="uncorrectable"):
        load_profile(fast_uncorr, strict=True)


def test_audit_report_and_runtime_builder_report_operation_kind() -> None:
    profile = load_profile(
        ROOT / "examples" / "recovery_vector_fault" / "profile_erased_vector_with_erase_points.yaml",
        strict=True,
    )
    results = [
        {
            "fault_at": -1,
            "fault_type": "control",
            "is_control": True,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {},
        },
        {
            "fault_at": 0,
            "fault_type": "w",
            "operation_kind": "program",
            "fault_injected": True,
            "fault_address": "0x10000000",
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "signals": {},
        },
        {
            "fault_at": 1,
            "fault_type": "w",
            "operation_kind": "program",
            "fault_injected": True,
            "fault_address": "0x10000004",
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {},
        },
        {
            "fault_at": 0,
            "fault_type": "e",
            "operation_kind": "erase",
            "fault_injected": True,
            "fault_address": "0x10000000",
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "signals": {},
        },
    ]
    summary = summarize_runtime_sweep(results, total_writes=2, profile=profile)
    assert summary["operation_kind_points"] == {"program": 2, "erase": 1}
    assert summary["operation_kind_issue_points"] == {"program": 1, "erase": 1}
    assert summary["operation_kind_bricks"] == {"program": 1, "erase": 1}
    cat = categorize_failure(results[3], total_writes=2, profile=profile)
    assert cat["operation_kind"] == "erase"
    cat_prog = categorize_failure(results[1], total_writes=2, profile=profile)
    assert cat_prog["operation_kind"] == "program"

    # Verify runtime helper in run_runtime_fault_sweep.py matches fault_types.py.
    runtime_src = (SCRIPTS / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    tree = ast.parse(runtime_src)
    fn_nodes = [
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_operation_kind_for_fault_type"
    ]
    assert len(fn_nodes) == 1
    ns: dict = {}
    exec(compile(ast.Module(body=fn_nodes, type_ignores=[]), "sweep", "exec"), ns, ns)
    assert ns["_operation_kind_for_fault_type"]("w") == "program"
    assert ns["_operation_kind_for_fault_type"]("e") == "erase"
    assert ns["_operation_kind_for_fault_type"]("a") == "erase"
    assert ns["_operation_kind_for_fault_type"]("control") is None


def test_erase_before_program_fixture_builds_and_profiles_validate() -> None:
    fixture = ROOT / "examples" / "erase_before_program"
    if shutil.which("arm-none-eabi-gcc") is None:
        pytest.skip("arm-none-eabi-gcc is not installed")
    subprocess.run(["make", "-C", str(fixture), "clean", "all"], cwd=ROOT, check=True)
    p_base = load_profile(fixture / "profile.yaml", strict=True)
    p_with = load_profile(fixture / "profile_with_erases.yaml", strict=True)
    p_unt = load_profile(fixture / "profile_erase_untouched.yaml", strict=True)
    p_era = load_profile(fixture / "profile_erase_erased.yaml", strict=True)
    p_unc = load_profile(fixture / "profile_erase_uncorrectable.yaml", strict=True)
    assert p_base.fault_sweep.include_erase_fault_points is False
    assert p_with.fault_sweep.include_erase_fault_points is True
    assert p_unt.fault_sweep.mram_torn_word == "untouched"
    assert p_era.fault_sweep.mram_torn_word == "erased"
    assert p_unc.fault_sweep.mram_torn_word == "uncorrectable"
