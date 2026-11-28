# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

try:
    from recovery_coverage import (  # noqa: E402
        RecoveryCoverageError,
        build_recovery_coverage_scope,
        describe_coverage_sizing,
        merge_sharded_coverage_results,
        partition_first_cuts_for_shard,
        resolve_executed_probe_pcs,
        summarize_recovery_coverage,
    )
except ModuleNotFoundError as exc:  # Allow per-test comparisons with the base revision.
    if exc.name != "recovery_coverage":
        raise

    class RecoveryCoverageError(ValueError):
        pass

    def _missing_recovery_coverage(*_args, **_kwargs):
        raise ModuleNotFoundError("recovery_coverage is unavailable in this revision")

    build_recovery_coverage_scope = _missing_recovery_coverage
    describe_coverage_sizing = _missing_recovery_coverage
    merge_sharded_coverage_results = _missing_recovery_coverage
    partition_first_cuts_for_shard = _missing_recovery_coverage
    resolve_executed_probe_pcs = _missing_recovery_coverage
    summarize_recovery_coverage = _missing_recovery_coverage


MCUBOOT_PR3011_ELF = (
    ROOT
    / "results"
    / "oss_validation"
    / "assets"
    / "oss_mcuboot_pr3011_move_broken.elf"
)
MRAM_DEFERRED_ELF = (
    ROOT / "examples" / "phase2_mram_parity" / "firmware_deferred.elf"
)


def test_build_scope_on_elf_without_dwarf_line_info_reports_function_only():
    scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=[
            "fixup_revert",
            "boot_swap_image",
            "context_boot_go",
        ],
    )

    assert scope["enabled"] is True
    assert scope["line_info_available"] is False
    assert scope["granularity"] == "function_only"
    assert "lacks DWARF line information (.debug_line)" in scope["line_info_notice"]
    assert scope["lines"] == []
    function_names = [fn["name"] for fn in scope["functions"]]
    assert set(function_names) == {
        "fixup_revert",
        "boot_swap_image",
        "context_boot_go",
    }
    fixup = next(fn for fn in scope["functions"] if fn["name"] == "fixup_revert")
    assert fixup["start_address"] == "0x000012E8"
    # 0x000012e8 (entry) and 0x000012fe (BOOT_MAGIC_BAD target) are basic-block leaders.
    assert 0x000012E8 in fixup["probe_pcs"]
    assert 0x000012FE in fixup["probe_pcs"]
    assert 0x00001356 in fixup["probe_pcs"]
    # All probe PCs have bit 0 cleared for Renode Thumb hooks.
    assert all((int(pc) & 1) == 0 for pc in scope["probe_pcs"])


def test_build_scope_refuses_source_files_when_elf_lacks_dwarf_line_info():
    with pytest.raises(
        RecoveryCoverageError,
        match=r"has no DWARF \.debug_line information",
    ):
        build_recovery_coverage_scope(
            MCUBOOT_PR3011_ELF,
            source_files=["swap_move.c"],
        )


def test_build_scope_refuses_unknown_function_and_empty_configuration():
    with pytest.raises(
        RecoveryCoverageError,
        match=r"no function symbols matching",
    ):
        build_recovery_coverage_scope(
            MCUBOOT_PR3011_ELF,
            functions=["nonexistent_recovery_fn"],
        )

    with pytest.raises(
        RecoveryCoverageError,
        match=r"requires at least one of functions, source_files, or address_ranges",
    ):
        build_recovery_coverage_scope(MCUBOOT_PR3011_ELF)


def test_build_scope_on_elf_with_dwarf_line_tables_includes_functions_and_lines():
    scope = build_recovery_coverage_scope(
        MRAM_DEFERRED_ELF,
        source_files=["firmware.c"],
    )

    assert scope["enabled"] is True
    assert scope["line_info_available"] is True
    assert scope["granularity"] == "function_and_line"
    assert scope["line_info_notice"] is None
    function_names = [fn["name"] for fn in scope["functions"]]
    assert "Default_Handler" in function_names
    assert "HardFault_Handler" in function_names
    assert "Reset_Handler" in function_names

    # Verify M-class Thumb disassembly of HardFault_Handler (contains mrs r0, msp).
    hardfault = next(
        fn for fn in scope["functions"] if fn["name"] == "HardFault_Handler"
    )
    assert hardfault["probe_pcs"] == [0x10000014]
    line_numbers = [line["line"] for line in scope["lines"]]
    # Default_Handler (56), HardFault_Handler (63), Reset_Handler recovery (112..114)
    assert 56 in line_numbers
    assert 63 in line_numbers
    assert 112 in line_numbers
    assert 113 in line_numbers
    assert 114 in line_numbers


def test_build_scope_with_address_ranges_limits_to_configured_range():
    full_scope = build_recovery_coverage_scope(
        MRAM_DEFERRED_ELF,
        functions=["HardFault_Handler"],
    )
    hf = full_scope["functions"][0]
    scope = build_recovery_coverage_scope(
        MRAM_DEFERRED_ELF,
        address_ranges=[{"start": hf["start"], "end": hf["end"] - 2}],
    )

    function_names = [fn["name"] for fn in scope["functions"]]
    assert function_names == ["HardFault_Handler"]
    assert all(
        hf["start"] <= int(pc) < hf["end"] for pc in scope["probe_pcs"]
    )


def test_resolve_executed_probe_pcs_matches_exact_and_block_ranges():
    scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=["fixup_revert"],
    )
    # 0x00001302 is inside basic block [0x00001300, 0x0000130c]
    resolved = resolve_executed_probe_pcs(
        scope, executed_pcs=[0x000012E9, 0x00001302]
    )
    assert 0x000012E8 in resolved
    assert 0x00001300 in resolved


def test_summarize_recovery_coverage_classifies_control_cut_only_and_never_executed():
    scope = build_recovery_coverage_scope(
        MRAM_DEFERRED_ELF,
        source_files=["firmware.c"],
    )
    fns_by_name = {fn["name"]: fn for fn in scope["functions"]}
    hardfault_fn = fns_by_name["HardFault_Handler"]
    default_fn = fns_by_name["Default_Handler"]

    lines_by_num = {line["line"]: line for line in scope["lines"]}
    control_pcs = []
    # Clean control executes Reset_Handler lines except recovery lines 112..114.
    for line in scope["lines"]:
        if line["function"] == "Reset_Handler" and line["line"] not in (
            112,
            113,
            114,
        ):
            control_pcs.extend(line["probe_pcs"])
    for fn_name in ("tracking_gate",):
        if fn_name in fns_by_name:
            control_pcs.extend(fns_by_name[fn_name]["probe_pcs"])

    cut1_pcs = list(control_pcs)
    for ln in (112, 113, 114):
        if ln in lines_by_num:
            cut1_pcs.extend(lines_by_num[ln]["probe_pcs"])

    cut2_pcs = list(control_pcs) + list(hardfault_fn["probe_pcs"])

    results = [
        {
            "fault_at": -1,
            "fault_type": "w",
            "fault_injected": False,
            "boot_outcome": "normal_boot",
            "recovery_coverage": {
                "executed_pcs": control_pcs,
                "recording_overhead_s": 0.002,
                "boot_wall_time_s": 0.100,
            },
        },
        {
            "fault_at": 1,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "recovered",
            "recovery_state_search": {
                "generation": 1,
                "state_identity": "aa" * 32,
                "chain": {
                    "text": "write[0]@0x10040000",
                    "cut_count": 1,
                },
            },
            "recovery_coverage": {
                "executed_pcs": cut1_pcs,
                "recording_overhead_s": 0.003,
                "boot_wall_time_s": 0.120,
            },
        },
        {
            "fault_at": 2,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "boot_failure",
            "recovery_state_search": {
                "generation": 2,
                "state_identity": "bb" * 32,
                "chain": {
                    "text": "write[0]@0x10040000 -> write[0]@0x1004000c",
                    "cut_count": 2,
                },
            },
            "recovery_coverage": {
                "executed_pcs": cut2_pcs,
                "recording_overhead_s": 0.004,
                "boot_wall_time_s": 0.110,
            },
        },
    ]

    report = summarize_recovery_coverage(results, scope)

    assert report["enabled"] is True
    assert report["line_info_available"] is True
    assert report["granularity"] == "function_and_line"

    fn_status = {fn["name"]: fn for fn in report["functions"]}
    assert fn_status["Reset_Handler"]["status"] == "executed_by_control"
    assert (
        fn_status["HardFault_Handler"]["status"]
        == "executed_only_under_cut"
    )
    assert (
        fn_status["HardFault_Handler"]["first_reached_by"]["chain"]
        == "write[0]@0x10040000 -> write[0]@0x1004000c"
    )
    assert fn_status["HardFault_Handler"]["first_reached_by"]["boot_index"] == 2
    assert (
        fn_status["Default_Handler"]["status"]
        == "never_executed_by_cut"
    )
    assert fn_status["Default_Handler"]["first_reached_by"] is None
    assert default_fn["id"] in report["function_summary"]["never_executed_by_cut"]

    line_status = {line["line"]: line for line in report["lines"]}
    assert line_status[112]["status"] == "executed_only_under_cut"
    assert (
        line_status[112]["first_reached_by"]["chain"] == "write[0]@0x10040000"
    )
    assert line_status[113]["status"] == "executed_only_under_cut"
    assert line_status[114]["status"] == "executed_only_under_cut"
    assert line_status[63]["status"] == "executed_only_under_cut"
    assert (
        line_status[63]["first_reached_by"]["chain"]
        == "write[0]@0x10040000 -> write[0]@0x1004000c"
    )
    assert line_status[56]["status"] == "never_executed_by_cut"

    assert len(report["coverage_by_boot"]) == 2
    assert (
        report["coverage_by_boot"][1]["cumulative_units"]
        > report["coverage_by_boot"][0]["cumulative_units"]
    )
    assert report["recording_overhead"]["boots_measured"] == 3
    assert report["recording_overhead"]["mean_recording_overhead_s"] == 0.003


def test_summarize_recovery_coverage_without_line_info_reports_functions_and_notice():
    scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=["fixup_revert", "context_boot_go"],
    )
    fixup = next(fn for fn in scope["functions"] if fn["name"] == "fixup_revert")
    boot_go = next(
        fn for fn in scope["functions"] if fn["name"] == "context_boot_go"
    )

    results = [
        {
            "fault_at": -1,
            "fault_type": "w",
            "fault_injected": False,
            "boot_outcome": "normal_boot",
            "recovery_coverage": {
                "executed_pcs": [boot_go["probe_pcs"][0]],
                "recording_overhead_s": 0.001,
            },
        },
        {
            "fault_at": 3,
            "fault_type": "w",
            "fault_injected": True,
            "boot_outcome": "recovered",
            "recovery_coverage": {
                "executed_pcs": [fixup["probe_pcs"][0], 0x000012FE],
                "recording_overhead_s": 0.002,
            },
        },
    ]

    report = summarize_recovery_coverage(results, scope)
    assert report["line_info_available"] is False
    assert report["lines"] == []
    assert report["line_summary"] is None
    assert "DWARF line information (.debug_line)" in report["line_info_notice"]

    fn_status = {fn["name"]: fn for fn in report["functions"]}
    assert fn_status["context_boot_go"]["status"] == "executed_by_control"
    assert fn_status["fixup_revert"]["status"] == "executed_only_under_cut"
    assert fn_status["fixup_revert"]["first_reached_by"]["kind"] == "point"
    assert fn_status["fixup_revert"]["first_reached_by"]["fault_at"] == 3


def test_sharding_partition_merge_and_sizing_are_deterministic():
    scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=["fixup_revert", "context_boot_go"],
    )
    first_cuts = [("write", idx) for idx in range(8)]
    shard0 = partition_first_cuts_for_shard(first_cuts, 3, 0)
    shard1 = partition_first_cuts_for_shard(first_cuts, 3, 1)
    shard2 = partition_first_cuts_for_shard(first_cuts, 3, 2)

    assert len(shard0) + len(shard1) + len(shard2) == 8
    assert set(shard0) | set(shard1) | set(shard2) == set(first_cuts)
    assert set(shard0).isdisjoint(shard1)
    assert set(shard1).isdisjoint(shard2)

    fixup_pc = scope["functions"][0]["probe_pcs"][0]
    boot_go_pc = scope["functions"][1]["probe_pcs"][0]
    shard0_results = [
        {
            "fault_at": 1,
            "fault_type": "w",
            "fault_injected": True,
            "recovery_state_search": {
                "generation": 1,
                "state_identity": "11" * 32,
                "chain": {"text": "write[0]@0x000f7fe8"},
            },
            "recovery_coverage": {"executed_pcs": [fixup_pc]},
        }
    ]
    shard1_results = [
        {
            "fault_at": 2,
            "fault_type": "w",
            "fault_injected": True,
            "recovery_state_search": {
                "generation": 1,
                "state_identity": "22" * 32,
                "chain": {"text": "write[3]@0x000f7ff4"},
            },
            "recovery_coverage": {"executed_pcs": [fixup_pc, boot_go_pc]},
        }
    ]

    _merged_results, merged = merge_sharded_coverage_results(
        [
            {"shard_index": 1, "results": shard1_results},
            {"shard_index": 0, "results": shard0_results},
        ],
        scope,
    )
    fn_status = {fn["name"]: fn for fn in merged["functions"]}
    # Shard 0 is ordered before shard 1 regardless of input list order.
    assert (
        fn_status[scope["functions"][0]["name"]]["first_reached_by"]["chain"]
        == "write[0]@0x000f7fe8"
    )
    assert (
        fn_status[scope["functions"][1]["name"]]["first_reached_by"]["chain"]
        == "write[3]@0x000f7ff4"
    )

    sizing = describe_coverage_sizing(
        scope, first_cuts=first_cuts, order="coverage_guided"
    )
    assert sizing["enabled"] is True
    assert sizing["total_functions"] == 2
    assert sizing["selected_first_cuts"] == 8
    assert sizing["order"] == "coverage_guided"


def test_profile_loader_recovery_coverage_and_state_search_options(tmp_path: Path) -> None:
    import base64
    import json
    from profile_loader import ProfileError, load_profile

    base_yaml = (
        ROOT / "examples" / "phase2_mram_parity" / "profile_state_search_16_uncorrectable.yaml"
    ).read_text(encoding="utf-8").replace(
        "examples/phase2_mram_parity/firmware_two_unit.elf",
        "examples/phase2_mram_parity/firmware_deferred.elf",
    )

    # 1. Off by default when recovery_coverage is not configured.
    default_profile = load_profile(
        ROOT / "examples" / "phase2_mram_parity" / "profile_deferred_state_search_16_uncorrectable.yaml"
    )
    assert default_profile.fault_sweep.recovery_coverage.enabled is False
    assert not any(
        rv.startswith("RECOVERY_COVERAGE_B64:")
        for rv in default_profile.robot_vars(ROOT)
    )

    # 2. Enabled with source_files + coverage_guided + plateau stop.
    configured_path = tmp_path / "profile_cov.yaml"
    configured_yaml = base_yaml.replace(
        "      max_new_states: 32\n",
        "      max_new_states: 32\n"
        "      order: coverage_guided\n"
        "      max_boots_without_new_coverage: 4\n",
    ).replace(
        "expect:\n",
        "  driver_functions: [tracking_gate]\n"
        "  recovery_coverage:\n"
        "    enabled: true\n"
        "    mechanism: oneshot_address_hooks\n"
        "    source_files:\n"
        "      - firmware.c\n"
        "expect:\n",
    )
    configured_path.write_text(configured_yaml, encoding="utf-8")
    prof = load_profile(configured_path)
    assert "tracking_gate" in prof.driver_functions
    assert prof.fault_sweep.recovery_coverage is not None
    assert prof.fault_sweep.recovery_coverage.enabled is True
    assert list(prof.fault_sweep.recovery_coverage.source_files) == ["firmware.c"]
    assert prof.fault_sweep.phase2_fault is not None
    assert prof.fault_sweep.phase2_fault.state_search is not None
    assert prof.fault_sweep.phase2_fault.state_search.order == "coverage_guided"
    assert (
        prof.fault_sweep.phase2_fault.state_search.max_boots_without_new_coverage
        == 4
    )
    rvars = prof.robot_vars(ROOT)
    cov_vars = [rv for rv in rvars if rv.startswith("RECOVERY_COVERAGE_B64:")]
    assert len(cov_vars) == 1
    decoded = json.loads(
        base64.b64decode(cov_vars[0].split(":", 1)[1]).decode("utf-8")
    )
    assert decoded["enabled"] is True
    assert decoded["line_info_available"] is True
    assert decoded["granularity"] == "function_and_line"
    assert len(decoded["probe_pcs"]) > 0

    # 3. Reject coverage_guided without recovery_coverage.enabled.
    missing_cov_path = tmp_path / "profile_missing_cov.yaml"
    missing_cov_path.write_text(
        base_yaml.replace(
            "      max_new_states: 32\n",
            "      max_new_states: 32\n      order: coverage_guided\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        (ValueError, ProfileError),
        match="requires fault_sweep.recovery_coverage",
    ):
        load_profile(missing_cov_path)


def test_runtime_recovery_coverage_hook_recording_and_merging() -> None:
    import ast
    from recovery_coverage import resolve_executed_probe_pcs

    py_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    target_names = {
        "_recovery_coverage_active",
        "_recovery_coverage_probe_pcs",
        "_recovery_coverage_intervals",
        "_pc_in_recovery_coverage_intervals",
        "_start_recovery_coverage_boot",
        "_stop_recovery_coverage_boot",
        "_merge_recovery_coverage_records",
        "_attach_result_recovery_coverage",
    }
    funcs = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in target_names
    ]
    clock = [100.0]

    def fake_time() -> float:
        clock[0] += 0.001
        return clock[0]

    scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=["fixup_revert"],
        mechanism="oneshot_address_hooks",
    )
    namespace: dict = {
        "_time": type("FakeTime", (), {"time": staticmethod(fake_time)}),
        "as_int": lambda x: int(x),
        "fmt_u32": lambda x: "0x{:08X}".format(int(x) & 0xFFFFFFFF),
        "resolve_executed_probe_pcs": resolve_executed_probe_pcs,
        "recovery_coverage_config": scope,
        "calibration_mode": False,
        "_in_live_cross_check": False,
    }
    exec(
        compile(ast.Module(body=funcs, type_ignores=[]), str(py_path), "exec"),
        namespace,
    )

    class FakeCpu:
        def __init__(self) -> None:
            self.hooks: dict[int, list] = {}
            self.remove_calls = 0

        def AddHook(self, pc: int, fn) -> None:
            self.hooks.setdefault(int(pc), []).append(fn)

        def RemoveHook(self, pc: int, fn) -> None:
            self.remove_calls += 1
            callbacks = self.hooks.get(int(pc), [])
            if fn in callbacks:
                callbacks.remove(fn)
            if not callbacks and int(pc) in self.hooks:
                del self.hooks[int(pc)]

        def fire_pc(self, pc: int) -> None:
            for fn in list(self.hooks.get(int(pc) & ~1, ())):
                fn(self, int(pc))

    cpu = FakeCpu()
    session = namespace["_start_recovery_coverage_boot"](cpu, label="boot_1")
    assert session is not None
    probe_pcs = scope["probe_pcs"]
    assert len(cpu.hooks) == len(probe_pcs)

    # Firing the first two probe PCs must self-disarm them immediately on first hit.
    first_pc = probe_pcs[0]
    second_pc = probe_pcs[1]
    cpu.fire_pc(first_pc)
    assert first_pc not in cpu.hooks
    # Firing again does nothing because the hook already removed itself.
    cpu.fire_pc(first_pc)
    cpu.fire_pc(second_pc)
    assert second_pc not in cpu.hooks

    stop_status: dict = {"elapsed_s": 0.025}
    cov_record = namespace["_stop_recovery_coverage_boot"](
        cpu, session, stop_status=stop_status
    )
    assert cov_record is not None
    # All remaining hooks must be disarmed after stop.
    assert len(cpu.hooks) == 0
    assert cov_record["executed_pcs"] == sorted([first_pc, second_pc])
    assert cov_record["recording_overhead_s"] > 0.0
    assert stop_status["recovery_coverage"]["executed_pcs"] == sorted(
        [first_pc, second_pc]
    )

    # Follow-up boot cycle coverage merges into the primary record.
    third_pc = probe_pcs[2]
    followup_cov = {
        "enabled": True,
        "mechanism": "oneshot_address_hooks",
        "granularity": "function_only",
        "line_info_available": False,
        "executed_pcs": [second_pc, third_pc],
        "executed_pc_hex": [
            "0x{:08X}".format(second_pc),
            "0x{:08X}".format(third_pc),
        ],
        "executed_block_count": 2,
        "raw_hit_pc_count": 2,
        "total_probe_pcs": len(probe_pcs),
        "setup_overhead_s": 0.001,
        "callback_overhead_s": 0.001,
        "teardown_overhead_s": 0.001,
        "recording_overhead_s": 0.003,
        "boot_wall_time_s": 0.015,
        "boots_recorded": 1,
    }
    result: dict = {}
    signals: dict = {}
    cycle_records = [
        {"cycle": 0, "recovery_coverage": cov_record},
        {"cycle": 1, "recovery_coverage": followup_cov},
    ]
    merged = namespace["_attach_result_recovery_coverage"](
        result, signals, (stop_status,), cycle_records
    )
    assert merged is not None
    assert result["recovery_coverage"]["executed_pcs"] == sorted(
        [first_pc, second_pc, third_pc]
    )
    assert result["recovery_coverage"]["boots_recorded"] == 2
    assert signals["recovery_coverage_blocks"] == 3


def test_json_and_html_recovery_coverage_reports_with_and_without_dwarf(
    tmp_path: Path,
) -> None:
    from audit_report import summarize_runtime_sweep
    from render_results_html import write_html

    # 1. With DWARF line info (MRAM deferred ELF).
    dwarf_scope = build_recovery_coverage_scope(
        MRAM_DEFERRED_ELF,
        source_files=["firmware.c"],
        mechanism="oneshot_address_hooks",
    )
    fn_by_name = {fn["name"]: fn for fn in dwarf_scope["functions"]}
    reset_pcs = fn_by_name["Reset_Handler"]["probe_pcs"]
    gate_pcs = fn_by_name["tracking_gate"]["probe_pcs"]
    hardfault_pcs = fn_by_name["HardFault_Handler"]["probe_pcs"]

    dwarf_results = [
        {
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "is_control": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "recovery_coverage": {
                "enabled": True,
                "mechanism": "oneshot_address_hooks",
                "executed_pcs": list(reset_pcs[:4]) + list(gate_pcs),
                "recording_overhead_s": 0.0012,
                "boot_wall_time_s": 0.020,
            },
        },
        {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "no_boot",
            "boot_slot": None,
            "recovery_state_search": {
                "generation": 1,
                "state_identity": "aa" * 32,
                "chain": {
                    "text": "w=0 (0x10100100)",
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 0,
                            "fault_type": "power_loss",
                            "address": "0x10100100",
                        }
                    ],
                },
            },
            "recovery_coverage": {
                "enabled": True,
                "mechanism": "oneshot_address_hooks",
                "executed_pcs": [reset_pcs[0]] + list(hardfault_pcs),
                "recording_overhead_s": 0.0009,
                "boot_wall_time_s": 0.018,
            },
        },
    ]
    dwarf_summary = summarize_runtime_sweep(
        dwarf_results,
        expected_fault_points=1,
        expected_control_points=1,
        planned_fault_types=["rs"],
        recovery_coverage_scope=dwarf_scope,
    )
    assert "recovery_coverage" in dwarf_summary
    cov_report = dwarf_summary["recovery_coverage"]
    assert cov_report["line_info_available"] is True
    assert cov_report["granularity"] == "function_and_line"
    assert cov_report["line_summary"] is not None
    assert cov_report["function_summary"]["executed_by_control_count"] == 2
    assert cov_report["function_summary"]["executed_only_under_cut_count"] == 1
    assert cov_report["function_summary"]["never_executed_by_cut_count"] >= 1

    dwarf_payload = {
        "profile": "phase2_mram_deferred_state_search_16_uncorrectable",
        "verdict": "FAIL — found 1 issue points",
        "summary": {"runtime_sweep": dwarf_summary},
        "recovery_coverage": cov_report,
        "runtime_sweep_results": dwarf_results,
    }
    dwarf_html_path = tmp_path / "dwarf_report.html"
    write_html([(Path("dwarf.json"), dwarf_payload)], dwarf_html_path)
    dwarf_html = dwarf_html_path.read_text(encoding="utf-8")
    assert "recovery code coverage" in dwarf_html
    assert "function_and_line // oneshot_address_hooks" in dwarf_html
    assert "recovery coverage by source line" in dwarf_html
    assert "recovery coverage vs. boots" in dwarf_html
    assert "HardFault_Handler" in dwarf_html
    assert "executed_only_under_cut" in dwarf_html
    assert "w=0 (0x10100100)" in dwarf_html

    # 2. Without DWARF line info (MCUboot PR 3011 ELF).
    nodwarf_scope = build_recovery_coverage_scope(
        MCUBOOT_PR3011_ELF,
        functions=["fixup_revert", "context_boot_go"],
        mechanism="oneshot_address_hooks",
    )
    nd_fns = {fn["name"]: fn for fn in nodwarf_scope["functions"]}
    boot_go_pcs = nd_fns["context_boot_go"]["probe_pcs"]
    fixup_pcs = nd_fns["fixup_revert"]["probe_pcs"]

    nodwarf_results = [
        {
            "fault_at": -1,
            "fault_requested": -1,
            "fault_type": "control",
            "fault_injected": False,
            "is_control": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "recovery_coverage": {
                "enabled": True,
                "mechanism": "oneshot_address_hooks",
                "executed_pcs": list(boot_go_pcs[:3]),
                "recording_overhead_s": 0.0015,
                "boot_wall_time_s": 0.030,
            },
        },
        {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "recovery_state_search": {
                "generation": 1,
                "state_identity": "bb" * 32,
                "chain": {
                    "text": "w=3 (0x000F7FF4)",
                    "cuts": [
                        {
                            "cut": 1,
                            "operation": "write",
                            "operation_index": 3,
                            "fault_type": "power_loss",
                            "address": "0x000F7FF4",
                        }
                    ],
                },
            },
            "recovery_coverage": {
                "enabled": True,
                "mechanism": "oneshot_address_hooks",
                "executed_pcs": [boot_go_pcs[0], fixup_pcs[0]],
                "recording_overhead_s": 0.0014,
                "boot_wall_time_s": 0.028,
            },
        },
    ]
    nodwarf_summary = summarize_runtime_sweep(
        nodwarf_results,
        expected_fault_points=1,
        expected_control_points=1,
        planned_fault_types=["rs"],
        recovery_coverage_scope=nodwarf_scope,
    )
    nd_cov = nodwarf_summary["recovery_coverage"]
    assert nd_cov["line_info_available"] is False
    assert nd_cov["granularity"] == "function_only"
    assert nd_cov["line_summary"] is None
    assert "DWARF" in (nd_cov["line_info_notice"] or "")

    nodwarf_payload = {
        "profile": "mcuboot_pr3011_move_broken_state_search",
        "verdict": "PASS",
        "summary": {"runtime_sweep": nodwarf_summary},
        "recovery_coverage": nd_cov,
        "runtime_sweep_results": nodwarf_results,
    }
    nodwarf_html_path = tmp_path / "nodwarf_report.html"
    write_html([(Path("nodwarf.json"), nodwarf_payload)], nodwarf_html_path)
    nodwarf_html = nodwarf_html_path.read_text(encoding="utf-8")
    assert "function_only // oneshot_address_hooks" in nodwarf_html
    assert str(nd_cov["line_info_notice"]) in nodwarf_html
    assert "recovery coverage by source line" not in nodwarf_html
    assert "fixup_revert" in nodwarf_html
    assert "w=3 (0x000F7FF4)" in nodwarf_html


def test_search_report_attributes_first_hit_in_visit_order():
    scope = build_recovery_coverage_scope(MRAM_DEFERRED_ELF, functions=["tracking_gate"])
    pcs = list(scope["probe_pcs"])
    rows = [
        {"fault_injected": True, "fault_at": i,
         "recovery_state_search": {"state_identity": state},
         "recovery_coverage": {"executed_pcs": pcs}}
        for i, state in enumerate(("later", "earlier"))
    ]
    summary = {"coverage_by_boot": [
        {"boot_index": 1, "state_identity": "earlier"},
        {"boot_index": 2, "state_identity": "later"},
    ]}
    report = summarize_recovery_coverage(rows, scope, state_search_summary=summary)
    assert [r["state_identity"] for r in report["coverage_by_boot"]] == ["earlier", "later"]
    first = report["functions"][0]["first_reached_by"]
    assert (first["boot_index"], first["state_identity"]) == (1, "earlier")
    assert rows[0]["recovery_state_search"]["state_identity"] == "later"
