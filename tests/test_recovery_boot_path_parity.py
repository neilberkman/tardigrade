# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for recovery boot path parity between computed-source and live cuts."""

from __future__ import annotations

import ast
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from recovery_explanation import explain_recovery_failures  # noqa: E402
from recovery_state import PersistentState  # noqa: E402

SWEEP_PATH = SCRIPTS / "run_runtime_fault_sweep.py"
POWER_RESET_CS_PATH = ROOT / "peripherals" / "PowerResetDomain.cs"


def _load_sweep_defs(names: set[str], namespace: dict) -> None:
    source = SWEEP_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SWEEP_PATH))
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    selected.append(node)
                    break
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, str(SWEEP_PATH), "exec"), namespace)


def test_power_reset_domain_enables_released_cpu_time_handles_on_every_reset_path() -> None:
    cs_text = POWER_RESET_CS_PATH.read_text(encoding="utf-8")
    assert "private void EnableReleasedCpuTimeHandles()" in cs_text
    assert "cpu.TimeHandle.Enabled = true;" in cs_text
    for method_header in (
        "public void PowerRestored()",
        "public void Reset()",
        "private void WarmReset(Source source)",
    ):
        start = cs_text.index(method_header)
        end = cs_text.index("\n        }", start)
        body = cs_text[start:end]
        assert "EnableReleasedCpuTimeHandles();" in body, (
            f"{method_header} must re-enable released CPU time handles"
        )


def test_machine_reset_and_prime_bootloader_entry_reenable_time_handles_after_mid_quantum_halt() -> None:
    time_handle_main = SimpleNamespace(Enabled=False)
    time_handle_aux = SimpleNamespace(Enabled=False)
    time_handle_halted = SimpleNamespace(Enabled=False)

    cpu_main = SimpleNamespace(
        IsHalted=False,
        TimeHandle=time_handle_main,
        PC=0,
        SP=SimpleNamespace(RawValue=0),
        VectorTableOffset=0,
        SetRegisterUnsafe=lambda reg, val: None,
        GetRegisterUnsafe=lambda reg: 0x08000101 if reg == 15 else 0x20001000,
    )
    cpu_aux = SimpleNamespace(
        IsHalted=False,
        TimeHandle=time_handle_aux,
    )
    cpu_halted = SimpleNamespace(
        IsHalted=True,
        TimeHandle=time_handle_halted,
    )

    bus = SimpleNamespace(
        GetCPUs=lambda: [cpu_main, cpu_aux, cpu_halted],
        ReadDoubleWord=lambda addr: 0x20001000 if addr == 0x08000000 else 0x08000101,
    )
    machine = {
        "sysbus.cpu": cpu_main,
        "sysbus.cpu_aux": cpu_aux,
        "sysbus.cpu_halted": cpu_halted,
    }
    monitor = SimpleNamespace(
        Machine=machine,
        Parse=lambda cmd: None,
    )

    ns = {
        "_time": time,
        "os": __import__("os"),
        "monitor": monitor,
        "bus": bus,
        "RegisterValue": SimpleNamespace(Create=lambda val, bits: val),
        "as_int": int,
        "fmt_u32": lambda val: f"0x{int(val) & 0xFFFFFFFF:08X}",
        "log": lambda msg: None,
        "bootloader_entry": 0x08000000,
        "sram_start": 0x20000000,
        "sram_end": 0x20010000,
        "platform_repl": "platforms/cortex_m0_mram.repl",
        "backend": {"kind": "mram", "data": SimpleNamespace()},
        "power_domain": None,
        "_machine_selector": "0",
        "refresh_runtime_handles": lambda: None,
        "reset_sticky_handoff_state": lambda: None,
        "_set_preserve_counters_across_reset": lambda flag: None,
        "_configure_tracking_start_address": lambda addr=None: None,
        "_configure_python_tracking_gate": lambda force=False, address=None: None,
        "_clear_sticky_observations": lambda: None,
        "_reinstall_pc_handoff_hooks": lambda: None,
        "_reinstall_function_return_probes": lambda: None,
        "_reinstall_rc_injection_hooks": lambda: None,
        "_reinstall_interrupt_timing_hook": lambda: None,
        "_reinstall_calibration_stop_hook": lambda: None,
    }
    _load_sweep_defs(
        {
            "_RESET_DOMAIN_FAMILIES",
            "_enable_released_cpu_time_handles",
            "_detect_reset_family",
            "_after_machine_reset",
            "_machine_reset",
            "prime_bootloader_entry",
            "load_machine_snapshot",
        },
        ns,
    )

    assert ns["_detect_reset_family"]("platforms/cortex_m0_mram.repl") == "generic"

    # 1. After _machine_reset(), every unhalted CPU's TimeHandle is re-enabled.
    time_handle_main.Enabled = False
    time_handle_aux.Enabled = False
    time_handle_halted.Enabled = False
    ns["_machine_reset"](apply_tracking_gate=False)
    assert time_handle_main.Enabled is True
    assert time_handle_aux.Enabled is True
    assert time_handle_halted.Enabled is False

    # 2. After prime_bootloader_entry(), a mid-quantum disabled TimeHandle is re-enabled.
    time_handle_main.Enabled = False
    time_handle_aux.Enabled = False
    cpu_main.IsHalted = True
    ns["prime_bootloader_entry"]()
    assert cpu_main.IsHalted is False
    assert time_handle_main.Enabled is True
    assert time_handle_aux.Enabled is True

    # 3. After load_machine_snapshot(), released CPUs have TimeHandle re-enabled.
    time_handle_main.Enabled = False
    time_handle_aux.Enabled = False
    ns["load_machine_snapshot"]("/tmp/fake.save")
    assert time_handle_main.Enabled is True
    assert time_handle_aux.Enabled is True


def test_setup_script_runs_on_recovery_with_boot_role_after_snapshot_and_marks_restore(
    tmp_path: Path,
) -> None:
    pre_boot_file = tmp_path / "pre_boot.bin"
    pre_boot_file.write_bytes((0x20000400).to_bytes(4, "little") + (0x12345678).to_bytes(4, "little"))

    events: list[tuple] = []
    monitor_vars: dict[str, str] = {}
    sram_words: dict[int, int] = {}
    mram_storage = bytearray(64)
    uncorrectable_marks: set[int] = set()

    def parse_cmd(cmd: str) -> None:
        cmd_str = cmd.strip()
        if cmd_str.startswith("$") and "=" in cmd_str:
            name, val = cmd_str.split("=", 1)
            monitor_vars[name.strip()] = val.strip()
            return
        if cmd_str.startswith("include @"):
            events.append(
                (
                    "setup_script",
                    dict(ns["get_boot_role"]()),
                    monitor_vars.get("$boot_phase"),
                    monitor_vars.get("$boot_generation"),
                    monitor_vars.get("$boot_source"),
                    monitor_vars.get("$boot_reset_kind"),
                    monitor_vars.get("$boot_cut_index"),
                    bytes(mram_storage[:8]),
                    sorted(uncorrectable_marks),
                )
            )
            return

    class FakeMram:
        Size = 64

        def RestoreSnapshotRaw(self, data: bytes) -> None:
            mram_storage[: len(data)] = data
            events.append(("restore_flash", bytes(mram_storage[:8])))

        def WriteBytes(self, offset: int, data: bytes, start: int = 0, count: int | None = None) -> None:
            length = len(data) if count is None else count
            mram_storage[offset : offset + length] = data[start : start + length]
            events.append(("restore_flash", bytes(mram_storage[:8])))

    def write_dword(addr: int, val: int) -> None:
        sram_words[int(addr)] = int(val)
        events.append(("pre_boot_write", int(addr), int(val)))

    ns = {
        "_time": time,
        "json": __import__("json"),
        "struct": __import__("struct"),
        "integer_types": (int,),
        "_json_safe": lambda v: v,
        "_json_dump_text": lambda v: __import__("json").dumps(v, sort_keys=True),
        "fmt_u32": lambda val: f"0x{int(val) & 0xFFFFFFFF:08X}",
        "as_int": int,
        "log": lambda msg: None,
        "monitor": SimpleNamespace(Parse=parse_cmd),
        "bus": SimpleNamespace(
            WriteDoubleWord=write_dword,
            ReadDoubleWord=lambda addr: sram_words.get(int(addr), 0),
        ),
        "backend": {"kind": "mram", "data": FakeMram()},
        "boundary_phase": "",
        "pre_boot_bin": str(pre_boot_file),
        "setup_script": "examples/recovery_boot_path_parity/setup.resc",
        "update_sequence_enabled": False,
        "enable_machine_snapshots": False,
        "reset_mode": "warm",
        "bootloader_elf": "firmware.elf",
        "_cached_recovery_snapshot_path": None,
        "_last_recovery_setup_detail": None,
        "apply_boundary_setup_environment": lambda: None,
        "_capture_recovery_marker_precondition": lambda: events.append(("capture_precondition",)),
        "_machine_reset": lambda apply_tracking_gate=True: events.append(("machine_reset",)),
        "_clear_volatile_memory": lambda: (sram_words.clear(), events.append(("clear_volatile",))),
        "_verify_recovery_marker_cleared": lambda: events.append(("verify_marker_cleared",)),
        "_bus_load_elf": lambda path: events.append(("load_elf", path)),
        "restore_hw_init": lambda: events.append(("restore_hw_init",)),
        "_clear_mram_uncorrectable_words": lambda: (
            uncorrectable_marks.clear(),
            events.append(("clear_uncorrectable",)),
        ),
        "_restore_mram_uncorrectable_offsets": lambda offsets: (
            uncorrectable_marks.update(int(o) for o in offsets),
            events.append(("restore_uncorrectable", sorted(uncorrectable_marks))),
        ),
        "prime_bootloader_entry": lambda: events.append(("prime_bootloader_entry",)),
    }
    _load_sweep_defs(
        {
            "_FAULT_NAME_TO_CODE",
            "_set_monitor_hook_var",
            "_build_boot_role_cut",
            "_copy_boot_role",
            "get_boot_role",
            "_sync_boot_role_globals",
            "_sync_boot_role_reset_kind",
            "_set_boot_role",
            "_export_boot_role_to_monitor",
            "apply_pre_boot_state",
            "prepare_recovery_shell_state",
            "restore_flash_and_boot",
        },
        ns,
    )

    # First-operation boot: setup_script runs with first_operation role, then pre_boot_state, then prime_bootloader_entry.
    ns["apply_pre_boot_state"]()
    setup_events = [e for e in events if e[0] == "setup_script"]
    assert len(setup_events) == 1
    first_role = setup_events[0][1]
    assert first_role["phase"] == "first_operation"
    assert first_role["generation"] == 0
    assert first_role["source"] == "live_injection"
    assert first_role["is_computed_source"] is False
    assert first_role["is_live_injection"] is True
    assert first_role["preceding_cut"] is None
    assert first_role["preceding_cuts"] == []
    assert first_role["reset_kind"] == "power_on"
    assert [e[0] for e in events] == [
        "setup_script",
        "pre_boot_write",
        "prime_bootloader_entry",
    ]

    # Recovery boot: reset -> clear volatile -> restore flash & uncorrectable marks -> setup_script -> prime_bootloader_entry.
    events.clear()
    cut_record = {
        "cut": 1,
        "operation": "write",
        "operation_index": 3,
        "fault_type": "w",
        "address": "0x00004010",
    }
    ns["_set_boot_role"](
        phase="recovery",
        generation=1,
        source="computed_source",
        preceding_cut=cut_record,
        preceding_cuts=[cut_record],
        reset_kind="power_loss",
        cycle=0,
    )
    ns["_pending_recovery_uncorrectable_offsets"] = [16]
    faulted_image = b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44" + bytes(56)
    ns["restore_flash_and_boot"](faulted_image)

    event_names = [e[0] for e in events]
    assert event_names == [
        "capture_precondition",
        "machine_reset",
        "clear_volatile",
        "verify_marker_cleared",
        "load_elf",
        "restore_hw_init",
        "restore_flash",
        "clear_uncorrectable",
        "restore_uncorrectable",
        "setup_script",
        "prime_bootloader_entry",
    ]
    assert "pre_boot_write" not in event_names
    rec_setup = next(e for e in events if e[0] == "setup_script")
    rec_role = rec_setup[1]
    assert rec_role["phase"] == "recovery"
    assert rec_role["generation"] == 1
    assert rec_role["source"] == "computed_source"
    assert rec_role["is_computed_source"] is True
    assert rec_role["is_live_injection"] is False
    assert rec_role["reset_kind"] == "power_loss"
    assert rec_role["preceding_cut"]["operation"] == "write"
    assert rec_role["preceding_cut"]["operation_index"] == 3
    assert rec_role["preceding_cut"]["fault_type"] == "power_loss"
    assert rec_role["preceding_cut"]["address"] == "0x00004010"
    assert rec_setup[2] == '"recovery"'
    assert rec_setup[3] == "1"
    assert rec_setup[4] == '"computed_source"'
    assert rec_setup[5] == '"power_loss"'
    assert rec_setup[6] == "3"
    # Persistent bytes and uncorrectable marks were already restored before setup_script ran!
    assert rec_setup[7] == b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44"
    assert rec_setup[8] == [16]


def test_computed_source_and_live_recovery_boots_share_identical_hook_sequence_and_boot_role() -> None:
    def run_recovery_path(mode: str) -> tuple[list[tuple[str, dict]], dict]:
        trace: list[tuple[str, dict]] = []
        mram_bytes = bytearray(64)
        marks: set[int] = set()
        time_handle = SimpleNamespace(Enabled=False)
        cpu = SimpleNamespace(
            IsHalted=False,
            TimeHandle=time_handle,
            PC=0x10000000,
            SP=SimpleNamespace(RawValue=0x20001000),
            VectorTableOffset=0x10000000,
            SetRegisterUnsafe=lambda reg, val: None,
            GetRegisterUnsafe=lambda reg: 0x10000021 if reg == 15 else 0x20001000,
        )

        class FakeMram:
            Size = 64
            ProgramUnitSize = 8
            WordSize = 8
            EraseFill = 0x00
            TotalWordWrites = 1
            TotalPageErases = 0
            FaultEverFired = True
            EraseFaultFired = False
            LastFaultInjected = True
            FaultEvidenceExact = True
            LastFaultWriteIndex = 1
            LastFaultProgramAddress = 0x10000008
            LastFaultOffset = 8
            LastFaultProgramWidth = 8
            LastFaultIntendedBytes = "1122334455667788"
            LastFaultPreProgramBytes = "0000000000000000"
            LastFaultPostFaultBytes = "1122334400000000"
            FaultMemorySnapshot = bytes(
                b"\x00" * 8 + b"\x11\x22\x33\x44\x00\x00\x00\x00" + b"\x00" * 48
            )
            ProgramTraceCount = 1
            EraseTraceCount = 0
            EraseTraceEnabled = False

            def ProgramTraceClear(self) -> None:
                pass

            def EraseTraceClear(self) -> None:
                pass

            def ProgramTraceToString(self) -> str:
                return "1:8:8:1122334455667788:0000000000000000:1122334400000000:1:0x10000010"

            def EraseTraceToString(self) -> str:
                return ""

            def RestoreSnapshotRaw(self, data: bytes) -> None:
                mram_bytes[: len(data)] = data
                trace.append(("restore_snapshot", dict(ns["get_boot_role"]())))

            def ReadBytes(self, offset: int, count: int) -> bytes:
                return bytes(mram_bytes[offset : offset + count])

            def WriteBytes(self, offset: int, data: bytes, start: int = 0, count: int | None = None) -> None:
                length = len(data) if count is None else count
                mram_bytes[offset : offset + length] = data[start : start + length]
                trace.append(("restore_snapshot", dict(ns["get_boot_role"]())))

        fake_mram = FakeMram()

        def parse_cmd(cmd: str) -> None:
            cmd_str = cmd.strip()
            if cmd_str.startswith("include @"):
                role = ns["get_boot_role"]()
                if role["phase"] == "recovery":
                    trace.append(("setup_script", dict(role)))

        def collect_semantic_state(context: dict):
            enriched = ns["_enrich_context_with_boot_role"](context)
            role = dict(enriched["boot_role"])
            stage = f"state_probe:{enriched.get('stage')}:cycle={enriched.get('cycle', 0)}"
            trace.append((stage, role))
            return {"stage": enriched.get("stage"), "boot_role": role}

        def run_boot_cycle_hook(cycle_index: int, cycle_records: list):
            role = dict(ns["get_boot_role"]())
            trace.append((f"boot_cycle_hook:cycle={cycle_index}", role))

        def run_until_done(cpu_ref, *, label: str, **kwargs):
            role = dict(ns["get_boot_role"]())
            if role["phase"] == "recovery":
                assert cpu_ref.TimeHandle.Enabled is True
                trace.append((f"run_recovery_cpu:cycle={role['cycle']}", role))
            else:
                # Simulate mid-quantum halt on phase 1 cut
                cpu_ref.TimeHandle.Enabled = False
            return {"reason": "fault_fired" if "_p1" in label else "vtor_captured", "iters": 1, "emulated_s": 0.01}

        ns = {
            "_time": time,
            "os": __import__("os"),
            "json": __import__("json"),
            "struct": __import__("struct"),
            "integer_types": (int,),
            "_json_safe": lambda v: v,
            "_json_dump_text": lambda v: __import__("json").dumps(v, sort_keys=True),
            "fmt_u32": lambda val: f"0x{int(val) & 0xFFFFFFFF:08X}",
            "as_int": int,
            "to_py_bytes": bytes,
            "to_clr_bytes": bytes,
            "log": lambda msg: None,
            "RegisterValue": SimpleNamespace(Create=lambda val, bits: val),
            "monitor": SimpleNamespace(
                Machine={"sysbus.cpu": cpu},
                Parse=parse_cmd,
            ),
            "bus": SimpleNamespace(
                GetCPUs=lambda: [cpu],
                ReadDoubleWord=lambda addr: 0x20001000 if addr == 0x10000000 else 0x10000021,
                WriteDoubleWord=lambda addr, val: None,
            ),
            "backend": {
                "kind": "mram",
                "data": fake_mram,
                "bus_base": 0x10000000,
                "supports_i2c_fault": False,
                "i2c_fault_reason": "",
                "supports_otp_fault": False,
                "otp_fault_reason": "",
                "supports_command_fault": False,
                "command_fault_reason": "",
            },
            "power_domain": None,
            "bootloader_entry": 0x10000000,
            "bootloader_elf": "firmware.elf",
            "sram_start": 0x20000000,
            "sram_end": 0x20010000,
            "slot_exec_base": 0x10000000,
            "slot_exec_size": 0x1000,
            "slot_staging_base": 0x10001000,
            "slot_staging_size": 0x1000,
            "slot_ranges": {"exec": (0x10000000, 0x10001000)},
            "success_marker_addr": 0,
            "boundary_phase": "",
            "pre_boot_bin": "",
            "setup_script": "examples/recovery_boot_path_parity/setup.resc",
            "update_sequence_enabled": False,
            "enable_machine_snapshots": False,
            "reset_mode": "warm",
            "_cached_recovery_snapshot_path": None,
            "_last_recovery_setup_detail": None,
            "_last_phase1_setup_detail": None,
            "_hash_bypass_active": False,
            "boot_cycles": 2,
            "phase2_time_slice": "0.01",
            "phase2_wall_timeout_s": 5.0,
            "max_writes_cap": 100,
            "tracking_start_address_config": 0,
            "recovery_tracking_start_address": None,
            "phase2_state_search": {"enabled": True, "max_cuts": 1},
            "mram_torn_word": "half",
            "mram_torn_word_choices": [],
            "mram_torn_word_seed": 0,
            "torn_word": "half",
            "torn_word_explicit": False,
            "torn_word_choices": [],
            "torn_word_seed": 0,
            "postmortem_dump_no_boot": False,
            "resume_trace_no_boot": False,
            "metadata_delta_enabled": False,
            "durability_model": "direct",
            "writeback_active": lambda: False,
            "apply_boundary_setup_environment": lambda: None,
            "_capture_recovery_marker_precondition": lambda: None,
            "_machine_reset": lambda apply_tracking_gate=True: (
                ns["_before_machine_reset"](),
                ns["_after_machine_reset"](),
                trace.append(("machine_reset", dict(ns["get_boot_role"]())))
                if ns["get_boot_role"]()["phase"] == "recovery"
                else None,
            ),
            "_clear_volatile_memory": lambda: (
                trace.append(("clear_volatile", dict(ns["get_boot_role"]())))
                if ns["get_boot_role"]()["phase"] == "recovery"
                else None
            ),
            "_verify_recovery_marker_cleared": lambda: None,
            "_bus_load_elf": lambda path: None,
            "restore_hw_init": lambda: None,
            "_clear_mram_uncorrectable_words": lambda: marks.clear(),
            "_restore_mram_uncorrectable_offsets": lambda offsets: (
                marks.update(int(o) for o in offsets),
                trace.append(("restore_uncorrectable", dict(ns["get_boot_role"]())))
                if (offsets and ns["get_boot_role"]()["phase"] == "recovery")
                else None,
            ),
            "_snapshot_mram_fault_uncorrectable_offsets": lambda: [8],
            "_snapshot_mram_fault_uncorrectable_addresses": lambda: ["0x10000008"],
            "_snapshot_mram_uncorrectable_offsets": lambda: sorted(marks),
            "_snapshot_mram_uncorrectable_addresses": lambda: [
                f"0x{0x10000000 + o:08X}" for o in sorted(marks)
            ],
            "_clear_mram_uncorrectable_read_log": lambda: None,
            "_mram_uncorrectable_target": lambda: fake_mram,
            "_attach_uncorrectable_read_signals": lambda *a, **k: None,
            "restore_phase1_baseline": lambda: (
                ns["_reset_trial_boot_history"]("power_on"),
                ns["_before_machine_reset"](),
                ns["_after_machine_reset"](),
                ns["_set_boot_role"](
                    phase="first_operation",
                    generation=0,
                    source="live_injection",
                    preceding_cut=None,
                    preceding_cuts=(),
                    reset_kind="power_on",
                    cycle=0,
                ),
            ),
            "capture_metadata_delta_snapshot": lambda: None,
            "annotate_result_metadata_delta": lambda *a, **k: None,
            "_metadata_delta_marker_written": lambda sig: False,
            "reset_verification_probes": lambda: None,
            "reset_rc_injection_state": lambda enabled=False: None,
            "_fault_uses_rc_injection_return_hook": lambda ft: False,
            "_select_point_mram_torn_word": lambda idx: None,
            "_select_point_torn_word": lambda idx: None,
            "_record_point_mram_torn_word": lambda res, tw: None,
            "_record_point_torn_word": lambda res, tw: None,
            "reset_nvmc_for_sweep": lambda tracking_start=None: None,
            "reset_nvmc_for_recovery": lambda tracking_start=0: trace.append(
                ("reset_nvmc_for_recovery", dict(ns["get_boot_role"]()))
            ),
            "_recovery_tracking_start": lambda inherit_first_gate=True: 0,
            "get_total_writes": lambda: 1,
            "get_total_erases": lambda: 0,
            "arm_fault": lambda arm_at, write_fault_mode=0: None,
            "disarm_fault": lambda: None,
            "disarm_erase_fault": lambda: None,
            "arm_vtor_watchpoint": lambda: None,
            "disarm_vtor_watchpoint": lambda: None,
            "phase1_wall_timeout": lambda default_s=4.0: default_s,
            "phase1_max_iters": lambda default_s=4.0: 10,
            "_copy_on_boot_vtor_settle_iters": lambda: 0,
            "run_until_done": run_until_done,
            "was_fault_injected": lambda: True,
            "get_last_write_address": lambda: 0x10000008,
            "get_last_fault_pc": lambda: 0x10000010,
            "get_last_fault_call_context": lambda: "0x10000010",
            "collect_mram_fault_evidence": lambda sel, exp: (
                {
                    "exact": True,
                    "program_address": "0x10000008",
                    "fault_pc": "0x10000010",
                    "fault_call_context": "0x10000010",
                },
                bytearray(fake_mram.FaultMemorySnapshot),
                fake_mram.FaultMemorySnapshot,
            ),
            "get_effective_criteria": lambda ft: {"vtor_in_slot": "exec"},
            "evaluate_boot_outcome": lambda *a, **k: ("success", "exec", {}),
            "merge_stop_status_signals": lambda *a, **k: None,
            "collect_semantic_state": collect_semantic_state,
            "run_boot_cycle_hook": run_boot_cycle_hook,
            "analyze_boot_cycles": lambda recs: {"final_outcome": "success", "cycles": len(recs)},
            "set_multiboot_cycles_run": lambda sig, recs: None,
            "classify_fault_result": lambda *a, **k: "recoverable",
            "analyze_fault_snapshot": lambda *a, **k: {"sha256": "00"},
            "persist_fault_snapshot": lambda *a, **k: None,
            "collect_verification_probe_telemetry": lambda: (None, None, None),
            "collect_function_return_probe_telemetry": lambda: None,
            "collect_terminal_error_telemetry": lambda *a, **k: None,
            "merge_verification_probe_signals": lambda sig: None,
            "merge_function_return_probe_signals": lambda sig: None,
            "merge_terminal_error_signals": lambda sig, *a, **k: None,
            "attach_verification_probe_fields": lambda res: None,
            "attach_function_return_probe_fields": lambda res: None,
            "attach_terminal_error_fields": lambda res, *a, **k: None,
            "attach_rc_injection_fields": lambda res, sig: None,
            "_apply_rc_injection_result_contract": lambda *a, **k: None,
            "_attach_function_return_probe_result_fields": lambda *a, **k: None,
            "_encode_pre_recovery_state": lambda *a, **k: None,
            "_attach_result_recovery_coverage": lambda *a, **k: None,
            "annotate_boot_span_result": lambda r: r,
            "annotate_update_sequence_result": lambda r: r,
            "_finalize_recovery_marker_precondition_result": lambda r: r,
            "_state_search_begin_observation": lambda: (None, None),
            "_state_search_timestamp": lambda ops, clk: None,
            "_set_next_reset_kind": lambda kind: ns.__setitem__("_next_reset_kind", kind),
            "_TRACE_REPLAY_WRITE_FAULT_TYPES": frozenset(("b", "s", "g", "x", "d", "l", "r")),
            "_I2C_WIRE_CODE_TO_FAULT_TYPE": {},
            "_OTP_WIRE_CODES": frozenset(),
            "_WRITE_FAULT_MODE": {"w": 0},
        }
        _load_sweep_defs(
            {
                "_FAULT_NAME_TO_CODE",
                "_base_fault_type_code",
                "_reset_trial_boot_history",
                "_sync_boot_reset_kinds_from_domain",
                "_before_machine_reset",
                "_after_machine_reset",
                "_set_monitor_hook_var",
                "_build_boot_role_cut",
                "_copy_boot_role",
                "get_boot_role",
                "_sync_boot_role_globals",
                "_sync_boot_role_reset_kind",
                "_set_boot_role",
                "_export_boot_role_to_monitor",
                "_enrich_context_with_boot_role",
                "_enable_released_cpu_time_handles",
                "prime_bootloader_entry",
                "prepare_recovery_shell_state",
                "restore_flash_and_boot",
                "build_cycle_record",
                "_boot_followup_cycle",
                "_continue_followup_boot_cycles",
                "run_followup_boot_cycles",
                "_build_fault_result",
                "run_execute_fault",
                "_state_search_trace_target",
                "_state_search_should_capture_trace",
                "_state_search_mark_addresses",
                "_state_search_resolve_recovery_trace",
                "_state_search_boot_state",
            },
            ns,
        )

        # Normalize duplicate restore_uncorrectable calls after restore_flash_and_boot
        if mode == "computed_source":
            state = PersistentState.from_bytes(
                bytearray(fake_mram.FaultMemorySnapshot),
                name="nvm",
                base_address=0x10000000,
                uncorrectable_words=(("nvm", 8),),
            )
            chain = [
                {
                    "cut": 1,
                    "operation": "write",
                    "operation_index": 0,
                    "fault_type": "power_loss",
                    "address": "0x10000008",
                    "pc": "0x10000010",
                    "call_context": "0x10000010",
                }
            ]
            result, _, _ = ns["_state_search_boot_state"](state, chain, 1)
        else:
            result = ns["run_execute_fault"](0, fault_type="w")

        # Collapse idempotent back-to-back restore_uncorrectable events for sequence comparison
        filtered: list[tuple[str, dict]] = []
        for name, role in trace:
            if name == "restore_uncorrectable" and any(n == "restore_uncorrectable" and r["cycle"] == role["cycle"] for n, r in filtered):
                continue
            filtered.append((name, role))
        return filtered, result

    computed_trace, computed_result = run_recovery_path("computed_source")
    live_trace, live_result = run_recovery_path("live_injection")

    computed_steps = [step for step, _ in computed_trace]
    live_steps = [step for step, _ in live_trace]
    assert computed_steps == live_steps == [
        "machine_reset",
        "clear_volatile",
        "restore_snapshot",
        "restore_uncorrectable",
        "setup_script",
        "state_probe:fault_snapshot:cycle=0",
        "reset_nvmc_for_recovery",
        "run_recovery_cpu:cycle=0",
        "state_probe:boot_cycle:cycle=0",
        "boot_cycle_hook:cycle=1",
        "machine_reset",
        "clear_volatile",
        "restore_snapshot",
        "restore_uncorrectable",
        "setup_script",
        "reset_nvmc_for_recovery",
        "run_recovery_cpu:cycle=1",
        "state_probe:boot_cycle:cycle=1",
        "state_probe:post_boot:cycle=0",
    ]

    for (comp_step, comp_role), (live_step, live_role) in zip(computed_trace, live_trace):
        assert comp_step == live_step
        assert comp_role["phase"] == live_role["phase"] == "recovery"
        assert comp_role["generation"] == live_role["generation"] == 1
        assert comp_role["reset_kind"] == live_role["reset_kind"]
        assert comp_role["cycle"] == live_role["cycle"]
        assert comp_role["preceding_cut"]["operation"] == live_role["preceding_cut"]["operation"] == "write"
        assert comp_role["preceding_cut"]["operation_index"] == live_role["preceding_cut"]["operation_index"] == 0
        assert comp_role["preceding_cut"]["address"] == live_role["preceding_cut"]["address"] == "0x10000008"
        assert comp_role["source"] == "computed_source"
        assert comp_role["is_computed_source"] is True
        assert comp_role["is_live_injection"] is False
        assert live_role["source"] == "live_injection"
        assert live_role["is_computed_source"] is False
        assert live_role["is_live_injection"] is True

    assert computed_result["boot_role"]["source"] == "computed_source"
    assert live_result["boot_role"]["source"] == "live_injection"
    assert computed_result["signals"]["boot_reset_kinds"] == ["power_on", "power_loss", "warm"]
    assert live_result["signals"]["boot_reset_kinds"] == ["power_on", "power_loss", "warm"]


def test_recovery_explanation_passes_boot_role_to_state_probe_describe_ranges() -> None:
    seen_contexts: list[dict] = []

    class ProbeWithBootRole:
        @staticmethod
        def describe_ranges(context: dict):
            seen_contexts.append(dict(context))
            return [
                {
                    "start": 0x10000000,
                    "end": 0x10000008,
                    "name": f"{context['boot_phase']}_g{context['boot_generation']}_{context['boot_source']}",
                }
            ]

    rows = [
        {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "no_boot",
            "fault_class": "unrecoverable",
            "signals": {
                "trace_replay_mode": "computed_recovery_state",
                "recovery_state_generation": 2,
                "pc": "0x10000010",
            },
            "recovery_state_search": {
                "generation": 2,
                "state_identity": "bad",
                "chain": {
                    "cuts": [
                        {"operation": "write", "operation_index": 0, "fault_type": "power_loss", "address": "0x10000000"},
                        {"operation": "write", "operation_index": 1, "fault_type": "power_loss", "address": "0x10000004"},
                    ]
                },
            },
            "fault_snapshot": {
                "sha256": "11" * 32,
                "identity_slot_base": "0x10000000",
                "identity_slot_extent": 64,
                "closest_declared_image": {
                    "name": "exec",
                    "sha256": "aa" * 32,
                    "ranges_truncated": False,
                    "differing_bytes": 4,
                    "differing_range_count": 1,
                    "differing_ranges": [
                        {
                            "address": "0x10000000",
                            "size": 4,
                            "actual_hex": "deadbeef",
                            "expected_hex": "00000000",
                            "bytes_truncated": False,
                        }
                    ],
                },
            },
        },
        {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "rs",
            "fault_injected": True,
            "boot_outcome": "success",
            "fault_class": "recoverable",
            "signals": {
                "trace_replay_mode": "computed_recovery_state",
                "recovery_state_generation": 2,
            },
            "recovery_state_search": {
                "generation": 2,
                "state_identity": "good",
                "chain": {
                    "cuts": [
                        {"operation": "write", "operation_index": 0, "fault_type": "power_loss", "address": "0x10000000"},
                        {"operation": "write", "operation_index": 2, "fault_type": "power_loss", "address": "0x10000008"},
                    ]
                },
            },
            "fault_snapshot": {
                "sha256": "22" * 32,
                "identity_slot_base": "0x10000000",
                "identity_slot_extent": 64,
                "closest_declared_image": {
                    "name": "exec",
                    "sha256": "aa" * 32,
                    "ranges_truncated": False,
                    "differing_bytes": 0,
                    "differing_range_count": 0,
                    "differing_ranges": [],
                },
            },
        },
    ]

    explain_recovery_failures(
        rows,
        expected="success",
        elf=None,
        root=ROOT,
        flash_base=0x10000000,
        state_probe=ProbeWithBootRole(),
    )

    assert len(seen_contexts) == 1
    ctx = seen_contexts[0]
    role = ctx["boot_role"]
    assert role["phase"] == "recovery"
    assert role["generation"] == 2
    assert role["source"] == "computed_source"
    assert role["is_computed_source"] is True
    assert role["is_live_injection"] is False
    assert role["reset_kind"] == "power_loss"
    assert len(role["preceding_cuts"]) == 2
    assert role["preceding_cut"]["operation_index"] == 1
    assert rows[0]["failure_explanation"]["state_comparison"]["ranges"][0]["field"] == (
        "recovery_g2_computed_source"
    )
