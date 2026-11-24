from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"
FIXTURE = ROOT / "examples" / "recovery_vector_fault"


def _load_runtime_function(name: str, namespace: dict):
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"))
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(RUNTIME), "exec"), namespace)
    return namespace[name]


class _Register:
    def __init__(self, value: int):
        self.RawValue = value


class _CPU:
    def __init__(self):
        self.SP = _Register(0x20002000)
        self.PC = _Register(0x10000041)
        self.IsHalted = True

    def GetRegisterUnsafe(self, number: int):
        assert number == 15
        return self.PC.RawValue


class _RegisterValue:
    @staticmethod
    def Create(value: int, width: int):
        assert width == 32
        return _Register(value)


def test_faulted_zero_vector_replaces_clean_shell_registers_and_halts():
    entry = 0x10000000
    cpu = _CPU()
    bus = SimpleNamespace(
        ReadDoubleWord=lambda address: {
            entry: 0,
            entry + 4: 0,
            0xE000ED08: 0,
        }[address]
    )
    monitor = SimpleNamespace(
        Machine={"sysbus.cpu": cpu},
        Parse=lambda command: None,
    )
    namespace = {
        "as_int": int,
        "bootloader_entry": entry,
        "bus": bus,
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "monitor": monitor,
        "RegisterValue": _RegisterValue,
        "_recovery_zero_vector_guard": False,
    }

    prime = _load_runtime_function("prime_bootloader_entry", namespace)
    prime()

    assert cpu.SP.RawValue == 0
    assert cpu.PC.RawValue == 0
    assert cpu.IsHalted is True
    assert namespace["_recovery_zero_vector_guard"] is True


def test_recovery_primes_only_after_faulted_flash_overlay():
    source = RUNTIME.read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {
        node.name: ast.get_source_segment(source, node)
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    restore = functions["restore_flash_and_boot"]
    assert restore.rfind("prime_bootloader_entry()") > restore.find("WriteBytes")
    assert "prime_bootloader_entry()" not in functions["prepare_recovery_shell_state"]
    assert "if _recovery_zero_vector_guard:" in functions["run_until_done"]
    assert "'reason': 'no_boot_zero_vectors'" in functions["run_until_done"]


def test_fixture_programs_reset_vector_as_its_only_tracked_write():
    firmware = (FIXTURE / "firmware.c").read_text(encoding="utf-8")
    profile = (FIXTURE / "profile.yaml").read_text(encoding="utf-8")

    assert "vectors[1] = ((uintptr_t)Brick_Handler) | 1u;" in firmware
    assert "vectors[1] = ((uintptr_t)Reset_Handler) | 1u;" in firmware
    assert firmware.index("NVMC_CONFIG = 1u") < firmware.index(
        "vectors[1] = ((uintptr_t)Reset_Handler) | 1u;"
    )
    assert "sweep_strategy: exhaustive" in profile
    assert "max_writes_cap: 4" in profile
    assert (FIXTURE / "firmware.elf").stat().st_size < 64 * 1024
    assert (FIXTURE / "firmware.bin").stat().st_size < 1024


def _load_runtime_functions(*names: str, namespace: dict):
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"))
    wanted = set(names)
    nodes = [
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name in wanted
    ]
    found = {item.name for item in nodes}
    assert found == wanted, f"missing functions: {sorted(wanted - found)}"
    module = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(RUNTIME), "exec"), namespace)
    return namespace


def test_erased_reset_and_hardfault_vector_halts_as_lockup():
    entry = 0x10000000
    cpu = _CPU()
    bus = SimpleNamespace(
        ReadDoubleWord=lambda address: {
            entry: 0x20002000,
            entry + 4: 0xFFFFFFFF,
            entry + 12: 0xFFFFFFFF,
            entry + 24: 0xFFFFFFFF,
            0xE000ED08: entry,
        }[address]
    )
    nvic = SimpleNamespace(SetLockupState=lambda value: None)
    monitor = SimpleNamespace(
        Machine={"sysbus.cpu": cpu, "sysbus.nvic": nvic},
        Parse=lambda command: None,
    )
    namespace = {
        "as_int": int,
        "bootloader_entry": entry,
        "bus": bus,
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "monitor": monitor,
        "RegisterValue": _RegisterValue,
        "_recovery_zero_vector_guard": False,
        "_recovery_erased_vector_lockup": None,
    }

    prime = _load_runtime_function("prime_bootloader_entry", namespace)
    prime()

    assert cpu.PC.RawValue == 0xFFFFFFFF
    assert cpu.IsHalted is True
    assert namespace["_recovery_zero_vector_guard"] is False
    obs = namespace["_recovery_erased_vector_lockup"]
    assert isinstance(obs, dict)
    assert obs["detected"] is True
    assert obs["erased_vector_lockup"] is True
    assert obs["exception"] == 3
    assert obs["vector"] == "0xFFFFFFFF"


def test_erased_reset_with_valid_hardfault_only_guards_renode_16_erased_usagefault():
    entry = 0x10000000
    mem = {
        entry: 0x20002000,
        entry + 4: 0xFFFFFFFF,
        entry + 12: 0x10000041,
        entry + 24: 0xFFFFFFFF,
        0xE000ED08: entry,
    }
    bus = SimpleNamespace(ReadDoubleWord=lambda address: mem[address])

    # Renode 1.16.1-like NVIC (no SetLockupState): UsageFault vector 0xFFFFFFFF
    # would loop forever, so prime_bootloader_entry guards it.
    cpu16 = _CPU()
    ns16 = {
        "as_int": int,
        "bootloader_entry": entry,
        "bus": bus,
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "monitor": SimpleNamespace(
            Machine={"sysbus.cpu": cpu16, "sysbus.nvic": SimpleNamespace()},
            Parse=lambda command: None,
        ),
        "RegisterValue": _RegisterValue,
        "_recovery_zero_vector_guard": False,
        "_recovery_erased_vector_lockup": None,
    }
    _load_runtime_function("prime_bootloader_entry", ns16)()
    assert cpu16.IsHalted is True
    assert ns16["_recovery_erased_vector_lockup"]["erased_vector_lockup"] is True

    # Renode 1.17.0-like NVIC (has SetLockupState): valid HardFault vector can run.
    cpu17 = _CPU()
    ns17 = {
        "as_int": int,
        "bootloader_entry": entry,
        "bus": bus,
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "monitor": SimpleNamespace(
            Machine={
                "sysbus.cpu": cpu17,
                "sysbus.nvic": SimpleNamespace(SetLockupState=lambda v: None),
            },
            Parse=lambda command: None,
        ),
        "RegisterValue": _RegisterValue,
        "_recovery_zero_vector_guard": False,
        "_recovery_erased_vector_lockup": None,
    }
    _load_runtime_function("prime_bootloader_entry", ns17)()
    assert cpu17.IsHalted is False
    assert ns17["_recovery_erased_vector_lockup"] is None


def test_runtime_erased_vector_and_real_lockup_classify_identically():
    import time as _time

    def _run_scenario(mode: str, allow_fault_after_success: bool = False):
        state = {
            "pc": 0x10000040,
            "vtor": 0x10000000,
            "ipsr": 0,
            "insns": 10,
            "pending": None,
            "acked": 0,
            "irq_hooks": [],
        }
        vectors = {
            0x10000000: 0x20002000,
            0x10000004: 0x10000041,
            0x1000000C: 0xFFFFFFFF if mode == "erased_hf" else 0x10000061,
            0x10000014: 0x10000061,
            0x10000018: 0xFFFFFFFF if mode == "erased_hf" else 0x10000061,
        }

        class FakeNvic:
            def FindPendingInterrupt(self):
                return state["pending"]

            def AcknowledgeIRQ(self):
                state["acked"] += 1
                p = state["pending"]
                state["pending"] = None
                return p

            def SetLockupState(self, value):
                pass

        class FakeCpu:
            IsHalted = False
            IsLockedUp = False
            Model = "cortex-m0+"

            @property
            def ExecutedInstructions(self):
                return state["insns"]

            @property
            def PC(self):
                return state["pc"]

            @property
            def XProgramStatusRegister(self):
                return state["ipsr"]

            def GetRegisterUnsafe(self, idx):
                assert idx == 15
                return state["pc"]

            def AddHookAtInterruptBegin(self, cb):
                state["irq_hooks"].append(cb)

        cpu = FakeCpu()
        nvic = FakeNvic()

        class FakeBus:
            def ReadDoubleWord(self, addr):
                if addr == 0xE000ED08:
                    return state["vtor"]
                if addr in (0xE000ED28, 0xE000ED2C):
                    return 0
                return vectors.get(int(addr), 0)

        def parse_cmd(cmd: str):
            if not cmd.startswith("emulation RunFor"):
                return
            if mode == "erased_hf":
                state["insns"] += 5
                state["pending"] = 3
                for cb in list(state["irq_hooks"]):
                    cb(5)
            elif mode == "real_lockup":
                state["insns"] += 5
                state["pc"] = 0xEFFFFFFE
                state["ipsr"] = 3
                cpu.IsLockedUp = True
            elif mode == "exc_return_zero_progress":
                state["pc"] = 0xFFFFFFFE
                state["ipsr"] = 3

        machine = {"sysbus.cpu": cpu, "sysbus.nvic": nvic}
        ns = {
            "_time": _time,
            "as_int": int,
            "fmt_u32": lambda v: "0x{:08X}".format(int(v) & 0xFFFFFFFF),
            "log": lambda msg: None,
            "bus": FakeBus(),
            "monitor": SimpleNamespace(Machine=machine, Parse=parse_cmd),
            "slot_ranges": {"exec": (0x10000000, 0x10001000)},
            "sram_start": 0x20000000,
            "sram_end": 0x20002000,
            "sticky_vtor": {"captured": False, "value": 0, "slot": None},
            "sticky_pc": {"captured": False, "value": 0, "slot": None},
            "success_vtor_slot": "exec",
            "success_pc_slot": "",
            "success_vector_offset": 0,
            "success_image_hash": False,
            "success_image_hash_slot": "",
            "success_marker_addr": 0,
            "success_marker_value": 0,
            "success_otadata_expect": {},
            "success_otadata_expect_scope": "always",
            "success_allow_fault_after_success": allow_fault_after_success,
            "success_terminal_after_reset": False,
            "security_anti_rollback": False,
            "max_reset_vector_offset": None,
            "allowed_image_hashes": [],
            "expected_exec_sha256": "",
            "image_exec_sha256": "",
            "image_staging_sha256": "",
            "expect_control_outcome": "success",
            "phase1_time_slice": "0.02",
            "max_step_limit": 100000,
            "progress_stall_timeout_s": 0.2,
            "no_boot_zero_write_slices": 10,
            "no_boot_min_emulated_s": 0.1,
            "calibration_mode": False,
            "_calibration_stop_state": {},
            "calibration_stop_address": 0,
            "_recovery_zero_vector_guard": False,
            "_recovery_erased_vector_lockup": (
                {
                    "detected": True,
                    "erased_vector_lockup": True,
                    "architectural_lockup": False,
                    "exception": 3,
                    "vector": "0xFFFFFFFF",
                    "vtor": "0x10000000",
                    "pc": "0xFFFFFFFF",
                    "ipsr": 3,
                    "instructions": 0,
                    "source": "prime_bootloader_entry",
                }
                if mode == "boot_erased_reset"
                else None
            ),
            "get_total_writes": lambda: 0,
            "get_total_erases": lambda: 0,
            "capture_console_state": lambda include_recent=False: {},
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "capture_sticky_pc": lambda pc: None,
            "_calibration_success_stop_observation": lambda *a, **kw: None,
            "_reset_gated_success_stop_observation": lambda *a, **kw: None,
            "collect_otadata_signals": lambda: {},
            "evaluate_structured_success_checks": lambda: {"requested": False, "all_ok": True},
            "capture_boot_registers": lambda: None,
            "boot_outcome_after_stop": lambda outcome, stop_reason: outcome,
        }
        _load_runtime_functions(
            "run_until_done",
            "collect_recovery_execution_evidence",
            "recovery_failure_outcome",
            "evaluate_boot_outcome",
            namespace=ns,
        )
        status = ns["run_until_done"](cpu, time_slice="0.02", max_iters=5)
        outcome, _slot, signals = ns["evaluate_boot_outcome"](
            state["vtor"], state["pc"], fault_injected=True, p2_status=status
        )
        return status, outcome, signals, state, cpu

    st_real, out_real, sig_real, _, cpu_real = _run_scenario("real_lockup")
    assert st_real["reason"] == "cpu_lockup"
    assert out_real == "hard_fault"
    assert sig_real["recovery_execution"]["lockup_observed"] is True
    assert sig_real["recovery_execution"].get("erased_vector_lockup") is None
    assert cpu_real.IsHalted is True

    st_hf, out_hf, sig_hf, state_hf, cpu_hf = _run_scenario(
        "erased_hf", allow_fault_after_success=True
    )
    assert st_hf["reason"] == "lockup_erased_vector"
    assert out_hf == out_real == "hard_fault"
    assert sig_hf["recovery_execution"]["lockup_observed"] is True
    assert sig_hf["recovery_execution"]["erased_vector_lockup"] is True
    assert state_hf["acked"] == 1
    assert cpu_hf.IsHalted is True

    st_boot, out_boot, sig_boot, _, cpu_boot = _run_scenario("boot_erased_reset")
    assert st_boot["reason"] == "lockup_erased_vector"
    assert st_boot["iters"] == 0
    assert out_boot == out_real == "hard_fault"
    assert sig_boot["recovery_execution"]["lockup_observed"] is True
    assert sig_boot["recovery_execution"]["erased_vector_lockup"] is True
    assert cpu_boot.IsHalted is True

    st_loop, out_loop, sig_loop, _, _ = _run_scenario("exc_return_zero_progress")
    assert st_loop["reason"] == "lockup_erased_vector"
    assert out_loop == out_real == "hard_fault"
    assert sig_loop["recovery_execution"]["lockup_observed"] is True
    assert sig_loop["recovery_execution"]["erased_vector_lockup"] is True


def test_erased_vector_fixture_loads_and_targets_erased_reset_and_hardfault():
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from profile_loader import load_profile

    profile = load_profile(FIXTURE / "profile_erased_vector.yaml", strict=True)
    assert profile.name == "recovery_vector_fault_erased_vector"
    src = (FIXTURE / "erased_vector.c").read_text(encoding="utf-8")
    assert "NVMC_ERASEPAGE" in src
    assert "vectors[3] == 0xFFFFFFFFu" in src
    assert 'udf #0' in src
    assert (FIXTURE / "erased_vector.elf").stat().st_size < 64 * 1024
    assert (FIXTURE / "erased_vector.bin").stat().st_size < 8192
