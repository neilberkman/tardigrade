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
