import ast
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"


def _runtime_namespace():
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    wanted = {
        "_runfor_fetch_preflight",
        "_run_for_with_watchdog",
        "classify_fault_result",
        "recovery_failure_outcome",
    }
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {node.name for node in functions} == wanted
    namespace = {
        "as_int": int,
        "fmt_u32": lambda value: f"0x{int(value) & 0xFFFFFFFF:08X}",
        "_time": time,
    }
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), str(RUNTIME), "exec"),
        namespace,
    )
    return namespace


class _RuntimeType:
    def __init__(self, name: str, interfaces: tuple[str, ...] = ()) -> None:
        self.FullName = name
        self._interfaces = [SimpleNamespace(FullName=item) for item in interfaces]

    def GetInterfaces(self):
        return self._interfaces


class _Peripheral:
    def __init__(self, name: str, interfaces: tuple[str, ...] = ()) -> None:
        self._type = _RuntimeType(name, interfaces)

    def GetType(self):
        return self._type


class _CPU:
    def __init__(self, pc: int) -> None:
        self.pc = pc
        self.IsHalted = False

    def GetRegisterUnsafe(self, register: int) -> int:
        assert register == 15
        return self.pc


def test_runfor_preflight_reports_controller_nvm_fetch_with_exact_pc() -> None:
    namespace = _runtime_namespace()
    namespace["bus"] = SimpleNamespace(
        WhatPeripheralIsAt=lambda address: _Peripheral(
            "Antmicro.Renode.Peripherals.Memory.NVMemory"
        )
    )

    error = namespace["_runfor_fetch_preflight"](_CPU(0x100001B5))

    assert error == {
        "error_kind": "instruction_fetch_non_executable_peripheral",
        "pc": "0x100001B4",
        "peripheral": "Antmicro.Renode.Peripherals.Memory.NVMemory",
        "message": (
            "Trying to execute code outside RAM or ROM at 0x100001B4 "
            "(peripheral Antmicro.Renode.Peripherals.Memory.NVMemory is not "
            "executable by this Renode build)"
        ),
    }


@pytest.mark.parametrize(
    ("pc", "peripheral_name", "stop_reason", "lockup", "expected_outcome"),
    [
        pytest.param(
            0xFFFFFFFF,
            None,
            "lockup_erased_vector",
            True,
            "hard_fault",
            id="erased-vector",
        ),
        pytest.param(
            0xEFFFFFFE,
            None,
            "cpu_lockup",
            True,
            "hard_fault",
            id="armv7m-lockup",
        ),
        pytest.param(
            0xDEADBEEF,
            None,
            "no_boot_stall(0.04s_emulated)",
            False,
            "no_boot",
            id="unmapped",
        ),
        pytest.param(
            0x40001001,
            "Antmicro.Renode.Peripherals.UART.NS16550",
            "no_boot_stall(0.04s_emulated)",
            False,
            "no_boot",
            id="register-peripheral",
        ),
    ],
)
def test_runfor_preflight_leaves_firmware_fault_fetches_to_runtime(
    pc: int,
    peripheral_name: str | None,
    stop_reason: str,
    lockup: bool,
    expected_outcome: str,
) -> None:
    namespace = _runtime_namespace()
    namespace["bus"] = SimpleNamespace(
        WhatPeripheralIsAt=lambda address: (
            _Peripheral(peripheral_name) if peripheral_name is not None else None
        )
    )
    parse_calls = []
    namespace["monitor"] = SimpleNamespace(
        Parse=parse_calls.append,
        Machine=SimpleNamespace(Pause=lambda: None),
    )

    error = namespace["_run_for_with_watchdog"](
        _CPU(pc), "0.02", 1.0, label="firmware_fault"
    )
    evidence = {
        "stop_reason": stop_reason,
        "lockup_observed": lockup,
    }
    if error is not None:
        evidence = {
            "stop_reason": "runfor_infrastructure_error",
            "infrastructure_error": True,
        }
    outcome = namespace["recovery_failure_outcome"](
        evidence, execution_observed=False
    )
    fault_class = namespace["classify_fault_result"](outcome, None, {})

    assert error is None
    assert parse_calls == ['emulation RunFor "0.02"']
    assert outcome == expected_outcome
    assert fault_class == "unrecoverable"


def test_runfor_watchdog_pauses_a_blocked_emulation_slice() -> None:
    namespace = _runtime_namespace()
    release = threading.Event()
    machine = SimpleNamespace(pause_calls=0)

    def pause() -> None:
        machine.pause_calls += 1
        release.set()

    def parse(command: str) -> None:
        assert command == 'emulation RunFor "0.02"'
        if not release.wait(2.0):
            raise AssertionError("watchdog did not release blocked RunFor")

    machine.Pause = pause
    namespace["monitor"] = SimpleNamespace(Parse=parse, Machine=machine)
    namespace["bus"] = SimpleNamespace(
        WhatPeripheralIsAt=lambda address: _Peripheral(
            "Antmicro.Renode.Peripherals.Memory.MappedMemory"
        )
    )
    cpu = _CPU(0x08000101)

    started = time.monotonic()
    error = namespace["_run_for_with_watchdog"](
        cpu, "0.02", 0.05, label="deliberately_blocked"
    )
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert error["error_kind"] == "runfor_watchdog"
    assert error["pc"] == "0x08000100"
    assert "watchdog expired" in error["message"]
    assert cpu.IsHalted is True
    assert machine.pause_calls == 1


def test_all_runtime_runfor_calls_are_guarded_by_the_watchdog() -> None:
    source = RUNTIME.read_text(encoding="utf-8")
    assert source.count("monitor.Parse('emulation RunFor") == 1
    wrapper = source[
        source.index("def _run_for_with_watchdog(") : source.index(
            "def _runfor_error_status(", source.index("def _run_for_with_watchdog(")
        )
    ]
    assert "monitor.Parse('emulation RunFor" in wrapper
    run_until = source[
        source.index("def run_until_done(") : source.index(
            "def parse_duration_seconds(", source.index("def run_until_done(")
        )
    ]
    assert "min(120.0, remaining_wall_s)" in run_until
