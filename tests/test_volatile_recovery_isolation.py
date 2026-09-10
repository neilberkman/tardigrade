from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"
FIXTURE = ROOT / "examples" / "volatile_marker_recovery"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile


def _load_runtime_functions(names: tuple[str, ...], namespace: dict) -> dict:
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(RUNTIME), "exec"), namespace)
    return namespace


def test_clear_volatile_memory_zeroes_every_declared_region(monkeypatch):
    writes: list[tuple[int, bytes]] = []
    memory: dict[int, int] = {}

    class _Array:
        @staticmethod
        def CreateInstance(_byte_type, size):
            return bytearray(size)

    fake_system = SimpleNamespace(Array=_Array, Byte=object())
    monkeypatch.setitem(sys.modules, "System", fake_system)

    def write_bytes(data, address):
        payload = bytes(data)
        writes.append((address, payload))
        memory.update({address + index: value for index, value in enumerate(payload)})

    def read_bytes(address, size):
        return bytes(memory.get(address + index, 0) for index in range(size))

    namespace = {
        "bus": SimpleNamespace(
            WriteBytes=write_bytes,
            ReadBytes=read_bytes,
        ),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "to_py_bytes": bytes,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 12},
            {"name": "retained", "base": 0x21000000, "size": 7},
        ],
    }
    functions = _load_runtime_functions(("_clear_volatile_memory",), namespace)

    functions["_clear_volatile_memory"]()

    assert memory[0x20000000] == 0
    assert memory[0x2000000B] == 0
    assert memory[0x21000000] == 0
    assert memory[0x21000006] == 0
    assert (0x20000000, bytes(12)) in writes
    assert (0x21000000, bytes(7)) in writes


def test_clear_volatile_memory_rejects_unmapped_region(monkeypatch):
    class _Array:
        @staticmethod
        def CreateInstance(_byte_type, size):
            return bytearray(size)

    monkeypatch.setitem(
        sys.modules,
        "System",
        SimpleNamespace(Array=_Array, Byte=object()),
    )
    namespace = {
        "bus": SimpleNamespace(
            WriteBytes=lambda data, address: None,
            ReadBytes=lambda address, size: bytes(size),
        ),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "to_py_bytes": bytes,
        "volatile_regions": [
            {"name": "missing", "base": 0x22000000, "size": 0x100}
        ],
    }
    functions = _load_runtime_functions(("_clear_volatile_memory",), namespace)

    with pytest.raises(RuntimeError, match="not writable"):
        functions["_clear_volatile_memory"]()


@pytest.mark.parametrize(
    "signals",
    [
        {"marker_ok": True},
        {"marker_ok": True, "phase2_stop_reason": "no_boot_stall(0.10s_emulated)"},
    ],
)
def test_marker_surviving_clear_is_inconclusive_with_or_without_stall(signals):
    marker_address = 0x20000100
    marker_value = 0x5A1ECA1B
    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(ReadDoubleWord=lambda address: marker_value),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 0x1000}
        ],
    }
    functions = _load_runtime_functions(
        (
            "_capture_recovery_marker_precondition",
            "_verify_recovery_marker_cleared",
            "_apply_recovery_marker_precondition",
        ),
        namespace,
    )

    functions["_capture_recovery_marker_precondition"]()
    functions["_verify_recovery_marker_cleared"]()
    outcome, fault_class, fields = functions[
        "_apply_recovery_marker_precondition"
    ](signals, "success", "recoverable", True)

    assert outcome == "infra_error"
    assert fault_class == "infrastructure_error"
    assert fields["infrastructure_error"] is True
    assert fields["error_kind"] == "recovery_marker_preexisting"
    assert "inconclusive" in fields["error"]
    assert signals["recovery_marker_preexisting"] is True


def test_successful_clear_removes_preexisting_marker_evidence():
    marker_address = 0x20000100
    marker_value = 0x5A1ECA1B
    reads = iter((marker_value, 0))
    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(ReadDoubleWord=lambda address: next(reads)),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 0x1000}
        ],
    }
    functions = _load_runtime_functions(
        (
            "_capture_recovery_marker_precondition",
            "_verify_recovery_marker_cleared",
            "_apply_recovery_marker_precondition",
        ),
        namespace,
    )

    functions["_capture_recovery_marker_precondition"]()
    functions["_verify_recovery_marker_cleared"]()
    outcome, fault_class, fields = functions[
        "_apply_recovery_marker_precondition"
    ]({}, "success", "recoverable", True)

    assert (outcome, fault_class, fields) == ("success", "recoverable", {})


def test_marker_clear_read_failure_is_inconclusive():
    marker_address = 0x20000100
    marker_value = 0x5A1ECA1B
    reads = iter((marker_value,))

    def read_marker(address):
        try:
            return next(reads)
        except StopIteration:
            raise RuntimeError("unmapped after clear")

    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(ReadDoubleWord=read_marker),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 0x1000}
        ],
    }
    functions = _load_runtime_functions(
        (
            "_capture_recovery_marker_precondition",
            "_verify_recovery_marker_cleared",
            "_apply_recovery_marker_precondition",
        ),
        namespace,
    )

    functions["_capture_recovery_marker_precondition"]()
    functions["_verify_recovery_marker_cleared"]()
    outcome, fault_class, fields = functions[
        "_apply_recovery_marker_precondition"
    ]({}, "success", "recoverable", True)

    assert outcome == "infra_error"
    assert fault_class == "infrastructure_error"
    assert fields["error_kind"] == "recovery_marker_clear_unverified"


def test_followup_boot_cannot_replace_first_boundary_evidence():
    marker_address = 0x20000100
    marker_value = 0x5A1ECA1B
    reads = iter((0, marker_value))
    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(ReadDoubleWord=lambda address: next(reads)),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 0x1000}
        ],
    }
    functions = _load_runtime_functions(
        ("_capture_recovery_marker_precondition",), namespace
    )

    functions["_capture_recovery_marker_precondition"]()
    functions["_capture_recovery_marker_precondition"]()

    evidence = namespace["_recovery_marker_precondition"]
    assert evidence["actual"] == 0
    assert evidence["matched_before_clear"] is False


def test_persistent_marker_is_not_a_volatile_precondition():
    marker_address = 0x0000C014
    marker_value = 0x00000001
    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(
            ReadDoubleWord=lambda address: pytest.fail(
                "persistent marker must not be read by volatile precondition"
            )
        ),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 0x1000}
        ],
    }
    functions = _load_runtime_functions(
        ("_capture_recovery_marker_precondition",), namespace
    )

    functions["_capture_recovery_marker_precondition"]()

    assert namespace["_recovery_marker_precondition"] is None


def test_profile_serializes_additional_volatile_regions(tmp_path):
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        (FIXTURE / "profile.yaml")
        .read_text(encoding="utf-8")
        .replace(
            "  write_granularity: 4",
            "  volatile_regions:\n"
            "    - { name: retained, base: 0x21000000, size: 0x1000 }\n"
            "  write_granularity: 4",
        ),
        encoding="utf-8",
    )
    profile = load_profile(profile_path, strict=True)
    encoded = next(
        item.split(":", 1)[1]
        for item in profile.robot_vars(ROOT)
        if item.startswith("VOLATILE_REGIONS_B64:")
    )

    assert json.loads(base64.b64decode(encoded)) == [
        {"base": 0x21000000, "name": "retained", "size": 0x1000}
    ]


def test_recovery_clear_wiring_and_fixture_contract():
    source = RUNTIME.read_text(encoding="utf-8")
    assert "_capture_recovery_marker_precondition()" in source
    assert source.count("_clear_volatile_memory()") >= 2
    assert "_recovery_marker_precondition = None" in source

    firmware = (FIXTURE / "firmware.c").read_text(encoding="utf-8")
    assert firmware.index("MARKER_ADDRESS = MARKER_VALUE") < firmware.index(
        "NVMC_CONFIG = 0u"
    )
    assert "Brick_Handler();" in firmware
    assert "MARKER_ADDRESS ((uintptr_t)0x20000100u)" in firmware
    assert (FIXTURE / "firmware.elf").stat().st_size < 64 * 1024
    assert (FIXTURE / "firmware.bin").stat().st_size < 1024

    marker_only = load_profile(FIXTURE / "profile_marker_only.yaml", strict=True)
    assert marker_only.fault_sweep.progress_stall_timeout_s == 0
    assert marker_only.fault_sweep.phase2_wall_timeout_s == 1
