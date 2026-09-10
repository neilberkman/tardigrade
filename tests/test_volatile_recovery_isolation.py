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

    class _Array:
        @staticmethod
        def CreateInstance(_byte_type, size):
            return bytearray(size)

    fake_system = SimpleNamespace(Array=_Array, Byte=object())
    monkeypatch.setitem(sys.modules, "System", fake_system)
    namespace = {
        "bus": SimpleNamespace(
            WriteBytes=lambda data, address: writes.append((address, bytes(data)))
        ),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "volatile_regions": [
            {"name": "sram", "base": 0x20000000, "size": 12},
            {"name": "retained", "base": 0x21000000, "size": 7},
        ],
    }
    functions = _load_runtime_functions(("_clear_volatile_memory",), namespace)

    functions["_clear_volatile_memory"]()

    assert writes == [(0x20000000, bytes(12)), (0x21000000, bytes(7))]


@pytest.mark.parametrize(
    "signals",
    [
        {"marker_ok": True},
        {"marker_ok": True, "phase2_stop_reason": "no_boot_stall(0.10s_emulated)"},
    ],
)
def test_preexisting_marker_is_inconclusive_with_or_without_stall(signals):
    marker_address = 0x20000020
    marker_value = 0x5A1ECA1B
    namespace = {
        "_recovery_marker_precondition": None,
        "as_int": int,
        "bus": SimpleNamespace(ReadDoubleWord=lambda address: marker_value),
        "fmt_u32": lambda value: "0x{:08X}".format(value),
        "log": lambda message: None,
        "success_marker_addr": marker_address,
        "success_marker_value": marker_value,
    }
    functions = _load_runtime_functions(
        (
            "_capture_recovery_marker_precondition",
            "_apply_recovery_marker_precondition",
        ),
        namespace,
    )

    functions["_capture_recovery_marker_precondition"]()
    outcome, fault_class, fields = functions[
        "_apply_recovery_marker_precondition"
    ](signals, "success", "recoverable", True)

    assert outcome == "infra_error"
    assert fault_class == "infrastructure_error"
    assert fields["infrastructure_error"] is True
    assert fields["error_kind"] == "recovery_marker_preexisting"
    assert "inconclusive" in fields["error"]
    assert signals["recovery_marker_preexisting"] is True


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
    assert (FIXTURE / "firmware.elf").stat().st_size < 64 * 1024
    assert (FIXTURE / "firmware.bin").stat().st_size < 1024
