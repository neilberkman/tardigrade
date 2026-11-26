#!/usr/bin/env python3
"""Selectable flash cut outcomes and cross-path byte agreement."""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNTIME = SCRIPTS / "run_runtime_fault_sweep.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, load_profile  # noqa: E402
from recovery_state import (  # noqa: E402
    PersistentState,
    apply_interrupted_operation,
)
from writeback_reconstruction import (  # noqa: E402
    flash_torn_erase_bytes,
    flash_torn_program_bytes,
    reconstruct_committed_snapshot,
)


BACKENDS = (
    ("NRF52NVMC", "NRF52NVMC.cs", "half"),
    ("cortex_m4_flash_fast", "NRF52NVMC.cs", "half"),
    ("STM32F4FlashController", "STM32F4FlashController.cs", "half"),
    ("STM32F4FastFlash", "STM32F4FastFlash.cs", "half"),
    ("STM32H7FlashController", "STM32H7FlashController.cs", "half"),
    ("STM32H7FastFlash", "STM32H7FastFlash.cs", "half"),
    ("An521NvmInterceptor", "An521NvmInterceptor.cs", "half"),
    ("CFIFlash", "CFIFlash.cs", "untouched"),
)
OUTCOMES = ("fixed", "untouched", "programmed", "partial_bits")


def _runtime_helpers():
    names = {
        "_trace_replay_next_lcg",
        "_flash_torn_partial_value",
        "_trace_replay_flash_torn_value",
        "_trace_replay_flash_torn_erase",
        "_mram_torn_word_for_point",
        "_parse_torn_word_choices",
    }
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in nodes} == names
    namespace: dict = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNTIME), "exec"), namespace)
    return namespace


RUNTIME_HELPERS = _runtime_helpers()


def _profile(tmp_path: Path, body: str, peripheral: str = "NRF52NVMC") -> Path:
    (tmp_path / "platform.repl").write_text(
        "faultFlash: Miscellaneous.{} @ sysbus 0x40000000\n".format(peripheral),
        encoding="utf-8",
    )
    path = tmp_path / "profile.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            name: flash_torn
            platform: platform.repl
            bootloader: { elf: firmware.elf, entry: 0x10000000 }
            memory:
              sram: { start: 0x20000000, end: 0x20001000 }
              slots:
                exec: { base: 0x10000000, size: 0x1000 }
                staging: { base: 0x10001000, size: 0x1000 }
            images: { staging: firmware.bin }
            flash_backend: faultFlash
            success_criteria: { vtor_in_slot: exec }
            fault_sweep:
            """
        ).lstrip()
        + body,
        encoding="utf-8",
    )
    return path


def test_profile_list_draw_and_result_wire_are_backend_neutral(tmp_path: Path) -> None:
    profile = load_profile(
        _profile(
            tmp_path,
            "  torn_word_seed: 19\n"
            "  torn_word: [fixed, untouched, programmed, {partial_bits: 3}]\n",
        ),
        strict=True,
    )
    fs = profile.fault_sweep
    assert fs.torn_word == "fixed"
    assert fs.torn_word_choices == (
        ("fixed", 1),
        ("untouched", 1),
        ("programmed", 1),
        ("partial_bits", 3),
    )
    variables = profile.robot_vars(ROOT)
    assert "TORN_WORD_EXPLICIT:true" in variables
    assert "TORN_WORD_SEED:19" in variables
    wire = next(value for value in variables if value.startswith("TORN_WORD_CHOICES:"))
    choices = RUNTIME_HELPERS["_parse_torn_word_choices"](wire.split(":", 1)[1])
    draw = RUNTIME_HELPERS["_mram_torn_word_for_point"]
    first = [draw(index, choices, 19) for index in range(64)]
    assert first == [draw(index, choices, 19) for index in range(64)]
    assert set(first) == set(OUTCOMES)


def test_omitted_setting_preserves_existing_profile_variables(tmp_path: Path) -> None:
    profile = load_profile(_profile(tmp_path, "  evaluation_mode: execute\n"), strict=True)
    fs = profile.fault_sweep
    assert fs.torn_word == "fixed"
    assert fs.torn_word_explicit is False
    assert not any(value.startswith("TORN_WORD") for value in profile.robot_vars(ROOT))


def test_flash_and_mram_settings_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="cannot be configured together"):
        load_profile(
            _profile(
                tmp_path,
                "  torn_word: partial_bits\n  mram_torn_word: untouched\n",
            ),
            strict=True,
        )


def test_profile_load_rejects_backend_without_outcome_support(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="not supported"):
        load_profile(
            _profile(tmp_path, "  torn_word: programmed\n", "UnsupportedFlash"),
            strict=True,
        )


def test_cfi_flash_exposes_the_runtime_fault_backend_contract() -> None:
    source = (ROOT / "peripherals" / "CFIFlash.cs").read_text(encoding="utf-8")
    for declaration in (
        "IQuadWordPeripheral, IMemory, IKnownSize",
        "public ulong TotalWordWrites",
        "public ulong TotalPageErases",
        "public ulong FaultAtWordWrite",
        "public ulong FaultAtPageErase",
        "public IMemory Flash => this",
        "public long FlashBaseAddress",
        "public long FlashSize",
        "public int PageSize",
        "public byte EraseFill",
    ):
        assert declaration in source
    assert "(ulong)(totalWrites + 1)" in source
    assert "(ulong)(totalErases + 1)" in source
    assert source.count("public void Reset()") == 1
    assert source.count("public long FlashSize => size;") == 1
    assert source.count("public byte[] ReadBytes(long offset, int count)") == 1
    assert source.count("public void WriteBytes(long offset, byte[] array)") == 1
    robot = (ROOT / "tests" / "ota_fault_point.robot").read_text(encoding="utf-8")
    assert 'include "${ROOT}/peripherals/CFIFlash.cs"' in robot


@pytest.mark.parametrize(
    "platform,addresses",
    (
        ("qemu_virt_a15.repl", ("0x04000000",)),
        ("qemu_virt_a53.repl", ("0x04000000",)),
        ("qemu_vexpress_a9.repl", ("0x40000000", "0x44000000")),
        ("qemu_vexpress_a9_secure.repl", ("0x40000000", "0x44000000")),
    ),
)
def test_cfi_platforms_declare_runtime_flash_base(
    platform: str, addresses: tuple[str, ...]
) -> None:
    source = (ROOT / "platforms" / platform).read_text(encoding="utf-8")
    for address in addresses:
        assert "FlashBaseAddress: {}".format(address) in source


@pytest.mark.parametrize("backend_name,source_name,_fixed", BACKENDS)
@pytest.mark.parametrize("outcome", OUTCOMES)
def test_each_backend_wires_every_program_outcome(
    backend_name: str, source_name: str, _fixed: str, outcome: str
) -> None:
    source = (ROOT / "peripherals" / source_name).read_text(encoding="utf-8")
    assert "TornWordMode" in source, backend_name
    assert "TornWordSeed" in source, backend_name
    assert "BuildFlashTornProgramValue" in source, backend_name

    old = 0xFFFFFFFF
    requested = 0x00000000
    value = RUNTIME_HELPERS["_trace_replay_flash_torn_value"](
        old, requested, 4, 0xFF, outcome, 0x12345678, 7, 0x104
    )
    if outcome in ("fixed", "untouched"):
        assert value == old
    elif outcome == "programmed":
        assert value == requested
    else:
        assert requested < value < old
        assert (value | old) == old


@pytest.mark.parametrize("backend_name,source_name,fixed_behavior", BACKENDS)
@pytest.mark.parametrize("outcome", OUTCOMES)
def test_each_backend_wires_every_erase_outcome(
    backend_name: str, source_name: str, fixed_behavior: str, outcome: str
) -> None:
    source = (ROOT / "peripherals" / source_name).read_text(encoding="utf-8")
    assert "TornWordMode" in source, backend_name
    assert "TornWordSeed" in source, backend_name
    assert "BuildFlashTornEraseSpan" in source, backend_name

    old = bytes.fromhex("0011223344556677")
    value = flash_torn_erase_bytes(
        old,
        0xFF,
        4,
        outcome,
        0x12345678,
        5,
        0x200,
        fixed_erase_behavior=fixed_behavior,
    )
    if outcome == "fixed":
        expected = old if fixed_behavior == "untouched" else b"\xff" * 4 + old[4:]
        assert value == expected
    elif outcome == "untouched":
        assert value == old
    elif outcome == "programmed":
        assert value == b"\xff" * len(old)
    else:
        assert value != old
        assert value != b"\xff" * len(old)
        assert all((before | after) == after for before, after in zip(old, value))


@pytest.mark.parametrize("outcome", OUTCOMES)
def test_live_algorithm_trace_replay_and_reconstruction_agree_for_program(outcome: str) -> None:
    previous = bytes.fromhex("f0ccaa55")
    requested = bytes.fromhex("00c08011")
    previous_value = int.from_bytes(previous, "little")
    requested_value = int.from_bytes(requested, "little")
    trace_value = RUNTIME_HELPERS["_trace_replay_flash_torn_value"](
        previous_value, requested_value, 4, 0xFF, outcome, 77, 9, 0
    ).to_bytes(4, "little")
    reconstructed = flash_torn_program_bytes(
        previous, requested, 0xFF, outcome, 77, 9, 0
    )

    state = PersistentState.from_bytes(previous, name="nvm")
    operation = {
        "kind": "write",
        "write_index": 9,
        "offset": 0,
        "value": requested_value,
        "width": 4,
        "region": "nvm",
    }
    computed = apply_interrupted_operation(
        state,
        operation,
        backend_kind="flash",
        torn_word_mode=outcome,
        erase_fill=0xFF,
        corruption_seed=77,
    ).materialize()["nvm"]
    assert trace_value == reconstructed == computed


@pytest.mark.parametrize("outcome", OUTCOMES)
def test_live_algorithm_trace_replay_and_reconstruction_agree_for_erase(outcome: str) -> None:
    previous = bytes.fromhex("0011223344556677")
    trace_value = bytes(
        RUNTIME_HELPERS["_trace_replay_flash_torn_erase"](
            previous, 0, 0xFF, 4, outcome, 91, 3
        )
    )
    reconstructed = flash_torn_erase_bytes(
        previous, 0xFF, 4, outcome, 91, 3, 0, fixed_erase_behavior="half"
    )
    state = PersistentState.from_bytes(previous, name="nvm")
    operation = {
        "kind": "erase",
        "erase_index": 3,
        "offset": 0,
        "erase_size": len(previous),
        "writes_at_this_point": 0,
        "region": "nvm",
    }
    computed = apply_interrupted_operation(
        state,
        operation,
        backend_kind="flash",
        torn_word_mode=outcome,
        erase_fill=0xFF,
        corruption_seed=91,
        program_unit=4,
    ).materialize()["nvm"]
    assert trace_value == reconstructed == computed


def test_writeback_snapshot_applies_selected_cut_program() -> None:
    initial = bytes.fromhex("f0ccaa55ffffffff")
    requested = 0x1180C000
    image, discarded = reconstruct_committed_snapshot(
        initial,
        [(1, 0, requested, 4)],
        [],
        0,
        0x08000000,
        4096,
        8,
        torn_word_mode="partial_bits",
        torn_word_seed=77,
    )
    expected = flash_torn_program_bytes(
        initial[:4], requested.to_bytes(4, "little"), 0xFF,
        "partial_bits", 77, 1, 0
    )
    assert bytes(image[:4]) == expected
    assert discarded == 0
