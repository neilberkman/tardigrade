#!/usr/bin/env python3
"""Unit tests for the STM32F1 and STM32L4 flash models, platforms, and torn-word/ECC plumbing."""

from __future__ import annotations

import ast
import subprocess
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
    apply_completed_operation,
    apply_interrupted_operation,
)
from writeback_reconstruction import (  # noqa: E402
    flash_torn_erase_bytes,
    flash_torn_program_bytes,
)


def _runtime_helpers() -> dict[str, object]:
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
    namespace: dict[str, object] = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNTIME), "exec"), namespace)
    return namespace


RUNTIME_HELPERS = _runtime_helpers()


def test_stm32f1_and_l4_platforms_and_controllers_exist_and_expose_contract() -> None:
    f1_cs = (ROOT / "peripherals" / "STM32F1FlashController.cs").read_text(encoding="utf-8")
    l4_cs = (ROOT / "peripherals" / "STM32L4FlashController.cs").read_text(encoding="utf-8")
    f1_repl = (ROOT / "platforms" / "stm32f103.repl").read_text(encoding="utf-8")
    l4_repl = (ROOT / "platforms" / "stm32l476.repl").read_text(encoding="utf-8")

    # STM32F1 contract checks
    assert f1_cs.startswith("// Copyright (c) 2026\n// SPDX-License-Identifier: Apache-2.0\n")
    assert "HaltActiveCpu" not in f1_cs
    assert "class STM32F1FlashController : IDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable" in f1_cs
    assert "class STM32F1RCCStub : IDoubleWordPeripheral, IKnownSize" in f1_cs
    assert "public int ProgramUnitSize => HalfWordSize;" in f1_cs
    assert "oldHalfWord != 0xFFFF && newHalfWord != 0x0000" in f1_cs
    assert "sr |= SrPgerrBit;" in f1_cs
    assert 'cpuType: "cortex-m3"' in f1_repl
    assert "faultFlash: Miscellaneous.STM32F1FlashController @ sysbus 0x40022000" in f1_repl
    assert "-> nvic@4\n" in f1_repl
    assert "-> nvic@3\n" not in f1_repl
    assert "size: 0x5000" in f1_repl
    assert "rcc: Miscellaneous.STM32F1RCCStub @ sysbus 0x40021000" in f1_repl

    # STM32L4 contract checks
    assert l4_cs.startswith("// Copyright (c) 2026\n// SPDX-License-Identifier: Apache-2.0\n")
    assert "HaltActiveCpu" not in l4_cs
    assert "class STM32L4FlashController : IDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable" in l4_cs
    assert "class STM32L4RCCStub : IDoubleWordPeripheral, IKnownSize" in l4_cs
    assert "public int ProgramUnitSize => DoubleWordSize;" in l4_cs
    assert "MarkWordUncorrectable" in l4_cs
    assert "ClearUncorrectableWords" in l4_cs
    assert "UncorrectableWordsToString" in l4_cs
    assert "FaultUncorrectableWordsToString" in l4_cs
    assert "UncorrectableReadsToString" in l4_cs
    assert "EccrEccdBit" in l4_cs
    assert "EccrBkEccBit" in l4_cs
    assert "CrFstpgBit" in l4_cs
    assert 'cpuType: "cortex-m4"' in l4_repl
    assert "faultFlash: Miscellaneous.STM32L4FlashController @ sysbus 0x40022000" in l4_repl
    assert "size: 0x18000" in l4_repl
    assert "sram2: Memory.MappedMemory @ { sysbus 0x10000000; sysbus 0x20018000 }" in l4_repl
    assert "rcc: Miscellaneous.STM32L4RCCStub @ sysbus 0x40021000" in l4_repl


def test_robot_suites_and_ci_include_stm32f1_and_l4_models() -> None:
    for rel_path in (
        "tests/ota_fault_point.robot",
        "tests/write_trace_widths.robot",
        "tests/erase_fault_points.robot",
        "tests/stm32f1_l4_flash.robot",
    ):
        text = (ROOT / rel_path).read_text(encoding="utf-8")
        assert "STM32F1FlashController.cs" in text, rel_path
        assert "STM32L4FlashController.cs" in text, rel_path

    ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/stm32f1_l4_flash.robot" in ci_text


@pytest.mark.parametrize(
    "profile_name,previous_hex,requested_hex",
    (
        ("mcuboot_stm32f103_upgrade", "ffff", "1234"),
        ("mcuboot_stm32l476_upgrade", "ffffffffffffffff", "1122334455667788"),
    ),
)
@pytest.mark.parametrize("outcome", ("fixed", "untouched", "programmed", "partial_bits"))
def test_halfword_and_doubleword_torn_outcomes_agree_across_paths(
    profile_name: str, previous_hex: str, requested_hex: str, outcome: str
) -> None:
    profile = load_profile(ROOT / "profiles" / f"{profile_name}.yaml", strict=True)
    width = profile.memory.write_granularity
    previous = bytes.fromhex(previous_hex)
    requested = bytes.fromhex(requested_hex)
    assert len(previous) == len(requested) == width
    previous_value = int.from_bytes(previous, "little")
    requested_value = int.from_bytes(requested, "little")

    trace_bytes = RUNTIME_HELPERS["_trace_replay_flash_torn_value"](
        previous_value, requested_value, width, 0xFF, outcome, 19, 5, 0x100
    ).to_bytes(width, "little")
    reconstructed = flash_torn_program_bytes(
        previous, requested, 0xFF, outcome, 19, 5, 0x100
    )
    state = PersistentState.from_bytes(bytearray(0x100) + previous, name="nvm")
    operation = {
        "kind": "write",
        "write_index": 5,
        "offset": 0x100,
        "value": requested_value,
        "width": width,
        "region": "nvm",
    }
    computed = apply_interrupted_operation(
        state,
        operation,
        backend_kind="flash",
        torn_word_mode=outcome,
        program_unit=width,
        erase_fill=0xFF,
        corruption_seed=19,
    ).materialize()["nvm"][0x100 : 0x100 + width]
    assert trace_bytes == reconstructed == computed


def test_stm32l4_uncorrectable_doubleword_outcome_marks_persistent_state() -> None:
    previous = bytes.fromhex("ffffffffffffffff")
    requested = bytes.fromhex("1122334455667788")
    previous_value = int.from_bytes(previous, "little")
    requested_value = int.from_bytes(requested, "little")

    trace_bytes = RUNTIME_HELPERS["_trace_replay_flash_torn_value"](
        previous_value, requested_value, 8, 0xFF, "uncorrectable", 0, 3, 0x80
    ).to_bytes(8, "little")
    reconstructed = flash_torn_program_bytes(
        previous, requested, 0xFF, "uncorrectable", 0, 3, 0x80
    )
    assert trace_bytes == previous
    assert reconstructed == previous

    state = PersistentState.from_bytes(bytearray(0x800), name="nvm", base_address=0x08000000)
    state = state.write("nvm", 0x80, previous)
    write_op = {
        "kind": "write",
        "write_index": 3,
        "offset": 0x80,
        "value": requested_value,
        "width": 8,
        "region": "nvm",
    }
    faulted = apply_interrupted_operation(
        state,
        write_op,
        backend_kind="fast",
        torn_word_mode="uncorrectable",
        erase_fill=0xFF,
        program_unit=8,
    )
    assert faulted.read("nvm", 0x80, 8) == previous
    assert faulted.uncorrectable_words == frozenset({("nvm", 0x80)})

    # Erasing the 2 KiB page clears the uncorrectable double-word mark.
    erase_op = {
        "kind": "erase",
        "erase_index": 1,
        "offset": 0,
        "erase_size": 0x800,
        "writes_at_this_point": 3,
        "region": "nvm",
    }
    cleared = apply_completed_operation(faulted, erase_op, erase_fill=0xFF)
    assert cleared.uncorrectable_words == frozenset()


def test_profile_loader_validates_torn_word_uncorrectable_for_stm32l4_and_rejects_f1(
    tmp_path: Path,
) -> None:
    def make_profile(platform_rel: str, body: str) -> Path:
        p = tmp_path / "profile.yaml"
        p.write_text(
            textwrap.dedent(
                f"""
                schema_version: 1
                name: test_stm32_torn
                platform: {platform_rel}
                bootloader: {{ elf: firmware.elf, entry: 0x08000000 }}
                memory:
                  sram: {{ start: 0x20000000, end: 0x20010000 }}
                  slots:
                    exec: {{ base: 0x08008000, size: 0x8000 }}
                    staging: {{ base: 0x08010000, size: 0x8000 }}
                images: {{ staging: firmware.bin }}
                flash_backend: faultFlash
                success_criteria: {{ vtor_in_slot: exec }}
                fault_sweep:
                """
            ).lstrip()
            + body,
            encoding="utf-8",
        )
        return p

    # STM32L4 supports torn_word: uncorrectable in execute + direct mode.
    l4_prof = load_profile(
        make_profile(
            "platforms/stm32l476.repl",
            "  evaluation_mode: execute\n  torn_word: uncorrectable\n",
        ),
        strict=True,
    )
    assert l4_prof.fault_sweep.torn_word == "uncorrectable"

    # STM32F1 supports standard flash torn_word outcomes, but rejects uncorrectable.
    f1_prof = load_profile(
        make_profile(
            "platforms/stm32f103.repl",
            "  evaluation_mode: execute\n  torn_word: partial_bits\n",
        ),
        strict=True,
    )
    assert f1_prof.fault_sweep.torn_word == "partial_bits"

    with pytest.raises(ProfileError, match="uncorrectable"):
        load_profile(
            make_profile(
                "platforms/stm32f103.repl",
                "  evaluation_mode: execute\n  torn_word: uncorrectable\n",
            ),
            strict=True,
        )

    with pytest.raises(ProfileError, match="evaluation_mode 'execute'"):
        load_profile(
            make_profile(
                "platforms/stm32l476.repl",
                "  evaluation_mode: state\n  torn_word: uncorrectable\n",
            ),
            strict=True,
        )


def test_stm32f1_and_stm32l4_mcuboot_profiles_and_target_source_provenance() -> None:
    expected_commit = "b1b886eca7c9cffa8508bebd47721ba745f8c283"
    profile_specs = [
        ("mcuboot_stm32f103_upgrade_control.yaml", "platforms/stm32f103.repl", 2, 0x400, False),
        ("mcuboot_stm32f103_upgrade.yaml", "platforms/stm32f103.repl", 2, 0x400, False),
        ("mcuboot_stm32l476_upgrade_control.yaml", "platforms/stm32l476.repl", 8, 0x800, False),
        ("mcuboot_stm32l476_upgrade.yaml", "platforms/stm32l476.repl", 8, 0x800, False),
        ("mcuboot_stm32l476_upgrade_state_search.yaml", "platforms/stm32l476.repl", 8, 0x800, True),
    ]
    for filename, expected_repl, expected_granularity, expected_page_size, expects_search in profile_specs:
        prof = load_profile(ROOT / "profiles" / filename, strict=True)
        assert prof.platform.endswith(expected_repl)
        assert prof.memory.write_granularity == expected_granularity
        assert prof.memory.page_size == expected_page_size
        assert prof.target_source is not None
        assert prof.target_source.to_dict() == {
            "name": "mcuboot",
            "repository": "https://github.com/zephyrproject-rtos/mcuboot",
            "revision": expected_commit,
        }
        assert Path(prof.bootloader_elf).is_file()
        assert Path(prof.images["exec"]).is_file()
        assert Path(prof.images["staging"]).is_file()
        if expects_search:
            assert prof.fault_sweep.phase2_fault.enabled is True
            assert prof.fault_sweep.phase2_fault.state_search.enabled is True


def test_build_script_requires_explicit_paths_and_has_no_machine_defaults() -> None:
    script = ROOT / "scripts" / "build_stm32f1_l4_mcuboot_targets.sh"
    base_env = {"PATH": "/usr/bin:/bin"}

    res_no_ws = subprocess.run(
        ["bash", str(script)],
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_no_ws.returncode != 0
    assert "ZEPHYR_WS is not set" in res_no_ws.stderr

    res_no_venv = subprocess.run(
        ["bash", str(script), "--zephyr-ws", "/nonexistent/ws"],
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_no_venv.returncode != 0
    assert "ZEPHYR_VENV is not set" in res_no_venv.stderr

    res_no_tc = subprocess.run(
        [
            "bash",
            str(script),
            "--zephyr-ws",
            "/nonexistent/ws",
            "--zephyr-venv",
            "/nonexistent/venv",
        ],
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_no_tc.returncode != 0
    assert "GNUARMEMB_TOOLCHAIN_PATH / TOOLCHAIN_PATH is not set" in res_no_tc.stderr
