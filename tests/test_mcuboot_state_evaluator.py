#!/usr/bin/env python3
"""Tests for MCUboot hybrid state-evaluator routing and prediction."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile  # noqa: E402
from sweep import run_runtime_sweep  # noqa: E402


def _load_state_evaluator():
    module_path = ROOT / "targets" / "mcuboot" / "state_evaluator.py"
    spec = importlib.util.spec_from_file_location("test_mcuboot_state_evaluator", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load {}".format(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_slot_image(slot_base: int, slot_size: int, marker_value: int, fill: int) -> bytes:
    data_size = slot_size - 4096
    image = bytearray([fill & 0xFF] * data_size)
    image[0:4] = (0x20008000).to_bytes(4, "little")
    image[4:8] = (slot_base + 0x101).to_bytes(4, "little")
    image[0x10:0x14] = int(marker_value).to_bytes(4, "little")
    return bytes(image)


class MCUbootStateEvaluatorModuleTest(unittest.TestCase):
    def test_bulk_point_predicts_successful_resume_into_staging_image(self) -> None:
        module = _load_state_evaluator()
        exec_base = 0x08020000
        staging_base = 0x08022000
        slot_size = 0x2000
        flash_base = exec_base
        flash_size = (staging_base + slot_size) - flash_base
        flash = bytearray([0xFF] * flash_size)
        exec_image = _make_slot_image(exec_base, slot_size, 0x11111111, 0x11)
        staging_image = _make_slot_image(staging_base, slot_size, 0x22222222, 0x22)
        flash[0:len(exec_image)] = exec_image
        stage_off = staging_base - flash_base
        flash[stage_off:stage_off + len(staging_image)] = staging_image
        magic_base = stage_off + slot_size - 16
        for idx, word in enumerate((0xF395C277, 0x7FEFD260, 0x0F505235, 0x8079B62C)):
            flash[magic_base + idx * 4:magic_base + idx * 4 + 4] = word.to_bytes(4, "little")

        slot_config = {
            "flash_base": flash_base,
            "slots": {
                "exec": {"base": exec_base, "size": slot_size},
                "staging": {"base": staging_base, "size": slot_size},
            },
            "sram_start": 0x20000000,
            "sram_end": 0x20040000,
            "vector_table_offset": 0,
            "trailer_align": 8,
            "trailer_window": 4096,
            "page_size": 4096,
            "pad_byte": 0xFF,
            "marker_address": exec_base + 0x10,
            "marker_value": 0x22222222,
            "image_hash": False,
            "image_hash_slot": "",
        }

        self.assertFalse(module.should_use_execute_mode(exec_base + 0x100, slot_config))
        self.assertTrue(module.should_use_execute_mode(staging_base + slot_size - 4, slot_config))

        result = module.predict_boot_outcome(bytes(flash), slot_config)
        self.assertEqual(result["boot_outcome"], "success")
        self.assertEqual(result["boot_slot"], "exec")
        self.assertEqual(
            result["signals"]["state_evaluator_predicted_source"],
            "staging",
        )
        self.assertEqual(result["signals"]["marker_actual"], "0x22222222")
        self.assertEqual(result["signals"]["trace_replay_mode"], "state_evaluator")


class MCUbootStateEvaluatorSweepRoutingTest(unittest.TestCase):
    def test_run_runtime_sweep_splits_bulk_points_to_state_evaluator(self) -> None:
        exec_base = 0x08020000
        staging_base = 0x08022000
        slot_size = 0x2000

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            exec_image = tempdir / "exec.bin"
            staging_image = tempdir / "staging.bin"
            exec_image.write_bytes(_make_slot_image(exec_base, slot_size, 0x11111111, 0x11))
            staging_image.write_bytes(_make_slot_image(staging_base, slot_size, 0x22222222, 0x22))
            trace_file = tempdir / "trace.csv"
            trace_file.write_text(
                "write_index,flash_offset,value\n"
                "{},256,305419896\n"
                "{},{},2271560481\n".format(
                    1,
                    2,
                    (staging_base - exec_base) + slot_size - 4,
                ),
                encoding="utf-8",
            )
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: mcuboot_state_eval_routing
                    platform: platforms/stm32f4.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf
                      entry: 0x08000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20040000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x{exec_base:08X}, size: 0x{slot_size:X} }}
                        staging: {{ base: 0x{staging_base:08X}, size: 0x{slot_size:X} }}
                    images:
                      exec: {exec_image}
                      staging: {staging_image}
                    pre_boot_state:
                      - {{ address: 0x{staging_base + slot_size - 16:08X}, u32: 0xF395C277 }}
                      - {{ address: 0x{staging_base + slot_size - 12:08X}, u32: 0x7FEFD260 }}
                      - {{ address: 0x{staging_base + slot_size - 8:08X}, u32: 0x0F505235 }}
                      - {{ address: 0x{staging_base + slot_size - 4:08X}, u32: 0x8079B62C }}
                    state_probe:
                      script: targets/mcuboot/probe.py
                    success_criteria:
                      vtor_in_slot: exec
                      marker_address: 0x{exec_base + 0x10:08X}
                      marker_value: 0x22222222
                    expect:
                      should_find_issues: false
                    fault_sweep:
                      mode: runtime
                      evaluation_mode: execute
                      max_writes: 2
                      fault_types: [power_loss]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            with mock.patch(
                "sweep._run_batches_chunked",
                return_value=[
                    {
                        "fault_at": 1,
                        "fault_type": "w",
                        "fault_injected": True,
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "signals": {"trace_replay_mode": "python"},
                    }
                ],
            ) as mock_batch:
                results = run_runtime_sweep(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[0, 1],
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    include_control=False,
                    evaluation_mode="execute",
                    trace_file=str(trace_file),
                    fault_types_list=["w", "w"],
                )

        mock_batch.assert_called_once()
        self.assertEqual(mock_batch.call_args.kwargs["fault_points"], [1])
        state_eval_result = next(r for r in results if r.get("fault_at") == 0)
        self.assertEqual(state_eval_result["boot_outcome"], "success")
        self.assertEqual(
            state_eval_result["signals"]["trace_replay_mode"],
            "state_evaluator",
        )
        self.assertTrue(state_eval_result["signals"]["state_evaluator_used"])

    def test_run_runtime_sweep_disables_state_evaluator_when_requested(self) -> None:
        exec_base = 0x08020000
        staging_base = 0x08022000
        slot_size = 0x2000

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            exec_image = tempdir / "exec.bin"
            staging_image = tempdir / "staging.bin"
            exec_image.write_bytes(_make_slot_image(exec_base, slot_size, 0x11111111, 0x11))
            staging_image.write_bytes(_make_slot_image(staging_base, slot_size, 0x22222222, 0x22))
            trace_file = tempdir / "trace.csv"
            trace_file.write_text(
                "write_index,flash_offset,value\n"
                "{},256,305419896\n"
                "{},{},2271560481\n".format(
                    1,
                    2,
                    (staging_base - exec_base) + slot_size - 4,
                ),
                encoding="utf-8",
            )
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: mcuboot_state_eval_disabled
                    platform: platforms/stm32f4.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf
                      entry: 0x08000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20040000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x{exec_base:08X}, size: 0x{slot_size:X} }}
                        staging: {{ base: 0x{staging_base:08X}, size: 0x{slot_size:X} }}
                    images:
                      exec: {exec_image}
                      staging: {staging_image}
                    pre_boot_state:
                      - {{ address: 0x{staging_base + slot_size - 16:08X}, u32: 0xF395C277 }}
                      - {{ address: 0x{staging_base + slot_size - 12:08X}, u32: 0x7FEFD260 }}
                      - {{ address: 0x{staging_base + slot_size - 8:08X}, u32: 0x0F505235 }}
                      - {{ address: 0x{staging_base + slot_size - 4:08X}, u32: 0x8079B62C }}
                    state_probe:
                      script: targets/mcuboot/probe.py
                    success_criteria:
                      vtor_in_slot: exec
                      marker_address: 0x{exec_base + 0x10:08X}
                      marker_value: 0x22222222
                    expect:
                      should_find_issues: false
                    fault_sweep:
                      mode: runtime
                      evaluation_mode: execute
                      max_writes: 2
                      fault_types: [power_loss]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            with mock.patch(
                "sweep._run_batches_chunked",
                return_value=[
                    {
                        "fault_at": 0,
                        "fault_type": "w",
                        "fault_injected": True,
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "signals": {"trace_replay_mode": "python"},
                    },
                    {
                        "fault_at": 1,
                        "fault_type": "w",
                        "fault_injected": True,
                        "boot_outcome": "success",
                        "boot_slot": "exec",
                        "signals": {"trace_replay_mode": "python"},
                    },
                ],
            ) as mock_batch:
                results = run_runtime_sweep(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=[0, 1],
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    include_control=False,
                    evaluation_mode="execute",
                    trace_file=str(trace_file),
                    fault_types_list=["w", "w"],
                    allow_state_evaluator=False,
                )

        mock_batch.assert_called_once()
        self.assertEqual(mock_batch.call_args.kwargs["fault_points"], [0, 1])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["signals"]["trace_replay_mode"] == "python" for r in results))

    def test_trace_replay_execute_mode_auto_batches_stm32f4_points(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            exec_image = tempdir / "exec.bin"
            staging_image = tempdir / "staging.bin"
            exec_image.write_bytes(b"\xFF" * 0x2000)
            staging_image.write_bytes(b"\xFF" * 0x2000)
            trace_file = tempdir / "trace.csv"
            trace_file.write_text(
                "write_index,flash_offset,value\n1,0,0\n",
                encoding="utf-8",
            )
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: stm32f4_trace_replay_batch_profile
                    platform: platforms/stm32f4.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf
                      entry: 0x08000000
                    memory:
                      sram: { start: 0x20000000, end: 0x20040000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x08020000, size: 0x2000 }
                        staging: { base: 0x08022000, size: 0x2000 }
                    images:
                      exec: EXEC_IMAGE
                      staging: STAGING_IMAGE
                    success_criteria:
                      vtor_in_slot: exec
                    expect:
                      should_find_issues: false
                    fault_sweep:
                      mode: runtime
                      evaluation_mode: execute
                      max_writes: 300
                      fault_types: [power_loss]
                    """
                ).strip()
                .replace("EXEC_IMAGE", str(exec_image))
                .replace("STAGING_IMAGE", str(staging_image))
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            with mock.patch("sweep._run_batches_chunked", return_value=[]) as mock_batch:
                results = run_runtime_sweep(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=list(range(300)),
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    include_control=False,
                    evaluation_mode="execute",
                    trace_file=str(trace_file),
                    fault_types_list=["w"] * 300,
                )

        mock_batch.assert_called_once()
        self.assertEqual(results, [])
        self.assertEqual(mock_batch.call_args.kwargs["max_batch_points"], 144)

    def test_trace_replay_execute_mode_auto_batches_replayable_write_faults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            exec_image = tempdir / "exec.bin"
            staging_image = tempdir / "staging.bin"
            exec_image.write_bytes(b"\xFF" * 0x2000)
            staging_image.write_bytes(b"\xFF" * 0x2000)
            trace_file = tempdir / "trace.csv"
            trace_file.write_text(
                "write_index,flash_offset,value\n1,0,0\n",
                encoding="utf-8",
            )
            profile_path = tempdir / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    """
                    schema_version: 1
                    name: stm32f4_trace_replay_batch_profile_bitflip
                    platform: platforms/stm32f4.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: results/oss_validation/assets/oss_mcuboot_head_move_stm32f4.elf
                      entry: 0x08000000
                    memory:
                      sram: { start: 0x20000000, end: 0x20040000 }
                      write_granularity: 4
                      slots:
                        exec: { base: 0x08020000, size: 0x2000 }
                        staging: { base: 0x08022000, size: 0x2000 }
                    images:
                      exec: EXEC_IMAGE
                      staging: STAGING_IMAGE
                    success_criteria:
                      vtor_in_slot: exec
                    expect:
                      should_find_issues: false
                    fault_sweep:
                      mode: runtime
                      evaluation_mode: execute
                      max_writes: 300
                      fault_types: [bit_corruption]
                    """
                ).strip()
                .replace("EXEC_IMAGE", str(exec_image))
                .replace("STAGING_IMAGE", str(staging_image))
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

            with mock.patch("sweep._run_batches_chunked", return_value=[]) as mock_batch:
                results = run_runtime_sweep(
                    repo_root=ROOT,
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile=profile,
                    fault_points=list(range(300)),
                    robot_vars=[],
                    work_dir=tempdir / "work",
                    renode_remote_server_dir="",
                    include_control=False,
                    evaluation_mode="execute",
                    trace_file=str(trace_file),
                    fault_types_list=["b"] * 300,
                )

        mock_batch.assert_called_once()
        self.assertEqual(results, [])
        self.assertEqual(mock_batch.call_args.kwargs["max_batch_points"], 144)


if __name__ == "__main__":
    unittest.main()
