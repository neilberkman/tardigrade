from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sweep import _auto_execute_batch_points  # noqa: E402


def _profile(
    platform: str = "platforms/cortex_m4_flash_fast.repl",
    durability_model: str = "direct",
) -> SimpleNamespace:
    return SimpleNamespace(
        platform=platform,
        has_update_sequence=False,
        fault_sweep=SimpleNamespace(durability_model=durability_model),
    )


def test_instruction_skip_execute_forces_single_point_batches() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(),
        evaluation_mode="execute",
        fault_points=[0x1000, 0x1004, 0x1008, 0x100C],
        fault_types_list=["i:0x1000", "i:0x1004", "i:0x1008", "i:0x100C"],
        max_batch_points=0,
        trace_file=None,
        trace_file_bin=None,
    )
    assert chosen == 1


def test_mixed_execute_fault_types_do_not_force_single_point_batches() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(),
        evaluation_mode="execute",
        fault_points=[1, 2, 3, 4],
        fault_types_list=["i:0x1000", "w", "w", "w"],
        max_batch_points=0,
        trace_file=None,
        trace_file_bin=None,
    )
    assert chosen > 1


def test_large_execute_write_indices_use_safe_small_batches() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(),
        evaluation_mode="execute",
        fault_points=list(range(14336)),
        fault_types_list=["w"] * 14336,
        max_batch_points=0,
        trace_file=None,
        trace_file_bin=None,
    )
    assert chosen == 1


def test_large_state_write_indices_on_nvm_use_safe_small_batches() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(platform="platforms/cortex_m0_nvm.repl"),
        evaluation_mode="state",
        fault_points=list(range(28672)),
        fault_types_list=["w"] * 28672,
        max_batch_points=0,
        trace_file=None,
        trace_file_bin=None,
    )
    assert chosen == 1


def test_writeback_power_loss_trace_points_use_single_point_batches() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(durability_model="writeback"),
        evaluation_mode="execute",
        fault_points=list(range(14336)),
        fault_types_list=["w"] * 14336,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    # Writeback replay reconstructs volatile state and then performs recovery
    # boots; treating it as 0.9s replay would incorrectly produce a huge batch.
    assert chosen == 1


def test_writeback_power_loss_early_trace_points_are_not_batched() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(durability_model="writeback"),
        evaluation_mode="execute",
        fault_points=list(range(128)),
        fault_types_list=["w"] * 128,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    assert chosen == 1


def test_direct_power_loss_trace_points_keep_cheap_replay_budget() -> None:
    chosen = _auto_execute_batch_points(
        profile=_profile(),
        evaluation_mode="execute",
        fault_points=list(range(128)),
        fault_types_list=["w"] * 128,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    assert chosen == 128
