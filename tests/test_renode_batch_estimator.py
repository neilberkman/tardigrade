from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from renode_runner import _estimate_batch_runtime_seconds, _is_trace_replay_batch


def _profile(durability_model: str = "direct") -> SimpleNamespace:
    return SimpleNamespace(
        platform="platforms/cortex_m4_flash_fast.repl",
        has_update_sequence=False,
        fault_sweep=SimpleNamespace(durability_model=durability_model),
    )


def test_writeback_power_loss_gets_recovery_replay_timeout_floor() -> None:
    profile = _profile("writeback")
    points = [0, 1000]
    fault_types = ["w", "w"]

    assert _is_trace_replay_batch(
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
        fault_types_list=fault_types,
    )
    assert _estimate_batch_runtime_seconds(
        profile=profile,
        fault_points=points,
        fault_types_list=fault_types,
        trace_replay=True,
    ) == 240.0


def test_direct_power_loss_still_uses_trace_replay_estimate() -> None:
    profile = _profile()
    points = [0, 1000]
    fault_types = ["w", "w"]

    assert _is_trace_replay_batch(
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
        fault_types_list=fault_types,
    )
    assert _estimate_batch_runtime_seconds(
        profile=profile,
        fault_points=points,
        fault_types_list=fault_types,
        trace_replay=True,
    ) == 1.8
