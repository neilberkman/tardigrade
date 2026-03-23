from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sweep import _auto_execute_batch_points  # noqa: E402


def _profile(platform: str = "platforms/cortex_m4_flash_fast.repl") -> SimpleNamespace:
    return SimpleNamespace(platform=platform, has_update_sequence=False)


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
