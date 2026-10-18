from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from renode_runner import _split_batch_plan  # noqa: E402
from sweep import (  # noqa: E402
    _auto_execute_batch_points,
    _auto_execute_batch_points_by_type,
)
import write_trace_heuristic  # noqa: E402


def _profile(
    platform: str = "platforms/cortex_m4_flash_fast.repl",
    durability_model: str = "direct",
    run_duration: str = "5.0",
) -> SimpleNamespace:
    return SimpleNamespace(
        platform=platform,
        has_update_sequence=False,
        fault_sweep=SimpleNamespace(
            durability_model=durability_model,
            run_duration=run_duration,
        ),
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


def test_mcuboot_full_fault_coverage_nohashbypass_profile_chunking(
    tmp_path: Path, monkeypatch
) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    profile_path = (
        repo_root
        / "profiles"
        / "mcuboot_head_move_nrf52_revert_full_fault_coverage_nohashbypass.yaml"
    )
    profile = load_profile(str(profile_path))
    trace_csv = tmp_path / "clean-write-trace.csv"
    trace_csv.write_text("0,0x20000\n", encoding="utf-8")

    heuristic_points = [round(i * 23814 / 401) for i in range(402)]
    monkeypatch.setattr(
        write_trace_heuristic,
        "load_trace",
        lambda _path: [(i, 0x20000) for i in range(23815)],
    )
    monkeypatch.setattr(
        write_trace_heuristic,
        "classify_trace",
        lambda **_kwargs: {"fault_points": list(heuristic_points)},
    )
    monkeypatch.setattr(
        write_trace_heuristic,
        "summarize_classification",
        lambda **_kwargs: {
            "selected_fault_points": len(heuristic_points),
            "total_writes": 23815,
            "reduction_ratio": len(heuristic_points) / 23815.0,
            "trailer_writes": 50,
        },
    )

    plan = build_fault_plan(
        profile,
        CalibrationInputs(
            max_writes=23815,
            total_erases=42,
            trace_file=str(trace_csv),
        ),
    )
    assert len(plan.fault_points) == 3300
    assert plan.fault_types_list is not None
    assert len(plan.fault_types_list) == 3300

    all_fps = list(plan.fault_points)
    all_fts = list(plan.fault_types_list)

    # Evaluating the mixed plan as a single global block collapses max_batch_points to 1.
    legacy_global_limit = _auto_execute_batch_points(
        profile=profile,
        evaluation_mode="execute",
        fault_points=all_fps,
        fault_types_list=all_fts,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    assert legacy_global_limit == 1

    # Evaluating per contiguous fault-type block preserves single-type batch sizes.
    by_type = _auto_execute_batch_points_by_type(
        profile=profile,
        evaluation_mode="execute",
        fault_points=all_fps,
        fault_types_list=all_fts,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    for ft in ("w", "e", "a", "b", "s", "g", "x", "d", "l", "r"):
        ft_fps = [fp for fp, code in zip(all_fps, all_fts) if code == ft]
        ft_fts = [code for code in all_fts if code == ft]
        single_type_limit = _auto_execute_batch_points(
            profile=profile,
            evaluation_mode="execute",
            fault_points=ft_fps,
            fault_types_list=ft_fts,
            max_batch_points=0,
            trace_file="clean-write-trace.csv",
            trace_file_bin="clean-write-trace.bin",
        )
        assert by_type[ft] == single_type_limit

    assert by_type["w"] == 16
    assert by_type["e"] == 42
    assert by_type["a"] == 42
    for ft in ("b", "s", "g", "x", "d", "l", "r"):
        assert by_type[ft] == 1

    # Check 4-worker round-robin splitting + per-type chunking on Worker 0.
    w0_fps = all_fps[0::4]
    w0_fts = all_fts[0::4]
    w0_by_type = _auto_execute_batch_points_by_type(
        profile=profile,
        evaluation_mode="execute",
        fault_points=w0_fps,
        fault_types_list=w0_fts,
        max_batch_points=0,
        trace_file="clean-write-trace.csv",
        trace_file_bin="clean-write-trace.bin",
    )
    chunks = _split_batch_plan(
        w0_fps,
        w0_fts,
        max(w0_by_type.values()),
        max_batch_points_by_type=w0_by_type,
    )
    # Every chunk must contain only one base fault type.
    for _chunk_fps, chunk_fts in chunks:
        assert len(set(chunk_fts)) == 1
    # First 7 chunks cover all 101 'w' points on Worker 0 (6x16 + 1x5),
    # chunk 7 covers all 10 'e' points, and chunk 8 covers all 11 'a' points.
    assert [len(c[0]) for c in chunks[:9]] == [16, 16, 16, 16, 16, 16, 5, 10, 11]
    assert [c[1][0] for c in chunks[:9]] == ["w"] * 7 + ["e", "a"]
    assert len(chunks) == 712


