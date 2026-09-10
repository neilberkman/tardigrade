from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_plan import CalibrationInputs, build_fault_plan
from profile_loader import ProfileError, load_profile


FIXTURE = ROOT / "examples" / "heuristic_mram_trace"


def test_traceless_heuristic_fails_before_exhaustive_planning() -> None:
    profile = load_profile(FIXTURE / "profile_traceless.yaml")

    with pytest.raises(ProfileError) as exc_info:
        build_fault_plan(
            profile,
            CalibrationInputs(max_writes=86_920, backend_name="nvm_ctrl"),
        )

    message = str(exc_info.value)
    assert "nvm_ctrl" in message
    assert "address-bearing calibration write trace" in message
    assert "--fault-step" in message


def test_fault_step_is_the_bounded_traceless_alternative() -> None:
    profile = load_profile(FIXTURE / "profile_traceless.yaml")

    plan = build_fault_plan(
        profile,
        CalibrationInputs(max_writes=21, backend_name="nvm_ctrl"),
        fault_step=10,
    )

    assert plan.fault_points == [0, 10, 20]
    assert plan.heuristic_summary is None


def test_direct_mram_trace_plans_and_reports_tiers(tmp_path: Path) -> None:
    trace = tmp_path / "trace.csv"
    trace.write_text(
        "write_index,flash_offset,value,width\n"
        + "".join(
            f"{index + 1},{index * 8},{index},8\n"
            for index in range(32)
        ),
        encoding="utf-8",
    )
    profile = load_profile(FIXTURE / "profile.yaml")

    plan = build_fault_plan(
        profile,
        CalibrationInputs(
            max_writes=32,
            trace_file=str(trace),
            backend_name="mram",
        ),
    )

    assert 0 < len(plan.fault_points) < 32
    assert len(plan.fault_points) <= 8
    assert plan.heuristic_summary is not None
    assert plan.heuristic_summary["selected_fault_points"] == len(plan.fault_points)
    assert plan.heuristic_summary["tier2_total"] > 0
    assert sum(
        plan.heuristic_summary[key]
        for key in ("tier0_count", "tier1_count", "tier2_count", "tier3_count")
    ) >= len(plan.fault_points)


def test_strict_profile_rejects_inert_max_heuristic_points(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        """
schema_version: 1
name: inert_heuristic_limit
platform: platform.repl
bootloader: { elf: firmware.elf, entry: 0x10000000 }
memory:
  sram: { start: 0x20000000, end: 0x20001000 }
  slots:
    exec: { base: 0x10000000, size: 0x1000 }
    staging: { base: 0x10001000, size: 0x1000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
  sweep_strategy: exhaustive
  max_heuristic_points: 4
""",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="max_heuristic_points.*heuristic"):
        load_profile(profile, strict=True)


def test_direct_mram_fixture_is_small_and_trace_capable() -> None:
    assert (FIXTURE / "firmware.bin").stat().st_size <= 512
    platform = (ROOT / "platforms" / "cortex_m0_mram.repl").read_text(
        encoding="utf-8"
    )
    peripheral = (ROOT / "peripherals" / "NVMemoryController.cs").read_text(
        encoding="utf-8"
    )
    runtime = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
        encoding="utf-8"
    )
    assert "mram: Memory.NVMemory" in platform
    assert "public bool WriteTraceWidthExplicit => true;" in peripheral
    assert "RecordWriteTrace(wordStart);" in peripheral
    assert "backend['kind'] in ('fast', 'mram')" in runtime


def test_explicit_bounded_mode_caps_structural_overwrite_tier() -> None:
    from write_trace_heuristic import classify_trace

    trace = [(index + 1, (index // 2) * 8) for index in range(64)]
    result = classify_trace(
        trace,
        {"exec": (0x10100000, 0x10102000)},
        flash_base=0,
        page_size=0x1000,
        target_points=8,
        preserve_critical_tiers=False,
        return_details=True,
    )

    assert len(result["fault_points"]) == 8
    assert result["fault_points"][0] == 0
    assert result["fault_points"][-1] == 63
