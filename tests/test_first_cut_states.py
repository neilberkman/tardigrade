from __future__ import annotations

import ast
import json
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import (
    _calibration_point_coverage,
    _first_cut_accounting_needs_erase_trace,
)
from boundary_snapshot import write_snapshot
from fault_plan import CalibrationInputs, build_fault_plan
from first_cut_states import (
    analyze_profile_first_cut_states,
    compute_first_cut_states,
    draw_torn_word_for_point,
    segment_trace_phases,
)
from merge_runtime_sweep_reports import merge_runtime_sweep_payloads
from point_counts import (
    build_point_counts,
    merge_point_counts,
    render_point_counts_markdown,
    render_point_counts_text,
)
from profile_loader import ProfileError, load_profile
from recovery_state import (
    PersistentState,
    RecoveryStateComputer,
    apply_completed_operation,
    apply_interrupted_operation,
    merge_operation_traces,
)
from render_results_html import render_point_counts_panel, runtime_payload
from report_junit import junit_report
from report_points import ReportRun
from report_sarif import sarif_report
from zero_day_results import format_profile_cell
from zero_day_summary import format_console_summary, format_step_summary


def _make_base_state(size: int = 0x4000, fill: int = 0xFF, base_address: int = 0) -> PersistentState:
    return PersistentState.from_bytes(
        bytearray([fill & 0xFF]) * size,
        name="nvm",
        base_address=base_address,
    )


def test_state_computation_reuses_recovery_state_across_backends() -> None:
    # 1. Fast flash backend: write of 0xFFFFFFFF to already-erased flash leaves
    # prefix unchanged, so cut before write 0 and cut before write 1 share one
    # persistent state under torn_word='fixed' (untouched).
    fast_initial = _make_base_state(size=0x2000, fill=0xFF, base_address=0x08000000)
    fast_ops = merge_operation_traces(
        [
            {"write_index": 1, "offset": 0x0, "value": 0xFFFFFFFF, "width": 4},
            {"write_index": 2, "offset": 0x4, "value": 0x12345678, "width": 4},
            {"write_index": 3, "offset": 0x4, "value": 0x12345678, "width": 4},
            {"write_index": 4, "offset": 0x8, "value": 0xCAFEBABE, "width": 4},
        ],
        [],
    )
    fast_analysis = compute_first_cut_states(
        fast_initial,
        fast_ops,
        backend_kind="fast",
        torn_word_mode="fixed",
        erase_fill=0xFF,
        flash_base=0x08000000,
    )
    ref_states = [
        state.identity_hex()
        for _, state in RecoveryStateComputer(
            fast_initial,
            fast_ops,
            fault_type="w",
            backend_kind="fast",
            torn_word_mode="fixed",
            erase_fill=0xFF,
        ).iter_cut_states()
    ]
    assert ref_states[0] == ref_states[1]
    assert ref_states[2] == ref_states[3]
    assert ref_states[0] != ref_states[2]
    assert fast_analysis["candidate_cuts"] == 4
    assert fast_analysis["distinct_states"] == 2
    assert fast_analysis["duplicate_cuts"] == 2
    reps = fast_analysis["representatives"]
    assert [r["operation_index"] for r in reps] == [0, 2]
    assert [c["operation_index"] for c in reps[0]["duplicate_cuts"]] == [1]
    assert [c["operation_index"] for c in reps[1]["duplicate_cuts"]] == [3]

    # 2. CFI vs Fast flash interrupted erase on non-erased sector:
    # Fast flash erases the entire page on fixed interrupted erase; CFI erases
    # only the lower half of the sector.
    pre_populated = bytearray([0xAA]) * 0x2000
    cfi_initial = PersistentState.from_bytes(pre_populated, name="nvm", base_address=0)
    erase_ops = merge_operation_traces(
        [],
        [{"erase_index": 1, "offset": 0x0, "writes_at_this_point": 0, "erase_size": 0x1000}],
    )
    fast_erase = compute_first_cut_states(
        cfi_initial,
        erase_ops,
        include_writes=False,
        include_erases=True,
        backend_kind="fast",
        torn_word_mode="fixed",
        erase_fill=0xFF,
    )
    cfi_erase = compute_first_cut_states(
        cfi_initial,
        erase_ops,
        include_writes=False,
        include_erases=True,
        backend_kind="cfi",
        torn_word_mode="fixed",
        erase_fill=0xFF,
    )
    assert (
        fast_erase["representatives"][0]["state_identity"]
        != cfi_erase["representatives"][0]["state_identity"]
    )

    # Corruption seeding incorporates the number of already-completed erases.
    # Distinct-state planning must advance that counter in lockstep with the
    # canonical recovery-state iterator, rather than using the trace's final
    # erase count for every candidate.
    interleaved_ops = merge_operation_traces(
        [
            {"write_index": 1, "offset": 0x20, "value": 0xAAAAAAAA, "width": 4},
            {"write_index": 2, "offset": 0x24, "value": 0xBBBBBBBB, "width": 4},
        ],
        [
            {
                "erase_index": 1,
                "offset": 0x100,
                "writes_at_this_point": 1,
                "erase_size": 0x100,
            }
        ],
    )
    corrupted = compute_first_cut_states(
        fast_initial,
        interleaved_ops,
        include_erases=False,
        write_fault_type="bit_corruption",
        backend_kind="fast",
        torn_word_mode="fixed",
        erase_fill=0xFF,
        corruption_seed=9,
    )
    canonical = []
    prefix = fast_initial
    completed_erases = 0
    for operation in interleaved_ops:
        if operation["kind"] == "write":
            canonical.append(
                apply_interrupted_operation(
                    prefix,
                    operation,
                    fault_type="bit_corruption",
                    backend_kind="fast",
                    torn_word_mode="fixed",
                    erase_fill=0xFF,
                    corruption_seed=9,
                    total_erases=completed_erases,
                ).identity_hex()
            )
        prefix = apply_completed_operation(prefix, operation, erase_fill=0xFF)
        if operation["kind"] == "erase":
            completed_erases += 1
    assert [corrupted["cut_to_state"][f"w:{idx}"] for idx in range(2)] == canonical


def test_exhaustive_phase2_first_cut_accounting_requests_erase_trace() -> None:
    profile = load_profile(ROOT / "profiles/mcuboot_pr3011_move_broken.yaml")

    assert profile.fault_sweep.phase2_fault.pairs
    assert _first_cut_accounting_needs_erase_trace(
        profile,
        "execute",
        profile.fault_sweep.fault_types,
    )
    assert not _first_cut_accounting_needs_erase_trace(
        profile,
        "state",
        profile.fault_sweep.fault_types,
    )


def test_mram_torn_word_modes_and_uncorrectable_marks() -> None:
    # 16-byte MRAM program unit where pre-boot already holds TARGET_VALUE in the
    # lower 8 bytes [0x100..0x107]. Writes 1..3 under mram_torn_word='half' all
    # leave the same 16-byte unit state; write 4 leaves a second distinct state.
    buf = bytearray(0x2000)
    buf[0x100:0x108] = struct.pack("<II", 0x56414C31, 0x54524754)
    mram_initial = PersistentState.from_bytes(
        buf, name="nvm", base_address=0x10100000
    )
    u0 = _little_endian_val = int.from_bytes(
        buf[0x100:0x110], byteorder="little"
    )
    u_after_w3_bytes = bytearray(buf[0x100:0x110])
    u_after_w3_bytes[8:12] = struct.pack("<I", 0x444F4E45)
    u_after_w3 = int.from_bytes(u_after_w3_bytes, byteorder="little")
    u_after_w4_bytes = bytearray(u_after_w3_bytes)
    u_after_w4_bytes[12:16] = struct.pack("<I", 0x50524F47)
    u_after_w4 = int.from_bytes(u_after_w4_bytes, byteorder="little")

    mram_ops = merge_operation_traces(
        [
            {
                "write_index": 1,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u0,
                "value": u0,
                "completed_value": u0,
            },
            {
                "write_index": 2,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u0,
                "value": u0,
                "completed_value": u0,
            },
            {
                "write_index": 3,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u0,
                "value": u_after_w3,
                "completed_value": u_after_w3,
            },
            {
                "write_index": 4,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u_after_w3,
                "value": u_after_w4,
                "completed_value": u_after_w4,
            },
        ],
        [],
    )
    half_analysis = compute_first_cut_states(
        mram_initial,
        mram_ops,
        backend_kind="mram",
        torn_word_mode="half",
        erase_fill=0x00,
        program_unit=16,
        flash_base=0x10100000,
    )
    # In 'half' mode, lower 8 bytes come from intended[:8] (TARGET_VALUE for all 4)
    # and upper 8 bytes are filled with erase_fill (0x00), so all 4 cuts leave 1 state!
    assert half_analysis["candidate_cuts"] == 4
    assert half_analysis["distinct_states"] == 1
    assert half_analysis["duplicate_cuts"] == 3
    assert [r["operation_index"] for r in half_analysis["representatives"]] == [0]
    assert [
        c["operation_index"]
        for c in half_analysis["representatives"][0]["duplicate_cuts"]
    ] == [1, 2, 3]

    # In 'half_retain' mode, upper 8 bytes retain previous[8:16], so cuts 0, 1, 2
    # share one state and cut 3 (after write 3 modified bytes[8:12]) is a second state!
    half_retain_analysis = compute_first_cut_states(
        mram_initial,
        mram_ops,
        backend_kind="mram",
        torn_word_mode="half_retain",
        erase_fill=0x00,
        program_unit=16,
        flash_base=0x10100000,
    )
    assert half_retain_analysis["candidate_cuts"] == 4
    assert half_retain_analysis["distinct_states"] == 2
    assert half_retain_analysis["duplicate_cuts"] == 2
    assert [r["operation_index"] for r in half_retain_analysis["representatives"]] == [0, 3]
    assert [
        c["operation_index"]
        for c in half_retain_analysis["representatives"][0]["duplicate_cuts"]
    ] == [1, 2]

    # Under 'uncorrectable', cuts 0, 1, and 2 all mark offset 0x100 uncorrectable
    # with the same underlying bytes u0, while cut 3 marks offset 0x100
    # uncorrectable with underlying bytes u_after_w3. If another write targets
    # offset 0x110, its uncorrectable mark is at 0x110 (a distinct state even if
    # bytes are unchanged!).
    two_unit_ops = merge_operation_traces(
        [
            {
                "write_index": 1,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u0,
                "value": u0,
                "completed_value": u0,
            },
            {
                "write_index": 2,
                "offset": 0x100,
                "width": 16,
                "pre_program_value": u0,
                "value": u0,
                "completed_value": u0,
            },
            {
                "write_index": 3,
                "offset": 0x110,
                "width": 16,
                "pre_program_value": 0,
                "value": 0,
                "completed_value": 0,
            },
        ],
        [],
    )
    uncorr_analysis = compute_first_cut_states(
        mram_initial,
        two_unit_ops,
        backend_kind="mram",
        torn_word_mode="uncorrectable",
        erase_fill=0x00,
        program_unit=16,
        flash_base=0x10100000,
    )
    # Cut 0 and Cut 1 both leave bytes unchanged and mark 0x100 uncorrectable -> same state.
    # Cut 2 leaves bytes unchanged but marks 0x110 uncorrectable -> distinct state!
    assert uncorr_analysis["distinct_states"] == 2
    assert uncorr_analysis["duplicate_cuts"] == 1
    assert [r["operation_index"] for r in uncorr_analysis["representatives"]] == [0, 2]
    assert all(
        r["uncorrectable_words"] == 1 for r in uncorr_analysis["representatives"]
    )

    # Under 'untouched', all three no-op writes leave identical bytes and 0 marks -> 1 state!
    untouched_analysis = compute_first_cut_states(
        mram_initial,
        two_unit_ops,
        backend_kind="mram",
        torn_word_mode="untouched",
        erase_fill=0x00,
        program_unit=16,
        flash_base=0x10100000,
    )
    assert untouched_analysis["distinct_states"] == 1
    assert untouched_analysis["duplicate_cuts"] == 2


def test_weighted_torn_word_choices_draw_matches_runtime() -> None:
    choices = (("untouched", 1), ("programmed", 1), ("uncorrectable", 2))
    drawn = [draw_torn_word_for_point(idx, choices, seed=42) for idx in range(16)]
    assert set(drawn).issubset({"untouched", "programmed", "uncorrectable"})
    # Drawing is deterministic per (seed, fault_at).
    assert drawn == [
        draw_torn_word_for_point(idx, choices, seed=42) for idx in range(16)
    ]


def test_cross_domain_erase_and_write_duplicate_grouping() -> None:
    # Sector 0 is already erased (0xFF). Cutting before erase 0 (fixed/programmed
    # on an already-0xFF sector) leaves all 0xFF. Cutting before write 0 (with
    # torn_word='fixed' -> untouched) ALSO leaves all 0xFF!
    # The earliest cut in trace sequence order (erase 0) is the representative
    # and stands for write 0.
    initial = _make_base_state(size=0x2000, fill=0xFF, base_address=0)
    ops = merge_operation_traces(
        [
            {"write_index": 1, "offset": 0x0, "value": 0x11223344, "width": 4},
            {"write_index": 2, "offset": 0x4, "value": 0x55667788, "width": 4},
        ],
        [
            {"erase_index": 1, "offset": 0x0, "writes_at_this_point": 0, "erase_size": 0x1000},
        ],
    )
    analysis = compute_first_cut_states(
        initial,
        ops,
        include_writes=True,
        include_erases=True,
        backend_kind="fast",
        torn_word_mode="fixed",
        erase_fill=0xFF,
    )
    assert analysis["candidate_cuts"] == 3
    assert analysis["distinct_states"] == 2
    assert analysis["duplicate_cuts"] == 1
    rep0, rep1 = analysis["representatives"]
    assert (rep0["operation"], rep0["operation_index"]) == ("erase", 0)
    assert [(c["operation"], c["operation_index"]) for c in rep0["duplicate_cuts"]] == [
        ("write", 0)
    ]
    assert (rep1["operation"], rep1["operation_index"]) == ("write", 1)


def test_cap_spreads_across_phases_and_preserves_short_phases() -> None:
    # Construct a trace with 4 phases:
    # Phase 0: 3 staging_trailer setup writes (0x000F7FF0..0x000F7FF8)
    # Phase 1: 100 exec_data bulk copy writes (0x0000C000..0x0000C18C)
    # Phase 2: 2 scratch erases (0x000F8000, 0x000F9000)
    # Phase 3: 4 exec_trailer commit writes (0x00081FF0..0x00081FFC)
    # Total distinct states: 3 + 100 + 2 + 4 = 109.
    # With cap=25, fair share is 25 // 4 = 6, so all three short phases
    # (3, 2, 4 <= 6) must be tested in full (9 states), and the long bulk-copy
    # phase gets the remaining 16 states evenly spaced across its 100 states!
    buf = bytearray([0xFF]) * 0x100000
    # Make scratch non-0xFF so its two erases produce 2 new distinct states.
    buf[0x000F8000:0x000FA000] = bytearray([0x55]) * 0x2000
    initial = PersistentState.from_bytes(buf, name="nvm", base_address=0)

    writes = []
    # Phase 0: 3 writes in staging_trailer [0x000F7000..0x000F8000)
    for i in range(3):
        writes.append(
            {
                "write_index": len(writes) + 1,
                "offset": 0x000F7FF0 + i * 4,
                "value": 0x1000 + i,
                "width": 4,
            }
        )
    # Phase 1: 100 writes in exec_data [0x0000C000..0x00081000)
    for i in range(100):
        writes.append(
            {
                "write_index": len(writes) + 1,
                "offset": 0x0000C000 + i * 4,
                "value": 0x2000 + i,
                "width": 4,
            }
        )
    writes_before_scratch_erases = len(writes)
    # Phase 3: 4 writes in exec_trailer [0x00081000..0x00082000)
    for i in range(4):
        writes.append(
            {
                "write_index": len(writes) + 1,
                "offset": 0x00081FF0 + i * 4,
                "value": 0x3000 + i,
                "width": 4,
            }
        )
    erases = [
        {
            "erase_index": 1,
            "offset": 0x000F8000,
            "writes_at_this_point": writes_before_scratch_erases,
            "erase_size": 0x1000,
        },
        {
            "erase_index": 2,
            "offset": 0x000F9000,
            "writes_at_this_point": writes_before_scratch_erases,
            "erase_size": 0x1000,
        },
    ]
    ops = merge_operation_traces(writes, erases)
    slots = {
        "exec": (0x0000C000, 0x00082000),
        "staging": (0x00082000, 0x000F8000),
    }
    partitions = [("scratch", 0x000F8000, 0x000FA000)]

    # Use torn_word_mode="programmed" so every write and erase leaves a distinct state.
    capped = compute_first_cut_states(
        initial,
        ops,
        include_writes=True,
        include_erases=True,
        backend_kind="fast",
        torn_word_mode="programmed",
        erase_fill=0xFF,
        page_size=0x1000,
        flash_base=0,
        cap=25,
        slots=slots,
        partitions=partitions,
    )
    assert capped["distinct_states"] == 109
    assert capped["selected_states"] == 25
    assert capped["capped_states"] == 84

    phases = capped["phases"]
    assert [p["region"] for p in phases] == [
        "staging_trailer",
        "exec_data",
        "scratch",
        "exec_trailer",
    ]
    # Short phases are tested in full!
    assert phases[0]["distinct_states"] == 3
    assert phases[0]["selected_states"] == 3
    assert phases[0]["tested_in_full"] is True

    assert phases[2]["distinct_states"] == 2
    assert phases[2]["selected_states"] == 2
    assert phases[2]["tested_in_full"] is True

    assert phases[3]["distinct_states"] == 4
    assert phases[3]["selected_states"] == 4
    assert phases[3]["tested_in_full"] is True

    # Long phase gets the remaining 16 states, spanning its first and last cut.
    assert phases[1]["distinct_states"] == 100
    assert phases[1]["selected_states"] == 16
    assert phases[1]["capped_states"] == 84
    assert phases[1]["tested_in_full"] is False
    assert phases[1]["selected_representatives"][0] == "w:3"
    assert phases[1]["selected_representatives"][-1] == "w:102"

    # Selection is completely deterministic across repeated calls.
    capped_again = compute_first_cut_states(
        initial,
        ops,
        include_writes=True,
        include_erases=True,
        backend_kind="fast",
        torn_word_mode="programmed",
        erase_fill=0xFF,
        page_size=0x1000,
        flash_base=0,
        cap=25,
        slots=slots,
        partitions=partitions,
    )
    assert [
        (r["operation"], r["operation_index"])
        for r in capped["selected_representatives"]
    ] == [
        (r["operation"], r["operation_index"])
        for r in capped_again["selected_representatives"]
    ]


def test_point_counts_and_all_renderers_report_first_cut_states() -> None:
    initial = _make_base_state(size=0x2000, fill=0xFF, base_address=0)
    ops = merge_operation_traces(
        [
            {"write_index": 1, "offset": 0x0, "value": 0xFFFFFFFF, "width": 4},
            {"write_index": 2, "offset": 0x4, "value": 0x11111111, "width": 4},
            {"write_index": 3, "offset": 0x4, "value": 0x11111111, "width": 4},
            {"write_index": 4, "offset": 0x8, "value": 0x22222222, "width": 4},
        ],
        [
            {"erase_index": 1, "offset": 0x1000, "writes_at_this_point": 4, "erase_size": 0x1000},
        ],
    )
    # Make page 0x1000 non-erased so erase 1 leaves a distinct erase state.
    initial = initial.write("nvm", 0x1000, b"\x00\x00\x00\x00")
    analysis = compute_first_cut_states(
        initial,
        ops,
        include_writes=True,
        include_erases=True,
        backend_kind="fast",
        torn_word_mode="fixed",
        erase_fill=0xFF,
    )
    # Write states: w=0 ( stands for w=1 ), w=2 ( stands for w=3 ) -> 2 distinct write states, 2 duplicates.
    # Erase states: e=0 -> 1 distinct erase state, 0 duplicates.
    # Total: 5 candidate cuts, 3 distinct states, 2 duplicate cuts.
    assert analysis["candidate_cuts"] == 5
    assert analysis["distinct_states"] == 3
    assert analysis["duplicate_cuts"] == 2

    # Simulate evaluating w=0 and e=0, while w=2 is skipped -> 2 of 3 distinct states tested!
    results = [
        {"is_control": True, "boot_outcome": "success"},
        {
            "fault_at": 0,
            "fault_type": "w",
            "operation_kind": "program",
            "fault_injected": True,
            "boot_outcome": "success",
        },
        {
            "fault_at": 2,
            "fault_type": "w",
            "operation_kind": "program",
            "fault_injected": False,
            "boot_outcome": "skipped",
        },
        {
            "fault_at": 0,
            "fault_type": "e",
            "operation_kind": "erase",
            "fault_injected": True,
            "boot_outcome": "success",
        },
    ]
    counts = build_point_counts(
        results,
        planned_fault_types=["w", "w", "e"],
        expected_control_points=1,
        calibration={
            "program": {
                "calibrated": 4,
                "planned_range": 4,
                "representation": ["distinct_states"],
                "representative_groups": analysis["program"]["representative_groups"],
            },
            "erase": {
                "calibrated": 1,
                "planned_range": 1,
                "representation": ["distinct_states"],
                "representative_groups": analysis["erase"]["representative_groups"],
            },
            "first_cut_states": analysis,
        },
    )
    fcs = counts["first_cut_states"]
    assert fcs["available"] is True
    assert fcs["candidate_cuts"] == 5
    assert fcs["distinct_states"] == 3
    assert fcs["planned_states"] == 3
    assert fcs["tested_states"] == 2
    assert fcs["duplicate_cuts"] == 2
    assert fcs["capped_states"] == 0
    assert fcs["summary"] == "2 of 3 distinct first-cut states tested"
    assert fcs["program"]["tested_states"] == 1
    assert fcs["program"]["distinct_states"] == 2
    assert fcs["program"]["duplicate_cuts"] == 2
    assert fcs["erase"]["tested_states"] == 1
    assert fcs["erase"]["distinct_states"] == 1
    # Direct cut at w=0 also represents duplicate w=1 in calibration coverage.
    assert counts["calibration"]["program"]["cut_directly"] == 1
    assert counts["calibration"]["program"]["represented_without_cut"] == 1

    text = render_point_counts_text(counts)
    assert "2 of 3 distinct first-cut states tested" in text
    assert "1 of 2 distinct first-cut states tested" in text
    assert "1 of 1 distinct first-cut states tested" in text

    md = render_point_counts_markdown(counts)
    assert "### First-cut persistent states" in md
    assert "2 of 3 distinct first-cut states tested" in md

    payload = {
        "profile": "test_profile",
        "verdict": "PASS",
        "calibrated_writes": 4,
        "calibrated_erases": 1,
        "setup_writes": 0,
        "summary": {
            "runtime_sweep": {
                "total_fault_points": 3,
                "issue_points": 0,
                "bricks": 0,
                "point_counts": counts,
            }
        },
        "runtime_sweep_results": results,
    }
    html = render_point_counts_panel(payload)
    assert "first-cut persistent states" in html
    assert "2 of 3 distinct first-cut states tested" in html

    audit = ReportRun(payload, "test_profile", ROOT / "test.yaml")
    suite = ET.fromstring(junit_report([audit]))
    exported = suite.find(".//property[@name='point_counts']")
    assert json.loads(exported.attrib["value"])["first_cut_states"] == fcs
    assert sarif_report([audit], ROOT)["runs"][0]["properties"]["first_cut_states"] == fcs
    # The standalone exporters also accept audit records without a saved summary.
    raw = {"first_cut_states": analysis, "runtime_sweep_results": results}
    assert ReportRun(raw, "raw").counts["first_cut_states"]["summary"] == fcs["summary"]
    rebuilt = runtime_payload(results, "raw", raw)
    assert rebuilt["summary"]["runtime_sweep"]["point_counts"]["first_cut_states"]["summary"] == fcs["summary"]

    record = {
        "profile": "mcuboot_head_move_small_upgrade",
        "verdict": "PASS",
        "security_status": "CLEAN",
        "points": 3,
        "issue_points": 0,
        "bricks": 0,
        "timeouts": 0,
        "wall_time_s": 1.2,
        "mcuboot_commit": "abc1234",
        "zephyr_commit": "def5678",
        "point_counts": counts,
    }
    cell = format_profile_cell(record)
    assert "2 of 3 distinct first-cut states tested" in cell
    assert "duplicate cuts 2" in cell

    console = format_console_summary(record)
    assert "2 of 3 distinct first-cut states tested" in console

    step_md = format_step_summary(record)
    assert "2 of 3 distinct first-cut states tested" in step_md

    merged = merge_point_counts(counts)
    assert merged["first_cut_states"]["summary"] == "2 of 3 distinct first-cut states tested"

    # Also verify merge_runtime_sweep_payloads preserves first_cut_states.
    slice_a = {
        "engine": "renode-test",
        "profile": "test_profile",
        "profile_path": None,
        "schema_version": 1,
        "calibrated_writes": 4,
        "calibrated_erases": 1,
        "setup_writes": 0,
        "quick": False,
        "verdict": "PASS",
        "first_cut_states": analysis,
        "summary": {"runtime_sweep": {"point_counts": counts}},
        "runtime_sweep_results": results[:2],
    }
    slice_b = {
        "engine": "renode-test",
        "profile": "test_profile",
        "profile_path": None,
        "schema_version": 1,
        "calibrated_writes": 4,
        "calibrated_erases": 1,
        "setup_writes": 0,
        "quick": False,
        "verdict": "PASS",
        "first_cut_states": analysis,
        "summary": {"runtime_sweep": {"point_counts": counts}},
        "runtime_sweep_results": [results[0], results[3]],
    }
    merged_payload = merge_runtime_sweep_payloads([slice_a, slice_b])
    merged_fcs = merged_payload["summary"]["runtime_sweep"]["point_counts"][
        "first_cut_states"
    ]
    assert merged_payload["first_cut_states"] == analysis
    assert merged_fcs["summary"] == "2 of 3 distinct first-cut states tested"
    assert merged_fcs["duplicate_cuts"] == 2


def test_deferred_mram_tracking_base_and_program_trace_validation(tmp_path: Path) -> None:
    (tmp_path / "mram16.repl").write_text(
        "mramTracker: Miscellaneous.MappedMRAMTracker @ sysbus 0x40000000\n"
        "    FlashBaseAddress: 0x10100000\n"
        "    FlashSize: 0x2000\n"
        "    ProgramUnitSize: 16\n"
        "    EraseFill: 0x00\n",
        encoding="utf-8",
    )
    prof_path = tmp_path / "deferred_mram.yaml"
    prof_path.write_text(
        """
schema_version: 1
name: deferred_mram_distinct
platform: mram16.repl
flash_backend: mramTracker
bootloader: { elf: firmware.elf, entry: 0x10000000 }
memory:
  sram: { start: 0x20000000, end: 0x20002000 }
  write_granularity: 16
  page_size: 0x1000
  slots:
    exec: { base: 0x10100000, size: 0x1000 }
    staging: { base: 0x10101000, size: 0x1000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
  evaluation_mode: execute
  sweep_strategy: distinct_states
  mram_torn_word: half
  tracking_start_address: 0x10000200
""",
        encoding="utf-8",
    )
    profile = load_profile(prof_path, strict=True)

    # Create a deferred tracking base snapshot where offset 0x100 already has pre-gate bytes.
    base_bytes = bytearray(0x2000)
    unit_pre = bytes.fromhex("314c4156544752540000000000000000")
    unit_post = bytes.fromhex("314c415654475254454e4f44474f5250")
    base_bytes[0x100:0x110] = unit_pre

    prog_csv = tmp_path / "cal_program_trace.csv"
    prog_csv.write_text(
        "write_index,program_address,offset,width,intended_hex,pre_program_hex,post_program_hex,faulted\n"
        f"1,0x10100100,0x100,16,{unit_pre.hex()},{unit_pre.hex()},{unit_pre.hex()},false\n"
        f"2,0x10100100,0x100,16,{unit_post.hex()},{unit_pre.hex()},{unit_post.hex()},false\n",
        encoding="utf-8",
    )
    tb_path = Path(str(prog_csv) + ".tracking_base.bin")
    write_snapshot(
        str(tb_path),
        {
            "nvm": bytes(base_bytes),
            "uncorrectable_words": bytes(len(base_bytes) // 16),
        },
        "test-tracking-base-v1",
    )
    plan = build_fault_plan(
        profile,
        CalibrationInputs(
            max_writes=2,
            program_trace_file=str(prog_csv),
            backend_name="mramTracker",
        ),
    )
    # Under mram_torn_word='half', both writes have the same lower 8 bytes in
    # intended_hex, so both cuts leave 1 distinct state (w=0 stands for w=1)!
    assert plan.fault_points == [0]
    assert plan.first_cut_states_summary is not None
    assert plan.first_cut_states_summary["distinct_states"] == 1
    assert plan.first_cut_states_summary["duplicate_cuts"] == 1

    # Corrupt pre_program_hex so it disagrees with the tracking base snapshot -> must refuse!
    bad_prog_csv = tmp_path / "bad_program_trace.csv"
    bad_prog_csv.write_text(
        "write_index,program_address,offset,width,intended_hex,pre_program_hex,post_program_hex,faulted\n"
        f"1,0x10100100,0x100,16,{unit_pre.hex()},{'ff' * 16},{unit_pre.hex()},false\n",
        encoding="utf-8",
    )
    bad_tb_path = Path(str(bad_prog_csv) + ".tracking_base.bin")
    bad_tb_path.write_bytes(tb_path.read_bytes())
    with pytest.raises(ProfileError, match="pre-program bytes disagree"):
        build_fault_plan(
            profile,
            CalibrationInputs(
                max_writes=1,
                program_trace_file=str(bad_prog_csv),
                backend_name="mramTracker",
            ),
        )


def test_load_time_and_plan_time_refusals(tmp_path: Path) -> None:
    (tmp_path / "mram.repl").write_text(
        "mram: Memory.MappedMRAMTracker @ sysbus 0x10100000\n"
        "    FlashBaseAddress: 0x10100000\n"
        "    FlashSize: 0x4000\n"
        "    ProgramUnitSize: 8\n",
        encoding="utf-8",
    )
    (tmp_path / "mapped_only.repl").write_text(
        "flash: Memory.MappedMemory @ sysbus 0x10000000\n    size: 0x4000\n",
        encoding="utf-8",
    )
    (tmp_path / "fast_flash.repl").write_text(
        "flash: Memory.MappedMemory @ sysbus 0x08000000\n    size: 0x20000\n"
        "faultFlash: Miscellaneous.STM32F4FastFlash @ sysbus 0x40023C00\n"
        "    Flash: flash\n"
        "    FlashBaseAddress: 0x08000000\n"
        "    FlashSize: 0x20000\n",
        encoding="utf-8",
    )

    def write_profile(name: str, body: str) -> Path:
        p = tmp_path / f"{name}.yaml"
        p.write_text(
            "schema_version: 1\n"
            f"name: {name}\n"
            "bootloader: { elf: firmware.elf, entry: 0x10000000 }\n"
            "memory:\n"
            "  sram: { start: 0x20000000, end: 0x20002000 }\n"
            "  slots:\n"
            "    exec: { base: 0x10100000, size: 0x2000 }\n"
            "    staging: { base: 0x10102000, size: 0x2000 }\n"
            "images: { staging: firmware.bin }\n"
            "success_criteria: { vtor_in_slot: exec }\n"
            + body,
            encoding="utf-8",
        )
        return p

    # 1. Unknown sweep_strategy
    p_unknown = write_profile(
        "unknown_strategy",
        "platform: mram.repl\nflash_backend: mram\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: magic_states\n",
    )
    with pytest.raises(ProfileError, match="fault_sweep.sweep_strategy"):
        load_profile(p_unknown)

    # 2. evaluation_mode != execute (state mode)
    p_state = write_profile(
        "state_mode",
        "platform: mram.repl\nflash_backend: mram\nfault_sweep:\n  evaluation_mode: state\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="evaluation_mode 'execute'"):
        load_profile(p_state)

    # 3. durability_model: writeback
    p_wb = write_profile(
        "writeback_mode",
        "platform: mram.repl\nflash_backend: mram\nfault_sweep:\n  evaluation_mode: execute\n  durability_model: writeback\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="durability_model"):
        load_profile(p_wb)

    # 4. Separate nvm_controller
    p_ctrl = write_profile(
        "sep_controller",
        "platform: mram.repl\nflash_backend: mram\nnvm_controller: gfc\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="nvm_controller"):
        load_profile(p_ctrl)

    # 5. Separate otp_peripheral
    p_otp = write_profile(
        "sep_otp",
        "platform: mram.repl\nflash_backend: mram\notp_peripheral: otp\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="otp_peripheral"):
        load_profile(p_otp)

    # 6. Controller-only flash_backend: nvm_ctrl
    p_nvm_ctrl = write_profile(
        "ctrl_only",
        "platform: mram.repl\nflash_backend: nvm_ctrl\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="flash_backend"):
        load_profile(p_nvm_ctrl)

    # 7. Plain MappedMemory platform with no trace peripheral
    p_mapped = write_profile(
        "mapped_only",
        "platform: mapped_only.repl\nflash_backend: flash\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n",
    )
    with pytest.raises(ProfileError, match="width-explicit trace-capable backend"):
        load_profile(p_mapped)

    # 8. Deferred tracking_start_address on non-MRAM backend
    p_deferred_flash = write_profile(
        "deferred_flash",
        "platform: fast_flash.repl\nflash_backend: faultFlash\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n  tracking_start_address: 0x08001000\n",
    )
    with pytest.raises(ProfileError, match="tracking_start_address.*TrackingBaseSnapshot"):
        load_profile(p_deferred_flash)

    # 9. Non-halting / non-cut fault_types
    p_bit = write_profile(
        "non_halting_ft",
        "platform: fast_flash.repl\nflash_backend: faultFlash\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n  fault_types: [power_loss, bit_corruption]\n",
    )
    with pytest.raises(ProfileError, match="fault_sweep.fault_types.*bit_corruption"):
        load_profile(p_bit)

    # 10. max_distinct_states without sweep_strategy: distinct_states
    p_cap_wrong = write_profile(
        "cap_wrong_strategy",
        "platform: fast_flash.repl\nflash_backend: faultFlash\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: exhaustive\n  max_distinct_states: 10\n",
    )
    with pytest.raises(ProfileError, match="max_distinct_states"):
        load_profile(p_cap_wrong, strict=True)

    # 11. Plan-time refusal when trace file is missing or lacks explicit width column
    p_valid = write_profile(
        "valid_distinct",
        "platform: fast_flash.repl\nflash_backend: faultFlash\nfault_sweep:\n  evaluation_mode: execute\n  sweep_strategy: distinct_states\n",
    )
    valid_profile = load_profile(p_valid, strict=True)
    with pytest.raises(ProfileError, match="width-explicit calibration write trace"):
        build_fault_plan(
            valid_profile,
            CalibrationInputs(max_writes=5, trace_file=None, backend_name="faultFlash"),
        )

    widthless_trace = tmp_path / "widthless_trace.csv"
    widthless_trace.write_text(
        "write_index,flash_offset,value\n1,0,123\n",
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="width"):
        build_fault_plan(
            valid_profile,
            CalibrationInputs(
                max_writes=1,
                trace_file=str(widthless_trace),
                backend_name="faultFlash",
            ),
        )


def test_combination_with_state_search_and_phase2_fault(tmp_path: Path) -> None:
    (tmp_path / "firmware.bin").write_bytes(b"")
    (tmp_path / "fast_flash.repl").write_text(
        "flash: Memory.MappedMemory @ sysbus 0x08000000\n    size: 0x20000\n"
        "faultFlash: Miscellaneous.STM32F4FastFlash @ sysbus 0x40023C00\n"
        "    Flash: flash\n"
        "    FlashBaseAddress: 0x08000000\n"
        "    FlashSize: 0x20000\n",
        encoding="utf-8",
    )
    trace_path = tmp_path / "cal_trace.csv"
    # Write 1 writes 0xFFFFFFFF to erased flash -> Cut 0 and Cut 1 leave same state!
    # Write 2 writes 0x11111111 -> Cut 2 leaves new state.
    trace_path.write_text(
        "write_index,flash_offset,value,width\n"
        "1,0,0xFFFFFFFF,4\n"
        "2,4,0x11111111,4\n"
        "3,8,0x22222222,4\n"
        "4,12,0x33333333,4\n",
        encoding="utf-8",
    )

    # 1. state_search + sweep_strategy: distinct_states
    ss_yaml = tmp_path / "ss.yaml"
    ss_yaml.write_text(
        """
schema_version: 1
name: ss_distinct
platform: fast_flash.repl
flash_backend: faultFlash
bootloader: { elf: firmware.elf, entry: 0x10000000 }
memory:
  sram: { start: 0x20000000, end: 0x20002000 }
  slots:
    exec: { base: 0x08000000, size: 0x10000 }
    staging: { base: 0x08010000, size: 0x10000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
  evaluation_mode: execute
  sweep_strategy: distinct_states
  max_distinct_states: 2
  phase2_fault:
    enabled: true
    fault_types: [power_loss]
    state_search:
      enabled: true
""",
        encoding="utf-8",
    )
    ss_profile = load_profile(ss_yaml, strict=True)
    assert ss_profile.fault_sweep.phase2_fault.state_search.first_cut_mode == "distinct_states"
    rt_dict = ss_profile.fault_sweep.phase2_fault.state_search.to_runtime_dict()
    assert rt_dict["first_cuts"]["distinct_states"] is True
    assert rt_dict["first_cuts"]["max_distinct_states"] == 2

    # 2. phase2_fault explicit pairs + sweep_strategy: distinct_states
    # Pair [0, 5] and Pair [1, 5] share the same second cut (5) and their first
    # cuts (0 and 1) leave the exact same first-cut state, so [1, 5] is
    # deduplicated into representative [0, 5], while [2, 5] is kept.
    pairs_yaml = tmp_path / "pairs.yaml"
    pairs_yaml.write_text(
        """
schema_version: 1
name: pairs_distinct
platform: fast_flash.repl
flash_backend: faultFlash
bootloader: { elf: firmware.elf, entry: 0x10000000 }
memory:
  sram: { start: 0x20000000, end: 0x20002000 }
  slots:
    exec: { base: 0x08000000, size: 0x10000 }
    staging: { base: 0x08010000, size: 0x10000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
  evaluation_mode: execute
  sweep_strategy: distinct_states
  phase2_fault:
    enabled: true
    fault_types: [power_loss]
    pairs:
      - [0, 5]
      - [1, 5]
      - [2, 5]
""",
        encoding="utf-8",
    )
    pairs_profile = load_profile(pairs_yaml, strict=True)
    pairs_plan = build_fault_plan(
        pairs_profile,
        CalibrationInputs(
            max_writes=4,
            trace_file=str(trace_path),
            backend_name="faultFlash",
        ),
    )
    assert pairs_plan.fault_types_list == ["p2:0:5:w:w", "p2:2:5:w:w"]
    assert pairs_plan.first_cut_states_summary["candidate_cuts"] == 3
    assert "w:3" not in pairs_plan.first_cut_states_summary["cut_to_state"]

    runtime_tree = ast.parse(
        (SCRIPTS / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    )
    helper_node = next(
        node
        for node in runtime_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_state_search_apply_distinct_first_cuts"
    )
    helper_ns: dict[str, object] = {}
    exec(
        compile(
            ast.Module(body=[helper_node], type_ignores=[]),
            "<state-search-distinct-first-cuts>",
            "exec",
        ),
        helper_ns,
    )
    selected = helper_ns["_state_search_apply_distinct_first_cuts"](
        (("write", 0), ("write", 1), ("write", 2)),
        pairs_plan.first_cut_states_summary,
    )
    # No cap is configured: state search must still replace duplicate cut 1
    # with the same representatives used by direct distinct-state planning.
    assert selected == (("write", 0), ("write", 2))


def test_existing_profiles_plan_identically_to_main() -> None:
    for rel in (
        "profiles/mcuboot_pr3011_move_broken.yaml",
        "profiles/mcuboot_pr3011_move_fixed.yaml",
        "profiles/mcuboot_pr3011_move_broken_state_search.yaml",
        "profiles/mcuboot_head_move_small_upgrade.yaml",
        "profiles/mcuboot_head_move_stm32f4_fast_upgrade.yaml",
        "profiles/mcuboot_head_move_nrf52_upgrade.yaml",
        "examples/phase2_mram_parity/profile_trace_replay_16_half.yaml",
    ):
        profile = load_profile(ROOT / rel)
        assert profile.fault_sweep.sweep_strategy in ("heuristic", "exhaustive")
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=16, total_erases=2),
            repo_root=ROOT,
        )
        if profile.fault_sweep.phase2_fault.pairs:
            assert len(plan.fault_points) == len(profile.fault_sweep.phase2_fault.pairs)
        elif profile.fault_sweep.phase2_fault.state_search.enabled:
            assert plan.fault_types_list == ["rs"]
        elif "swap_progress" in profile.fault_sweep.fault_types:
            assert plan.fault_points == list(range(16))
        else:
            assert plan.fault_points == list(range(16))


def test_bootloader_elf_pt_load_segments_in_initial_state(tmp_path: Path) -> None:
    # Build a minimal little-endian 32-bit ELF with one PT_LOAD segment at 0x08000800..0x08001000
    # (the upper half of page 0 at 0x08000000..0x08001000).
    seg_bytes = b"\x12\x34\x56\x78" * 512
    e_ident = b"\x7fELF\x01\x01\x01" + (b"\x00" * 9)
    elf_header = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,          # e_type = ET_EXEC
        40,         # e_machine = EM_ARM
        1,          # e_version
        0x08000000, # e_entry
        52,         # e_phoff
        0,          # e_shoff
        0,          # e_flags
        52,         # e_ehsize
        32,         # e_phentsize
        1,          # e_phnum
        40,         # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )
    phdr = struct.pack(
        "<8I",
        1,              # PT_LOAD
        84,             # p_offset
        0x08000800,     # p_vaddr
        0x08000800,     # p_paddr
        len(seg_bytes), # p_filesz
        len(seg_bytes), # p_memsz
        5,              # p_flags
        4,              # p_align
    )
    (tmp_path / "bootloader.elf").write_bytes(elf_header + phdr + seg_bytes)
    (tmp_path / "firmware.bin").write_bytes(b"\xff" * 64)
    (tmp_path / "platform.repl").write_text(
        """
faultFlash: Memory.STM32F4FastFlash @ sysbus
    FlashBaseAddress: 0x08000000
    FlashSize: 0x20000
""",
        encoding="utf-8",
    )
    trace_path = tmp_path / "result_trace.csv"
    trace_path.write_text(
        "write_index,flash_offset,value,width\n1,0,0xAABBCCDD,4\n",
        encoding="utf-8",
    )
    erase_path = tmp_path / "result_erase_trace.csv"
    erase_path.write_text(
        "erase_index,flash_offset,writes_at_this_point,erase_size\n1,0,0,4096\n",
        encoding="utf-8",
    )
    prof_path = tmp_path / "profile.yaml"
    prof_path.write_text(
        """
schema_version: 1
name: elf_segment_distinct
platform: platform.repl
flash_backend: faultFlash
bootloader: { elf: bootloader.elf, entry: 0x08000000 }
memory:
  sram: { start: 0x20000000, end: 0x20010000 }
  page_size: 4096
  slots:
    exec: { base: 0x08004000, size: 0x8000 }
    staging: { base: 0x0800C000, size: 0x8000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
  evaluation_mode: execute
  sweep_strategy: distinct_states
  fault_types: [power_loss, interrupted_erase]
""",
        encoding="utf-8",
    )
    prof = load_profile(prof_path, strict=True)
    summary = analyze_profile_first_cut_states(
        prof,
        trace_file=str(trace_path),
        erase_trace_file=str(erase_path),
        total_writes=1,
        total_erases=1,
        include_writes=True,
        include_erases=True,
    )
    # Half-sector interrupted erase of 0x08000000..0x08001000 retains the ELF PT_LOAD
    # bytes in the upper half (0x08000800..0x08001000), whereas completed erase before w=0
    # clears the upper half to 0xFF. They must be distinct states.
    assert summary["candidate_cuts"] == 2
    assert summary["distinct_states"] == 2
    assert summary["duplicate_cuts"] == 0
