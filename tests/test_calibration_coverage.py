#!/usr/bin/env python3
"""Tests for calibration coverage classification and verdict gating."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from audit_report import compute_verdict  # noqa: E402
from self_test import check_verdict  # noqa: E402
from trace_utils import (  # noqa: E402
    annotate_clean_trace,
    build_clean_operation_trace,
    load_exact_program_trace,
    load_clean_erase_trace,
    load_clean_write_trace,
    summarize_calibration_coverage,
)
from fault_inject import MetadataFaultRegion  # noqa: E402
import renode_runner  # noqa: E402


def _slot(name_base: int, size: int = 0x1000) -> SimpleNamespace:
    return SimpleNamespace(base=name_base, size=size)


def _write_trace(path: Path, rows: list[str]) -> None:
    path.write_text(
        "write_index,flash_offset,value\n" + "\n".join(rows) + ("\n" if rows else ""),
        encoding="utf-8",
    )


def _program_trace(path: Path, rows: list[str]) -> None:
    path.write_text(
        "write_index,program_address,offset,width,intended_hex,"
        "pre_program_hex,post_program_hex,faulted\n"
        + "\n".join(rows)
        + ("\n" if rows else ""),
        encoding="utf-8",
    )


def _program_row(
    index: int,
    address: int,
    offset: int,
    width: int = 16,
    byte: int = 0x11,
) -> str:
    data = "{:02x}".format(byte) * width
    pre = "ff" * width
    return "{},{:#x},{},{},{},{},{},false".format(
        index, address, offset, width, data, pre, data
    )


def _base_summary() -> dict:
    return {
        "bricks": 0,
        "issue_points": 0,
        "semantic_issue_points": 0,
        "invariant_issue_points": 0,
        "metadata_delta_issue_points": 0,
        "timeout_points": 0,
        "resilient_rollbacks": 0,
        "control": {
            "boot_outcome": "success",
            "effective_outcome": "success",
            "final_boot_outcome": "success",
            "issue_count": 0,
        },
    }


def test_summarize_calibration_coverage_detects_slot_activity() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, ["1,8448,305419896"])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "slot_activity"
    assert coverage["slot_data_writes"] == 1
    assert coverage["slot_trailer_writes"] == 0


def test_exact_program_trace_provides_slot_coverage_without_legacy_trace(
    tmp_path: Path,
) -> None:
    program_trace = tmp_path / "programs.csv"
    _program_trace(program_trace, [_program_row(1, 0x1800, 0x800)])

    coverage = summarize_calibration_coverage(
        trace_file=None,
        erase_trace_file=None,
        flash_base=0x1000,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
        program_trace_file=str(program_trace),
    )

    assert coverage["status"] == "slot_activity"
    assert coverage["write_trace_source"] == "exact_mram_program_trace"
    assert coverage["writes"] == 1
    assert coverage["exact_programs"] == 1


def test_run_calibration_preserves_exact_program_trace_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    program_trace = tmp_path / "programs.csv"
    _program_trace(program_trace, [_program_row(1, 0x1000, 0, width=4)])
    monkeypatch.setattr(
        renode_runner,
        "run_single_point",
        lambda **_kwargs: {
            "total_writes": 1,
            "total_erases": 0,
            "calibration_stop_reason": "vtor_captured",
            "program_trace_file": str(program_trace),
            "barrier_audit": {
                "total_phases": 1,
                "phases": [
                    {
                        "domain": "exec",
                        "start_write": 1,
                        "end_write": 1,
                        "write_count": 1,
                        "barrier_at_end": True,
                    }
                ],
                "total_barrier_events": 0,
                "missing_barriers": 0,
                "verdict": "ok",
            },
        },
    )
    profile = SimpleNamespace(
        expect=SimpleNamespace(control_outcome="success"),
        fault_sweep=SimpleNamespace(max_writes_cap=10),
    )

    calibration = renode_runner.run_calibration(
        repo_root=ROOT,
        renode_test="renode-test",
        robot_suite="suite.robot",
        profile=profile,
        robot_vars=[],
        work_dir=tmp_path,
        renode_remote_server_dir="",
    )

    assert calibration.program_trace_file == str(program_trace)
    assert calibration.barrier_audit is not None
    assert calibration.barrier_audit["verdict"] == "ok"


@pytest.mark.parametrize(
    ("address", "offset", "expected_status", "expected_count"),
    [
        (0x1F10, 0xF10, "metadata_only", "slot_trailer_writes"),
        (0x3000, 0x2000, "named_metadata_only", "metadata_region_writes"),
        (0x4000, 0x3000, "outside_slots_only", "outside_slot_writes"),
    ],
)
def test_exact_program_trace_classifies_non_data_regions(
    tmp_path: Path,
    address: int,
    offset: int,
    expected_status: str,
    expected_count: str,
) -> None:
    program_trace = tmp_path / "programs.csv"
    _program_trace(program_trace, [_program_row(1, address, offset)])

    coverage = summarize_calibration_coverage(
        trace_file=None,
        erase_trace_file=None,
        flash_base=0x1000,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
        metadata_regions=[
            MetadataFaultRegion(name="state", start=0x3000, end=0x3100)
        ],
        program_trace_file=str(program_trace),
    )

    assert coverage["status"] == expected_status
    assert coverage[expected_count] == 1


def test_empty_exact_program_trace_is_available_but_has_no_activity(
    tmp_path: Path,
) -> None:
    program_trace = tmp_path / "programs.csv"
    _program_trace(program_trace, [])

    coverage = summarize_calibration_coverage(
        trace_file=None,
        erase_trace_file=None,
        flash_base=0x1000,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
        program_trace_file=str(program_trace),
    )

    assert coverage["status"] == "no_nvm_activity"
    assert coverage["write_trace_source"] == "exact_mram_program_trace"
    assert coverage["writes"] == 0


def test_exact_program_width_classifies_both_sides_of_region_boundary(
    tmp_path: Path,
) -> None:
    program_trace = tmp_path / "programs.csv"
    _program_trace(
        program_trace,
        [_program_row(1, 0x1EF8, 0xEF8, width=16)],
    )

    coverage = summarize_calibration_coverage(
        trace_file=None,
        erase_trace_file=None,
        flash_base=0x1000,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
        program_trace_file=str(program_trace),
    )

    assert coverage["slot_data_writes"] == 1
    assert coverage["slot_trailer_writes"] == 1
    assert coverage["cross_region_programs"] == 1


def test_width_aware_write_classifies_every_touched_region(tmp_path: Path) -> None:
    trace_file = tmp_path / "writes.csv"
    trace_file.write_text(
        "write_index,flash_offset,value,width\n"
        "1,0xffc,0x1122334455667788,8\n",
        encoding="utf-8",
    )

    coverage = summarize_calibration_coverage(
        trace_file=str(trace_file),
        erase_trace_file=None,
        flash_base=0,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
    )

    assert coverage["status"] == "slot_activity"
    assert coverage["slot_data_writes"] == 1
    assert coverage["outside_slot_writes"] == 1
    assert coverage["cross_region_writes"] == 1


def test_erase_size_classifies_every_touched_region(tmp_path: Path) -> None:
    erase_trace = tmp_path / "erases.csv"
    erase_trace.write_text(
        "erase_index,flash_offset,writes_at_this_point,erase_size\n"
        "1,0,0,0x1100\n",
        encoding="utf-8",
    )

    coverage = summarize_calibration_coverage(
        trace_file=None,
        erase_trace_file=str(erase_trace),
        flash_base=0,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
    )

    assert coverage["status"] == "slot_activity"
    assert coverage["slot_data_erases"] == 1
    assert coverage["outside_slot_erases"] == 1
    assert coverage["cross_region_erases"] == 1


def test_width_aware_write_splits_at_trace_address_map_boundary(
    tmp_path: Path,
) -> None:
    trace_file = tmp_path / "aliased-writes.csv"
    trace_file.write_text(
        "write_index,flash_offset,value,width\n"
        "1,0xffc,0x1122334455667788,8\n",
        encoding="utf-8",
    )

    coverage = summarize_calibration_coverage(
        trace_file=str(trace_file),
        erase_trace_file=None,
        flash_base=0,
        slots={"exec": _slot(0x3000)},
        page_size=0x100,
        trace_address_map=[
            {"offset_start": 0, "offset_end": 0x1000, "address_addend": 0},
            {
                "offset_start": 0x1000,
                "offset_end": 0x2000,
                "address_addend": 0x2000,
            },
        ],
    )

    assert coverage["status"] == "slot_activity"
    assert coverage["slot_data_writes"] == 1
    assert coverage["outside_slot_writes"] == 1
    assert coverage["cross_region_writes"] == 1


@pytest.mark.parametrize(
    "rows",
    [
        ["1,0x1000,0,4,00,00000000,00000000,false"],
        [
            _program_row(1, 0x1000, 0, width=4),
            _program_row(1, 0x1004, 4, width=4),
        ],
        [_program_row(1, 0xFFFFFFFF, 0xFFFFEFFF, width=2)],
        [
            _program_row(1, 0x1000, 0, width=4),
            _program_row(2, 0x1008, 4, width=4),
        ],
    ],
)
def test_exact_program_trace_fails_closed_on_invalid_events(
    tmp_path: Path, rows: list[str]
) -> None:
    program_trace = tmp_path / "bad-programs.csv"
    _program_trace(program_trace, rows)

    with pytest.raises(ValueError):
        load_exact_program_trace(str(program_trace))


def test_exact_program_trace_fails_closed_on_missing_file_and_columns(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="regular file"):
        load_exact_program_trace(str(tmp_path / "missing.csv"))

    missing_column = tmp_path / "missing-column.csv"
    missing_column.write_text(
        "write_index,program_address,offset\n1,0x1000,0\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="header"):
        load_exact_program_trace(str(missing_column))


def test_coexisting_write_traces_use_legacy_once_and_require_agreement(
    tmp_path: Path,
) -> None:
    write_trace = tmp_path / "writes.csv"
    _write_trace(write_trace, ["1,256,286331153"])
    program_trace = tmp_path / "programs.csv"
    _program_trace(program_trace, [_program_row(1, 0x1100, 0x100, width=4)])

    coverage = summarize_calibration_coverage(
        trace_file=str(write_trace),
        erase_trace_file=None,
        flash_base=0x1000,
        slots={"exec": _slot(0x1000)},
        page_size=0x100,
        program_trace_file=str(program_trace),
    )

    assert coverage["write_trace_source"] == "legacy_write_trace"
    assert coverage["coexisting_write_traces"] is True
    assert coverage["writes"] == 1
    assert coverage["slot_data_writes"] == 1

    _program_trace(program_trace, [_program_row(1, 0x1104, 0x104, width=4)])
    with pytest.raises(ValueError, match="contradicts"):
        summarize_calibration_coverage(
            trace_file=str(write_trace),
            erase_trace_file=None,
            flash_base=0x1000,
            slots={"exec": _slot(0x1000)},
            page_size=0x100,
            program_trace_file=str(program_trace),
        )


def test_summarize_calibration_coverage_detects_metadata_only() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, ["1,12096,305419896"])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "metadata_only"
    assert coverage["slot_trailer_writes"] == 1
    assert coverage["slot_data_writes"] == 0


def test_summarize_calibration_coverage_detects_no_activity() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, [])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
        )
    assert coverage["status"] == "no_nvm_activity"
    assert coverage["writes"] == 0
    assert coverage["erases"] == 0


def test_summarize_calibration_coverage_detects_named_metadata_activity() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(trace_file, ["1,61440,305419896"])
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0,
            slots={"exec": _slot(0x1000), "staging": _slot(0x2000)},
            page_size=0x100,
            metadata_regions=[MetadataFaultRegion(name="otadata0", start=0xF000, end=0xF100)],
        )
    assert coverage["status"] == "named_metadata_only"
    assert coverage["metadata_region_writes"] == 1
    assert coverage["outside_slot_writes"] == 0
    assert coverage["metadata_region_breakdown"] == {"otadata0": 1}


def test_aliased_trace_offsets_are_classified_by_canonical_address() -> None:
    with tempfile.TemporaryDirectory() as td:
        trace_file = Path(td) / "trace.csv"
        _write_trace(
            trace_file,
            [
                "1,1048552,4294967041",
                "2,1572840,4294967041",
            ],
        )
        slots = {
            "secure": _slot(0x10080000, 0x80000),
            "nonsecure": _slot(0x00100000, 0x80000),
        }
        coverage = summarize_calibration_coverage(
            trace_file=str(trace_file),
            erase_trace_file=None,
            flash_base=0x10080000,
            slots=slots,
            page_size=0x100,
            trace_address_map=[
                {"offset_start": 0x80000, "offset_end": 0x100000, "address_addend": 0x10000000},
                {"offset_start": 0x100000, "offset_end": 0x180000, "address_addend": 0},
            ],
        )
    assert coverage["status"] == "metadata_only"
    assert coverage["slot_trailer_writes"] == 2
    assert coverage["outside_slot_writes"] == 0


def test_aliased_trace_operation_addresses_use_canonical_aliases() -> None:
    ops = build_clean_operation_trace(
        [
            {"write_index": 1, "flash_offset": 0x0FFFE8, "value": 1},
            {"write_index": 2, "flash_offset": 0x17FFE8, "value": 1},
        ],
        [],
        0x10080000,
        trace_address_map=[
            {"offset_start": 0x80000, "offset_end": 0x100000, "address_addend": 0x10000000},
            {"offset_start": 0x100000, "offset_end": 0x180000, "address_addend": 0},
        ],
    )
    assert [item["address"] for item in ops] == ["0x100FFFE8", "0x0017FFE8"]


def test_width_aware_clean_trace_is_preserved_in_operation_metadata(tmp_path: Path) -> None:
    trace_file = tmp_path / "widths.csv"
    trace_file.write_text(
        "write_index,flash_offset,value,width\n1,0,4660,2\n2,4,1,4\n",
        encoding="utf-8",
    )
    entries = load_clean_write_trace(str(trace_file))
    assert entries[0]["width"] == 2
    ops = build_clean_operation_trace(entries, [], 0x08000000)
    assert ops[0]["width"] == 2


@pytest.mark.parametrize(
    "rows",
    [
        "-1,0,1\n",
        "1,-1,1\n",
        "2,0,1\n2,4,2\n",
        "2,0,1\n1,4,2\n",
    ],
)
def test_clean_write_trace_fails_closed_on_bad_provenance(tmp_path: Path, rows: str) -> None:
    trace_file = tmp_path / "bad.csv"
    trace_file.write_text("write_index,flash_offset,value\n" + rows, encoding="utf-8")
    with pytest.raises(ValueError):
        load_clean_write_trace(str(trace_file))


def test_clean_trace_bounds_and_negative_erase_offsets_fail_closed(tmp_path: Path) -> None:
    write_trace = tmp_path / "write.csv"
    write_trace.write_text(
        "write_index,flash_offset,value\n1,16,1\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="outside flash"):
        load_clean_write_trace(str(write_trace), flash_size=16)

    erase_trace = tmp_path / "erase.csv"
    erase_trace.write_text(
        "erase_index,flash_offset,writes_at_this_point,erase_size\n"
        "1,-1,0,4\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="offset is negative"):
        load_clean_erase_trace(str(erase_trace), flash_size=16, page_size=4)


def test_clean_erase_trace_rejects_nonblank_malformed_size_but_keeps_legacy_blank(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed-erase.csv"
    malformed.write_text(
        "erase_index,flash_offset,writes_at_this_point,erase_size\n"
        "1,0,0,nope\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="size is malformed"):
        load_clean_erase_trace(str(malformed), flash_size=16, page_size=4)

    legacy = tmp_path / "legacy-erase.csv"
    legacy.write_text(
        "flash_offset,writes_at_this_point\n0,0\n",
        encoding="utf-8",
    )
    entries = load_clean_erase_trace(str(legacy), flash_size=16, page_size=4)
    assert entries[0]["erase_index"] == 1
    assert entries[0]["erase_size"] == 0


@pytest.mark.parametrize(
    "header,row,error",
    [
        (
            "erase_index,writes_at_this_point,erase_size",
            "1,0,4096",
            "missing flash_offset",
        ),
        (
            "erase_index,flash_offset,offset,erase_size",
            "1,0,0,4096",
            "conflicting offset columns",
        ),
        (
            "erase_index,flash_offset,erase_size,unknown",
            "1,0,4096,1",
            "unexpected columns",
        ),
    ],
)
def test_clean_erase_trace_rejects_ambiguous_or_incomplete_headers(
    tmp_path: Path, header: str, row: str, error: str
) -> None:
    erase_trace = tmp_path / "bad-header.csv"
    erase_trace.write_text("{}\n{}\n".format(header, row), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        load_clean_erase_trace(str(erase_trace))


def test_supplied_missing_clean_trace_paths_fail_closed(tmp_path: Path) -> None:
    slots = {"exec": _slot(0x1000)}

    with pytest.raises(ValueError, match="write trace path is not a regular file"):
        summarize_calibration_coverage(
            trace_file=str(tmp_path / "missing-write.csv"),
            erase_trace_file=None,
            flash_base=0,
            slots=slots,
        )
    with pytest.raises(ValueError, match="erase trace path is not a regular file"):
        summarize_calibration_coverage(
            trace_file=None,
            erase_trace_file=str(tmp_path / "missing-erase.csv"),
            flash_base=0,
            slots=slots,
        )
    with pytest.raises(ValueError, match="write trace path is not a regular file"):
        annotate_clean_trace([], str(tmp_path / "missing-write.csv"), None, 0)


def test_clean_trace_annotation_reports_to_stderr_without_runtime_error(
    tmp_path: Path,
) -> None:
    trace_file = tmp_path / "writes.csv"
    trace_file.write_text(
        "write_index,flash_offset,value\n1,0,1\n", encoding="utf-8"
    )
    metadata = annotate_clean_trace([], str(trace_file), None, 0x08000000)
    assert metadata is not None
    assert metadata["writes"] == 1


def test_compute_verdict_fails_clean_profile_when_calibration_only_touches_metadata() -> None:
    summary = _base_summary()
    summary["calibration_coverage"] = {
        "status": "metadata_only",
        "reason": "Calibration touched slot trailers/metadata but never moved slot data.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "FAIL — Calibration touched slot trailers/metadata but never moved slot data."


def test_compute_verdict_allows_clean_profile_when_named_metadata_was_exercised() -> None:
    summary = _base_summary()
    summary["calibration_coverage"] = {
        "status": "named_metadata_only",
        "reason": "Calibration touched declared metadata regions (otadata0) but never moved slot data.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "PASS"


def test_compute_verdict_fails_closed_for_required_unavailable_calibration() -> None:
    summary = _base_summary()
    summary["configured_fault_types"] = ["power_loss"]
    summary["calibration_coverage"] = {
        "status": "unavailable",
        "reason": "No calibration trace available.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "FAIL — No calibration trace available."


def test_compute_verdict_keeps_unavailable_optional_calibration_diagnostic() -> None:
    summary = _base_summary()
    summary["configured_fault_types"] = ["read_bit_flip"]
    summary["calibration_coverage"] = {
        "status": "unavailable",
        "reason": "No calibration trace available.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "PASS"


def test_compute_verdict_fails_closed_for_legacy_unavailable_calibration() -> None:
    summary = _base_summary()
    summary["calibration_coverage"] = {
        "status": "unavailable",
        "reason": "No calibration trace available.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=False,
            control_outcome="success",
            allow_control_only_issues=False,
        ),
    )
    assert verdict == "FAIL — No calibration trace available."


def test_compute_verdict_preserves_control_only_opt_in() -> None:
    summary = _base_summary()
    summary["control"] = {
        "boot_outcome": "wrong_image",
        "effective_outcome": "wrong_image",
        "final_boot_outcome": "wrong_image",
        "issue_count": 0,
    }
    summary["calibration_coverage"] = {
        "status": "no_nvm_activity",
        "reason": "Calibration produced no NVM writes or erases.",
    }
    verdict = compute_verdict(
        summary,
        SimpleNamespace(
            should_find_issues=True,
            control_outcome="wrong_image",
            allow_control_only_issues=True,
        ),
    )
    assert verdict == "PASS — control exhibits expected wrong_image"


def test_self_test_rejects_clean_profile_when_calibration_never_exercised_slot_data() -> None:
    passed, reason = check_verdict(
        Path("profiles/clean.yaml"),
        {"expect": {"should_find_issues": False, "control_outcome": "success"}},
        {
            "summary": {
                "runtime_sweep": {
                    **_base_summary(),
                    "calibration_coverage": {
                        "status": "no_nvm_activity",
                        "reason": "Calibration produced no NVM writes or erases.",
                    },
                }
            }
        },
        1,
    )
    assert passed is False
    assert reason == "Calibration produced no NVM writes or erases."


def test_self_test_accepts_named_metadata_only_calibration_for_clean_profile() -> None:
    passed, reason = check_verdict(
        Path("profiles/clean.yaml"),
        {"expect": {"should_find_issues": False, "control_outcome": "success"}},
        {
            "summary": {
                "runtime_sweep": {
                    **_base_summary(),
                    "calibration_coverage": {
                        "status": "named_metadata_only",
                        "reason": "Calibration touched declared metadata regions (otadata0) but never moved slot data.",
                    },
                }
            }
        },
        1,
    )
    assert passed is True
    assert reason == "No issues found, as expected"
