"""Unit tests for audit_report._aggregate_read_fault_summaries.

These lock in two behaviours that regressed before:

* The verdict warning fires when read faults were requested but never armed,
  even when no regions were configured (the sidecar carries `requested`, so
  the aggregator must not re-derive it from region config).
* `cpu_path_not_interceptable` points are counted as armed-without-coverage,
  NOT as skips, so the planned == armed + skipped partition holds.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from audit_report import _aggregate_read_fault_summaries  # noqa: E402


def _result(stats, requested):
    return {"read_fault_summary": {"stats": stats, "requested": requested}}


def test_returns_none_when_no_sidecars_present():
    assert _aggregate_read_fault_summaries([{"fault_type": "w"}]) is None


def test_requested_but_no_regions_warns_even_with_zero_armed():
    # read_bit_flip enabled but no target_regions: every point skips with
    # no_regions_configured. requested is carried on the sidecar, so the
    # aggregator must surface the "planned N but none armed" warning.
    stats = {
        "planned": 4, "armed": 0, "fired": 0, "skipped": 4,
        "cpu_path_validated": 0, "cpu_path_unsupported": 0,
        "skip_reasons": {"no_regions_configured": 4},
    }
    agg = _aggregate_read_fault_summaries([_result(stats, requested=True)])
    assert agg is not None
    assert agg["requested"] is True
    assert agg["coverage_validated"] is False
    assert "warning" in agg
    assert "none armed" in agg["warning"]


def test_healthy_read_fault_run_has_no_warning():
    stats = {
        "planned": 10, "armed": 10, "fired": 8, "skipped": 0,
        "cpu_path_validated": 10, "cpu_path_unsupported": 0,
    }
    agg = _aggregate_read_fault_summaries([_result(stats, requested=True)])
    assert agg["coverage_validated"] is True
    assert "warning" not in agg


def test_cpu_path_not_interceptable_is_armed_not_skipped():
    # Armed faults whose CPU read bypassed the hook must not inflate `skipped`;
    # planned == armed + skipped must hold, and the cpu-bypass warning fires.
    stats = {
        "planned": 5, "armed": 5, "fired": 0, "skipped": 0,
        "cpu_path_validated": 0, "cpu_path_unsupported": 5,
    }
    agg = _aggregate_read_fault_summaries([_result(stats, requested=True)])
    assert agg["planned"] == agg["armed"] + agg["skipped"]
    assert agg["coverage_validated"] is False
    assert "warning" in agg
    assert "bypass the read hook" in agg["warning"]


def test_mixed_batches_surface_partial_bypass_warning():
    # Batch A validated cleanly; batch B had every armed point bypass the
    # hook. The merged aggregate must still report the bypass (coverage
    # invalid) rather than letting batch A's success suppress the warning.
    clean = {
        "planned": 4, "armed": 4, "fired": 4, "skipped": 0,
        "cpu_path_validated": 4, "cpu_path_unsupported": 0,
    }
    bypassed = {
        "planned": 3, "armed": 3, "fired": 0, "skipped": 0,
        "cpu_path_validated": 0, "cpu_path_unsupported": 3,
    }
    agg = _aggregate_read_fault_summaries(
        [_result(clean, requested=True), _result(bypassed, requested=True)]
    )
    assert agg["coverage_validated"] is False
    assert "warning" in agg
    assert "bypass the read hook" in agg["warning"]


def test_merges_counters_across_batches():
    a = {
        "planned": 3, "armed": 3, "fired": 2, "skipped": 0,
        "cpu_path_validated": 3, "cpu_path_unsupported": 0,
    }
    b = {
        "planned": 2, "armed": 1, "fired": 1, "skipped": 1,
        "cpu_path_validated": 1, "cpu_path_unsupported": 0,
        "skip_reasons": {"probability_gate": 1},
    }
    agg = _aggregate_read_fault_summaries(
        [_result(a, requested=True), _result(b, requested=True)]
    )
    assert agg["planned"] == 5
    assert agg["armed"] == 4
    assert agg["fired"] == 3
    assert agg["skipped"] == 1
    assert agg["planned"] == agg["armed"] + agg["skipped"]
    assert agg["skip_reasons"] == {"probability_gate": 1}
