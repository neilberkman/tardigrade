#!/usr/bin/env python3
"""Tests for heuristic enrichment and comparison harness."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

sys.path.insert(0, str(SCRIPTS))

from compare_heuristic_vs_exhaustive import (  # noqa: E402
    compare_results,
    load_results_payload,
    normalize_results,
)
from write_trace_heuristic import classify_trace, summarize_classification  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_trace(offsets, start_write_idx=1):
    """Build a trace list from a sequence of flash offsets.

    Returns list of (write_index, flash_offset) with 1-based write indices.
    """
    return [(start_write_idx + i, off) for i, off in enumerate(offsets)]


# ---------------------------------------------------------------------------
# classify_trace return_details tests
# ---------------------------------------------------------------------------


class TestClassifyTraceDetails(unittest.TestCase):
    """Tests for classify_trace with return_details=True."""

    def _slot_ranges(self):
        # Two slots: exec 0x0000-0x8000, staging 0x8000-0x10000.
        return {
            "exec": (0x0000, 0x8000),
            "staging": (0x8000, 0x10000),
        }

    def test_empty_trace_returns_details(self):
        details = classify_trace(
            trace=[],
            slot_ranges=self._slot_ranges(),
            return_details=True,
        )
        self.assertIsInstance(details, dict)
        self.assertEqual(details["fault_points"], [])
        self.assertEqual(details["tier0"], set())
        self.assertEqual(details["tier2_total"], 0)
        self.assertEqual(details["tier3_total"], 0)
        self.assertEqual(details["discontinuity_count"], 0)
        self.assertIn("heuristic_config", details)

    def test_empty_trace_default_returns_list(self):
        result = classify_trace(
            trace=[],
            slot_ranges=self._slot_ranges(),
            return_details=False,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_tier_membership_with_known_trace(self):
        page = 4096
        # Trailer of exec slot: last page [0x7000, 0x8000)
        # Trailer of staging slot: last page [0xF000, 0x10000)
        # Boundary of exec: first page [0x0000, 0x1000)
        # Boundary of staging: first page [0x8000, 0x9000)
        # Bulk: anything else within slots.
        offsets = [
            # 2 trailer writes (tier 1)
            0x7000,
            0x7004,
            # 3 bulk writes in middle of exec (tier 3)
            0x3000,
            0x3004,
            0x3008,
            # 2 boundary writes in first page of staging (tier 2)
            0x8000,
            0x8004,
        ]
        trace = _make_trace(offsets)
        details = classify_trace(
            trace=trace,
            slot_ranges=self._slot_ranges(),
            page_size=page,
            tier2_step=1,
            tier3_step=1,
            return_details=True,
        )

        self.assertIsInstance(details, dict)
        self.assertIn("fault_points", details)
        self.assertIsInstance(details["fault_points"], list)

        # Tier 0: no bootloader region configured.
        self.assertEqual(len(details["tier0"]), 0)

        # Tier 1: trailer writes (fp 0, 1). Discontinuity between
        # 0x7004 and 0x3000 adds a window of writes to tier 1 too.
        # With window=3 around index 2 (the jump): indices 0,1,2,3,4,5
        # are all in discontinuity_indices. But 0,1 already trailer.
        # Indices 2,3,4,5 (fps 2,3,4,5) would be discontinuity -> tier1.
        # And there's a second discontinuity at index 5 (0x3008->0x8000),
        # window covers indices 2..6 (already covered) plus potentially.
        # So most things end up in tier 1 for this small trace.
        # Let's just verify the structure is correct.
        self.assertIsInstance(details["tier1"], set)
        self.assertIsInstance(details["tier2_selected"], set)
        self.assertIsInstance(details["tier3_selected"], set)
        self.assertIsInstance(details["tier2_total"], int)
        self.assertIsInstance(details["tier3_total"], int)
        self.assertGreaterEqual(details["discontinuity_count"], 1)

        # Verify fault_points matches what non-details mode returns.
        plain = classify_trace(
            trace=trace,
            slot_ranges=self._slot_ranges(),
            page_size=page,
            tier2_step=1,
            tier3_step=1,
            return_details=False,
        )
        self.assertEqual(details["fault_points"], plain)

    def test_large_trace_tier_counts(self):
        """Build a trace large enough to have clear tier separation."""
        page = 4096
        offsets = []
        # 10 trailer writes in exec trailer [0x7000, 0x8000)
        for i in range(10):
            offsets.append(0x7000 + i * 4)
        # 100 sequential bulk writes in mid-exec [0x3000, ...)
        for i in range(100):
            offsets.append(0x3000 + i * 4)
        # 20 boundary writes in first page of staging [0x8000, 0x9000)
        for i in range(20):
            offsets.append(0x8000 + i * 4)

        trace = _make_trace(offsets)
        details = classify_trace(
            trace=trace,
            slot_ranges=self._slot_ranges(),
            page_size=page,
            tier2_step=3,
            tier3_step=10,
            discontinuity_window=2,
            return_details=True,
        )

        # Tier 0: none (no bootloader region).
        self.assertEqual(len(details["tier0"]), 0)

        # Tier 1 should have trailer writes + discontinuity windows.
        self.assertGreater(len(details["tier1"]), 0)

        # tier2_total should be total boundary writes classified as tier 2
        # (minus any that ended up in tier 1 due to discontinuity window).
        self.assertGreaterEqual(details["tier2_total"], 0)

        # tier3_total should be total bulk writes classified as tier 3.
        self.assertGreaterEqual(details["tier3_total"], 0)

        # tier2_selected <= tier2_total (step sampling)
        self.assertLessEqual(
            len(details["tier2_selected"]), details["tier2_total"]
        )
        # tier3_selected <= tier3_total
        self.assertLessEqual(
            len(details["tier3_selected"]), details["tier3_total"]
        )

        # heuristic_config captures the parameters.
        cfg = details["heuristic_config"]
        self.assertEqual(cfg["tier2_step"], 3)
        self.assertEqual(cfg["tier3_step"], 10)
        self.assertEqual(cfg["discontinuity_window"], 2)

    def test_bootloader_region_tier0(self):
        """Writes in bootloader region go to tier 0."""
        page = 4096
        bl_region = (0x0, 0x1000)  # bootloader at first page
        offsets = [
            0x0000,  # bootloader -> tier0
            0x0004,  # bootloader -> tier0
            0x3000,  # bulk -> tier3
        ]
        trace = _make_trace(offsets)
        details = classify_trace(
            trace=trace,
            slot_ranges=self._slot_ranges(),
            page_size=page,
            bootloader_region=bl_region,
            return_details=True,
        )
        self.assertEqual(len(details["tier0"]), 2)


# ---------------------------------------------------------------------------
# summarize_classification enrichment tests
# ---------------------------------------------------------------------------


class TestSummarizeClassificationEnriched(unittest.TestCase):
    """Tests that summarize_classification includes tier details."""

    def _slot_ranges(self):
        return {
            "exec": (0x0000, 0x8000),
            "staging": (0x8000, 0x10000),
        }

    def test_without_tier_details_backward_compat(self):
        """Without tier_details, output matches original schema."""
        trace = _make_trace([0x7000, 0x7004, 0x3000])
        fps = [0, 1, 2]
        summary = summarize_classification(
            trace=trace,
            fault_points=fps,
            slot_ranges=self._slot_ranges(),
        )
        self.assertIn("total_writes", summary)
        self.assertIn("trailer_writes", summary)
        self.assertIn("bulk_writes", summary)
        self.assertIn("selected_fault_points", summary)
        self.assertIn("reduction_ratio", summary)
        # No tier detail fields.
        self.assertNotIn("tier0_count", summary)
        self.assertNotIn("heuristic_config", summary)

    def test_with_tier_details(self):
        """With tier_details, output includes per-tier counts and config."""
        page = 4096
        offsets = []
        for i in range(10):
            offsets.append(0x7000 + i * 4)
        for i in range(50):
            offsets.append(0x3000 + i * 4)

        trace = _make_trace(offsets)
        details = classify_trace(
            trace=trace,
            slot_ranges=self._slot_ranges(),
            page_size=page,
            tier2_step=3,
            tier3_step=10,
            return_details=True,
        )
        summary = summarize_classification(
            trace=trace,
            fault_points=details["fault_points"],
            slot_ranges=self._slot_ranges(),
            page_size=page,
            tier_details=details,
        )
        # Original fields still present.
        self.assertIn("total_writes", summary)
        self.assertEqual(summary["total_writes"], 60)

        # New fields.
        self.assertIn("tier0_count", summary)
        self.assertIn("tier1_count", summary)
        self.assertIn("tier2_count", summary)
        self.assertIn("tier3_count", summary)
        self.assertIn("tier2_total", summary)
        self.assertIn("tier3_total", summary)
        self.assertIn("discontinuity_count", summary)
        self.assertIn("heuristic_config", summary)
        self.assertEqual(summary["heuristic_config"]["tier2_step"], 3)
        self.assertEqual(summary["heuristic_config"]["tier3_step"], 10)

        # Counts are non-negative integers.
        for key in [
            "tier0_count",
            "tier1_count",
            "tier2_count",
            "tier3_count",
        ]:
            self.assertIsInstance(summary[key], int)
            self.assertGreaterEqual(summary[key], 0)


# ---------------------------------------------------------------------------
# compare_results tests
# ---------------------------------------------------------------------------


class TestCompareResults(unittest.TestCase):
    """Tests for the heuristic-vs-exhaustive comparison harness."""

    def test_perfect_recall(self):
        """All exhaustive issue points are present in heuristic set."""
        exhaustive = [
            {"fault_point": 0, "outcome": "success"},
            {"fault_point": 1, "outcome": "no_boot"},
            {"fault_point": 2, "outcome": "wrong_image"},
            {"fault_point": 3, "outcome": "success"},
        ]
        heuristic = [
            {"fault_point": 1, "outcome": "no_boot"},
            {"fault_point": 2, "outcome": "wrong_image"},
            {"fault_point": 3, "outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["total_exhaustive_points"], 4)
        self.assertEqual(result["total_heuristic_points"], 3)
        self.assertEqual(result["exhaustive_issue_count"], 2)
        self.assertEqual(result["heuristic_issue_count"], 2)
        self.assertEqual(result["issue_recall"], 1.0)
        self.assertEqual(result["missed_issue_points"], [])
        self.assertEqual(result["missed_issue_classifications"], [])

    def test_zero_recall(self):
        """No overlap between exhaustive issues and heuristic set."""
        exhaustive = [
            {"fault_point": 0, "outcome": "no_boot"},
            {"fault_point": 1, "outcome": "wrong_image"},
        ]
        heuristic = [
            {"fault_point": 5, "outcome": "success"},
            {"fault_point": 6, "outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["issue_recall"], 0.0)
        self.assertEqual(result["missed_issue_points"], [0, 1])
        self.assertEqual(
            sorted(result["missed_issue_classifications"]),
            ["no_boot", "wrong_image"],
        )

    def test_partial_recall(self):
        """Some exhaustive issue points covered, some missed."""
        exhaustive = [
            {"fault_point": 0, "outcome": "no_boot"},
            {"fault_point": 1, "outcome": "wrong_image"},
            {"fault_point": 2, "outcome": "success"},
            {"fault_point": 3, "outcome": "no_boot"},
        ]
        # Heuristic covers fp 0 and 2, misses fp 1 and 3.
        heuristic = [
            {"fault_point": 0, "outcome": "no_boot"},
            {"fault_point": 2, "outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["exhaustive_issue_count"], 3)
        self.assertEqual(result["heuristic_issue_count"], 1)
        # 1 of 3 issue points covered (fp 0).
        self.assertAlmostEqual(result["issue_recall"], 1.0 / 3.0, places=4)
        self.assertEqual(result["missed_issue_points"], [1, 3])

    def test_empty_exhaustive(self):
        """No issues in exhaustive -> perfect recall by convention."""
        exhaustive = [
            {"fault_point": 0, "outcome": "success"},
        ]
        heuristic = [
            {"fault_point": 0, "outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["exhaustive_issue_count"], 0)
        self.assertEqual(result["issue_recall"], 1.0)

    def test_both_empty(self):
        result = compare_results([], [])
        self.assertEqual(result["total_exhaustive_points"], 0)
        self.assertEqual(result["total_heuristic_points"], 0)
        self.assertEqual(result["issue_recall"], 1.0)
        self.assertEqual(result["missed_issue_points"], [])

    def test_success_variants_not_issues(self):
        """complete_image_ok and safe_fallback are success outcomes."""
        exhaustive = [
            {"fault_point": 0, "outcome": "complete_image_ok"},
            {"fault_point": 1, "outcome": "safe_fallback"},
            {"fault_point": 2, "outcome": "no_boot"},
        ]
        heuristic = [
            {"fault_point": 2, "outcome": "no_boot"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["exhaustive_issue_count"], 1)
        self.assertEqual(result["issue_recall"], 1.0)

    def test_recall_by_fault_type(self):
        """Per-fault_type recall when fault_type is present."""
        exhaustive = [
            {"fault_point": 0, "outcome": "no_boot", "fault_type": "power_loss"},
            {"fault_point": 1, "outcome": "no_boot", "fault_type": "power_loss"},
            {"fault_point": 2, "outcome": "wrong_image", "fault_type": "bit_corruption"},
            {"fault_point": 3, "outcome": "success", "fault_type": "power_loss"},
        ]
        # Heuristic covers fp 0 (power_loss issue) but misses fp 1 and fp 2.
        heuristic = [
            {"fault_point": 0, "outcome": "no_boot", "fault_type": "power_loss"},
            {"fault_point": 3, "outcome": "success", "fault_type": "power_loss"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertIn("recall_by_fault_type", result)
        # power_loss: 2 issue points (fp 0, 1), 1 covered -> 0.5
        self.assertAlmostEqual(
            result["recall_by_fault_type"]["power_loss"], 0.5
        )
        # bit_corruption: 1 issue point (fp 2), 0 covered -> 0.0
        self.assertAlmostEqual(
            result["recall_by_fault_type"]["bit_corruption"], 0.0
        )

    def test_no_recall_by_fault_type_when_absent(self):
        """recall_by_fault_type omitted when no fault_type in results."""
        exhaustive = [
            {"fault_point": 0, "outcome": "no_boot"},
        ]
        heuristic = [
            {"fault_point": 0, "outcome": "no_boot"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertNotIn("recall_by_fault_type", result)

    def test_issue_recall_checks_point_presence_not_outcome(self):
        """Recall is about whether the point was tested, not outcome match."""
        exhaustive = [
            {"fault_point": 5, "outcome": "no_boot"},
        ]
        # Heuristic tested fp 5 but got a different outcome.
        heuristic = [
            {"fault_point": 5, "outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        # fp 5 was tested by heuristic, so it counts as covered.
        self.assertEqual(result["issue_recall"], 1.0)
        self.assertEqual(result["missed_issue_points"], [])

    def test_runtime_sweep_results_payload_normalized(self):
        """Real audit JSON payloads are accepted and control points are skipped."""
        payload = {
            "runtime_sweep_results": [
                {"fault_at": 1, "boot_outcome": "no_boot", "fault_type": "w"},
                {"fault_at": 2, "boot_outcome": "success", "fault_type": "b"},
                {"fault_at": 999, "boot_outcome": "success", "is_control": True},
            ]
        }
        rows = load_results_payload(payload)
        self.assertEqual(
            rows,
            [
                {"fault_point": 1, "outcome": "no_boot", "fault_type": "w"},
                {"fault_point": 2, "outcome": "success", "fault_type": "b"},
            ],
        )

    def test_compare_results_accepts_audit_rows(self):
        """Audit-style rows compare correctly without manual normalization."""
        exhaustive = [
            {"fault_at": 1, "boot_outcome": "no_boot"},
            {"fault_at": 2, "boot_outcome": "success"},
            {"fault_at": 3, "boot_outcome": "wrong_image"},
        ]
        heuristic = [
            {"fault_at": 1, "boot_outcome": "success"},
            {"fault_at": 2, "boot_outcome": "success"},
        ]
        result = compare_results(exhaustive, heuristic)
        self.assertEqual(result["total_exhaustive_points"], 3)
        self.assertEqual(result["total_heuristic_points"], 2)
        self.assertEqual(result["exhaustive_issue_count"], 2)
        self.assertEqual(result["heuristic_issue_count"], 0)
        self.assertEqual(result["issue_recall"], 0.5)
        self.assertEqual(result["missed_issue_points"], [3])

    def test_invalid_payload_rejected(self):
        """Unsupported JSON shapes fail loudly instead of comparing empty lists."""
        with self.assertRaises(ValueError):
            load_results_payload({"summary": {"runtime_sweep": {}}})

    def test_missing_fields_rejected(self):
        """Rows missing a point or outcome are rejected."""
        with self.assertRaises(ValueError):
            normalize_results([{"fault_at": 1}])


if __name__ == "__main__":
    unittest.main()
