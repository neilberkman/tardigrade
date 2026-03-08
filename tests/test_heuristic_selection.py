"""Tests for write_trace_heuristic run segmentation and stratified sampling."""

import sys
import os

# Allow importing from scripts/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from write_trace_heuristic import (
    _sample_bulk_run,
    _segment_runs,
    classify_trace,
)


# ---------------------------------------------------------------------------
# Helpers to build synthetic traces.
# ---------------------------------------------------------------------------

PAGE = 4096
# Slot layout for tests: two 256KB slots starting at 0x10000.
SLOT_RANGES = {
    "exec": (0x10000, 0x50000),
    "staging": (0x50000, 0x90000),
}


def _make_trace(offsets, start_write_idx=1):
    """Build a trace list from a sequence of flash offsets.

    Returns list of (write_index, flash_offset) with 1-based write indices.
    """
    return [(start_write_idx + i, off) for i, off in enumerate(offsets)]


def _bulk_offsets(base, count, word_size=4):
    """Generate `count` sequential word-aligned offsets starting at `base`."""
    return [base + i * word_size for i in range(count)]


# ---------------------------------------------------------------------------
# 1. Run segmentation tests
# ---------------------------------------------------------------------------


class TestSegmentRuns:
    """Tests for _segment_runs()."""

    def test_single_contiguous_bulk_run(self):
        """One long sequential bulk run -> one run detected."""
        # 50 sequential writes inside a single page.
        offsets = _bulk_offsets(0x20000, 50)
        trace = _make_trace(offsets)
        # All are tier3: trace indices 0..49
        tier3_indices = list(range(50))

        runs = _segment_runs(tier3_indices, trace, PAGE)

        assert len(runs) == 1
        start, end, length = runs[0]
        assert start == 0
        assert end == 49
        assert length == 50

    def test_gap_splits_into_two_runs(self):
        """A gap > 1 page between writes splits into two runs."""
        offsets_a = _bulk_offsets(0x20000, 20)
        offsets_b = _bulk_offsets(0x30000, 20)  # >1 page gap from end of A
        trace = _make_trace(offsets_a + offsets_b)
        tier3_indices = list(range(40))

        runs = _segment_runs(tier3_indices, trace, PAGE)

        assert len(runs) == 2
        assert runs[0] == (0, 19, 20)
        assert runs[1] == (20, 39, 20)

    def test_non_contiguous_trace_indices_split(self):
        """Non-adjacent trace indices (tier1 write in between) split runs."""
        # indices 0,1,2 then skip 3 (tier1), then 4,5,6
        offsets = _bulk_offsets(0x20000, 7)
        trace = _make_trace(offsets)
        tier3_indices = [0, 1, 2, 4, 5, 6]  # gap at index 3

        runs = _segment_runs(tier3_indices, trace, PAGE)

        assert len(runs) == 2
        assert runs[0] == (0, 2, 3)
        assert runs[1] == (4, 6, 3)

    def test_no_tier3_writes_empty(self):
        """No tier3 writes -> no runs."""
        trace = _make_trace([0x4F000, 0x4F004])  # trailer region
        runs = _segment_runs([], trace, PAGE)
        assert runs == []

    def test_single_write_run(self):
        """A single tier3 write is a run of length 1."""
        trace = _make_trace([0x20000])
        runs = _segment_runs([0], trace, PAGE)
        assert len(runs) == 1
        assert runs[0] == (0, 0, 1)


# ---------------------------------------------------------------------------
# 2. Stratified sampling tests
# ---------------------------------------------------------------------------


class TestSampleBulkRun:
    """Tests for _sample_bulk_run()."""

    def test_long_run_has_structural_anchors(self):
        """200-write run -> anchors at 0%, 10%, 25%, 50%, 75%, 90%, 100%."""
        run_start = 100
        run_length = 200
        run_end = run_start + run_length - 1

        selected = _sample_bulk_run(run_start, run_end, run_length,
                                    tier3_step=100, tier2_step=3)

        # Expected anchor offsets within the run.
        expected_anchors = {
            run_start + int(p * 199)
            for p in [0.0, 0.10, 0.25, 0.50, 0.75, 0.90, 1.0]
        }
        for anchor in expected_anchors:
            assert anchor in selected, f"Missing anchor at {anchor}"

    def test_long_run_budget_reasonable(self):
        """Total selected ~ run_length // tier3_step for long runs."""
        run_start = 0
        run_length = 500
        run_end = run_length - 1

        selected = _sample_bulk_run(run_start, run_end, run_length,
                                    tier3_step=100, tier2_step=3)

        budget = max(7, run_length // 100)  # = 7
        # Should be close to budget (anchors + fill). Allow some tolerance
        # because fill points may collide with anchors.
        assert len(selected) >= 7
        # Should not be dramatically more than budget.
        assert len(selected) <= budget + 7  # anchors can add up to 7

    def test_short_run_dense_sampling(self):
        """Short run (<=20) uses tier2_step density."""
        run_start = 0
        run_length = 15
        run_end = 14

        selected = _sample_bulk_run(run_start, run_end, run_length,
                                    tier3_step=100, tier2_step=3)

        # Every 3rd + endpoints. At least ceil(15/3) = 5 points.
        assert len(selected) >= 5
        assert run_start in selected
        assert run_end in selected

    def test_medium_run_anchors_plus_periodic(self):
        """Medium run (21-100) has start, mid, end anchors."""
        run_start = 10
        run_length = 60
        run_end = 69

        selected = _sample_bulk_run(run_start, run_end, run_length,
                                    tier3_step=100, tier2_step=3)

        assert run_start in selected
        assert run_end in selected
        midpoint = run_start + run_length // 2
        assert midpoint in selected

    def test_single_write_run(self):
        """Run of length 1 returns that single index."""
        selected = _sample_bulk_run(42, 42, 1, tier3_step=100, tier2_step=3)
        assert selected == [42]


# ---------------------------------------------------------------------------
# 3. Structural signal promotion tests
# ---------------------------------------------------------------------------


class TestStructuralSignalPromotion:
    """Tests for page-entry, page-exit, and overwrite promotion to tier1."""

    def test_overwrite_promoted_to_tier1(self):
        """Same address written twice -> second write promoted to tier1."""
        # Build trace: bulk writes in mid-slot, with one repeated address.
        base = 0x20000
        offsets = _bulk_offsets(base, 10)
        # Repeat the 5th address (index 4 and 5 will have same offset).
        offsets[5] = offsets[4]
        trace = _make_trace(offsets)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        # The overwrite fault point (write_idx=6, fp=5) must be selected.
        assert 5 in result

    def test_page_entry_promoted(self):
        """First write to a new page is promoted to tier1."""
        # Writes spanning two pages inside bulk region.
        page_a_end = 0x20000 + PAGE - 4  # last word in page
        page_b_start = 0x20000 + PAGE     # first word in next page
        offsets = [
            page_a_end - 8, page_a_end - 4, page_a_end,
            page_b_start, page_b_start + 4, page_b_start + 8,
        ]
        trace = _make_trace(offsets)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        # page_b_start is at trace index 3, write_idx=4, fp=3.
        assert 3 in result

    def test_page_exit_promoted(self):
        """Last write before page change is promoted to tier1."""
        page_a_end = 0x20000 + PAGE - 4
        page_b_start = 0x20000 + PAGE
        offsets = [
            page_a_end - 8, page_a_end - 4, page_a_end,
            page_b_start, page_b_start + 4,
        ]
        trace = _make_trace(offsets)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        # page_a_end is at trace index 2, write_idx=3, fp=2 (page exit).
        assert 2 in result


# ---------------------------------------------------------------------------
# 4. Backward compatibility tests
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Verify tier0 and tier1 semantics are unchanged."""

    def test_trailer_writes_all_selected(self):
        """All writes to trailer region (last page of slot) are tier1."""
        # Trailer of exec slot: 0x50000 - PAGE = 0x4F000 to 0x50000.
        trailer_base = 0x50000 - PAGE
        offsets = _bulk_offsets(trailer_base, 20)
        trace = _make_trace(offsets)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        # All 20 fault points (0..19) must be selected.
        expected = list(range(20))
        for fp in expected:
            assert fp in result

    def test_bootloader_region_all_selected(self):
        """All writes to bootloader region are tier0 (always selected)."""
        bl_region = (0x0, 0x8000)
        offsets = _bulk_offsets(0x1000, 30)
        trace = _make_trace(offsets)

        result = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, bootloader_region=bl_region
        )

        # All 30 fault points must be selected.
        for fp in range(30):
            assert fp in result

    def test_discontinuity_writes_selected(self):
        """Writes near address discontinuities are tier1."""
        # Two clusters with a big gap.
        offsets_a = _bulk_offsets(0x20000, 5)
        offsets_b = _bulk_offsets(0x60000, 5)  # >1 page gap
        trace = _make_trace(offsets_a + offsets_b)

        result = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, discontinuity_window=2
        )

        # The discontinuity is between trace index 4 and 5.
        # Window=2 means indices 3,4,5,6,7 are tier1.
        # fp = write_idx - 1 = trace_index (since write_idx starts at 1).
        for fp in [3, 4, 5, 6, 7]:
            assert fp in result

    def test_no_long_bulk_runs_similar_output(self):
        """With only short bulk runs, output count is reasonable."""
        # 30 writes: 10 trailer + 20 bulk (short run).
        trailer_offsets = _bulk_offsets(0x4F000, 10)  # exec trailer
        bulk_offsets = _bulk_offsets(0x25000, 20)      # mid-slot
        trace = _make_trace(trailer_offsets + bulk_offsets)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        # All 10 trailer are tier1 -> 10 selected.
        # 20 bulk in a short run -> dense sampling ~7 + endpoints.
        # Plus first/last. Should be reasonable, not dramatically inflated.
        assert len(result) >= 10  # at least the trailer writes
        assert len(result) <= 30  # not more than total


# ---------------------------------------------------------------------------
# 5. First/last fault points always included
# ---------------------------------------------------------------------------


class TestFirstLastAlwaysIncluded:
    """First and last fault points must always be in the result."""

    def test_first_and_last_included(self):
        """Verify first and last fault points are always selected."""
        offsets = _bulk_offsets(0x25000, 500)
        trace = _make_trace(offsets, start_write_idx=100)

        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)

        first_fp = 100 - 1   # = 99
        last_fp = 599 - 1    # = 598
        assert first_fp in result
        assert last_fp in result

    def test_single_write_trace(self):
        """Single-write trace returns that one fault point."""
        trace = [(1, 0x25000)]
        result = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        assert result == [0]


# ---------------------------------------------------------------------------
# 6. Empty trace
# ---------------------------------------------------------------------------


class TestEmptyTrace:
    """Empty trace edge case."""

    def test_empty_trace_returns_empty(self):
        result = classify_trace([], SLOT_RANGES, page_size=PAGE)
        assert result == []


# ---------------------------------------------------------------------------
# 7. Target points budget
# ---------------------------------------------------------------------------


class TestTargetPoints:
    """target_points trims low-risk tiers only, never tier0/tier1."""

    def test_target_points_trims_total(self):
        """Result should not exceed target_points."""
        # Mix tier1 (trailer) + tier2 (boundary) + tier3 (bulk).
        # Structural signal promotions inflate tier1, so target must
        # exceed the mandatory core to see trimming on lower tiers.
        trailer_offsets = _bulk_offsets(0x4F000, 10)  # tier1
        boundary_offsets = _bulk_offsets(0x10000, 20)  # tier2 (first page)
        bulk_offsets = _bulk_offsets(0x25000, 500)  # tier3
        trace = _make_trace(trailer_offsets + boundary_offsets + bulk_offsets)

        uncapped = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        # Target above tier0+tier1 core but below total.
        target = 25
        assert len(uncapped) > target
        capped = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, target_points=target
        )
        assert len(capped) <= target

    def test_target_points_preserves_tier0(self):
        """Bootloader region (tier0) is never trimmed."""
        bl_region = (0x0, 0x8000)
        bl_offsets = _bulk_offsets(0x1000, 20)
        bulk_offsets = _bulk_offsets(0x25000, 300)
        trace = _make_trace(bl_offsets + bulk_offsets)

        result = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            bootloader_region=bl_region, target_points=25,
        )
        # All 20 bootloader writes must survive.
        for fp in range(20):
            assert fp in result

    def test_target_points_preserves_tier1(self):
        """Trailer writes (tier1) are never trimmed."""
        trailer_offsets = _bulk_offsets(0x4F000, 15)  # exec trailer
        bulk_offsets = _bulk_offsets(0x25000, 300)
        trace = _make_trace(trailer_offsets + bulk_offsets)

        result = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, target_points=20,
        )
        # All 15 trailer writes must survive.
        for fp in range(15):
            assert fp in result

    def test_target_points_no_effect_when_under(self):
        """When total points <= target_points, no trimming."""
        offsets = _bulk_offsets(0x25000, 10)
        trace = _make_trace(offsets)

        uncapped = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        capped = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, target_points=1000
        )
        assert uncapped == capped


# ---------------------------------------------------------------------------
# 8. Sharding
# ---------------------------------------------------------------------------


class TestSharding:
    """shard_count/shard_index partitions tier3 across shards."""

    def test_shards_all_contain_critical_core(self):
        """Every shard gets all tier1 (trailer) points."""
        trailer_offsets = _bulk_offsets(0x4F000, 10)
        bulk_offsets = _bulk_offsets(0x25000, 200)
        trace = _make_trace(trailer_offsets + bulk_offsets)

        trailer_fps = set(range(10))
        for shard_idx in range(4):
            result = classify_trace(
                trace, SLOT_RANGES, page_size=PAGE,
                shard_count=4, shard_index=shard_idx,
            )
            # All trailer points in every shard.
            assert trailer_fps.issubset(set(result))

    def test_shards_are_different(self):
        """Different shards select different tier3 points."""
        offsets = _bulk_offsets(0x25000, 500)
        trace = _make_trace(offsets)

        shard0 = set(classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            shard_count=4, shard_index=0,
        ))
        shard1 = set(classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            shard_count=4, shard_index=1,
        ))
        # They should differ (different tier3 slices).
        assert shard0 != shard1

    def test_shards_union_covers_full_selection(self):
        """All shards together cover the same points as shard_count=1."""
        offsets = _bulk_offsets(0x25000, 200)
        trace = _make_trace(offsets)

        full = set(classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, shard_count=1,
        ))
        union = set()
        for i in range(4):
            shard = classify_trace(
                trace, SLOT_RANGES, page_size=PAGE,
                shard_count=4, shard_index=i,
            )
            union.update(shard)
        assert union == full

    def test_shard_count_1_is_no_op(self):
        """shard_count=1 produces identical output to default."""
        offsets = _bulk_offsets(0x25000, 200)
        trace = _make_trace(offsets)

        default = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        sharded = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            shard_count=1, shard_index=0,
        )
        assert default == sharded


# ---------------------------------------------------------------------------
# 9. Random tail budget
# ---------------------------------------------------------------------------


class TestRandomTailBudget:
    """random_tail_budget adds extra points from unselected tier3 pool."""

    def test_random_tail_adds_points(self):
        """With random_tail_budget > 0, result has more points."""
        offsets = _bulk_offsets(0x25000, 500)
        trace = _make_trace(offsets)

        base = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        with_tail = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, random_tail_budget=20,
        )
        assert len(with_tail) > len(base)

    def test_random_tail_deterministic(self):
        """Same seed produces same extra points."""
        offsets = _bulk_offsets(0x25000, 500)
        trace = _make_trace(offsets)

        r1 = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, random_tail_budget=10,
        )
        r2 = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, random_tail_budget=10,
        )
        assert r1 == r2

    def test_random_tail_different_shards_different_extra(self):
        """Different shard_index gives different random extra points."""
        offsets = _bulk_offsets(0x25000, 500)
        trace = _make_trace(offsets)

        r0 = set(classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            shard_count=2, shard_index=0, random_tail_budget=10,
        ))
        r1 = set(classify_trace(
            trace, SLOT_RANGES, page_size=PAGE,
            shard_count=2, shard_index=1, random_tail_budget=10,
        ))
        # The random extras should differ due to different seed.
        assert r0 != r1

    def test_random_tail_zero_is_no_op(self):
        """random_tail_budget=0 is identical to default."""
        offsets = _bulk_offsets(0x25000, 200)
        trace = _make_trace(offsets)

        default = classify_trace(trace, SLOT_RANGES, page_size=PAGE)
        with_zero = classify_trace(
            trace, SLOT_RANGES, page_size=PAGE, random_tail_budget=0,
        )
        assert default == with_zero
