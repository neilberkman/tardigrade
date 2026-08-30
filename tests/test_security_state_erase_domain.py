import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from security_state_layout import (  # noqa: E402
    SecurityStateLayoutError,
    analyze_persistent_state_layout,
    parse_persistent_state_layout,
    select_security_state_erase_cutpoints,
)


def _layout(regions, fields):
    return parse_persistent_state_layout({"erase_regions": regions, "fields": fields})


def test_shared_unit_is_candidate_and_adjacent_unit_is_not():
    layout = _layout(
        [{"start": 0x1000, "end": 0x3000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "display", "base": 0x1200, "size": 4, "role": "mutable"},
            {"name": "other", "base": 0x2100, "size": 4, "role": "mutable"},
        ],
    )
    report = analyze_persistent_state_layout(layout)
    assert len(report["findings"]) == 1
    assert report["findings"][0]["code"] == "SECURITY_STATE_SHARED_ERASE_UNIT"
    assert report["findings"][0]["unit"] == {"start": 0x1000, "end": 0x2000}


def test_nonuniform_regions_map_addresses_and_crossing_field():
    layout = _layout(
        [
            {"start": 0x1000, "end": 0x3000, "erase_size": 0x1000},
            {"start": 0x3000, "end": 0x5000, "erase_size": 0x800},
        ],
        [
            {"name": "cross", "base": 0x1FF0, "size": 0x30, "role": "mutable"},
            {"name": "fine", "base": 0x3200, "size": 4, "role": "recovery"},
        ],
    )
    report = analyze_persistent_state_layout(layout)
    cross = next(field for field in report["fields"] if field["name"] == "cross")
    assert cross["units"] == [{"start": 0x1000, "end": 0x2000}, {"start": 0x2000, "end": 0x3000}]
    fine = next(field for field in report["fields"] if field["name"] == "fine")
    assert fine["units"] == [{"start": 0x3000, "end": 0x3800}]


@pytest.mark.parametrize(
    "regions,fields",
    [
        ([{"start": 0x1000, "end": 0x1800, "erase_size": 0x300}], []),
        ([{"start": 0x2000, "end": 0x1000, "erase_size": 0x100}], [{"name": "x", "base": 0x1000, "size": 1, "role": "mutable"}]),
        ([{"start": 0x1000, "end": 0x2000, "erase_size": 0x100}], [{"name": "x", "base": 0x1800, "size": 1, "role": "unknown"}]),
        ([{"start": 0x1000, "end": 0x2000, "erase_size": 0x100}], [{"name": "x", "base": 0x1FF0, "size": 0x20, "role": "mutable"}]),
    ],
)
def test_malformed_geometry_and_fields_fail_closed(regions, fields):
    with pytest.raises(SecurityStateLayoutError):
        _layout(regions, fields)


def test_conflicting_geometry_boundary_is_rejected():
    with pytest.raises(SecurityStateLayoutError, match="conflicting geometry"):
        _layout(
            [
                {"start": 0x1000, "end": 0x2000, "erase_size": 0x1000},
                {"start": 0x2000, "end": 0x3000, "erase_size": 0x800},
            ],
            [{"name": "x", "base": 0x1FF0, "size": 0x20, "role": "mutable"}],
        )


def test_erase_trace_precedes_geometry_and_emits_three_distinct_cuts():
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    cuts, summary = select_security_state_erase_cutpoints(
        layout,
        [
            {"write_index": 7, "flash_offset": 0x300},
            {"write_index": 8, "flash_offset": 0x200},
            {"write_index": 9, "flash_offset": 0x100},
        ],
        [{"flash_offset": 0, "erase_size": 0x1000, "writes_at_this_point": 7}],
        flash_base=0x1000,
    )
    assert summary["source"] == "erase_trace"
    assert [cut["fault_at"] for cut in cuts] == [7, 8]
    assert cuts[0]["phases"] == ["erase", "first_write_after_erase"]
    assert cuts[1]["phases"] == ["last_security_restore"]
    assert len({cut["wire_type"] for cut in cuts}) == 2


def test_semantically_duplicate_first_and_last_cut_is_merged():
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    cuts, _summary = select_security_state_erase_cutpoints(
        layout,
        [{"write_index": 2, "flash_offset": 0x100}],
        [{"flash_offset": 0, "erase_size": 0x1000, "writes_at_this_point": 1}],
        flash_base=0x1000,
    )
    assert [cut["fault_at"] for cut in cuts] == [1]
    assert cuts[0]["phases"] == [
        "erase", "first_write_after_erase", "last_security_restore"
    ]


def test_erase_count_minus_one_is_pre_erase_not_selected_erase_cut():
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    cuts, _summary = select_security_state_erase_cutpoints(
        layout,
        [{"write_index": 8, "flash_offset": 0x200}, {"write_index": 9, "flash_offset": 0x100}],
        [{"flash_offset": 0, "erase_size": 0x1000, "writes_at_this_point": 7}],
        flash_base=0x1000,
    )
    assert cuts[0]["fault_at"] == 7
    assert cuts[0]["fault_at"] != 6


def test_aliased_trace_ranges_select_shared_security_erase_unit():
    """Trace offsets must use the profile's CPU-visible alias mapping."""
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    cuts, summary = select_security_state_erase_cutpoints(
        layout,
        [
            {"write_index": 2, "flash_offset": 0x100},
            {"write_index": 3, "flash_offset": 0x200},
        ],
        [{"flash_offset": 0, "erase_size": 0x1000, "writes_at_this_point": 1}],
        # Without the map these offsets would be interpreted relative to the
        # unrelated backend base and the shared unit would be missed.
        flash_base=0x8000,
        trace_address_map=[
            {"offset_start": 0, "offset_end": 0x1000, "address_addend": 0x1000},
        ],
    )
    assert summary["status"] == "selected"
    assert summary["flagged_units"] == [{"start": 0x1000, "end": 0x2000}]
    assert [cut["fault_at"] for cut in cuts] == [1]
    assert "last_security_restore" in cuts[0]["phases"]


def test_geometry_fallback_uses_write_trace_and_separated_fields_are_clean():
    layout = _layout(
        [{"start": 0x1000, "end": 0x3000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x2100, "size": 4, "role": "mutable"},
        ],
    )
    cuts, summary = select_security_state_erase_cutpoints(
        layout,
        [{"write_index": 4, "flash_offset": 0x100}],
        [],
        flash_base=0x1000,
    )
    assert cuts == []
    assert summary["status"] == "clean"


def test_geometry_fallback_converts_one_based_write_index():
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    cuts, summary = select_security_state_erase_cutpoints(
        layout,
        [{"write_index": 8, "flash_offset": 0x100}],
        [],
        flash_base=0x1000,
    )
    assert summary["source"] == "declared_geometry"
    assert len(cuts) == 1
    assert cuts[0]["fault_at"] == 7
    assert set(cuts[0]["phases"]) == {
        "erase", "first_write_after_erase", "last_security_restore"
    }


def test_trace_geometry_mismatch_reports_both_ranges():
    layout = _layout(
        [{"start": 0x1000, "end": 0x2000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    with pytest.raises(SecurityStateLayoutError, match=r"\[0x1000, 0x1800\).*\[0x1000, 0x2000\)"):
        select_security_state_erase_cutpoints(
            layout,
            [],
            [{"flash_offset": 0, "erase_size": 0x800, "writes_at_this_point": 0}],
            flash_base=0x1000,
        )


def _synthetic_interrupted_mutable_update(layout, epoch_address, mutable_address):
    """Model a power cut immediately after the mutable field's unit erase."""
    policy_epoch = 7
    mutable = 1
    epoch_unit = next(unit for unit in layout.units if unit.start <= epoch_address < unit.end)
    mutable_unit = next(unit for unit in layout.units if unit.start <= mutable_address < unit.end)
    if epoch_unit == mutable_unit:
        policy_epoch = None  # erase cleared the security record before restoration
    return policy_epoch, mutable


def test_synthetic_runtime_shared_unit_loses_epoch_but_separated_units_pass():
    shared = _layout(
        [{"start": 0x1000, "end": 0x3000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x1200, "size": 4, "role": "mutable"},
        ],
    )
    separated = _layout(
        [{"start": 0x1000, "end": 0x3000, "erase_size": 0x1000}],
        [
            {"name": "policy_epoch", "base": 0x1100, "size": 8, "role": "security_monotonic"},
            {"name": "mutable", "base": 0x2100, "size": 4, "role": "mutable"},
        ],
    )
    shared_epoch, _ = _synthetic_interrupted_mutable_update(shared, 0x1100, 0x1200)
    separated_epoch, _ = _synthetic_interrupted_mutable_update(separated, 0x1100, 0x2100)
    assert shared_epoch is None
    assert separated_epoch == 7
