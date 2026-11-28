# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def write(offset, value, time=7):
    return dict(kind="write", region="nvm", offset=offset, width=2, value=value,
                pc="0x00000040", virtual_us_since_reset=time)


def compare(a, b, start="a", mismatch=None):
    from recovery_trace_comparison import compare_recovery_traces
    return compare_recovery_traces(a, b, "a", start, 0x1000, 0xff, mismatch)


def test_write_data_disagreement_locates_last_writer_in_each_boot():
    a = [write(2, 1), write(3, 0x1234), write(8, 8)]
    b = [write(2, 1), write(3, 0x1278, 9), write(8, 8)]
    result = compare(a, b, mismatch=dict(kind="bytes", region="nvm", offset=3))
    assert result["classification"] == "same operations, different data"
    assert result["starting_state_identical"]
    diff = result["first_differing_operation"]
    assert diff["index"] == 1 and diff["live"]["address"] == "0x00001003"
    assert (diff["computed"]["data"], diff["live"]["data"]) == ("3412", "7812")
    assert diff["live"]["virtual_us_since_reset"] == 9
    assert result["last_completed_writer"]["computed"] == diff["computed"]


def test_sequence_disagreement_after_earlier_data_disagreement():
    erase = dict(kind="erase", region="nvm", offset=0, erase_size=4)
    result = compare([write(0, 2), erase], [write(0, 3), write(0, 4)])
    assert result["classification"] == "different operation sequence"
    assert result["first_differing_operation"]["index"] == 0


@pytest.mark.parametrize("short_side", ["computed", "live"])
def test_unmatched_tail_has_only_one_event(short_side):
    traces = [[write(0, 2)], [write(0, 2), write(4, 3)]]
    if short_side == "live":
        traces.reverse()
    result = compare(*traces)
    assert result["classification"] == "one boot ended early"
    assert result["trace_lengths"][short_side] == 1
    assert result["first_differing_operation"][short_side] is None


def test_replay_defect_requires_equal_initial_state_and_operations():
    a, b = [write(0, 2)], [write(0, 2, 12)]
    diff = dict(kind="bytes", region="nvm", offset=6)
    result = compare(a, b, mismatch=diff)
    assert result["classification"] == "identical traces, different resulting state (replay defect)"
    assert result["last_completed_writer"] == {"computed": None, "live": None}
    assert compare(a, b, start="b", mismatch=diff)["starting_state_identical"] is False
    assert compare(a, b)["classification"] == "identical traces"


def test_byte_history_distinguishes_completed_writer_and_overlapping_cut():
    from recovery_trace_comparison import compare_recovery_traces
    erased = dict(kind="erase", region="nvm", offset=0, erase_size=16)
    trace = [erased, write(2, 8)]
    diff = dict(kind="bytes", region="nvm", offset=2)
    result = compare_recovery_traces(trace, trace, "a", "a", 0x1000, 255, diff, cut_reached=True)
    assert result["last_completed_writer"]["computed"]["kind"] == "erase"
    assert result["interrupted_operation_covering_byte"]["live"]["index"] == 1


def test_different_tracking_bases_preclude_replay_defect():
    from recovery_trace_comparison import compare_recovery_traces
    result = compare_recovery_traces([], [], "start", "start", 0, 0,
                                     {"kind": "region_length"}, trace_bases=("a", "b"))
    assert result["classification"] == "identical operations, different states at tracking start"


def test_interrupted_program_compares_issued_data():
    a = [dict(write(2, 0xabcd), intended_value=0xabcd)]
    b = [dict(write(2, 0x00cd), intended_value=0xabcd)]
    assert compare(a, b)["classification"] == "identical traces"


def test_same_path_repeat_labels_the_second_observation():
    from recovery_trace_comparison import compare_recovery_traces, comparison_message
    result = compare_recovery_traces([write(0, 2)], [write(0, 3)], "a", "a", 0, 255,
                                     other_side="repeat")
    assert result["trace_lengths"] == {"computed": 1, "repeat": 1}
    assert result["first_differing_operation"]["repeat"]["data"] == "0300"
    assert "repeat write" in comparison_message(result)


def test_preflight_samples_distinct_selected_first_cuts_in_trace_order():
    from recovery_search import RecoveryStateExplorer
    from recovery_state import PersistentState, merge_operation_traces

    operations = merge_operation_traces([
        dict(write_index=i + 1, offset=0, width=2, value=v)
        for i, v in enumerate([2, 2, 3, 4])
    ], [])
    explorer = RecoveryStateExplorer(
        PersistentState.from_bytes(b"\x00\x00"), operations, range(4), 2, 4, 10,
        lambda: 0, lambda *args: pytest.fail("sampling issued a recovery boot"),
        backend_kind="mram", torn_word_mode="programmed")
    assert [chain[0]["operation_index"] for _, chain in explorer.preflight_states(2)] == [0, 2]
    assert list(explorer.preflight_states(0)) == []


def test_preflight_option_survives_strict_profile_loading(tmp_path):
    from profile_loader import load_profile
    root = Path(__file__).resolve().parents[1]
    base = root / "examples/phase2_mram_parity/profile_state_search.yaml"
    profile = tmp_path / "preflight.yaml"
    profile.write_text(base.read_text().replace("cross_check_every: 1",
                                               "cross_check_every: 1\n      determinism_preflight: 3"))
    config = load_profile(profile, strict=True).fault_sweep.phase2_fault.state_search
    assert config.to_runtime_dict()["determinism_preflight"] == 3


@pytest.mark.parametrize("length", [2, 3])
def test_missed_live_cut_retains_comparison_in_infrastructure_result(length):
    from test_phase2_fault_parity import _load_state_search_live_cross_check
    from recovery_trace_comparison import RecoveryTraceMismatch, compare_recovery_traces

    chain = [dict(operation_index=0, operation="write", trace_sequence=0) for _ in range(length)]

    def missed(*args, diagnostic, **kwargs):
        diagnostic.update(live=("a", [], "a"), ordinal=length)
        status = dict(matched=False, infrastructure_error=True, first_unreached_cut=length,
                      error="missed cut", error_kind="recovery_state_cross_check_cut_not_reached",
                      live_boot_outcome="success")
        return {key: {"cross_check_persistent_state": status}
                for key in ("phase2_fault", "phase2_fault_chain")}

    ns = dict(run_phase2_fault=missed, run_phase2_fault_chain=missed,
              _replay_storage_geometry=lambda: (0, 16, 4, 255),
              RecoveryTraceMismatch=RecoveryTraceMismatch, compare_recovery_traces=compare_recovery_traces)
    _load_state_search_live_cross_check(ns)
    with pytest.raises(RecoveryTraceMismatch) as error:
        ns["_state_search_live_cross_check"](object(), chain, length, None,
                                             lambda cuts: ([write(0, 2)], 10, "a", "a"))
    report = error.value.result()
    assert report["boot_outcome"] == "infra_error" and report["infrastructure_error"]
    assert report["error_kind"] == "recovery_state_cross_check_cut_not_reached"
    assert "one boot ended early" in report["error"]
    comparison = report["recovery_trace_comparison"]
    assert comparison["trace_lengths"] == {"computed": 1, "live": 0}
    assert comparison["computed_full_trace_length"] == 10
    assert comparison["first_unreached_cut"] == length
    assert comparison["live_boot_outcome"] == "success"

@pytest.mark.parametrize("kind", ["write", "erase"])
def test_truncated_device_export_is_refused(kind):
    import ast
    from types import SimpleNamespace

    path = Path(__file__).resolve().parents[1] / "scripts/run_runtime_fault_sweep.py"
    node = next(node for node in ast.parse(path.read_text()).body
                if getattr(node, "name", "") == "_state_search_capture_trace")
    target = SimpleNamespace(WriteTraceCount=int(kind == "write"), EraseTraceCount=int(kind == "erase"),
                             WriteTraceToString=lambda: "", EraseTraceToString=lambda: "")
    ns = dict(_state_search_trace_target=lambda: target, backend={"kind": "fast"},
              parse_erase_trace_map=lambda *a, **kw: {}, parse_write_trace_map=lambda *a, **kw: {},
              _state_search_operations_from_maps=lambda writes, erases: [])
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), ns)
    with pytest.raises(RuntimeError, match="recovery " + kind + " trace"):
        ns["_state_search_capture_trace"]()
