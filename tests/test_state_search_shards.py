# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_report import summarize_runtime_sweep
from profile_loader import ProfileError, RecoveryStateSearchConfig, load_profile
from recovery_search import RecoveryStateExplorer
from recovery_state import PersistentState, merge_operation_traces
from tardigrade.cli import main


def operations(values):
    writes = [{"write_index": i + 1, "offset": offset, "value": value, "width": 1}
              for i, (offset, value) in enumerate(values)]
    return merge_operation_traces(writes, [])


def model(index=None, limit=100, expire_after=None, sample=1, *, count=4,
          explorer_only=False, plan_only=False, order="breadth_first"):
    boots = []
    def boot(state, chain, generation):
        value = state.materialize()["nvm"][0]
        boots.append((generation, state.identity_hex()))
        # Both first cuts reach 6. Distinct second-cut roots converge again
        # one generation later. The last boot also returns a terminal trace.
        if value in (1, 2):
            values = range(3, 8) if value == 1 else range(6, 10)
        elif value < 10:
            values = (20, 21, 1)
        else:
            values = (42,)
        ops = operations([(1, 0xff), *((0, v) for v in values)])
        return ({"fault_injected": True, "boot_outcome": "no_boot" if value == 20 else "success",
                 "boot_slot": "exec", "signals": {}}, ops)

    options = dict(
        initial_state=PersistentState.from_bytes(b"\xff\xff"),
        calibration_operations=operations([(0, 1), (0, 2)]),
        first_cuts=[0, 1], max_cuts=4, max_new_states=limit, max_wall_time_s=1,
        clock=lambda: int(expire_after is not None and len(boots) >= expire_after),
        boot_state=boot, backend_kind="mram", torn_word_mode="programmed",
        address_ranges=[{"start": 0, "end": 0}], cross_check_every=sample,
        cross_check=lambda *_: {"matched": True},
        order=order,
    )
    if index is None:
        explorer = RecoveryStateExplorer(**options)
    else:
        from recovery_search_shard import ShardedRecoveryStateExplorer
        explorer = ShardedRecoveryStateExplorer(shard_index=index, shard_count=count,
                                                plan_only=plan_only, **options)
    if explorer_only:
        return explorer
    rows, summary = explorer.run()
    runtime = summarize_runtime_sweep(rows, expected_fault_points=1, expected_control_points=0)
    if index is None:
        return rows, summary
    expect = {"control_outcome": "success", "should_find_issues": True, "mode": "regression"}
    return {"state_search_shard": {**explorer.partition, "firmware_sha256": "1" * 64,
                                   "profile_sha256": "2" * 64, "tardigrade_revision": "3" * 40,
                                   "renode_version": "1.17.0",
                                   "report_context": {"expect": expect, "page_size": 4096, "slots": {},
                                                      "planned_fault_types": ["rs"], "total_writes": 2,
                                                      "calibration_point_coverage": {}}},
            "summary": {"runtime_sweep": runtime}, "runtime_sweep_results": rows,
            "expect": expect, "profile": "model", "calibrated_writes": 2, "fault_points_tested": 1}


def test_generation_two_partition_covers_each_candidate_once():
    from recovery_search_shard import chain_key, state_owner

    reports = [model(i) for i in range(4)]
    assigned = {}
    for index, report in enumerate(reports):
        for row in report["runtime_sweep_results"]:
            m = row["recovery_state_search"]
            if m["generation"] == 1:
                for cut, identity in row["shard_expansion"]["edges"]:
                    chain = chain_key([*m["chain"]["cuts"], cut])
                    assert state_owner(identity, 4) == index
                    assert chain not in assigned
                    assigned[chain] = identity
    expected = {}
    for row in model()[0]:
        m = row["recovery_state_search"]
        for chain in [m["chain"], *m.get("equivalent_chains", [])]:
            if chain["cut_count"] == 2:
                expected[chain_key(chain["cuts"])] = m["state_identity"]
    assert len(expected) == 9
    assert assigned == expected
    assert model(2) == reports[2]


@pytest.mark.parametrize("limit", [100, 5, 1])
def test_merge_matches_single_breadth_first_search_including_limits(limit):
    from merge_state_search import merge_reports

    reports = [model(i, limit=limit, sample=1) for i in reversed(range(4))]
    merged = merge_reports(reports)
    rows, summary = model(limit=limit, sample=1)
    assert merged["runtime_sweep_results"] == rows
    assert merged["summary"]["runtime_sweep"]["recovery_state_search"] == summary
    complete = limit == 100
    assert merged["summary"]["runtime_sweep"]["campaign_complete"] is complete
    if complete:
        assert len(rows) < sum(r["summary"]["runtime_sweep"]["recovery_state_search"]["states_booted"]
                               for r in reports)
        assert any(r["boot_outcome"] == "no_boot" for r in rows)


def test_merge_generation_two_sample_ordinal_matches_single():
    from merge_state_search import merge_reports

    for limit in range(1, 16):
        for sample in range(0, 4):
            merged = merge_reports([model(i, limit=limit, sample=sample) for i in range(4)])
            rows, summary = model(limit=limit, sample=sample)
            assert merged["runtime_sweep_results"] == rows
            assert merged["summary"]["runtime_sweep"]["recovery_state_search"] == summary


def test_one_runner_wall_limit_makes_union_incomplete():
    from merge_state_search import merge_reports

    reports = [model(i, expire_after=1 if i == 2 else None) for i in range(4)]
    merged = merge_reports(reports)
    sweep = merged["summary"]["runtime_sweep"]
    assert merged["state_search_merge"]["stopped_shards"] == {2: "max_wall_time_s"}
    assert sweep["recovery_state_search"]["stopped_reason"] == "max_wall_time_s"
    assert merged["verdict"].startswith("INCONCLUSIVE")
    assert not sweep["campaign_integrity"]["complete"]
    assert sweep["recovery_state_search"]["states_excluded_by_wall_time"] == 3


@pytest.mark.parametrize("field,value", [("firmware_sha256", "a"*64), ("profile_sha256", "b"*64),
                                         ("tardigrade_revision", "c"*40), ("renode_version", "1.16.1"),
                                         ("shard_count", 5)])
def test_refuse_different_inputs(field, value):
    from merge_state_search import merge_reports

    reports = [model(0), model(1)]
    reports[1]["state_search_shard"][field] = value
    with pytest.raises(ValueError, match="shard 1 mismatched " + field):
        merge_reports(reports)


@pytest.mark.parametrize("indices,error", [([0, 2, 3], "missing shard 1"),
                                          ([2, 0, 1, 2, 3], "duplicate shard 2")])
def test_refuse_missing_or_repeated_shard(indices, error):
    from merge_state_search import merge_reports

    with pytest.raises(ValueError, match=error):
        merge_reports([model(i) for i in indices])


def test_refuse_conflicting_outcomes_for_the_same_first_cut():
    from merge_state_search import merge_reports

    reports = [model(i) for i in range(4)]
    row = reports[1]["runtime_sweep_results"][0]
    row["boot_outcome"] = "wrong_image"
    with pytest.raises(ValueError, match="conflicting outcomes for state " + row["recovery_state_search"]["state_identity"]):
        merge_reports(reports)


def test_refuse_a_missing_boot_record_from_a_complete_runner():
    from merge_state_search import merge_reports

    reports = [model(i) for i in range(4)]
    reports[3]["runtime_sweep_results"].pop()
    with pytest.raises(ValueError, match="shard 3 is missing boot records"):
        merge_reports(reports)


def test_cli_merges_saved_reports(tmp_path):
    paths = []
    for index in range(4):
        path = tmp_path / f"{index}.json"
        path.write_text(json.dumps(model(index)))
        paths.append(str(path))
    output = tmp_path / "merged.json"
    assert main(["merge-state-search", "--output", str(output), *paths]) == 0
    assert json.loads(output.read_text())["runtime_sweep_results"] == model()[0]


def test_input_digest_uses_inherited_profile_and_image_contents(tmp_path):
    from audit_bootloader import _state_search_shard_inputs

    profile = ROOT / "examples/phase2_mram_parity/profile_state_search_16_corrupted.yaml"
    image = tmp_path / "image.bin"
    image.write_bytes(b"one")
    def inputs(index, limit=32):
        path = tmp_path / f"shard-{index}.yaml"
        path.write_text(f"base_profile: {profile}\nimages:\n  exec: {image}\nfault_sweep:\n"
                        f"  phase2_fault:\n    state_search: {{shard_count: 4, shard_index: {index}, max_new_states: {limit}}}\n")
        parsed = load_profile(path, repo_root=ROOT)
        config = parsed.fault_sweep.phase2_fault.state_search.to_runtime_dict()
        assert (config["shard_index"], config["shard_count"]) == (index, 4)
        return _state_search_shard_inputs(parsed, ROOT)
    baseline = inputs(0)
    assert inputs(3) == baseline
    assert inputs(0, 40)["profile_sha256"] != baseline["profile_sha256"]
    image.write_bytes(b"two")
    assert inputs(0)["firmware_sha256"] != baseline["firmware_sha256"]


@pytest.mark.parametrize("count,index", [(0, 0), (2, -1), (2, 2), (True, 0), (4, 1.5)])
def test_invalid_shard_config(count, index):
    with pytest.raises(ProfileError, match="state_search.shard"):
        RecoveryStateSearchConfig(shard_count=count, shard_index=index)
    assert "shard_count" not in RecoveryStateSearchConfig().to_runtime_dict()


@pytest.mark.parametrize("detached", [False, True])
def test_merge_refuses_cross_check_without_positive_evidence(detached):
    from merge_state_search import merge_reports

    reports = [model(i) for i in range(4)]
    if detached:
        reports[0]["state_search_shard"]["cross_checks"].append([[99, 99], {"matched": False}])
    else:
        meta = next(r["recovery_state_search"] for r in reports[0]["runtime_sweep_results"]
                    if "cross_check" in r["recovery_state_search"])
        meta["cross_check"]["matched"] = False
    with pytest.raises(ValueError, match="shard 0.*cross-check"):
        merge_reports(reports)

@pytest.mark.parametrize("limit", [1, 3, 6])
@pytest.mark.parametrize("index", range(4))
def test_shard_resume_preserves_evidence_and_counts(index, limit):
    first = model(index, limit, explorer_only=True)
    first.run()
    checkpoint = json.loads(json.dumps(first.checkpoint({})))
    expected = model(index, explorer_only=True)
    rows, summary = expected.run()
    if checkpoint is None:
        assert len(first.results) == len(rows)
        return
    resumed = model(index, 100 - limit, explorer_only=True)
    resumed.restore(checkpoint, {})
    actual, resumed_summary = resumed.run()
    for row in actual:
        row["recovery_state_search"].pop("resume_origin")
    assert actual == rows
    assert resumed_summary == summary
    assert resumed.partition == expected.partition


@pytest.mark.parametrize("index,count,field", [(0, 4, "shard_index"), (1, 3, "shard_count"),
                                               (None, 1, "shard_index")])
def test_cannot_move_checkpoint_to_another_shard(index, count, field):
    first = model(1, limit=1, explorer_only=True)
    first.run()
    with pytest.raises(ValueError, match=field):
        model(index, count=count, explorer_only=True).restore(first.checkpoint({}), {})


@pytest.mark.parametrize("index", range(4))
def test_shard_plan_predicts_owned_second_generation(index):
    explorer = model(index, explorer_only=True, plan_only=True)
    _, summary = explorer.run()
    assert explorer.checkpoint({}) is None
    full = model(index)
    rows = full["runtime_sweep_results"]
    actual = [row for row in rows if row["recovery_state_search"]["generation"] <= 2]
    plan = summary["generation_two_plan"]
    assert plan["recovery_boots_through_generation_two"] == len(actual)
    roots = [row for row in actual if row["recovery_state_search"]["generation"] == 1]
    counts = [len(row["shard_expansion"]["edges"]) for row in roots]
    traces = summary["first_cut_traces"]
    full_traces = full["summary"]["runtime_sweep"]["recovery_state_search"]["first_cut_traces"]
    for plan_row, full_row in zip(traces, full_traces, strict=True):
        assert {key: plan_row[key] for key in full_row} == full_row
    assert [r["owned_generation_two_candidates"] for r in traces] == counts
    assert plan["generation_two_candidates"] == sum(counts)


@pytest.mark.parametrize("sample", [0, 1, 2, 3])
def test_best_first_unlimited_shard_merge_matches_single_and_breadth_first_outcomes(sample):
    from merge_state_search import merge_reports

    reports = [model(i, limit=100, sample=sample, order="best_first") for i in reversed(range(4))]
    merged = merge_reports(reports)
    rows, summary = model(limit=100, sample=sample, order="best_first")
    assert merged["runtime_sweep_results"] == rows
    assert merged["summary"]["runtime_sweep"]["recovery_state_search"] == summary
    assert merged["summary"]["runtime_sweep"]["campaign_complete"] is True
    bfs_rows, _bfs_summary = model(limit=100, sample=sample, order="breadth_first")
    assert {
        r["recovery_state_search"]["state_identity"]: r["boot_outcome"] for r in rows
    } == {
        r["recovery_state_search"]["state_identity"]: r["boot_outcome"] for r in bfs_rows
    }


@pytest.mark.parametrize("limit", [1, 3, 6])
@pytest.mark.parametrize("index", range(4))
def test_best_first_shard_resume_preserves_evidence_and_counts(index, limit):
    first = model(index, limit, explorer_only=True, order="best_first")
    first.run()
    checkpoint = json.loads(json.dumps(first.checkpoint({})))
    expected = model(index, explorer_only=True, order="best_first")
    rows, summary = expected.run()
    if checkpoint is None:
        assert len(first.results) == len(rows)
        return
    resumed = model(index, 100 - limit, explorer_only=True, order="best_first")
    resumed.restore(checkpoint, {})
    actual, resumed_summary = resumed.run()
    for row in actual:
        row["recovery_state_search"].pop("resume_origin")
    assert actual == rows
    assert resumed_summary == summary
    assert resumed.partition == expected.partition
