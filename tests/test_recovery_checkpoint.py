# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import base64
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from recovery_search import RecoveryStateExplorer
from recovery_state import PersistentState, merge_operation_traces


INPUTS = dict(firmware_sha256="firmware", profile_sha256="profile",
              tardigrade_revision="revision", renode_version="1.17.0")


def model(limit=100, seconds=100, boots=None, checks=None):
    now = [0]
    baseline = PersistentState.from_bytes(b"\xff" * 8192,
                                          persistent_values={"epoch": b"\x01"})

    def trace(offsets):
        return merge_operation_traces([
            {"write_index": i + 1, "offset": offset, "width": 1, "value": offset}
            for i, offset in enumerate(offsets)
        ], [])

    def boot(state, chain, generation):
        now[0] += 1
        if boots is not None:
            boots.append(state.identity_hex())
        # The deferred trace starts with a different persistent snapshot.
        trace_base = state.write("nvm", 16, bytes([generation]))
        ops = trace([4, 5, 4, 6]) if generation < 3 else ()
        return {"boot_outcome": "success", "boot_slot": "exec"}, ops, trace_base

    def check(state, chain, generation, operation):
        if checks is not None:
            checks.append((state.identity_hex(), generation, operation["sequence"]))
        return {"matched": True}

    return RecoveryStateExplorer(
        baseline, trace([0, 1, 2]), (0, 1, 2), 3, limit, seconds,
        lambda: now[0], boot, backend_kind="mram", torn_word_mode="uncorrectable",
        program_unit=1, cross_check_every=2, cross_check=check,
    )


def saved(explorer):
    return json.loads(json.dumps(explorer.checkpoint(INPUTS)))


def test_wall_checkpoint_holds_verdicts_traces_and_ordered_partial_trace():
    explorer = model(seconds=4)
    results, summary = explorer.run()
    assert summary["stopped_reason"] == "max_wall_time_s"
    assert summary["complete"] is False
    data = saved(explorer)
    assert data["inputs"] == INPUTS
    assert [r["recovery_state_search"]["state_identity"] for r in data["results"]] == [
        r["recovery_state_search"]["state_identity"] for r in results
    ]
    assert all(r["boot_outcome"] == "success" for r in data["results"])
    assert [[op["offset"] for op in t] for t in data["recovery_traces"]] == [[4, 5, 4, 6]] * 4
    assert [frame[:2] for frame in data["trace_queue"]] == [[0, 1], [1, 0], [2, 0], [3, 0]]
    assert data["cross_check_position"] == 0
    assert data["counters"]["states_booted"] == 4
    for _, _, identity, _ in data["trace_queue"]:
        state = data["snapshots"][identity]
        assert state["persistent_values"] == {"epoch": "AQ=="}
        assert state["uncorrectable_words"]
    assert len(data["chunks"]) < sum(len(s["regions"][0][3]) for s in data["snapshots"].values())


def test_restore_handles_character_octets_from_worker_base64(monkeypatch):
    from recovery_checkpoint import SnapshotWriter, restore_snapshots

    raw = bytes(range(256))
    state = PersistentState.from_bytes(raw, persistent_values={"register": raw[::-1]})
    writer = SnapshotWriter()
    identity = writer.reference(state)
    decode = base64.b64decode
    monkeypatch.setattr(base64, "b64decode", lambda text: decode(text).decode("latin-1"))
    restored = restore_snapshots({"chunks": writer.chunks, "snapshots": writer.states})[identity]
    assert restored.materialize() == state.materialize()
    assert restored.persistent_values == state.persistent_values


@pytest.mark.parametrize("key", INPUTS)
def test_resume_refuses_each_changed_input_before_any_boot(key):
    explorer = model(limit=4)
    explorer.run()
    boots = []
    with pytest.raises(ValueError, match=key):
        model(boots=boots).restore(saved(explorer), dict(INPUTS, **{key: "changed"}))
    assert not boots


@pytest.mark.parametrize("first_limit,first_seconds", [(4, 100), (100, 4), (1, 100), (100, 1)])
@pytest.mark.parametrize("additional", [3, 100])
def test_split_matches_single_including_bounded_counts(first_limit, first_seconds, additional):
    boots, checks = [], []
    first = model(first_limit, first_seconds, boots, checks)
    prior, first_summary = first.run()
    assert first_summary["complete"] is False
    data = saved(first)
    if first_summary["stopped_reason"] == "max_new_states":
        assert len(set(v[2] for v in data["pending_visits"] + data["computed_frontier"]) - set(boots)) == (
            first_summary["states_excluded_by_max_new_states"]
        )
        assert data["pending_visits"]

    second = model(limit=additional, boots=boots, checks=checks)
    second.restore(data, INPUTS)
    actual, summary = second.run()
    expected_boots, expected_checks = [], []
    single = model(first_limit + additional, first_seconds + 100, expected_boots, expected_checks)
    expected, expected_summary = single.run()
    assert boots == expected_boots
    assert len(boots) == len(set(boots))
    assert checks == expected_checks
    assert summary == expected_summary
    for i, r in enumerate(actual):
        assert r["recovery_state_search"].pop("resume_origin") == (
            "before_resume" if i < len(prior) else "after_resume"
        )
    assert actual == expected
    assert (second.checkpoint(INPUTS) is None) == expected_summary["complete"]


def test_cross_check_sampling_position_survives_a_second_resume():
    checks = []
    first = model(limit=18, seconds=18, checks=checks)
    prior, _ = first.run()
    data = saved(first)
    assert data["cross_check_position"] > 0
    second = model(limit=1, checks=checks)
    second.restore(data, INPUTS)
    interim, _ = second.run()
    third = model(checks=checks)
    third.restore(saved(second), INPUTS)
    results, summary = third.run()
    uninterrupted_checks = []
    _, uninterrupted = model(checks=uninterrupted_checks).run()
    assert checks == uninterrupted_checks
    assert len(prior) < len(interim) < len(results)
    assert uninterrupted == summary


def test_audit_checkpoint_fingerprints_firmware_and_inherited_profile_except_budgets(tmp_path):
    from audit_bootloader import _state_search_checkpoint_vars
    from profile_loader import load_profile
    import yaml

    raw = yaml.safe_load((ROOT / "examples/phase2_mram_parity/profile_state_search.yaml").read_text())
    image = tmp_path / "slot.bin"
    image.write_bytes(b"original")
    raw["images"]["exec"] = str(image)
    base = tmp_path / "base.yaml"
    base.write_text(yaml.safe_dump(raw))
    derived = tmp_path / "derived.yaml"
    derived.write_text("base_profile: base.yaml\n")
    args = SimpleNamespace(profile=derived, output=tmp_path / "r.json", robot_suite="tests/ota_fault_point.robot",
                           robot_var=[], no_hash_bypass=False, progress_stall_timeout_s=2,
                           resume_state_search=None)

    def inputs():
        profile = load_profile(derived)
        variables = _state_search_checkpoint_vars(profile, ROOT, args, profile.robot_vars(ROOT))
        config = next(v.split(":", 1)[1] for v in variables if v.startswith("PHASE2_STATE_SEARCH_B64:"))
        return json.loads(base64.b64decode(config))["checkpoint_inputs"]

    original = inputs()
    derived.write_text("base_profile: base.yaml\nfault_sweep:\n  phase2_fault:\n    state_search:\n"
                       "      max_new_states: 2\n      max_wall_time_s: 2\n")
    assert inputs() == original
    image.write_bytes(b"modified")
    assert inputs()["firmware_sha256"] != original["firmware_sha256"]
    raw["fault_sweep"]["phase2_fault"]["state_search"]["cross_check_every"] = 3
    base.write_text(yaml.safe_dump(raw))
    assert inputs()["profile_sha256"] != original["profile_sha256"]


def test_resume_refuses_changed_search_settings_supplied_to_runner(tmp_path):
    from audit_bootloader import _state_search_checkpoint_vars
    from profile_loader import load_profile

    path = ROOT / "examples/phase2_mram_parity/profile_state_search.yaml"
    profile = load_profile(path)
    args = SimpleNamespace(profile=path, output=tmp_path / "report.json",
                           robot_suite="tests/ota_fault_point.robot", no_hash_bypass=False,
                           resume_state_search=tmp_path / "first.checkpoint.json")
    prefix = "PHASE2_STATE_SEARCH_B64:"

    def settings(variables):
        value = next(v[len(prefix):] for v in variables if v.startswith(prefix))
        return json.loads(base64.b64decode(value))

    variables = profile.robot_vars(ROOT)
    config = settings(_state_search_checkpoint_vars(profile, ROOT, args, variables))
    checkpoint = {"version": 1, "inputs": config["checkpoint_inputs"]}
    args.resume_state_search.write_text(json.dumps(checkpoint))
    changed = settings(variables)
    changed["cross_check_every"] += 1
    override = prefix + base64.b64encode(json.dumps(changed).encode()).decode()
    variables = [override if v.startswith(prefix) else v for v in variables]
    with pytest.raises(ValueError, match="runtime_options_sha256"):
        _state_search_checkpoint_vars(profile, ROOT, args, variables, checkpoint)


def test_final_checkpoint_refused():
    with pytest.raises(ValueError, match="final"):
        model().restore({"version": 1, "final": True}, INPUTS)


def test_sum_of_wall_budgets_preserves_exact_deadline_and_unexpanded_queue():
    phases = []
    first = model(limit=3, seconds=5)
    first.run()
    second = model(limit=100, seconds=2, boots=phases)
    second.restore(saved(first), INPUTS)
    rows, summary = second.run()
    expected, total = model(limit=103, seconds=7).run()
    assert len(rows) == 7 and len(phases) == 4
    assert summary == total
    assert summary["unexpanded_states_at_wall_time"] > 0
    for r in rows:
        r["recovery_state_search"].pop("resume_origin")
    assert rows == expected


def test_limited_search_makes_campaign_incomplete():
    from audit_report import summarize_runtime_sweep
    search = model(limit=1)
    results, _ = search.run()
    for result in results:
        result["fault_injected"] = True
    summary = summarize_runtime_sweep(results, expected_fault_points=1, expected_control_points=0)
    assert summary["campaign_complete"] is False
    assert summary["campaign_integrity"]["complete"] is False


@pytest.mark.parametrize("key", ["tardigrade_revision", "firmware_sha256", "profile_sha256"])
def test_cli_names_host_input_mismatch_before_calibration(tmp_path, monkeypatch, capsys, key):
    import audit_bootloader as audit
    path = ROOT / "examples/phase2_mram_parity/profile_state_search.yaml"
    inputs = audit._state_search_inputs(audit.load_profile(path), ROOT)
    inputs[key] = "different"
    source = tmp_path / "first.checkpoint.json"
    source.write_text(json.dumps({
        "version": 1, "inputs": inputs, "limits": {}, "elapsed_s": 0,
    }))
    monkeypatch.setattr(sys, "argv", ["audit", "--profile", str(path), "--output", str(tmp_path / "run.json"),
                                      "--resume-state-search", str(source), "--no-assert-verdict"])
    monkeypatch.setattr(audit, "ensure_tool", lambda *_args: pytest.fail("started runner selection"))
    assert audit.main() == audit.EXIT_INFRA_FAILURE
    assert "state search checkpoint mismatch: " + key in capsys.readouterr().err
