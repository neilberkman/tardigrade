# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import argparse
import html
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_formats import saved_run, write_formats


def row(index, outcome="success", **fields):
    return {"fault_type": "w", "fault_requested": index, "boot_outcome": outcome,
            "fault_injected": True, **fields}


def snapshot(changes, marks=()):
    spans = [{"address": hex(address), "size": len(bytes.fromhex(actual)),
              "actual_hex": actual, "expected_hex": "00" * len(bytes.fromhex(actual)),
              "bytes_truncated": False} for address, actual in changes]
    return {"identity_slot_base": "0x1000", "identity_slot_extent": 16,
            "uncorrectable_words": list(marks), "closest_declared_image": {
                "sha256": "a" * 64, "ranges_truncated": False, "differing_range_count": len(spans),
                "differing_bytes": sum(s["size"] for s in spans), "differing_ranges": spans}}


def audit(rows, tmp_path):
    return saved_run({"runtime_sweep_results": rows}, tmp_path / "audit.json", ROOT,
                     ROOT / "examples/phase2_mram_parity/profile_state_search.yaml")


def test_nearest_passing_sibling_and_observed_byte_ranges(tmp_path):
    left = snapshot([(0x1000, "01020304"), (0x1008, "ff")], ["0x1008"])
    right = snapshot([(0x1001, "0209"), (0x1007, "eeff")])
    failed = row(6, "no_boot", fault_snapshot=left)
    rows = [row(8, fault_snapshot=right), row(5, fault_injected=False), failed,
            row(7, "unknown"), row(6, fault_type="e"), row(4, fault_snapshot=right)]
    audit(rows, tmp_path)
    explanation = failed["failure_explanation"]
    assert explanation["passing_sibling"]["operation_index"] == 4
    assert explanation["state_comparison"]["ranges"] == [
        {"address": "0x00001000", "failing_hex": "01", "passing_hex": "00"},
        {"address": "0x00001002", "failing_hex": "0304", "passing_hex": "0900"},
        {"address": "0x00001007", "failing_hex": "00", "passing_hex": "ee"}]
    assert explanation["state_comparison"]["uncorrectable_only_in_failing"] == ["0x1008"]


def test_incomplete_snapshot_does_not_imply_equal_bytes(tmp_path):
    left = snapshot([(0x1001, "ff")])
    left["closest_declared_image"]["differing_ranges"][0]["bytes_truncated"] = True
    failed = row(1, "hard_fault", fault_snapshot=left)
    audit([failed, row(2, fault_snapshot=snapshot([]))], tmp_path)
    assert failed["failure_explanation"]["state_comparison"]["status"] == "no_complete_common_extent"


def test_equivalent_state_path_can_supply_passing_sibling(tmp_path):
    def chain(indices):
        return {"cuts": [{"operation_index": i, "fault_type": "power_loss"} for i in indices]}
    def state(indices, outcome, identity, aliases=()):
        return row(0, outcome, fault_type="rs", recovery_state_search={
            "chain": chain(indices), "state_identity": identity, "equivalent_chains": list(map(chain, aliases))})
    failed = state([1, 5], "no_boot", "bad")
    audit([state([1], "success", "parent", [[4]]), state([0, 4], "success", "other"),
           state([2], "success", "good", [[4, 9]]), failed], tmp_path)
    assert failed["failure_explanation"]["passing_sibling"] == {
        "state_identity": "good", "fault_type": "power_loss", "operation_index": 9}


def test_recovery_endpoint_and_messages_in_all_formats(tmp_path):
    failed = row(0, "hard_fault", signals={
        "pc": "0x100000a2", "recovery_execution": {"ipsr": 3, "stop_reason": "fault",
            "fault_timing": {"fault_first_active": {
                "source": "interrupt_begin", "exception": 3, "pc": "0x1000004a"}}}})
    report = audit([failed], tmp_path)
    args = argparse.Namespace(junit=tmp_path / "junit", sarif=tmp_path / "sarif", html=tmp_path / "html")
    write_formats(args, [report], ROOT)
    explanation = failed["failure_explanation"]
    endpoint = explanation["recovery"]
    assert endpoint["exception_entry"]["pc"] == "0x1000004A" and endpoint["exception"] == "HardFault"
    assert endpoint["last_observed"]["resolution"] == "dwarf"
    message = explanation["message"]
    result = json.loads(args.sarif.read_text())["runs"][0]["results"][0]
    assert result["properties"]["points"][0]["failure_explanation"] == explanation
    assert message in result["message"]["text"]
    failure = ET.parse(args.junit).find(".//failure")
    assert failure.get("message") == message and json.loads(failure.text.split("\n", 1)[1]) == explanation
    assert message in html.unescape(args.html.read_text())


def test_state_evaluation_has_no_execution_location(tmp_path):
    failed = row(2, "hard_fault", signals={"copy_completed": False, "vector_valid": True,
                                           "vector_reset": "0x10000045"})
    audit([failed], tmp_path)
    explanation = failed["failure_explanation"]
    assert explanation["recovery"]["execution_evidence"] == "simulated_copy"
    assert "last_observed" not in explanation["recovery"]
    assert "simulated copy was interrupted" in explanation["message"]


def test_cached_state_comparison_covers_regions_ecc_and_backend_values():
    from recovery_state import PersistentState, RegionState
    from recovery_search import compare_persistent_states
    region = RegionState.from_bytes("store", 0x1000, bytes(8200))
    reference = PersistentState([region], persistent_values={"counter": b"\x00"})
    changed = PersistentState([region.write_many([(4095, b"abc"), (8199, b"z")])],
                              uncorrectable_words=[("store", 8)], persistent_values={"counter": b"\x01"})
    comparison = compare_persistent_states(changed, reference)
    assert comparison == {
        "status": "compared_persistent_state",
        "ranges": [
            {"region": "store", "address": "0x00001FFF", "failing_hex": "616263", "passing_hex": "000000"},
            {"region": "store", "address": "0x00003007", "failing_hex": "7a", "passing_hex": "00"}],
        "uncorrectable_only_in_failing": ["0x00001008"], "uncorrectable_only_in_passing": [],
        "persistent_values": [{"name": "counter", "failing_hex": "01", "passing_hex": "00"}],
    }


def test_comparison_is_bound_to_the_final_passing_state(tmp_path):
    def state(index, outcome, identity, **fields):
        return row(index, outcome, fault_type="rs", recovery_state_search={
            "chain": {"cuts": [{"operation_index": index, "fault_type": "power_loss"}]},
            "state_identity": identity}, **fields)
    provisional = {"status": "compared_persistent_state", "ranges": []}
    bad = state(2, "no_boot", "b", _sibling_snapshot_comparison={"sibling": "a", "comparison": provisional})
    good = state(1, "success", "a")
    audit([bad, good], tmp_path)
    assert bad["failure_explanation"]["state_comparison"] == provisional
    bad.pop("failure_explanation")
    bad["_sibling_snapshot_comparison"] = {"sibling": "a", "comparison": provisional}
    good["semantic_observation_failures"] = ["missing"]
    audit([bad, good, state(4, "success", "c")], tmp_path)
    assert bad["failure_explanation"]["passing_sibling"]["state_identity"] == "c"
    assert bad["failure_explanation"]["state_comparison"]["status"] == "snapshots_unavailable"
    assert "_sibling_snapshot_comparison" not in bad


def test_exception_entry_pc_precedes_handler_pc():
    from test_deliberate_fault_after_success import _build_harness

    def step(state, _machine, _cpu, _mem, fire_fault):
        state["pc"] = 0x10100042
        fire_fault(3)
        state["pc"] = 0x10100080
        state["instructions"] = 100
        state["virtual_time"].seconds = 0.02

    namespace, state, _, cpu = _build_harness(step_fn=step, memory_specs=[], mem_values={})
    status = namespace["run_until_done"](cpu, time_slice="0.02", max_iters=1)
    entry = status["fault_timing"]["fault_first_active"]
    assert entry["source"] == "interrupt_begin" and entry["pc"] == "0x10100042"
    assert state["pc"] == 0x10100080
