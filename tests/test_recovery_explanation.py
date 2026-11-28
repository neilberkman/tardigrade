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


def test_byte_range_attribution_and_dwarf_vs_symtab_message_shape(tmp_path):
    from elftools.elf.elffile import ELFFile
    from source_locations import SourceLocations

    dwarf_elf = ROOT / "examples/phase2_mram_parity/firmware.elf"
    dwarf_loc = SourceLocations(dwarf_elf, ROOT)
    _, dwarf_ranges, _, _, _ = dwarf_loc.index
    code_ranges = [r for r in dwarf_ranges if r[4]]
    write_pc = f"0x{code_ranges[0][0]:08X}"
    fault_pc = f"0x{code_ranges[-1][0]:08X}"
    write_resolved = dwarf_loc.resolve_pc(write_pc)
    fault_resolved = dwarf_loc.resolve_pc(fault_pc)

    left = snapshot([(0x1004, "ffffffff")])
    right = snapshot([(0x1004, "77c295f3")])
    window = {
        "operations": [
            {
                "sequence": 4,
                "operation": "write",
                "operation_index": 3,
                "address": "0x00001004",
                "width": 4,
                "value": "0xF395C277",
                "pc": write_pc,
            }
        ]
    }
    failed = row(
        3,
        "no_boot",
        fault_address="0x00001004",
        fault_pc=write_pc,
        fault_snapshot=left,
        fault_window=window,
        signals={
            "pc": fault_pc,
            "phase2_executed_instructions": 42,
            "phase2_terminal_self_branch_observation": {"pc": fault_pc},
        },
    )
    passed = row(4, "success", fault_snapshot=right)
    report = saved_run(
        {"runtime_sweep_results": [failed, passed]},
        tmp_path / "dwarf_audit.json",
        ROOT,
        ROOT / "examples/phase2_mram_parity/profile_state_search.yaml",
        elf=dwarf_elf,
    )
    args = argparse.Namespace(
        junit=tmp_path / "dwarf.junit",
        sarif=tmp_path / "dwarf.sarif",
        html=tmp_path / "dwarf.html",
    )
    write_formats(args, [report], ROOT)

    exp = failed["failure_explanation"]
    assert exp["cuts"][0]["pc"] == write_pc
    assert exp["cuts"][0]["source"]["resolution"] == "dwarf"
    span_op = exp["state_comparison"]["ranges"][0]["operation"]
    assert span_op["operation"] == "write"
    assert span_op["operation_index"] == 3
    assert span_op["pc"] == write_pc
    assert span_op["source"]["file"] == write_resolved["file"]
    assert span_op["source"]["line"] == write_resolved["line"]
    assert exp["recovery"]["last_function"]["function"] == fault_resolved["function"]
    expected_msg = (
        f"cut during {write_resolved['function']} at {write_resolved['file']}:{write_resolved['line']} "
        f"leaves 0x00001004..0x00001007 (4 bytes) holding ffffffff instead of 77c295f3; "
        f"recovery hung in self-branch (no boot) at {fault_resolved['function']} "
        f"{fault_resolved['file']}:{fault_resolved['line']}"
    )
    assert exp["message"] == expected_msg
    assert expected_msg in args.sarif.read_text()
    assert ET.parse(args.junit).find(".//failure").get("message") == expected_msg
    assert expected_msg in html.unescape(args.html.read_text())

    # Symbol-table fallback when DWARF line info is absent.
    sym_elf = ROOT / "examples/naive_copy/bootloader_bare_copy.elf"
    with sym_elf.open("rb") as stream:
        symtab = ELFFile(stream).get_section_by_name(".symtab")
        funcs = [
            s for s in symtab.iter_symbols()
            if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] >= 8
        ]
    sym_pc = f"0x{((funcs[0]['st_value'] & ~1) + 2):08X}"
    sym_failed = row(
        1,
        "no_boot",
        fault_address="0x00001004",
        fault_pc=sym_pc,
        fault_snapshot=left,
        signals={"pc": sym_pc, "phase2_executed_instructions": 10},
    )
    saved_run(
        {"runtime_sweep_results": [sym_failed, row(2, "success", fault_snapshot=right)]},
        tmp_path / "sym_audit.json",
        ROOT,
        ROOT / "examples/phase2_mram_parity/profile_state_search.yaml",
        elf=sym_elf,
    )
    sym_exp = sym_failed["failure_explanation"]
    assert sym_exp["cuts"][0]["source"]["resolution"] == "symbol_table"
    assert "symbol table only" in sym_exp["message"]
    assert funcs[0].name in sym_exp["message"]


def test_two_cut_neighbouring_parent_sibling_and_p2_trace_attribution(tmp_path):
    import base64
    import zlib

    dwarf_elf = ROOT / "examples/phase2_mram_parity/firmware.elf"
    from source_locations import SourceLocations
    dwarf_loc = SourceLocations(dwarf_elf, ROOT)
    _, dwarf_ranges, _, _, _ = dwarf_loc.index
    code_ranges = [r for r in dwarf_ranges if r[4]]
    p1_pc = f"0x{code_ranges[0][0]:08X}"
    p2_pc = f"0x{code_ranges[1][0]:08X}"
    end_pc = f"0x{code_ranges[-1][0]:08X}"

    def encode_state(word_bytes):
        buf = bytearray(b"\xff" * 64)
        buf[0x30:0x34] = word_bytes
        return {
            "base_address": "0x0003FFC0",
            "size": len(buf),
            "zlib_b64": base64.b64encode(zlib.compress(bytes(buf), 1)).decode("ascii"),
        }

    failed = {
        "fault_at": 5179,
        "fault_requested": 5179,
        "fault_type": "p2",
        "fault_injected": True,
        "fault_address": "0x0003FFF0",
        "fault_pc": p2_pc,
        "boot_outcome": "wrong_image",
        "boot_slot": "exec",
        "fault_class": "wrong_image",
        "_pre_recovery_state": encode_state(b"\xff\xff\xff\xff"),
        "phase2_fault": {
            "p1_fault_at": 5179,
            "p2_fault_at": 48,
            "p1_fault_type": "w",
            "p2_fault_type": "w",
            "p1_injected": True,
            "p2_injected": True,
            "p1_fault_address": "0x0003FF34",
            "p2_fault_address": "0x0003FFF0",
            "p1_fault_pc": p1_pc,
            "p2_fault_pc": p2_pc,
            "p2_write_trace": [
                {
                    "write_index": 49,
                    "flash_offset": 0x3FFF0,
                    "address": "0x0003FFF0",
                    "value": "0xF395C277",
                    "width": 4,
                    "pc": p2_pc,
                }
            ],
            "p2_erase_trace": [],
        },
        "signals": {
            "pc": end_pc,
            "phase2_executed_instructions": 100,
            "phase2_terminal_self_branch_observation": {"pc": end_pc},
        },
    }
    passed = {
        "fault_at": 5174,
        "fault_requested": 5174,
        "fault_type": "p2",
        "fault_injected": True,
        "fault_address": "0x0003FFF0",
        "boot_outcome": "success",
        "boot_slot": "exec",
        "fault_class": "recoverable",
        "_pre_recovery_state": encode_state(b"\x77\xc2\x95\xf3"),
        "phase2_fault": {
            "p1_fault_at": 5174,
            "p2_fault_at": 35,
            "p1_fault_type": "w",
            "p2_fault_type": "w",
            "p1_injected": True,
            "p2_injected": True,
            "p1_fault_address": "0x0003DFEC",
            "p2_fault_address": "0x0003FFF0",
            "p2_write_trace": [],
            "p2_erase_trace": [],
        },
        "signals": {"pc": end_pc, "phase2_executed_instructions": 100},
    }
    saved_run(
        {"runtime_sweep_results": [passed, failed]},
        tmp_path / "p2_audit.json",
        ROOT,
        ROOT / "examples/phase2_mram_parity/profile_state_search.yaml",
        elf=dwarf_elf,
    )
    assert "_pre_recovery_state" not in failed and "_pre_recovery_state" not in passed
    exp = failed["failure_explanation"]
    assert exp["passing_sibling"] == {
        "operation_index": 35,
        "fault_type": "power_loss",
        "parent_operation_index": 5174,
    }
    assert len(exp["cuts"]) == 2
    assert exp["cuts"][1]["pc"] == p2_pc
    span = exp["state_comparison"]["ranges"][0]
    assert span["address"] == "0x0003FFF0"
    assert span["failing_hex"] == "ffffffff"
    assert span["passing_hex"] == "77c295f3"
    assert span["operation"]["operation_index"] == 48
    assert span["operation"]["pc"] == p2_pc
    assert span["operation"]["source"]["resolution"] == "dwarf"


def test_recovery_endpoint_stays_at_unsymbolized_application_pc(tmp_path):
    # Only the boot firmware has a matching ELF. All earlier PCs resolve.
    previous = "0x1000004A"
    failed = row(0, "no_boot", signals={
        "pc": "0x103e8",
        "phase2_executed_instructions": 100,
        "phase2_pc_samples": [previous],
        "phase2_pc_handoff_observation": {"indirect_branches": [{"pc": previous}]},
    }, phase2_fault={"p2_write_trace": [{"write_index": 1, "pc": previous}]})
    audit([failed], tmp_path)
    endpoint = failed["failure_explanation"]["recovery"]
    assert endpoint["last_function"] == endpoint["last_observed"] == {
        "resolution": "address_only", "pc": "0x000103E8",
    }


def test_saved_report_uses_original_endpoint_evidence(tmp_path):
    observed = {"pc": "0x000103E8", "resolution": "address_only"}
    earlier = {"pc": "0x1000004A", "function": "old_write", "resolution": "symbol_table"}
    recovery = {"last_observed": observed, "last_function": earlier}
    explanation = {"message": "recorded message", "recovery": recovery}
    failed = row(0, "no_boot", failure_explanation=explanation)
    audit([failed], tmp_path)
    assert recovery["last_function"] == observed
    assert failed["failure_explanation"]["message"] == "recorded message"


def test_missing_endpoint_pc_has_no_last_function(tmp_path):
    failed = row(0, "no_boot", signals={
        "phase2_executed_instructions": 42,
        "phase2_pc_handoff_observation": {"indirect_branches": [{"pc": "0x1000004A"}]},
    })
    audit([failed], tmp_path)
    assert "last_function" not in failed["failure_explanation"]["recovery"]
