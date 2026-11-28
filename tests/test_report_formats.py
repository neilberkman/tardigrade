# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from point_counts import POINT_KIND_LABELS, build_point_counts
from render_results_html import write_html
from report_formats import saved_run, write_audit_report
from report_junit import junit_report
from report_points import ReportRun
from report_sarif import sarif_report

EXAMPLE = ROOT / "tests/fixtures/report_formats_mram.json"


def result(code="w", outcome="success", **fields):
    return {"fault_type": code, "fault_requested": 3, "fault_at": 3, "fault_injected": True,
            "boot_outcome": outcome, **fields}


def search(codes):
    cuts = [{"operation_index": i, "fault_type": code, "operation": "erase" if code == "e" else "write"}
            for i, code in enumerate(codes)]
    return result("rs", recovery_state_search={"chain": {"cuts": cuts}, "generation": len(cuts)})


def run(rows, **more):
    return ReportRun({"runtime_sweep_results": rows, **more}, "test", Path("profiles/test fixture.yaml"))


def all_kinds():
    pair = {"p1_fault_at": 2, "p2_fault_at": 5, "p1_fault_type": "e", "p2_fault_type": "b"}
    return [result(), result("e"), search("w"), search("e"), search("ew"), search("wew"),
            result("p2", phase2_fault=pair, phase2_selection="pairs"),
            result("p2", phase2_fault=pair, phase2_selection="grid"),
            result("pc", phase2_fault_chain={"cuts": [{"fault_at": i, "fault_type": c}
                                                      for i, c in enumerate("wew")]}),
            result("mf:3:6", fault_sequence=[3, 6]), result("c:3:7"), result("i"), result("f"),
            result("ic"), result("control", is_control=True, fault_injected=False)]


def test_junit_counts_cases_and_statuses():
    rows = all_kinds()
    report = run(rows, multi_fault_results=[result("mf:0:1", "hard_fault")],
                 terminal_error_results=[result("te", signals={"terminal_error_escaped": True})])
    rows.extend([result("w", "infra_error", error="broken <bus>\x01"), result("e", "timeout"),
                 result("w", "skipped", skip_reason="unreached"), result(fault_injected=False),
                 result("w", "hard_fault", signals={"total_ms": 105}),
                 result(signals={"total_ms": 250})])
    suites = ET.fromstring(junit_report([report, run([])]))
    suite = suites[0]
    counts = json.loads(suite.find("properties/property[@name='point_counts']").get("value"))
    assert len(suites) == 2
    assert {p.get("classname").split(".")[-1] for p in suite.findall("testcase")} == set(POINT_KIND_LABELS)
    assert Counter(p.get("classname").split(".")[-1] for p in suite.findall("testcase")) == {
        k: v["run"] for k, v in counts["kinds"].items() if v["run"]}
    assert int(suite.get("tests")) == len(suite.findall("testcase")) == counts["totals"]["run"]
    assert int(suite.get("failures")) == counts["totals"]["issues"] == 3
    assert suite.get("errors") == "1" and suite.get("skipped") == "3"
    assert suite.find(".//error").get("message") == "broken <bus>�"
    assert "hard_fault" in suite.find(".//failure[@type='brick']").text
    assert suite.get("time") == "0.355"
    assert suites[1].get("time") is None
    assert [c.get("time") for c in suite.findall("testcase") if c.get("time") is not None] == ["0.105", "0.250"]


def test_junit_suite_and_case_times_from_report_timing():
    rows = [
        result("e", signals={"phase1_ms": 632, "phase2_ms": 759, "followup_ms": 1313}),
        result("control", is_control=True, fault_injected=False,
               signals={"phase1_ms": 780, "phase2_ms": 0, "followup_ms": 1465}),
        result("pc", phase2_fault_chain={"cuts": [{"fault_at": 0, "fault_type": "w"}]},
               signals={"cut_ms": [410, 320], "final_boot_ms": 270, "followup_ms": 0}),
        result("mf:1:2", fault_sequence=[1, 2],
               per_fault_states=[{"signals": {"stage_ms": 150}}, {"signals": {"stage_ms": 250}}],
               signals={"multi_fault_recovery_ms": 100, "followup_ms": 0}),
        result("w", "skipped", fault_injected=False,
               signals={"phase1_ms": 0, "phase2_ms": 0, "followup_ms": 0}),
    ]
    report = run(rows, summary={"runtime_sweep": {"wall_time_s": 52.5}})
    suite = ET.fromstring(junit_report([report]))[0]
    assert suite.get("time") == "52.500"
    assert [c.get("time") for c in suite.findall("testcase")] == ["2.704", "2.245", "1.000", "0.500", None]


def test_junit_initial_timeout_and_followup_timeout():
    inconclusive = result("w", "no_boot", timeout=True)
    observed = result("w", "no_boot", boot_cycles=[{"boot_outcome": "no_boot"}, {"boot_outcome": "timeout"}])
    xml = ET.fromstring(junit_report([run([inconclusive, observed])]))
    assert [case[0].tag for case in xml.findall(".//testcase")] == ["skipped", "failure"]


def test_example_exports_preserve_json_and_group_recovery_states(tmp_path):
    data = json.loads(EXAMPLE.read_text())
    before = copy.deepcopy(data)
    commands = [sys.executable, str(ROOT / "scripts/report_formats.py"), "--input", str(EXAMPLE)]
    for name in ("junit", "sarif", "html"):
        commands.extend(["--" + name, str(tmp_path / name)])
    subprocess.run(commands, check=True)
    suite = ET.parse(tmp_path / "junit").find("testsuite")
    assert suite.get("failures") == "2" and suite.get("tests") == "3"
    assert suite.find(".//testcase[@time='0.304']") is not None
    sarif = json.loads((tmp_path / "sarif").read_text())
    results = sarif["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"brick", "vtor_expectation", "content_criteria"}
    points = results[0]["properties"]["points"]
    assert len(points) == 2
    assert points[0]["reproduction"] == {"FAULT_TYPE_CSV": "w", "FAULT_POINTS_CSV": "2"}
    assert points[1]["reproduction"]["fault_sweep"]["phase2_fault"]["pairs"][0][0] == 2
    html = (tmp_path / "html").read_text()
    assert "generation 1" in html and "generation 2" in html and "point counts by kind" in html
    assert json.loads(EXAMPLE.read_text()) == before


def test_sarif_reproduces_all_point_kinds():
    rows = all_kinds()
    for row in rows:
        row["signals"] = {"anti_rollback_ok": False}
    results = sarif_report([run(rows)], ROOT)["runs"][0]["results"]
    assert len(results) == 1 and results[0]["ruleId"] == "anti_rollback"
    points = results[0]["properties"]["points"]
    assert {point["kind"] for point in points} == set(POINT_KIND_LABELS)
    examples = {point["kind"]: point["reproduction"] for point in points}
    assert examples["two_cut_pairs"]["fault_sweep"]["phase2_fault"] == {
        "enabled": True, "first_fault_types": ["interrupted_erase"], "fault_types": ["bit_corruption"], "pairs": [[2, 5]]}
    assert examples["n_cut_explicit"]["fault_sweep"]["phase2_fault"]["chains"] == [
        [[0, "power_loss"], [1, "interrupted_erase"], [2, "power_loss"]]]
    assert examples["multi_fault"]["FAULT_TYPE_CSV"] == "mf:3:6"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "profiles/test%20fixture.yaml"


def test_sarif_distinguishes_classes_and_groups_named_checks():
    signals = {k: False for k in ("marker_ok", "otadata_expect_ok", "anti_rollback_ok", "reset_vector_offset_ok",
                                   "memory_checks_ok", "config_checks_ok", "bootloader_integrity_ok",
                                   "expectations_met", "vtor_ok", "vtor_aligned", "pc_ok")}
    signals["terminal_error_escaped"] = True
    row = result(signals=signals, semantic_assertion_failures=[{"path": "floor", "expected": 2, "actual": 1}],
                 invariant_violations=[{"name": "inv1", "description": "<invalid>"}, {"name": "inv2"}],
                 metadata_delta_violations=[{"field": "counter", "finding_category": "boot_count_suppressed"}],
                 confirm_cycle={key: True for key in ("confirm_incomplete", "rollback_not_ratcheted",
                                                      "metadata_inconsistent_after_confirm")})
    rows = [row, {**row, "fault_at": 4, "fault_requested": 4}, result("e", "infra_error"), result("w", "skipped")]
    expected = {"content_criteria", "otadata_expect", "anti_rollback", "reset_vector_offset", "memory_check",
                "config_check", "bootloader_integrity", "vtor_expectation", "vtor_alignment", "pc_expectation",
                "terminal_error_path_escape", "semantic_assertion", "invariant", "boot_count_suppressed",
                "confirm_incomplete", "rollback_not_ratcheted", "metadata_inconsistent_after_confirm"}
    sarif = sarif_report([run(rows)], ROOT)["runs"][0]
    assert {r["id"] for r in sarif["tool"]["driver"]["rules"]} == expected
    assert len(sarif["results"]) == len(expected) + 1
    assert all(len(r["properties"]["points"]) == 2 for r in sarif["results"])


@pytest.mark.parametrize(("outcome", "fields", "rule"), [
    ("no_boot", {}, "brick"), ("wrong_image", {}, "wrong_image"),
    ("wrong_image", {"signals": {"image_hash_match": "unknown"}}, "silent_corruption"),
    ("rollback_accepted", {}, "rollback_accepted"), ("toctou_corruption", {}, "toctou_corruption"),
    ("config_lost", {}, "config_lost"), ("config_crash", {}, "config_crash"),
    ("memory_checks_unmet", {}, "memory_checks_unmet"),
    ("wrong_image", {"severity": "security_bypass", "fault_type": "i"}, "security_bypass"),
])
def test_junit_and_sarif_failure_classes(outcome, fields, rule):
    report = run([result(outcome=outcome, **fields)])
    suite = ET.fromstring(junit_report([report]))
    assert suite.find(".//failure").get("type") == rule
    assert [r["ruleId"] for r in sarif_report([report], ROOT)["runs"][0]["results"]] == [rule]


def test_sarif_dwarf_locations_from_addresses_and_symbols(tmp_path):
    # Use the checked-in debug ELF, including its ARM Thumb symbol values.
    elf = ROOT / "examples/erase_before_program/firmware.elf"
    from elftools.elf.elffile import ELFFile
    with elf.open("rb") as stream:
        address = ELFFile(stream).get_section_by_name(".symtab").get_symbol_by_name("Reset_Handler")[0]["st_value"]
    rows = [result(outcome="hard_fault", fault_address=hex(address & ~1)),
            result(outcome="hard_fault", rc_injection={"applied_symbol": "Reset_Handler"}),
            result(outcome="hard_fault", fault_address="0xffffffff")]
    report = run(rows)
    report.elf = elf
    findings = sarif_report([report], ROOT)["runs"][0]["results"]
    assert len(findings) == 2
    physical = [r["locations"][0]["physicalLocation"] for r in findings]
    source = next(loc for loc in physical if loc["artifactLocation"]["uri"].endswith("firmware.c"))
    assert source["region"]["startLine"] > 1
    assert sorted(len(r["properties"]["points"]) for r in findings) == [1, 2]

    ota_elf = ROOT / "examples/vulnerable_ota/firmware.elf"
    state_rows = [
        result(outcome="hard_fault", fault_address="0x10000000",
               signals={"vector_base": "0x10000000", "vector_reset": "0x00000000"}),
        result(outcome="hard_fault", fault_address="0x1001c000",
               signals={"vector_base": "0x10000000", "vector_reset": "0x10000045"}),
    ]
    ota_report = run(state_rows)
    ota_report.elf = ota_elf
    ota_locs = [r["locations"][0]["physicalLocation"] for r in sarif_report([ota_report], ROOT)["runs"][0]["results"]]
    assert [(loc["artifactLocation"]["uri"], loc["region"]["startLine"]) for loc in ota_locs] == [
        ("examples/vulnerable_ota/firmware.c", 24),
        ("examples/vulnerable_ota/firmware.c", 57),
    ]


def test_html_raw_and_wrapped_batches(tmp_path):
    rows = all_kinds()
    for payload in [rows, {"runtime_sweep_results": rows}, {"aborted": False, "results": rows}, rows[0]]:
        out = tmp_path / "index.html"
        write_html([(Path("batch.json"), payload)], out)
        page = out.read_text()
        assert "Unsupported JSON" not in page
        assert "point counts by kind" in page
        if payload is not rows[0]:
            assert all(label in page for label in POINT_KIND_LABELS.values())
            assert "interrupted_erase[2] → bit_corruption[5]" in page
            assert "power_loss[0] → interrupted_erase[1] → power_loss[2]" in page


def test_explicit_pairs_retain_canonical_kind_without_profile():
    row = result("p2", phase2_fault={"p1_fault_at": 2, "p2_fault_at": 6})
    counts = build_point_counts([{**row, "phase2_selection": "pairs"}])
    report = run([row], summary={"runtime_sweep": {"point_counts": counts}})
    assert ".two_cut_pairs" in junit_report([report])


def test_legacy_compound_points_keep_all_stage_selectors():
    report = run([result("mf", "hard_fault", fault_sequence=[5, 3], fault_stage_codes=["w", "e"]),
                  result("cascade", "hard_fault", cascade={"write_fault_at": 2, "erase_fault_at": 6})])
    points = sarif_report([report], ROOT)["runs"][0]["results"][0]["properties"]["points"]
    assert [p["reproduction"]["FAULT_TYPE_CSV"] for p in points] == ["mf:5:3@e", "c:2:6"]


def test_different_invariants_and_memory_checks_at_same_location():
    rows = [result(signals={"memory_checks_ok": False, "failed_memory_checks": [
        {"index": i, "address": "0x2000", "summary": f"check {i} observed {v}"} for i in (0, 1)]})
            for v in (2, 3)]
    results = sarif_report([run(rows)], ROOT)["runs"][0]["results"]
    assert len(results) == 2 and all(r["ruleId"] == "memory_check" for r in results)
    assert all(len(r["properties"]["points"]) == 2 for r in results)


def test_auxiliary_findings_and_infrastructure():
    data = run([], partial_staging_results=[
        {"classification": "partial_image_booted", "truncation_point": {"offset": 64}},
        {"classification": "timeout", "truncation_point": {"offset": 32}}],
        state_fuzz_results=[{"scenario_index": 2, "mode": "fixture", "blob_sha256": "ab", "finding": True,
                             "issue_reasons": {"anti_rollback": 1}, "field_values": {"v": 3}, "crc_mode": "valid"}],
        fuzz_crash_results=[{"security_finding": True, "generated_profile": "regression.yaml", "sha256": "12",
                             "crash_file": "input.bin", "verdict": "PASS"}],
        authorization_review_analysis={"findings": [{"id": "SIGNED_FIELD_NOT_REVIEWED", "severity": "high",
            "sequence": "example", "message": "review missing"}, {"id": "infra", "severity": "configuration"}]})
    result_ids = {r["ruleId"] for r in sarif_report([data], ROOT)["runs"][0]["results"]}
    assert result_ids == {"partial_image_booted", "anti_rollback", "fuzz_crash", "SIGNED_FIELD_NOT_REVIEWED"}
    failed = ReportRun({"verdict": "INCONCLUSIVE", "error": "geometry mismatch"}, "setup", Path("profile.yaml"))
    assert ET.fromstring(junit_report([failed])).find(".//error").text == "geometry mismatch"
    sarif = sarif_report([failed], ROOT)["runs"][0]
    assert sarif["results"] == [] and sarif["invocations"][0]["executionSuccessful"] is False


def test_live_audit_preserves_json_bytes_and_writes_requested_formats(tmp_path):
    from clause_evidence import clause_evidence
    data = json.loads(EXAMPLE.read_text())
    expected = json.dumps({**data, "clause_evidence": clause_evidence(data)}, sort_keys=True, indent=2).encode()
    from profile_loader import load_profile
    path = ROOT / data["profile_path"]
    profile = load_profile(path)
    args = argparse.Namespace(profile=path, output=tmp_path / "audit.json",
                              junit=tmp_path / "xml", html=tmp_path / "index.html", sarif=tmp_path / "scan.sarif")
    write_audit_report(args, data, profile, ROOT)
    assert args.output.read_bytes() == expected
    assert ET.parse(args.junit).find("testsuite").get("failures") == "2"
    assert json.loads(args.sarif.read_text())["version"] == "2.1.0"
    assert "point counts by kind" in args.html.read_text()


def test_merge_orchestrated_reports_retains_suites_and_missing_child(tmp_path):
    from report_formats import child_report_args, collect_child_reports
    args = argparse.Namespace(junit=tmp_path / "all.xml", sarif=tmp_path / "all.sarif", html=None)
    data = json.loads(EXAMPLE.read_text())
    profile = ROOT / data["profile_path"]
    children = [(name, tmp_path / (name + ".json"), profile, "child failed to start") for name in ("A", "B")]
    _, path, _, _ = children[0]
    assert child_report_args(args, path) == ["--junit", str(path.with_suffix(".junit")),
                                            "--sarif", str(path.with_suffix(".sarif"))]
    report = saved_run(data, path, ROOT)
    path.with_suffix(".junit").write_text(junit_report([report]))
    path.with_suffix(".sarif").write_text(json.dumps(sarif_report([report], ROOT)))
    collect_child_reports(args, children)
    suites = ET.parse(args.junit).findall("testsuite")
    assert [(s.get("tests"), s.get("errors")) for s in suites] == [("3", "0"), ("1", "1")]
    runs = json.loads(args.sarif.read_text())["runs"]
    assert len(runs[0]["results"]) == 3 and not runs[1]["invocations"][0]["executionSuccessful"]


def test_no_sidecar_overwrites_json(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("sentinel")
    proc = subprocess.run([sys.executable, str(ROOT / "scripts/audit_bootloader.py"),
                           "--profile", "profiles/mcuboot_head_move_small_upgrade.yaml",
                           "--output", str(output), "--junit", str(output)], capture_output=True, text=True)
    assert proc.returncode == 2 and "distinct output path" in proc.stderr
    assert output.read_text() == "sentinel"


def test_phase2_requested_chain_and_reused_states():
    state = search("wew")
    metadata = state["recovery_state_search"]
    metadata["equivalent_chains"] = [metadata["chain"]]
    row = result("pc", "hard_fault", phase2_fault_chain={
        "cuts": [{"fault_at": 0, "fault_type": "w"}],
        "requested_cuts": [{"fault_at": i, "fault_type": c} for i, c in enumerate("wew")]})
    report = run([state, row])
    suite = ET.fromstring(junit_report([report]))[0]
    assert suite.get("tests") == "2" and report.counts["totals"]["reused"] == 1
    assert len(sarif_report([report], ROOT)["runs"][0]["results"][0]["properties"]["points"][0]
               ["reproduction"]["fault_sweep"]["phase2_fault"]["chains"][0]) == 3


@pytest.mark.parametrize("category", ["boot_count_exhausted", "boot_count_suppressed", "rollback_floor_decreased",
                                       "metadata_delta_below_min", "metadata_delta_above_max"])
def test_metadata_classes_survive_successful_boot(category):
    report = run([result(metadata_delta_violations=[{"field": "version", "finding_category": category}])])
    assert ET.fromstring(junit_report([report])).find(".//failure").get("type") == category
    assert sarif_report([report], ROOT)["runs"][0]["results"][0]["ruleId"] == category


def test_recovered_and_dismissed_findings_follow_audit_classification():
    recovered = result(outcome="hard_fault", final_boot_outcome="success",
                       multi_boot_analysis={"status": "recovered_after_failure"})
    dismissed = result(outcome="hard_fault", finding_validation={"disposition": "harness_artifact"})
    report = run([recovered, dismissed])
    results = sarif_report([report], ROOT)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["recovered_after_failure"]
    assert ET.fromstring(junit_report([report]))[0].get("failures") == "1"


def test_matrix_sidecars_include_every_child_preserving_wrapper(tmp_path, monkeypatch):
    import audit_bootloader as audit
    from types import SimpleNamespace

    data = json.loads(EXAMPLE.read_text())
    profile_path = ROOT / data["profile_path"]
    profile = SimpleNamespace(name="matrix", schema_version=1, initial_states=[
        SimpleNamespace(name=name, description=name) for name in ("first", "second")], profile_path=profile_path)
    profile.resolve_initial_state = lambda state: SimpleNamespace(bootloader_elf=None)
    args = argparse.Namespace(output=tmp_path / "report.json", profile=profile_path, no_assert_verdict=True,
                              repo_root=str(ROOT), junit=tmp_path / "report.xml", sarif=tmp_path / "report.sarif",
                              html=tmp_path / "index.html")

    def child(command, **kwargs):
        if command[0] == "git":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        path = Path(command[command.index("--output") + 1])
        assert "--junit" not in command and not any(arg.startswith("--sarif=") for arg in command)
        path.write_text(json.dumps({**data, "verdict": "PASS", "summary": {}}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sys, "argv", ["audit", "--profile", str(profile_path), "--output", str(args.output),
                                     "--junit", str(args.junit), "--sarif=" + str(args.sarif)])
    monkeypatch.setattr(audit.subprocess, "run", child)
    assert audit._run_initial_state_matrix(args, profile) == 0
    assert [(s.get("name"), s.get("tests")) for s in ET.parse(args.junit).findall("testsuite")] == [
        ("matrix/first", "3"), ("matrix/second", "3")]
    assert len(json.loads(args.sarif.read_text())["runs"]) == 2
    assert all("_child_payload" not in r for r in json.loads(args.output.read_text())["initial_state_results"])


def test_action_optional_artifacts_available_before_gate():
    import yaml
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(step for step in action["runs"]["steps"] if step.get("id") == "run")
    for fmt in ("junit", "html", "sarif"):
        assert action["inputs"][fmt]["default"] == "false"
        assert action["outputs"][fmt + "-path"]["value"] == "${{ steps.run.outputs." + fmt + "_path }}"
        assert step["env"][fmt.upper() + "_INPUT"] == "${{ inputs." + fmt + " }}"
    assert step["run"].index("_path=${path}") < step["run"].index("publish-report")


def test_raw_batch_respects_supplied_profile_outcome_and_pair_selection(tmp_path):
    profile = tmp_path / "negative.yaml"
    profile.write_text("name: negative\nexpect: {control_outcome: no_boot}\nfault_sweep: {phase2_fault: {pairs: [[3, 1]]}}\n")
    rows = [result("p2", "no_boot", phase2_fault={"p1_fault_at": 3, "p2_fault_at": 1})]
    report = saved_run(rows, tmp_path / "raw.json", tmp_path, profile_path=profile)
    assert report.counts["kinds"]["two_cut_pairs"]["run"] == 1
    assert report.counts["totals"]["issues"] == 0
    assert ET.fromstring(junit_report([report]))[0].get("failures") == "0"
    assert sarif_report([report], tmp_path)["runs"][0]["results"] == []
