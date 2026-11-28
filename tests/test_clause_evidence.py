# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def audit():
    from audit_report import summarize_runtime_sweep
    control = {"is_control": True, "boot_outcome": "success", "fault_injected": False}
    point = {
        "boot_outcome": "success", "fault_type": "w", "fault_at": 0, "fault_injected": True,
        "effective_success_criteria": {"vtor_slot": "exec", "image_hash": True},
        "signals": {"vtor_ok": True, "image_hash_actual": "a" * 64, "image_hash_match": "exec_image"},
    }
    rows = [control, point, {**point, "fault_type": "b", "boot_outcome": "wrong_image"}]
    summary = summarize_runtime_sweep(rows, expected_fault_points=2,
                                      planned_fault_types=["w", "b"], expected_control_points=1)
    return {"engine": "renode-test", "profile": "demo", "verdict": "PASS",
            "runtime_sweep_results": rows, "summary": {"runtime_sweep": summary}}


def test_selects_faults_criteria_and_observed_verdicts():
    from clause_evidence import clause_evidence
    recovery, authenticity, integrity = clause_evidence(audit())["clauses"]
    rec, auth, data = [c["campaigns"][0] for c in (recovery, authenticity, integrity)]
    assert rec["points_evaluated"] == 1 and rec["returned_points_omitted"] == 1
    assert rec["criteria"] == {"boot_handoff": {"criterion_met": 1}, "running_image": {}}
    assert rec["absent_criteria"] == ["running_image"]
    assert auth["points_evaluated"] == data["points_evaluated"] == 2
    assert auth["verdicts"] == {"finding": 1, "observation": 1}
    assert data["criteria"] == {"image_digest": {"exec_image": 2}}
    assert auth["absent_criteria"] == ["verification_probe"]
    assert authenticity["campaigns"][1]["requested_fault_points"] is None


def test_skipped_digest_and_unreached_probe_supply_no_observation():
    from clause_evidence import clause_evidence
    report = audit()
    for row in report["runtime_sweep_results"]:
        row["signals"] = {"vtor_ok": True, "image_hash_match": "skipped",
                          "verification_probes": {"signature": {"reached": False}}}
    section = clause_evidence(report)
    assert section["clauses"][1]["campaigns"][0]["points_evaluated"] == 0
    probe = report["runtime_sweep_results"][1]["signals"]["verification_probes"]["signature"]
    probe.update(reached=True, first_bypassed=False, bypassed=False)
    result = clause_evidence(report)["clauses"][1]["campaigns"][0]
    assert result["criteria"]["verification_probe"] == {"reached": 1}
    probe["first_return_value"] = "0x01"
    result = clause_evidence(report)["clauses"][1]["campaigns"][0]
    assert result["criteria"]["verification_probe"] == {"other_return": 1}
    assert result["absent_criteria"] == ["image_digest"]


@pytest.mark.parametrize("damage", ["incomplete", "runner", "missing", "legacy", "aborted", "control"])
def test_incomplete_campaign_exposes_gap_even_with_favourable_rows(damage):
    from clause_evidence import clause_evidence
    report = audit()
    rows = report["runtime_sweep_results"]
    sweep = report["summary"]["runtime_sweep"]
    if damage == "incomplete":
        sweep["campaign_complete"] = False
    elif damage == "runner":
        rows[2].update(boot_outcome="infra_error", infrastructure_error=True)
    elif damage == "missing":
        rows.pop()
    elif damage == "legacy":
        sweep.pop("campaign_integrity")
    elif damage == "aborted":
        report["verdict"] = "INCONCLUSIVE"
    elif damage == "control":
        rows[0]["boot_outcome"] = "infra_error"
    for clause in clause_evidence(report)["clauses"]:
        result = clause["campaigns"][0]
        assert result["gaps"] and not result["verdicts"]
        assert result["points_evaluated"] == 0
        assert result["returned_points_omitted"] == len(rows) - 1
        if damage in {"runner", "control"}:
            assert "Infrastructure errors" in " ".join(result["gaps"])


def test_json_html_wording_and_untrusted_report_labels(tmp_path):
    from clause_mapping import decision_wording
    from report_formats import write_audit_report
    from render_results_html import write_html
    report = audit()
    report.update(profile="certified firmware", verdict="PASS — approved")
    output = tmp_path / "report.json"
    args = argparse.Namespace(output=output, html=None, junit=None, sarif=None)
    write_audit_report(args, report, None, ROOT)
    data = json.loads(output.read_text())
    section = data["clause_evidence"]
    assert section["profile"].startswith("profile-")
    assert not decision_wording(json.dumps(section))
    assert all(c["title"].startswith("evidence relevant to ") for c in section["clauses"])
    assert "Emulation only" in section["limit"]
    # Rendering a saved report must recompute the observations, including the title.
    section["clauses"][0]["title"] = "product certified"
    html = tmp_path / "report.html"
    write_html([(output, data)], html)
    markup = html.read_text().split("<h3>Software update clause evidence</h3>")[1].split("</section>")[0]
    assert "evidence relevant to" in markup and "Emulation only" in markup
    assert not decision_wording(markup)


def test_replace_mapping_and_render_standalone(tmp_path):
    import yaml
    from clause_mapping import load_mapping
    mapping = load_mapping()
    mapping["mapping_version"] = 7
    mapping["clauses"] = [mapping["clauses"][-1]]
    mapping["clauses"][0]["paraphrase"] = "Protect <program> contents."
    source, custom, out, html = [tmp_path / name for name in ("audit.json", "custom.yaml", "out.json", "out.html")]
    source.write_text(json.dumps(audit()))
    custom.write_text(yaml.safe_dump(mapping))
    subprocess.run([sys.executable, str(ROOT / "scripts/report_clause_evidence.py"), "--input", str(source),
                    "--clause-map", str(custom), "--output", str(out), "--html", str(html)], check=True, timeout=30)
    section = json.loads(out.read_text())
    assert section["mapping_version"] == 7 and len(section["clauses"]) == 1
    assert "Protect &lt;program&gt;" in html.read_text()


def test_installed_report_accepts_a_replacement_mapping(tmp_path):
    import yaml
    from clause_mapping import load_mapping
    from tardigrade.cli import main
    mapping = load_mapping()
    mapping["clauses"] = [mapping["clauses"][-1]]
    source, custom, html = [tmp_path / name for name in ("audit.json", "map.yaml", "audit.html")]
    source.write_text(json.dumps(audit()))
    custom.write_text(yaml.safe_dump(mapping))
    assert main(["report", "--input", str(source), "--output", str(html), "--clause-map", str(custom)]) == 0
    assert "Annex I" in html.read_text() and "7.2.2.1.1" not in html.read_text()


def test_incomplete_secondary_campaign_never_displaces_primary_observations():
    from clause_evidence import clause_evidence
    report = audit()
    report["multi_fault_results"] = report["runtime_sweep_results"]
    summary = dict(report["summary"]["runtime_sweep"], infrastructure_error_points=1)
    report["summary"]["multi_fault_runtime_sweep"] = summary
    primary, secondary = clause_evidence(report)["clauses"][1]["campaigns"]
    assert primary["points_evaluated"] == 2
    assert secondary["points_evaluated"] == 0
    assert any("infrastructure_error" in message for message in secondary["gaps"])


def test_saved_mapping_survives_reprojection_and_never_trusts_stored_counts():
    from clause_evidence import clause_evidence
    from clause_mapping import load_mapping
    report = audit()
    mapping = load_mapping()
    mapping["mapping_version"] = 2
    mapping["clauses"] = mapping["clauses"][:1]
    result = clause_evidence(report, mapping)
    result["clauses"][0]["campaigns"][0]["points_evaluated"] = 100
    report["clause_evidence"] = result
    reread = clause_evidence(report)
    assert len(reread["clauses"]) == 1 and reread["mapping_version"] == 2
    assert reread["clauses"][0]["campaigns"][0]["points_evaluated"] == 1


def test_limited_search_reports_its_stopping_reason_and_excluded_states():
    from clause_evidence import clause_evidence
    report = audit()
    sweep = report["summary"]["runtime_sweep"]
    sweep["campaign_complete"] = sweep["campaign_integrity"]["complete"] = False
    sweep["recovery_state_search"] = {"complete": False, "stopped_reason": "max_new_states",
                                      "states_booted": 2, "states_excluded_by_max_new_states": 3}
    campaign = clause_evidence(report)["clauses"][0]["campaigns"][0]
    assert campaign["gaps"] == ["Recovery state search stopped at max_new_states."]
    assert campaign["campaign_coverage"]["state_search"] == {"states_booted": 2, "states_excluded_by_max_new_states": 3}
    assert campaign["points_evaluated"] == 0
