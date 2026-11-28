# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""SARIF 2.1.0 serialization of distinct runtime audit findings."""

from __future__ import annotations

from collections import defaultdict
from itertools import chain

from report_points import reproduction
from source_locations import SourceLocations

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"


def sarif_run(run, root):
    sources = {}
    groups = defaultdict(list)
    for point in chain(run.points(), run.additional_findings()):
        if not point.findings:
            continue
        elf = point.elf or run.elf
        if elf not in sources:
            sources[elf] = SourceLocations(elf, root)
        source = sources[elf]
        location = source.lookup(point.row)
        if not location:
            location = (source.uri(run.profile_path), 1)
        seen = set()
        for finding in point.findings:
            key = (finding.rule, finding.subject, location, point.component or "")
            if key not in seen:
                groups[key].append((point, finding))
                seen.add(key)
    rule_ids = sorted({key[0] for key in groups})
    rules = [{"id": rule, "shortDescription": {"text": rule.replace("_", " ")}} for rule in rule_ids]
    results = []
    for (rule, _, (uri, line), component), entries in sorted(groups.items()):
        message = entries[0][1].message
        points = []
        explanations = {}
        for point, _ in entries:
            row = point.row if isinstance(point.row, dict) else {}
            record = {
                "name": point.name,
                "kind": point.kind,
                "reproduction": point.selector or reproduction(row),
            }
            if "fault_at" in row and not row.get("is_control") and row.get("fault_type") != "control":
                record["fault_at"] = row.get("fault_at")
                raw_op = str(row.get("operation_kind") or "").strip().lower()
                ft = row.get("fault_type") or ("e" if raw_op == "erase" else "w")
                record["fault_type"] = ft
                ft_base = str(ft).split(":", 1)[0].strip().lower()
                record["operation_kind"] = row.get("operation_kind") or (
                    "erase"
                    if ft_base in ("e", "a", "interrupted_erase", "multi_sector_atomicity")
                    else "program"
                )
            if isinstance(row.get("mram_fault_evidence"), dict):
                record["mram_fault_evidence"] = row["mram_fault_evidence"]
            if isinstance(row.get("fault_snapshot"), dict):
                record["fault_snapshot"] = row["fault_snapshot"]
            explanation = row.get("failure_explanation")
            if explanation:
                record["failure_explanation"] = explanation
                explanations[explanation["message"]] = None
            points.append(record)
        if explanations:
            message += "\n" + "\n".join(explanations)
        properties = {"profile": run.name, "points": points}
        if component:
            properties["component"] = component
        results.append({
            "ruleId": rule, "level": "error",
            "message": {"text": f"{message} ({len(points)} affected point(s))"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
            "properties": properties,
        })
    aggregate = run.data.get("security_aggregate") or {}
    incomplete = aggregate.get("inconclusive_reasons") or []
    if not incomplete and (run.data.get("error") or str(run.data.get("verdict", "")).startswith("INCONCLUSIVE")):
        incomplete = [run.data.get("error") or run.data["verdict"]]
    invocation = {"executionSuccessful": not incomplete}
    if incomplete:
        invocation["toolExecutionNotifications"] = [{"message": {"text": reason}} for reason in incomplete]
    report = {"tool": {"driver": {"name": "Tardigrade", "rules": rules}},
              "automationDetails": {"id": f"{run.name}/"}, "invocations": [invocation], "results": results}
    first_cuts = run.counts.get("first_cut_states") or {}
    summary = run.data.get("summary") or {}
    sweep = summary.get("runtime_sweep") if isinstance(summary.get("runtime_sweep"), dict) else summary
    run_props = {}
    if first_cuts.get("available"):
        run_props["first_cut_states"] = first_cuts
    if isinstance(sweep, dict) and sweep.get("fault_evidence"):
        run_props["fault_evidence"] = sweep["fault_evidence"]
    if run_props:
        report["properties"] = run_props
    return report


def sarif_report(runs, root):
    return {"version": "2.1.0", "$schema": SARIF_SCHEMA, "runs": [sarif_run(run, root) for run in runs]}
