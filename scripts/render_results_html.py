#!/usr/bin/env python3
"""Render HTML summaries for audit/self-test JSON outputs."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fault_classification import _effective_boot_result


FAULT_LABELS = {
    "w": "power_loss",
    "b": "bit_corruption",
    "s": "silent_write_failure",
    "g": "driver_error",
    "x": "rc_injection",
    "d": "write_disturb",
    "l": "wear_leveling_corruption",
    "e": "interrupted_erase",
    "a": "multi_sector_atomicity",
}


def render_security_erase_panel(payload: Dict[str, Any]) -> str:
    """Render static erase-domain findings and selected cutpoint count."""
    summary = payload.get("summary", {})
    layout = summary.get("persistent_state_layout")
    if not isinstance(layout, dict) or layout.get("status") != "analyzed":
        return ""
    findings = layout.get("findings") or []
    selector = summary.get("security_state_erase") or {}
    count = len(selector.get("cutpoints") or []) if isinstance(selector, dict) else 0
    if not findings and not count:
        return ""
    rows = []
    for finding in findings:
        unit = finding.get("unit") or {}
        fields = ", ".join(str(item.get("name", "")) for item in finding.get("fields", []))
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(finding.get("code", ""))),
                html.escape("[0x{:X}, 0x{:X})".format(_as_int(unit.get("start")), _as_int(unit.get("end")))),
                html.escape(fields),
            )
        )
    if not rows:
        rows.append("<tr><td colspan='3'>No shared security erase units.</td></tr>")
    return (
        "<div class='telemetry-heading'><span>security erase domains</span>"
        "<code>{} semantic cuts</code></div>"
        "<table class='telemetry-table'><thead><tr><th>finding</th><th>unit</th><th>resident fields</th></tr></thead>"
        "<tbody>{}</tbody></table>".format(count, "".join(rows))
    )


def render_boundary_campaign_panel(payload: Dict[str, Any]) -> str:
    """Render logical counter campaign classifications and rollback checks."""
    reports = payload.get("boundary_campaign_results") or []
    if not isinstance(reports, list) or not reports:
        return ""
    rows = []
    detail_rows = []
    for report in reports:
        summary = report.get("summary") or {}
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(report.get("campaign", ""))),
                _as_int(report.get("logical_capacity")),
                _as_int(summary.get("candidate_rejected_before_persistence")),
                _as_int(summary.get("candidate_accepted_and_correctly_persisted")),
                _as_int(summary.get("candidate_accepted_but_persisted_state_is_smaller")),
                _as_int(summary.get("follow_up_rollback_accepted")),
                _as_int(summary.get("infrastructure_setup_failure")),
                html.escape(str(report.get("verdict", "INCONCLUSIVE"))),
            )
        )
        for result in report.get("results") or []:
            if not isinstance(result, dict):
                continue
            snapshot_evidence = result.get("boundary_snapshot_restore") or result.get("boundary_snapshot_capture")
            if not isinstance(snapshot_evidence, dict):
                snapshot_evidence = {}
            component_details = []
            for component in snapshot_evidence.get("components") or []:
                if isinstance(component, dict):
                    component_details.append(
                        "{} ({} bytes, sha256={})".format(
                            component.get("name", "?"),
                            component.get("length", "?"),
                            component.get("sha256", "?"),
                        )
                    )
                else:
                    component_details.append(str(component))
            detail_rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(str(report.get("campaign", ""))),
                    _as_int(result.get("resolved_value")),
                    html.escape(str(result.get("classification", "infrastructure/setup failure"))),
                    html.escape(str(result.get("follow_up_classification", "—"))),
                    html.escape(str(result.get("persisted_value", "—"))),
                    html.escape(str(snapshot_evidence.get("path", "—"))),
                    html.escape(str(snapshot_evidence.get("backend_identity", "—"))),
                    html.escape(str(snapshot_evidence.get("sha256", "—"))),
                    html.escape("; ".join(component_details) if component_details else "—"),
                    html.escape(str(result.get("infrastructure_reason", "—"))),
                )
            )
    return (
        "<div class='telemetry-heading'><span>security counter boundaries</span>"
        "<code>candidate / follow-up relation</code></div>"
        "<table class='telemetry-table'><thead><tr>"
        "<th>campaign</th><th>capacity</th><th>rejected</th><th>persisted</th>"
        "<th>smaller state</th><th>rollback accepted</th><th>infrastructure</th><th>verdict</th>"
        "</tr></thead><tbody>{}</tbody></table>".format("".join(rows))
        + ("<h4>per-value evidence</h4><table class='telemetry-table'><thead><tr>"
           "<th>campaign</th><th>value</th><th>candidate</th><th>follow-up</th><th>persisted</th><th>snapshot path</th><th>backend identity</th><th>snapshot digest</th><th>components (length/digest)</th><th>reason</th>"
           "</tr></thead><tbody>{}</tbody></table>".format("".join(detail_rows)) if detail_rows else "")
    )


def render_authorization_review_panel(payload: Dict[str, Any]) -> str:
    """Render the fail-closed reviewed-versus-signed authorization report."""
    report = payload.get("authorization_review_analysis")
    if not isinstance(report, dict):
        return ""
    findings = report.get("findings") or []
    rows = []
    for finding in findings[:256]:
        evidence = finding.get("evidence") or {}
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(finding.get("id", ""))),
                html.escape(str(finding.get("sequence", ""))),
                html.escape(str(evidence.get("field", evidence.get("event", "—")))),
                html.escape(str(finding.get("message", ""))),
            )
        )
    if not rows:
        rows.append("<tr><td colspan='4'>No authorization-review findings.</td></tr>")
    return (
        "<div class='telemetry-heading'><span>authorization review</span>"
        "<code>{} variants / {} traces / {}</code></div>"
        "<table class='telemetry-table'><thead><tr>"
        "<th>finding</th><th>sequence</th><th>field/event</th><th>message</th>"
        "</tr></thead><tbody>{}</tbody></table>"
    ).format(
        _as_int(report.get("variants_analyzed")),
        _as_int(report.get("traces_analyzed")),
        html.escape(str(report.get("verdict", "INCONCLUSIVE"))),
        "".join(rows),
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def classify_payload(payload: Any) -> str:
    if isinstance(payload, dict) and "engine" in payload and "summary" in payload:
        return "audit"
    if isinstance(payload, dict) and "total_profiles" in payload and "results" in payload:
        return "self_test"
    if isinstance(payload, dict) and "clusters" in payload and "totals" in payload:
        return "matrix"
    return "unknown"


def score_color(outcome: str, injected: bool) -> str:
    if not injected:
        return "#52606d"
    return "#37f6a0" if outcome == "success" else "#ff4d6d"


def status_class(value: Any) -> str:
    """Map report values to a fixed CSS vocabulary."""
    normalized = str(value or "unknown").strip().lower()
    if normalized.startswith("pass") or normalized in {"success", "ok", "clean"}:
        return "status-pass"
    if normalized.startswith("fail") or normalized in {
        "error",
        "hard_fault",
        "no_boot",
        "wrong_image",
    }:
        return "status-fail"
    return "status-warn"


def _boot_span_outcomes(result: Dict[str, Any]) -> Tuple[str, str]:
    initial = str(
        result.get("initial_boot_outcome") or result.get("boot_outcome") or "unknown"
    )
    final = result.get("final_boot_outcome")
    if final is None:
        final = result.get("effective_outcome")
    if final is None:
        final, _ = _effective_boot_result(result)
    return initial, str(final or initial or "unknown")


def render_fault_grid(results: List[Dict[str, Any]]) -> str:
    points = [r for r in results if not r.get("is_control", False)]
    if not points:
        return "<p class='empty-state'>No runtime sweep results found.</p>"

    points.sort(key=lambda r: (str(r.get("fault_type", "w")), int(r.get("fault_requested", r.get("fault_at", 0)))))

    cells = []
    for p in points:
        ftype = str(p.get("fault_type", "w"))
        label = FAULT_LABELS.get(ftype, ftype)
        if ftype.startswith("w:ss:"):
            label = "security_state_erase"
        at = int(p.get("fault_requested", p.get("fault_at", 0)))
        initial_outcome, final_outcome = _boot_span_outcomes(p)
        injected = bool(p.get("fault_injected", False))
        color = score_color(final_outcome, injected)
        state = "idle" if not injected else ("safe" if final_outcome == "success" else "alert")
        if initial_outcome == final_outcome:
            title = f"type={label} fp={at} outcome={final_outcome} injected={injected}"
        else:
            title = (
                f"type={label} fp={at} initial={initial_outcome} "
                f"final={final_outcome} injected={injected}"
            )
        cells.append(
            "<div class='cell cell-{}' style='--cell-color:{}' title='{}' "
            "aria-label='{}'></div>".format(
                state,
                color,
                html.escape(title, quote=True),
                html.escape(title, quote=True),
            )
        )

    return (
        "<div class='telemetry-heading'><span>fault-point telemetry</span>"
        f"<code>{len(points):04d} points</code></div>"
        "<div class='grid' role='img' aria-label='Fault point outcome grid'>"
        + "".join(cells)
        + "</div>"
        "<div class='legend'>"
        "<span><i class='key-safe'></i> recovered</span>"
        "<span><i class='key-alert'></i> finding</span>"
        "<span><i class='key-idle'></i> not injected</span>"
        "</div>"
    )


def render_success_effect_panel(results: List[Dict[str, Any]]) -> str:
    """Render function-return contract telemetry and failures."""
    rows = []
    for result in results:
        if not isinstance(result, dict):
            continue
        signals = result.get("signals") or {}
        probes = signals.get("function_return_probes") if isinstance(signals, dict) else None
        violations = [
            v for v in (result.get("invariant_violations") or [])
            if isinstance(v, dict) and v.get("name") == "success_implies_effect"
        ]
        if not isinstance(probes, dict) and not violations:
            continue
        for violation in violations or [{}]:
            details = violation.get("details") or {}
            label = details.get("probe", "")
            probe = probes.get(label, {}) if isinstance(probes, dict) else {}
            raw_values = probe.get("raw_values") or []
            return_value = details.get("return_value_text") or ("0x{:08X}".format(_as_int(raw_values[-1])) if raw_values else "—")
            condition = (details.get("conditions") or [{}])[0]
            rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(str(details.get("contract") or "—")),
                    html.escape(str(label or "—")),
                    html.escape(str(return_value)),
                    html.escape(str(condition.get("pre_value", "—"))),
                    html.escape(str(condition.get("post_value", "—"))),
                    html.escape(str(result.get("fault_address") or result.get("fault_at") or "control")),
                )
            )
    if not rows:
        return ""
    return (
        "<div class='telemetry-heading'><span>success-implies-effect contracts</span>"
        "<code>return / pre / post</code></div>"
        "<table class='telemetry-table'><thead><tr>"
        "<th>contract</th><th>probe</th><th>return</th><th>pre</th><th>post</th><th>fault point</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def render_multi_component_panel(payload: Dict[str, Any]) -> str:
    """Render joined component outcomes and semantic version evidence."""
    if not payload.get("multi_component"):
        return ""
    combined_results = payload.get("combined_results") or []
    if not isinstance(combined_results, list):
        return ""
    rows = []
    control_state = payload.get("control_state") or {}
    if isinstance(control_state, dict):
        for name, component in control_state.items():
            if not isinstance(component, dict):
                continue
            state = component.get("semantic_state")
            if not isinstance(state, dict):
                state = component.get("nvm_state")
            if not isinstance(state, dict):
                state = {}
            rows.append(
                "<tr><td>control</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
                    html.escape(str(name)),
                    html.escape(str(component.get("boot_outcome") or "unknown")),
                    html.escape(json.dumps(state, sort_keys=True, separators=(",", ":"))),
                    html.escape(str(state.get("version", "—"))),
                )
            )
    for combined in combined_results:
        if not isinstance(combined, dict):
            continue
        per_component = combined.get("per_component") or {}
        if not isinstance(per_component, dict):
            continue
        for name, component in per_component.items():
            if not isinstance(component, dict):
                continue
            state = component.get("semantic_state")
            if not isinstance(state, dict):
                state = component.get("nvm_state")
            if not isinstance(state, dict):
                state = {}
            version = state.get("version", "—")
            rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
                    html.escape(str(combined.get("faulted_component") or "control")),
                    html.escape(str(name)),
                    html.escape(str(component.get("boot_outcome") or "unknown")),
                    html.escape(json.dumps(state, sort_keys=True, separators=(",", ":"))),
                    html.escape(str(version)),
                )
            )
    if not rows:
        return ""
    return (
        "<div class='telemetry-heading'><span>multi-component state relations</span>"
        "<code>joined outcomes / observed versions</code></div>"
        "<table class='telemetry-table'><thead><tr>"
        "<th>faulted component</th><th>component</th><th>boot outcome</th>"
        "<th>observed state</th><th>version</th>"
        "</tr></thead><tbody>{}</tbody></table>".format("".join(rows))
    )


def render_terminal_error_panel(payload: Dict[str, Any]) -> str:
    """Render emitted callsite, control, and sink telemetry."""
    rows = []
    all_results = list(payload.get("runtime_sweep_results", []))
    # The dedicated campaign is kept separately from the ordinary runtime
    # sweep so its instruction-skip evidence is not lost in the HTML report.
    all_results.extend(payload.get("terminal_error_results", []))
    for result in all_results:
        signals = result.get("signals") if isinstance(result, dict) else None
        paths = signals.get("terminal_error_paths") if isinstance(signals, dict) else None
        if not isinstance(paths, dict):
            continue
        for name, item in paths.items():
            rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
                    html.escape(str(name)),
                    html.escape(str(item.get("last_callsite") or item.get("selected_callsite") or "—")),
                    "yes" if item.get("callsite_reached") else "no",
                    "yes" if item.get("control_terminal") else "no",
                    html.escape(str(item.get("first_forbidden_sink") or "—")),
                    html.escape(str(item.get("snapshot_identity_hash") or "—")),
                )
            )
    if not rows:
        return ""
    return (
        "<div class='telemetry-heading'><span>terminal-error escape</span>"
        "<code>emitted callsite / sink observation</code></div>"
        "<table class='telemetry-table'><thead><tr>"
        "<th>campaign</th><th>callsite</th><th>reached</th><th>terminal</th><th>first sink</th><th>snapshot hash</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def render_audit_card(path: Path, payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    sweep = payload.get("summary", {}).get("runtime_sweep", {})
    profile = str(payload.get("profile", path.stem))
    bricks = int(sweep.get("bricks", 0))
    total = int(sweep.get("total_fault_points", 0))
    brick_rate = float(sweep.get("brick_rate", 0.0)) * 100.0
    verdict = str(payload.get("verdict", "unknown"))
    control = sweep.get("control", {})
    control_initial_outcome, control_final_outcome = _boot_span_outcomes(control)
    issues = int(sweep.get("issue_points", bricks) or 0)
    recoveries = int(sweep.get("recoveries", max(total - bricks, 0)) or 0)
    status_css = status_class(verdict)

    metrics = (
        "<div class='metrics'>"
        f"<div class='metric metric-primary {status_css}'><b>verdict</b><span>{html.escape(verdict)}</span></div>"
        f"<div class='metric'><b>fault points</b><span>{total}</span><small>in campaign</small></div>"
        f"<div class='metric'><b>recoveries</b><span>{recoveries}</span><small>resilient paths</small></div>"
        f"<div class='metric'><b>findings</b><span>{issues}</span><small>anomalous paths</small></div>"
        f"<div class='metric'><b>brick rate</b><span>{brick_rate:.1f}%</span><small>{bricks}/{total} devices</small></div>"
        f"<div class='metric'><b>control span</b><span class='outcome-span'>"
        f"{html.escape(control_initial_outcome)} <em>→</em> {html.escape(control_final_outcome)}"
        "</span><small>initial → final</small></div>"
        "</div>"
    )

    grid = render_fault_grid(payload.get("runtime_sweep_results", []))

    rc_cfg = payload.get("rc_injection_config") or {}
    rc_panel = ""
    if isinstance(rc_cfg, dict) and rc_cfg.get("symbols"):
        rc_results = [
            item.get("rc_injection")
            for item in payload.get("runtime_sweep_results", [])
            if isinstance(item, dict) and isinstance(item.get("rc_injection"), dict)
        ]
        applied = sum(1 for item in rc_results if item.get("applied"))
        applied_functions = []
        for item in rc_results:
            if item.get("applied") and item.get("applied_symbol"):
                address = _as_int(item.get("applied_return_address")) & 0xFFFFFFFF
                applied_functions.append(
                    "{}@0x{:08X}".format(item.get("applied_symbol"), address)
                )
        applied_text = ", ".join(dict.fromkeys(applied_functions)) or "none"
        rc_panel = (
            "<div class='telemetry-heading'><span>rc-injection contract</span>"
            "<code>configured / applied</code></div>"
            "<p class='path'><span>symbols</span> {} &nbsp; "
            "<span>return</span> 0x{:08X} / r{} &nbsp; "
            "<span>applied</span> {} &nbsp; "
            "<span>function</span> {}</p>"
        ).format(
            html.escape(", ".join(str(value) for value in rc_cfg.get("symbols", []))),
            _as_int(rc_cfg.get("return_value")) & 0xFFFFFFFF,
            _as_int(rc_cfg.get("return_register")),
            applied,
            html.escape(applied_text),
        )

    card = (
        f"<section class='card audit-card {status_css}'>"
        "<header class='card-header'><div>"
        "<p class='eyebrow'>target // boot integrity</p>"
        f"<h2>{html.escape(profile)}</h2>"
        f"<p class='path'><span>source</span> {html.escape(str(path))}</p>"
        "</div>"
        f"<div class='verdict-sigil' aria-label='Verdict {html.escape(verdict, quote=True)}'>"
        f"<span>{html.escape(verdict)}</span></div></header>"
        f"{metrics}"
        f"{rc_panel}"
        f"{render_security_erase_panel(payload)}"
        f"{render_boundary_campaign_panel(payload)}"
        f"{render_authorization_review_panel(payload)}"
        f"{render_success_effect_panel(payload.get('runtime_sweep_results', []))}"
        f"{render_multi_component_panel(payload)}"
        f"{render_terminal_error_panel(payload)}"
        f"{grid}"
        "</section>"
    )

    summary = {
        "profile": profile,
        "bricks": bricks,
        "total": total,
        "brick_rate": brick_rate,
        "verdict": verdict,
        "control_initial_outcome": control_initial_outcome,
        "control_final_outcome": control_final_outcome,
    }
    return card, summary


def render_self_test_card(path: Path, payload: Dict[str, Any]) -> str:
    total = int(payload.get("total_profiles", 0))
    passed = int(payload.get("passed", 0))
    failed = int(payload.get("failed", 0))

    rows = []
    for item in payload.get("results", []):
        profile = html.escape(str(item.get("profile", "")))
        verdict = html.escape(str(item.get("verdict", "")))
        reason = html.escape(str(item.get("reason", "")))
        css = "ok" if item.get("passed") else "bad"
        rows.append(
            f"<tr class='{css}'><td>{profile}</td><td>{verdict}</td><td>{reason}</td></tr>"
        )

    return (
        "<section class='card'>"
        "<p class='eyebrow'>system // validation suite</p>"
        "<h2>Self-Test Summary</h2>"
        f"<p class='path'><span>source</span> {html.escape(str(path))}</p>"
        "<div class='metrics'>"
        f"<div class='metric'><b>profiles</b><span>{total}</span></div>"
        f"<div class='metric status-pass'><b>passed</b><span>{passed}</span></div>"
        f"<div class='metric status-fail'><b>failed</b><span>{failed}</span></div>"
        "</div>"
        "<div class='table-wrap'><table><thead><tr><th>Profile</th><th>Verdict</th><th>Reason</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        "</section>"
    )


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def render_matrix_card(path: Path, payload: Dict[str, Any]) -> str:
    totals = payload.get("totals", {})
    if not isinstance(totals, dict):
        totals = {}

    clusters = payload.get("clusters", [])
    if not isinstance(clusters, list):
        clusters = []
    defect_deltas = payload.get("defect_deltas", [])
    if not isinstance(defect_deltas, list):
        defect_deltas = []
    regressions = [d for d in defect_deltas if d.get("direction") == "worse"]

    metrics = (
        "<div class='metrics'>"
        f"<div class='metric'><b>cases</b><span>{_as_int(totals.get('cases_total', len(payload.get('cases', []))))}</span></div>"
        f"<div class='metric'><b>clusters</b><span>{len(clusters)}</span></div>"
        f"<div class='metric'><b>control mismatches</b><span>{_as_int(totals.get('cases_control_mismatch'))}</span></div>"
        f"<div class='metric'><b>defect deltas</b><span>{len(defect_deltas)}</span></div>"
        f"<div class='metric'><b>anomalous points</b><span>{_as_int(totals.get('anomalous_points_total'))}</span></div>"
        f"<div class='metric'><b>otadata suspicious</b><span>{_as_int(totals.get('otadata_suspicious_drift_points_total'))}</span></div>"
        "</div>"
    )

    top_cluster_rows: List[str] = []
    for idx, cluster in enumerate(clusters[:12], 1):
        signature = json.dumps(cluster.get("signature", {}), sort_keys=True)
        if len(signature) > 120:
            signature = signature[:117] + "..."
        top_cluster_rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td>{html.escape(str(cluster.get('kind', '')))}</td>"
            f"<td>{_as_float(cluster.get('score')):.3f}</td>"
            f"<td>{_as_int(cluster.get('count'))}</td>"
            f"<td>{_as_int(cluster.get('case_count'))}</td>"
            f"<td><code>{html.escape(signature)}</code></td>"
            "</tr>"
        )
    if not top_cluster_rows:
        top_cluster_rows.append(
            "<tr><td colspan='6'>No clusters available.</td></tr>"
        )

    top_regression_rows: List[str] = []
    for idx, row in enumerate(regressions[:12], 1):
        deltas = row.get("deltas", {})
        if not isinstance(deltas, dict):
            deltas = {}
        top_regression_rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td>{_as_float(row.get('delta_score')):.3f}</td>"
            f"<td>{html.escape(str(row.get('scenario_tag', '')))}</td>"
            f"<td>{html.escape(str(row.get('fault_preset', '')))}</td>"
            f"<td>{html.escape(str(row.get('criteria_preset', '')))}</td>"
            f"<td>{_as_float(deltas.get('failure_rate')):+.3f}</td>"
            f"<td>{_as_float(deltas.get('brick_rate')):+.3f}</td>"
            f"<td>{_as_int(deltas.get('control_mismatch')):+d}</td>"
            f"<td>{_as_int(deltas.get('control_outcome_shift')):+d}</td>"
            "</tr>"
        )
    if not top_regression_rows:
        top_regression_rows.append(
            "<tr><td colspan='9'>No worsening defect deltas detected.</td></tr>"
        )

    return (
        "<section class='card'>"
        "<p class='eyebrow'>matrix // attack surface</p>"
        "<h2>Exploratory Matrix Summary</h2>"
        f"<p class='path'><span>source</span> {html.escape(str(path))}</p>"
        f"{metrics}"
        "<h3>Top Clusters</h3>"
        "<div class='table-wrap'><table><thead><tr>"
        "<th>#</th><th>Kind</th><th>Score</th><th>Occurrences</th><th>Cases</th><th>Signature</th>"
        "</tr></thead><tbody>"
        f"{''.join(top_cluster_rows)}"
        "</tbody></table></div>"
        "<h3>Top Worsening Defect Deltas</h3>"
        "<div class='table-wrap'><table><thead><tr>"
        "<th>#</th><th>Score</th><th>Scenario</th><th>Fault</th><th>Criteria</th>"
        "<th>Δfailure</th><th>Δbrick</th><th>Δcontrol</th><th>Δcontrol_outcome</th>"
        "</tr></thead><tbody>"
        f"{''.join(top_regression_rows)}"
        "</tbody></table></div>"
        "</section>"
    )


def extract_matrix_summary(path: Path, payload: Dict[str, Any]) -> Dict[str, Any]:
    totals = payload.get("totals", {})
    if not isinstance(totals, dict):
        totals = {}
    clusters = payload.get("clusters", [])
    if not isinstance(clusters, list):
        clusters = []
    defect_deltas = payload.get("defect_deltas", [])
    if not isinstance(defect_deltas, list):
        defect_deltas = []
    regressions = [d for d in defect_deltas if d.get("direction") == "worse"]

    return {
        "path": str(path),
        "cases": _as_int(totals.get("cases_total", len(payload.get("cases", [])))),
        "clusters": len(clusters),
        "control_mismatches": _as_int(totals.get("cases_control_mismatch")),
        "defect_deltas": len(defect_deltas),
        "worse_deltas": len(regressions),
        "anomalous_points": _as_int(totals.get("anomalous_points_total")),
        "otadata_suspicious": _as_int(
            totals.get("otadata_suspicious_drift_points_total")
        ),
    }


def render_matrix_comparison(summaries: List[Dict[str, Any]]) -> str:
    if len(summaries) < 2:
        return ""
    rows = []
    for item in summaries:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('path', '')))}</td>"
            f"<td>{_as_int(item.get('cases'))}</td>"
            f"<td>{_as_int(item.get('clusters'))}</td>"
            f"<td>{_as_int(item.get('control_mismatches'))}</td>"
            f"<td>{_as_int(item.get('defect_deltas'))}</td>"
            f"<td>{_as_int(item.get('worse_deltas'))}</td>"
            f"<td>{_as_int(item.get('anomalous_points'))}</td>"
            f"<td>{_as_int(item.get('otadata_suspicious'))}</td>"
            "</tr>"
        )
    return (
        "<section class='card'>"
        "<p class='eyebrow'>matrix // comparative intelligence</p>"
        "<h2>Matrix Dashboard</h2>"
        "<div class='table-wrap'><table><thead><tr>"
        "<th>Matrix JSON</th><th>Cases</th><th>Clusters</th><th>Control mismatches</th>"
        "<th>Defect deltas</th><th>Worse deltas</th><th>Anomalous points</th><th>OtaData suspicious</th>"
        "</tr></thead><tbody>"
        f"{''.join(rows)}"
        "</tbody></table></div>"
        "</section>"
    )


def render_comparison(summaries: List[Dict[str, Any]]) -> str:
    if len(summaries) != 2:
        return ""
    a, b = summaries
    delta = b["bricks"] - a["bricks"]
    direction = "fewer" if delta < 0 else "more"
    return (
        "<section class='card'>"
        "<p class='eyebrow'>diff // campaign comparison</p>"
        "<h2>Two-Report Comparison</h2>"
        "<div class='table-wrap'><table><thead><tr><th>Report</th><th>Bricks</th><th>Rate</th><th>Verdict</th></tr></thead><tbody>"
        f"<tr><td>{html.escape(a['profile'])}</td><td>{a['bricks']}/{a['total']}</td><td>{a['brick_rate']:.1f}%</td><td>{html.escape(a['verdict'])}</td></tr>"
        f"<tr><td>{html.escape(b['profile'])}</td><td>{b['bricks']}/{b['total']}</td><td>{b['brick_rate']:.1f}%</td><td>{html.escape(b['verdict'])}</td></tr>"
        "</tbody></table></div>"
        f"<p class='note'>Delta: {delta:+d} bricks ({direction} than first report).</p>"
        "</section>"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render HTML summary for audit/self-test JSON reports")
    parser.add_argument("--input", action="append", required=True, help="Input JSON file (repeatable)")
    parser.add_argument("--output", required=True, help="Output HTML path")
    args = parser.parse_args()

    inputs = [Path(p) for p in args.input]
    cards: List[str] = []
    audit_summaries: List[Dict[str, Any]] = []
    matrix_summaries: List[Dict[str, Any]] = []

    for path in inputs:
        payload = load_json(path)
        kind = classify_payload(payload)
        if kind == "audit":
            card, summary = render_audit_card(path, payload)
            cards.append(card)
            audit_summaries.append(summary)
        elif kind == "self_test":
            cards.append(render_self_test_card(path, payload))
        elif kind == "matrix":
            cards.append(render_matrix_card(path, payload))
            matrix_summaries.append(extract_matrix_summary(path, payload))
        else:
            cards.append(
                "<section class='card'><h2>Unsupported JSON</h2>"
                f"<p class='path'>{html.escape(str(path))}</p>"
                "<p>Could not classify this payload.</p></section>"
            )

    comparison = render_comparison(audit_summaries)
    matrix_comparison = render_matrix_comparison(matrix_summaries)

    html_doc = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta name='color-scheme' content='dark'>
<title>Tardigrade // Fault Campaign</title>
<style>
:root {
  --void: #03070a;
  --panel: #091117;
  --panel-2: #0d1820;
  --ink: #e7f6f2;
  --muted: #809a99;
  --line: #1b3438;
  --safe: #37f6a0;
  --signal: #20d7ff;
  --alert: #ff4d6d;
  --warn: #ffd166;
}
* { box-sizing: border-box; }
html { background: var(--void); }
body {
  margin: 0;
  min-height: 100vh;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  background:
    linear-gradient(rgba(55,246,160,.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(55,246,160,.025) 1px, transparent 1px),
    radial-gradient(circle at 78% -8%, rgba(32,215,255,.13), transparent 31rem),
    radial-gradient(circle at 4% 14%, rgba(55,246,160,.08), transparent 24rem),
    var(--void);
  background-size: 34px 34px, 34px 34px, auto, auto, auto;
  color: var(--ink);
  letter-spacing: .01em;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 10;
  opacity: .16;
  background: repeating-linear-gradient(0deg, transparent 0 3px, rgba(0,0,0,.28) 4px);
}
main {
  position: relative;
  max-width: 1320px;
  margin: 0 auto;
  padding: 28px 22px 64px;
}
.masthead {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  padding: 42px 2px 28px;
  border-bottom: 1px solid var(--line);
  margin-bottom: 22px;
}
.brand-lockup { display: flex; align-items: center; gap: 18px; }
.mark {
  position: relative;
  width: 54px;
  height: 54px;
  border: 1px solid var(--safe);
  background: rgba(55,246,160,.04);
  box-shadow: inset 0 0 18px rgba(55,246,160,.09), 0 0 22px rgba(55,246,160,.07);
  clip-path: polygon(14% 0, 100% 0, 100% 86%, 86% 100%, 0 100%, 0 14%);
}
.mark::before, .mark::after { content: ""; position: absolute; background: var(--safe); }
.mark::before { width: 26px; height: 2px; left: 13px; top: 26px; box-shadow: 0 -9px 0 -0.5px var(--safe), 0 9px 0 -0.5px var(--safe); }
.mark::after { height: 26px; width: 2px; top: 13px; left: 26px; box-shadow: -9px 0 0 -0.5px var(--safe), 9px 0 0 -0.5px var(--safe); }
h1 { margin: 0; font-size: clamp(30px, 5vw, 54px); line-height: .9; letter-spacing: -.055em; text-transform: uppercase; }
.deck { margin: 9px 0 0; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; text-transform: uppercase; letter-spacing: .16em; }
.system-state { display: flex; align-items: center; gap: 9px; color: var(--safe); font: 700 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .14em; text-transform: uppercase; white-space: nowrap; }
.system-state i { width: 7px; height: 7px; background: var(--safe); border-radius: 50%; box-shadow: 0 0 10px var(--safe); animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 50% { opacity: .35; } }
.card {
  position: relative;
  overflow: hidden;
  background: linear-gradient(145deg, rgba(13,24,32,.96), rgba(6,13,18,.98));
  border: 1px solid var(--line);
  border-radius: 2px;
  padding: clamp(18px, 3vw, 28px);
  margin: 0 0 18px;
  box-shadow: 0 18px 50px rgba(0,0,0,.24);
}
.card::before { content: ""; position: absolute; width: 44px; height: 2px; top: -1px; left: 24px; background: var(--signal); box-shadow: 0 0 10px var(--signal); }
.audit-card.status-pass::before { background: var(--safe); box-shadow: 0 0 10px var(--safe); }
.audit-card.status-fail::before { background: var(--alert); box-shadow: 0 0 10px var(--alert); }
.card-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 22px; }
h2 { margin: 0; font-size: clamp(20px, 3vw, 30px); line-height: 1.15; letter-spacing: -.025em; overflow-wrap: anywhere; }
h3 { margin: 28px 0 10px; color: var(--ink); font-size: 13px; text-transform: uppercase; letter-spacing: .11em; }
.eyebrow { margin: 0 0 8px; color: var(--signal); font: 700 10px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .16em; text-transform: uppercase; }
.path { margin: 8px 0 0; color: var(--muted); font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.path span { color: #b9ceca; text-transform: uppercase; }
.verdict-sigil { flex: 0 0 auto; padding: 9px 11px; border: 1px solid currentColor; color: var(--warn); background: rgba(255,209,102,.04); font: 800 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .12em; text-transform: uppercase; clip-path: polygon(7px 0, 100% 0, 100% calc(100% - 7px), calc(100% - 7px) 100%, 0 100%, 0 7px); }
.status-pass .verdict-sigil, .metric.status-pass span { color: var(--safe); }
.status-fail .verdict-sigil, .metric.status-fail span { color: var(--alert); }
.status-warn .verdict-sigil, .metric.status-warn span { color: var(--warn); }
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: 1px;
  margin: 0 0 24px;
  background: var(--line);
  border: 1px solid var(--line);
}
.metric {
  min-height: 94px;
  padding: 15px 16px 13px;
  background: rgba(6,13,18,.92);
}
.metrics b { display: block; margin-bottom: 10px; color: var(--muted); font: 700 9px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .14em; text-transform: uppercase; }
.metrics span { display: block; font-size: clamp(18px, 2.3vw, 27px); font-weight: 700; letter-spacing: -.035em; overflow-wrap: anywhere; }
.metrics small { display: block; margin-top: 6px; color: #627a79; font: 10px/1.25 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
.metric-primary { background: linear-gradient(145deg, rgba(55,246,160,.07), rgba(6,13,18,.92)); }
.metric-primary.status-fail { background: linear-gradient(145deg, rgba(255,77,109,.09), rgba(6,13,18,.92)); }
.metric-primary span { color: var(--safe); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
.metric-primary.status-fail span { color: var(--alert); }
.outcome-span { font-size: 16px !important; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
.outcome-span em { color: var(--signal); font-style: normal; }
.telemetry-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; color: var(--muted); font: 700 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .14em; text-transform: uppercase; }
.telemetry-heading code { color: var(--signal); font-size: 10px; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(11px, 1fr));
  gap: 3px;
  min-height: 34px;
  border: 1px solid var(--line);
  padding: 9px;
  background: #050b0f;
}
.cell { width: 100%; min-height: 14px; background: var(--cell-color); opacity: .8; box-shadow: inset 0 0 0 1px rgba(255,255,255,.04); transition: opacity .15s, transform .15s, box-shadow .15s; }
.cell:hover { position: relative; z-index: 2; opacity: 1; transform: scale(1.55); box-shadow: 0 0 10px var(--cell-color); }
.cell-alert { animation: alert-ping 2.8s ease-in-out infinite; }
@keyframes alert-ping { 50% { opacity: .48; } }
.legend { display: flex; gap: 16px; margin-top: 9px; color: var(--muted); font: 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; flex-wrap: wrap; }
.legend i { display: inline-block; width: 7px; height: 7px; margin-right: 6px; vertical-align: 1px; }
.key-safe { background: var(--safe); box-shadow: 0 0 7px rgba(55,246,160,.55); }
.key-alert { background: var(--alert); box-shadow: 0 0 7px rgba(255,77,109,.55); }
.key-idle { background: #52606d; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); }
table { width: 100%; min-width: 640px; border-collapse: collapse; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; font-size: 12px; }
th { background: #071016; color: var(--muted); font: 700 9px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .1em; text-transform: uppercase; }
td { color: #bfd2ce; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: rgba(32,215,255,.035); color: var(--ink); }
tr.ok td:first-child { border-left: 2px solid var(--safe); }
tr.bad td:first-child { border-left: 2px solid var(--alert); }
code { color: #99e8f7; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.note { color: var(--muted); font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 10px 0 0; }
.empty-state { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.footer { display: flex; justify-content: space-between; gap: 16px; padding: 14px 2px 0; color: #58706f; font: 9px/1.3 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .1em; text-transform: uppercase; }
@media (max-width: 680px) {
  main { padding: 14px 12px 42px; }
  .masthead { align-items: flex-start; padding-top: 26px; }
  .system-state { display: none; }
  .mark { width: 44px; height: 44px; }
  .mark::before { left: 8px; top: 21px; }
  .mark::after { top: 8px; left: 21px; }
  .card-header { display: block; }
  .verdict-sigil { display: inline-block; margin-top: 14px; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  .metric { min-height: 84px; padding: 13px; }
  .grid { grid-template-columns: repeat(auto-fill, minmax(9px, 1fr)); }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
</style>
</head>
<body>
<main>
<header class='masthead'>
  <div class='brand-lockup'>
    <div class='mark' aria-hidden='true'></div>
    <div><h1>Tardigrade</h1><p class='deck'>adversarial OTA resilience // campaign report</p></div>
  </div>
  <div class='system-state'><i></i>analysis complete</div>
</header>
""" + comparison + """\n""" + matrix_comparison + """\n""" + "\n".join(cards) + """
<footer class='footer'><span>trace replay engine</span><span>trust nothing // verify recovery</span></footer>
</main>
</body>
</html>
"""

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc, encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
