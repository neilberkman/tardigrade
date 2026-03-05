#!/usr/bin/env python3
"""Render HTML summaries for audit/self-test JSON outputs."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


FAULT_LABELS = {
    "w": "power_loss",
    "b": "bit_corruption",
    "s": "silent_write_failure",
    "d": "write_disturb",
    "l": "wear_leveling_corruption",
    "e": "interrupted_erase",
    "a": "multi_sector_atomicity",
}


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
        return "#a3a3a3"
    return "#059669" if outcome == "success" else "#dc2626"


def render_fault_grid(results: List[Dict[str, Any]]) -> str:
    points = [r for r in results if not r.get("is_control", False)]
    if not points:
        return "<p>No runtime sweep results found.</p>"

    points.sort(key=lambda r: (str(r.get("fault_type", "w")), int(r.get("fault_requested", r.get("fault_at", 0)))))

    cells = []
    for p in points:
        ftype = str(p.get("fault_type", "w"))
        label = FAULT_LABELS.get(ftype, ftype)
        at = int(p.get("fault_requested", p.get("fault_at", 0)))
        outcome = str(p.get("boot_outcome", "unknown"))
        injected = bool(p.get("fault_injected", False))
        color = score_color(outcome, injected)
        title = f"type={label} fp={at} outcome={outcome} injected={injected}"
        cells.append(
            "<div class='cell' style='background:{}' title='{}'></div>".format(
                color,
                html.escape(title, quote=True),
            )
        )

    return (
        "<div class='grid'>" + "".join(cells) + "</div>"
        "<div class='legend'>"
        "<span><i style='background:#059669'></i> success</span>"
        "<span><i style='background:#dc2626'></i> failure</span>"
        "<span><i style='background:#a3a3a3'></i> not injected</span>"
        "</div>"
    )


def render_audit_card(path: Path, payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    sweep = payload.get("summary", {}).get("runtime_sweep", {})
    profile = str(payload.get("profile", path.stem))
    bricks = int(sweep.get("bricks", 0))
    total = int(sweep.get("total_fault_points", 0))
    brick_rate = float(sweep.get("brick_rate", 0.0)) * 100.0
    verdict = str(payload.get("verdict", "unknown"))
    control = sweep.get("control", {})
    control_outcome = control.get("boot_outcome", "n/a")

    metrics = (
        "<div class='metrics'>"
        f"<div><b>verdict</b><span>{html.escape(verdict)}</span></div>"
        f"<div><b>bricks</b><span>{bricks}/{total}</span></div>"
        f"<div><b>brick rate</b><span>{brick_rate:.1f}%</span></div>"
        f"<div><b>control</b><span>{html.escape(str(control_outcome))}</span></div>"
        "</div>"
    )

    grid = render_fault_grid(payload.get("runtime_sweep_results", []))

    card = (
        "<section class='card'>"
        f"<h2>{html.escape(profile)}</h2>"
        f"<p class='path'>{html.escape(str(path))}</p>"
        f"{metrics}"
        f"{grid}"
        "</section>"
    )

    summary = {
        "profile": profile,
        "bricks": bricks,
        "total": total,
        "brick_rate": brick_rate,
        "verdict": verdict,
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
        "<h2>Self-Test Summary</h2>"
        f"<p class='path'>{html.escape(str(path))}</p>"
        "<div class='metrics'>"
        f"<div><b>profiles</b><span>{total}</span></div>"
        f"<div><b>passed</b><span>{passed}</span></div>"
        f"<div><b>failed</b><span>{failed}</span></div>"
        "</div>"
        "<table><thead><tr><th>Profile</th><th>Verdict</th><th>Reason</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
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
        f"<div><b>cases</b><span>{_as_int(totals.get('cases_total', len(payload.get('cases', []))))}</span></div>"
        f"<div><b>clusters</b><span>{len(clusters)}</span></div>"
        f"<div><b>control mismatches</b><span>{_as_int(totals.get('cases_control_mismatch'))}</span></div>"
        f"<div><b>defect deltas</b><span>{len(defect_deltas)}</span></div>"
        f"<div><b>anomalous points</b><span>{_as_int(totals.get('anomalous_points_total'))}</span></div>"
        f"<div><b>otadata suspicious</b><span>{_as_int(totals.get('otadata_suspicious_drift_points_total'))}</span></div>"
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
        "<h2>Exploratory Matrix Summary</h2>"
        f"<p class='path'>{html.escape(str(path))}</p>"
        f"{metrics}"
        "<h3>Top Clusters</h3>"
        "<table><thead><tr>"
        "<th>#</th><th>Kind</th><th>Score</th><th>Occurrences</th><th>Cases</th><th>Signature</th>"
        "</tr></thead><tbody>"
        f"{''.join(top_cluster_rows)}"
        "</tbody></table>"
        "<h3>Top Worsening Defect Deltas</h3>"
        "<table><thead><tr>"
        "<th>#</th><th>Score</th><th>Scenario</th><th>Fault</th><th>Criteria</th>"
        "<th>Δfailure</th><th>Δbrick</th><th>Δcontrol</th><th>Δcontrol_outcome</th>"
        "</tr></thead><tbody>"
        f"{''.join(top_regression_rows)}"
        "</tbody></table>"
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
        "<h2>Matrix Dashboard</h2>"
        "<table><thead><tr>"
        "<th>Matrix JSON</th><th>Cases</th><th>Clusters</th><th>Control mismatches</th>"
        "<th>Defect deltas</th><th>Worse deltas</th><th>Anomalous points</th><th>OtaData suspicious</th>"
        "</tr></thead><tbody>"
        f"{''.join(rows)}"
        "</tbody></table>"
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
        "<h2>Two-Report Comparison</h2>"
        "<table><thead><tr><th>Report</th><th>Bricks</th><th>Rate</th><th>Verdict</th></tr></thead><tbody>"
        f"<tr><td>{html.escape(a['profile'])}</td><td>{a['bricks']}/{a['total']}</td><td>{a['brick_rate']:.1f}%</td><td>{html.escape(a['verdict'])}</td></tr>"
        f"<tr><td>{html.escape(b['profile'])}</td><td>{b['bricks']}/{b['total']}</td><td>{b['brick_rate']:.1f}%</td><td>{html.escape(b['verdict'])}</td></tr>"
        "</tbody></table>"
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
<html>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>OTA Resilience Report</title>
<style>
:root {
  --bg: #f5f7fb;
  --card: #ffffff;
  --text: #0f172a;
  --muted: #475569;
  --border: #dbe2ea;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
  background: radial-gradient(circle at 20% -5%, #dbeafe, transparent 35%), var(--bg);
  color: var(--text);
}
main {
  max-width: 1200px;
  margin: 24px auto;
  padding: 0 16px 40px;
}
h1 { margin: 0 0 16px; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
  margin: 0 0 16px;
}
.path { margin: 4px 0 12px; color: var(--muted); font-size: 13px; }
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
  margin: 0 0 14px;
}
.metrics div {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px;
  background: #f8fafc;
}
.metrics b { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; }
.metrics span { font-size: 18px; font-weight: 700; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(10px, 1fr));
  gap: 2px;
  border: 1px solid var(--border);
  padding: 6px;
  border-radius: 8px;
  background: #f8fafc;
}
.cell { width: 100%; min-height: 10px; border-radius: 2px; }
.legend { display: flex; gap: 12px; margin-top: 8px; color: var(--muted); font-size: 12px; flex-wrap: wrap; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid var(--border); padding: 6px 8px; text-align: left; font-size: 13px; }
tr.ok { background: #ecfdf5; }
tr.bad { background: #fef2f2; }
.note { color: var(--muted); font-size: 13px; margin-top: 8px; }
</style>
</head>
<body>
<main>
<h1>OTA Resilience Report</h1>
""" + comparison + """\n""" + matrix_comparison + """\n""" + "\n".join(cards) + """
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
