#!/usr/bin/env python3
"""Unit tests for fault-kind-qualified evidence, reports, explicit points, and zero-point kinds."""

from __future__ import annotations

import ast
import json
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_report import categorize_failure, compute_verdict, summarize_runtime_sweep  # noqa: E402
from compare_heuristic_vs_exhaustive import compare_results  # noqa: E402
from debug_point import (  # noqa: E402
    _parse_reproduction_dict,
    _parse_selector_cuts,
    _preserve_pre_recovery_states,
    resolve_debug_target,
)
from fault_inject import generate_multi_fault_sequences  # noqa: E402
from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from invariants import InvariantViolation  # noqa: E402
from point_counts import (  # noqa: E402
    build_point_counts,
    merge_point_counts,
    render_point_counts_markdown,
    render_point_counts_text,
)
from profile_loader import ProfileError, load_profile  # noqa: E402
from recovery_coverage import summarize_recovery_coverage  # noqa: E402
from recovery_explanation import explain_recovery_failures  # noqa: E402
from recovery_search import attach_search_metadata  # noqa: E402
from render_results_html import render_audit_card  # noqa: E402
from report_junit import junit_report  # noqa: E402
from report_points import ReportRun  # noqa: E402
from report_sarif import sarif_report  # noqa: E402
from run_demo import result_from_report  # noqa: E402


def _write_profile(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def _load_runtime_evidence_namespace(globals_dict: Dict[str, Any] | None = None) -> Dict[str, Any]:
    runtime_src = (SCRIPTS / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    tree = ast.parse(runtime_src)
    wanted_funcs = {
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        "parse_mram_erase_trace",
        "collect_mram_fault_evidence",
        "collect_mram_erase_fault_evidence",
        "_deferred_mram_replay_fault_evidence",
        "_operation_kind_for_fault_type",
    }
    selected_nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted_funcs
    ]
    ns: Dict[str, Any] = dict(globals_dict or {})
    exec(compile(ast.Module(body=selected_nodes, type_ignores=[]), "runtime_sweep", "exec"), ns, ns)
    return ns


def _build_mixed_same_index_payload(tmp_path: Path) -> tuple[ Any, Dict[str, Any] ]:
    prof_path = _write_profile(
        tmp_path,
        "mixed_same_index",
        """
        schema_version: 1
        name: mixed_same_index
        platform: platforms/cortex_m0_self_update.repl
        bootloader:
          elf: examples/erase_before_program/firmware.elf
          entry: 0x00000000
        memory:
          sram: { start: 0x20000000, end: 0x20004000 }
          write_granularity: 16
          page_size: 0x400
          slots:
            exec: { base: 0x10100000, size: 0x400 }
            staging: { base: 0x10100400, size: 0x400 }
        flash_backend: mramTracker
        success_criteria:
          pc_in_slot: exec
        fault_sweep:
          evaluation_mode: execute
          sweep_strategy: exhaustive
          fault_types: [power_loss, interrupted_erase]
          include_erase_fault_points: true
          mram_torn_word: half
        """,
    )
    profile = load_profile(prof_path, strict=True)

    control_row: Dict[str, Any] = {
        "fault_at": -1,
        "fault_type": "control",
        "is_control": True,
        "fault_injected": False,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "recovery_coverage": {
            "executed_pcs": [0x00000100],
            "recording_overhead_s": 0.001,
            "boot_wall_time_s": 0.01,
        },
        "signals": {
            "execution_observed": True,
            "pc_ok": True,
            "recovery_coverage_pcs": [0x00000100],
        },
    }
    program_row: Dict[str, Any] = {
        "fault_at": 0,
        "fault_requested": 0,
        "fault_type": "w",
        "operation_kind": "program",
        "is_control": False,
        "fault_injected": True,
        "fault_address": "0x10100000",
        "mram_torn_word": "half",
        "boot_outcome": "wrong_image",
        "boot_slot": "exec",
        "mram_fault_evidence": {
            "exact": True,
            "operation_kind": "program",
            "selected_write_index": 0,
            "backend_write_index": 1,
            "program_address": "0x10100000",
            "offset": "0x0",
            "program_width": 16,
            "intended_bytes": "00200020110100000000000000000000",
            "pre_program_bytes": "ffffffffffffffffffffffffffffffff",
            "post_fault_bytes": "0020002011010000ffffffffffffffff",
            "word_marked_uncorrectable": False,
            "write_trace": [
                {
                    "write_index": 1,
                    "offset": "0x0",
                    "address": "0x10100000",
                    "width": 16,
                    "intended_bytes": "00200020110100000000000000000000",
                    "pre_bytes": "ffffffffffffffffffffffffffffffff",
                    "post_bytes": "0020002011010000ffffffffffffffff",
                    "faulted": True,
                }
            ],
        },
        "fault_snapshot": {
            "sha256": "11" * 32,
            "size": 1024,
            "closest_declared_image": {
                "name": "staging",
                "differing_bytes": 8,
                "differing_ranges": [{"offset": 8, "size": 8, "address": "0x10100008"}],
            },
        },
        "fault_snapshot_file": "snapshots/program_0.bin",
        "signals": {
            "execution_observed": True,
            "pc_ok": False,
            "content_mismatch": True,
            "function_return_probes": {
                "flash_write": {"raw_values": [0]},
            },
            "uncorrectable_read": {
                "read_observed": True,
                "word_address": "0x10100000",
                "word_addresses": ["0x10100000"],
                "read_count": 1,
                "outcome": "faulted",
                "handled": False,
            },
            "recovery_coverage_pcs": [0x00000100, 0x00000110],
        },
        "recovery_coverage": {
            "executed_pcs": [0x00000100, 0x00000110],
            "recording_overhead_s": 0.001,
            "boot_wall_time_s": 0.01,
        },
        "invariant_violations": [
            {
                "name": "success_implies_effect",
                "description": "contract violated at program 0",
                "details": InvariantViolation(
                    "success_implies_effect",
                    "contract violated at program 0",
                    SimpleNamespace(fault_type="w", is_control=False, fault_sequence=None),
                    {
                        "fault_at": 0,
                        "fault_type": "w",
                        "contract": "write_commit",
                        "probe": "flash_write",
                        "return_value_text": "0x00000000",
                        "conditions": [{"pre_value": "0xFFFFFFFF", "post_value": "0xFFFFFFFF"}],
                    },
                ).details,
            }
        ],
    }
    erase_row: Dict[str, Any] = {
        "fault_at": 0,
        "fault_requested": 0,
        "fault_type": "e",
        "operation_kind": "erase",
        "is_control": False,
        "fault_injected": True,
        "fault_address": "0x10100000",
        "mram_torn_word": "half",
        "boot_outcome": "hard_fault",
        "boot_slot": None,
        "mram_fault_evidence": {
            "exact": True,
            "operation_kind": "erase",
            "selected_erase_index": 0,
            "backend_erase_index": 1,
            "erase_address": "0x10100000",
            "program_address": "0x10100000",
            "offset": "0x0",
            "erase_size": 1024,
            "program_width": 1024,
            "intended_bytes": "ff" * 32,
            "pre_erase_bytes": "aa" * 32,
            "pre_program_bytes": "aa" * 32,
            "post_fault_bytes": ("ff" * 16) + ("aa" * 16),
            "post_erase_bytes": ("ff" * 16) + ("aa" * 16),
            "word_marked_uncorrectable": True,
            "uncorrectable_word_address": "0x10100000",
            "uncorrectable_words": ["0x10100000", "0x10100010"],
            "erase_trace": [
                {
                    "erase_index": 1,
                    "offset": "0x0",
                    "address": "0x10100000",
                    "erase_size": 1024,
                    "intended_bytes": "ff" * 32,
                    "pre_bytes": "aa" * 32,
                    "post_bytes": ("ff" * 16) + ("aa" * 16),
                    "faulted": True,
                    "writes_at_this_point": 0,
                }
            ],
        },
        "fault_snapshot": {
            "sha256": "22" * 32,
            "size": 1024,
            "uncorrectable_words": ["0x10100000", "0x10100010"],
            "closest_declared_image": {
                "name": "exec",
                "differing_bytes": 512,
                "differing_ranges": [{"offset": 0, "size": 512, "address": "0x10100000"}],
            },
        },
        "fault_snapshot_file": "snapshots/erase_0.bin",
        "signals": {
            "execution_observed": False,
            "uncorrectable_words_at_fault": ["0x10100000", "0x10100010"],
            "uncorrectable_read": {
                "read_observed": True,
                "word_address": "0x10100010",
                "word_addresses": ["0x10100000", "0x10100010"],
                "read_count": 2,
                "outcome": "faulted",
                "handled": False,
            },
            "recovery_coverage_pcs": [0x00000100, 0x00000120],
        },
        "recovery_coverage": {
            "executed_pcs": [0x00000100, 0x00000120],
            "recording_overhead_s": 0.001,
            "boot_wall_time_s": 0.01,
        },
    }

    cov_scope = {
        "enabled": True,
        "granularity": "function_and_line",
        "mechanism": "oneshot_address_hooks",
        "line_info_available": True,
        "functions": [
            {
                "id": "fn_recover",
                "name": "recover_boot",
                "start": 0x00000100,
                "end": 0x00000130,
                "start_address": "0x00000100",
                "end_address": "0x00000130",
                "size_bytes": 48,
                "probe_pcs": [0x00000100, 0x00000110, 0x00000120],
                "basic_blocks": [
                    {"start": 0x00000100, "end": 0x00000108, "probe_pc": 0x00000100},
                    {"start": 0x00000110, "end": 0x00000118, "probe_pc": 0x00000110},
                    {"start": 0x00000120, "end": 0x00000128, "probe_pc": 0x00000120},
                ],
            }
        ],
        "basic_blocks": [
            {"function_id": "fn_recover", "start": 0x00000100, "end": 0x00000108, "probe_pc": 0x00000100},
            {"function_id": "fn_recover", "start": 0x00000110, "end": 0x00000118, "probe_pc": 0x00000110},
            {"function_id": "fn_recover", "start": 0x00000120, "end": 0x00000128, "probe_pc": 0x00000120},
        ],
        "lines": [
            {
                "id": "main.c:40",
                "file": "main.c",
                "line": 40,
                "function": "recover_boot",
                "start": 0x00000110,
                "end": 0x00000118,
                "start_address": "0x00000110",
                "end_address": "0x00000118",
                "probe_pcs": [0x00000110],
            },
            {
                "id": "main.c:55",
                "file": "main.c",
                "line": 55,
                "function": "recover_boot",
                "start": 0x00000120,
                "end": 0x00000128,
                "start_address": "0x00000120",
                "end_address": "0x00000128",
                "probe_pcs": [0x00000120],
            },
        ],
    }

    results = [control_row, program_row, erase_row]
    explain_recovery_failures(
        rows=results,
        expected="success",
        elf=ROOT / "examples" / "erase_before_program" / "firmware.elf",
        root=ROOT,
        flash_base=0x10100000,
        page_size=1024,
        write_granularity=16,
    )
    summary = summarize_runtime_sweep(
        results,
        total_writes=1,
        profile=profile,
        expected_fault_points=2,
        planned_fault_types=["w", "e"],
        recovery_coverage_scope=cov_scope,
    )
    payload: Dict[str, Any] = {
        "profile": profile.name,
        "profile_path": str(prof_path),
        "verdict": compute_verdict(summary, profile.expect),
        "summary": {"runtime_sweep": summary},
        "runtime_sweep_results": results,
    }
    return profile, payload


def test_mixed_sweep_same_index_keeps_evidence_apart_across_all_formats(tmp_path: Path) -> None:
    profile, payload = _build_mixed_same_index_payload(tmp_path)
    summary = payload["summary"]["runtime_sweep"]

    # 1. JSON report structures carry operation_kind alongside fault_at and keep w[0] and e[0] apart.
    non_control = [r for r in payload["runtime_sweep_results"] if not r.get("is_control")]
    assert len(non_control) == 2
    by_kind = {(r["operation_kind"], r["fault_at"]): r for r in non_control}
    assert set(by_kind.keys()) == {("program", 0), ("erase", 0)}
    assert by_kind[("program", 0)]["fault_snapshot"]["sha256"] == "11" * 32
    assert by_kind[("erase", 0)]["fault_snapshot"]["sha256"] == "22" * 32

    failures = summary["failures"]
    assert len(failures) == 2
    failures_by_kind = {(f["operation_kind"], f["fault_at"]): f for f in failures}
    assert set(failures_by_kind.keys()) == {("program", 0), ("erase", 0)}
    assert failures_by_kind[("program", 0)]["mram_fault_evidence"]["operation_kind"] == "program"
    assert failures_by_kind[("program", 0)]["mram_fault_evidence"]["post_fault_bytes"].startswith("00200020")
    assert failures_by_kind[("erase", 0)]["mram_fault_evidence"]["operation_kind"] == "erase"
    assert failures_by_kind[("erase", 0)]["mram_fault_evidence"]["erase_size"] == 1024
    assert failures_by_kind[("erase", 0)]["mram_fault_evidence"]["pre_erase_bytes"] == "aa" * 32
    assert failures_by_kind[("erase", 0)]["mram_fault_evidence"]["post_fault_bytes"] == ("ff" * 16) + ("aa" * 16)
    assert failures_by_kind[("erase", 0)]["mram_fault_evidence"]["uncorrectable_words"] == [
        "0x10100000",
        "0x10100010",
    ]

    # Failure explanations carry distinct cut kinds for w[0] vs e[0].
    prog_expl = failures_by_kind[("program", 0)]["failure_explanation"]
    erase_expl = failures_by_kind[("erase", 0)]["failure_explanation"]
    assert prog_expl["cuts"][0]["operation"] == "write"
    assert prog_expl["cuts"][0]["fault_type"] == "power_loss"
    assert erase_expl["cuts"][0]["operation"] == "erase"
    assert erase_expl["cuts"][0]["fault_type"] == "interrupted_erase"

    # summary.fault_evidence keeps both entries at fault_at=0 with distinct operation_kind and bytes.
    fe_list = summary["fault_evidence"]
    assert len(fe_list) == 2
    fe_by_kind = {(item["operation_kind"], item["fault_at"]): item for item in fe_list}
    assert set(fe_by_kind.keys()) == {("program", 0), ("erase", 0)}
    assert fe_by_kind[("program", 0)]["snapshot_sha256"] == "11" * 32
    assert fe_by_kind[("erase", 0)]["snapshot_sha256"] == "22" * 32
    assert fe_by_kind[("erase", 0)]["erase_size"] == 1024
    assert fe_by_kind[("erase", 0)]["pre_erase_bytes"] == "aa" * 32
    assert fe_by_kind[("erase", 0)]["post_fault_bytes"] == ("ff" * 16) + ("aa" * 16)
    assert fe_by_kind[("erase", 0)]["uncorrectable_words"] == ["0x10100000", "0x10100010"]

    # mram_uncorrectable_reads.observations carries operation_kind on every observation.
    uncorr_obs = summary["mram_uncorrectable_reads"]["observations"]
    assert len(uncorr_obs) == 2
    obs_by_kind = {(o["operation_kind"], o["fault_at"]): o for o in uncorr_obs}
    assert set(obs_by_kind.keys()) == {("program", 0), ("erase", 0)}
    assert obs_by_kind[("program", 0)]["word_address"] == "0x10100000"
    assert obs_by_kind[("erase", 0)]["word_address"] == "0x10100010"

    # InvariantViolation details with fault_at automatically include operation_kind.
    inv_details = by_kind[("program", 0)]["invariant_violations"][0]["details"]
    assert inv_details["fault_at"] == 0
    assert inv_details["operation_kind"] == "program"

    # Recovery coverage "first point that reached it" and coverage_by_boot carry operation_kind.
    cov = summary["recovery_coverage"]
    lines_by_num = {ln["line"]: ln for ln in cov["lines"]}
    assert lines_by_num[40]["first_reached_by"]["fault_at"] == 0
    assert lines_by_num[40]["first_reached_by"]["operation_kind"] == "program"
    assert lines_by_num[40]["first_reached_by"]["label"] == "w@0"
    assert lines_by_num[55]["first_reached_by"]["fault_at"] == 0
    assert lines_by_num[55]["first_reached_by"]["operation_kind"] == "erase"
    assert lines_by_num[55]["first_reached_by"]["label"] == "e@0"
    boot_kinds = [(b["operation_kind"], b["fault_at"], b["label"]) for b in cov["coverage_by_boot"]]
    assert boot_kinds == [("program", 0, "w@0"), ("erase", 0, "e@0")]

    # 2. SARIF output keeps w[0] and e[0] distinct in results[].properties.points.
    run = ReportRun(payload, "mixed_same_index", profile_path=Path(payload["profile_path"]))
    sarif_doc = sarif_report([run], ROOT)
    sarif_run = sarif_doc["runs"][0]
    sarif_results = sarif_run["results"]
    assert len(sarif_results) >= 2
    sarif_by_kind: Dict[tuple[str, int], Dict[str, Any]] = {}
    for res in sarif_results:
        for pt in (res.get("properties") or {}).get("points") or []:
            sarif_by_kind[(pt["operation_kind"], pt["fault_at"])] = pt
    assert set(sarif_by_kind.keys()) == {("program", 0), ("erase", 0)}
    assert sarif_by_kind[("program", 0)]["name"].endswith("w[0]")
    assert sarif_by_kind[("program", 0)]["fault_type"] == "w"
    assert sarif_by_kind[("program", 0)]["mram_fault_evidence"]["operation_kind"] == "program"
    assert sarif_by_kind[("program", 0)]["fault_snapshot"]["sha256"] == "11" * 32
    assert sarif_by_kind[("erase", 0)]["name"].endswith("e[0]")
    assert sarif_by_kind[("erase", 0)]["fault_type"] == "e"
    assert sarif_by_kind[("erase", 0)]["mram_fault_evidence"]["operation_kind"] == "erase"
    assert sarif_by_kind[("erase", 0)]["mram_fault_evidence"]["erase_size"] == 1024
    assert sarif_by_kind[("erase", 0)]["fault_snapshot"]["sha256"] == "22" * 32
    sarif_fe = sarif_run["properties"]["fault_evidence"]
    assert {(item["operation_kind"], item["fault_at"]) for item in sarif_fe} == {
        ("program", 0),
        ("erase", 0),
    }

    # 3. JUnit XML keeps w[0] and e[0] distinct on <testcase> attributes and suite properties.
    junit_xml = junit_report([run])
    root = ET.fromstring(junit_xml)
    suite = root.find("testsuite")
    assert suite is not None
    cases = {
        (tc.attrib["operation_kind"], int(tc.attrib["fault_at"])): tc
        for tc in suite.findall("testcase")
        if "operation_kind" in tc.attrib and "fault_at" in tc.attrib
    }
    assert set(cases.keys()) == {("program", 0), ("erase", 0)}
    assert cases[("program", 0)].attrib["name"].endswith("w[0]")
    assert cases[("program", 0)].attrib["fault_type"] == "w"
    w_ev = json.loads(cases[("program", 0)].attrib["fault_evidence"])
    assert w_ev["operation_kind"] == "program"
    assert json.loads(cases[("program", 0)].attrib["fault_snapshot"])["sha256"] == "11" * 32

    assert cases[("erase", 0)].attrib["name"].endswith("e[0]")
    assert cases[("erase", 0)].attrib["fault_type"] == "e"
    e_ev = json.loads(cases[("erase", 0)].attrib["fault_evidence"])
    assert e_ev["operation_kind"] == "erase"
    assert e_ev["erase_size"] == 1024
    assert json.loads(cases[("erase", 0)].attrib["fault_snapshot"])["sha256"] == "22" * 32

    # 4. HTML report renders both w[0] and e[0] with distinct evidence rows.
    html_text, _ = render_audit_card(Path("mixed_same_index.json"), payload)
    assert "w[0]" in html_text
    assert "e[0]" in html_text
    assert "per-point unit / before / after / snapshot" in html_text
    assert "111111111111" in html_text
    assert "222222222222" in html_text
    assert "0020002011010000ffffffffffffffff" in html_text
    assert ("ff" * 16) + ("aa" * 16) in html_text

    # 5. Index-keyed helpers keep w[0] and e[0] apart instead of colliding on index 0.
    erase_first_payload = {
        **payload,
        "summary": {
            "runtime_sweep": {
                **summary,
                "failures": [failures_by_kind[("erase", 0)], failures_by_kind[("program", 0)]],
            }
        },
    }
    demo_erase_first = result_from_report(
        erase_first_payload,
        label="Mixed",
        report_path=tmp_path / "mixed.json",
    )
    assert demo_erase_first.first_boot_outcome == "hard_fault"

    comp = compare_results(non_control, [by_kind[("program", 0)]])
    assert comp["exhaustive_issue_count"] == 2
    assert comp["heuristic_issue_count"] == 1
    assert comp["issue_recall"] == 0.5


def test_erase_cut_evidence_parity_and_backend_contracts() -> None:
    intended = bytes([0xFF] * 64)
    pre = bytes([0xA5] * 64)
    post = bytes([0xFF] * 32 + [0xA5] * 32)
    snapshot = post + bytes([0xFF] * 64)
    erase_trace = "1:0:0:64\n"
    data = SimpleNamespace(
        FaultFired=True,
        EraseFaultFired=True,
        EraseFaultEvidenceExact=True,
        FaultEvidenceExact=True,
        LastFaultWriteIndex=0,
        LastFaultEraseIndex=1,
        LastFaultProgramAddress=0x10100000,
        LastFaultOffset=0,
        LastFaultEraseSize=64,
        LastFaultProgramWidth=64,
        LastFaultIntendedBytes=intended,
        LastFaultPreEraseBytes=pre,
        LastFaultPreProgramBytes=pre,
        LastFaultPostEraseBytes=post,
        LastFaultPostFaultBytes=post,
        LastFaultWordMarkedUncorrectable=True,
        LastFaultUncorrectableWordAddress=0x10100000,
        FaultUncorrectableWords=[0x10100000, 0x10100010],
        FaultMemorySnapshot=snapshot,
        EraseTraceCount=1,
        EraseTraceToString=lambda: erase_trace,
        Size=128,
    )
    backend = {"data": data, "bus_base": 0x10100000}
    ns = _load_runtime_evidence_namespace(
        {
            "backend": backend,
            "fmt_u32": lambda value: "0x{:08X}".format(int(value)),
            "to_py_bytes": lambda value: bytearray(value) if value is not None else None,
        }
    )
    collect_mram_fault_evidence = ns["collect_mram_fault_evidence"]
    collect_mram_erase_fault_evidence = ns["collect_mram_erase_fault_evidence"]

    ev, observed_snap, raw_snap = collect_mram_erase_fault_evidence(0, 1)
    assert ev["exact"] is True
    assert ev["operation_kind"] == "erase"
    assert ev["selected_erase_index"] == 0
    assert ev["backend_erase_index"] == 1
    assert ev["erase_address"] == "0x10100000"
    assert ev["program_address"] == "0x10100000"
    assert ev["offset"] == 0
    assert ev["erase_size"] == 64
    assert ev["program_width"] == 64
    assert ev["intended_bytes"] == "ff" * 64
    assert ev["pre_erase_bytes"] == "a5" * 64
    assert ev["pre_program_bytes"] == "a5" * 64
    assert ev["post_fault_bytes"] == ("ff" * 32) + ("a5" * 32)
    assert ev["post_erase_bytes"] == ("ff" * 32) + ("a5" * 32)
    assert ev["word_marked_uncorrectable"] is True
    assert ev["uncorrectable_word_address"] == "0x10100000"
    assert ev["uncorrectable_words"] == ["0x10100000", "0x10100010"]
    assert len(ev["erase_trace"]) == 1
    assert ev["erase_trace"][0]["faulted"] is True
    assert ev["erase_trace"][0]["erase_size"] == 64
    assert observed_snap == bytearray(snapshot)
    assert raw_snap == snapshot

    # Auto-detection through collect_mram_fault_evidence also returns erase evidence.
    ev_auto, _, _ = collect_mram_fault_evidence(0, 1)
    assert ev_auto["operation_kind"] == "erase"
    assert ev_auto["exact"] is True
    assert ev_auto["erase_size"] == 64

    # Fail-closed when backend erase index disagrees.
    ev_mismatch, _, _ = collect_mram_erase_fault_evidence(0, 2)
    assert ev_mismatch["exact"] is False
    assert ev_mismatch["operation_kind"] == "erase"
    assert "fault erase index" in ev_mismatch["capability_error"]

    # Check C# peripheral implementations expose the exact erase evidence properties.
    for rel_cs in (
        "peripherals/MappedMRAMTracker.cs",
        "peripherals/NVMemoryController.cs",
        "peripherals/GenericNvmController.cs",
    ):
        cs_text = (ROOT / rel_cs).read_text(encoding="utf-8")
        assert "LastFaultEraseIndex" in cs_text, rel_cs
        assert "LastFaultEraseSize" in cs_text, rel_cs
        assert "LastFaultPreEraseBytes" in cs_text, rel_cs
        assert "LastFaultPostEraseBytes" in cs_text, rel_cs
        assert "EraseFaultEvidenceExact" in cs_text, rel_cs


def test_explicit_point_syntax_roundtrips_through_profile_and_debug(tmp_path: Path) -> None:
    # 1. tardigrade debug point parser distinguishes w[0] and e[0], 2-cut chains, and dicts.
    assert _parse_selector_cuts("w[0]") == [(0, "w")]
    assert _parse_selector_cuts("e[0]") == [(0, "e")]
    assert _parse_selector_cuts("w@0") == [(0, "w")]
    assert _parse_selector_cuts("e@0") == [(0, "e")]
    assert _parse_selector_cuts("e:0") == [(0, "e")]
    assert _parse_selector_cuts('[0, "interrupted_erase"]') == [(0, "e")]
    assert _parse_selector_cuts("e[0] -> w[2]") == [(0, "e"), (2, "w")]

    repro_dict = _parse_reproduction_dict({"fault_at": 0, "operation_kind": "erase"})
    assert repro_dict["fault_at"] == 0
    assert repro_dict["fault_type_code"] == "e"
    assert repro_dict["cuts"] == ((0, "e"),)

    repro_points = _parse_reproduction_dict({"fault_sweep": {"points": ["e[0]"]}})
    assert repro_points["fault_at"] == 0
    assert repro_points["fault_type_code"] == "e"
    assert repro_points["cuts"] == ((0, "e"),)

    repro_chain_2 = _parse_reproduction_dict(
        {"fault_sweep": {"phase2_fault": {"chains": [[[0, "interrupted_erase"], [2, "power_loss"]]]}}}
    )
    assert repro_chain_2["fault_at"] == 0
    assert repro_chain_2["fault_type_code"] == "p2:0:2:e:w"
    assert repro_chain_2["cuts"] == ((0, "e"), (2, "w"))

    # 2. Profile explicit points, typed pairs, 2-cut chains, and typed multi-fault sequences.
    prof_points_path = _write_profile(
        tmp_path,
        "explicit_points",
        """
        schema_version: 1
        name: explicit_points
        platform: platforms/cortex_m0_self_update.repl
        bootloader:
          elf: examples/erase_before_program/firmware.elf
          entry: 0x00000000
        memory:
          sram: { start: 0x20000000, end: 0x20004000 }
          write_granularity: 16
          page_size: 0x400
          slots:
            exec: { base: 0x10100000, size: 0x400 }
            staging: { base: 0x10100400, size: 0x400 }
        flash_backend: mramTracker
        success_criteria:
          pc_in_slot: exec
        fault_sweep:
          evaluation_mode: execute
          sweep_strategy: exhaustive
          include_erase_fault_points: true
          points:
            - "w[0]"
            - "e[0]"
          multi_fault:
            enabled: true
            strategy: explicit
            sequences:
              - ["e[0]", "w[1]"]
        """,
    )
    prof_points = load_profile(prof_points_path, strict=True)
    plan = build_fault_plan(prof_points, CalibrationInputs(max_writes=5, total_erases=3))
    assert plan.fault_points == [0, 0]
    assert plan.fault_types_list == ["w", "e"]

    _, mixed_payload = _build_mixed_same_index_payload(tmp_path)
    report_path = tmp_path / "mixed_report.json"
    report_path.write_text(json.dumps(mixed_payload), encoding="utf-8")
    target_w0 = resolve_debug_target(report=report_path, point="w[0]", repo_root=ROOT)
    target_e0 = resolve_debug_target(report=report_path, point="e[0]", repo_root=ROOT)
    assert target_w0.fault_at == 0
    assert target_w0.fault_type_code == "w"
    assert target_e0.fault_at == 0
    assert target_e0.fault_type_code == "e"

    mf_plan = generate_multi_fault_sequences(
        strategy="explicit",
        interesting_points=[0, 1],
        max_faults_per_run=2,
        explicit_sequences=prof_points.fault_sweep.multi_fault.sequences,
        explicit_stage_types=prof_points.fault_sweep.multi_fault.sequence_stage_types,
    )
    assert len(mf_plan.sequences) == 1
    assert mf_plan.sequences[0].fault_points == (0, 1)
    assert mf_plan.sequences[0].stage_codes() == ("e", "w")

    # 3. 2-cut phase2_fault.chains and typed phase2_fault.pairs.
    prof_p2_path = _write_profile(
        tmp_path,
        "explicit_p2",
        """
        schema_version: 1
        name: explicit_p2
        platform: platforms/cortex_m0_self_update.repl
        bootloader:
          elf: examples/erase_before_program/firmware.elf
          entry: 0x00000000
        memory:
          sram: { start: 0x20000000, end: 0x20004000 }
          write_granularity: 16
          page_size: 0x400
          slots:
            exec: { base: 0x10100000, size: 0x400 }
            staging: { base: 0x10100400, size: 0x400 }
        flash_backend: mramTracker
        success_criteria:
          pc_in_slot: exec
        fault_sweep:
          evaluation_mode: execute
          sweep_strategy: exhaustive
          include_erase_fault_points: true
          phase2_fault:
            enabled: true
            pairs:
              - ["e[0]", "w[1]"]
              - ["w[0]", "e[1]"]
        """,
    )
    prof_p2 = load_profile(prof_p2_path, strict=True)
    plan_p2 = build_fault_plan(prof_p2, CalibrationInputs(max_writes=4, total_erases=2))
    p2_items = [
        (fp, ft)
        for fp, ft in zip(plan_p2.fault_points, plan_p2.fault_types_list or [])
        if ft.startswith("p2:")
    ]
    assert p2_items == [(0, "p2:0:1:e:w"), (0, "p2:0:1:w:e")]

    # 4. Pre-recovery state preservation keeps operation_kind alongside fault_at.
    preserved = _preserve_pre_recovery_states(
        [
            {"fault_at": 0, "fault_type": "w", "operation_kind": "program", "_pre_recovery_state": {"zlib_b64": "prog_b64"}},
            {"fault_at": 0, "fault_type": "e", "operation_kind": "erase", "_pre_recovery_state": {"zlib_b64": "erase_b64"}},
        ]
    )
    assert preserved[("row", 0, 0, "w", "program")]["zlib_b64"] == "prog_b64"
    assert preserved[("row", 1, 0, "e", "erase")]["zlib_b64"] == "erase_b64"

    # 5. State search attach_search_metadata sets operation_kind from first cut.
    search_row: Dict[str, Any] = {"fault_at": 0, "fault_type": "rs"}
    attach_search_metadata(
        search_row,
        [
            {
                "operation": "erase",
                "operation_index": 0,
                "fault_type": "interrupted_erase",
                "address": "0x10100000",
                "offset": 0,
                "size": 1024,
            }
        ],
        SimpleNamespace(identity_hex=lambda: "ab" * 32),
        1,
    )
    assert search_row["operation_kind"] == "erase"


def test_zero_point_requested_kind_reported_in_summary_and_fails_under_strict_option(
    tmp_path: Path,
) -> None:
    base_yaml = """
    schema_version: 1
    name: zero_erase_points
    platform: platforms/cortex_m0_nvm_flash.repl
    bootloader:
      elf: examples/recovery_vector_fault/firmware.elf
      entry: 0x10000000
    memory:
      sram: { start: 0x20000000, end: 0x20002000 }
      write_granularity: 4
      page_size: 0x1000
      slots:
        exec: { base: 0x10000000, size: 0x1000 }
        staging: { base: 0x10001000, size: 0x1000 }
    flash_backend: nvm_ctrl
    success_criteria:
      vtor_in_slot: exec
    fault_sweep:
      sweep_strategy: exhaustive
      fault_types: [power_loss, interrupted_erase]
      include_erase_fault_points: true
    """
    prof_non_strict = load_profile(_write_profile(tmp_path, "non_strict", base_yaml), strict=True)
    assert prof_non_strict.fault_sweep.require_planned_points_per_kind is False

    # Calibration finds 2 writes and 0 erases.
    plan = build_fault_plan(prof_non_strict, CalibrationInputs(max_writes=2, total_erases=0))
    assert plan.fault_points == [0, 1]
    assert "single_cut_erase" in plan.zero_point_fault_kinds
    assert "interrupted_erase" in plan.zero_point_fault_kinds

    results = [
        {
            "fault_at": -1,
            "fault_type": "control",
            "is_control": True,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {"execution_observed": True, "vtor_ok": True},
        },
        {
            "fault_at": 0,
            "fault_type": "w",
            "operation_kind": "program",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {"execution_observed": True, "vtor_ok": True},
        },
        {
            "fault_at": 1,
            "fault_type": "w",
            "operation_kind": "program",
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {"execution_observed": True, "vtor_ok": True},
        },
    ]
    summary = summarize_runtime_sweep(
        results,
        total_writes=2,
        profile=prof_non_strict,
        expected_fault_points=2,
        planned_fault_types=["w", "w"],
    )
    erase_kind_row = summary["point_counts"]["kinds"]["single_cut_erase"]
    assert erase_kind_row["requested"] == 0
    assert erase_kind_row["zero_planned_points"] is True
    assert erase_kind_row["status"] == "zero_planned_points"
    assert erase_kind_row["note"] == "requested fault kind yielded zero planned points"
    assert summary["point_counts"]["zero_point_kinds"] == ["single_cut_erase"]
    assert summary["zero_point_fault_kinds"] == ["single_cut_erase"]
    assert summary["zero_point_fault_kind_statuses"]["single_cut_erase"]["zero_planned_points"] is True

    text_out = render_point_counts_text(summary["point_counts"])
    assert "single-cut erase: 0 / 0 / 0 / 0 / 0 / 0 / 0 / 0 / 0 (zero planned points)" in text_out
    md_out = render_point_counts_markdown(summary["point_counts"])
    assert "| single-cut erase | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |" in md_out
    assert "zero planned points for requested kind" in md_out

    merged_pc = merge_point_counts(summary["point_counts"])
    assert merged_pc["kinds"]["single_cut_erase"]["zero_planned_points"] is True
    assert merged_pc["zero_point_kinds"] == ["single_cut_erase"]

    payload = {
        "profile": prof_non_strict.name,
        "verdict": compute_verdict(summary, prof_non_strict.expect),
        "summary": {"runtime_sweep": summary},
        "runtime_sweep_results": results,
    }
    html_out, _ = render_audit_card(Path("zero_erase.json"), payload)
    assert "single-cut erase" in html_out
    assert "zero planned points" in html_out
    assert payload["verdict"].startswith("PASS")

    # Under require_planned_points_per_kind: true, both planning and verdict fail closed.
    strict_yaml = base_yaml + "  require_planned_points_per_kind: true\n"
    prof_strict = load_profile(_write_profile(tmp_path, "strict_zero", strict_yaml), strict=True)
    assert prof_strict.fault_sweep.require_planned_points_per_kind is True

    with pytest.raises(ProfileError, match="requested fault kind\\(s\\) yielded zero planned points"):
        build_fault_plan(prof_strict, CalibrationInputs(max_writes=2, total_erases=0))

    strict_summary = summarize_runtime_sweep(
        results,
        total_writes=2,
        profile=prof_strict,
        expected_fault_points=2,
        planned_fault_types=["w", "w"],
    )
    assert "zero_point_fault_kind_error" in strict_summary
    strict_verdict = compute_verdict(strict_summary, prof_strict.expect)
    assert strict_verdict.startswith("FAIL")
    assert "zero planned points" in strict_verdict


def test_profile_without_erase_cuts_unchanged_apart_from_added_kind_field(tmp_path: Path) -> None:
    prof_path = _write_profile(
        tmp_path,
        "program_only",
        """
        schema_version: 1
        name: program_only
        platform: platforms/cortex_m0_self_update.repl
        bootloader:
          elf: examples/erase_before_program/firmware.elf
          entry: 0x00000000
        memory:
          sram: { start: 0x20000000, end: 0x20004000 }
          write_granularity: 16
          page_size: 0x400
          slots:
            exec: { base: 0x10100000, size: 0x400 }
            staging: { base: 0x10100400, size: 0x400 }
        flash_backend: mramTracker
        success_criteria:
          pc_in_slot: exec
        fault_sweep:
          evaluation_mode: execute
          sweep_strategy: exhaustive
          fault_types: [power_loss]
        """,
    )
    profile = load_profile(prof_path, strict=True)
    plan = build_fault_plan(profile, CalibrationInputs(max_writes=2, total_erases=2))
    assert plan.fault_points == [0, 1]
    assert plan.fault_types_list is None
    assert plan.zero_point_fault_kinds == ()

    results = [
        {
            "fault_at": -1,
            "fault_type": "control",
            "is_control": True,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "exec",
            "signals": {"execution_observed": True, "pc_ok": True},
        },
        {
            "fault_at": 0,
            "fault_requested": 0,
            "fault_type": "w",
            "is_control": False,
            "fault_injected": True,
            "fault_address": "0x10100000",
            "boot_outcome": "hard_fault",
            "boot_slot": None,
            "mram_fault_evidence": {"exact": True, "program_width": 16},
            "fault_snapshot": {"sha256": "aa" * 32},
            "signals": {"execution_observed": False},
        },
    ]
    summary = summarize_runtime_sweep(
        results,
        total_writes=1,
        profile=profile,
        expected_fault_points=1,
        planned_fault_types=["w"],
    )
    assert "zero_point_fault_kinds" not in summary
    assert summary["fault_evidence"] == [
        {
            "fault_at": 0,
            "operation_kind": "program",
            "fault_address": "0x10100000",
            "boot_outcome": "hard_fault",
            "exact": True,
            "program_width": 16,
            "snapshot_sha256": "aa" * 32,
        }
    ]
    assert summary["failures"][0]["fault_at"] == 0
    assert summary["failures"][0]["operation_kind"] == "program"

