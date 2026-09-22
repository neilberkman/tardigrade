#!/usr/bin/env python3
"""Focused tests for generic MRAM fault evidence and report precedence."""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNTIME = SCRIPTS / "run_runtime_fault_sweep.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import summarize_runtime_sweep  # noqa: E402


def _runtime_functions(*names: str, globals_dict=None):
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in set(names)
    ]
    module = ast.Module(body=selected, type_ignores=[])
    namespace = dict(globals_dict or {})
    exec(compile(module, str(RUNTIME), "exec"), namespace, namespace)
    return namespace


def _hex(byte: int, width: int = 16) -> str:
    return "{:02x}".format(byte) * width


def test_exact_trace_parser_preserves_sixteen_byte_programs() -> None:
    ns = _runtime_functions(
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        globals_dict={"fmt_u32": lambda value: "0x{:08X}".format(value)},
    )
    trace = "1:32:16:{}:{}:{}:1\n".format(
        _hex(0x44), _hex(0x11), _hex(0x44, 8) + _hex(0xFF, 8)
    )

    events = ns["parse_mram_program_trace"](trace, 128, 0x10000000)

    assert events == [
        {
            "write_index": 1,
            "program_address": "0x10000020",
            "offset": 32,
            "program_width": 16,
            "intended_bytes": _hex(0x44),
            "pre_program_bytes": _hex(0x11),
            "post_program_bytes": _hex(0x44, 8) + _hex(0xFF, 8),
            "faulted": True,
        }
    ]


def test_exact_trace_parser_rejects_ambiguous_width() -> None:
    ns = _runtime_functions(
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        globals_dict={"fmt_u32": lambda value: "0x{:08X}".format(value)},
    )
    malformed = "1:0:16:{}:{}:{}:1\n".format(
        _hex(0x22, 8), _hex(0x00), _hex(0x22)
    )

    try:
        ns["parse_mram_program_trace"](malformed, 64, 0x1000)
    except ValueError as exc:
        assert "expected 32" in str(exc)
    else:
        raise AssertionError("ambiguous program width was accepted")


def test_mram_contract_validates_address_width_snapshot_and_trace() -> None:
    intended = bytes([0x22] * 16)
    pre = bytes([0x00] * 16)
    post = bytes([0x22] * 8 + [0x00] * 8)
    snapshot = post + bytes(48)
    trace = "1:0:16:{}:{}:{}:1\n".format(
        intended.hex(), pre.hex(), post.hex()
    )
    data = SimpleNamespace(
        FaultEvidenceExact=True,
        LastFaultWriteIndex=1,
        LastFaultProgramAddress=0x10000000,
        LastFaultOffset=0,
        LastFaultProgramWidth=16,
        LastFaultIntendedBytes=intended,
        LastFaultPreProgramBytes=pre,
        LastFaultPostFaultBytes=post,
        FaultMemorySnapshot=snapshot,
        ProgramTraceCount=1,
        ProgramTraceToString=lambda: trace,
        Size=64,
    )
    backend = {"data": data, "bus_base": 0x10000000}
    ns = _runtime_functions(
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        "collect_mram_fault_evidence",
        globals_dict={
            "backend": backend,
            "fmt_u32": lambda value: "0x{:08X}".format(value),
            "to_py_bytes": lambda value: bytearray(value) if value is not None else None,
        },
    )

    evidence, observed_snapshot, raw_snapshot = ns[
        "collect_mram_fault_evidence"
    ](0, 1)

    assert evidence["exact"] is True
    assert evidence["program_address"] == "0x10000000"
    assert evidence["program_width"] == 16
    assert evidence["post_fault_bytes"] == post.hex()
    assert len(evidence["write_trace"]) == 1
    assert observed_snapshot == bytearray(snapshot)
    assert raw_snapshot == snapshot


def test_mram_contract_fails_closed_without_trustworthy_width() -> None:
    data = SimpleNamespace(
        FaultEvidenceExact=False,
        LastFaultWriteIndex=1,
        LastFaultProgramAddress=0x1000,
        LastFaultOffset=0,
        LastFaultProgramWidth=0,
        LastFaultIntendedBytes=b"",
        LastFaultPreProgramBytes=b"",
        LastFaultPostFaultBytes=b"",
        FaultMemorySnapshot=bytes(16),
        ProgramTraceCount=0,
        ProgramTraceToString=lambda: "",
        Size=16,
    )
    ns = _runtime_functions(
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        "collect_mram_fault_evidence",
        globals_dict={
            "backend": {"data": data, "bus_base": 0x1000},
            "fmt_u32": lambda value: "0x{:08X}".format(value),
            "to_py_bytes": lambda value: bytearray(value) if value is not None else None,
        },
    )

    evidence, snapshot, raw_snapshot = ns["collect_mram_fault_evidence"](0, 1)

    assert evidence["exact"] is False
    assert "inexact" in evidence["capability_error"]
    assert snapshot is None
    assert raw_snapshot is None


def test_snapshot_reports_digest_closest_image_and_compact_ranges(tmp_path: Path) -> None:
    exec_image = tmp_path / "exec.bin"
    staging_image = tmp_path / "staging.bin"
    exec_image.write_bytes(bytes([0x11] * 16))
    staging_image.write_bytes(bytes([0x22] * 16))
    actual = bytearray([0x22] * 16)
    actual[8] = 0x00
    snapshot = actual + bytearray(16)
    ns = _runtime_functions(
        "_program_bytes_hex",
        "_compact_differing_byte_ranges",
        "analyze_fault_snapshot",
        globals_dict={
            "flash_geometry": lambda: (0x10000000, 32),
            "slot_ranges": {
                "exec": (0x10000000, 0x10000010),
                "staging": (0x10000010, 0x10000020),
            },
            "success_image_hash_slot": "exec",
            "image_exec_path": str(exec_image),
            "image_staging_path": str(staging_image),
            "image_tertiary_path": "",
            "image_recovery_path": "",
            "backend": {"data": SimpleNamespace(EraseFill=0)},
            "fmt_u32": lambda value: "0x{:08X}".format(value),
            "os": __import__("os"),
        },
    )

    analysis = ns["analyze_fault_snapshot"](snapshot, boot_slot="exec")

    assert analysis["sha256"] == hashlib.sha256(snapshot).hexdigest()
    closest = analysis["closest_declared_image"]
    assert closest["name"] == "staging"
    assert closest["exact"] is False
    assert closest["differing_bytes"] == 1
    assert closest["differing_ranges"][0]["offset"] == 8
    assert closest["differing_ranges"][0]["actual_hex"] == "00"
    assert closest["differing_ranges"][0]["expected_hex"] == "22"


def test_execution_failures_precede_content_identity_failures() -> None:
    ns = _runtime_functions("recovery_failure_outcome")

    assert ns["recovery_failure_outcome"](
        {"hardfault_observed": True, "stop_reason": "vtor_captured"}, True, True
    ) == "hard_fault"
    assert ns["recovery_failure_outcome"](
        {"hardfault_observed": False, "stop_reason": "no_progress_stall"}, True, True
    ) == "no_boot"
    assert ns["recovery_failure_outcome"](
        {"hardfault_observed": False, "stop_reason": "wall_timeout(10s)"}, True, True
    ) == "timeout"


def test_summary_retains_concise_evidence_and_snapshot_identity() -> None:
    snapshot = {
        "sha256": "ab" * 32,
        "closest_declared_image": {
            "name": "candidate",
            "differing_bytes": 2,
            "differing_ranges": [{"offset": 4, "size": 2}],
        },
    }
    result = {
        "is_control": False,
        "fault_at": 3,
        "fault_requested": 3,
        "fault_address": "0x10000030",
        "fault_injected": True,
        "boot_outcome": "hard_fault",
        "boot_slot": "exec",
        "fault_class": "unrecoverable",
        "mram_fault_evidence": {"exact": True, "program_width": 16},
        "fault_snapshot": snapshot,
        "signals": {"content_mismatch": True},
    }

    summary = summarize_runtime_sweep([result], expected_control_points=0)

    assert summary["exact_mram_evidence_points"] == 1
    assert summary["incomplete_mram_evidence_points"] == 0
    assert summary["fault_evidence"] == [
        {
            "fault_at": 3,
            "fault_address": "0x10000030",
            "boot_outcome": "hard_fault",
            "exact": True,
            "program_width": 16,
            "snapshot_sha256": "ab" * 32,
            "closest_declared_image": "candidate",
            "differing_bytes": 2,
            "differing_ranges": [{"offset": 4, "size": 2}],
        }
    ]
