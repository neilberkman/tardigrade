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
            "operation_kind": "program",
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


def test_recovery_infrastructure_error_keeps_cut_evidence_outside_judged_counts() -> None:
    result = {
        "is_control": False,
        "fault_at": 4,
        "fault_requested": 4,
        "fault_address": "0x10000040",
        "fault_injected": True,
        "boot_outcome": "infra_error",
        "boot_slot": None,
        "fault_class": "infrastructure_error",
        "infrastructure_error": True,
        "error_kind": "runfor_exception",
        "error": "RunFor failed during recovery",
        "mram_fault_evidence": {"exact": True, "program_width": 16},
        "fault_snapshot": {"sha256": "cd" * 32},
        "signals": {},
    }

    summary = summarize_runtime_sweep(
        [result],
        expected_fault_points=1,
        expected_control_points=0,
        planned_fault_types=["w"],
    )

    assert summary["infrastructure_error_points"] == 1
    assert summary["total_fault_points"] == 0
    assert summary["issue_points"] == 0
    assert summary["point_counts"]["kinds"]["single_cut_program"][
        "infrastructure_error"
    ] == 1
    assert summary["fault_evidence"] == [
        {
            "fault_at": 4,
            "operation_kind": "program",
            "fault_address": "0x10000040",
            "boot_outcome": "infra_error",
            "exact": True,
            "program_width": 16,
            "snapshot_sha256": "cd" * 32,
        }
    ]


def test_mapped_mram_tracker_preserves_counters_across_firmware_reset_when_enabled() -> None:
    interface_cs = (ROOT / "peripherals" / "ITardigradeFaultInjectable.cs").read_text(
        encoding="utf-8"
    )
    tracker_cs = (ROOT / "peripherals" / "MappedMRAMTracker.cs").read_text(
        encoding="utf-8"
    )

    # The interface stays unchanged so third-party implementers keep compiling;
    # the runner probes for the property instead.
    assert "PreserveCountersAcrossReset" not in interface_cs
    assert "MramTornWordMode" not in interface_cs
    assert "public bool PreserveCountersAcrossReset { get; set; }" in tracker_cs
    assert "if(trackingStopHit || FaultEverFired)" in tracker_cs
    assert "else if(PreserveCountersAcrossReset)" in tracker_cs
    assert "if(trackingStarted)\n                {\n                    trackingStartAddress = 0;\n                }" in tracker_cs
    assert "ResetCampaignObservability();" in tracker_cs


def test_mapped_mram_tracker_suppresses_stores_after_power_loss() -> None:
    tracker_cs = (ROOT / "peripherals" / "MappedMRAMTracker.cs").read_text(
        encoding="utf-8"
    )

    assert "FaultEverFired && WriteFaultMode == 0" in tracker_cs
    assert "EraseFaultFired || writePowerLossLatched" in tracker_cs




def _extract_csharp_switch_blocks(source: str, header: str) -> list[str]:
    blocks: list[str] = []
    search_from = 0
    while True:
        idx = source.find(header, search_from)
        if idx < 0:
            break
        brace_start = source.index("{", idx)
        depth = 0
        for pos in range(brace_start, len(source)):
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(source[brace_start + 1 : pos])
                    search_from = pos + 1
                    break
        else:
            raise AssertionError("unterminated switch block in C# source")
    return blocks


def _parse_csharp_switch_cases(switch_body: str) -> dict[str, str]:
    import re

    pattern = re.compile(r'(?:case\s+"([^"]+)"|(default))\s*:')
    matches = list(pattern.finditer(switch_body))
    assert matches, "no switch cases found"
    cases: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group(1) if match.group(1) is not None else "default"
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(switch_body)
        body = switch_body[start:end]
        assert "break;" in body, f"switch case {key!r} missing break"
        cases[key] = body.split("break;", 1)[0]
    return cases


def _translate_csharp_case_to_python(case_body: str) -> str:
    import re

    cleaned_lines: list[str] = []
    for raw_line in case_body.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if line:
            cleaned_lines.append(line)
    text = " ".join(cleaned_lines)

    def _clean_expr(expr: str) -> str:
        expr = expr.strip()
        expr = re.sub(r"\b(\d+)L\b", r"\1", expr)
        expr = re.sub(r"\(int\)\s*", "", expr)
        expr = re.sub(r"\(long\)\s*", "", expr)
        expr = expr.replace("data.Length", "len(data)")
        expr = expr.replace("&&", "and")
        expr = expr.replace("/", "//")
        return expr

    py_lines: list[str] = []
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        for_match = re.match(
            r"for\(\s*var\s+(\w+)\s*=\s*([^;]+);\s*\1\s*<\s*([^;]+);\s*\1\+\+\s*\)\s*\{",
            text[pos:],
        )
        if for_match:
            var_name = for_match.group(1)
            start_expr = _clean_expr(for_match.group(2))
            end_expr = _clean_expr(for_match.group(3))
            brace_open = pos + for_match.end() - 1
            depth = 0
            for scan in range(brace_open, len(text)):
                if text[scan] == "{":
                    depth += 1
                elif text[scan] == "}":
                    depth -= 1
                    if depth == 0:
                        inner = text[brace_open + 1 : scan]
                        pos = scan + 1
                        break
            else:
                raise AssertionError("unterminated for loop in C# case")
            py_lines.append(f"for {var_name} in range(int({start_expr}), int({end_expr})):")
            inner_py = _translate_csharp_case_to_python(inner)
            for inner_line in inner_py.splitlines():
                py_lines.append("    " + inner_line)
            continue

        if_match = re.match(r"if\(([^)]+)\)\s*\{", text[pos:])
        if if_match:
            cond_expr = _clean_expr(if_match.group(1))
            brace_open = pos + if_match.end() - 1
            depth = 0
            for scan in range(brace_open, len(text)):
                if text[scan] == "{":
                    depth += 1
                elif text[scan] == "}":
                    depth -= 1
                    if depth == 0:
                        inner = text[brace_open + 1 : scan]
                        pos = scan + 1
                        break
            else:
                raise AssertionError("unterminated if block in C# case")
            py_lines.append(f"if {cond_expr}:")
            inner_py = _translate_csharp_case_to_python(inner)
            for inner_line in inner_py.splitlines():
                py_lines.append("    " + inner_line)
            continue

        semi = text.find(";", pos)
        assert semi >= 0, f"unterminated C# statement in {text[pos:]!r}"
        stmt = text[pos:semi].strip()
        pos = semi + 1
        if not stmt:
            continue
        if stmt.startswith("var "):
            stmt = stmt[4:].strip()
        if "=" in stmt:
            lhs, rhs = stmt.split("=", 1)
            py_lines.append(f"{_clean_expr(lhs)} = {_clean_expr(rhs)}")
        else:
            py_lines.append(_clean_expr(stmt))

    return "\n".join(py_lines) if py_lines else "pass"


def _run_mapped_mram_tracker_case(
    cases: dict[str, str],
    mode: str,
    pre_program: bytes,
    intended: bytes,
    erase_fill: int,
    *,
    write_index: int = 1,
    unit_offset: int = 0,
    seed: int = 0,
) -> tuple[bytes, list[int]]:
    code = _translate_csharp_case_to_python(cases.get(mode, cases["default"]))
    marked: list[int] = []
    corrupt_ns = _runtime_functions("_corrupt_mram_torn_bytes")

    def _apply_corrupted(buf: bytearray, wi: int, off: int, seed_val: int) -> None:
        buf[:] = corrupt_ns["_corrupt_mram_torn_bytes"](
            bytes(buf), wi, off, seed_val
        )

    ns = {
        "ProgramUnitSize": len(intended),
        "preProgram": bytearray(pre_program),
        "intended": bytearray(intended),
        "result": bytearray(intended),
        "EraseFill": erase_fill,
        "CloneBytes": lambda b: bytearray(b),
        "unitOffset": unit_offset,
        "TotalWordWrites": write_index,
        "MarkWordUncorrectableInternal": lambda off: marked.append(int(off)),
        "EffectiveMramTornWordSeed": lambda: seed,
        "ApplyCorruptedTornWord": _apply_corrupted,
    }
    exec(code, ns, ns)
    return bytes(ns["result"]), marked


def _run_nvmemory_case(
    cases: dict[str, str],
    mode: str,
    previous_word: bytes,
    new_word: bytes,
    erase_fill: int,
    *,
    enforce_word_semantics: bool,
    write_index: int = 1,
    word_start: int = 0,
    seed: int = 0,
) -> tuple[bytes, list[int]]:
    code = _translate_csharp_case_to_python(cases.get(mode, cases["default"]))
    initial_storage = (
        bytearray([erase_fill] * len(new_word))
        if enforce_word_semantics
        else bytearray(new_word)
    )
    marked: list[int] = []
    corrupt_ns = _runtime_functions("_corrupt_mram_torn_bytes")

    def _program_word(ws: int, merged: bytearray) -> None:
        initial_storage[ws : ws + len(merged)] = merged

    def _apply_corrupted_at(ws: int, intended_buf: bytearray, wi: int) -> None:
        initial_storage[ws : ws + len(intended_buf)] = corrupt_ns[
            "_corrupt_mram_torn_bytes"
        ](bytes(intended_buf), wi, ws, seed)

    ns = {
        "WordSize": len(new_word),
        "wordStart": word_start,
        "offset": word_start,
        "data": bytearray(new_word),
        "previousWord": bytearray(previous_word),
        "intendedWord": bytearray(new_word),
        "mergedWord": bytearray(new_word),
        "currentWriteIndex": write_index,
        "storage": initial_storage,
        "EraseFill": erase_fill,
        "ProgramWord": _program_word,
        "MarkWordUncorrectableInternal": lambda off: marked.append(int(off)),
        "ClearUncorrectableWordInternal": lambda off: marked.remove(int(off))
        if int(off) in marked
        else None,
        "ApplyCorruptedWordAt": _apply_corrupted_at,
        "lastFaultMarkedUncorrectable": False,
        "true": True,
        "false": False,
    }
    exec(code, ns, ns)
    return bytes(ns["storage"]), marked


def test_mram_torn_word_modes_across_trace_replay_and_csharp_peripherals() -> None:
    modes = (
        "half",
        "half_retain",
        "untouched",
        "erased",
        "programmed",
        "uncorrectable",
        "corrupted",
    )
    pre_program = bytes.fromhex("10111213141516172021222324252627")
    intended = bytes.fromhex("a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7")
    assert pre_program[8:] != intended[8:]
    test_seed = 0x12345678

    # 1. Verify trace replay across all seven modes with distinct old and new upper halves.
    replay_ns = _runtime_functions(
        "_corrupt_mram_torn_bytes", "_trace_replay_mram_torn_value"
    )
    replay_fn = replay_ns["_trace_replay_mram_torn_value"]
    corrupt_bytes_fn = replay_ns["_corrupt_mram_torn_bytes"]
    prev_u128 = int.from_bytes(pre_program, "little")
    new_u128 = int.from_bytes(intended, "little")
    expected_half_retain_u128 = int.from_bytes(
        intended[:8] + pre_program[8:], "little"
    )
    assert replay_fn(new_u128, 16, 0xFF, "half", prev_u128) == int.from_bytes(
        intended[:8] + b"\xFF" * 8, "little"
    )
    assert (
        replay_fn(new_u128, 16, 0xFF, "half_retain", prev_u128)
        == expected_half_retain_u128
    )
    assert (
        replay_fn(new_u128, 16, 0x00, "half_retain", prev_u128)
        == expected_half_retain_u128
    )
    assert replay_fn(new_u128, 16, 0xFF, "untouched", prev_u128) == prev_u128
    assert replay_fn(new_u128, 16, 0xFF, "uncorrectable", prev_u128) == prev_u128
    assert replay_fn(new_u128, 16, 0xFF, "erased", prev_u128) == int.from_bytes(
        b"\xFF" * 16, "little"
    )
    assert replay_fn(new_u128, 16, 0xFF, "programmed", prev_u128) == new_u128
    corrupted_u128 = replay_fn(
        new_u128, 16, 0xFF, "corrupted", prev_u128,
        seed=test_seed, write_index=1, offset=0
    )
    assert 3 <= bin(corrupted_u128 ^ new_u128).count("1") <= 5
    assert corrupted_u128 == int.from_bytes(
        corrupt_bytes_fn(new_u128.to_bytes(16, "little"), 1, 0, test_seed),
        "little",
    )

    # 2. Verify MappedMRAMTracker.cs and NVMemoryController.cs word images for all modes.
    tracker_cs = (ROOT / "peripherals" / "MappedMRAMTracker.cs").read_text(
        encoding="utf-8"
    )
    nvm_cs = (ROOT / "peripherals" / "NVMemoryController.cs").read_text(
        encoding="utf-8"
    )
    for cs_text in (tracker_cs, nvm_cs):
        assert (
            'if(normalized != "half" && normalized != "half_retain"\n'
            '                   && normalized != "untouched" && normalized != "erased"\n'
            '                   && normalized != "programmed" && normalized != "uncorrectable"\n'
            '                   && normalized != "corrupted")'
        ) in cs_text
        assert (
            '"MramTornWordMode must be half, half_retain, untouched, erased, programmed, uncorrectable, or corrupted"'
            in cs_text
        )

    tracker_switches = _extract_csharp_switch_blocks(
        tracker_cs, "switch(mramTornWordMode)"
    )
    assert len(tracker_switches) == 1
    tracker_cases = _parse_csharp_switch_cases(tracker_switches[0])

    nvm_switches = _extract_csharp_switch_blocks(nvm_cs, "switch(mramTornWordMode)")
    assert len(nvm_switches) == 2
    nvm_fast_cases = _parse_csharp_switch_cases(nvm_switches[0])
    nvm_word_cases = _parse_csharp_switch_cases(nvm_switches[1])

    expected_corrupted = corrupt_bytes_fn(intended, 1, 0, test_seed)
    assert 3 <= sum(bin(a ^ b).count("1") for a, b in zip(intended, expected_corrupted)) <= 5

    for erase_fill in (0x00, 0xFF):
        expected_by_mode = {
            "half": intended[:8] + bytes([erase_fill] * 8),
            "half_retain": intended[:8] + pre_program[8:],
            "untouched": pre_program,
            "erased": bytes([erase_fill] * 16),
            "programmed": intended,
            "uncorrectable": pre_program,
            "corrupted": expected_corrupted,
        }
        for mode in modes:
            expected_word = expected_by_mode[mode]
            expected_marked = [0] if mode == "uncorrectable" else []
            t_word, t_marked = _run_mapped_mram_tracker_case(
                tracker_cases, mode, pre_program, intended, erase_fill, seed=test_seed
            )
            assert t_word == expected_word
            assert t_marked == expected_marked

            nf_word, nf_marked = _run_nvmemory_case(
                nvm_fast_cases,
                mode,
                pre_program,
                intended,
                erase_fill,
                enforce_word_semantics=False,
                seed=test_seed,
            )
            assert nf_word == expected_word
            assert nf_marked == expected_marked

            nw_word, nw_marked = _run_nvmemory_case(
                nvm_word_cases,
                mode,
                pre_program,
                intended,
                erase_fill,
                enforce_word_semantics=True,
                seed=test_seed,
            )
            assert nw_word == expected_word
            assert nw_marked == expected_marked

    # 3. Verify every C# peripheral that exposes MramTornWordMode forwards or stores it.
    forwarding_peripherals = {
        "GenericNvmController.cs": "Nvm.MramTornWordMode = value;",
        "NVMemoryController.cs": "Nvm.MramTornWordMode = value;",
        "An521NvmInterceptor.cs": "tracker.MramTornWordMode = value;",
        "NRF52NVMC.cs": "tracker.MramTornWordMode = value;",
        "STM32F1FlashController.cs": "tracker.MramTornWordMode = value;",
        "STM32F4FastFlash.cs": "tracker.MramTornWordMode = value;",
        "STM32F4FlashController.cs": "tracker.MramTornWordMode = value;",
        "STM32H7FastFlash.cs": "tracker.MramTornWordMode = value;",
        "STM32H7FlashController.cs": "tracker.MramTornWordMode = value;",
        "STM32L4FlashController.cs": "tracker.MramTornWordMode = value;",
    }
    for filename, expected_forwarding in forwarding_peripherals.items():
        cs_source = (ROOT / "peripherals" / filename).read_text(encoding="utf-8")
        assert "public string MramTornWordMode" in cs_source
        assert expected_forwarding in cs_source

    # 4. Verify collect_mram_fault_evidence preserves the half_retain post-fault word
    #    and records word_marked_uncorrectable when set by the backend.
    post_half_retain = intended[:8] + pre_program[8:]
    snapshot = post_half_retain + bytes(48)
    trace = "1:0:16:{}:{}:{}:1\n".format(
        intended.hex(), pre_program.hex(), post_half_retain.hex()
    )
    data = SimpleNamespace(
        FaultEvidenceExact=True,
        LastFaultWriteIndex=1,
        LastFaultProgramAddress=0x10000000,
        LastFaultOffset=0,
        LastFaultProgramWidth=16,
        LastFaultIntendedBytes=intended,
        LastFaultPreProgramBytes=pre_program,
        LastFaultPostFaultBytes=post_half_retain,
        LastFaultMarkedUncorrectable=True,
        FaultMemorySnapshot=snapshot,
        ProgramTraceCount=1,
        ProgramTraceToString=lambda: trace,
        Size=64,
    )
    ns = _runtime_functions(
        "_decode_exact_program_bytes",
        "_program_bytes_hex",
        "parse_mram_program_trace",
        "collect_mram_fault_evidence",
        globals_dict={
            "backend": {"data": data, "bus_base": 0x10000000},
            "fmt_u32": lambda value: "0x{:08X}".format(value),
            "to_py_bytes": lambda value: (
                bytearray(value) if value is not None else None
            ),
        },
    )
    evidence, observed_snapshot, _ = ns["collect_mram_fault_evidence"](0, 1)
    assert evidence["exact"] is True
    assert evidence["pre_program_bytes"] == pre_program.hex()
    assert evidence["intended_bytes"] == intended.hex()
    assert evidence["post_fault_bytes"] == post_half_retain.hex()
    assert evidence["word_marked_uncorrectable"] is True
    assert evidence["uncorrectable_word_address"] == "0x10000000"
    assert bytes(observed_snapshot[:16]) == post_half_retain


def test_live_power_loss_refuses_a_torn_word_mode_the_mram_peripheral_ignores() -> None:
    source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    import ast

    tree = ast.parse(source)
    wanted = {"_apply_mram_torn_word_mode", "_require_mram_torn_word_support"}
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    assert {f.name for f in funcs} == wanted

    class Bare:
        pass

    class Capable:
        MramTornWordMode = "half"

    class UncorrectableCapable(Capable):
        UncorrectableReadCount = 0

        def MarkWordUncorrectable(self, _offset):
            pass

        def ClearUncorrectableWords(self):
            pass

        def ClearUncorrectableReadLog(self):
            pass

        def UncorrectableWordsToString(self):
            return ""

        def UncorrectableReadsToString(self):
            return ""

    def run(mode, data):
        ns = {
            "backend": {"kind": "mram", "data": data, "backend_sysbus_name": "mram"},
            "mram_torn_word": mode,
        }
        exec(compile(ast.Module(body=funcs, type_ignores=[]), "rr", "exec"), ns)
        ns["_require_mram_torn_word_support"]()
        return data

    run("half", Bare())
    for mode in ("half_retain", "untouched", "erased", "programmed", "corrupted"):
        assert run(mode, Capable()).MramTornWordMode == mode
        try:
            run(mode, Bare())
        except Exception as exc:
            assert "MramTornWordMode" in str(exc)
        else:
            raise AssertionError(
                "a non-default mode on a peripheral without the property must fail"
            )

    # uncorrectable additionally requires uncorrectable-word tracking methods.
    assert run("uncorrectable", UncorrectableCapable()).MramTornWordMode == "uncorrectable"
    try:
        run("uncorrectable", Capable())
    except Exception as exc:
        assert "uncorrectable" in str(exc)
    else:
        raise AssertionError(
            "uncorrectable mode must fail when peripheral lacks uncorrectable tracking"
        )


def test_uncorrectable_read_observation_and_sweep_summary_distinguish_handled_vs_faulted() -> None:
    def _make_obs(boot_outcome, exec_ev, p2_status, remaining_text):
        data = SimpleNamespace(
            UncorrectableReadCount=1,
            LastUncorrectableReadWordAddress=0x10100200,
            MarkWordUncorrectable=lambda _o: None,
            UncorrectableReadsToString=lambda: "1:512:0x10100200:0x10100200:4:0x10000090\n",
            UncorrectableWordsToString=lambda: remaining_text,
        )
        ns = _runtime_functions(
            "_mram_uncorrectable_target",
            "_parse_uncorrectable_words_table",
            "_parse_uncorrectable_reads_table",
            "_snapshot_mram_uncorrectable_addresses",
            "collect_uncorrectable_read_observation",
            globals_dict={
                "backend": {"data": data, "bus_base": 0x10100000},
                "fmt_u32": lambda value: "0x{:08X}".format(value),
            },
        )
        return ns["collect_uncorrectable_read_observation"](
            boot_outcome,
            execution_evidence=exec_ev,
            p2_status=p2_status,
            marked_at_fault=["0x10100200"],
        )

    handled_obs = _make_obs(
        "success", {"hardfault_observed": False, "ipsr": 0}, {"reason": "vtor_captured"}, ""
    )
    assert handled_obs["read_observed"] is True
    assert handled_obs["word_address"] == "0x10100200"
    assert handled_obs["outcome"] == "recovered"
    assert handled_obs["handled"] is True
    assert handled_obs["cleared_by_recovery"] is True

    faulted_obs = _make_obs(
        "hard_fault",
        {"hardfault_observed": True, "fault_exception_active": True, "ipsr": 3},
        {"reason": "no_boot_stall(0.10s_emulated)"},
        "512:0x10100200\n",
    )
    assert faulted_obs["outcome"] == "faulted"
    assert faulted_obs["handled"] is False
    assert faulted_obs["cleared_by_recovery"] is False

    stalled_obs = _make_obs(
        "no_boot",
        {"hardfault_observed": False, "fault_exception_active": False, "ipsr": 0},
        {"reason": "no_boot_stall(0.10s_emulated)"},
        "512:0x10100200\n",
    )
    assert stalled_obs["outcome"] == "stalled"
    assert stalled_obs["handled"] is False

    summary = summarize_runtime_sweep(
        [
            {
                "is_control": False,
                "fault_at": 0,
                "fault_requested": 0,
                "fault_address": "0x10100200",
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_class": "recoverable",
                "mram_fault_evidence": {
                    "exact": True,
                    "program_width": 8,
                    "word_marked_uncorrectable": True,
                    "uncorrectable_word_address": "0x10100200",
                },
                "signals": {
                    "uncorrectable_words_at_fault": ["0x10100200"],
                    "uncorrectable_read": handled_obs,
                },
            },
            {
                "is_control": False,
                "fault_at": 1,
                "fault_requested": 1,
                "fault_address": "0x10100208",
                "fault_injected": True,
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "mram_fault_evidence": {
                    "exact": True,
                    "program_width": 8,
                    "word_marked_uncorrectable": True,
                    "uncorrectable_word_address": "0x10100208",
                },
                "signals": {
                    "uncorrectable_words_at_fault": ["0x10100208"],
                    "uncorrectable_read": faulted_obs,
                },
            },
            {
                "is_control": False,
                "fault_at": 2,
                "fault_requested": 2,
                "fault_address": "0x10100210",
                "fault_injected": True,
                "boot_outcome": "no_boot",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "signals": {
                    "uncorrectable_words_at_fault": ["0x10100210"],
                    "uncorrectable_read": stalled_obs,
                },
            },
        ],
        expected_control_points=0,
    )
    uncorr_summary = summary["mram_uncorrectable_reads"]
    assert uncorr_summary["marked_points"] == 3
    assert uncorr_summary["read_points"] == 3
    assert uncorr_summary["handled_points"] == 1
    assert uncorr_summary["faulted_points"] == 1
    assert uncorr_summary["stalled_points"] == 1
    assert len(uncorr_summary["observations"]) == 3


def test_uncorrectable_followup_boot_cycle_records_read_observation() -> None:
    """Follow-up cycles in uncorrectable mode must not crash when marked words survive cycle 0."""
    bus_base = 0x10100000
    marked_offset = 0x200
    marked_addr = "0x{:08X}".format(bus_base + marked_offset)

    class FakeMram:
        Size = 0x1000

        def __init__(self) -> None:
            self.storage = bytearray(self.Size)
            self.marked_offsets = {marked_offset}
            self.reads = [
                (1, marked_offset, bus_base + marked_offset, bus_base + marked_offset, 4, 0x10000090)
            ]

        @property
        def UncorrectableReadCount(self) -> int:
            return len(self.reads)

        @property
        def LastUncorrectableReadWordAddress(self) -> int:
            return self.reads[-1][2] if self.reads else 0

        def ReadBytes(self, offset: int, size: int) -> bytes:
            return bytes(self.storage[offset : offset + size])

        def WriteBytes(self, offset: int, data: bytes, src_offset: int, count: int) -> None:
            self.storage[offset : offset + count] = data[src_offset : src_offset + count]
            self.marked_offsets.clear()

        def MarkWordUncorrectable(self, offset: int) -> None:
            self.marked_offsets.add(int(offset))

        def ClearUncorrectableWords(self) -> None:
            self.marked_offsets.clear()
            self.reads.clear()

        def ClearUncorrectableReadLog(self) -> None:
            self.reads.clear()

        def UncorrectableWordsToString(self) -> str:
            return "".join(
                "{}:0x{:08X}\n".format(off, bus_base + off)
                for off in sorted(self.marked_offsets)
            )

        def UncorrectableReadsToString(self) -> str:
            return "".join(
                "{}:{}:0x{:08X}:0x{:08X}:{}:0x{:08X}\n".format(*row)
                for row in self.reads
            )

    def _run_scenario(
        *,
        clear_on_cycle1: bool,
        cycle1_outcome: str,
        cycle1_exec_ev: dict,
        cycle1_reason: str,
    ):
        mram = FakeMram()
        followup_calls = []

        def _restore_flash_and_boot(saved_flash: bytes) -> None:
            mram.WriteBytes(0, saved_flash, 0, len(saved_flash))

        def _reset_nvmc_for_recovery() -> None:
            ns["_clear_mram_uncorrectable_read_log"]()

        def _run_until_done(_cpu_ref, **kwargs):
            # Cycle 0's read log must be cleared while the surviving marked word remains marked.
            assert mram.marked_offsets == {marked_offset}
            assert mram.UncorrectableReadCount == 0
            followup_calls.append(kwargs.get("label"))
            mram.reads.append(
                (
                    1,
                    marked_offset,
                    bus_base + marked_offset,
                    bus_base + marked_offset + 4,
                    4,
                    0x10000094,
                )
            )
            if clear_on_cycle1:
                mram.marked_offsets.clear()
            return {
                "reason": cycle1_reason,
                "emulated_s": 0.1,
                "elapsed_s": 0.05,
                "iters": 2,
            }

        ns = _runtime_functions(
            "_mram_uncorrectable_target",
            "_parse_uncorrectable_words_table",
            "_parse_uncorrectable_reads_table",
            "_snapshot_mram_uncorrectable_offsets",
            "_snapshot_mram_uncorrectable_addresses",
            "_restore_mram_uncorrectable_offsets",
            "_clear_mram_uncorrectable_read_log",
            "collect_uncorrectable_read_observation",
            "_attach_uncorrectable_read_signals",
            "build_cycle_record",
            "_boot_followup_cycle",
            "_continue_followup_boot_cycles",
            "run_followup_boot_cycles",
            globals_dict={
                "backend": {"kind": "mram", "data": mram, "bus_base": bus_base},
                "mram_torn_word": "uncorrectable",
                "boot_cycles": 2,
                "phase2_wall_timeout_s": 5.0,
                "phase2_time_slice": "0.05",
                "_hash_bypass_active": False,
                "apply_hash_bypass": lambda: None,
                "run_boot_cycle_hook": lambda _idx, _records: None,
                "restore_flash_and_boot": _restore_flash_and_boot,
                "reset_nvmc_for_recovery": _reset_nvmc_for_recovery,
                "arm_vtor_watchpoint": lambda: None,
                "disarm_vtor_watchpoint": lambda: None,
                "run_until_done": _run_until_done,
                "monitor": SimpleNamespace(
                    Machine={
                        "sysbus.cpu": SimpleNamespace(
                            GetRegisterUnsafe=lambda _reg: 0x10000060
                        )
                    }
                ),
                "bus": SimpleNamespace(ReadDoubleWord=lambda _addr: 0x10000000),
                "as_int": int,
                "fmt_u32": lambda value: "0x{:08X}".format(value),
                "evaluate_boot_outcome": lambda *_args, **_kwargs: (
                    cycle1_outcome,
                    "exec" if cycle1_outcome == "success" else None,
                    {"recovery_execution": dict(cycle1_exec_ev)},
                ),
                "collect_semantic_state": lambda _ctx: None,
                "analyze_boot_cycles": lambda records: {
                    "requested_cycles": 2,
                    "completed_cycles": len(records),
                },
                "_time": SimpleNamespace(time=lambda: 0.0),
            },
        )
        cycle_records, analysis, _ms = ns["run_followup_boot_cycles"](
            "hard_fault",
            None,
            {"uncorrectable_words_at_fault": [marked_addr]},
            initial_status={"reason": "no_boot_stall(0.10s_emulated)"},
            fault_injected=True,
            label="fp0_followup",
        )
        return cycle_records, analysis, followup_calls

    # 1. Surviving marked word read again on cycle 1 and still faulted/unhandled.
    records, analysis, labels = _run_scenario(
        clear_on_cycle1=False,
        cycle1_outcome="hard_fault",
        cycle1_exec_ev={
            "hardfault_observed": True,
            "fault_exception_active": True,
            "ipsr": 3,
        },
        cycle1_reason="no_boot_stall(0.10s_emulated)",
    )
    assert labels == ["fp0_followup_1"]
    assert analysis["completed_cycles"] == 2
    assert len(records) == 2
    c1 = records[1]
    assert c1["cycle"] == 1
    assert c1["boot_outcome"] == "hard_fault"
    c1_sig = c1["signals"]
    assert c1_sig["followup_cycle"] == 1
    assert c1_sig["mram_torn_word_mode"] == "uncorrectable"
    assert c1_sig["uncorrectable_words_at_fault"] == [marked_addr]
    assert c1_sig["uncorrectable_words_remaining"] == [marked_addr]
    obs = c1_sig["uncorrectable_read"]
    assert obs["read_observed"] is True
    assert obs["read_count"] == 1
    assert obs["word_address"] == marked_addr
    assert obs["word_addresses"] == [marked_addr]
    assert obs["reads"] == [
        {
            "word_address": marked_addr,
            "access_address": "0x{:08X}".format(bus_base + marked_offset + 4),
            "width": 4,
            "pc": "0x10000094",
        }
    ]
    assert obs["outcome"] == "faulted"
    assert obs["handled"] is False
    assert obs["cleared_by_recovery"] is False
    assert obs["remaining_marked_words"] == [marked_addr]
    assert obs["active_exception"] == 3

    # 2. Surviving marked word read on cycle 1 and cleared during recovery.
    rec_records, _rec_analysis, _rec_labels = _run_scenario(
        clear_on_cycle1=True,
        cycle1_outcome="success",
        cycle1_exec_ev={"hardfault_observed": False, "ipsr": 0},
        cycle1_reason="vtor_captured",
    )
    rec_sig = rec_records[1]["signals"]
    assert rec_sig["uncorrectable_words_at_fault"] == [marked_addr]
    assert rec_sig["uncorrectable_words_remaining"] == []
    rec_obs = rec_sig["uncorrectable_read"]
    assert rec_obs["read_observed"] is True
    assert rec_obs["outcome"] == "recovered"
    assert rec_obs["handled"] is True
    assert rec_obs["cleared_by_recovery"] is True
    assert rec_obs["remaining_marked_words"] == []

    # 3. Follow-up stop status is forwarded so stall reasons classify as stalled.
    stall_records, _stall_analysis, _stall_labels = _run_scenario(
        clear_on_cycle1=False,
        cycle1_outcome="wrong_slot",
        cycle1_exec_ev={"hardfault_observed": False, "ipsr": 0},
        cycle1_reason="no_progress_stall(0.10s_emulated)",
    )
    stall_obs = stall_records[1]["signals"]["uncorrectable_read"]
    assert stall_obs["read_observed"] is True
    assert stall_obs["outcome"] == "stalled"
    assert stall_obs["handled"] is False
    assert stall_obs["cleared_by_recovery"] is False


def test_attach_uncorrectable_read_signals_call_sites_match_signature() -> None:
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    attach_def = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_attach_uncorrectable_read_signals"
    )
    allowed_kwargs = {arg.arg for arg in attach_def.args.args}
    attach_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_attach_uncorrectable_read_signals"
    ]
    assert len(attach_calls) == 8
    for call in attach_calls:
        kw_names = [kw.arg for kw in call.keywords if kw.arg is not None]
        assert set(kw_names) <= allowed_kwargs
        assert "marked_at_fault" in kw_names
        assert "marked_offsets" not in kw_names


