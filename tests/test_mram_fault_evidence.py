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
) -> bytes:
    code = _translate_csharp_case_to_python(cases.get(mode, cases["default"]))
    ns = {
        "ProgramUnitSize": len(intended),
        "preProgram": bytearray(pre_program),
        "intended": bytearray(intended),
        "result": bytearray(intended),
        "EraseFill": erase_fill,
        "CloneBytes": lambda b: bytearray(b),
    }
    exec(code, ns, ns)
    return bytes(ns["result"])


def _run_nvmemory_case(
    cases: dict[str, str],
    mode: str,
    previous_word: bytes,
    new_word: bytes,
    erase_fill: int,
    *,
    enforce_word_semantics: bool,
) -> bytes:
    code = _translate_csharp_case_to_python(cases.get(mode, cases["default"]))
    initial_storage = (
        bytearray([erase_fill] * len(new_word))
        if enforce_word_semantics
        else bytearray(new_word)
    )

    def _program_word(word_start: int, merged: bytearray) -> None:
        initial_storage[word_start : word_start + len(merged)] = merged

    ns = {
        "WordSize": len(new_word),
        "wordStart": 0,
        "offset": 0,
        "data": bytearray(new_word),
        "previousWord": bytearray(previous_word),
        "intendedWord": bytearray(new_word),
        "mergedWord": bytearray(new_word),
        "storage": initial_storage,
        "EraseFill": erase_fill,
        "ProgramWord": _program_word,
    }
    exec(code, ns, ns)
    return bytes(ns["storage"])


def test_mram_torn_word_modes_across_trace_replay_and_csharp_peripherals() -> None:
    modes = ("half", "half_retain", "untouched", "erased", "programmed")
    pre_program = bytes.fromhex("10111213141516172021222324252627")
    intended = bytes.fromhex("a0a1a2a3a4a5a6a7b0b1b2b3b4b5b6b7")
    assert pre_program[8:] != intended[8:]

    # 1. Verify trace replay across all five modes with distinct old and new upper halves.
    replay_ns = _runtime_functions("_trace_replay_mram_torn_value")
    replay_fn = replay_ns["_trace_replay_mram_torn_value"]
    prev_u64 = int.from_bytes(pre_program[:4] + pre_program[8:12], "little")
    new_u64 = int.from_bytes(intended[:4] + intended[8:12], "little")
    expected_half_retain_u64 = int.from_bytes(
        intended[:4] + pre_program[8:12], "little"
    )
    assert replay_fn(new_u64, 8, 0xFF, "half", prev_u64) == (
        0xFFFFFFFF00000000 | int.from_bytes(intended[:4], "little")
    )
    assert (
        replay_fn(new_u64, 8, 0xFF, "half_retain", prev_u64)
        == expected_half_retain_u64
    )
    assert (
        replay_fn(new_u64, 8, 0x00, "half_retain", prev_u64)
        == expected_half_retain_u64
    )
    assert replay_fn(new_u64, 8, 0xFF, "untouched", prev_u64) == prev_u64
    assert replay_fn(new_u64, 8, 0xFF, "erased", prev_u64) == 0xFFFFFFFFFFFFFFFF
    assert replay_fn(new_u64, 8, 0xFF, "programmed", prev_u64) == new_u64

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
            '                   && normalized != "programmed")'
        ) in cs_text
        assert (
            '"MramTornWordMode must be half, half_retain, untouched, erased, or programmed"'
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

    for erase_fill in (0x00, 0xFF):
        expected_by_mode = {
            "half": intended[:8] + bytes([erase_fill] * 8),
            "half_retain": intended[:8] + pre_program[8:],
            "untouched": pre_program,
            "erased": bytes([erase_fill] * 16),
            "programmed": intended,
        }
        for mode in modes:
            expected_word = expected_by_mode[mode]
            assert (
                _run_mapped_mram_tracker_case(
                    tracker_cases, mode, pre_program, intended, erase_fill
                )
                == expected_word
            )
            assert (
                _run_nvmemory_case(
                    nvm_fast_cases,
                    mode,
                    pre_program,
                    intended,
                    erase_fill,
                    enforce_word_semantics=False,
                )
                == expected_word
            )
            assert (
                _run_nvmemory_case(
                    nvm_word_cases,
                    mode,
                    pre_program,
                    intended,
                    erase_fill,
                    enforce_word_semantics=True,
                )
                == expected_word
            )

    # 3. Verify every C# peripheral that exposes MramTornWordMode forwards or stores it.
    forwarding_peripherals = {
        "GenericNvmController.cs": "Nvm.MramTornWordMode = value;",
        "NVMemoryController.cs": "Nvm.MramTornWordMode = value;",
        "An521NvmInterceptor.cs": "tracker.MramTornWordMode = value;",
        "NRF52NVMC.cs": "tracker.MramTornWordMode = value;",
        "STM32F4FastFlash.cs": "tracker.MramTornWordMode = value;",
        "STM32F4FlashController.cs": "tracker.MramTornWordMode = value;",
        "STM32H7FastFlash.cs": "tracker.MramTornWordMode = value;",
        "STM32H7FlashController.cs": "tracker.MramTornWordMode = value;",
    }
    for filename, expected_forwarding in forwarding_peripherals.items():
        cs_source = (ROOT / "peripherals" / filename).read_text(encoding="utf-8")
        assert "public string MramTornWordMode" in cs_source
        assert expected_forwarding in cs_source

    # 4. Verify collect_mram_fault_evidence preserves the half_retain post-fault word.
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

    def run(mode, data):
        ns = {
            "backend": {"kind": "mram", "data": data, "backend_sysbus_name": "mram"},
            "mram_torn_word": mode,
        }
        exec(compile(ast.Module(body=funcs, type_ignores=[]), "rr", "exec"), ns)
        ns["_require_mram_torn_word_support"]()
        return data

    run("half", Bare())
    for mode in ("half_retain", "untouched", "erased", "programmed"):
        assert run(mode, Capable()).MramTornWordMode == mode
        try:
            run(mode, Bare())
        except Exception as exc:
            assert "MramTornWordMode" in str(exc)
        else:
            raise AssertionError(
                "a non-default mode on a peripheral without the property must fail"
            )

