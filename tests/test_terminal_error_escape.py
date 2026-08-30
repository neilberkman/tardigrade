"""Emitted-code discovery tests for terminal-error escape campaigns."""

from __future__ import annotations

import subprocess
import sys
import hashlib
from pathlib import Path

import pytest

pytest.importorskip("elftools")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from terminal_error_escape import (  # noqa: E402
    TerminalCallsite,
    TerminalDiscovery,
    TerminalErrorPathConfig,
    build_terminal_runtime_payload,
    discover_terminal_error_paths,
    evaluate_terminal_error_differential,
    parse_terminal_error_paths,
    terminal_observation_window_open,
    terminal_payload_identity,
)
from render_results_html import render_terminal_error_panel  # noqa: E402


def _fixture_elf(tmp_path: Path) -> Path:
    source = tmp_path / "terminal.s"
    obj = tmp_path / "terminal.o"
    elf = tmp_path / "terminal.elf"
    source.write_text(
        ".syntax unified\n"
        ".thumb\n"
        ".section .text.container,\"ax\"\n"
        ".thumb_func\n"
        "process_candidate:\n"
        " bl reject_request\n"
        " b reject_request\n"
        ".size process_candidate, .-process_candidate\n"
        ".thumb_func\n"
        "unrelated:\n"
        " bl reject_request\n"
        " bx lr\n"
        ".size unrelated, .-unrelated\n"
        ".thumb_func\n"
        "reject_request:\n"
        " bx lr\n"
        ".size reject_request, .-reject_request\n",
        encoding="utf-8",
    )
    subprocess.run(["arm-none-eabi-as", "-mcpu=cortex-m4", "-o", str(obj), str(source)], check=True)
    subprocess.run(["arm-none-eabi-ld", "-Ttext=0x10000000", "-o", str(elf), str(obj)], check=True)
    return elf


def test_direct_and_tail_calls_are_discovered(tmp_path: Path) -> None:
    elf = _fixture_elf(tmp_path)
    config = TerminalErrorPathConfig(
        "rejected_request",
        ("reject_request",),
        ("process_candidate",),
        ("commit_state",),
    )
    result = discover_terminal_error_paths(elf, [config])
    assert [candidate.call_kind for candidate in result.candidates] == ["direct_call", "tail_call"]
    assert [candidate.callsite_address for candidate in result.candidates] == [0x10000000, 0x10000004]


def test_unrelated_handler_call_is_not_selected(tmp_path: Path) -> None:
    elf = _fixture_elf(tmp_path)
    config = TerminalErrorPathConfig("reject", ("reject_request",), ("process_candidate",), ("commit_state",))
    result = discover_terminal_error_paths(elf, [config])
    assert all(candidate.containing_symbol == "process_candidate" for candidate in result.candidates)


def test_same_resolved_callsite_in_distinct_campaigns_fails_closed(
    tmp_path: Path,
) -> None:
    elf = _fixture_elf(tmp_path)
    configs = [
        TerminalErrorPathConfig(
            campaign,
            ("reject_request",),
            ("process_candidate",),
            ("reject_request",),
        )
        for campaign in ("reject-a", "reject-b")
    ]

    result = discover_terminal_error_paths(elf, configs)

    collisions = [
        item
        for item in result.infrastructure_errors
        if item.get("kind") == "ambiguous_callsite_campaign"
    ]
    assert len(collisions) == 4  # two shared callsites, once per campaign
    assert {item["campaign"] for item in collisions} == {"reject-a", "reject-b"}
    assert all(item["campaigns"] == ["reject-a", "reject-b"] for item in collisions)


def test_runtime_payload_keeps_forbidden_sink_wildcard_matches() -> None:
    config = TerminalErrorPathConfig(
        "reject",
        ("reject_*",),
        ("process_*",),
        ("commit_*",),
    )
    discovery = TerminalDiscovery(
        symbols={
            "process_candidate": [(0x1000, 0x1010)],
            "reject_request": [(0x2000, 0x2010)],
            "commit_state": [(0x3000, 0x3010)],
        }
    )

    payload = build_terminal_runtime_payload(discovery, [config])

    assert payload[0]["forbidden_sink_addresses"] == ["0x00003000"]


def test_missing_symbols_are_infrastructure_results() -> None:
    config = TerminalErrorPathConfig("reject", ("missing_handler",), ("missing_containing",), ("commit_state",))
    result = discover_terminal_error_paths("examples/vulnerable_ota/firmware.elf", [config])
    assert result.candidates == []
    assert {item["kind"] for item in result.infrastructure_errors} >= {"missing_symbol"}


def test_declaration_validation_rejects_non_terminal_control() -> None:
    with pytest.raises(ValueError, match="expected 'terminal'"):
        parse_terminal_error_paths([{
            "name": "reject",
            "handler_symbols": ["reject_request"],
            "containing_symbols": ["process_candidate"],
            "forbidden_sink_symbols": ["commit_state"],
            "expected_control": "success",
        }])


def _wide_tail_fixture_elf(tmp_path: Path) -> Path:
    source = tmp_path / "terminal_wide.s"
    obj = tmp_path / "terminal_wide.o"
    elf = tmp_path / "terminal_wide.elf"
    source.write_text(
        ".syntax unified\n"
        ".thumb\n"
        ".section .text.container,\"ax\"\n"
        ".thumb_func\n"
        "process_candidate:\n"
        " beq.w reject_request\n"
        " b.w reject_request\n"
        ".size process_candidate, .-process_candidate\n"
        ".thumb_func\n"
        "reject_request:\n"
        " bx lr\n"
        ".size reject_request, .-reject_request\n"
        ".thumb_func\n"
        "commit_state:\n"
        " bx lr\n"
        ".size commit_state, .-commit_state\n",
        encoding="utf-8",
    )
    subprocess.run(["arm-none-eabi-as", "-mcpu=cortex-m4", "-o", str(obj), str(source)], check=True)
    subprocess.run(["arm-none-eabi-ld", "-Ttext=0x10000000", "-o", str(elf), str(obj)], check=True)
    return elf


def test_wide_and_conditional_tail_calls_are_discovered(tmp_path: Path) -> None:
    elf = _wide_tail_fixture_elf(tmp_path)
    config = TerminalErrorPathConfig(
        "rejected_request",
        ("reject_request",),
        ("process_candidate",),
        ("commit_state",),
    )
    result = discover_terminal_error_paths(elf, [config])
    assert [candidate.call_kind for candidate in result.candidates] == ["tail_call", "tail_call"]
    assert [candidate.disassembly.split()[0] for candidate in result.candidates] == ["beq.w", "b.w"]


def _differential_fixture():
    candidate = TerminalCallsite(
        "reject", "process_candidate", "reject_request", 0x1000,
        b"\x00\xf0\x00\xf8", "bl #0x1004", "direct_call",
    )
    discovery = TerminalDiscovery(candidates=[candidate])
    identity = "a" * 64
    control = {
        "signals": {
            "terminal_error_snapshot_hash": identity,
            "terminal_error_artifact_hash": identity,
            "terminal_error_paths": {
                "reject": {"callsite_reached": True, "control_terminal": True},
            },
        },
    }
    return discovery, control, identity


def test_differential_requires_patch_application_and_matching_control(tmp_path: Path) -> None:
    discovery, control, identity = _differential_fixture()
    fault = {
        "fault_address": "0x1000",
        "fault_injected": True,
        "signals": {
            "terminal_error_snapshot_hash": identity,
            "terminal_error_artifact_hash": identity,
            "terminal_error_paths": {
                "reject": {"fault_applied": False, "forbidden_sink_reached": True},
            },
        },
    }
    assert evaluate_terminal_error_differential(discovery, control, [fault])["findings"] == []
    fault["signals"]["terminal_error_paths"]["reject"]["fault_applied"] = True
    assert len(evaluate_terminal_error_differential(discovery, control, [fault])["findings"]) == 1

    control["signals"]["terminal_error_paths"]["reject"]["control_terminal"] = False
    gated = evaluate_terminal_error_differential(discovery, control, [fault])
    assert gated["findings"] == []
    assert any(item["kind"] == "control_not_terminal" for item in gated["infrastructure_errors"])


def test_differential_rejects_identity_mismatch() -> None:
    discovery, control, identity = _differential_fixture()
    fault = {
        "fault_address": "0x1000",
        "fault_injected": True,
        "signals": {
            "terminal_error_snapshot_hash": "b" * 64,
            "terminal_error_artifact_hash": identity,
            "terminal_error_paths": {
                "reject": {"fault_applied": True, "forbidden_sink_reached": True},
            },
        },
    }
    result = evaluate_terminal_error_differential(discovery, control, [fault])
    assert result["findings"] == []
    assert any(item["kind"] == "terminal_identity_mismatch" for item in result["infrastructure_errors"])


def test_payload_identity_and_observation_window() -> None:
    payload = b"terminal payload"
    digest = hashlib.sha256(payload).hexdigest()
    assert terminal_payload_identity(payload, digest)
    assert not terminal_payload_identity(payload + b"!", digest)
    assert terminal_observation_window_open(10.0, 10.5, 1.0)
    assert not terminal_observation_window_open(10.0, 11.1, 1.0)


def test_terminal_campaign_overrides_profile_skip_count() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "audit_bootloader.py").read_text(
        encoding="utf-8"
    )
    block = source[source.index("terminal_robot_vars = ["):source.index(
        "terminal_error_results = run_runtime_sweep(",
        source.index("terminal_robot_vars = ["),
    )]
    assert '"INSTRUCTION_SKIP_COUNT:"' in block
    assert 'terminal_robot_vars.append("INSTRUCTION_SKIP_COUNT:1")' in block


def test_html_renders_dedicated_terminal_campaign_results() -> None:
    html = render_terminal_error_panel({
        "runtime_sweep_results": [],
        "terminal_error_results": [{
            "signals": {"terminal_error_paths": {
                "reject": {
                    "selected_callsite": "0x00001000",
                    "callsite_reached": True,
                    "control_terminal": False,
                    "first_forbidden_sink": "0x00002000",
                    "snapshot_identity_hash": "a" * 64,
                },
            }},
        }],
    })
    assert "terminal-error escape" in html
    assert "0x00002000" in html
