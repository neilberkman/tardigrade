#!/usr/bin/env python3
"""Each multi-fault stage runs as the fault type it names."""

from __future__ import annotations

import ast
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_classification import _interesting_multi_fault_points  # noqa: E402
from fault_inject import (  # noqa: E402
    AnnotatedSequence,
    MultiFaultPlan,
    assign_multi_fault_stage_types,
    decode_multi_fault_sequence,
    decode_multi_fault_stage_types,
    encode_multi_fault_sequence,
)
from fault_types import (  # noqa: E402
    FAULT_TYPE_NAME_TO_CODE,
    MULTI_FAULT_STAGE_FAULT_TYPES,
    multi_fault_stage_code,
)
from profile_loader import load_profile  # noqa: E402
from renode_runner import _fault_type_semantically_matches  # noqa: E402
from sweep import run_multi_fault_phase  # noqa: E402

MOVE_MF_SELFTEST = (
    ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade_multifault_selftest.yaml"
)

SUPPORTED_CODES = sorted(
    FAULT_TYPE_NAME_TO_CODE[name] for name in MULTI_FAULT_STAGE_FAULT_TYPES
)
WRITE_CODES = ("w", "b", "s", "g", "x", "d", "l", "r")
ERASE_CODES = ("e", "a")

_RUNTIME_NAMES = {
    "_FAULT_CODE_TO_NAME",
    "_WRITE_FAULT_MODE",
    "_MF_STAGE_WRITE_CODES",
    "_MF_STAGE_ERASE_CODES",
    "_MF_STAGE_CODES",
    "_MF_STAGE_HALTING_CODES",
    "_base_fault_type_code",
    "_fault_uses_rc_injection_return_hook",
    "_multi_fault_stage_unsupported_reason",
    "_multi_fault_stage_state",
    "_multi_fault_stage_error",
    "_arm_multi_fault_stage",
    "_multi_fault_stage_fired",
    "run_multi_fault_sequence",
    "decode_multi_fault_stages_local",
    "_mram_torn_word_for_point",
    "_select_point_mram_torn_word",
    "_record_point_mram_torn_word",
}


def _runtime_nodes():
    tree = ast.parse((SCRIPTS / "run_runtime_fault_sweep.py").read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _RUNTIME_NAMES:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in _RUNTIME_NAMES for t in node.targets
        ):
            nodes.append(node)
    return nodes


class _Bytes:
    def __init__(self, size: int) -> None:
        self.Size = size
        self.FlashSize = size

    def ReadBytes(self, offset: int, count: int) -> bytes:
        return bytes(count)


class _FakeRuntime:
    """Minimal Renode stand-in that records how each stage was armed."""

    def __init__(self, kind: str = "mram", read_supported: bool = True,
                 read_arm_skip=None) -> None:
        self.calls = []
        self.fired = {"write": False, "erase": False}
        data = _Bytes(64)
        data.FaultFlashSnapshot = None
        data.Flash = data
        data.ReadFaultEnabled = False
        data.ReadFaultFired = False
        data.Nvm = data
        self.data = data
        self.ns = {
            "backend": {"kind": kind, "data": data},
            "monitor": mock.Mock(
                Machine={"sysbus.cpu": mock.Mock(GetRegisterUnsafe=lambda reg: 0)}
            ),
            "bus": mock.Mock(ReadDoubleWord=lambda addr: 0),
            "_time": time,
            "_hash_bypass_active": False,
            "max_writes_cap": 10_000,
            "phase2_time_slice": "0.1",
            "phase2_wall_timeout_s": 5,
            "log": lambda msg: None,
            "as_int": int,
            "phase1_wall_timeout": lambda default_s: default_s,
            "restore_phase1_baseline": lambda: None,
            "restore_flash_and_boot": lambda flash: None,
            "apply_hash_bypass": lambda: None,
            "reset_nvmc_for_sweep": self._reset,
            "reset_nvmc_for_recovery": lambda: None,
            "get_total_writes": lambda: 40,
            "get_total_erases": lambda: 4,
            "arm_fault": self._arm_fault,
            "arm_erase_fault": self._arm_erase_fault,
            "_arm_read_bit_flip": self._arm_read,
            "disarm_fault": lambda: None,
            "disarm_write_fault": lambda: None,
            "disarm_erase_fault": lambda: None,
            "arm_vtor_watchpoint": lambda: None,
            "disarm_vtor_watchpoint": lambda: None,
            "run_until_done": self._run_until_done,
            "was_write_fault_injected": lambda: self.fired["write"],
            "was_fault_injected": lambda: self.fired["write"] or self.fired["erase"],
            "ensure_read_fault_preflight": lambda: {
                "supported": read_supported,
                "reason": "" if read_supported else "fast_path_no_read_intercept",
            },
            "ensure_rc_injection_preflight": lambda: {"supported": True, "reason": ""},
            "reset_rc_injection_state": self._reset_rc,
            "rc_injection_telemetry": lambda: {"applied": self.rc["applied"]},
            "get_effective_criteria": lambda code: None,
            "evaluate_boot_outcome": lambda *a, **k: ("success", "exec", {}),
            "merge_stop_status_signals": lambda *a, **k: None,
            "collect_semantic_state": lambda payload: None,
            "classify_fault_result": lambda *a, **k: "success",
            "run_followup_boot_cycles": lambda *a, **k: (None, None, 0),
            "mram_torn_word": "half",
            "mram_torn_word_seed": 0,
            "mram_torn_word_choices": [],
            "_apply_mram_torn_word_mode": self._apply_torn_word,
        }
        self.torn_word_applied = []
        self.read_arm_skip = read_arm_skip
        self.rc = {"enabled": False, "applied": False}
        self.armed_torn_words = []
        exec(
            compile(ast.Module(body=_runtime_nodes(), type_ignores=[]), "runtime", "exec"),
            self.ns,
            self.ns,
        )

    def _apply_torn_word(self) -> bool:
        self.torn_word_applied.append(self.ns["mram_torn_word"])
        return True

    def _reset(self, tracking_start=None) -> None:
        self.fired = {"write": False, "erase": False}

    def _arm_fault(self, arm_at, write_fault_mode=0) -> None:
        self.calls.append(("write", arm_at, write_fault_mode))
        self.armed_torn_words.append(self.ns["mram_torn_word"])
        self.fired["write"] = True

    def _arm_erase_fault(self, arm_at, erase_fault_mode=0) -> None:
        self.calls.append(("erase", arm_at, erase_fault_mode))
        self.armed_torn_words.append(self.ns["mram_torn_word"])
        self.fired["erase"] = True

    def _arm_read(self, fault_at):
        self.calls.append(("read", fault_at))
        self.armed_torn_words.append(self.ns["mram_torn_word"])
        if self.read_arm_skip is None:
            self.data.ReadFaultFired = True
        return {"skip_reason": self.read_arm_skip}

    def _reset_rc(self, enabled=False) -> None:
        self.calls.append(("rc_hook", bool(enabled)))
        self.rc = {"enabled": bool(enabled), "applied": False}

    def _run_until_done(self, cpu, **kwargs):
        if self.rc["enabled"]:
            self.rc["applied"] = True
        return {"reason": "fault_fired", "emulated_s": 0.01}

    def arms(self):
        return [call for call in self.calls if call[0] != "rc_hook"]

    def run(self, encoded: str):
        points, codes = self.ns["decode_multi_fault_stages_local"](encoded)
        return self.ns["run_multi_fault_sequence"](points, codes)


def test_runtime_stage_codes_match_public_registry() -> None:
    runtime = _FakeRuntime()
    assert runtime.ns["_MF_STAGE_CODES"] == frozenset(SUPPORTED_CODES)


@pytest.mark.parametrize("code", SUPPORTED_CODES)
@pytest.mark.parametrize("position", [0, 1])
def test_each_supported_stage_runs_as_its_own_type(code: str, position: int) -> None:
    runtime = _FakeRuntime()
    stage_codes = ["w", "w"]
    stage_codes[position] = code
    encoded = encode_multi_fault_sequence([3, 9], stage_codes)

    result = runtime.run(encoded)

    assert result["fault_injected"] is True
    assert result["fault_stage_codes"] == stage_codes
    arm = runtime.arms()[position]
    fault_at = [3, 9][position]
    if code in WRITE_CODES:
        mode = runtime.ns["_WRITE_FAULT_MODE"][code]
        assert arm == ("write", 40 + fault_at + 1, mode)
    elif code in ERASE_CODES:
        assert arm == ("erase", 4 + fault_at + 1, 1 if code == "a" else 0)
    else:
        assert code == "f"
        assert arm == ("read", fault_at)
    # The other stage stays a power-loss write fault.
    other = runtime.arms()[1 - position]
    assert other == ("write", 40 + [3, 9][1 - position] + 1, 0)

    stage = result["per_fault_states"][position]
    label = {v: k for k, v in FAULT_TYPE_NAME_TO_CODE.items()}[code]
    assert stage["fault_type"] == label
    assert stage["fault_code"] == code
    assert stage["outcome"] == "injected"
    assert result["per_fault_states"][1 - position]["fault_type"] == "power_loss"


def test_rc_injection_stage_enables_return_hook_only_for_that_stage() -> None:
    runtime = _FakeRuntime()
    result = runtime.run("mf:3:9@x")
    hooks = [call[1] for call in runtime.calls if call[0] == "rc_hook"]
    # stage 1 armed without hook, stage 2 armed with it; each stage resets after.
    assert hooks == [False, False, True, False]
    assert result["per_fault_states"][1]["rc_injection"] == {"applied": True}


@pytest.mark.parametrize(
    "encoded, kind, read_supported, stage, label",
    [
        ("mf:3:9@i", "mram", True, 2, "instruction_skip"),
        ("mf:3@k:9", "mram", True, 1, "command_drop"),
        ("mf:3@e:9", "otp", True, 1, "interrupted_erase"),
        ("mf:3:9@f", "fast", False, 2, "read_bit_flip"),
    ],
)
def test_unsupported_stage_is_an_error_naming_stage_and_type(
    encoded: str, kind: str, read_supported: bool, stage: int, label: str,
) -> None:
    runtime = _FakeRuntime(kind=kind, read_supported=read_supported)
    result = runtime.run(encoded)

    assert runtime.arms() == [], "no stage may run, least of all as power loss"
    assert result["infrastructure_error"] is True
    assert result["boot_outcome"] == "infra_error"
    assert result["error_kind"] == "multi_fault_stage_unsupported"
    assert "multi-fault stage {} ({})".format(stage, label) in result["error"]
    states = result["per_fault_states"]
    assert [s["stage"] for s in states] == [1, 2]
    assert [s["outcome"] for s in states] == [
        "unsupported" if s["stage"] == stage else "not_run" for s in states
    ]
    assert states[stage - 1]["fault_type"] == label


def test_read_stage_that_cannot_arm_is_an_error_naming_the_stage() -> None:
    runtime = _FakeRuntime(read_arm_skip="probability_gate")
    result = runtime.run("mf:3:9@f")
    assert result["infrastructure_error"] is True
    assert "multi-fault stage 2 (read_bit_flip)" in result["error"]
    assert "probability_gate" in result["error"]
    assert [s["outcome"] for s in result["per_fault_states"]] == ["injected", "unsupported"]


def test_encoding_round_trips_stage_types() -> None:
    assert encode_multi_fault_sequence([1, 2]) == "mf:1:2"
    encoded = encode_multi_fault_sequence([1, 2, 3], ["b", "w", "e"])
    assert encoded == "mf:1@b:2:3@e"
    assert decode_multi_fault_sequence(encoded) == [1, 2, 3]
    assert decode_multi_fault_stage_types(encoded) == ["b", "w", "e"]
    seq = AnnotatedSequence([4, 5], "r", fault_types=["f", "x"])
    assert encode_multi_fault_sequence(seq) == "mf:4@f:5@x"
    assert seq.to_dict()["fault_types"] == ["read_bit_flip", "rc_injection"]
    with pytest.raises(ValueError):
        encode_multi_fault_sequence([1, 2], ["w:sp", "w"])


def test_stage_code_reduces_single_fault_wire_codes() -> None:
    assert multi_fault_stage_code("w:sp") == "w"
    assert multi_fault_stage_code("w:ss:0") == "w"
    assert multi_fault_stage_code("b:42") == "b"
    assert multi_fault_stage_code("i:0x100:nop") == "i"
    assert multi_fault_stage_code(None) == "w"


def test_interesting_points_carry_every_issue_fault_type() -> None:
    results = [
        {"fault_at": 4, "fault_type": "b", "fault_injected": True, "boot_outcome": "no_boot"},
        {"fault_at": 4, "fault_type": "e", "fault_injected": True, "boot_outcome": "wrong_image"},
        {"fault_at": 4, "fault_type": "w", "fault_injected": True,
         "boot_outcome": "success", "boot_slot": "exec"},
        {"fault_at": 8, "fault_type": "w:sp", "fault_injected": True, "boot_outcome": "no_boot"},
    ]
    points = _interesting_multi_fault_points(results, "success")
    assert [(p.fault_at, p.fault_types) for p in points] == [(4, ("b", "e")), (8, ("w",))]


def test_assign_stage_types_expands_and_caps() -> None:
    plan = MultiFaultPlan(
        sequences=[AnnotatedSequence([4, 8], "pairwise")],
        strategy="pairwise_interesting",
        interesting_point_count=2,
        max_faults_per_run=2,
        seed=None,
        diagnostics={},
    )
    typed = assign_multi_fault_stage_types(plan, {4: ["e", "b"], 8: ["w"]}, 10)
    assert [s.stage_codes() for s in typed.sequences] == [("b", "w"), ("e", "w")]
    capped = assign_multi_fault_stage_types(plan, {4: ["e", "b"]}, 1)
    assert [s.stage_codes() for s in capped.sequences] == [("b", "w")]
    assert capped.diagnostics["stage_type_variants_capped_at"] == 1


def test_multi_fault_phase_dispatches_each_stage_as_its_source_type() -> None:
    profile = load_profile(MOVE_MF_SELFTEST)
    sweep_results = [
        {"fault_at": 5, "fault_type": "b", "fault_injected": True, "boot_outcome": "no_boot",
         "signals": {}},
        {"fault_at": 30, "fault_type": "e", "fault_injected": True,
         "boot_outcome": "wrong_image", "boot_slot": "staging", "signals": {}},
    ]
    captured = {}

    def fake_run_runtime_sweep(**kwargs):
        captured["fault_types_list"] = list(kwargs["fault_types_list"])
        return [
            {
                "fault_at": kwargs["fault_points"][idx],
                "fault_type": ft,
                "fault_injected": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "signals": {},
            }
            for idx, ft in enumerate(kwargs["fault_types_list"])
        ]

    with tempfile.TemporaryDirectory(prefix="mf_stage_types_") as td:
        with mock.patch("sweep.run_runtime_sweep", side_effect=fake_run_runtime_sweep):
            out = run_multi_fault_phase(
                profile=profile,
                sweep_results=sweep_results,
                repo_root=ROOT,
                renode_test="renode-test",
                robot_suite="tests/ota_fault_point.robot",
                robot_vars=[],
                work_dir=Path(td),
                renode_remote_server_dir="",
                num_workers=1,
                max_batch_points=0,
                max_writes=256,
            )

    assert captured["fault_types_list"] == ["mf:5@b:30@e"]
    assert out.results[0]["fault_stage_types"] == ["bit_corruption", "interrupted_erase"]
    assert out.plan_data["sample_sequences"][0]["fault_types"] == [
        "bit_corruption", "interrupted_erase",
    ]


def test_runner_rejects_result_whose_stage_types_differ_from_request() -> None:
    result = {"fault_type": "mf", "fault_sequence": [5, 30],
              "fault_stage_codes": ["b", "e"], "signals": {}}
    assert _fault_type_semantically_matches("mf:5@b:30@e", "mf", result)
    assert not _fault_type_semantically_matches("mf:5:30", "mf", result)
    result["fault_stage_codes"] = ["w", "w"]
    assert not _fault_type_semantically_matches("mf:5@b:30@e", "mf", result)
    assert _fault_type_semantically_matches("mf:5:30", "mf", result)


def test_report_finding_records_each_stage_type_and_outcome() -> None:
    from audit_report import categorize_failure

    profile = load_profile(MOVE_MF_SELFTEST)
    runtime = _FakeRuntime()
    result = runtime.run("mf:3@b:9@e")
    result.update({"boot_outcome": "no_boot", "fault_address": "0x00000000"})
    finding = categorize_failure(result, total_writes=256, profile=profile)
    assert finding["fault_stages"] == [
        {"stage": 1, "fault_at": 3, "fault_type": "bit_corruption", "outcome": "injected"},
        {"stage": 2, "fault_at": 9, "fault_type": "interrupted_erase", "outcome": "injected"},
    ]


def test_multi_fault_point_cuts_every_stage_under_its_one_drawn_torn_word() -> None:
    """Per-cut torn-word draws meet multi-fault stage types.

    The sweep draws once per fault point, keyed on the point's fault index
    (``seq[0]`` for a multi-fault point), before dispatch.  Every stage of the
    sequence, whatever its fault type, cuts under that one mode, and the
    sequence itself never redraws.
    """
    from audit_report import categorize_failure

    choices = [("untouched", 1), ("erased", 1), ("corrupted", 1)]
    runtime = _FakeRuntime()
    draw = runtime.ns["_mram_torn_word_for_point"]
    seed = 7
    # Pick a sequence whose stage indices draw different modes on their own,
    # so a per-stage redraw would show up as a mismatch.
    first, second = next(
        (a, b)
        for a in range(1, 64)
        for b in range(a + 1, 64)
        if draw(a, choices, seed) != draw(b, choices, seed)
    )
    runtime.ns["mram_torn_word_choices"] = choices
    runtime.ns["mram_torn_word_seed"] = seed
    encoded = encode_multi_fault_sequence([first, second], ["b", "w"])

    # Mirror the sweep loop: draw for the point, dispatch, record.
    point_mode = runtime.ns["_select_point_mram_torn_word"](first)
    result = runtime.ns["_record_point_mram_torn_word"](runtime.run(encoded), point_mode)

    assert point_mode == draw(first, choices, seed)
    assert runtime.torn_word_applied == [point_mode]
    assert runtime.armed_torn_words == [point_mode, point_mode]
    assert [s["fault_type"] for s in result["per_fault_states"]] == [
        "bit_corruption", "power_loss",
    ]
    assert result["mram_torn_word"] == point_mode

    profile = load_profile(MOVE_MF_SELFTEST)
    result.update({"boot_outcome": "no_boot", "fault_address": "0x00000000"})
    finding = categorize_failure(result, total_writes=256, profile=profile)
    assert finding["mram_torn_word"] == point_mode
    assert [s["fault_type"] for s in finding["fault_stages"]] == [
        "bit_corruption", "power_loss",
    ]
