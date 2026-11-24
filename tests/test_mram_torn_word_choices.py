#!/usr/bin/env python3
"""Per-cut torn-word outcomes: profile parsing, seeded draw, per-point record."""

from __future__ import annotations

import ast
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNTIME = SCRIPTS / "run_runtime_fault_sweep.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_report import summarize_runtime_sweep  # noqa: E402
from profile_loader import ProfileError, load_profile  # noqa: E402


def _runtime_functions(*names: str, globals_dict=None):
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in set(names)
    ]
    assert {node.name for node in selected} == set(names)
    namespace = dict(globals_dict or {})
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, str(RUNTIME), "exec"), namespace, namespace)
    return namespace


def _draw_functions():
    ns = _runtime_functions(
        "_parse_mram_torn_word_choices", "_mram_torn_word_for_point"
    )
    return ns["_parse_mram_torn_word_choices"], ns["_mram_torn_word_for_point"]


def _write_profile(tmp_path: Path, fault_sweep: str, repl: str | None = None) -> Path:
    (tmp_path / "platform.repl").write_text(
        repl
        or "mram: Memory.MappedMRAMTracker @ sysbus 0x10000000\n    size: 0x2000\n",
        encoding="utf-8",
    )
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(
        """
schema_version: 1
name: mram_torn_word_choices
platform: platform.repl
bootloader: { elf: firmware.elf, entry: 0x10000000 }
memory:
  sram: { start: 0x20000000, end: 0x20001000 }
  slots:
    exec: { base: 0x10000000, size: 0x1000 }
    staging: { base: 0x10001000, size: 0x1000 }
images: { staging: firmware.bin }
success_criteria: { vtor_in_slot: exec }
fault_sweep:
"""
        + fault_sweep,
        encoding="utf-8",
    )
    return profile_path


# --- profile loader -------------------------------------------------------


def test_single_mode_profile_is_unchanged(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(tmp_path, "  evaluation_mode: execute\n  mram_torn_word: untouched\n"),
        strict=True,
    )
    fs = profile.fault_sweep
    assert fs.mram_torn_word == "untouched"
    assert fs.mram_torn_word_choices == ()
    robot_vars = profile.robot_vars(tmp_path)
    assert "MRAM_TORN_WORD:untouched" in robot_vars
    assert not any(v.startswith("MRAM_TORN_WORD_CHOICES:") for v in robot_vars)


def test_default_profile_has_no_choices(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(tmp_path, "  evaluation_mode: execute\n"), strict=True
    )
    assert profile.fault_sweep.mram_torn_word == "half"
    assert profile.fault_sweep.mram_torn_word_choices == ()
    assert profile.fault_sweep.mram_torn_word_explicit is False
    assert not any(
        v.startswith("MRAM_TORN_WORD_CHOICES:") for v in profile.robot_vars(tmp_path)
    )


def test_list_form_parses_weights_and_emits_robot_var(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(
            tmp_path,
            "  evaluation_mode: execute\n"
            "  mram_torn_word_seed: 7\n"
            "  mram_torn_word:\n"
            "    - half_retain: 3\n"
            "    - untouched\n"
            "    - corrupted: 2\n",
        ),
        strict=True,
    )
    fs = profile.fault_sweep
    assert fs.mram_torn_word_choices == (
        ("half_retain", 3),
        ("untouched", 1),
        ("corrupted", 2),
    )
    assert fs.mram_torn_word == "half_retain"
    assert fs.mram_torn_word_explicit is True
    robot_vars = profile.robot_vars(tmp_path)
    assert "MRAM_TORN_WORD_CHOICES:half_retain:3,untouched:1,corrupted:2" in robot_vars
    assert "MRAM_TORN_WORD:half_retain" in robot_vars
    assert "MRAM_TORN_WORD_SEED:7" in robot_vars

    # The sweep parses exactly what the loader emits.
    parse, _ = _draw_functions()
    wire = next(
        v.split(":", 1)[1] for v in robot_vars if v.startswith("MRAM_TORN_WORD_CHOICES:")
    )
    assert tuple(parse(wire)) == fs.mram_torn_word_choices


@pytest.mark.parametrize(
    "body, message",
    [
        ("    - half\n    - bogus\n", "Invalid fault_sweep.mram_torn_word 'bogus'"),
        ("    - half\n    - half: 2\n", "more than once"),
        ("    - half: 0\n", "positive integer"),
        ("    - half: -1\n", "positive integer"),
        ("    - half: true\n", "positive integer"),
        ("    - half: 1.5\n", "positive integer"),
        ("    - { half: 1, untouched: 1 }\n", "one-key mapping"),
        ("    []\n", "non-empty list"),
    ],
)
def test_list_form_rejects_bad_entries(tmp_path: Path, body: str, message: str) -> None:
    path = _write_profile(
        tmp_path, "  evaluation_mode: execute\n  mram_torn_word:\n" + body
    )
    with pytest.raises(ProfileError, match=message):
        load_profile(path, strict=True)


def test_uncorrectable_in_a_set_follows_the_single_mode_rules(tmp_path: Path) -> None:
    path = _write_profile(
        tmp_path,
        "  evaluation_mode: state\n"
        "  mram_torn_word:\n"
        "    - half\n"
        "    - uncorrectable\n",
    )
    with pytest.raises(ProfileError, match="uncorrectable.*evaluation_mode"):
        load_profile(path, strict=True)


def test_list_form_rejected_on_non_mram_backend_without_erase_points(tmp_path: Path) -> None:
    path = _write_profile(
        tmp_path,
        "  evaluation_mode: execute\n  mram_torn_word: [half, untouched]\n",
        repl="flash: Memory.MappedMemory @ sysbus 0x10000000\n    size: 0x2000\n",
    )
    with pytest.raises(ProfileError, match="fault_sweep.mram_torn_word.*MRAM"):
        load_profile(path, strict=True)


# --- seeded draw ----------------------------------------------------------


def test_sweep_parser_accepts_default_weights_and_rejects_bad_input() -> None:
    parse, _ = _draw_functions()
    assert parse("") == []
    assert parse("half_retain, untouched:4 ,") == [("half_retain", 1), ("untouched", 4)]
    for bad in ("bogus", "half,half", "half:0", "half:x", "half:-2"):
        with pytest.raises(Exception, match="mram_torn_word_choices"):
            parse(bad)


def test_draw_is_reproducible_and_depends_only_on_seed_and_fault_index() -> None:
    _, draw = _draw_functions()
    choices = [("half_retain", 1), ("untouched", 1), ("corrupted", 1), ("programmed", 1)]
    points = list(range(500))

    first = [draw(fp, choices, 1234) for fp in points]
    again = [draw(fp, choices, 1234) for fp in points]
    assert first == again

    # Replaying one point alone, or the run in another order, gives the
    # same outcome per point.
    for fp in (0, 17, 499):
        assert draw(fp, choices, 1234) == first[fp]
    assert [draw(fp, choices, 1234) for fp in reversed(points)] == first[::-1]

    # One run sees cuts ending in different outcomes.
    assert set(first) == {mode for mode, _ in choices}

    # A different seed gives a different history.
    other = [draw(fp, choices, 1235) for fp in points]
    assert other != first
    assert sum(a != b for a, b in zip(first, other)) > len(points) // 2


def test_draw_pins_known_values() -> None:
    # A change to the generator would silently change the outcome every
    # recorded point replays with, so pin a few draws.
    _, draw = _draw_functions()
    choices = [("half", 1), ("untouched", 1), ("corrupted", 1)]
    assert [draw(fp, choices, 0) for fp in range(8)] == [
        "untouched", "corrupted", "untouched", "half",
        "untouched", "corrupted", "corrupted", "half",
    ]
    assert [draw(fp, choices, 42) for fp in range(8)] == [
        "half", "untouched", "corrupted", "half",
        "untouched", "untouched", "half", "half",
    ]


def test_weights_shape_the_distribution() -> None:
    _, draw = _draw_functions()
    choices = [("half_retain", 3), ("untouched", 1)]
    counts = Counter(draw(fp, choices, 99) for fp in range(8000))
    share = counts["half_retain"] / 8000
    assert 0.72 < share < 0.78, counts

    lopsided = Counter(
        draw(fp, [("programmed", 1), ("erased", 99)], 5) for fp in range(5000)
    )
    assert 0 < lopsided["programmed"] < 150, lopsided

    assert {draw(fp, [("corrupted", 7)], 3) for fp in range(200)} == {"corrupted"}


# --- per-point selection and recording ------------------------------------


class _Peripheral:
    def __init__(self) -> None:
        self.MramTornWordMode = "half"
        self.MramTornWordSeed = 0
        self.history: list[str] = []

    def __setattr__(self, name, value):
        if name == "MramTornWordMode" and hasattr(self, "history"):
            self.history.append(value)
        object.__setattr__(self, name, value)


def _selection_namespace(choices, mode="half", seed=0):
    data = _Peripheral()
    ns = _runtime_functions(
        "_mram_torn_word_for_point",
        "_apply_mram_torn_word_mode",
        "_select_point_mram_torn_word",
        "_record_point_mram_torn_word",
        globals_dict={
            "backend": {"kind": "mram", "data": data, "backend_sysbus_name": "mram"},
            "mram_torn_word": mode,
            "mram_torn_word_seed": seed,
            "mram_torn_word_choices": choices,
        },
    )
    return ns, data


def test_each_point_sets_its_drawn_mode_on_the_backend_and_records_it() -> None:
    choices = [("half_retain", 1), ("untouched", 1), ("programmed", 1)]
    ns, data = _selection_namespace(choices, mode="half_retain", seed=77)
    draw = ns["_mram_torn_word_for_point"]

    results = []
    for fp in range(40):
        mode = ns["_select_point_mram_torn_word"](fp)
        assert mode == draw(fp, choices, 77)
        # Runners read the module global and the peripheral property.
        assert ns["mram_torn_word"] == mode
        assert data.MramTornWordMode == mode
        assert data.MramTornWordSeed == 77
        results.append(
            ns["_record_point_mram_torn_word"]({"fault_at": fp, "is_control": False}, mode)
        )

    assert [r["mram_torn_word"] for r in results] == [
        draw(fp, choices, 77) for fp in range(40)
    ]
    assert len({r["mram_torn_word"] for r in results}) > 1

    control = ns["_record_point_mram_torn_word"](
        {"fault_at": -1, "is_control": True}, "untouched"
    )
    assert "mram_torn_word" not in control


def test_single_mode_run_leaves_mode_alone_and_records_nothing() -> None:
    ns, data = _selection_namespace([], mode="untouched", seed=5)
    for fp in range(10):
        assert ns["_select_point_mram_torn_word"](fp) is None
        result = ns["_record_point_mram_torn_word"]({"fault_at": fp}, None)
        assert "mram_torn_word" not in result
    assert ns["mram_torn_word"] == "untouched"
    assert data.history == []


def test_sweep_loop_selects_before_dispatch_and_records_after() -> None:
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    loops = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Call)
        and getattr(node.iter.func, "id", None) == "enumerate"
        and getattr(node.iter.args[0], "id", None) == "fault_points"
    ]
    assert len(loops) == 1
    order = [
        call.func.id
        for stmt in loops[0].body
        for call in ast.walk(stmt)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id
        in (
            "_select_point_mram_torn_word",
            "_dispatch_fault_point",
            "_record_point_mram_torn_word",
        )
    ]
    assert order == [
        "_select_point_mram_torn_word",
        "_dispatch_fault_point",
        "_record_point_mram_torn_word",
    ]


# --- report ---------------------------------------------------------------


def test_issue_points_carry_the_outcome_that_produced_them(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(
            tmp_path,
            "  evaluation_mode: execute\n  mram_torn_word: [half_retain, untouched]\n",
        ),
        strict=True,
    )
    base = {
        "is_control": False,
        "fault_injected": True,
        "fault_type": "w",
        "fault_address": "0x10000040",
        "boot_slot": None,
        "signals": {},
    }
    results = [
        dict(base, fault_at=1, fault_requested=1, boot_outcome="success",
             boot_slot="exec", fault_class="recovered", mram_torn_word="half_retain"),
        dict(base, fault_at=2, fault_requested=2, boot_outcome="hard_fault",
             fault_class="unrecoverable", mram_torn_word="untouched",
             mram_fault_evidence={"exact": True, "program_width": 8}),
    ]
    summary = summarize_runtime_sweep(
        results, total_writes=10, profile=profile, expected_control_points=0
    )
    failures = summary["failures"]
    assert [(f["fault_at"], f["mram_torn_word"]) for f in failures] == [(2, "untouched")]
    evidence = summary["fault_evidence"]
    assert [(e["fault_at"], e["mram_torn_word"]) for e in evidence] == [(2, "untouched")]


def test_single_mode_issue_points_have_no_torn_word_field(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(tmp_path, "  evaluation_mode: execute\n"), strict=True
    )
    summary = summarize_runtime_sweep(
        [
            {
                "is_control": False,
                "fault_injected": True,
                "fault_type": "w",
                "fault_at": 2,
                "fault_requested": 2,
                "fault_address": "0x10000040",
                "boot_outcome": "hard_fault",
                "boot_slot": None,
                "fault_class": "unrecoverable",
                "signals": {},
            }
        ],
        total_writes=10,
        profile=profile,
        expected_control_points=0,
    )
    assert "mram_torn_word" not in summary["failures"][0]
