import ast
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


def test_apply_pre_boot_state_runs_setup_script_before_pre_boot_state() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    start = source.index("def apply_pre_boot_state():")
    end = source.index("def capture_pre_boot_state_debug():", start)
    block = source[start:end]

    assert block.index("if setup_script:") < block.index("if pre_boot_bin:")
    assert block.index("monitor.Parse('include @' + setup_script)") < block.index(
        "bus.WriteDoubleWord(addr, val)"
    )


def test_boundary_follow_up_restores_snapshot_before_setup() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    start = source.index("def apply_pre_boot_state():")
    end = source.index("def capture_pre_boot_state_debug():", start)
    block = source[start:end]
    assert block.index("restore_boundary_persistent_snapshot(boundary_durable_state_file)") < block.index(
        "monitor.Parse('include @' + setup_script)"
    )
    assert "boundary follow-up cannot apply baseline pre_boot_state" in block


def test_boundary_snapshot_capture_is_optional_without_follow_up_relation() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "boundary_setup_env and boundary_durable_state_file" in source
    assert "boundary follow-up requires boundary_durable_state_file" in source


def _load_probe_reset_functions():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {
        "_terminal_error_hook",
        "reset_verification_probes",
        "reset_terminal_error_paths",
    }
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {node.name for node in functions} == wanted

    namespace = {
        "_verification_probes_raw": "verification-config",
        "_function_return_probes_raw": "return-config",
        "_load_verification_probe_configs": lambda raw: [{"label": "verify"}],
        "_load_function_return_probe_configs": lambda raw: [{"label": "effect"}],
        "_make_verification_probe_capture": lambda cfg: {
            "label": cfg["label"],
            "reached": False,
        },
        "_make_function_return_probe_capture": lambda cfg: {
            "label": cfg["label"],
            "reached": False,
        },
        "_verification_probe_state": {
            "active_frames": [{"stale": True}],
            "captures": {"stale": {"reached": True}},
        },
        "_terminal_error_artifact_hash": "a" * 64,
        "_terminal_error_snapshot_hash": "b" * 64,
        "_terminal_error_state": {
            "selected_callsite": None,
            "patch_applied": True,
            "by_callsite": {},
            "by_sink": {},
            "paths": [{
                "config": {
                    "name": "fatal-authentication-error",
                    "required_failure_marker": {"address": 1},
                },
                "unresolved_candidates": [],
                "infrastructure_errors": [],
            }],
            "captures": {"stale": {"callsite_reached": True}},
        },
        "_terminal_marker_matches": lambda marker: (True, "0x00000001"),
        "_time": SimpleNamespace(time=lambda: 123.0),
    }
    exec(
        compile(ast.Module(body=functions, type_ignores=[]), str(SCRIPT_PATH), "exec"),
        namespace,
    )
    return namespace


def test_instruction_skip_resets_all_observer_state_before_baseline_restore() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    start = source.index("def run_instruction_skip_fault(")
    end = source.index("\ndef ", start + 1)
    block = source[start:end]

    reset = "reset_verification_probes(selected_terminal_callsite=skip_addr)"
    assert reset in block
    assert block.index(reset) < block.index("restore_phase1_baseline()")


def test_probe_resets_are_isolated_across_sequential_fault_points() -> None:
    namespace = _load_probe_reset_functions()
    reset = namespace["reset_verification_probes"]

    reset(selected_terminal_callsite=0x101)
    verification = namespace["_verification_probe_state"]
    terminal = namespace["_terminal_error_state"]
    verification["active_frames"].append({"return_addr": 0xDEAD})
    verification["captures"]["verify"]["reached"] = True
    verification["captures"]["effect"]["reached"] = True
    terminal["captures"]["fatal-authentication-error"]["callsite_reached"] = True
    terminal["patch_applied"] = True

    reset(selected_terminal_callsite=0x203)

    assert verification["active_frames"] == []
    assert verification["captures"] == {
        "verify": {"label": "verify", "reached": False},
        "effect": {"label": "effect", "reached": False},
    }
    assert terminal["selected_callsite"] == 0x202
    assert terminal["patch_applied"] is False
    assert terminal["captures"]["fatal-authentication-error"]["callsite_reached"] is False
    assert terminal["captures"]["fatal-authentication-error"]["forbidden_sink_reached"] is False


def test_shared_terminal_sink_is_recorded_for_every_campaign() -> None:
    namespace = _load_probe_reset_functions()
    state = namespace["_terminal_error_state"]
    state["observation_started_at"] = 100.0
    state["by_sink"] = {0x3000: ["reject-a", "reject-b"]}
    state["captures"] = {
        name: {
            "observation_window": 1.0 if name == "reject-a" else None,
            "forbidden_sink_reached": False,
            "first_forbidden_sink": None,
        }
        for name in ("reject-a", "reject-b")
    }

    namespace["_terminal_error_hook"](None, 0x3001)

    assert state["captures"]["reject-a"]["observation_window_expired"] is True
    assert state["captures"]["reject-a"]["forbidden_sink_reached"] is False
    assert state["captures"]["reject-b"]["forbidden_sink_reached"] is True
