"""Recovery tracking configuration at the profile/runner boundary."""

import ast
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from profile_loader import ProfileError, load_profile


def profile_with_gate(tmp_path, **settings):
    base = ROOT / "examples/phase2_mram_parity/profile_deferred_state_search_16_half.yaml"
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump({"base_profile": str(base), "fault_sweep": settings}))
    return load_profile(path)


@pytest.mark.parametrize(("setting", "address"), [("reset", 0), ("0x10000040", 0x10000040)])
def test_recovery_start_is_independent_of_first_cut(tmp_path, setting, address):
    profile = profile_with_gate(tmp_path, recovery_tracking_start_address=setting)
    variables = profile.robot_vars(ROOT)
    assert "TRACKING_START_ADDRESS:0x10000200" in variables
    assert f"RECOVERY_TRACKING_START_ADDRESS:0x{address:08X}" in variables


def test_omitted_recovery_start_preserves_legacy_selection(tmp_path):
    profile = profile_with_gate(tmp_path)
    assert profile.fault_sweep.recovery_tracking_start_address is None
    variables = profile.robot_vars(ROOT)
    assert "TRACKING_START_ADDRESS:0x10000200" in variables
    assert not any(var.startswith("RECOVERY_TRACKING_START_ADDRESS:") for var in variables)


@pytest.mark.parametrize("setting", [-1, 2**32, None, True, "no such address"])
def test_invalid_recovery_start_is_refused(tmp_path, setting):
    with pytest.raises(ProfileError, match="recovery_tracking_start_address"):
        profile_with_gate(tmp_path, recovery_tracking_start_address=setting)


def test_recovery_start_requires_an_executing_boot(tmp_path):
    with pytest.raises(ProfileError, match="recovery_tracking_start_address requires execute"):
        profile_with_gate(tmp_path, recovery_tracking_start_address="reset", evaluation_mode="state")


@pytest.mark.parametrize("address", [None, 0, 0x10000040])
def test_computed_and_live_recovery_select_same_boundary(address):
    from test_phase2_fault_parity import RUNNER, _Phase2Runtime

    runtime = _Phase2Runtime()
    ns = runtime.ns
    ns.update(
        tracking_start_address_config=0x10000200,
        recovery_tracking_start_address=address,
        to_clr_bytes=bytes,
    )
    tree = ast.parse(RUNNER.read_text())
    boot = next(node for node in tree.body if getattr(node, "name", "") == "_state_search_boot_state")
    exec(compile(ast.Module(body=[boot], type_ignores=[]), str(RUNNER), "exec"), ns)

    # Observe the recovery reset after restoring persistent bytes and before the CPU runs.
    class ResetObserved(Exception):
        pass

    def observe_reset(**settings):
        raise ResetObserved(settings)

    ns["reset_nvmc_for_recovery"] = observe_reset
    state = SimpleNamespace(materialize=lambda: {"nvm": b"1234"}, uncorrectable_words=())
    with pytest.raises(ResetObserved) as reset:
        ns["_state_search_boot_state"](state, (), 1)
    search_start = 0x10000200 if address is None else address
    assert reset.value.args == ({"tracking_start": search_start},)

    # A missed last cut returns normally from the injector and exposes each armed start.
    expected = SimpleNamespace(identity_hex=lambda: "computed")
    runtime.miss_pair_second = True
    explicit_start = 0 if address is None else address
    for cross_check, start in ((None, explicit_start), (expected, search_start)):
        runtime.sweep_tracking_gates.clear()
        runtime.run(0, 99, cross_check_expected=cross_check)
        assert runtime.sweep_tracking_gates == [None, start]

    runtime.missed_chain_cut = 3
    for cross_check, start in ((None, explicit_start), (expected, search_start)):
        runtime.sweep_tracking_gates.clear()
        runtime.run_chain([(0, "w"), (1, "w"), (99, "w")], cross_check_expected=cross_check)
        assert runtime.sweep_tracking_gates == [0x10000200, start, start]


def test_recovery_trace_size_counts_selected_operations():
    from recovery_state import merge_operation_traces
    from recovery_search import recovery_trace_size

    writes = [
        {"write_index": index + 1, "offset": index, "value": 0x40, "width": 1}
        for index in range(2)
    ]
    erase = {"erase_index": 1, "offset": 0, "erase_size": 1, "writes_at_this_point": 0}
    operations = merge_operation_traces(writes, [erase])

    config = {"fault_types": ["power_loss"], "address_ranges": [{"start": 0, "end": 0}]}
    row = recovery_trace_size(operations, 0, 0, config)
    assert row == {"address": "0x00000000", "traced_operations": 3, "candidate_operations": 1}


def test_recovery_only_gate_requires_snapshot_support_without_loading_calibration_base():
    from test_phase2_fault_parity import _load_state_search_preflight

    methods = (
        "ProgramTraceClear ProgramTraceCount ProgramTraceToString "
        "EraseTraceClear EraseTraceEnabled EraseTraceCount EraseTraceToString"
    ).split()
    checks = []
    namespace = {
        "phase2_state_search": {"enabled": True},
        "backend": {"kind": "mram", "data": SimpleNamespace(**dict.fromkeys(methods)), "per_write_accurate": True},
        "durability_model": "direct",
        "tracking_start_address_config": 0,
        "recovery_tracking_start_address": 0x10000040,
        "program_trace_file_path": __file__,
        "os": os,
        "_tracking_base_capability_error": lambda: checks.append("capabilities"),
    }
    _load_state_search_preflight(namespace)
    namespace["_state_search_preflight"]()
    assert checks == ["capabilities"]
    namespace["backend"]["kind"] = "fast"
    with pytest.raises(RuntimeError, match="MRAM tracking-base snapshot"):
        namespace["_state_search_preflight"]()
