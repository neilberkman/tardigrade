"""Focused tests for success-implies-effect contracts."""

from __future__ import annotations

import sys
import tempfile
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fault_inject import FaultResult  # noqa: E402
from invariants import check_success_implies_effect, run_invariants  # noqa: E402
from profile_loader import (  # noqa: E402
    FunctionReturnProbeConfig,
    ProfileError,
    _parse_invariant_config,
    load_profile,
)


_PROFILE_TEMPLATE = """\
schema_version: 1
name: effect_contract
platform: platforms/cortex_m4_flash_fast.repl
bootloader:
  elf: examples/vulnerable_ota/firmware.elf
  entry: 0
memory:
  sram: {{start: 0x20000000, end: 0x20020000}}
  slots:
    exec: {{base: 0, size: 0x1000}}
    staging: {{base: 0x1000, size: 0x1000}}
success_criteria:
  vtor_in_slot: exec
fault_sweep:
  mode: {mode}
  evaluation_mode: {evaluation_mode}
{verification}
  function_return_probes:
{probes}
invariants: {invariants}
invariant_config:
  success_implies_effect:
{contracts}
"""


def _load_contract_profile(
    probes,
    contracts,
    verification="",
    *,
    mode="runtime",
    evaluation_mode="execute",
    invariants="[success_implies_effect]",
):
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML unavailable")
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "profile.yaml"
        path.write_text(_PROFILE_TEMPLATE.format(
            probes=probes,
            contracts=contracts,
            verification=verification,
            mode=mode,
            evaluation_mode=evaluation_mode,
            invariants=invariants,
        ), encoding="utf-8")
        return load_profile(path)


def _evaluate(*, raw=0, pre=None, post=None, require=None, capture="last", calls=None, call=None, control=False, call_count=None):
    result = FaultResult(4, "success", "exec", post, "", control)
    contract = {
        "name": "generation_is_persisted",
        "probe": "persist_generation",
        "success_values": [0],
        "require": require or {"all": [{"source": "post", "path": "state.commit_generation", "op": "gt_pre"}]},
    }
    if call is not None:
        contract["call"] = call
    if control:
        contract["evaluate_control"] = True
    telemetry = {
        "call_count": call_count if call_count is not None else (len(calls) if calls is not None else 1),
        "capture": capture,
        "raw_values": [raw] if calls is None else [item["raw_value"] for item in calls],
        "calls": calls if calls is not None else [{"raw_value": raw}],
    }
    return run_invariants(
        result,
        [check_success_implies_effect],
        pre_state=pre,
        invariant_config={"success_implies_effect": [contract]},
        result_signals={"semantic_state": post, "function_return_probes": {"persist_generation": telemetry}},
        result_dict={"fault_at": 4, "fault_address": "0x100"},
    )


def test_successful_return_and_mutation_pass():
    assert _evaluate(pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 6}}) == []


def test_successful_return_without_mutation_is_finding():
    violations = _evaluate(pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 5}})
    assert violations[0].details["finding_code"] == "SUCCESS_WITHOUT_REQUIRED_EFFECT"
    assert violations[0].details["return_value"] == 0


def test_failure_return_does_not_violate_contract():
    assert _evaluate(raw=1, pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 5}}) == []


def test_any_and_all_groups():
    pre = {"state": {"commit_generation": "0x5"}}
    post = {"state": {"commit_generation": "0x6"}}
    assert _evaluate(pre=pre, post=post, require={"any": [
        {"source": "post", "path": "state.commit_generation", "op": "eq", "value": "0x6"},
        {"source": "post", "path": "state.commit_generation", "op": "eq", "value": 99},
    ]}) == []
    assert _evaluate(pre=pre, post=post, require={"all": [
        {"source": "post", "path": "state.commit_generation", "op": "ge", "value": 6},
        {"source": "post", "path": "state.commit_generation", "op": "gt_pre"},
    ]}) == []


def test_missing_state_fails_closed():
    violations = _evaluate(pre=None, post=None)
    assert violations[0].invariant_name == "invariant_evaluation_error"


def test_control_can_be_evaluated_when_requested():
    assert _evaluate(control=True, pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 6}}) == []


def test_capture_all_index_and_absent_index():
    calls = [{"raw_value": 1}, {"raw_value": 0}]
    assert _evaluate(calls=calls, capture="all", call=1, pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 6}}) == []
    violations = _evaluate(calls=calls, capture="all", call=2, pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 6}})
    assert violations[0].invariant_name == "invariant_evaluation_error"


def test_first_and_last_capture_selectors_are_bounded():
    # Runtime telemetry for first/last contains only the selected call, while
    # the total invocation count still makes absent integer calls detectable.
    first = {"call_count": 3, "capture": "first", "raw_values": [0], "calls": [{"call_index": 0, "raw_value": 0}]}
    last = {"call_count": 3, "capture": "last", "raw_values": [0], "calls": [{"call_index": 2, "raw_value": 0}]}
    common = {"state": {"commit_generation": 6}}
    assert _evaluate(calls=first["calls"], call_count=3, capture="first", call=0, pre={"state": {"commit_generation": 5}}, post=common) == []
    assert _evaluate(calls=last["calls"], call_count=3, capture="last", call=2, pre={"state": {"commit_generation": 5}}, post=common) == []
    missing = _evaluate(calls=first["calls"], call_count=3, capture="first", call=1, pre={"state": {"commit_generation": 5}}, post=common)
    assert missing[0].invariant_name == "invariant_evaluation_error"


def test_register_read_failure_fails_closed():
    calls = [{"call_index": 0, "raw_value": None, "register_read_error": "unavailable"}]
    violations = _evaluate(calls=calls, capture="all", call=0, pre={"state": {"commit_generation": 5}}, post={"state": {"commit_generation": 6}})
    assert violations[0].invariant_name == "invariant_evaluation_error"
    assert "register read failed" in violations[0].description


def test_profile_contract_validation_rejects_bad_references_and_duplicates():
    with pytest.raises(ProfileError, match="success_values.*boolean"):
        _parse_invariant_config({"success_implies_effect": [{
            "name": "c", "probe": "p", "success_values": [True],
            "require": {"all": [{"source": "post", "path": "x", "op": "eq", "value": 1}]},
        }]})


def test_multiple_function_probes_can_share_a_symbol():
    first = FunctionReturnProbeConfig(symbol="api", label="first", capture="first")
    last = FunctionReturnProbeConfig(symbol="api", label="last", capture="last")
    assert first.symbol == last.symbol == "api"


def test_profile_load_rejects_missing_or_undefined_effect_probe():
    contract = """    - name: c
      probe: missing
      success_values: [0]
      require:
        all:
          - {source: post, path: state.commit_generation, op: ge, value: 1}
"""
    with pytest.raises(ProfileError, match="undefined.*function_return_probe.*missing"):
        _load_contract_profile("    - {label: present, symbol: api, capture: last}\n", contract)
    with pytest.raises(ProfileError, match="invariant_config.*missing"):
        profile = _PROFILE_TEMPLATE.format(
            probes="", contracts="", verification="", mode="runtime",
            evaluation_mode="execute", invariants="[success_implies_effect]",
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(profile.replace("invariants: [success_implies_effect]\n", "invariants: [success_implies_effect]\n"), encoding="utf-8")
            load_profile(path)


def test_profile_load_rejects_duplicate_contract_names_and_label_collisions():
    contract = """    - name: c
      probe: p
      success_values: [0]
      require:
        all:
          - {source: post, path: state.commit_generation, op: ge, value: 1}
"""
    duplicate = contract + contract.replace("name: c", "name: c")
    with pytest.raises(ProfileError, match="duplicate contract name"):
        _load_contract_profile("    - {label: p, symbol: api, capture: last}\n", duplicate)
    with pytest.raises(ProfileError, match="label collision"):
        _load_contract_profile(
            "    - {label: p, symbol: api, capture: last}\n",
            contract,
            "  verification_probes:\n    - {label: p, symbol: api}\n",
        )


def test_profile_load_rejects_effect_features_outside_runtime_execute():
    probe = "    - {label: p, symbol: api, capture: last}\n"
    contract = """    - name: c
      probe: p
      success_values: [0]
      require:
        all:
          - {source: post, path: state.commit_generation, op: ge, value: 1}
"""
    with pytest.raises(ProfileError, match="requires fault_sweep.mode 'runtime'"):
        _load_contract_profile(probe, contract, mode="state")
    with pytest.raises(ProfileError, match="requires fault_sweep.evaluation_mode 'execute'"):
        _load_contract_profile(probe, contract, evaluation_mode="state")
    with pytest.raises(ProfileError, match="requires fault_sweep.mode 'runtime'"):
        _load_contract_profile(probe, "", mode="state", invariants="[]")
    with pytest.raises(ProfileError, match="requires fault_sweep.evaluation_mode 'execute'"):
        _load_contract_profile(probe, "", evaluation_mode="state", invariants="[]")


def test_profile_load_rejects_incompatible_capture_selectors():
    contract = """    - name: c
      probe: p
      call: {call}
      success_values: [0]
      require:
        all:
          - {source: post, path: state.commit_generation, op: ge, value: 1}
"""
    with pytest.raises(ProfileError, match="capture='first'"):
        _load_contract_profile(
            "    - {label: p, symbol: api, capture: first}\n",
            contract.replace("{call}", "last"),
        )
    with pytest.raises(ProfileError, match="capture='last'"):
        _load_contract_profile(
            "    - {label: p, symbol: api, capture: last}\n",
            contract.replace("{call}", "0"),
        )
    with pytest.raises(ProfileError, match="call is required.*capture is 'all'"):
        _load_contract_profile(
            "    - {label: p, symbol: api, capture: all}\n",
            contract.replace("      call: {call}\n", "").replace("{call}", "last"),
        )
    _load_contract_profile(
            "    - {label: p, symbol: api, capture: all}\n",
            contract.replace("{call}", "first"),
    )


def test_synthetic_runtime_target_normal_and_injected_false_success():
    sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
    from success_effect_runtime_target import GenerationTarget

    target = GenerationTarget()
    pre = {"state": {"commit_generation": target.commit_generation}}
    assert target.persist_generation(6, injected=False) == 0
    normal = _evaluate(pre=pre, post={"state": {"commit_generation": target.commit_generation}})
    assert normal == []

    target = GenerationTarget()
    pre = {"state": {"commit_generation": target.commit_generation}}
    assert target.persist_generation(6, injected=True) == 0
    injected = _evaluate(pre=pre, post={"state": {"commit_generation": target.commit_generation}})
    assert injected and injected[0].details["finding_code"] == "SUCCESS_WITHOUT_REQUIRED_EFFECT"


def test_shared_runtime_hook_captures_multiple_probes_on_one_symbol():
    source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {"_verification_fmt_u32", "_make_function_return_probe_capture", "_verification_probe_entry_hook", "_verification_probe_return_hook"}
    namespace = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            exec(compile(ast.Module(body=[node], type_ignores=[]), "runtime", "exec"), namespace)

    class CPU:
        def __init__(self):
            self.hooks = {}

        def GetRegister(self, index):
            return type("Register", (), {"RawValue": 0x501})()

        def AddHook(self, address, callback):
            self.hooks[address] = callback

    captures = {
        label: namespace["_make_function_return_probe_capture"]({
            "label": label, "symbol": "api", "return_register": "r0", "capture": "all",
        })
        for label in ("first", "second")
    }
    namespace.update({
        "_verification_probe_state": {
            "entry_templates": {0x100: [
                {"label": "first", "symbol": "api", "return_register_index": 0, "probe_kind": "function_return"},
                {"label": "second", "symbol": "api", "return_register_index": 0, "probe_kind": "function_return"},
            ]},
            "installed_return_hooks": set(), "active_frames": [], "captures": captures,
        },
        "log": lambda *args: None,
    })
    cpu = CPU()
    namespace["_verification_probe_entry_hook"](cpu, 0x101)
    cpu.hooks[0x500](cpu, 0x501)
    assert captures["first"]["call_count"] == 1
    assert captures["second"]["call_count"] == 1


def test_runtime_register_read_failure_is_not_encoded_as_zero_success():
    source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {"_verification_fmt_u32", "_make_function_return_probe_capture", "_verification_probe_entry_hook", "_verification_probe_return_hook"}
    namespace = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            exec(compile(ast.Module(body=[node], type_ignores=[]), "runtime", "exec"), namespace)

    class CPU:
        def __init__(self): self.hooks = {}
        def GetRegister(self, index):
            if index == 14: return type("Register", (), {"RawValue": 0x501})()
            raise RuntimeError("register unavailable")
        def AddHook(self, address, callback): self.hooks[address] = callback

    capture = namespace["_make_function_return_probe_capture"]({
        "label": "p", "symbol": "api", "return_register": "r0", "capture": "all",
    })
    namespace.update({
        "_verification_probe_state": {
            "entry_templates": {0x100: [{"label": "p", "symbol": "api", "return_register_index": 0, "probe_kind": "function_return"}]},
            "installed_return_hooks": set(), "active_frames": [], "captures": {"p": capture},
        },
        "log": lambda *args: None,
    })
    cpu = CPU()
    namespace["_verification_probe_entry_hook"](cpu, 0x101)
    cpu.hooks[0x500](cpu, 0x501)
    assert capture["raw_values"] == []
    assert capture["calls"][0]["register_read_error"] == "register unavailable"
