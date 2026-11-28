# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from profile_loader import ProfileError, load_profile


def profile_with(tmp_path, fields, *, strict=False):
    base = ROOT / "examples/volatile_marker_recovery/profile.yaml"
    text = base.read_text().replace("memory:\n", "memory:\n" + fields + "\n")
    path = tmp_path / "profile.yaml"
    path.write_text(text)
    return load_profile(path, strict=strict)


def test_retained_ranges_split_sram_and_accept_separate_bank(tmp_path):
    profile = profile_with(tmp_path, """  retained_regions:
    - {base: 0x20000001, size: 2, fill: 0xa5}
    - {base: 0x21000000, size: 4}
  volatile_regions:
    - {base: 0x20000000, size: 0x1000}""", strict=True)
    from reset_domain import reset_setup

    assert reset_setup(profile).splitlines()[3:] == [
        "powerDomain AddRetainedRegion 0x20000000 0x1 0x0",
        "powerDomain AddRetainedRegion 0x20000001 0x2 0xa5",
        "powerDomain AddRetainedRegion 0x20000003 0xffd 0x0",
        "powerDomain AddRetainedRegion 0x20001000 0x1000 0x0",
        "powerDomain AddRetainedRegion 0x21000000 0x4 0x0",
    ]


@pytest.mark.parametrize("fields, message", [
    ("  retained_regions: [{base: 0, size: 0}]", "invalid 32-bit range"),
    ("  retained_regions: [{base: 0xffffffff, size: 2}]", "invalid 32-bit range"),
    ("  retained_regions: [{base: 0, size: 2}, {base: 1, size: 1}]", "overlapping"),
    ("  retained_regions: [{base: 0, size: 1, fill: 256}]", "fill"),
    ("  retained_regions: [{base: 0, size: 1, fill: true}]", "fill"),
    ("  retained_regions: [{base: 0, size: 1, erase_size: 1}]", "unknown field"),
    ('  vbat_present: "false"', "expected boolean"),
])
def test_invalid_reset_settings_refused_in_permissive_profiles(tmp_path, fields, message):
    with pytest.raises(ProfileError, match=message):
        profile_with(tmp_path, fields)


def test_sweep_serializes_retained_regions_and_vbat(tmp_path):
    import base64
    import json

    profile = profile_with(
        tmp_path,
        """  retained_regions:
    - {name: boot_flag, base: 0x20000200, size: 4, fill: 0xa5}
  vbat_present: false""",
    )
    rv = dict(item.split(":", 1) for item in profile.robot_vars(ROOT))
    assert rv["VBAT_PRESENT"] == "false"
    decoded = json.loads(base64.b64decode(rv["RETAINED_REGIONS_B64"]).decode("utf-8"))
    assert decoded == [
        {"name": "boot_flag", "base": 0x20000200, "size": 4, "fill": 0xA5}
    ]


def test_sweep_robot_vars_refuses_invalid_vbat_or_persistent_slot(tmp_path):
    profile_vbat = profile_with(tmp_path, "  vbat_present: true")
    with pytest.raises(ProfileError, match="backup domain"):
        profile_vbat.robot_vars(ROOT)

    profile_slot = profile_with(
        tmp_path, "  retained_regions: [{base: 0x10000000, size: 4}]"
    )
    with pytest.raises(ProfileError, match="persistent slot"):
        profile_slot.robot_vars(ROOT)


def test_reset_cause_example_profiles_load_and_build_robot_vars():
    for name, expected_vbat in (("nrf52840.yaml", ""), ("stm32f4.yaml", "false")):
        profile = load_profile(ROOT / "examples" / "reset_cause" / name, repo_root=ROOT)
        rv = dict(item.split(":", 1) for item in profile.robot_vars(ROOT))
        assert rv.get("VBAT_PRESENT", "") == expected_vbat
        assert rv["RETAINED_REGIONS_B64"] != ""


def test_sweep_power_domain_lifecycle_and_reset_kind_reporting():
    import ast

    sweep_path = ROOT / "scripts" / "run_runtime_fault_sweep.py"
    source = sweep_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(sweep_path))
    wanted = {
        "_set_next_reset_kind",
        "_reset_trial_boot_history",
        "_sync_boot_reset_kinds_from_domain",
        "_before_machine_reset",
        "_after_machine_reset",
        "_machine_reset",
        "build_cycle_record",
        "annotate_boot_span_result",
    }
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    module = ast.Module(body=selected, type_ignores=[])

    events = []

    class FakeDomain:
        def __init__(self):
            self.BootCount = 0

        def StartTrial(self):
            self.BootCount = 0
            events.append("start_trial")

        def PreparePowerOn(self):
            events.append("prepare_power_on")

        def BeginPowerLoss(self):
            events.append("power_lost")

        def EndPowerLoss(self):
            events.append("power_restored")

    domain = FakeDomain()

    class FakeMonitor:
        def Parse(self, cmd):
            assert cmd == "machine Reset"
            events.append("machine_reset")
            domain.BootCount += 1

    namespace = {
        "power_domain": domain,
        "monitor": FakeMonitor(),
        "_next_reset_kind": "power_on",
        "_current_boot_reset_kind": "power_on",
        "_trial_boot_reset_kinds": [],
        "_set_preserve_counters_across_reset": lambda _flag: None,
        "refresh_runtime_handles": lambda: None,
        "_configure_tracking_start_address": lambda _addr: None,
        "_configure_python_tracking_gate": lambda **_kw: None,
        "reset_sticky_handoff_state": lambda: None,
        "collect_semantic_state": lambda _ctx: None,
        "log": lambda _msg: None,
    }
    exec(compile(module, str(sweep_path), "exec"), namespace)

    # Trial starts with power_on reset.
    namespace["_reset_trial_boot_history"]("power_on")
    namespace["_machine_reset"](apply_tracking_gate=True)
    assert events == ["start_trial", "prepare_power_on", "machine_reset"]
    assert namespace["_trial_boot_reset_kinds"] == ["power_on"]

    # Simulate an in-run software/watchdog reset inside Renode during Phase 1.
    domain.BootCount += 1

    # Power-loss cut triggers Phase 2 recovery reset.
    namespace["_machine_reset"](apply_tracking_gate=False)
    assert events == [
        "start_trial",
        "prepare_power_on",
        "machine_reset",
        "power_lost",
        "machine_reset",
        "power_restored",
    ]
    assert namespace["_trial_boot_reset_kinds"] == [
        "power_on",
        "warm",
        "power_loss",
    ]
    cycle0 = namespace["build_cycle_record"](0, "success", "exec", {})
    assert cycle0["reset_kind"] == "power_loss"
    assert cycle0["signals"]["reset_kind"] == "power_loss"

    # Follow-up boot cycle uses warm reset.
    namespace["_set_next_reset_kind"]("warm")
    namespace["_machine_reset"](apply_tracking_gate=False)
    cycle1 = namespace["build_cycle_record"](1, "success", "exec", {})
    assert cycle1["reset_kind"] == "warm"

    annotated = namespace["annotate_boot_span_result"](
        {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "boot_cycles": [cycle0, cycle1],
        }
    )
    assert annotated["boot_reset_kinds"] == [
        "power_on",
        "warm",
        "power_loss",
        "warm",
    ]
    assert annotated["initial_reset_kind"] == "power_on"
    assert annotated["final_reset_kind"] == "warm"
    assert annotated["reset_kind"] == "warm"


def test_present_battery_requires_a_backup_domain(tmp_path):
    profile = profile_with(tmp_path, "  vbat_present: true")
    from reset_domain import reset_setup

    with pytest.raises(ProfileError, match="backup domain"):
        reset_setup(profile)


def test_reset_setup_refuses_persistent_slot(tmp_path):
    profile = profile_with(tmp_path, "  retained_regions: [{base: 0x10000000, size: 4}]")
    from reset_domain import reset_setup

    with pytest.raises(ProfileError, match="persistent slot"):
        reset_setup(profile)
