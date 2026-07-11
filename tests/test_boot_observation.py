"""Tests for the generic campaign's polling boot oracle."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from boot_observation import poll_boot  # noqa: E402


class Scenario:
    def __init__(self, pcs, markers=None, vtors=None):
        self.pcs = list(pcs)
        self.markers = list(markers or [0] * len(self.pcs))
        self.vtors = list(vtors or [0] * len(self.pcs))
        self.index = 0

    def run(self, _duration):
        self.index = min(self.index + 1, len(self.pcs) - 1)

    def pc(self):
        return self.pcs[self.index]

    def marker(self):
        return self.markers[self.index]

    def vtor(self):
        return self.vtors[self.index]


def classify_pc(value):
    if 0x10002000 <= value < 0x10039000:
        return "A"
    if 0x10039000 <= value < 0x10070000:
        return "B"
    return None


def classify_vtor(value):
    return classify_pc(value)


def observe(scenario, *, control=False, timeout=2.0, interval=0.02, clock=None):
    return poll_boot(
        run_slice=scenario.run,
        read_pc=scenario.pc,
        read_vtor=scenario.vtor,
        read_marker=scenario.marker,
        classify_pc=classify_pc,
        classify_vtor=classify_vtor,
        is_control=control,
        expected_slot="A",
        marker_value=0x534C4F42,
        emulated_timeout_s=timeout,
        poll_interval_s=interval,
        wall_timeout_s=10.0,
        clock=clock,
    )


def test_handoff_after_old_half_second_window_is_observed() -> None:
    scenario = Scenario([0x10000040] * 30 + [0x10002040])
    result = observe(scenario, timeout=2.0, interval=0.02)
    assert result["reason"] == "pc_handoff"
    assert result["emulated_s"] > 0.5
    assert result["pc_sticky_slot"] == "A"


def test_transient_pc_handoff_survives_later_wfi_zero() -> None:
    scenario = Scenario(
        [0x10000040, 0x10002040, 0],
        markers=[0, 0, 0x534C4F42],
    )
    result = observe(scenario, control=True, interval=0.1)
    assert result["reason"] == "control_complete"
    assert result["pc_final"] == "0x00000000"
    assert result["pc_sticky"] == "0x10002040"


def test_control_waits_for_marker_after_pc_handoff() -> None:
    scenario = Scenario(
        [0x10000040, 0x10002040, 0x10002040, 0x10002040],
        markers=[0, 0, 0, 0x534C4F42],
    )
    result = observe(scenario, control=True, interval=0.1)
    assert result["reason"] == "control_complete"
    assert result["emulated_s"] == 0.3
    assert result["marker_ok"] is True


def test_no_signal_consumes_full_emulated_budget() -> None:
    scenario = Scenario([0x10000040] * 20)
    result = observe(scenario, timeout=1.0, interval=0.1)
    assert result["reason"] == "emulated_timeout"
    assert result["emulated_s"] == 1.0
    assert result["infrastructure_error"] is None


def test_wall_timeout_is_infrastructure_not_no_boot() -> None:
    scenario = Scenario([0x10000040] * 4)
    values = iter([0.0, 11.0, 11.0])
    result = observe(scenario, clock=lambda: next(values))
    assert result["reason"] == "wall_timeout"
    assert result["emulated_s"] == 0.0
    assert "wall-clock" in result["infrastructure_error"]


def test_wrong_slot_does_not_satisfy_control() -> None:
    scenario = Scenario(
        [0x10000040, 0x10039040, 0x10039040],
        markers=[0, 0x534C4F42, 0x534C4F42],
    )
    result = observe(scenario, control=True, timeout=0.2, interval=0.1)
    assert result["reason"] == "emulated_timeout"
    assert result["pc_sticky_slot"] == "B"
