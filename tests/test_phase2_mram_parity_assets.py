#!/usr/bin/env python3
"""Static checks for the phase-two MRAM Renode examples."""

from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "phase2_mram_parity"
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


def test_uncorrectable_profile_targets_one_phase_two_pair() -> None:
    profile = load_profile(EXAMPLE / "profile_uncorrectable.yaml")
    assert profile.fault_sweep.mram_torn_word == "uncorrectable"
    assert profile.fault_sweep.boot_cycles == 1
    assert profile.fault_sweep.phase2_fault.pairs == [(0, 1)]


def test_followup_profile_runs_hook_for_two_cycles() -> None:
    profile = load_profile(EXAMPLE / "profile_followup.yaml")
    assert profile.fault_sweep.mram_torn_word == "uncorrectable"
    assert profile.fault_sweep.boot_cycles == 2
    assert profile.fault_sweep.phase2_fault.pairs == [(0, 1)]
    assert profile.fault_sweep.boot_cycle_hook.endswith("phase2_mram_parity/hook.py")
    assert profile.state_probe.script.endswith("phase2_mram_parity/state_probe.py")


def test_state_search_profile_deduplicates_uncorrectable_states() -> None:
    profile = load_profile(EXAMPLE / "profile_state_search.yaml")
    search = profile.fault_sweep.phase2_fault.state_search
    assert profile.platform.endswith("cortex_m0_mram_tracked.repl")
    assert profile.flash_backend == "mramTracker"
    assert profile.fault_sweep.mram_torn_word == "uncorrectable"
    assert search.enabled is True
    assert search.first_cut_mode == "ranges"
    assert search.first_cut_ranges == [(0, 0), (2, 2)]
    assert search.max_cuts == 2
    assert search.cross_check_every == 1


def test_exec_slot_fixture_has_a_valid_cortex_m_vector() -> None:
    slot = (EXAMPLE / "slot.bin").read_bytes()
    stack_pointer, reset_vector = struct.unpack_from("<II", slot)
    assert stack_pointer == 0x20002000
    assert reset_vector & 1
    assert 0x10100000 <= (reset_vector & ~1) < 0x10100100
