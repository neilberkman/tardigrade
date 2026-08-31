#!/usr/bin/env python3
"""Focused checks for the MCUboot STM32F4 writeback campaign profile."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


def test_mcuboot_scratch_stm32f4_writeback_profile() -> None:
    profile_path = ROOT / "profiles" / "mcuboot_head_scratch_stm32f4_writeback.yaml"
    raw = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile = load_profile(profile_path)

    assert raw["base_profile"] == "mcuboot_head_scratch_stm32f4_upgrade.yaml"
    assert raw["skip_self_test"] is True
    assert profile.name == "mcuboot_head_scratch_stm32f4_writeback"
    assert profile.platform == "platforms/stm32f4.repl"
    assert profile.fault_sweep.evaluation_mode == "execute"
    assert profile.fault_sweep.fault_types == ["power_loss"]
    assert profile.fault_sweep.durability_model == "writeback"
    assert profile.fault_sweep.writeback.buffer_capacity == "auto"
    assert profile.fault_sweep.writeback.erase_flushes_domain is False
    assert profile.fault_sweep.writeback.barriers == []
