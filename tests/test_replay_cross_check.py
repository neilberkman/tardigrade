# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import ProfileError, load_profile  # noqa: E402
from replay_cross_check import (  # noqa: E402
    ReplayCrossCheckError,
    first_pre_cut_trace_difference,
    replay_cross_check_selected,
)


def test_sample_selection_is_stable_across_batches_and_zero_disables():
    points = [0, 1, 99, 100, 101, 200]
    assert [point for point in points if replay_cross_check_selected(point, 100)] == [
        0,
        100,
        200,
    ]
    assert not any(replay_cross_check_selected(point, 0) for point in points)
    with pytest.raises(ReplayCrossCheckError, match="non-negative"):
        replay_cross_check_selected(0, -1)


def test_pre_cut_write_divergence_names_the_first_different_operation():
    expected = [
        (1, 0x10, 0x11111111, 4),
        (2, 0x14, 0x22222222, 4),
        (3, 0x18, 0x33333333, 4),
    ]
    observed = [
        (1, 0x10, 0x11111111, 4),
        (2, 0x24, 0x22222222, 4),
    ]
    difference = first_pre_cut_trace_difference(
        "write", 2, expected, observed
    )
    assert difference["kind"] == "pre_cut_execution_diverged"
    assert difference["operation"] == "write"
    assert difference["sequence_position"] == 1
    assert difference["expected"]["offset"] == "0x14"
    assert difference["observed"]["offset"] == "0x24"


def test_pre_cut_erase_prefix_is_compared():
    writes = [(1, 0x10, 1, 4), (2, 0x14, 2, 4)]
    expected_erases = [(0x100, 1, 0x1000), (0x200, 2, 0x1000)]
    observed_erases = [(0x180, 1, 0x1000)]
    difference = first_pre_cut_trace_difference(
        "erase",
        1,
        writes,
        writes,
        expected_erases,
        observed_erases,
    )
    assert difference["operation"] == "erase"
    assert difference["expected"]["offset"] == "0x100"
    assert difference["observed"]["offset"] == "0x180"


def test_profile_cross_check_interval_defaults_and_validates(tmp_path):
    base = textwrap.dedent(
        """
        schema_version: 1
        name: replay_check_config
        platform: platforms/cortex_m4_flash_fast.repl
        bootloader:
          elf: examples/recovery_vector_fault/firmware.elf
          entry: 0x10000000
        memory:
          sram: { start: 0x20000000, end: 0x20002000 }
          write_granularity: 4
          page_size: 0x1000
          slots:
            exec: { base: 0x10000000, size: 0x1000 }
            staging: { base: 0x10001000, size: 0x1000 }
        flash_backend: faultFlash
        success_criteria:
          vtor_in_slot: exec
        fault_sweep:
          fault_types: [power_loss]
          evaluation_mode: execute
        """
    ).lstrip()
    default_path = tmp_path / "default.yaml"
    default_path.write_text(base)
    default = load_profile(default_path)
    assert default.fault_sweep.trace_replay_cross_check_every == 100
    assert "TRACE_REPLAY_CROSS_CHECK_EVERY:100" in default.robot_vars(ROOT)

    disabled_path = tmp_path / "disabled.yaml"
    disabled_path.write_text(
        base.replace("fault_sweep:\n", "fault_sweep:\n  trace_replay_cross_check_every: 0\n", 1)
    )
    assert load_profile(disabled_path).fault_sweep.trace_replay_cross_check_every == 0

    invalid_path = tmp_path / "invalid.yaml"
    invalid_path.write_text(
        base.replace("fault_sweep:\n", "fault_sweep:\n  trace_replay_cross_check_every: -1\n", 1)
    )
    with pytest.raises(ProfileError, match="trace_replay_cross_check_every"):
        load_profile(invalid_path)
