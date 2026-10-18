"""The clean-control gate only demands image_hash evidence in execute mode."""

from __future__ import annotations

import sys
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402
from sweep import _validate_runtime_control_result  # noqa: E402


def _profile(evaluation_mode):
    return SimpleNamespace(
        expect=SimpleNamespace(control_outcome="success"),
        success_criteria=SimpleNamespace(
            pc_in_slot="",
            vtor_in_slot="exec",
            image_hash=True,
            image_hash_slot="exec",
            expected_image="staging",
            allowed_images=[],
            marker_address=None,
            marker_value=None,
        ),
        fault_sweep=SimpleNamespace(evaluation_mode=evaluation_mode),
    )


def _state_mode_control_result():
    return {
        "boot_outcome": "success",
        "boot_slot": "exec",
        "signals": {
            "copy_completed": True,
            "vector_valid": True,
            "vector_base": "0x10002200",
        },
    }


class ControlGateEvaluationModeTest(unittest.TestCase):
    def test_state_mode_control_passes_without_hash_evidence(self) -> None:
        _validate_runtime_control_result(_profile(None), _state_mode_control_result())
        _validate_runtime_control_result(_profile("state"), _state_mode_control_result())

    def test_execute_mode_control_still_requires_hash_evidence(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            _validate_runtime_control_result(_profile("execute"), _state_mode_control_result())
        self.assertIn("image_hash was not confirmed", str(ctx.exception))

    def test_loader_warns_when_image_hash_is_declared_outside_execute_mode(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_profile(ROOT / "profiles" / "nxboot_style_no_recovery.yaml")
        messages = [str(w.message) for w in caught]
        self.assertTrue(
            any("image_hash is only evaluated" in m for m in messages), messages
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_profile(ROOT / "profiles" / "mcuboot_head_upgrade.yaml")
        self.assertFalse(
            any("image_hash is only evaluated" in str(w.message) for w in caught)
        )


if __name__ == "__main__":
    unittest.main()
