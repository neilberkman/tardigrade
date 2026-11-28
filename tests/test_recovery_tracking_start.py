"""Recovery tracking configuration at the profile/runner boundary."""

from pathlib import Path
import sys

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
