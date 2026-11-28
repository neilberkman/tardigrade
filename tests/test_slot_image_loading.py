# SPDX-License-Identifier: Apache-2.0
"""A slot declaration supplies geometry. Only an image declaration supplies bytes."""

import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import ProfileError, load_profile
from renode_runner import run_single_point


PROFILE = ROOT / "examples/phase2_mram_parity/profile_state_search_16_uncorrectable.yaml"


@pytest.mark.parametrize("value", [None, ""])
def test_loader_rejects_missing_image_path(tmp_path, value):
    data = yaml.safe_load(PROFILE.read_text())
    data["images"]["staging"] = value
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ProfileError, match=r"images\.staging"):
        load_profile(path)


def test_loader_rejects_image_with_no_slot_address(tmp_path):
    data = yaml.safe_load(PROFILE.read_text())
    del data["memory"]["slots"]["staging"]
    data["images"]["staging"] = data["images"]["exec"]
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ProfileError, match=r"images\.staging"):
        load_profile(path)


def test_slot_image_variables_cover_initial_load_and_reload():
    profile = load_profile(PROFILE)
    profile.pre_boot_state = []
    variables = dict(v.split(":", 1) for v in profile.robot_vars(ROOT))
    assert set(profile.images) == {"exec"}
    assert variables["IMAGE_EXEC"] == variables["IMAGE_EXEC_PATH"] == str(ROOT / profile.images["exec"])
    assert variables["IMAGE_STAGING_LOAD_ADDR"] == "0x10102000"
    assert variables["IMAGE_STAGING"] == variables["IMAGE_STAGING_PATH"] == ""


@pytest.mark.parametrize(
    "path,fill", [(PROFILE, 0x00), (ROOT / "examples/erase_before_program/profile.yaml", 0xFF)],
    ids=["mram", "flash"],
)
def test_undeclared_staging_reads_as_erased(tmp_path, path, fill):
    renode = shutil.which(os.environ.get("RENODE_TEST", "renode-test"))
    if renode is None:
        pytest.skip("renode-test is required for bus readback")
    profile = load_profile(path)
    slot = profile.memory.slots["staging"]
    dump = tmp_path / "staging.bin"
    probe = tmp_path / "read_staging.resc"
    probe.write_text(
        f"""python "System.IO.File.WriteAllBytes(r'{dump}', monitor.Machine.SystemBus.ReadBytes({slot.base}, {slot.size}))"\n"""
    )
    profile.setup_script = str(probe)
    variables = profile.robot_vars(ROOT)
    if not profile.images:
        # A caller supplying just geometry must also get safe suite defaults.
        variables = [var for var in variables if not var.startswith("IMAGE_") or not var.endswith(":")]
    try:
        run_single_point(
            ROOT, renode, str(ROOT / "tests/ota_fault_point.robot"), profile,
            -1, variables, tmp_path, "", is_control=True,
        )
    finally:
        for var in variables:
            if var.startswith("PRE_BOOT_STATE_BIN:"):
                Path(var.split(":", 1)[1]).unlink(missing_ok=True)
    assert dump.read_bytes() == bytes([fill]) * slot.size
