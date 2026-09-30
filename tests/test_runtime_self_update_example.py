from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "runtime_self_update"
sys.path.insert(0, str(ROOT / "scripts"))

from profile_loader import load_profile  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _build_runtime_self_update_fixture():
    if shutil.which("arm-none-eabi-gcc") is None:
        pytest.skip("arm-none-eabi-gcc is not installed")
    subprocess.run(
        ["make", "-C", str(FIXTURE), "clean", "all"],
        cwd=ROOT,
        check=True,
    )


def _symbol_address(elf: Path, symbol: str) -> int:
    nm = shutil.which("arm-none-eabi-nm")
    if nm is None:
        pytest.skip("arm-none-eabi-nm is not installed")
    output = subprocess.check_output([nm, "-n", str(elf)], text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == symbol:
            return int(fields[0], 16)
    raise AssertionError("missing symbol {!r} in {}".format(symbol, elf))


def test_profile_uses_reset_gated_full_success_and_automatic_step_limit():
    profile = load_profile(FIXTURE / "profile.yaml", strict=True)

    assert profile.success_criteria.terminal_after_reset is True
    assert profile.success_criteria.pc_in_slot == "exec"
    assert profile.success_criteria.image_hash is True
    assert profile.success_criteria.allowed_images == ["exec", "staging"]
    assert len(profile.success_criteria.memory_checks) == 2
    assert profile.fault_sweep.max_step_limit is None
    assert profile.memory.write_granularity == 16
    assert profile.bootloader_entry == 0
    assert "MAX_STEP_LIMIT:0" in profile.robot_vars(ROOT)


@pytest.mark.parametrize(
    "profile_name,exec_name,staging_name",
    [
        ("profile_no_reset.yaml", "no_reset.bin", "update.bin"),
        ("profile_hung_update.yaml", "old.bin", "hung_update.bin"),
    ],
)
def test_negative_profiles_require_timeout(
    profile_name: str, exec_name: str, staging_name: str
):
    profile = load_profile(FIXTURE / profile_name, strict=True)

    assert profile.success_criteria.terminal_after_reset is True
    assert profile.fault_sweep.max_step_limit == 2_000_000
    assert profile.images["exec"] == "examples/runtime_self_update/{}".format(
        exec_name
    )
    assert profile.images["staging"] == (
        "examples/runtime_self_update/{}".format(staging_name)
    )


def test_fixture_boundaries_match_built_ram_functions():
    profile = load_profile(FIXTURE / "profile.yaml", strict=True)
    old_elf = FIXTURE / "old.elf"

    assert profile.fault_sweep.tracking_start_address == _symbol_address(
        old_elf, "copy_update"
    )
    assert profile.fault_sweep.calibration_stop.address == _symbol_address(
        old_elf, "request_reset"
    )


def test_fixture_images_preserve_reset_entry_but_change_noncritical_vectors():
    old = (FIXTURE / "old.bin").read_bytes()
    update = (FIXTURE / "update.bin").read_bytes()

    assert len(old) == 0x1000
    assert len(update) == 0x1000
    assert old != update
    assert struct.unpack_from("<I", old, 4) == struct.unpack_from("<I", update, 4)
    assert struct.unpack_from("<I", old, 8) != struct.unpack_from("<I", update, 8)
    assert struct.unpack_from("<I", old, 16) != struct.unpack_from("<I", update, 16)
    assert (FIXTURE / "no_reset.bin").read_bytes() != update
    assert (FIXTURE / "hung_update.bin").read_bytes() != update
