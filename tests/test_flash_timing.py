# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from profile_loader import ProfileError, load_profile


def config(tmp_path, timing, **sweep):
    base = ROOT / "profiles/mcuboot_stm32f4_upgrade.yaml"
    profile = yaml.safe_load(base.read_text())
    profile["fault_sweep"].update(max_writes=0, sweep_hash_bypass_symbols=[])
    profile["fault_sweep"].update(sweep)
    profile["memory"]["flash_timing"] = timing
    dest = tmp_path / "control.yaml"
    dest.write_text(yaml.safe_dump(profile))
    return load_profile(dest, strict=True)


@pytest.mark.parametrize(
    ("value", "variable"),
    [("off", None), (False, None), ("typical", "typical"), ("maximum", "maximum"),
     ({"program_us": 6, "erase_us": 850}, "6,850")],
)
def test_control_timing_reaches_robot(tmp_path, value, variable):
    profile = config(tmp_path, value)
    assert [v for v in profile.robot_vars(ROOT) if v.startswith("FLASH_TIMING:")] == (
        [] if variable is None else ["FLASH_TIMING:" + variable]
    )


@pytest.mark.parametrize("value", ["max", True, {"program_us": 5}, {"program_us": 0, "erase_us": 10}])
def test_unknown_timing_rejected(tmp_path, value):
    with pytest.raises(ProfileError, match="memory.flash_timing"):
        config(tmp_path, value)


@pytest.mark.parametrize(
    ("profile_rel", "max_writes"),
    [
        ("profiles/mcuboot_stm32f4_upgrade.yaml", 0),
        ("profiles/mcuboot_stm32f4_upgrade.yaml", 4),
        ("profiles/mcuboot_stm32f4_upgrade.yaml", "auto"),
        ("profiles/mcuboot_offset_upgrade.yaml", "auto"),
        ("profiles/mcuboot_stm32f103_upgrade.yaml", "auto"),
        ("profiles/mcuboot_stm32l476_upgrade.yaml", "auto"),
    ],
)
@pytest.mark.parametrize("timing", ["off", "typical", "maximum"])
def test_flash_timing_accepted_for_controls_and_full_sweeps(tmp_path, profile_rel, max_writes, timing):
    base = ROOT / profile_rel
    profile_data = yaml.safe_load(base.read_text())
    profile_data.setdefault("memory", {})["flash_timing"] = timing
    profile_data.setdefault("fault_sweep", {})["max_writes"] = max_writes
    if max_writes == 0:
        profile_data["fault_sweep"]["sweep_hash_bypass_symbols"] = []
    dest = tmp_path / base.name
    dest.write_text(yaml.safe_dump(profile_data))
    loaded = load_profile(dest, strict=True)
    expected = [] if timing == "off" else [f"FLASH_TIMING:{timing}"]
    assert [v for v in loaded.robot_vars(ROOT) if v.startswith("FLASH_TIMING:")] == expected


@pytest.mark.parametrize("sweep", [{"mode": "batch"}, {"evaluation_mode": "state"}])
def test_flash_timing_requires_runtime_execute_profile(tmp_path, sweep):
    with pytest.raises(ProfileError, match="runtime execute"):
        config(tmp_path, "maximum", **sweep)


def test_stm32f1_and_stm32l4_flash_models_and_docs_define_datasheet_timing():
    f1_cs = (ROOT / "peripherals/STM32F1FlashController.cs").read_text(encoding="utf-8")
    l4_cs = (ROOT / "peripherals/STM32L4FlashController.cs").read_text(encoding="utf-8")
    nrf_cs = (ROOT / "peripherals/NRF52NVMC.cs").read_text(encoding="utf-8")
    docs = (ROOT / "docs/flash-timing.md").read_text(encoding="utf-8")

    # STM32F103: DS5319 Table 28 (tprog 52.5/70 us -> 53/70 us, tERASE/tME 20/40 ms)
    assert "public FlashTiming OperationTiming" in f1_cs
    assert "(sr & ~SrBsyBit) | (operation.Busy ? SrBsyBit : 0u)" in f1_cs
    assert "F1ProgTypMicros = 53UL;" in f1_cs
    assert "F1ProgMaxMicros = 70UL;" in f1_cs
    assert "F1EraseTypMicros = 20000UL;" in f1_cs
    assert "F1EraseMaxMicros = 40000UL;" in f1_cs

    # STM32L476: DS10198 Table 63 (tprog 81.69/90.76 us -> 82/91 us,
    # tprog_row 1.91/2.12 ms -> 1910/2120 us, tERASE 22.02/24.47 ms -> 22020/24470 us,
    # tME 22.13/24.59 ms -> 22130/24590 us)
    assert "public FlashTiming OperationTiming" in l4_cs
    assert "(sr & ~SrBsyBit) | (operation.Busy ? SrBsyBit : 0u)" in l4_cs
    assert "L4ProgTypMicros = 82UL;" in l4_cs
    assert "L4ProgMaxMicros = 91UL;" in l4_cs
    assert "L4FastRowProgTypMicros = 1910UL;" in l4_cs
    assert "L4FastRowProgMaxMicros = 2120UL;" in l4_cs
    assert "L4PageEraseTypMicros = 22020UL;" in l4_cs
    assert "L4PageEraseMaxMicros = 24470UL;" in l4_cs
    assert "L4MassEraseTypMicros = 22130UL;" in l4_cs
    assert "L4MassEraseMaxMicros = 24590UL;" in l4_cs

    # nRF52840 accepts both Typical and Maximum using published 41 us / 85 ms / 169 ms
    assert 'throw new ArgumentException("nRF52840 specifies maximum program and erase times only")' not in nrf_cs

    # Documentation cites RM0008 / DS5319 Table 28 and RM0351 / DS10198 Table 63
    assert "RM0008" in docs and "DS5319" in docs and "Table 28" in docs
    assert "RM0351" in docs and "DS10198" in docs and "Table 63" in docs
