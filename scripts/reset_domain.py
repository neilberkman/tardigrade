#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write a Renode monitor include for the reset domains of a loaded platform."""

import argparse
from pathlib import Path

from profile_loader import ProfileConfig, ProfileError, load_profile


ROOT = Path(__file__).resolve().parents[1]

FAMILIES = {
    "cortex_m4_flash": "nrf52840",
    "cortex_m4_flash_fast": "nrf52840",
    "nrf52840_nvmc_psel": "nrf52840",
    "nrf52840_external_nvm": "nrf52840",
    "nrf52840_mcuboot_spi_nor": "nrf52840",
    "stm32f4": "stm32f4",
    "stm32f4_fast": "stm32f4",
    "stm32h743_fast": "stm32h7",
    "stm32h743_tardigrade": "stm32h7",
    "stm32h753_tardigrade": "stm32h7",
    "nucleo_h753zi_tardigrade": "stm32h7",
    "stm32f103": "stm32f1",
    "stm32l476": "stm32l4",
}


def reset_setup(profile: ProfileConfig) -> str:
    memory = profile.memory
    family = FAMILIES.get(Path(profile.platform).stem, "generic")
    if memory.vbat_present and not family.startswith("stm32"):
        raise ProfileError("memory.vbat_present requires a platform with a backup domain")
    commands = [
        f'include "{ROOT}/peripherals/PowerResetDomain.cs"',
        f'machine LoadPlatformDescription "{ROOT}/platforms/reset/{family}.repl"',
        f"powerDomain VbatPresent {str(bool(memory.vbat_present)).lower()}",
    ]

    # Split the union into disjoint spans. Retained subranges inside ordinary
    # SRAM use their own fill and may cross adjacent declared RAM banks.
    ranges = [(memory.sram_start, memory.sram_end, 0)]
    ranges.extend((r.base, r.base + r.size, 0) for r in memory.volatile_regions)
    retained = [(r.base, r.base + r.size, r.power_loss_fill) for r in memory.retained_regions]
    all_ranges = ranges + retained
    if any(not 0 <= start < end <= 1 << 32 for start, end, _ in all_ranges):
        raise ProfileError("reset memory requires nonempty 32-bit ranges")
    boundaries = sorted({addr for start, end, _ in all_ranges for addr in (start, end)})
    for start, end in zip(boundaries, boundaries[1:]):
        fills = [fill for lo, hi, fill in all_ranges if lo <= start and end <= hi]
        if not fills:
            continue
        if any(start < slot.base + slot.size and slot.base < end for slot in memory.slots.values()):
            raise ProfileError("reset RAM overlaps a persistent slot")
        commands.append(f"powerDomain AddRetainedRegion {start:#x} {end-start:#x} {fills[-1]:#x}")
    return "\n".join(commands) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        commands = reset_setup(load_profile(args.profile))
    except ProfileError as error:
        parser.error(str(error))
    args.output.write_text(commands, encoding="utf-8")


if __name__ == "__main__":
    main()
