#!/usr/bin/env python3
"""Generate a real NuttX nxboot tardigrade profile from public build outputs."""

from __future__ import annotations

import argparse
from pathlib import Path


SLOT_EXEC_BASE = 0x08040000
SLOT_STAGING_BASE = 0x080C0000
SLOT_TERTIARY_BASE = 0x08140000
SLOT_SIZE = 0x80000
BOOTLOADER_ENTRY = 0x08000000
SRAM_START = 0x20000000
SRAM_END = 0x240A0000
WRITE_GRANULARITY = 8


def render_runtime_profile(
    build_dir: Path,
    *,
    header_size: int = 0x400,
    fault_max_writes: str = "auto",
    boot_cycles: int = 2,
    run_duration: str = "8.0",
    name: str = "nuttx_nxboot_real_update",
) -> str:
    build_dir = build_dir.resolve()
    loader_elf = build_dir / "nxboot-loader.elf"
    primary_img = build_dir / "images" / "nxboot-primary-v1-h400.img"
    update_img = build_dir / "images" / "nxboot-update-v2-h400.img"

    for required in (loader_elf, primary_img, update_img):
        if not required.exists():
            raise FileNotFoundError(required)

    return """schema_version: 1
name: {name}
description: Real NuttX nxboot STM32H7 update profile generated from public build outputs
platform: platforms/nucleo_h753zi_tardigrade.repl
flash_backend: faultFlash
bootloader:
  elf: {loader_elf}
  entry: 0x{bootloader_entry:08X}
memory:
  sram: {{ start: 0x{sram_start:08X}, end: 0x{sram_end:08X} }}
  write_granularity: {write_granularity}
  slots:
    exec: {{ base: 0x{slot_exec_base:08X}, size: 0x{slot_size:05X} }}
    staging: {{ base: 0x{slot_staging_base:08X}, size: 0x{slot_size:05X} }}
    tertiary: {{ base: 0x{slot_tertiary_base:08X}, size: 0x{slot_size:05X} }}
images:
  exec: {primary_img}
  staging: {update_img}
extra_peripherals:
  - peripherals/STM32H7FlashController.cs
success_criteria:
  vtor_in_slot: exec
  vector_table_offset: 0x{header_size:X}
  image_hash: false
fault_sweep:
  mode: runtime
  max_writes: {fault_max_writes}
  evaluation_mode: execute
  run_duration: "{run_duration}"
  boot_cycles: {boot_cycles}
  expected_rollback_at_cycle: 1
state_probe:
  script: targets/nuttx_nxboot/probe.py
semantic_assertions:
  control:
    semantic_state.roles.primary_confirmed: false
    semantic_state.roles.recovery_valid: true
    semantic_state.roles.next_boot: revert
    semantic_state.slots.primary.magic_kind: internal
    multi_boot_analysis.final_outcome: success
    multi_boot_analysis.final_slot: exec
invariant_providers:
  - targets/nuttx_nxboot/invariants.py
invariants:
  - nuttx_nxboot_roles_distinct
  - nuttx_nxboot_confirmed_has_recovery
  - nuttx_nxboot_duplicate_update_consumed
  - nuttx_nxboot_unconfirmed_internal_requires_revert
  - successful_rollback
expect:
  should_find_issues: false
""".format(
        name=name,
        loader_elf=loader_elf,
        primary_img=primary_img,
        update_img=update_img,
        bootloader_entry=BOOTLOADER_ENTRY,
        sram_start=SRAM_START,
        sram_end=SRAM_END,
        write_granularity=WRITE_GRANULARITY,
        slot_exec_base=SLOT_EXEC_BASE,
        slot_staging_base=SLOT_STAGING_BASE,
        slot_tertiary_base=SLOT_TERTIARY_BASE,
        slot_size=SLOT_SIZE,
        header_size=int(header_size),
        fault_max_writes=fault_max_writes,
        boot_cycles=max(1, int(boot_cycles)),
        run_duration=str(run_duration),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-profile", type=Path, required=True)
    parser.add_argument("--header-size", type=lambda x: int(x, 0), default=0x400)
    parser.add_argument("--fault-max-writes", default="auto")
    parser.add_argument("--boot-cycles", type=int, default=2)
    parser.add_argument("--run-duration", default="8.0")
    parser.add_argument("--name", default="nuttx_nxboot_real_update")
    args = parser.parse_args()

    rendered = render_runtime_profile(
        args.build_dir,
        header_size=args.header_size,
        fault_max_writes=args.fault_max_writes,
        boot_cycles=args.boot_cycles,
        run_duration=args.run_duration,
        name=args.name,
    )
    args.output_profile.parent.mkdir(parents=True, exist_ok=True)
    args.output_profile.write_text(rendered)
    print(args.output_profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
