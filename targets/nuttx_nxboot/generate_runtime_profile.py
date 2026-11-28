#!/usr/bin/env python3
"""Generate a real NuttX nxboot tardigrade profile from public build outputs."""

from __future__ import annotations

import argparse
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SLOT_EXEC_BASE = 0x08040000
SLOT_STAGING_BASE = 0x080C0000
SLOT_TERTIARY_BASE = 0x08140000
SLOT_SIZE = 0x80000
BOOTLOADER_ENTRY = 0x08000000
# NuttX places the loader stack in AXI SRAM.  Keep the primary SRAM interval
# contiguous and exactly aligned with the Renode platform mapping; the STM32H7
# RAM banks below are disjoint and are declared separately for cold-recovery
# clearing rather than pretending the address holes are writable memory.
SRAM_START = 0x24000000
SRAM_END = 0x24080000
VOLATILE_REGIONS = (
    ("dtcm", 0x20000000, 0x20000),
    ("sram1", 0x30000000, 0x20000),
    ("sram2", 0x30020000, 0x20000),
    ("sram3", 0x30040000, 0x8000),
    ("sram4", 0x38000000, 0x10000),
)
WRITE_GRANULARITY = 8
# STM32H743/H753 platform files map two 1 MiB flash banks at these bases;
# STM32H7FlashController models each bank as 128 KiB erase sectors.
FLASH_BANK1_BASE = 0x08000000
FLASH_BANK2_BASE = 0x08100000
FLASH_BANK_SIZE = 0x100000
ERASE_SECTOR_SIZE = 0x20000
CAMPAIGNS = {
    "baseline": {
        "image_suffix": "",
        "default_fault_types": "",
        "default_boot_cycles": 2,
        "description": "ordinary update and recovery control",
    },
    "sector_boundary_resume": {
        "image_suffix": "-sector-boundary",
        "default_fault_types": "swap_progress",
        "default_boot_cycles": 3,
        "description": (
            "resume campaign with the update image padded to the next "
            "STM32H7 erase-sector boundary and a three-boot recovery sequence"
        ),
    },
    "metadata_erase_resume": {
        "image_suffix": "",
        "default_fault_types": "swap_progress,interrupted_erase",
        "default_boot_cycles": 3,
        "description": (
            "metadata and erase interruption campaign covering critical "
            "slot-metadata transitions and partially completed erase recovery"
        ),
    },
    "sector_boundary_writeback": {
        "image_suffix": "-sector-boundary",
        "default_fault_types": "power_loss",
        "default_boot_cycles": 3,
        "description": (
            "three-boot writeback campaign using the sector-boundary update "
            "image and STM32H7 sector geometry"
        ),
        "durability_model": "writeback",
        "writeback_buffer_capacity": "auto",
        "writeback_erase_flushes_domain": False,
    },
    "state_search": {
        "image_suffix": "",
        "default_fault_types": "power_loss",
        "default_boot_cycles": 3,
        "description": (
            "recovery-state search campaign across write and erase cuts with "
            "mixed torn-word outcomes and live cross-checks"
        ),
        "include_erase_fault_points": True,
        "torn_word": "[fixed, untouched, programmed, { partial_bits: 3 }]",
        "torn_word_seed": 20261127,
        "state_search": {
            "first_fault_types": ["power_loss", "interrupted_erase"],
            "fault_types": ["power_loss", "interrupted_erase"],
            "max_cuts": 3,
            "max_new_states": 384,
            "max_wall_time_s": 3600,
            "cross_check_every": 16,
        },
    },
    "state_search_sector_boundary": {
        "image_suffix": "-sector-boundary",
        "default_fault_types": "power_loss",
        "default_boot_cycles": 3,
        "description": (
            "recovery-state search campaign with sector-boundary update image "
            "across write and erase cuts, mixed torn-word outcomes, and live "
            "cross-checks"
        ),
        "include_erase_fault_points": True,
        "torn_word": "[fixed, untouched, programmed, { partial_bits: 3 }]",
        "torn_word_seed": 20261127,
        "state_search": {
            "first_fault_types": ["power_loss", "interrupted_erase"],
            "fault_types": ["power_loss", "interrupted_erase"],
            "max_cuts": 3,
            "max_new_states": 384,
            "max_wall_time_s": 3600,
            "cross_check_every": 16,
        },
    },
}


def render_runtime_profile(
    build_dir: Path,
    *,
    header_size: int = 0x400,
    fault_max_writes: str = "auto",
    boot_cycles: int | None = None,
    run_duration: str = "8.0",
    calibration_time_slice: str = "0.1",
    progress_stall_timeout_s: float = 4.0,
    max_step_limit: int = 1_000_000_000,
    name: str = "nuttx_nxboot_real_update",
    fault_types: str = "",
    campaign: str = "baseline",
    state_search_max_cuts: int | None = None,
    state_search_max_new_states: int | None = None,
    state_search_max_wall_time_s: float | None = None,
    state_search_cross_check_every: int | None = None,
) -> str:
    try:
        campaign_config = CAMPAIGNS[campaign]
    except KeyError as exc:
        raise ValueError(
            "unsupported NuttX nxboot campaign: {} (choose {})".format(
                campaign, ", ".join(sorted(CAMPAIGNS))
            )
        ) from exc
    build_dir = build_dir.resolve()
    loader_elf = build_dir / "nxboot-loader.elf"
    image_suffix = campaign_config["image_suffix"]
    primary_img = build_dir / "images" / (
        "nxboot-primary-v1-h400{}.img".format(image_suffix)
    )
    update_img = build_dir / "images" / (
        "nxboot-update-v2-h400{}.img".format(image_suffix)
    )

    for required in (loader_elf, primary_img, update_img):
        if not required.exists():
            raise FileNotFoundError(required)
        if required != loader_elf and required.stat().st_size > SLOT_SIZE:
            raise ValueError(
                "{} is larger than the declared nxboot slot (0x{:X} bytes)".format(
                    required, SLOT_SIZE
                )
            )

    selected_fault_types = fault_types or campaign_config["default_fault_types"]
    selected_boot_cycles = (
        int(campaign_config["default_boot_cycles"])
        if boot_cycles is None
        else int(boot_cycles)
    )
    try:
        observation_budget_s = float(run_duration)
        stall_timeout_s = float(progress_stall_timeout_s)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "run_duration and progress_stall_timeout_s must be numeric"
        ) from exc
    if stall_timeout_s <= 0 or stall_timeout_s >= observation_budget_s:
        raise ValueError(
            "progress_stall_timeout_s must be positive and less than run_duration"
        )
    durability_model = campaign_config.get("durability_model")
    writeback_block = ""
    if durability_model == "writeback":
        writeback_block = (
            "\n  durability_model: writeback"
            "\n  writeback:"
            "\n    buffer_capacity: {}"
            "\n    erase_flushes_domain: {}".format(
                campaign_config.get("writeback_buffer_capacity", "auto"),
                str(campaign_config.get("writeback_erase_flushes_domain", False)).lower(),
            )
        )
    if campaign_config.get("include_erase_fault_points"):
        writeback_block += "\n  include_erase_fault_points: true"
    if campaign_config.get("torn_word"):
        writeback_block += "\n  torn_word: {}".format(campaign_config["torn_word"])
        if campaign_config.get("torn_word_seed") is not None:
            writeback_block += "\n  torn_word_seed: {}".format(
                int(campaign_config["torn_word_seed"])
            )
    state_search_cfg = campaign_config.get("state_search")
    if isinstance(state_search_cfg, dict):
        ss_first = ", ".join(state_search_cfg.get("first_fault_types", ["power_loss"]))
        ss_deeper = ", ".join(state_search_cfg.get("fault_types", ["power_loss"]))
        ss_max_cuts = (
            int(state_search_max_cuts)
            if state_search_max_cuts is not None
            else int(state_search_cfg.get("max_cuts", 2))
        )
        ss_max_states = (
            int(state_search_max_new_states)
            if state_search_max_new_states is not None
            else int(state_search_cfg.get("max_new_states", 384))
        )
        ss_max_wall = (
            float(state_search_max_wall_time_s)
            if state_search_max_wall_time_s is not None
            else float(state_search_cfg.get("max_wall_time_s", 3600))
        )
        ss_cross_check = (
            int(state_search_cross_check_every)
            if state_search_cross_check_every is not None
            else int(state_search_cfg.get("cross_check_every", 16))
        )
        addr_range_lines = []
        for slot_base in (SLOT_EXEC_BASE, SLOT_STAGING_BASE, SLOT_TERTIARY_BASE):
            slot_end = slot_base + SLOT_SIZE
            addr_range_lines.append(
                "        - {{ start: 0x{:08X}, end: 0x{:08X} }}".format(
                    slot_base, slot_base + int(header_size)
                )
            )
            addr_range_lines.append(
                "        - {{ start: 0x{:08X}, end: 0x{:08X} }}".format(
                    slot_end - 0x1000, slot_end
                )
            )
        writeback_block += (
            "\n  phase2_fault:"
            "\n    enabled: true"
            "\n    first_fault_types: [{}]"
            "\n    fault_types: [{}]"
            "\n    state_search:"
            "\n      enabled: true"
            "\n      max_cuts: {}"
            "\n      max_new_states: {}"
            "\n      max_wall_time_s: {}"
            "\n      address_ranges:"
            "\n{}"
            "\n      cross_check_every: {}".format(
                ss_first,
                ss_deeper,
                ss_max_cuts,
                ss_max_states,
                ss_max_wall,
                "\n".join(addr_range_lines),
                ss_cross_check,
            )
        )

    def _rel_or_abs(path: Path) -> str:
        resolved = path.resolve()
        try:
            return resolved.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            pass
        if "instruction_skip" not in selected_fault_types:
            try:
                return resolved.relative_to(build_dir).as_posix()
            except ValueError:
                pass
        return resolved.as_posix()

    return """schema_version: 1
name: {name}
description: Real NuttX nxboot STM32H7 {campaign_description}
platform: platforms/nucleo_h753zi_tardigrade.repl
flash_backend: faultFlash
bootloader:
  elf: {loader_elf}
  entry: 0x{bootloader_entry:08X}
memory:
  sram: {{ start: 0x{sram_start:08X}, end: 0x{sram_end:08X} }}
  volatile_regions:
{volatile_regions}
  write_granularity: {write_granularity}
  page_size: 0x{erase_sector_size:X}
  erase_regions:
    - {{ base: 0x{flash_bank1_base:08X}, size: 0x{flash_bank_size:X}, sector_size: 0x{erase_sector_size:X} }}
    - {{ base: 0x{flash_bank2_base:08X}, size: 0x{flash_bank_size:X}, sector_size: 0x{erase_sector_size:X} }}
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
  calibration_time_slice: "{calibration_time_slice}"
  # Allow cold JIT and flash recovery on slow hosts, including control follow-ups.
  # This wall-clock limit does not extend emulated-time or instruction budgets.
  phase2_wall_timeout_s: 120.0
  # Keep the explicit no-progress observation inside the run budget so a
  # stable recovery wait is terminal evidence, not generic budget exhaustion.
  progress_stall_timeout_s: {progress_stall_timeout_s}
  max_step_limit: {max_step_limit}
  boot_cycles: {boot_cycles}{rollback_line}{fault_types_line}{instruction_skip_block}
{writeback_block}
state_probe:
  script: targets/nuttx_nxboot/probe.py
semantic_assertions:
  control:
    semantic_state.roles.primary_confirmed: true
    semantic_state.roles.recovery_valid: true
    semantic_state.roles.next_boot: none
    semantic_state.slots.primary.magic_kind: external
invariant_providers:
  - targets/nxboot/invariants.py
invariants:
  - nxboot_roles_distinct
  - nxboot_confirmed_has_recovery
  - nxboot_duplicate_update_consumed
  - nxboot_unconfirmed_internal_requires_revert
  - nxboot_unconfirmed_internal_requires_recovery
  - successful_rollback
expect:
  should_find_issues: false
""".format(
        rollback_line=(
            "\n  expected_rollback_at_cycle: 1"
            if int(selected_boot_cycles) > 1 else ""
        ),
        fault_types_line=(
            "\n  fault_types: [{}]".format(
                ", ".join(
                    item.strip()
                    for item in selected_fault_types.split(",")
                    if item.strip()
                )
            )
            if selected_fault_types else ""
        ),
        instruction_skip_block=(
            "\n  instruction_skip_config:"
            "\n    target_addresses:"
            "\n      - { symbol: validate_image }"
            "\n      - { symbol: copy_partition }"
            "\n      - { symbol: perform_update }"
            "\n      - { symbol: get_update_type }"
            "\n    skip_count: 1"
            if "instruction_skip" in selected_fault_types else ""
        ),
        writeback_block=writeback_block,
        name=name,
        loader_elf=_rel_or_abs(loader_elf),
        primary_img=_rel_or_abs(primary_img),
        update_img=_rel_or_abs(update_img),
        bootloader_entry=BOOTLOADER_ENTRY,
        sram_start=SRAM_START,
        sram_end=SRAM_END,
        volatile_regions="\n".join(
            "    - {{ name: {}, base: 0x{:08X}, size: 0x{:X} }}".format(
                region_name, region_base, region_size
            )
            for region_name, region_base, region_size in VOLATILE_REGIONS
        ),
        write_granularity=WRITE_GRANULARITY,
        flash_bank1_base=FLASH_BANK1_BASE,
        flash_bank2_base=FLASH_BANK2_BASE,
        flash_bank_size=FLASH_BANK_SIZE,
        erase_sector_size=ERASE_SECTOR_SIZE,
        slot_exec_base=SLOT_EXEC_BASE,
        slot_staging_base=SLOT_STAGING_BASE,
        slot_tertiary_base=SLOT_TERTIARY_BASE,
        slot_size=SLOT_SIZE,
        header_size=int(header_size),
        fault_max_writes=fault_max_writes,
        boot_cycles=max(1, int(selected_boot_cycles)),
        campaign_description=campaign_config["description"],
        run_duration=str(run_duration),
        calibration_time_slice=str(calibration_time_slice),
        progress_stall_timeout_s=stall_timeout_s,
        max_step_limit=int(max_step_limit),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-profile", type=Path, required=True)
    parser.add_argument("--header-size", type=lambda x: int(x, 0), default=0x400)
    parser.add_argument("--fault-max-writes", default="auto")
    parser.add_argument(
        "--boot-cycles",
        type=int,
        default=None,
        help="clean boots to execute (defaults to the selected campaign preset)",
    )
    parser.add_argument("--run-duration", default="8.0")
    parser.add_argument("--calibration-time-slice", default="0.1")
    parser.add_argument(
        "--progress-stall-timeout-s",
        type=float,
        default=4.0,
        help=(
            "emulated no-progress interval used for terminal recovery evidence "
            "(default: 4.0)"
        ),
    )
    parser.add_argument(
        "--max-step-limit",
        type=int,
        default=1_000_000_000,
        help="per-observation instruction ceiling (default: 1000000000)",
    )
    parser.add_argument("--name", default="nuttx_nxboot_real_update")
    parser.add_argument(
        "--campaign",
        choices=tuple(sorted(CAMPAIGNS)),
        default="baseline",
        help="named second-wave campaign preset (default: baseline)",
    )
    parser.add_argument(
        "--fault-types",
        default="",
        help="Comma-separated fault types (e.g. 'power_loss, bit_corruption')",
    )
    parser.add_argument(
        "--state-search-max-cuts",
        type=int,
        default=None,
        help="Override state_search.max_cuts for state_search campaigns",
    )
    parser.add_argument(
        "--state-search-max-new-states",
        type=int,
        default=None,
        help="Override state_search.max_new_states for state_search campaigns",
    )
    parser.add_argument(
        "--state-search-max-wall-time-s",
        type=float,
        default=None,
        help="Override state_search.max_wall_time_s for state_search campaigns",
    )
    parser.add_argument(
        "--state-search-cross-check-every",
        type=int,
        default=None,
        help="Override state_search.cross_check_every for state_search campaigns",
    )
    args = parser.parse_args()

    rendered = render_runtime_profile(
        args.build_dir,
        header_size=args.header_size,
        fault_max_writes=args.fault_max_writes,
        boot_cycles=args.boot_cycles,
        run_duration=args.run_duration,
        calibration_time_slice=args.calibration_time_slice,
        progress_stall_timeout_s=args.progress_stall_timeout_s,
        max_step_limit=args.max_step_limit,
        name=args.name,
        fault_types=args.fault_types,
        campaign=args.campaign,
        state_search_max_cuts=args.state_search_max_cuts,
        state_search_max_new_states=args.state_search_max_new_states,
        state_search_max_wall_time_s=args.state_search_max_wall_time_s,
        state_search_cross_check_every=args.state_search_cross_check_every,
    )
    args.output_profile.parent.mkdir(parents=True, exist_ok=True)
    args.output_profile.write_text(rendered)
    print(args.output_profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
