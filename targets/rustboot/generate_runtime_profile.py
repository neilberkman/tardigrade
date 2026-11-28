#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate a rustBoot nRF52840 runtime or recovery-state search profile."""

from __future__ import annotations

import argparse
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
PROFILES_DIR = (REPO_ROOT / "profiles").resolve()

BOOT_BASE = 0x0002F000
BOOT_SIZE = 0x00028000
UPDATE_BASE = 0x00058000
UPDATE_SIZE = 0x00028000
BOOTLOADER_ENTRY = 0x00000000
SRAM_START = 0x20000000
SRAM_END = 0x20040000


def _rel_or_abs(path: Path, build_dir: Path | None = None) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        pass
    if build_dir is not None:
        try:
            return resolved.relative_to(build_dir.resolve()).as_posix()
        except ValueError:
            pass
    return resolved.as_posix()


def render_runtime_profile(
    build_dir: Path,
    *,
    name: str = "rustboot_nrf52840_update",
    run_duration_s: str = "20.0",
    max_writes_cap: int = 200000,
    max_step_limit: int = 200000000,
    boot_cycles: int = 1,
    state_search: bool = False,
    state_search_max_cuts: int = 3,
    state_search_max_new_states: int = 64,
    state_search_max_wall_time_s: float = 300.0,
    state_search_cross_check_every: int = 4,
    first_fault_types: tuple[str, ...] = ("power_loss", "interrupted_erase"),
    deeper_fault_types: tuple[str, ...] = ("power_loss", "interrupted_erase"),
    torn_word_seed: int = 20261127,
    should_find_issues: bool = True,
) -> str:
    """Render a rustBoot nRF52840 runtime profile from a local build directory."""
    build_dir = build_dir.resolve()
    loader_elf = build_dir / "rustboot_nrf52840.elf"
    boot_img = build_dir / "rustboot_boot_v1.bin"
    update_img = build_dir / "rustboot_update_v2.bin"

    for required in (loader_elf, boot_img, update_img):
        if not required.exists():
            raise FileNotFoundError(required)
    if boot_img.stat().st_size > BOOT_SIZE:
        raise ValueError(
            f"{boot_img} ({boot_img.stat().st_size} bytes) exceeds BOOT slot size 0x{BOOT_SIZE:X}"
        )
    if update_img.stat().st_size > UPDATE_SIZE:
        raise ValueError(
            f"{update_img} ({update_img.stat().st_size} bytes) exceeds UPDATE slot size 0x{UPDATE_SIZE:X}"
        )

    probe_script = REPO_ROOT / "targets" / "rustboot" / "probe.py"
    invariant_provider = REPO_ROOT / "targets" / "rustboot" / "invariants.py"

    state_search_block = ""
    if state_search:
        first_csv = ", ".join(first_fault_types)
        deeper_csv = ", ".join(deeper_fault_types)
        state_search_block = (
            "  include_erase_fault_points: true\n"
            "  torn_word: [fixed, untouched, programmed, { partial_bits: 3 }]\n"
            f"  torn_word_seed: {int(torn_word_seed)}\n"
            "  phase2_fault:\n"
            "    enabled: true\n"
            f"    first_fault_types: [{first_csv}]\n"
            f"    fault_types: [{deeper_csv}]\n"
            "    state_search:\n"
            "      enabled: true\n"
            f"      max_cuts: {int(state_search_max_cuts)}\n"
            f"      max_new_states: {int(state_search_max_new_states)}\n"
            f"      max_wall_time_s: {float(state_search_max_wall_time_s)}\n"
            "      address_ranges:\n"
            "        - { start: 0x0002F000, end: 0x0002F3FF }\n"
            "        - { start: 0x00056000, end: 0x000583FF }\n"
            "        - { start: 0x0007F000, end: 0x0007FFFF }\n"
            f"      cross_check_every: {int(state_search_cross_check_every)}\n"
        )

    return f"""schema_version: 1
name: {name}
description: >
  rustBoot nRF52840 swap-scratch update scenario built from upstream
  nihalpasham/rustBoot. Boot partition holds v1 firmware, update partition
  holds v2 firmware with trailer state Updating (0x70).
platform: platforms/cortex_m4_flash_fast.repl
flash_backend: faultFlash
bootloader:
  elf: {_rel_or_abs(loader_elf, build_dir)}
  entry: 0x{BOOTLOADER_ENTRY:08X}
memory:
  sram: {{ start: 0x{SRAM_START:08X}, end: 0x{SRAM_END:08X} }}
  write_granularity: 4
  slots:
    exec: {{ base: 0x{BOOT_BASE:08X}, size: 0x{BOOT_SIZE:05X} }}
    staging: {{ base: 0x{UPDATE_BASE:08X}, size: 0x{UPDATE_SIZE:05X} }}
images:
  exec: {_rel_or_abs(boot_img, build_dir)}
  staging: {_rel_or_abs(update_img, build_dir)}
pre_boot_state:
  - {{ address: 0x0007FFF8, u32: 0x70FFFFFF }}
  - {{ address: 0x0007FFFC, u32: 0x544F4F42 }}
success_criteria:
  vtor_in_slot: exec
  image_hash: true
  image_hash_slot: exec
  expected_image: staging
state_probe:
  script: {_rel_or_abs(probe_script)}
  required_paths:
    - semantic_state.target
    - semantic_state.boot.magic_valid
    - semantic_state.boot.state
    - semantic_state.flags.boot_flags_monotonic
    - semantic_state.flags.update_flags_monotonic
semantic_assertions:
  control:
    semantic_state.target: rustboot
    semantic_state.boot.magic_valid: true
    semantic_state.boot.state: testing
    semantic_state.flags.boot_flags_monotonic: true
    semantic_state.flags.update_flags_monotonic: true
invariant_providers:
  - {_rel_or_abs(invariant_provider)}
invariants:
  - rustboot_boot_not_empty
  - rustboot_swap_flags_consistent
  - rustboot_no_packed_flag_corruption
fault_sweep:
  mode: runtime
  evaluation_mode: execute
  fault_types: [power_loss]
  max_writes: auto
  max_writes_cap: {int(max_writes_cap)}
  boot_cycles: {int(boot_cycles)}
  run_duration: "{run_duration_s}"
  calibration_time_slice: "0.05"
  calibration_stop:
    success_criteria: true
  max_step_limit: {int(max_step_limit)}
{state_search_block}skip_self_test: true
expect:
  should_find_issues: {"true" if should_find_issues else "false"}
"""


def write_runtime_profile(output_path: Path, content: str) -> Path:
    """Write generated profile, refusing to write inside profiles/."""
    resolved_out = output_path.resolve()
    if resolved_out == PROFILES_DIR or PROFILES_DIR in resolved_out.parents:
        raise ValueError(
            f"Refusing to write generated profile inside {PROFILES_DIR}: {resolved_out}"
        )
    resolved_out.parent.mkdir(parents=True, exist_ok=True)
    resolved_out.write_text(content, encoding="utf-8")
    return resolved_out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=REPO_ROOT / "results" / "rustboot_nrf52840",
        help="Directory containing rustboot_nrf52840.elf and signed v1/v2 images",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output YAML path (defaults to <build-dir>/rustboot_nrf52840_update.yaml)",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Profile name override",
    )
    parser.add_argument(
        "--boot-cycles",
        type=int,
        default=1,
        help="Number of recovery boot cycles per fault point (default: 1)",
    )
    parser.add_argument(
        "--state-search",
        action="store_true",
        help="Enable recovery-state search across interrupted-erase cuts",
    )
    parser.add_argument(
        "--state-search-max-cuts",
        type=int,
        default=3,
        help="Maximum cut depth for state_search (default: 3)",
    )
    parser.add_argument(
        "--state-search-max-new-states",
        type=int,
        default=64,
        help="Maximum distinct persistent states to boot in state_search (default: 64)",
    )
    parser.add_argument(
        "--state-search-max-wall-time-s",
        type=float,
        default=300.0,
        help="Wall-clock budget in seconds for state_search (default: 300.0)",
    )
    parser.add_argument(
        "--state-search-cross-check-every",
        type=int,
        default=4,
        help="Live cross-check interval for state_search (default: 4)",
    )
    args = parser.parse_args(argv)

    default_name = (
        "rustboot_nrf52840_state_search"
        if args.state_search
        else "rustboot_nrf52840_update"
    )
    profile_name = args.name or default_name
    output_path = args.output or (args.build_dir / f"{profile_name}.yaml")
    rendered = render_runtime_profile(
        args.build_dir,
        name=profile_name,
        boot_cycles=args.boot_cycles,
        state_search=args.state_search,
        state_search_max_cuts=args.state_search_max_cuts,
        state_search_max_new_states=args.state_search_max_new_states,
        state_search_max_wall_time_s=args.state_search_max_wall_time_s,
        state_search_cross_check_every=args.state_search_cross_check_every,
    )
    written = write_runtime_profile(output_path, rendered)
    print(written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
