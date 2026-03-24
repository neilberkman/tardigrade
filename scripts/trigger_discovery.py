"""Automatic update-trigger discovery for runtime calibration.

Discovery is intentionally conservative:

- It only runs for profiles that do not already seed a pre-boot state.
- It uses a small family-aware strategy cascade (currently MCUboot-focused).
- A strategy only "wins" if calibration reaches slot data movement, not
  trailer-only metadata writes.
"""

from __future__ import annotations

import copy
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from trace_utils import summarize_calibration_coverage
from renode_runner import (
    CalibrationResult,
    calibration_completed,
    run_single_point,
)
from profile_loader import ELFFile, ProfileConfig, UpdateTrigger


MCUBOOT_FLASH_AREA_IDS = {
    "bootloader": 0,
    "exec": 1,
    "staging": 2,
    "scratch": 3,
}

STM32F4_ERASE_GEOMETRY = [
    (0x00000, 0x04000),
    (0x04000, 0x04000),
    (0x08000, 0x04000),
    (0x0C000, 0x04000),
    (0x10000, 0x10000),
    (0x20000, 0x20000),
    (0x40000, 0x20000),
    (0x60000, 0x20000),
    (0x80000, 0x20000),
    (0xA0000, 0x20000),
    (0xC0000, 0x20000),
    (0xE0000, 0x20000),
    (0x100000, 0x04000),
    (0x104000, 0x04000),
    (0x108000, 0x04000),
    (0x10C000, 0x04000),
    (0x110000, 0x10000),
    (0x120000, 0x20000),
    (0x140000, 0x20000),
    (0x160000, 0x20000),
    (0x180000, 0x20000),
    (0x1A0000, 0x20000),
    (0x1C0000, 0x20000),
    (0x1E0000, 0x20000),
]


@dataclass
class TriggerStrategy:
    name: str
    trigger_fields: Optional[Dict[str, Any]] = None
    use_offset_image: bool = False
    max_align: int = 8


@dataclass
class TriggerDiscoveryAttempt:
    name: str
    update_trigger: Optional[Dict[str, Any]]
    image_load_addresses: Dict[str, str]
    image_overrides: Dict[str, str]
    calibration: Dict[str, Any]
    coverage: Dict[str, Any]
    selected: bool = False
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


@dataclass
class TriggerDiscoveryResult:
    selected_profile: Optional[ProfileConfig]
    selected_robot_vars: Optional[List[str]]
    selected_calibration: Optional[CalibrationResult]
    selected_strategy: Optional[str]
    attempts: List[TriggerDiscoveryAttempt] = field(default_factory=list)
    flash_map_check: Optional[Dict[str, Any]] = None
    swap_algorithm: Optional[Dict[str, Any]] = None
    geometry_override: Optional[Dict[str, Any]] = None
    failure_reason: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.selected_profile is not None

    def to_summary(self) -> Dict[str, Any]:
        return {
            "selected_strategy": self.selected_strategy,
            "failure_reason": self.failure_reason,
            "flash_map_check": self.flash_map_check,
            "swap_algorithm": self.swap_algorithm,
            "geometry_override": self.geometry_override,
            "attempts": [
                {
                    "name": attempt.name,
                    "update_trigger": attempt.update_trigger,
                    "image_load_addresses": attempt.image_load_addresses,
                    "image_overrides": attempt.image_overrides,
                    "calibration": attempt.calibration,
                    "coverage": attempt.coverage,
                    "selected": bool(attempt.selected),
                    "error": attempt.error,
                    "skipped_reason": attempt.skipped_reason,
                }
                for attempt in self.attempts
            ],
        }


def _cleanup_generated_robot_files(robot_vars: List[str]) -> None:
    for prefix in ("PRE_BOOT_STATE_BIN:", "UPDATE_SEQUENCE_FILE:"):
        for entry in robot_vars:
            if not entry.startswith(prefix):
                continue
            path = entry.split(":", 1)[1]
            if not path:
                continue
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def should_auto_discover_trigger(profile: ProfileConfig, eval_mode: str) -> bool:
    """Return whether the profile should run trigger discovery."""
    if eval_mode != "execute":
        return False
    if getattr(profile, "has_update_sequence", False):
        return False
    if profile.pre_boot_state:
        return False
    if getattr(profile, "update_trigger", None) is not None and not bool(
        getattr(profile, "auto_update_trigger", False)
    ):
        return False
    if _default_update_slot(profile) is None:
        return False
    return bool(getattr(profile, "auto_update_trigger", False) or profile.update_trigger is None)


def _flash_base(profile: ProfileConfig) -> int:
    slot_bases = [int(slot.base) for slot in profile.memory.slots.values()]
    if slot_bases:
        return min([int(profile.bootloader_entry)] + slot_bases)
    return int(profile.bootloader_entry)


def _detect_bootloader_family(profile: ProfileConfig) -> str:
    name = "{} {}".format(profile.name, profile.bootloader_elf).lower()
    if "mcuboot" in name:
        return "mcuboot"
    return "unknown"


def _resolve_mcuboot_flash_map(elf_path: str) -> Tuple[Optional[List[Dict[str, int]]], Optional[str]]:
    if ELFFile is None:
        return None, "pyelftools not available"
    path = Path(elf_path)
    try:
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return None, "ELF has no .symtab"
            symbols = symtab.get_symbol_by_name("default_flash_map")
            if not symbols:
                return None, "ELF has no default_flash_map symbol"
            symbol = symbols[0]
            section = elf.get_section(symbol["st_shndx"])
            if section is None:
                return None, "default_flash_map symbol has no backing section"
            offset = int(symbol["st_value"]) - int(section["sh_addr"])
            size = int(symbol["st_size"])
            raw = section.data()[offset:offset + size]
    except Exception as exc:
        return None, "failed to read default_flash_map: {}".format(exc)

    if not raw or len(raw) % 16 != 0:
        return None, "default_flash_map has unexpected size {}".format(len(raw))

    entries: List[Dict[str, int]] = []
    for idx in range(0, len(raw), 16):
        area_id, off, area_size, device_ptr = struct.unpack("<IIII", raw[idx:idx + 16])
        entries.append(
            {
                "index": idx // 16,
                "area_id": int(area_id),
                "off": int(off),
                "size": int(area_size),
                "device_ptr": int(device_ptr),
            }
        )
    return entries, None


def _read_elf_symbol_names(elf_path: str) -> Tuple[Optional[Set[str]], Optional[str]]:
    if ELFFile is None:
        return None, "pyelftools not available"
    path = Path(elf_path)
    try:
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return None, "ELF has no .symtab"
            names = {
                str(symbol.name or "").strip()
                for symbol in symtab.iter_symbols()
                if str(symbol.name or "").strip()
            }
            return names, None
    except Exception as exc:
        return None, "failed to read ELF symbols: {}".format(exc)


def _detect_mcuboot_swap_algorithm(
    profile: ProfileConfig,
    repo_root: Path,
) -> Dict[str, Any]:
    family = _detect_bootloader_family(profile)
    if family != "mcuboot":
        return {
            "status": "unavailable",
            "reason": "swap-algorithm detection is only implemented for MCUboot profiles",
        }

    resolved_elf = profile.resolve_path(repo_root, profile.bootloader_elf)
    candidates = [
        ("offset", ["boot_swap_offset", "swap_offset"]),
        ("scratch", ["boot_swap_scratch", "swap_scratch"]),
        ("move", ["boot_swap_move", "swap_move"]),
    ]

    symbols, error = _read_elf_symbol_names(resolved_elf)
    if symbols is None:
        heuristic_tokens = " ".join(
            [
                str(getattr(profile, "name", "") or ""),
                str(getattr(profile, "bootloader_elf", "") or ""),
                str(resolved_elf),
            ]
        ).lower()
        heuristic_needles = {
            "offset": ["swap_offset", "boot_swap_offset", " offset", "_offset", "offset_"],
            "scratch": ["swap_scratch", "boot_swap_scratch", " scratch", "_scratch", "scratch_"],
            "move": ["swap_move", "boot_swap_move", " move", "_move", "move_"],
        }
        for algorithm, needles in heuristic_needles.items():
            if any(needle in heuristic_tokens for needle in needles):
                return {
                    "status": "heuristic",
                    "algorithm": algorithm,
                    "reason": error,
                    "bootloader_elf": resolved_elf,
                    "source": "profile_name_or_path",
                }
        return {
            "status": "unavailable",
            "reason": error,
            "bootloader_elf": resolved_elf,
        }
    matched: List[Dict[str, Any]] = []
    lowered = {name.lower(): name for name in symbols}
    for algorithm, needles in candidates:
        hits = [
            lowered[name]
            for name in lowered
            if any(needle in name for needle in needles)
        ]
        if hits:
            matched.append(
                {
                    "algorithm": algorithm,
                    "symbols": sorted(set(hits)),
                }
            )

    if not matched:
        return {
            "status": "unknown",
            "reason": "ELF does not expose recognizable MCUboot swap symbols",
            "bootloader_elf": resolved_elf,
        }

    selected = matched[0]
    return {
        "status": "detected",
        "algorithm": selected["algorithm"],
        "symbols": selected["symbols"],
        "all_matches": matched,
        "bootloader_elf": resolved_elf,
    }


def validate_compiled_flash_map(
    profile: ProfileConfig,
    repo_root: Path,
) -> Dict[str, Any]:
    """Compare the ELF's compiled flash map against the profile slot layout."""
    family = _detect_bootloader_family(profile)
    if family != "mcuboot":
        return {
            "status": "unavailable",
            "reason": "compiled flash-map preflight is only implemented for MCUboot profiles",
        }

    resolved_elf = profile.resolve_path(repo_root, profile.bootloader_elf)
    entries, error = _resolve_mcuboot_flash_map(resolved_elf)
    if entries is None:
        return {
            "status": "unavailable",
            "reason": error,
            "bootloader_elf": resolved_elf,
        }

    flash_base = _flash_base(profile)
    by_id = {entry["area_id"]: entry for entry in entries}
    checked_slots: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    for slot_name, area_id in (("exec", 1), ("staging", 2)):
        slot = profile.memory.slots.get(slot_name)
        if slot is None:
            continue
        compiled = by_id.get(area_id)
        profile_off = int(slot.base) - flash_base
        slot_summary: Dict[str, Any] = {
            "slot": slot_name,
            "area_id": area_id,
            "profile_base": "0x{:08X}".format(int(slot.base)),
            "profile_size": "0x{:X}".format(int(slot.size)),
            "profile_off": "0x{:X}".format(profile_off),
        }
        if compiled is None:
            slot_summary["status"] = "missing"
            mismatches.append("{} missing from compiled flash map".format(slot_name))
            checked_slots.append(slot_summary)
            continue
        slot_summary.update(
            {
                "compiled_off": "0x{:X}".format(compiled["off"]),
                "compiled_size": "0x{:X}".format(compiled["size"]),
            }
        )
        if compiled["off"] != profile_off or compiled["size"] != int(slot.size):
            slot_summary["status"] = "mismatch"
            mismatches.append(
                "{} profile={} size={} compiled_off={} compiled_size={}".format(
                    slot_name,
                    slot_summary["profile_off"],
                    slot_summary["profile_size"],
                    slot_summary["compiled_off"],
                    slot_summary["compiled_size"],
                )
            )
        else:
            slot_summary["status"] = "match"
        checked_slots.append(slot_summary)

    sector_geometry = validate_swap_sector_geometry(profile)

    if mismatches or sector_geometry.get("status") == "mismatch":
        combined_mismatches = list(mismatches)
        if sector_geometry.get("status") == "mismatch":
            combined_mismatches.append(str(sector_geometry.get("reason")))
        return {
            "status": "mismatch",
            "reason": "compiled flash map or erase-sector layout does not match declared slot layout",
            "bootloader_elf": resolved_elf,
            "flash_base": "0x{:08X}".format(flash_base),
            "checked_slots": checked_slots,
            "compiled_entries": entries,
            "mismatches": combined_mismatches,
            "sector_geometry": sector_geometry,
        }
    return {
        "status": "match",
        "reason": "compiled flash map matches declared slot layout",
        "bootloader_elf": resolved_elf,
        "flash_base": "0x{:08X}".format(flash_base),
        "checked_slots": checked_slots,
        "compiled_entries": entries,
        "sector_geometry": sector_geometry,
    }


def _clone_with_compiled_flash_map(
    profile: ProfileConfig,
    flash_map_check: Optional[Dict[str, Any]],
) -> Tuple[Optional[ProfileConfig], Optional[Dict[str, Any]], Optional[str]]:
    """Return a profile copy rewritten to the ELF's compiled flash map."""
    if not isinstance(flash_map_check, dict):
        return None, None, "no compiled flash-map data available"
    compiled_entries = flash_map_check.get("compiled_entries")
    flash_base_raw = flash_map_check.get("flash_base")
    if not isinstance(compiled_entries, list) or not flash_base_raw:
        return None, None, "compiled flash-map data is incomplete"

    try:
        flash_base = int(str(flash_base_raw), 16)
    except Exception:
        return None, None, "compiled flash-map base is invalid"

    by_id = {
        int(entry["area_id"]): entry
        for entry in compiled_entries
        if isinstance(entry, dict) and "area_id" in entry
    }
    candidate = copy.deepcopy(profile)
    changed_slots: List[Dict[str, str]] = []

    for slot_name, area_id in (("exec", 1), ("staging", 2), ("scratch", 3)):
        slot = candidate.memory.slots.get(slot_name)
        compiled = by_id.get(area_id)
        if slot is None or compiled is None:
            continue
        old_base = int(slot.base)
        old_size = int(slot.size)
        new_base = flash_base + int(compiled["off"])
        new_size = int(compiled["size"])
        if old_base == new_base and old_size == new_size:
            continue
        slot.base = new_base
        slot.size = new_size
        changed_slots.append(
            {
                "slot": slot_name,
                "old_base": "0x{:08X}".format(old_base),
                "old_size": "0x{:X}".format(old_size),
                "new_base": "0x{:08X}".format(new_base),
                "new_size": "0x{:X}".format(new_size),
            }
        )

    if not changed_slots:
        return candidate, None, None
    return (
        candidate,
        {
            "status": "applied",
            "reason": "using compiled flash map for trigger discovery",
            "changed_slots": changed_slots,
        },
        None,
    )


def _erase_geometry(profile: ProfileConfig) -> List[Tuple[int, int]]:
    flash_base = _flash_base(profile)
    platform_name = Path(str(profile.platform)).name.lower()
    if platform_name in {"stm32f4.repl", "stm32f4_fast.repl"}:
        return [
            (flash_base + int(offset), flash_base + int(offset) + int(size))
            for offset, size in STM32F4_ERASE_GEOMETRY
        ]

    slot_bases = [int(slot.base) for slot in profile.memory.slots.values()]
    slot_ends = [int(slot.base) + int(slot.size) for slot in profile.memory.slots.values()]
    if not slot_bases or not slot_ends:
        return []
    region_start = min(slot_bases)
    region_end = max(slot_ends)
    page_size = int(getattr(profile.memory, "page_size", 0) or 0) or int(
        getattr(profile.memory, "write_granularity", 0) or 0
    ) or 4096
    geometry: List[Tuple[int, int]] = []
    cursor = region_start
    while cursor < region_end:
        geometry.append((cursor, min(region_end, cursor + page_size)))
        cursor += page_size
    return geometry


def _slot_erase_segments(profile: ProfileConfig, slot_name: str) -> List[Dict[str, int]]:
    slot = profile.memory.slots.get(slot_name)
    if slot is None:
        return []
    slot_base = int(slot.base)
    slot_end = slot_base + int(slot.size)
    segments: List[Dict[str, int]] = []
    for start, end in _erase_geometry(profile):
        overlap_start = max(slot_base, int(start))
        overlap_end = min(slot_end, int(end))
        if overlap_end <= overlap_start:
            continue
        segments.append(
            {
                "erase_start": int(start),
                "erase_end": int(end),
                "overlap_start": int(overlap_start),
                "overlap_end": int(overlap_end),
                "erase_size": int(end - start),
                "overlap_size": int(overlap_end - overlap_start),
                "partial": not (overlap_start == start and overlap_end == end),
            }
        )
    return segments


def validate_swap_sector_geometry(profile: ProfileConfig) -> Dict[str, Any]:
    """Check whether exec/staging share a discovery-friendly sector layout."""
    family = _detect_bootloader_family(profile)
    if family != "mcuboot":
        return {
            "status": "unavailable",
            "reason": "sector-geometry preflight is only implemented for MCUboot profiles",
        }

    exec_segments = _slot_erase_segments(profile, "exec")
    staging_segments = _slot_erase_segments(profile, "staging")
    if not exec_segments or not staging_segments:
        return {
            "status": "unavailable",
            "reason": "exec/staging slots are required for sector-geometry preflight",
        }

    exec_layout = [(seg["erase_size"], seg["overlap_size"]) for seg in exec_segments]
    staging_layout = [(seg["erase_size"], seg["overlap_size"]) for seg in staging_segments]
    if (
        exec_layout != staging_layout
        or any(seg["partial"] for seg in exec_segments)
        or any(seg["partial"] for seg in staging_segments)
    ):
        return {
            "status": "mismatch",
            "reason": "exec/staging slots do not map cleanly onto the same erase-sector layout",
            "exec_segments": exec_segments,
            "staging_segments": staging_segments,
        }

    return {
        "status": "match",
        "reason": "exec/staging slots share the same erase-sector layout",
        "exec_segments": exec_segments,
        "staging_segments": staging_segments,
    }


def _next_slot_boundary_offset(profile: ProfileConfig, slot_name: str) -> Optional[int]:
    slot = profile.memory.slots.get(slot_name)
    if slot is None:
        return None
    slot_base = int(slot.base)
    slot_end = slot_base + int(slot.size)
    for start, end in _erase_geometry(profile):
        if start <= slot_base < end:
            if end >= slot_end:
                return None
            return int(end - slot_base)
    return None


def _offset_strategy_image_path(
    profile: ProfileConfig,
    repo_root: Path,
    slot_name: str,
) -> Tuple[Optional[str], Optional[str]]:
    image_path = profile.images.get(slot_name)
    if not image_path:
        return None, "no image configured for slot '{}'".format(slot_name)
    resolved = Path(profile.resolve_path(repo_root, image_path))
    if resolved.name.endswith("_offsetslot.bin"):
        base_name = resolved.name.replace("_offsetslot.bin", ".bin")
        candidate = resolved.with_name(base_name)
        if candidate.exists():
            return str(candidate), None
        return None, "offset placement requested but base image '{}' is missing".format(candidate)
    return str(resolved), None


def _default_update_slot(profile: ProfileConfig) -> Optional[str]:
    if "staging" in profile.memory.slots and "staging" in profile.images:
        return "staging"
    for slot_name in profile.memory.slots:
        if slot_name == "exec":
            continue
        if slot_name in profile.images:
            return slot_name
    return None


def _max_align_candidates(profile: ProfileConfig) -> List[int]:
    explicit = getattr(profile, "update_trigger", None)
    if explicit is not None and explicit.fields.get("max_align") is not None:
        try:
            return [int(explicit.fields["max_align"])]
        except Exception:
            pass
    return [8, 32]


def _prefers_triggered_upgrade(profile: ProfileConfig, repo_root: Path) -> bool:
    criteria = getattr(profile, "success_criteria", None)
    if criteria is None:
        return False
    expected_image = str(getattr(criteria, "expected_image", "") or "").strip().lower()
    if expected_image == "staging":
        return True
    marker_address = getattr(criteria, "marker_address", None)
    marker_value = getattr(criteria, "marker_value", None)
    if marker_address is None or marker_value is None:
        return False
    exec_slot = profile.memory.slots.get("exec")
    if exec_slot is None:
        return False
    offset = int(marker_address) - int(exec_slot.base)
    if offset < 0:
        return False
    exec_image = profile.images.get("exec")
    staging_image = profile.images.get("staging")
    if not exec_image or not staging_image:
        return False
    try:
        exec_path = profile.resolve_path(repo_root, exec_image)
        staging_path = profile.resolve_path(repo_root, staging_image)
        with open(exec_path, "rb") as handle:
            handle.seek(offset)
            exec_word = int.from_bytes(handle.read(4), "little")
        with open(staging_path, "rb") as handle:
            handle.seek(offset)
            staging_word = int.from_bytes(handle.read(4), "little")
    except Exception:
        return False
    return exec_word != staging_word and staging_word == int(marker_value)


def _build_mcuboot_strategies(
    profile: ProfileConfig,
    repo_root: Path,
    swap_algorithm: Optional[Dict[str, Any]] = None,
) -> List[TriggerStrategy]:
    slot_name = _default_update_slot(profile)
    if slot_name is None:
        return [TriggerStrategy(name="no_trigger")]

    staging_path = profile.resolve_path(repo_root, profile.images[slot_name])
    staging_size = os.path.getsize(staging_path) if os.path.exists(staging_path) else 0
    strategies_by_name: Dict[str, TriggerStrategy] = {"no_trigger": TriggerStrategy(name="no_trigger")}
    for max_align in _max_align_candidates(profile):
        strategies_by_name["trailer_magic_align{}".format(max_align)] = (
            TriggerStrategy(
                name="trailer_magic_align{}".format(max_align),
                trigger_fields={"max_align": max_align},
                max_align=max_align,
            )
        )
        strategies_by_name["trailer_magic_swap_metadata_align{}".format(max_align)] = (
            TriggerStrategy(
                name="trailer_magic_swap_metadata_align{}".format(max_align),
                trigger_fields={
                    "max_align": max_align,
                    "swap_type": 0x02,
                    "image_num": 0x00,
                    "swap_size": staging_size,
                },
                max_align=max_align,
            )
        )
        strategies_by_name["offset_image_align{}".format(max_align)] = (
            TriggerStrategy(
                name="offset_image_align{}".format(max_align),
                trigger_fields={"max_align": max_align},
                use_offset_image=True,
                max_align=max_align,
            )
        )
        strategies_by_name["offset_image_swap_metadata_align{}".format(max_align)] = (
            TriggerStrategy(
                name="offset_image_swap_metadata_align{}".format(max_align),
                trigger_fields={
                    "max_align": max_align,
                    "swap_type": 0x02,
                    "image_num": 0x00,
                    "swap_size": staging_size,
                },
                use_offset_image=True,
                max_align=max_align,
            )
        )
    algorithm = str((swap_algorithm or {}).get("algorithm") or "").strip().lower()
    prefer_triggered = _prefers_triggered_upgrade(profile, repo_root)
    ordered_names: List[str] = []
    for max_align in _max_align_candidates(profile):
        if algorithm == "offset":
            ordered_names.extend(
                [
                    "offset_image_swap_metadata_align{}".format(max_align),
                    "offset_image_align{}".format(max_align),
                    "trailer_magic_swap_metadata_align{}".format(max_align),
                    "trailer_magic_align{}".format(max_align),
                ]
            )
        else:
            ordered_names.extend(
                [
                    "trailer_magic_swap_metadata_align{}".format(max_align),
                    "trailer_magic_align{}".format(max_align),
                    "offset_image_swap_metadata_align{}".format(max_align),
                    "offset_image_align{}".format(max_align),
                ]
            )
    if prefer_triggered:
        ordered_names.append("no_trigger")
    else:
        ordered_names.insert(0, "no_trigger")
    return [strategies_by_name[name] for name in ordered_names if name in strategies_by_name]


def _build_strategies(profile: ProfileConfig, repo_root: Path) -> List[TriggerStrategy]:
    family = _detect_bootloader_family(profile)
    if family == "mcuboot":
        return _build_mcuboot_strategies(
            profile,
            repo_root,
            swap_algorithm=_detect_mcuboot_swap_algorithm(profile, repo_root),
        )
    return [TriggerStrategy(name="no_trigger")]


def _clone_for_strategy(
    profile: ProfileConfig,
    repo_root: Path,
    strategy: TriggerStrategy,
) -> Tuple[Optional[ProfileConfig], Optional[str]]:
    candidate = copy.deepcopy(profile)
    candidate.auto_update_trigger = False
    candidate.pre_boot_state = []
    candidate.update_trigger = None
    candidate.image_load_addresses = {}

    slot_name = _default_update_slot(candidate)
    if strategy.trigger_fields is not None:
        if slot_name is None:
            return None, "no update slot available for trailer-based discovery"
        candidate.update_trigger = UpdateTrigger(
            type="mcuboot_trailer_magic",
            slot=slot_name,
            fields=dict(strategy.trigger_fields),
        )
        candidate.pre_boot_state = candidate.expand_update_trigger()

    if strategy.use_offset_image:
        if slot_name is None:
            return None, "no update slot available for offset placement"
        offset = _next_slot_boundary_offset(candidate, slot_name)
        if offset is None or offset <= 0:
            return None, "slot '{}' has no usable next erase boundary".format(slot_name)
        image_path, error = _offset_strategy_image_path(candidate, repo_root, slot_name)
        if error:
            return None, error
        candidate.images[slot_name] = str(image_path)
        candidate.image_load_addresses[slot_name] = int(candidate.memory.slots[slot_name].base) + int(offset)

    return candidate, None


def _calibration_from_raw_data(profile: ProfileConfig, data: Dict[str, Any]) -> CalibrationResult:
    total_writes = int(data.get("total_writes", 0))
    cap = int(profile.fault_sweep.max_writes_cap)
    if total_writes > cap:
        total_writes = cap
    return CalibrationResult(
        total_writes=total_writes,
        total_erases=int(data.get("total_erases", 0)),
        trace_file=data.get("trace_file"),
        erase_trace_file=data.get("erase_trace_file"),
        trace_file_bin=data.get("trace_file_bin"),
        erase_trace_file_bin=data.get("erase_trace_file_bin"),
        calibration_exec_hash=data.get("calibration_exec_hash"),
        stop_reason=data.get("calibration_stop_reason"),
        emulated_s=data.get("calibration_emulated_s"),
        elapsed_s=data.get("calibration_elapsed_s"),
        pc=data.get("calibration_pc"),
        setup_writes=int(data.get("setup_writes", 0)),
        total_i2c_transactions=int(data.get("total_i2c_transactions", 0)),
        total_otp_blows=int(data.get("total_otp_blows", 0)),
    )


def _attempt_calibration_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "writes": int(data.get("total_writes", 0)),
        "erases": int(data.get("total_erases", 0)),
        "stop_reason": data.get("calibration_stop_reason"),
        "pc": data.get("calibration_pc"),
        "elapsed_s": data.get("calibration_elapsed_s"),
        "emulated_s": data.get("calibration_emulated_s"),
    }


def _calibration_matches_expected_boot(data: Dict[str, Any]) -> bool:
    """Return whether the calibration control run reached the expected boot state."""
    signals = data.get("signals")
    if not isinstance(signals, dict):
        return True
    if signals.get("expectations_met") is False:
        return False
    if str(data.get("boot_outcome") or "").strip().lower() == "wrong_image":
        return False
    return True


def discover_update_trigger(
    profile: ProfileConfig,
    *,
    repo_root: Path,
    renode_test: str,
    robot_suite: str,
    work_dir: Path,
    renode_remote_server_dir: str,
    keep_run_artifacts: bool,
    robot_vars_factory: Callable[[ProfileConfig], List[str]],
) -> TriggerDiscoveryResult:
    """Try a family-specific trigger cascade and return the first viable strategy."""
    flash_map_check = validate_compiled_flash_map(profile, repo_root)
    swap_algorithm = _detect_mcuboot_swap_algorithm(profile, repo_root)
    discovery_profile = profile
    geometry_override: Optional[Dict[str, Any]] = None
    if flash_map_check.get("status") == "mismatch":
        overridden_profile, geometry_override, override_error = _clone_with_compiled_flash_map(
            profile,
            flash_map_check,
        )
        if overridden_profile is None:
            return TriggerDiscoveryResult(
                selected_profile=None,
                selected_robot_vars=None,
                selected_calibration=None,
                selected_strategy=None,
                attempts=[],
                flash_map_check=flash_map_check,
                swap_algorithm=swap_algorithm,
                geometry_override={
                    "status": "failed",
                    "reason": override_error or flash_map_check.get("reason"),
                },
                failure_reason=flash_map_check.get("reason"),
            )
        discovery_profile = overridden_profile

    attempts: List[TriggerDiscoveryAttempt] = []
    family = _detect_bootloader_family(discovery_profile)
    if family == "mcuboot":
        strategies = _build_mcuboot_strategies(
            discovery_profile,
            repo_root,
            swap_algorithm=swap_algorithm,
        )
    else:
        strategies = _build_strategies(discovery_profile, repo_root)

    for strategy in strategies:
        candidate, skipped_reason = _clone_for_strategy(discovery_profile, repo_root, strategy)
        if candidate is None:
            attempts.append(
                TriggerDiscoveryAttempt(
                    name=strategy.name,
                    update_trigger=None,
                    image_load_addresses={},
                    image_overrides={},
                    calibration={},
                    coverage={"status": "unavailable", "reason": skipped_reason or "strategy not applicable"},
                    skipped_reason=skipped_reason,
                )
            )
            continue

        robot_vars = robot_vars_factory(candidate)
        try:
            data = run_single_point(
                repo_root=repo_root,
                renode_test=renode_test,
                robot_suite=robot_suite,
                profile=candidate,
                fault_at=0,
                robot_vars=robot_vars,
                work_dir=work_dir,
                renode_remote_server_dir=renode_remote_server_dir,
                calibration=True,
                keep_run_artifacts=keep_run_artifacts,
            )
        except Exception as exc:
            _cleanup_generated_robot_files(robot_vars)
            attempts.append(
                TriggerDiscoveryAttempt(
                    name=strategy.name,
                    update_trigger=(
                        {
                            "type": candidate.update_trigger.type,
                            "slot": candidate.update_trigger.slot,
                            **candidate.update_trigger.fields,
                        }
                        if candidate.update_trigger is not None
                        else None
                    ),
                    image_load_addresses={
                        slot_name: "0x{:08X}".format(int(addr))
                        for slot_name, addr in candidate.effective_image_load_addresses().items()
                    },
                    image_overrides=dict(candidate.images),
                    calibration={},
                    coverage={"status": "unavailable", "reason": "calibration attempt failed before producing a result"},
                    error=str(exc),
                )
            )
            continue

        coverage = summarize_calibration_coverage(
            trace_file=data.get("trace_file"),
            erase_trace_file=data.get("erase_trace_file"),
            flash_base=_flash_base(candidate),
            slots=candidate.memory.slots,
            page_size=getattr(candidate.memory, "page_size", 4096),
            metadata_regions=getattr(candidate, "metadata_fault_regions", None),
        )
        completed = calibration_completed(
            data.get("calibration_stop_reason"),
            candidate.expect.control_outcome,
        )
        selected = bool(
            completed
            and coverage.get("status") in {"slot_activity", "named_metadata_only"}
            and _calibration_matches_expected_boot(data)
        )
        attempt = TriggerDiscoveryAttempt(
            name=strategy.name,
            update_trigger=(
                {
                    "type": candidate.update_trigger.type,
                    "slot": candidate.update_trigger.slot,
                    **candidate.update_trigger.fields,
                }
                if candidate.update_trigger is not None
                else None
            ),
            image_load_addresses={
                slot_name: "0x{:08X}".format(int(addr))
                for slot_name, addr in candidate.effective_image_load_addresses().items()
            },
            image_overrides=dict(candidate.images),
            calibration=_attempt_calibration_dict(data),
            coverage=coverage,
            selected=selected,
        )
        attempts.append(attempt)
        if selected:
            return TriggerDiscoveryResult(
                selected_profile=candidate,
                selected_robot_vars=robot_vars,
                selected_calibration=_calibration_from_raw_data(candidate, data),
                selected_strategy=strategy.name,
                attempts=attempts,
                flash_map_check=flash_map_check,
                swap_algorithm=swap_algorithm,
                geometry_override=geometry_override,
                failure_reason=None,
            )
        _cleanup_generated_robot_files(robot_vars)

    return TriggerDiscoveryResult(
        selected_profile=None,
        selected_robot_vars=None,
        selected_calibration=None,
        selected_strategy=None,
        attempts=attempts,
        flash_map_check=flash_map_check,
        swap_algorithm=swap_algorithm,
        geometry_override=geometry_override,
        failure_reason="could not trigger firmware update",
    )
