"""Automatic update-trigger discovery for runtime calibration.

Discovery is intentionally conservative:

- It only runs for profiles that do not already seed a pre-boot state.
- It uses a small family-aware strategy cascade (currently MCUboot-focused).
- A strategy only "wins" if calibration reaches slot data movement, not
  trailer-only metadata writes.
"""

from __future__ import annotations

import copy
import csv
import hashlib
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
    """Return whether the profile should run trigger discovery.

    Only profiles that explicitly opt in via ``update_trigger: auto``
    (which sets ``auto_update_trigger=True``) enter discovery.  Profiles
    that simply omit ``update_trigger`` (direct-XIP, bare-metal, etc.)
    go straight to calibration and sweep — their metadata-only writes
    are the intended fault targets.
    """
    if eval_mode != "execute":
        return False
    if getattr(profile, "has_update_sequence", False):
        return False
    if profile.pre_boot_state:
        return False
    if not bool(getattr(profile, "auto_update_trigger", False)):
        return False
    if _default_update_slot(profile) is None:
        return False
    return True


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


def _parse_flash_map_entries(raw: bytes) -> Tuple[Optional[List[Dict[str, int]]], Optional[str]]:
    """Parse a packed default_flash_map array (4×uint32 per entry)."""
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


def _resolve_mcuboot_flash_map_pyelftools(elf_path: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Read default_flash_map raw bytes via pyelftools."""
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
            return bytes(section.data()[offset:offset + size]), None
    except Exception as exc:
        return None, "failed to read default_flash_map: {}".format(exc)


def _resolve_mcuboot_flash_map_toolchain(elf_path: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Read default_flash_map raw bytes by parsing the ELF binary directly.

    Uses ``nm`` to locate the symbol address and size, then parses the ELF
    section headers to find which loadable section contains that address and
    reads the raw bytes directly from the file.  No pyelftools or objcopy
    needed — just ``nm`` and Python's ``struct``.
    """
    import subprocess as _sp
    import shutil

    nm_bin = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
    if nm_bin is None:
        return None, "nm not found"

    # Step 1: get symbol address and size from nm --print-size
    try:
        result = _sp.run(
            [nm_bin, "--print-size", elf_path],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return None, "nm failed: {}".format(exc)
    if result.returncode != 0:
        return None, "nm returned exit code {}".format(result.returncode)

    sym_addr = None
    sym_size = None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == "default_flash_map":
            sym_addr = int(parts[0], 16)
            sym_size = int(parts[1], 16)
            break
    if sym_addr is None:
        return None, "ELF has no default_flash_map symbol"
    if sym_size is None or sym_size == 0:
        sym_size = 16 * 6  # conservative estimate

    # Step 2: parse ELF section headers to find the containing section
    path = Path(elf_path)
    try:
        with path.open("rb") as f:
            ident = f.read(16)
            if ident[:4] != b"\x7fELF":
                return None, "not a valid ELF file"
            ei_class = ident[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = ident[5]   # 1 = little-endian, 2 = big-endian
            endian = "<" if ei_data == 1 else ">"

            if ei_class == 1:
                # 32-bit ELF header
                f.seek(0)
                ehdr = f.read(52)
                e_shoff = struct.unpack(endian + "I", ehdr[32:36])[0]
                e_shentsize = struct.unpack(endian + "H", ehdr[46:48])[0]
                e_shnum = struct.unpack(endian + "H", ehdr[48:50])[0]
                # Read section headers
                f.seek(e_shoff)
                for _ in range(e_shnum):
                    shdr = f.read(e_shentsize)
                    if len(shdr) < 40:
                        break
                    sh_addr = struct.unpack(endian + "I", shdr[12:16])[0]
                    sh_offset = struct.unpack(endian + "I", shdr[16:20])[0]
                    sh_size = struct.unpack(endian + "I", shdr[20:24])[0]
                    sh_flags = struct.unpack(endian + "I", shdr[8:12])[0]
                    # Check if this section contains our symbol (SHF_ALLOC = 0x2)
                    if sh_flags & 0x2 and sh_addr <= sym_addr < sh_addr + sh_size:
                        file_offset = sh_offset + (sym_addr - sh_addr)
                        f.seek(file_offset)
                        raw = f.read(sym_size)
                        if len(raw) == sym_size:
                            return raw, None
                        return None, "short read: got {} expected {}".format(len(raw), sym_size)
            else:
                # 64-bit ELF header
                f.seek(0)
                ehdr = f.read(64)
                e_shoff = struct.unpack(endian + "Q", ehdr[40:48])[0]
                e_shentsize = struct.unpack(endian + "H", ehdr[58:60])[0]
                e_shnum = struct.unpack(endian + "H", ehdr[60:62])[0]
                f.seek(e_shoff)
                for _ in range(e_shnum):
                    shdr = f.read(e_shentsize)
                    if len(shdr) < 64:
                        break
                    sh_addr = struct.unpack(endian + "Q", shdr[16:24])[0]
                    sh_offset = struct.unpack(endian + "Q", shdr[24:32])[0]
                    sh_size = struct.unpack(endian + "Q", shdr[32:40])[0]
                    sh_flags = struct.unpack(endian + "Q", shdr[8:16])[0]
                    if sh_flags & 0x2 and sh_addr <= sym_addr < sh_addr + sh_size:
                        file_offset = sh_offset + (sym_addr - sh_addr)
                        f.seek(file_offset)
                        raw = f.read(sym_size)
                        if len(raw) == sym_size:
                            return raw, None
                        return None, "short read: got {} expected {}".format(len(raw), sym_size)

            return None, "no loadable section contains default_flash_map at 0x{:X}".format(sym_addr)
    except Exception as exc:
        return None, "ELF parsing failed: {}".format(exc)


def _resolve_mcuboot_flash_map(elf_path: str) -> Tuple[Optional[List[Dict[str, int]]], Optional[str]]:
    # Try pyelftools first, then fall back to nm + direct ELF parsing.
    raw, error = _resolve_mcuboot_flash_map_pyelftools(elf_path)
    if not raw:
        raw, error = _resolve_mcuboot_flash_map_toolchain(elf_path)
    if not raw:
        return None, error
    return _parse_flash_map_entries(raw)


def _compiled_flash_map_candidates(
    entries: List[Dict[str, int]],
    *,
    profile_off: int,
    profile_size: int,
    exclude_indices: Optional[Set[int]] = None,
) -> List[Dict[str, int]]:
    """Return compiled areas that can represent one declared slot.

    Zephyr assigns flash-map area IDs from the complete partition table.  The
    IDs therefore are not stable slot identities: a scratch or storage area
    may be inserted between the two image slots.  Offset and size are the
    contract shared by the profile and the compiled map.
    """
    excluded = exclude_indices or set()
    return [
        entry
        for entry in entries
        if int(entry.get("index", -1)) not in excluded
        and int(entry.get("off", -1)) == profile_off
        and int(entry.get("size", -1)) == profile_size
    ]


def _resolve_compiled_flash_slots(
    entries: List[Dict[str, int]],
    slots: Dict[str, Any],
    flash_base: int,
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, str]]:
    """Resolve declared slots to unique compiled areas without using area IDs.

    Exact offset/size matches are required.  A size-only match is unsafe:
    scratch and storage commonly have the same size as an image slot, so a
    stale profile must fail closed rather than silently selecting another
    partition.
    """
    resolved: Dict[str, Dict[str, int]] = {}
    errors: Dict[str, str] = {}
    used_indices: Set[int] = set()
    pending: List[Tuple[str, int, int]] = []

    for slot_name, slot in slots.items():
        profile_off = int(slot.base) - flash_base
        profile_size = int(slot.size)
        candidates = _compiled_flash_map_candidates(
            entries,
            profile_off=profile_off,
            profile_size=profile_size,
            exclude_indices=used_indices,
        )
        if len(candidates) == 1:
            compiled = candidates[0]
            resolved[slot_name] = compiled
            used_indices.add(int(compiled["index"]))
        elif len(candidates) > 1:
            errors[slot_name] = (
                "ambiguous compiled flash map: {} entries match off=0x{:X} size=0x{:X}".format(
                    len(candidates), profile_off, profile_size
                )
            )
        else:
            pending.append((slot_name, profile_off, profile_size))

    for slot_name, profile_off, profile_size in pending:
        errors[slot_name] = (
            "no compiled flash-map entry matches off=0x{:X} size=0x{:X}; "
            "size-only resolution is disabled".format(
                profile_off, profile_size
            )
        )
    return resolved, errors


def _read_elf_symbol_names(elf_path: str) -> Tuple[Optional[Set[str]], Optional[str]]:
    path = Path(elf_path)
    if ELFFile is not None:
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
    # Fallback: use nm(1) which is available on virtually all toolchains.
    import subprocess as _sp
    import shutil
    nm_bin = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
    if nm_bin is None:
        return None, "pyelftools not available and nm not found"
    try:
        result = _sp.run(
            [nm_bin, str(path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None, "nm returned exit code {}".format(result.returncode)
        names: Set[str] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                names.add(parts[2])
            elif len(parts) == 2:
                names.add(parts[1])
        if not names:
            return None, "nm produced no symbols"
        return names, None
    except Exception as exc:
        return None, "nm fallback failed: {}".format(exc)


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
        ("offset", ["boot_swap_offset", "swap_offset", "swap_using_offset", "prefer_swap_offset"]),
        ("scratch", ["boot_swap_scratch", "swap_scratch", "swap_using_scratch", "prefer_swap_scratch"]),
        ("move", ["boot_swap_move", "swap_move", "swap_using_move", "prefer_swap_move"]),
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
    checked_slots: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    declared_slots = {
        slot_name: profile.memory.slots[slot_name]
        for slot_name in ("exec", "staging")
        if slot_name in profile.memory.slots
    }
    resolved_slots, resolution_errors = _resolve_compiled_flash_slots(
        entries,
        declared_slots,
        flash_base,
    )
    for slot_name, slot in declared_slots.items():
        profile_off = int(slot.base) - flash_base
        slot_summary: Dict[str, Any] = {
            "slot": slot_name,
            "profile_base": "0x{:08X}".format(int(slot.base)),
            "profile_size": "0x{:X}".format(int(slot.size)),
            "profile_off": "0x{:X}".format(profile_off),
        }
        if slot_name in resolution_errors:
            error = resolution_errors[slot_name]
            slot_summary["status"] = "ambiguous" if error.startswith("ambiguous") else "missing"
            slot_summary["resolution_error"] = error
            mismatches.append("{}: {}".format(slot_name, error))
            checked_slots.append(slot_summary)
            continue
        compiled = resolved_slots[slot_name]
        slot_summary.update(
            {
                # Keep ``area_id`` as a compatibility alias for serialized
                # reports; unlike the old checker, it records the actual
                # compiled ID rather than assuming an ID for the slot role.
                "area_id": compiled["area_id"],
                "compiled_area_id": compiled["area_id"],
                "compiled_off": "0x{:X}".format(compiled["off"]),
                "compiled_size": "0x{:X}".format(compiled["size"]),
            }
        )
        slot_summary["status"] = "match"
        checked_slots.append(slot_summary)

    sector_geometry = validate_swap_sector_geometry(profile)

    # The compiled area table is the authoritative flash-map contract.  A
    # nonuniform or partially covered sector layout is useful diagnostic
    # information, but it is not a compiled-map mismatch: profiles may
    # intentionally describe such layouts for geometry-specific regressions.
    # Keep the advisory nested under ``sector_geometry`` while failing closed
    # only when the ELF's area offsets/sizes differ from the profile.
    if mismatches:
        return {
            "status": "mismatch",
            "reason": "compiled flash map does not match declared slot layout",
            "bootloader_elf": resolved_elf,
            "flash_base": "0x{:08X}".format(flash_base),
            "checked_slots": checked_slots,
            "compiled_entries": entries,
            "mismatches": list(mismatches),
            "sector_geometry": sector_geometry,
        }
    geometry_note = ""
    if sector_geometry.get("status") == "mismatch":
        geometry_note = "; sector geometry advisory: {}".format(
            sector_geometry.get("reason") or "nonuniform or partial sector layout"
        )
    return {
        "status": "match",
        "reason": "compiled flash map matches declared slot layout{}".format(
            geometry_note
        ),
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

    candidate = copy.deepcopy(profile)
    changed_slots: List[Dict[str, str]] = []

    declared_slots = {
        slot_name: candidate.memory.slots[slot_name]
        for slot_name in ("exec", "staging")
        if slot_name in candidate.memory.slots
    }
    resolved_slots, resolution_errors = _resolve_compiled_flash_slots(
        compiled_entries,
        declared_slots,
        flash_base,
    )
    if resolution_errors:
        details = "; ".join(
            "{}: {}".format(slot_name, error)
            for slot_name, error in sorted(resolution_errors.items())
        )
        return None, None, "cannot resolve declared slots in compiled flash map: " + details

    for slot_name, slot in declared_slots.items():
        compiled = resolved_slots[slot_name]
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
    total_writes = _strict_nonnegative_counter(data, "total_writes")
    cap = int(profile.fault_sweep.max_writes_cap)
    if total_writes > cap:
        total_writes = cap
    return CalibrationResult(
        total_writes=total_writes,
        total_erases=_strict_nonnegative_counter(data, "total_erases"),
        trace_file=data.get("trace_file"),
        erase_trace_file=data.get("erase_trace_file"),
        trace_file_bin=data.get("trace_file_bin"),
        erase_trace_file_bin=data.get("erase_trace_file_bin"),
        calibration_exec_hash=data.get("calibration_exec_hash"),
        calibration_boot_outcome=data.get("calibration_boot_outcome"),
        stop_reason=data.get("calibration_stop_reason"),
        emulated_s=data.get("calibration_emulated_s"),
        elapsed_s=data.get("calibration_elapsed_s"),
        pc=data.get("calibration_pc"),
        setup_writes=_strict_nonnegative_counter(data, "setup_writes"),
        total_i2c_transactions=_strict_nonnegative_counter(
            data, "total_i2c_transactions"
        ),
        total_otp_blows=_strict_nonnegative_counter(data, "total_otp_blows"),
    )


def _attempt_calibration_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    def counter(name: str) -> Any:
        value = data.get(name, 0)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    return {
        "writes": counter("total_writes"),
        "erases": counter("total_erases"),
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


def _calibration_boot_evidence_is_success(data: Dict[str, Any]) -> bool:
    """Require explicit successful boot evidence for the trace-less fallback."""
    signals = data.get("signals")
    if not isinstance(signals, dict) or signals.get("expectations_met") is not True:
        return False
    outcomes = []
    for field_name in (
        "calibration_boot_outcome",
        "final_boot_outcome",
        "boot_outcome",
    ):
        if field_name in data:
            value = data[field_name]
            if value is None:
                return False
            outcomes.append(str(value).strip().lower())
    if not outcomes or any(outcome != "success" for outcome in outcomes):
        return False
    if len(set(outcomes)) != 1:
        return False
    return True


def _strict_nonnegative_counter(data: Dict[str, Any], field_name: str) -> int:
    """Read a calibration counter without silently coercing malformed JSON."""
    if field_name not in data:
        return 0
    value = data[field_name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            "calibration {} must be a nonnegative JSON integer (got {!r})".format(
                field_name, value
            )
        )
    return value


def _validate_trace_artifacts(data: Dict[str, Any]) -> Optional[str]:
    """Validate trace paths and CSV contents before coverage classification."""
    path_fields = (
        "trace_file",
        "erase_trace_file",
        "trace_file_bin",
        "erase_trace_file_bin",
    )
    for field_name in path_fields:
        if field_name not in data or data[field_name] in (None, ""):
            continue
        path = data[field_name]
        if not isinstance(path, str):
            return "{} must be a string path or null (got {!r})".format(field_name, path)
        try:
            if not os.path.isfile(path):
                return "{} does not identify a regular file: {}".format(field_name, path)
        except (OSError, TypeError, ValueError) as exc:
            return "{} path could not be checked: {}".format(field_name, exc)

    for binary_field, csv_field in (
        ("trace_file_bin", "trace_file"),
        ("erase_trace_file_bin", "erase_trace_file"),
    ):
        if data.get(binary_field) and not data.get(csv_field):
            return (
                "{} requires its CSV companion {} for coverage classification"
                .format(binary_field, csv_field)
            )

    csv_specs = (
        ("trace_file", ("write_index", "flash_offset", "value")),
        ("erase_trace_file", ("erase_index", "flash_offset")),
    )
    for field_name, required_fields in csv_specs:
        path = data.get(field_name)
        if not path:
            continue
        try:
            with open(path, "r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle, strict=True)
                fieldnames = {name.strip() for name in (reader.fieldnames or []) if name}
                missing = [name for name in required_fields if name not in fieldnames]
                if missing:
                    return "{} is missing required columns: {}".format(
                        field_name, ", ".join(missing)
                    )
                for row_number, row in enumerate(reader, start=2):
                    if None in row:
                        return "{} has malformed CSV content at row {}".format(
                            field_name, row_number
                        )
                    for column in required_fields:
                        raw_value = row.get(column)
                        if raw_value is None or not str(raw_value).strip():
                            return "{} has an empty {} at row {}".format(
                                field_name, column, row_number
                            )
                        try:
                            int(str(raw_value).strip(), 0)
                        except (TypeError, ValueError):
                            return "{} has a non-integer {} at row {}".format(
                                field_name, column, row_number
                            )
                    if field_name == "erase_trace_file":
                        for optional_column in ("writes_at_this_point", "writes_at", "write_index", "write_count_at_erase", "erase_size"):
                            if optional_column in row and str(row[optional_column]).strip():
                                try:
                                    int(str(row[optional_column]).strip(), 0)
                                except (TypeError, ValueError):
                                    return "{} has a non-integer {} at row {}".format(
                                        field_name, optional_column, row_number
                                    )
        except (OSError, UnicodeError, csv.Error, ValueError) as exc:
            return "{} content could not be read: {}".format(field_name, exc)
    return None


def _parse_evidence_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _image_path(profile: ProfileConfig, repo_root: Path, image_name: str) -> Optional[Path]:
    images = getattr(profile, "images", None)
    if not isinstance(images, dict) or image_name not in images:
        return None
    raw_path = images[image_name]
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    try:
        resolver = getattr(profile, "resolve_path", None)
        resolved = resolver(repo_root, raw_path) if callable(resolver) else raw_path
        path = Path(resolved)
        if not path.is_absolute():
            path = repo_root / path
        if not path.is_file():
            return None
        return path
    except (OSError, TypeError, ValueError):
        return None


def _image_digest_for_evidence(
    profile: ProfileConfig, repo_root: Path, image_name: str
) -> Optional[str]:
    """Derive the runtime-comparable image digest without profile-provided labels."""
    path = _image_path(profile, repo_root, image_name)
    if path is None:
        return None
    try:
        raw = path.read_bytes()
        memory = getattr(profile, "memory", None)
        slots = getattr(memory, "slots", None)
        exec_slot = slots.get("exec") if isinstance(slots, dict) else None
        if exec_slot is None:
            return None
        page_size = 4096
        data_size = int(exec_slot.size) - page_size
        if data_size > 0:
            pad_byte = (
                0x00
                if str(getattr(profile, "flash_backend", "")).lower() == "mram"
                else 0xFF
            )
            raw = raw[:data_size].ljust(data_size, bytes([pad_byte]))
        return hashlib.sha256(raw).hexdigest()
    except (OSError, TypeError, ValueError):
        return None


def _image_word_for_evidence(
    profile: ProfileConfig, repo_root: Path, image_name: str, offset: int
) -> Optional[int]:
    path = _image_path(profile, repo_root, image_name)
    if path is None or offset < 0:
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(4)
        if len(raw) != 4:
            return None
        return int.from_bytes(raw, "little")
    except (OSError, ValueError):
        return None


def _slot_bounds(profile: ProfileConfig, slot_name: str) -> Optional[Tuple[int, int]]:
    memory = getattr(profile, "memory", None)
    slots = getattr(memory, "slots", None)
    if not isinstance(slots, dict) or slot_name not in slots:
        return None
    slot = slots[slot_name]
    try:
        base = int(slot.base)
        size = int(slot.size)
    except (AttributeError, TypeError, ValueError):
        return None
    if base < 0 or size < 4:
        return None
    return base, base + size


def _trace_less_boot_state_is_valid(
    profile: ProfileConfig, data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Validate final halted-state addresses instead of trusting sticky boot labels."""
    signals = data.get("signals")
    criteria = getattr(profile, "success_criteria", None)
    if not isinstance(signals, dict) or criteria is None:
        return None
    raw_vtor = signals.get("vtor_final")
    vtor = _parse_evidence_int(raw_vtor)
    if vtor is None:
        return None
    if vtor % 128 != 0:
        return None
    ranges = getattr(getattr(profile, "memory", None), "slots", None)
    if not isinstance(ranges, dict):
        return None
    actual_slot = None
    for name in ranges:
        bounds = _slot_bounds(profile, name)
        if bounds is not None and bounds[0] <= vtor < bounds[1]:
            if actual_slot is not None:
                return None
            actual_slot = str(name).strip().lower()
    if actual_slot is None:
        return None

    reported_slots = []
    for field_name in ("boot_slot", "final_boot_slot"):
        if field_name in data:
            value = data[field_name]
            if value is None or not str(value).strip():
                return None
            reported_slots.append(str(value).strip().lower())
    if any(slot != actual_slot for slot in reported_slots):
        return None
    expected_vtor_slot = str(getattr(criteria, "vtor_in_slot", None) or "").strip().lower()
    if not expected_vtor_slot:
        return None
    if expected_vtor_slot and expected_vtor_slot != "any" and actual_slot != expected_vtor_slot:
        return None
    if expected_vtor_slot == "any" and not actual_slot:
        return None

    pc = _parse_evidence_int(signals.get("pc"))
    if pc is None:
        return None
    pc_for_range = pc & ~1
    expected_pc_slot = str(getattr(criteria, "pc_in_slot", None) or "").strip().lower()
    if expected_pc_slot:
        if expected_pc_slot == "any":
            if not any(
                (bounds := _slot_bounds(profile, name)) is not None
                and bounds[0] <= pc_for_range < bounds[1]
                for name in ranges
            ):
                return None
        else:
            bounds = _slot_bounds(profile, expected_pc_slot)
            if bounds is None or not bounds[0] <= pc_for_range < bounds[1]:
                return None
    else:
        bounds = _slot_bounds(profile, actual_slot)
        if bounds is None or not bounds[0] <= pc_for_range < bounds[1]:
            return None
    return {"slot": actual_slot, "vtor": vtor, "pc": pc}


def _trace_less_content_evidence(
    profile: ProfileConfig,
    data: Dict[str, Any],
    repo_root: Path,
) -> Optional[Dict[str, Any]]:
    """Return definitive, baseline-distinct content evidence, or None when unsafe.

    A marker must be explicitly configured, nonzero, and observed exactly.
    Hash labels such as ``expected_image`` are deliberately insufficient:
    discovery needs the exact runtime hash and an independently derived
    expected target hash.
    """
    if not _calibration_boot_evidence_is_success(data):
        return None
    try:
        total_writes = _strict_nonnegative_counter(data, "total_writes")
        total_erases = _strict_nonnegative_counter(data, "total_erases")
    except ValueError:
        return None
    if total_writes < 0 or total_erases < 0:
        return None
    if total_writes <= 0 and total_erases <= 0:
        return None

    signals = data.get("signals")
    criteria = getattr(profile, "success_criteria", None)
    if criteria is None:
        return None

    boot_state = _trace_less_boot_state_is_valid(profile, data)
    if boot_state is None:
        return None
    boot_slot = boot_state["slot"]
    expected_vtor_slot = str(getattr(criteria, "vtor_in_slot", None) or "").strip().lower()
    if expected_vtor_slot == "any" and not boot_slot:
        return None
    if expected_vtor_slot and expected_vtor_slot != "any" and boot_slot != expected_vtor_slot:
        return None
    expected_hash_slot = str(getattr(criteria, "image_hash_slot", None) or "").strip().lower()
    if expected_hash_slot and expected_hash_slot != "any" and boot_slot != expected_hash_slot:
        return None

    marker_value = _parse_evidence_int(getattr(criteria, "marker_value", None))
    marker_address = _parse_evidence_int(getattr(criteria, "marker_address", None))
    marker_actual = _parse_evidence_int(signals.get("marker_actual"))
    marker_configured = (
        marker_address is not None
        and marker_address != 0
        and marker_value is not None
        and marker_value != 0
    )
    marker_evidence = bool(
        marker_configured
        and signals.get("marker_ok") is True
        and marker_actual == marker_value
    )

    expected_name = str(getattr(criteria, "expected_image", None) or "staging").strip()
    exec_hash = _image_digest_for_evidence(profile, repo_root, "exec")
    target_hash = _image_digest_for_evidence(profile, repo_root, expected_name)
    hashes_distinct = bool(exec_hash and target_hash and exec_hash != target_hash)
    observed_hashes = []
    for value in (
        data.get("calibration_exec_hash"),
        signals.get("calibration_exec_hash"),
        signals.get("image_hash_actual"),
    ):
        if value is None:
            continue
        normalized = str(value).strip().lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            return None
        observed_hashes.append(normalized)
    observed_hash = observed_hashes[0] if observed_hashes else None
    hash_evidence = bool(
        hashes_distinct
        and observed_hash is not None
        and all(value == observed_hash for value in observed_hashes)
        and observed_hash == target_hash
    )
    hash_configured = bool(getattr(criteria, "image_hash", False))

    marker_details = None
    if marker_evidence:
        exec_bounds = _slot_bounds(profile, "exec")
        baseline_offset = None
        target_offset = None
        exec_load = exec_bounds[0] if exec_bounds is not None else None
        try:
            load_addresses = profile.effective_image_load_addresses()
            exec_load = int(load_addresses.get("exec", exec_load))
        except (AttributeError, TypeError, ValueError):
            pass
        if exec_bounds is not None and exec_bounds[0] <= marker_address <= exec_bounds[1] - 4:
            target_offset = marker_address - exec_bounds[0]
            baseline_offset = marker_address - exec_load if exec_load is not None else None
            if baseline_offset is not None and baseline_offset < 0:
                baseline_offset = None
        baseline_word = (
            _image_word_for_evidence(profile, repo_root, "exec", baseline_offset)
            if baseline_offset is not None
            else None
        )
        target_word = (
            _image_word_for_evidence(profile, repo_root, expected_name, target_offset)
            if target_offset is not None
            else None
        )
        if (
            baseline_offset is None
            or target_offset is None
            or baseline_word is None
            or target_word is None
            or baseline_word == marker_value
            or target_word != marker_value
        ):
            marker_evidence = False
        else:
            marker_details = {
                "address": "0x{:08X}".format(marker_address),
                "offset": target_offset,
                "baseline_offset": baseline_offset,
                "target_offset": target_offset,
                "expected": "0x{:08X}".format(marker_value),
                "observed": "0x{:08X}".format(marker_actual),
                "baseline": "0x{:08X}".format(baseline_word),
                "target": "0x{:08X}".format(target_word),
            }
    if marker_configured and hash_configured:
        if not (marker_evidence and hash_evidence):
            return None
        kind = "exact_marker_and_expected_image_hash"
    elif marker_evidence:
        kind = "exact_marker"
    elif hash_configured and hash_evidence:
        kind = "exact_expected_image_hash"
    else:
        return None
    return {
        "kind": kind,
        "boot_outcome": "success",
        "boot_slot": boot_slot,
        "vtor_final": "0x{:08X}".format(boot_state["vtor"]),
        "pc_final": "0x{:08X}".format(boot_state["pc"]),
        "outcomes": {
            field_name: str(data[field_name]).strip().lower()
            for field_name in (
                "calibration_boot_outcome",
                "final_boot_outcome",
                "boot_outcome",
            )
            if field_name in data
        },
        "writes": total_writes,
        "erases": total_erases,
        "target_image": expected_name,
        "marker": marker_details,
        "hash": {
            "baseline": exec_hash,
            "target": target_hash,
            "observed": observed_hash,
            "distinct": hashes_distinct,
        } if hash_configured else None,
    }


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

        if not isinstance(data, dict):
            _cleanup_generated_robot_files(robot_vars)
            attempts.append(
                TriggerDiscoveryAttempt(
                    name=strategy.name,
                    update_trigger=None,
                    image_load_addresses={},
                    image_overrides={},
                    calibration={},
                    coverage={
                        "status": "unavailable",
                        "reason": "Calibration returned a non-object result.",
                    },
                    error="calibration result is not a JSON object",
                )
            )
            continue

        try:
            validated_counters = {
                name: _strict_nonnegative_counter(data, name)
                for name in (
                    "total_writes",
                    "total_erases",
                    "setup_writes",
                    "total_i2c_transactions",
                    "total_otp_blows",
                )
            }
            total_writes = validated_counters["total_writes"]
            total_erases = validated_counters["total_erases"]
        except ValueError as exc:
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
                    calibration=_attempt_calibration_dict(data),
                    coverage={
                        "status": "unavailable",
                        "reason": "Calibration counters are malformed; candidate rejected.",
                    },
                    error=str(exc),
                )
            )
            _cleanup_generated_robot_files(robot_vars)
            continue

        trace_error = _validate_trace_artifacts(data)
        if trace_error:
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
                    calibration=_attempt_calibration_dict(data),
                    coverage={
                        "status": "unavailable",
                        "reason": "Calibration trace coverage unavailable: {}".format(trace_error),
                    },
                    error=trace_error,
                )
            )
            _cleanup_generated_robot_files(robot_vars)
            continue

        try:
            coverage = summarize_calibration_coverage(
                trace_file=data.get("trace_file"),
                erase_trace_file=data.get("erase_trace_file"),
                flash_base=_flash_base(candidate),
                slots=candidate.memory.slots,
                page_size=getattr(candidate.memory, "page_size", 4096),
                metadata_regions=getattr(candidate, "metadata_fault_regions", None),
            )
            if not isinstance(coverage, dict):
                raise ValueError("coverage classifier returned a non-object result")
            if "status" in coverage and not isinstance(coverage["status"], str):
                raise ValueError("coverage classifier returned a non-string status")
        except Exception as exc:
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
                    calibration=_attempt_calibration_dict(data),
                    coverage={
                        "status": "unavailable",
                        "reason": "Calibration trace coverage unavailable: {}".format(exc),
                    },
                    error="failed to classify calibration trace: {}".format(exc),
                )
            )
            _cleanup_generated_robot_files(robot_vars)
            continue

        completed = calibration_completed(
            data.get("calibration_stop_reason"),
            candidate.expect.control_outcome,
            total_writes=total_writes,
            total_erases=total_erases,
        )
        trace_available = any(
            bool(data.get(name)) and os.path.exists(str(data.get(name)))
            for name in (
                "trace_file",
                "erase_trace_file",
                "trace_file_bin",
                "erase_trace_file_bin",
            )
        )
        target_boot_evidence = None
        if completed and not trace_available:
            target_boot_evidence = _trace_less_content_evidence(
                candidate, data, repo_root
            )
        selected = bool(
            completed
            and (
                (
                    coverage.get("status") in {"slot_activity", "named_metadata_only"}
                    and _calibration_matches_expected_boot(data)
                )
                or target_boot_evidence is not None
            )
        )
        if target_boot_evidence is not None:
            trace_status = coverage.get("status")
            trace_reason = coverage.get("reason")
            coverage = {
                "status": "verified_target_boot",
                "reason": (
                    "Calibration had no bounded NVM trace, but the halted-state "
                    "boot result exactly matched the configured target content."
                ),
                "trace_less_evidence": target_boot_evidence,
                "trace_status": trace_status,
                "trace_reason": trace_reason,
            }
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
