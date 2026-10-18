#!/usr/bin/env python3
"""Fast MCUboot fault-state evaluator for bulk-copy power-loss points.

This module is intentionally conservative. It only short-circuits points
outside the trailer/status window, where MCUboot's recovery decision is driven
by stable trailer metadata rather than the bulk data bytes that were being
copied when power was lost.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, Mapping, MutableMapping, Optional


MCUBOOT_GOOD_MAGIC = struct.pack(
    "<IIII",
    0xF395C277,
    0x7FEFD260,
    0x0F505235,
    0x8079B62C,
)
MCUBOOT_IMAGE_MAGIC = 0x96F3B83D


def _fmt_u32(value: int) -> str:
    return "0x{0:08X}".format(int(value) & 0xFFFFFFFF)


def _slot_slice(flash: bytes, *, flash_base: int, base: int, size: int) -> bytes:
    start = int(base) - int(flash_base)
    end = start + int(size)
    return bytes(flash[start:end])


def _read_u32_le(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0xFFFFFFFF
    return struct.unpack_from("<I", blob, offset)[0]


def _vector_table_offset(slot_bytes: bytes, configured_offset: int) -> int:
    """Resolve an explicit vector offset or an MCUboot image header size."""
    configured = max(0, int(configured_offset))
    if configured:
        return configured
    if len(slot_bytes) < 12 or _read_u32_le(slot_bytes, 0) != MCUBOOT_IMAGE_MAGIC:
        return 0
    header_size = int(struct.unpack_from("<H", slot_bytes, 8)[0])
    if header_size < 32 or header_size % 4 != 0 or header_size + 8 > len(slot_bytes):
        return 0
    return header_size


def _flag_state(raw: int) -> str:
    if raw == 0xFFFFFFFF:
        return "unset"
    if raw == 0x00000001:
        return "set"
    return "other"


def _magic_state(raw: bytes) -> str:
    if raw == MCUBOOT_GOOD_MAGIC:
        return "good"
    if raw == (b"\xFF" * len(MCUBOOT_GOOD_MAGIC)):
        return "unset"
    if raw[:8] == MCUBOOT_GOOD_MAGIC[:8] and raw[8:] == (b"\xFF" * 8):
        return "partial"
    return "other"


def _vector_snapshot(
    slot_bytes: bytes,
    *,
    slot_base: int,
    slot_size: int,
    sram_start: int,
    sram_end: int,
    vector_table_offset: int,
) -> Dict[str, Any]:
    vector_off = max(0, int(vector_table_offset))
    sp = _read_u32_le(slot_bytes, vector_off)
    reset = _read_u32_le(slot_bytes, vector_off + 4)
    reset_pc = int(reset) & ~1
    vector_base = int(slot_base) + vector_off
    valid = (
        int(sram_start) <= int(sp) <= int(sram_end)
        and ((int(reset) & 1) == 1)
        and vector_base <= reset_pc < (int(slot_base) + int(slot_size))
    )
    return {
        "sp": int(sp),
        "reset": int(reset),
        "pc": int(reset_pc),
        "valid": bool(valid),
        "vector_base": int(vector_base),
    }


def _slot_state(
    flash: bytes,
    *,
    flash_base: int,
    slot_name: str,
    slot_info: Mapping[str, int],
    execution_base: int,
    sram_start: int,
    sram_end: int,
    vector_table_offset: int,
    trailer_align: int,
) -> Dict[str, Any]:
    base = int(slot_info["base"])
    size = int(slot_info["size"])
    slot_bytes = _slot_slice(flash, flash_base=flash_base, base=base, size=size)
    trailer_magic_off = size - 16
    image_ok_off = trailer_magic_off - int(trailer_align)
    copy_done_off = trailer_magic_off - (2 * int(trailer_align))
    resolved_vector_offset = _vector_table_offset(slot_bytes, vector_table_offset)
    vector = _vector_snapshot(
        slot_bytes,
        slot_base=int(execution_base),
        slot_size=size,
        sram_start=sram_start,
        sram_end=sram_end,
        vector_table_offset=resolved_vector_offset,
    )
    return {
        "name": slot_name,
        "base": base,
        "size": size,
        "bytes": slot_bytes,
        "vector": vector,
        "vector_table_offset": resolved_vector_offset,
        "magic_state": _magic_state(slot_bytes[trailer_magic_off:trailer_magic_off + 16]),
        "image_ok": _flag_state(_read_u32_le(slot_bytes, image_ok_off)),
        "copy_done": _flag_state(_read_u32_le(slot_bytes, copy_done_off)),
    }


def should_use_execute_mode(
    fault_address: Optional[int],
    slot_config: Mapping[str, Any],
) -> bool:
    """Return True when a point is too close to MCUboot trailer/status state."""
    if fault_address is None:
        return True
    trailer_window = int(slot_config.get("trailer_window", 4096))
    matched_slot = False
    for slot_info in slot_config.get("slots", {}).values():
        base = int(slot_info["base"])
        size = int(slot_info["size"])
        if not (base <= int(fault_address) < base + size):
            continue
        matched_slot = True
        trailer_start = base + max(0, size - trailer_window)
        trailer_end = base + size
        if trailer_start <= int(fault_address) < trailer_end:
            return True
    if matched_slot:
        return False
    # Scratch, bootloader, and other non-slot writes can influence recovery
    # but are not represented by this two-slot evaluator.
    return True


def _predict_final_source(exec_slot: Mapping[str, Any], staging_slot: Mapping[str, Any]) -> str:
    # Revert-in-progress / revert-requested:
    if (
        exec_slot.get("magic_state") == "good"
        and exec_slot.get("copy_done") == "set"
        and exec_slot.get("image_ok") != "set"
    ):
        return "staging"
    # Fresh or resumed upgrade: staging trailer still requests the swap.
    if staging_slot.get("magic_state") == "good" and exec_slot.get("copy_done") != "set":
        return "staging"
    # Completed/confirmed upgrade and all non-updating steady states boot exec.
    return "exec"


MCUBOOT_TLV_INFO_MAGIC = 0x6907
MCUBOOT_TLV_PROT_INFO_MAGIC = 0x6908


def _mcuboot_validated_image_extent(blob: bytes, slot_size: int = 0) -> Optional[int]:
    if not blob or len(blob) < 32:
        return None
    if _read_u32_le(blob, 0) != MCUBOOT_IMAGE_MAGIC:
        return None
    ih_hdr_size, ih_protect_tlv_size, ih_img_size = struct.unpack_from("<HHI", blob, 8)
    if ih_hdr_size < 32:
        return None
    prot_off = int(ih_hdr_size) + int(ih_img_size)
    unprot_off = prot_off + int(ih_protect_tlv_size)
    if ih_protect_tlv_size > 0:
        if ih_protect_tlv_size < 4 or prot_off + 4 > len(blob):
            return None
        prot_magic, prot_tot = struct.unpack_from("<HH", blob, prot_off)
        if prot_magic != MCUBOOT_TLV_PROT_INFO_MAGIC or prot_tot != ih_protect_tlv_size:
            return None
    if unprot_off + 4 > len(blob):
        return None
    tlv_magic, tlv_tot = struct.unpack_from("<HH", blob, unprot_off)
    if tlv_magic != MCUBOOT_TLV_INFO_MAGIC or tlv_tot < 4:
        return None
    extent = unprot_off + int(tlv_tot)
    if extent <= 0:
        return None
    if int(slot_size) > 0 and extent > int(slot_size):
        return None
    return extent


def resolve_slot_hash_extent(
    slot_bytes: bytes,
    *,
    slot_size: int,
    slot_base: int = 0,
    erase_regions: Any = None,
    declared_sector_size: Optional[int] = None,
) -> tuple[int, str]:
    slot_size = int(slot_size)
    mcu_extent = _mcuboot_validated_image_extent(slot_bytes, slot_size=slot_size)
    if mcu_extent is not None:
        return mcu_extent, "mcuboot_header"
    if slot_size > 0:
        slot_end = int(slot_base) + slot_size
        last_addr = slot_end - 1
        for entry in erase_regions or ():
            try:
                if isinstance(entry, Mapping):
                    region_base = int(entry["base"])
                    region_size = int(entry["size"])
                    sector_size = int(entry.get("sector_size", entry.get("erase_size")))
                    region_end = region_base + region_size
                elif hasattr(entry, "base") and hasattr(entry, "size"):
                    region_base = int(entry.base)
                    region_size = int(entry.size)
                    sector_size = int(entry.sector_size)
                    region_end = region_base + region_size
                else:
                    region_base, region_end, sector_size = (
                        int(entry[0]),
                        int(entry[1]),
                        int(entry[2]),
                    )
            except Exception:
                continue
            if region_base < 0 or region_end <= region_base or sector_size <= 0:
                continue
            if region_base <= last_addr < region_end:
                sector_start = (
                    region_base + ((last_addr - region_base) // sector_size) * sector_size
                )
                last_sector = min(sector_size, slot_end - max(int(slot_base), sector_start))
                if 0 < last_sector < slot_size:
                    return slot_size - last_sector, "last_erase_sector"
        if declared_sector_size is not None and 0 < int(declared_sector_size) < slot_size:
            return slot_size - int(declared_sector_size), "last_erase_sector"
    data_size = slot_size - 4096 if slot_size > 4096 else slot_size
    return data_size, "fallback_4096"


def _hash_slot_bytes(
    slot_bytes: bytes,
    *,
    slot_size: int,
    page_size: int = 4096,
    pad_byte: int = 0xFF,
    slot_base: int = 0,
    erase_regions: Any = None,
    declared_sector_size: Optional[int] = None,
) -> str:
    eff_sector_size = declared_sector_size
    if eff_sector_size is None and int(page_size) != 4096:
        eff_sector_size = int(page_size)
    data_size, _path = resolve_slot_hash_extent(
        slot_bytes,
        slot_size=int(slot_size),
        slot_base=int(slot_base),
        erase_regions=erase_regions,
        declared_sector_size=eff_sector_size,
    )
    raw = bytes(slot_bytes)
    if data_size > 0:
        if len(raw) >= data_size:
            raw = raw[:data_size]
        else:
            raw = raw + (bytes([int(pad_byte) & 0xFF]) * (data_size - len(raw)))
    return hashlib.sha256(raw).hexdigest()


def predict_boot_outcome(
    faulted_flash: bytes,
    slot_config: Mapping[str, Any],
) -> Dict[str, Any]:
    """Predict final MCUboot outcome from reconstructed flash bytes."""
    flash_base = int(slot_config["flash_base"])
    vector_table_offset = int(slot_config.get("vector_table_offset", 0))
    trailer_align = int(slot_config.get("trailer_align", 8))
    slots = slot_config["slots"]
    exec_slot = _slot_state(
        faulted_flash,
        flash_base=flash_base,
        slot_name="exec",
        slot_info=slots["exec"],
        execution_base=int(slots["exec"]["base"]),
        sram_start=int(slot_config["sram_start"]),
        sram_end=int(slot_config["sram_end"]),
        vector_table_offset=vector_table_offset,
        trailer_align=trailer_align,
    )
    staging_slot = _slot_state(
        faulted_flash,
        flash_base=flash_base,
        slot_name="staging",
        slot_info=slots["staging"],
        execution_base=int(slots["exec"]["base"]),
        sram_start=int(slot_config["sram_start"]),
        sram_end=int(slot_config["sram_end"]),
        vector_table_offset=vector_table_offset,
        trailer_align=trailer_align,
    )

    final_source = _predict_final_source(exec_slot, staging_slot)
    final_slot = exec_slot if final_source == "exec" else staging_slot
    final_vector = final_slot["vector"]
    actual_vtor = int(final_vector["vector_base"]) if final_vector["valid"] else 0
    boot_slot = "exec" if final_vector["valid"] else None
    vtor_ok = boot_slot == "exec"
    vtor_aligned = actual_vtor == 0 or (actual_vtor % 128 == 0)
    pc_ok = bool(final_vector["valid"])

    marker_ok = True
    marker_actual = 0
    marker_addr = slot_config.get("marker_address")
    marker_value = slot_config.get("marker_value")
    if marker_addr is not None and marker_value is not None and final_vector["valid"]:
        marker_offset = int(marker_addr) - int(slots["exec"]["base"])
        marker_actual = _read_u32_le(final_slot["bytes"], marker_offset)
        marker_ok = int(marker_actual) == int(marker_value)

    hash_result = None
    matched_image = None
    actual_hash = None
    if bool(slot_config.get("image_hash")) and final_vector["valid"]:
        actual_hash = _hash_slot_bytes(
            final_slot["bytes"],
            slot_size=int(slots["exec"]["size"]),
            page_size=int(slot_config.get("page_size", 4096)),
            pad_byte=int(slot_config.get("pad_byte", 0xFF)),
            slot_base=int(slots["exec"]["base"]),
            erase_regions=slot_config.get("erase_regions"),
            declared_sector_size=slot_config.get("declared_sector_size"),
        )
        exec_hash = str(slot_config.get("image_exec_sha256", "") or "")
        staging_hash = str(slot_config.get("image_staging_sha256", "") or "")
        expected_hash = str(slot_config.get("expected_exec_sha256", "") or "")
        expected_name = str(slot_config.get("expected_image", "") or "")
        allowed_entries = list(slot_config.get("allowed_image_hashes", []) or [])
        for entry in allowed_entries:
            if actual_hash == str(entry.get("sha256", "") or ""):
                matched_image = str(entry.get("name", "") or "") or None
                break
        if matched_image is None and expected_hash and actual_hash == expected_hash:
            matched_image = expected_name or "expected"
        if matched_image is None and actual_hash and actual_hash == exec_hash:
            matched_image = "exec"
        if matched_image is None and actual_hash and actual_hash == staging_hash:
            matched_image = "staging"
        if matched_image == "exec":
            hash_result = "exec_image"
        elif matched_image == "staging":
            hash_result = "staging_image"
        elif matched_image is not None:
            hash_result = "expected_image"
        else:
            hash_result = "unknown"
        if allowed_entries:
            hash_ok = any(
                actual_hash == str(entry.get("sha256", "") or "")
                for entry in allowed_entries
            )
        else:
            hash_ok = not expected_hash or actual_hash == expected_hash
        marker_ok = marker_ok and hash_ok

    expectations_met = bool(final_vector["valid"]) and vtor_ok and vtor_aligned and pc_ok and marker_ok
    if not final_vector["valid"]:
        boot_outcome = "no_boot"
    elif not vtor_aligned:
        boot_outcome = "misaligned_vtor"
    elif not pc_ok:
        boot_outcome = "wrong_pc"
    elif not marker_ok:
        boot_outcome = "wrong_image"
    else:
        boot_outcome = "success"

    signals: Dict[str, Any] = {
        "vtor": _fmt_u32(actual_vtor),
        "vtor_final": _fmt_u32(actual_vtor),
        "vtor_sticky": False,
        "execution_observed": bool(final_vector["valid"]),
        "vtor_aligned": bool(vtor_aligned),
        "vtor_ok": bool(vtor_ok),
        "pc": _fmt_u32(final_vector["pc"]),
        "pc_ok": bool(pc_ok),
        "marker_ok": bool(marker_ok),
        "marker_actual": _fmt_u32(marker_actual),
        "expectations_met": bool(expectations_met),
        "state_evaluator_predicted_source": final_source,
        "state_evaluator_exec_magic_state": exec_slot["magic_state"],
        "state_evaluator_exec_copy_done": exec_slot["copy_done"],
        "state_evaluator_exec_image_ok": exec_slot["image_ok"],
        "state_evaluator_staging_magic_state": staging_slot["magic_state"],
        "state_evaluator_exec_vector_offset": exec_slot["vector_table_offset"],
        "state_evaluator_staging_vector_offset": staging_slot["vector_table_offset"],
        "trace_replay_mode": "state_evaluator",
    }
    if hash_result is not None:
        signals["image_hash_match"] = hash_result
    if actual_hash is not None:
        signals["image_hash_actual"] = actual_hash
    if matched_image is not None:
        signals["matched_image"] = matched_image
    image_hash_slot = str(slot_config.get("image_hash_slot", "") or "")
    if image_hash_slot:
        signals["image_hash_slot"] = image_hash_slot

    return {
        "boot_outcome": boot_outcome,
        "boot_slot": boot_slot,
        "signals": signals,
    }
