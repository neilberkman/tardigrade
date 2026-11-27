# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-
"""First-cut persistent-state computation, duplicate grouping, and phase-spread capping.

Reuses the canonical persistent-state representation and operation semantics
from ``recovery_state.py`` so single-cut planning, two-cut recovery-state
search, and point accounting share one definition of persistent state.
"""

import csv
import hashlib
import json
import os
import re
import struct

from boundary_snapshot import (
    MAGIC as _BOUNDARY_SNAPSHOT_MAGIC,
    read_snapshot as _read_boundary_snapshot,
)
from recovery_state import (
    PersistentState,
    apply_completed_operation,
    apply_interrupted_operation,
    merge_operation_traces,
)


SWEEP_STRATEGY_DISTINCT_STATES = "distinct_states"
VALID_SWEEP_STRATEGIES = ("heuristic", "exhaustive", SWEEP_STRATEGY_DISTINCT_STATES)

# Fault types whose Phase-1 persistent state is completely determined by cutting
# at the traced calibration write or erase operation.
SUPPORTED_DISTINCT_STATE_FAULT_TYPES = (
    "power_loss",
    "interrupted_erase",
    "swap_progress",
)


def draw_torn_word_for_point(fault_at, choices, seed=0):
    """Draw the deterministic torn-word mode for one zero-based operation index.

    Uses the exact SplitMix64 finalizer over ``(seed, fault_at)`` used by the
    Renode runtime harness so host planning and device execution always draw
    identical per-point outcomes.
    """
    if not choices:
        raise ValueError("choices must be non-empty")
    mask64 = 0xFFFFFFFFFFFFFFFF
    x = (((int(seed) & 0xFFFFFFFF) << 32) | (int(fault_at) & 0xFFFFFFFF)) & mask64
    x = (x + 0x9E3779B97F4A7C15) & mask64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & mask64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & mask64
    x = x ^ (x >> 31)
    total = sum(int(weight) for _, weight in choices)
    if total <= 0:
        raise ValueError("choices total weight must be positive")
    pick = x % total
    for mode, weight in choices:
        if pick < int(weight):
            return str(mode)
        pick -= int(weight)
    return str(choices[-1][0])


def resolve_operation_torn_word(operation_index, default_mode, choices=(), seed=0):
    """Return the torn-word mode for ``operation_index``."""
    if choices:
        return draw_torn_word_for_point(operation_index, choices, seed=seed)
    return str(default_mode or "fixed").strip().lower()


def _little_endian_bytes(value, width):
    raw = bytearray(int(width))
    remaining = int(value)
    for idx in range(int(width)):
        raw[idx] = (remaining >> (8 * idx)) & 0xFF
    return bytes(raw)


def _little_endian_int(raw_bytes):
    if isinstance(raw_bytes, str):
        text = raw_bytes.strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        decoded = bytearray(
            int(text[idx : idx + 2], 16) for idx in range(0, len(text), 2)
        )
    else:
        decoded = bytearray(raw_bytes)
    value = 0
    for idx, byte in enumerate(decoded):
        value |= (int(byte) & 0xFF) << (8 * idx)
    return value


def _seed_elf_load_segments(buf, flash_base, elf_path):
    """Apply the file-backed PT_LOAD bytes that the runtime loads onto NVM.

    The runtime loader writes both the VMA and a distinct LMA and pads each
    segment write to a 32-bit boundary. Mirror that behavior here so erase
    cuts in bootloader sectors use the actual clean baseline.
    """
    from profile_loader import ProfileError

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise ProfileError(
            "fault_sweep.sweep_strategy: distinct_states requires pyelftools "
            "to reconstruct bootloader PT_LOAD bytes from '{}'".format(elf_path)
        )

    try:
        with open(str(elf_path), "rb") as stream:
            elf = ELFFile(stream)
            load_segments = [
                segment
                for segment in elf.iter_segments()
                if segment.header.p_type == "PT_LOAD"
                and int(segment.header.p_filesz) > 0
            ]
            if not load_segments:
                raise ValueError("ELF has no file-backed PT_LOAD segments")
            for segment in load_segments:
                data = bytearray(segment.data())
                while len(data) % 4:
                    data.append(0)
                addresses = [int(segment.header.p_vaddr)]
                paddr = int(segment.header.p_paddr)
                if paddr != addresses[0]:
                    addresses.append(paddr)
                for address in addresses:
                    start = max(int(flash_base), address)
                    end = min(int(flash_base) + len(buf), address + len(data))
                    if start >= end:
                        continue
                    source_start = start - address
                    dest_start = start - int(flash_base)
                    length = end - start
                    buf[dest_start : dest_start + length] = data[
                        source_start : source_start + length
                    ]
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(
            "fault_sweep.sweep_strategy: distinct_states could not reconstruct "
            "bootloader PT_LOAD bytes from '{}': {}".format(elf_path, exc)
        )


def classify_operation_phase_region(
    address,
    slots=None,
    page_size=4096,
    partitions=None,
    metadata_regions=None,
    bootloader_region=None,
    nvs_region=None,
):
    """Classify an operation's bus address into a semantic region label.

    Contiguous operations targeting the same region form one trace phase (for
    example, a bulk slot copy, a trailer update, or a scratch erase).
    """
    addr = int(address)
    eff_page_size = max(1, int(page_size or 4096))

    if bootloader_region is not None:
        b_start, b_end = int(bootloader_region[0]), int(bootloader_region[1])
        if b_start <= addr < b_end:
            return "bootloader"

    for entry in metadata_regions or ():
        name, m_start, m_end = str(entry[0]), int(entry[1]), int(entry[2])
        if m_start <= addr < m_end:
            return "metadata:{}".format(name)

    for entry in partitions or ():
        name, p_start, p_end = str(entry[0]), int(entry[1]), int(entry[2])
        if p_start <= addr < p_end:
            return name

    if nvs_region is not None:
        n_start, n_end = int(nvs_region[0]), int(nvs_region[1])
        if n_start <= addr < n_end:
            return "nvs"

    slot_items = list((slots or {}).items())
    for slot_name, bounds in slot_items:
        s_start, s_end = int(bounds[0]), int(bounds[1])
        if s_start <= addr < s_end:
            if "scratch" in str(slot_name).lower():
                return str(slot_name)
            slot_size = s_end - s_start
            if slot_size > eff_page_size:
                trailer_size = eff_page_size
            elif slot_size >= 64:
                trailer_size = min(64, max(16, slot_size // 4))
            else:
                trailer_size = 0
            if trailer_size > 0 and addr >= (s_end - trailer_size):
                return "{}_trailer".format(slot_name)
            return "{}_data".format(slot_name)

    if not slot_items and not partitions and not metadata_regions:
        return "page_{}".format(addr // eff_page_size)
    return "outside"


def segment_trace_phases(
    operations,
    flash_base=0,
    slots=None,
    page_size=4096,
    partitions=None,
    metadata_regions=None,
    bootloader_region=None,
    nvs_region=None,
):
    """Segment merged calibration operations into contiguous region phases.

    Returns ``(phases, operation_phase_map)`` where ``phases`` is a list of
    phase dictionaries in trace execution order and ``operation_phase_map``
    maps each operation's ``sequence`` integer to its ``phase_index``.
    """
    phases = []
    operation_phase_map = {}
    base = int(flash_base or 0)

    for position, operation in enumerate(operations):
        seq = int(operation.get("sequence", position))
        offset = int(operation.get("offset", 0))
        address = base + offset
        region = classify_operation_phase_region(
            address,
            slots=slots,
            page_size=page_size,
            partitions=partitions,
            metadata_regions=metadata_regions,
            bootloader_region=bootloader_region,
            nvs_region=nvs_region,
        )
        if not phases or phases[-1]["region"] != region:
            phases.append(
                {
                    "phase_index": len(phases),
                    "region": region,
                    "start_sequence": seq,
                    "end_sequence": seq,
                    "operation_count": 1,
                    "candidate_cuts": 0,
                    "distinct_states": 0,
                    "selected_states": 0,
                    "capped_states": 0,
                    "tested_in_full": False,
                    "selected_representatives": [],
                    "omitted_representatives": [],
                }
            )
        else:
            phases[-1]["end_sequence"] = seq
            phases[-1]["operation_count"] += 1
        operation_phase_map[seq] = phases[-1]["phase_index"]

    return phases, operation_phase_map


def _select_evenly_spaced_indices(count, quota):
    """Deterministically select ``quota`` indices from ``range(count)``."""
    total = int(count)
    target = int(quota)
    if target <= 0 or total <= 0:
        return []
    if target >= total:
        return list(range(total))
    if target == 1:
        return [0]
    selected = []
    used = set()
    for i in range(target):
        idx = int(round((i * (total - 1)) / float(target - 1)))
        if idx < 0:
            idx = 0
        elif idx >= total:
            idx = total - 1
        if idx in used:
            for candidate in range(idx + 1, total):
                if candidate not in used:
                    idx = candidate
                    break
            else:
                for candidate in range(idx - 1, -1, -1):
                    if candidate not in used:
                        idx = candidate
                        break
        used.add(idx)
        selected.append(idx)
    selected.sort()
    return selected


def select_capped_states_across_phases(representatives, phases, cap=None):
    """Apply an optional cap by spreading selection across trace phases.

    Uses progressive water-filling over active phases so short phases (whose
    distinct-state count fits within the fair per-phase share) are tested in
    full and long phases share the remaining budget without starving other
    phases. Within any capped phase, representatives are sampled at evenly
    spaced positions including the phase's first and last distinct states.
    """
    phase_reps = {int(phase["phase_index"]): [] for phase in phases}
    for rep in representatives:
        p_idx = int(rep.get("phase_index", 0))
        if p_idx not in phase_reps:
            phase_reps[p_idx] = []
        phase_reps[p_idx].append(rep)

    for phase in phases:
        p_idx = int(phase["phase_index"])
        phase["distinct_states"] = len(phase_reps.get(p_idx, ()))

    total_distinct = len(representatives)
    if cap is not None:
        cap = int(cap)
        if cap < 1:
            raise ValueError("cap must be a positive integer")

    if cap is None or total_distinct <= cap:
        quotas = {
            int(phase["phase_index"]): len(phase_reps.get(int(phase["phase_index"]), ()))
            for phase in phases
        }
    else:
        active_phase_indices = [
            int(phase["phase_index"])
            for phase in phases
            if len(phase_reps.get(int(phase["phase_index"]), ())) > 0
        ]
        quotas = {int(phase["phase_index"]): 0 for phase in phases}
        if len(active_phase_indices) > cap:
            chosen_positions = _select_evenly_spaced_indices(
                len(active_phase_indices), cap
            )
            for pos in chosen_positions:
                quotas[active_phase_indices[pos]] = 1
        else:
            remaining_budget = int(cap)
            unfrozen = list(active_phase_indices)
            while unfrozen:
                share = remaining_budget // len(unfrozen)
                short = [
                    p_idx
                    for p_idx in unfrozen
                    if len(phase_reps[p_idx]) <= share
                ]
                if short:
                    for p_idx in short:
                        count = len(phase_reps[p_idx])
                        quotas[p_idx] = count
                        remaining_budget -= count
                    short_set = set(short)
                    unfrozen = [
                        p_idx for p_idx in unfrozen if p_idx not in short_set
                    ]
                    continue
                for p_idx in unfrozen:
                    quotas[p_idx] = share
                remainder = remaining_budget - (share * len(unfrozen))
                if remainder > 0:
                    ranked = sorted(
                        unfrozen,
                        key=lambda p_idx: (-len(phase_reps[p_idx]), p_idx),
                    )
                    for p_idx in ranked[:remainder]:
                        quotas[p_idx] += 1
                break

    for phase in phases:
        p_idx = int(phase["phase_index"])
        reps_in_phase = phase_reps.get(p_idx, [])
        count = len(reps_in_phase)
        quota = int(quotas.get(p_idx, 0))
        chosen_local = set(_select_evenly_spaced_indices(count, quota))
        selected_labels = []
        omitted_labels = []
        for local_idx, rep in enumerate(reps_in_phase):
            label = "{}:{}".format(
                "e" if rep["operation"] == "erase" else "w",
                int(rep["operation_index"]),
            )
            if local_idx in chosen_local:
                rep["selected"] = True
                selected_labels.append(label)
            else:
                rep["selected"] = False
                omitted_labels.append(label)
        phase["selected_states"] = len(selected_labels)
        phase["capped_states"] = count - len(selected_labels)
        phase["tested_in_full"] = bool(count > 0 and len(selected_labels) == count)
        phase["selected_representatives"] = selected_labels
        phase["omitted_representatives"] = omitted_labels

    return [rep for rep in representatives if rep.get("selected")]


def compute_first_cut_states(
    initial_state,
    operations,
    include_writes=True,
    include_erases=False,
    write_fault_type="w",
    erase_fault_type="e",
    backend_kind="fast",
    torn_word_mode="fixed",
    torn_word_choices=(),
    torn_word_seed=0,
    erase_fill=0xFF,
    corruption_seed=0,
    page_size=4096,
    program_unit=4,
    flash_base=0,
    cap=None,
    slots=None,
    partitions=None,
    metadata_regions=None,
    bootloader_region=None,
    nvs_region=None,
    allowed_write_indices=None,
    allowed_erase_indices=None,
):
    """Compute the persistent state left by each candidate first cut in trace order.

    Every operation in ``operations`` updates the completed prefix via
    ``apply_completed_operation`` so that erased sectors and earlier writes are
    reflected in later candidate cut states even when only a subset of
    operations are candidate first cuts.
    """
    if not isinstance(initial_state, PersistentState):
        raise TypeError("initial_state must be a PersistentState")

    ops = list(operations)
    phases, operation_phase_map = segment_trace_phases(
        ops,
        flash_base=flash_base,
        slots=slots,
        page_size=page_size,
        partitions=partitions,
        metadata_regions=metadata_regions,
        bootloader_region=bootloader_region,
        nvs_region=nvs_region,
    )

    completed_erases = 0
    prefix = initial_state
    seen_by_identity = {}
    representatives = []
    cut_to_state = {}
    cut_to_representative = {}
    candidate_counts = {"write": 0, "erase": 0}
    duplicate_counts = {"write": 0, "erase": 0}

    allowed_writes = (
        None if allowed_write_indices is None else set(int(i) for i in allowed_write_indices)
    )
    allowed_erases = (
        None if allowed_erase_indices is None else set(int(i) for i in allowed_erase_indices)
    )
    base_addr = int(flash_base or 0)

    for position, operation in enumerate(ops):
        kind = str(operation.get("kind") or "")
        if kind not in ("write", "erase"):
            raise ValueError("unsupported operation kind {!r}".format(kind))
        op_index = int(operation["operation_index"])
        seq = int(operation.get("sequence", position))
        offset = int(operation["offset"])
        address = base_addr + offset
        phase_idx = int(operation_phase_map.get(seq, 0))
        phase_region = phases[phase_idx]["region"] if phases else "outside"

        if kind == "write":
            is_candidate = bool(include_writes) and (
                allowed_writes is None or op_index in allowed_writes
            )
            fault_code = write_fault_type
        else:
            is_candidate = bool(include_erases) and (
                allowed_erases is None or op_index in allowed_erases
            )
            fault_code = erase_fault_type

        if is_candidate:
            candidate_counts[kind] += 1
            if phases:
                phases[phase_idx]["candidate_cuts"] += 1
            mode = resolve_operation_torn_word(
                op_index,
                torn_word_mode,
                choices=torn_word_choices,
                seed=torn_word_seed,
            )
            candidate_state = apply_interrupted_operation(
                prefix,
                operation,
                fault_type=fault_code,
                backend_kind=backend_kind,
                torn_word_mode=mode,
                erase_fill=erase_fill,
                corruption_seed=corruption_seed,
                total_erases=completed_erases,
                page_size=page_size,
                program_unit=program_unit,
            )
            state_id = candidate_state.identity_hex()
            cut_key = (kind, op_index)
            cut_to_state[cut_key] = state_id
            cut_record = {
                "operation": kind,
                "operation_index": op_index,
                "fault_type": "e" if kind == "erase" else "w",
                "sequence": seq,
                "offset": offset,
                "address": "0x{:08X}".format(address),
                "torn_word": mode,
                "phase_index": phase_idx,
                "region": phase_region,
            }
            if state_id not in seen_by_identity:
                rep_record = {
                    "state_identity": state_id,
                    "operation": kind,
                    "operation_index": op_index,
                    "fault_type": "e" if kind == "erase" else "w",
                    "sequence": seq,
                    "offset": offset,
                    "address": "0x{:08X}".format(address),
                    "torn_word": mode,
                    "phase_index": phase_idx,
                    "region": phase_region,
                    "uncorrectable_words": len(candidate_state.uncorrectable_words),
                    "duplicate_cuts": [],
                    "duplicate_count": 0,
                    "represented_cuts": [cut_record],
                    "selected": True,
                }
                seen_by_identity[state_id] = rep_record
                representatives.append(rep_record)
                cut_to_representative[cut_key] = (kind, op_index)
            else:
                rep_record = seen_by_identity[state_id]
                rep_record["duplicate_cuts"].append(cut_record)
                rep_record["duplicate_count"] += 1
                rep_record["represented_cuts"].append(cut_record)
                duplicate_counts[kind] += 1
                cut_to_representative[cut_key] = (
                    rep_record["operation"],
                    int(rep_record["operation_index"]),
                )

        prefix = apply_completed_operation(
            prefix, operation, erase_fill=erase_fill
        )
        if kind == "erase":
            completed_erases += 1

    selected_reps = select_capped_states_across_phases(
        representatives, phases, cap=cap
    )

    program_reps = [r for r in representatives if r["operation"] == "write"]
    erase_reps = [r for r in representatives if r["operation"] == "erase"]
    selected_program_reps = [r for r in selected_reps if r["operation"] == "write"]
    selected_erase_reps = [r for r in selected_reps if r["operation"] == "erase"]

    # Representative group sizes per domain (for calibration operation coverage).
    program_rep_groups = {}
    erase_rep_groups = {}
    for rep in selected_reps:
        same_domain_count = sum(
            1
            for cut in rep["represented_cuts"]
            if cut["operation"] == rep["operation"]
        )
        key = str(int(rep["operation_index"]))
        if rep["operation"] == "write":
            program_rep_groups[key] = same_domain_count
        else:
            erase_rep_groups[key] = same_domain_count

    total_candidates = candidate_counts["write"] + candidate_counts["erase"]
    total_distinct = len(representatives)
    total_selected = len(selected_reps)
    total_duplicates = duplicate_counts["write"] + duplicate_counts["erase"]
    total_capped = total_distinct - total_selected

    return {
        "initial_state_identity": initial_state.identity_hex(),
        "final_state_identity": prefix.identity_hex(),
        "backend_kind": backend_kind,
        "torn_word_mode": torn_word_mode,
        "torn_word_choices": [
            {"mode": str(m), "weight": int(w)} for m, w in (torn_word_choices or ())
        ],
        "torn_word_seed": int(torn_word_seed),
        "cap": None if cap is None else int(cap),
        "candidate_cuts": total_candidates,
        "distinct_states": total_distinct,
        "selected_states": total_selected,
        "planned_states": total_selected,
        "duplicate_cuts": total_duplicates,
        "capped_states": total_capped,
        "program": {
            "candidate_cuts": candidate_counts["write"],
            "distinct_states": len(program_reps),
            "selected_states": len(selected_program_reps),
            "planned_states": len(selected_program_reps),
            "duplicate_cuts": duplicate_counts["write"],
            "capped_states": len(program_reps) - len(selected_program_reps),
            "representative_groups": program_rep_groups,
        },
        "erase": {
            "candidate_cuts": candidate_counts["erase"],
            "distinct_states": len(erase_reps),
            "selected_states": len(selected_erase_reps),
            "planned_states": len(selected_erase_reps),
            "duplicate_cuts": duplicate_counts["erase"],
            "capped_states": len(erase_reps) - len(selected_erase_reps),
            "representative_groups": erase_rep_groups,
        },
        "phases": phases,
        "representatives": representatives,
        "selected_representatives": selected_reps,
        "cut_to_state": {
            "{}:{}".format("e" if k[0] == "erase" else "w", k[1]): v
            for k, v in sorted(cut_to_state.items())
        },
        "cut_to_representative": {
            "{}:{}".format("e" if k[0] == "erase" else "w", k[1]): "{}:{}".format(
                "e" if v[0] == "erase" else "w", v[1]
            )
            for k, v in sorted(cut_to_representative.items())
        },
    }


def _resolve_platform_repl_text(profile, repo_root=None):
    platform = getattr(profile, "platform", None)
    if not platform:
        return ""
    default_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = []
    profile_path = getattr(profile, "profile_path", None)
    if profile_path is not None:
        candidates.append(
            os.path.join(
                os.path.dirname(os.path.abspath(str(profile_path))),
                str(platform),
            )
        )
    if repo_root is not None:
        candidates.append(os.path.join(str(repo_root), str(platform)))
    candidates.append(os.path.join(default_root, str(platform)))
    candidates.append(str(platform))
    for candidate in candidates:
        try:
            if os.path.isfile(candidate):
                with open(candidate, "r") as handle:
                    return handle.read()
        except OSError:
            continue
    return ""


def infer_backend_kind_for_profile(profile, backend_name=None, repo_root=None):
    """Determine the recovery-state backend kind ('fast', 'cfi', or 'mram')."""
    from profile_loader import _is_mram_backend

    repl_text = _resolve_platform_repl_text(profile, repo_root=repo_root)
    raw_backend = str(
        backend_name
        if backend_name is not None
        else (getattr(profile, "flash_backend", None) or "")
    ).strip().lower()
    if raw_backend.startswith("sysbus."):
        raw_backend = raw_backend[len("sysbus."):]

    if "cfiflash" in repl_text.lower() or "cfi" in raw_backend:
        return "cfi"
    if _is_mram_backend(
        getattr(profile, "platform", None),
        raw_backend or getattr(profile, "flash_backend", None),
        getattr(profile, "extra_peripherals", None),
        profile_path=getattr(profile, "profile_path", None),
        repo_root=repo_root,
    ):
        return "mram"
    if "nvm_ctrl" in raw_backend or raw_backend == "nvm":
        return "mram"
    return "fast"


def infer_program_unit_for_profile(profile, operations=None, repo_root=None):
    """Determine the program-unit byte width for persistent-state modeling."""
    repl_text = _resolve_platform_repl_text(profile, repo_root=repo_root)
    match = re.search(r"ProgramUnitSize:\s*(0x[0-9a-fA-F]+|\d+)", repl_text)
    if match:
        unit = int(match.group(1), 0)
        if unit > 0:
            return unit
    match = re.search(r"WordSize:\s*(0x[0-9a-fA-F]+|\d+)", repl_text)
    if match:
        unit = int(match.group(1), 0)
        if unit > 0:
            return unit
    granularity = int(getattr(getattr(profile, "memory", None), "write_granularity", 0) or 0)
    if granularity > 0:
        return granularity
    for op in operations or ():
        if op.get("kind") == "write" and int(op.get("width", 0) or 0) > 0:
            return int(op["width"])
    return 4


def infer_flash_geometry_for_profile(profile, operations=(), repo_root=None):
    """Return ``(flash_base, flash_size, page_size, erase_fill)`` for ``profile``."""
    from trace_utils import flash_base_for_profile

    memory = getattr(profile, "memory", None)
    page_size = max(1, int(getattr(memory, "page_size", 4096) or 4096))
    erase_fill = int(profile.image_pad_byte(repo_root)) & 0xFF
    flash_base = int(flash_base_for_profile(profile))

    repl_text = _resolve_platform_repl_text(profile, repo_root=repo_root)
    repl_base = None
    repl_size = None
    base_match = re.search(r"FlashBaseAddress:\s*(0x[0-9a-fA-F]+|\d+)", repl_text)
    if base_match:
        repl_base = int(base_match.group(1), 0)
    size_match = re.search(r"FlashSize:\s*(0x[0-9a-fA-F]+|\d+)", repl_text)
    if size_match:
        repl_size = int(size_match.group(1), 0)
    if repl_base is None:
        mram_match = re.search(
            r"(?:mram|nvm|flash)\s*:\s*Memory\.(?:NVMemory|MappedMemory)\s*@\s*sysbus\s+(0x[0-9a-fA-F]+|\d+)",
            repl_text,
        )
        if mram_match:
            repl_base = int(mram_match.group(1), 0)

    slots = getattr(memory, "slots", None) or {}
    slot_bases = [int(s.base) for s in slots.values()]
    slot_ends = [int(s.base) + int(s.size) for s in slots.values()]
    min_slot_base = min(slot_bases) if slot_bases else None
    max_slot_end = max(slot_ends) if slot_ends else 0

    if flash_base == 0:
        if repl_base is not None and repl_base > 0:
            if min_slot_base is None or min_slot_base >= repl_base:
                flash_base = repl_base
        elif min_slot_base is not None and min_slot_base >= 0x04000000:
            op_offsets = [int(op.get("offset", 0)) for op in (operations or ())]
            max_op_offset = max(op_offsets) if op_offsets else 0
            if max_op_offset < min_slot_base:
                flash_base = min_slot_base

    max_offset = 0
    if repl_size is not None and repl_size > 0:
        max_offset = max(max_offset, int(repl_size))
    if max_slot_end > flash_base:
        max_offset = max(max_offset, max_slot_end - flash_base)

    for region in getattr(memory, "erase_regions", None) or ():
        end = int(region.base) + int(region.size)
        if end > flash_base:
            max_offset = max(max_offset, end - flash_base)
    for region in getattr(memory, "postmortem_partitions", None) or ():
        end = int(region.base) + int(region.size)
        if end > flash_base:
            max_offset = max(max_offset, end - flash_base)
    for region in getattr(profile, "metadata_fault_regions", None) or ():
        end = int(region.end)
        if end > flash_base:
            max_offset = max(max_offset, end - flash_base)
    boot_reg = getattr(profile, "bootloader_region", None)
    if boot_reg is not None:
        end = int(boot_reg.base) + int(boot_reg.size)
        if end > flash_base:
            max_offset = max(max_offset, end - flash_base)
    nvs_reg = getattr(profile, "nvs_region", None)
    if nvs_reg is not None:
        end = int(nvs_reg.address) + int(nvs_reg.size)
        if end > flash_base:
            max_offset = max(max_offset, end - flash_base)
    for entry in getattr(profile, "pre_boot_state", None) or ():
        addr = int(entry.address)
        if addr >= flash_base and (addr - flash_base + 4) <= 0x04000000:
            max_offset = max(max_offset, addr - flash_base + 4)
    for op in operations or ():
        offset = int(op.get("offset", 0))
        span = int(
            op.get("erase_size", 0)
            if op.get("kind") == "erase"
            else op.get("width", 4)
        )
        max_offset = max(max_offset, offset + max(1, span))

    align = max(4096, page_size)
    flash_size = max(align, ((max_offset + align - 1) // align) * align)
    return flash_base, flash_size, page_size, erase_fill


def load_calibration_operations_for_profile(
    profile,
    trace_file=None,
    erase_trace_file=None,
    program_trace_file=None,
    total_writes=0,
    total_erases=0,
    include_erases=False,
    backend_name=None,
    repo_root=None,
):
    """Load and validate width-explicit write/program and erase calibration traces."""
    from profile_loader import ProfileError
    from trace_utils import load_exact_program_trace

    backend_kind = infer_backend_kind_for_profile(
        profile, backend_name=backend_name, repo_root=repo_root
    )
    if program_trace_file is None and trace_file and str(trace_file).endswith("_trace.csv"):
        candidate_prog = str(trace_file)[:-len("_trace.csv")] + "_program_trace.csv"
        if os.path.isfile(candidate_prog):
            program_trace_file = candidate_prog
    if erase_trace_file is None and trace_file and str(trace_file).endswith("_trace.csv"):
        candidate_erase = str(trace_file)[:-len("_trace.csv")] + "_erase_trace.csv"
        if os.path.isfile(candidate_erase):
            erase_trace_file = candidate_erase
    if erase_trace_file is None and program_trace_file and str(program_trace_file).endswith("_program_trace.csv"):
        candidate_erase = str(program_trace_file)[:-len("_program_trace.csv")] + "_erase_trace.csv"
        if os.path.isfile(candidate_erase):
            erase_trace_file = candidate_erase

    writes = []
    if backend_kind == "mram" and program_trace_file and os.path.isfile(str(program_trace_file)):
        try:
            raw_events = load_exact_program_trace(str(program_trace_file))
        except ValueError as exc:
            raise ProfileError(
                "sweep_strategy 'distinct_states' requires a valid MRAM program trace: {}".format(
                    exc
                )
            )
        if not raw_events and int(total_writes or 0) > 0:
            raise ProfileError(
                "sweep_strategy 'distinct_states' requires a non-empty calibration MRAM program trace"
            )
        expected_unit = infer_program_unit_for_profile(profile, repo_root=repo_root)
        for expected_idx, event in enumerate(raw_events, start=1):
            width = int(event.get("program_width", event.get("width", 0)))
            if int(event["write_index"]) != expected_idx:
                raise ProfileError(
                    "sweep_strategy 'distinct_states' requires contiguous MRAM program trace indices (expected {}, got {})".format(
                        expected_idx, event["write_index"]
                    )
                )
            if event.get("faulted"):
                raise ProfileError(
                    "sweep_strategy 'distinct_states' requires clean calibration MRAM program records, but write {} is marked faulted".format(
                        expected_idx
                    )
                )
            if expected_unit > 0 and width != expected_unit:
                raise ProfileError(
                    "sweep_strategy 'distinct_states' requires whole-unit MRAM program records of {} bytes (got {} at write {})".format(
                        expected_unit, width, expected_idx
                    )
                )
            writes.append(
                {
                    "write_index": expected_idx,
                    "offset": int(event["offset"]),
                    "width": width,
                    "value": _little_endian_int(event["intended_bytes"]),
                    "pre_program_value": _little_endian_int(event["pre_program_bytes"]),
                    "completed_value": _little_endian_int(event["post_program_bytes"]),
                }
            )
    elif int(total_writes or 0) > 0 or (trace_file and os.path.isfile(str(trace_file))):
        if not trace_file or not os.path.isfile(str(trace_file)):
            backend_label = (
                backend_name
                or getattr(profile, "flash_backend", None)
                or getattr(profile, "platform", None)
                or "configured backend"
            )
            raise ProfileError(
                "fault_sweep.sweep_strategy: distinct_states requires a width-explicit "
                "calibration write trace, but '{}' produced no trace file".format(
                    backend_label
                )
            )
        with open(str(trace_file), "r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or ())
            if "width" not in fieldnames:
                raise ProfileError(
                    "fault_sweep.sweep_strategy: distinct_states requires an explicit "
                    "'width' column in calibration write trace '{}'".format(trace_file)
                )
            for expected_idx, row in enumerate(reader, start=1):
                try:
                    write_idx = int(str(row.get("write_index", "")).strip(), 0)
                    offset = int(str(row.get("flash_offset", "")).strip(), 0)
                    value = int(str(row.get("value", "")).strip(), 0)
                    width_text = str(row.get("width", "")).strip()
                    if not width_text:
                        raise ValueError("missing width")
                    width = int(width_text, 0)
                except (TypeError, ValueError) as exc:
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires valid "
                        "width-explicit write trace rows in '{}': {}".format(
                            trace_file, exc
                        )
                    )
                if write_idx != expected_idx:
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires contiguous "
                        "1-based write_index values in '{}' (expected {}, got {})".format(
                            trace_file, expected_idx, write_idx
                        )
                    )
                if width <= 0:
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires positive "
                        "write widths in '{}' (got {} at write {})".format(
                            trace_file, width, write_idx
                        )
                    )
                writes.append(
                    {
                        "write_index": write_idx,
                        "offset": offset,
                        "value": value,
                        "width": width,
                    }
                )
        if not writes and int(total_writes or 0) > 0:
            raise ProfileError(
                "fault_sweep.sweep_strategy: distinct_states requires non-empty "
                "calibration write trace records when max_writes={}".format(total_writes)
            )

    erases = []
    if erase_trace_file and os.path.isfile(str(erase_trace_file)):
        with open(str(erase_trace_file), "r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or ())
            if "erase_size" not in fieldnames:
                raise ProfileError(
                    "fault_sweep.sweep_strategy: distinct_states requires an explicit "
                    "'erase_size' column in calibration erase trace '{}'".format(
                        erase_trace_file
                    )
                )
            for expected_idx, row in enumerate(reader, start=1):
                try:
                    erase_idx = int(str(row.get("erase_index", "")).strip(), 0)
                    offset = int(str(row.get("flash_offset", "")).strip(), 0)
                    writes_at = int(str(row.get("writes_at_this_point", "0")).strip(), 0)
                    erase_size = int(str(row.get("erase_size", "")).strip(), 0)
                except (TypeError, ValueError) as exc:
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires valid "
                        "erase trace rows in '{}': {}".format(erase_trace_file, exc)
                    )
                if erase_idx != expected_idx or erase_size <= 0:
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires contiguous "
                        "erase_index values and positive erase_size in '{}'".format(
                            erase_trace_file
                        )
                    )
                erases.append(
                    {
                        "erase_index": erase_idx,
                        "offset": offset,
                        "writes_at_this_point": writes_at,
                        "erase_size": erase_size,
                    }
                )
    elif include_erases and int(total_erases or 0) > 0:
        raise ProfileError(
            "fault_sweep.sweep_strategy: distinct_states with erase fault points "
            "requires a calibration erase trace CSV (total_erases={})".format(
                total_erases
            )
        )

    return merge_operation_traces(writes, erases)


def _load_tracking_base_snapshot_file(
    snapshot_path,
    flash_base,
    program_unit,
    program_trace_file=None,
):
    """Load and authenticate a ``.tracking_base.bin`` boundary snapshot."""
    from profile_loader import ProfileError

    path_str = str(snapshot_path)
    try:
        with open(path_str, "rb") as stream:
            magic = stream.readline()
            if magic != _BOUNDARY_SNAPSHOT_MAGIC:
                raise ValueError("snapshot has invalid magic")
            header = json.loads(stream.readline(1 << 16).decode("utf-8"))
    except Exception as exc:
        raise ProfileError(
            "deferred tracking base snapshot '{}' is malformed: {}".format(
                path_str, exc
            )
        )

    if not isinstance(header, dict) or not isinstance(header.get("components"), list):
        raise ProfileError(
            "deferred tracking base snapshot '{}' has invalid header".format(path_str)
        )
    identity = str(header.get("identity") or "")
    if (
        identity.startswith("tracking-base-v1|")
        and program_trace_file
        and os.path.isfile(str(program_trace_file))
    ):
        parts = identity.split("|")
        expected_trace_sha = parts[-1] if len(parts) >= 8 else ""
        if expected_trace_sha:
            with open(str(program_trace_file), "rb") as tf:
                actual_sha = hashlib.sha256(tf.read()).hexdigest()
            if actual_sha != expected_trace_sha:
                raise ProfileError(
                    "deferred tracking base snapshot '{}' does not match program trace '{}'".format(
                        path_str, program_trace_file
                    )
                )

    expected_lengths = {}
    for comp in header["components"]:
        if isinstance(comp, dict) and isinstance(comp.get("name"), str):
            expected_lengths[comp["name"]] = int(comp.get("length", -1))
    if "nvm" not in expected_lengths:
        raise ProfileError(
            "deferred tracking base snapshot '{}' is missing the 'nvm' component".format(
                path_str
            )
        )
    try:
        components, _hdr = _read_boundary_snapshot(
            path_str, identity, expected_lengths
        )
    except Exception as exc:
        raise ProfileError(
            "deferred tracking base snapshot '{}' failed integrity check: {}".format(
                path_str, exc
            )
        )

    nvm_bytes = bytearray(components["nvm"])
    unit = max(1, int(program_unit or 4))
    uncorrectable = []
    if "uncorrectable_words" in components:
        mark_bytes = bytearray(components["uncorrectable_words"])
        if len(mark_bytes) * unit != len(nvm_bytes) or any(
            b not in (0, 1) for b in mark_bytes
        ):
            raise ProfileError(
                "deferred tracking base snapshot '{}' has invalid uncorrectable_words table".format(
                    path_str
                )
            )
        for idx, flag in enumerate(mark_bytes):
            if flag:
                uncorrectable.append(("nvm", idx * unit))

    return PersistentState.from_bytes(
        nvm_bytes,
        name="nvm",
        base_address=int(flash_base),
        uncorrectable_words=uncorrectable,
    )


def build_initial_state_for_profile(
    profile,
    operations=(),
    repo_root=None,
    tracking_base_file=None,
    program_trace_file=None,
):
    """Construct the initial ``PersistentState`` before Phase-1 calibration operations."""
    from profile_loader import ProfileError

    root = (
        str(repo_root)
        if repo_root is not None
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    flash_base, flash_size, _page_size, erase_fill = infer_flash_geometry_for_profile(
        profile, operations=operations, repo_root=root
    )
    program_unit = infer_program_unit_for_profile(
        profile, operations=operations, repo_root=root
    )

    candidate_tracking_base = tracking_base_file
    if candidate_tracking_base is None and program_trace_file:
        default_tb = str(program_trace_file) + ".tracking_base.bin"
        if os.path.isfile(default_tb):
            candidate_tracking_base = default_tb

    tracking_start = int(
        getattr(getattr(profile, "fault_sweep", None), "tracking_start_address", 0) or 0
    )
    if candidate_tracking_base and os.path.isfile(str(candidate_tracking_base)):
        state = _load_tracking_base_snapshot_file(
            candidate_tracking_base,
            flash_base=flash_base,
            program_unit=program_unit,
            program_trace_file=program_trace_file,
        )
        _validate_mram_program_prefix(state, operations, erase_fill)
        return state

    if tracking_start != 0:
        has_exact_pre_program = bool(operations) and all(
            "pre_program_value" in op
            for op in operations
            if op.get("kind") == "write"
        )
        if not has_exact_pre_program:
            raise ProfileError(
                "fault_sweep.sweep_strategy: distinct_states with deferred "
                "tracking_start_address=0x{:X} requires a tracking_base snapshot "
                "or exact MRAM pre-program trace".format(tracking_start)
            )

    buf = bytearray([erase_fill & 0xFF]) * flash_size

    boot_elf_rel = getattr(profile, "bootloader_elf", None)
    if boot_elf_rel:
        boot_elf_path = str(profile.resolve_path(root, boot_elf_rel))
        if os.path.isfile(boot_elf_path):
            _seed_elf_load_segments(buf, flash_base, boot_elf_path)
        else:
            entry = int(getattr(profile, "bootloader_entry", 0) or 0)
            boot_reg = getattr(profile, "bootloader_region", None)
            region_overlaps = bool(
                boot_reg is not None
                and int(boot_reg.base) < flash_base + len(buf)
                and int(boot_reg.base) + int(boot_reg.size) > flash_base
            )
            if flash_base <= entry < flash_base + len(buf) or region_overlaps:
                raise ProfileError(
                    "fault_sweep.sweep_strategy: distinct_states requires "
                    "bootloader PT_LOAD bytes for the persistent NVM baseline, "
                    "but '{}' does not exist".format(boot_elf_path)
                )

    residual = getattr(profile, "residual_image", None)
    slots = getattr(getattr(profile, "memory", None), "slots", None) or {}
    if residual is not None and residual.slot in slots:
        slot_cfg = slots[residual.slot]
        s_off = int(slot_cfg.base) - flash_base
        s_size = int(slot_cfg.size)
        if 0 <= s_off and s_off + s_size <= len(buf):
            if residual.fill_pattern is not None and not residual.prior_image:
                fill_b = int(residual.fill_pattern) & 0xFF
                buf[s_off : s_off + s_size] = bytearray([fill_b]) * s_size
            if residual.prior_image:
                prior_path = str(profile.resolve_path(root, residual.prior_image))
                if not os.path.isfile(prior_path):
                    raise ProfileError(
                        "fault_sweep.sweep_strategy: distinct_states requires "
                        "residual_image.prior_image baseline bytes, but '{}' does "
                        "not exist".format(prior_path)
                    )
                with open(prior_path, "rb") as handle:
                    prior_bytes = bytearray(handle.read()[:s_size])
                buf[s_off : s_off + len(prior_bytes)] = prior_bytes
                if residual.fill_pattern is not None:
                    actual_rel = (getattr(profile, "images", None) or {}).get(
                        residual.slot
                    )
                    actual_size = 0
                    if actual_rel:
                        actual_path = str(profile.resolve_path(root, actual_rel))
                        if os.path.isfile(actual_path):
                            actual_size = min(s_size, os.path.getsize(actual_path))
                    tail_end = min(s_size, len(prior_bytes))
                    if tail_end > actual_size:
                        fill_b = int(residual.fill_pattern) & 0xFF
                        buf[
                            s_off + actual_size : s_off + tail_end
                        ] = bytearray([fill_b]) * (tail_end - actual_size)

    try:
        load_addrs = profile.effective_image_load_addresses()
    except Exception:
        load_addrs = {name: int(slot.base) for name, slot in slots.items()}

    for slot_name, rel_path in (getattr(profile, "images", None) or {}).items():
        if not rel_path or slot_name not in load_addrs:
            continue
        img_path = str(profile.resolve_path(root, rel_path))
        load_addr = int(load_addrs[slot_name])
        off = load_addr - flash_base
        if off >= len(buf):
            continue
        if not os.path.isfile(img_path):
            raise ProfileError(
                "fault_sweep.sweep_strategy: distinct_states requires initial "
                "image bytes for slot '{}', but '{}' does not exist".format(
                    slot_name, img_path
                )
            )
        with open(img_path, "rb") as handle:
            img_bytes = bytearray(handle.read())
        source_start = max(0, -off)
        dest_start = max(0, off)
        if source_start < len(img_bytes) and dest_start < len(buf):
            length = min(
                len(img_bytes) - source_start,
                len(buf) - dest_start,
            )
            buf[dest_start : dest_start + length] = img_bytes[
                source_start : source_start + length
            ]

    for entry in getattr(profile, "pre_boot_state", None) or ():
        off = int(entry.address) - flash_base
        if 0 <= off and off + 4 <= len(buf):
            buf[off : off + 4] = struct.pack("<I", int(entry.u32) & 0xFFFFFFFF)

    # For exact MRAM program traces without a separate tracking_base snapshot,
    # seed each unit's initial bytes from its first observed pre_program_value.
    touched_ranges = []

    def _range_touched(start, end):
        for t_start, t_end in touched_ranges:
            if start < t_end and end > t_start:
                return True
        return False

    for op in operations or ():
        kind = op.get("kind")
        off = int(op.get("offset", 0))
        if kind == "erase":
            span = int(op.get("erase_size", 0))
            touched_ranges.append((off, off + span))
        elif kind == "write":
            width = int(op.get("width", 4))
            if "pre_program_value" in op and not _range_touched(off, off + width):
                if 0 <= off and off + width <= len(buf):
                    buf[off : off + width] = _little_endian_bytes(
                        op["pre_program_value"], width
                    )
            touched_ranges.append((off, off + width))

    state = PersistentState.from_bytes(
        buf,
        name="nvm",
        base_address=flash_base,
    )
    _validate_mram_program_prefix(state, operations, erase_fill)
    return state


def _validate_mram_program_prefix(initial_state, operations, erase_fill):
    """Verify that exact MRAM pre_program_value entries agree with the completed stream."""
    from profile_loader import ProfileError

    prefix = initial_state
    for op in operations or ():
        if op.get("kind") == "write" and "pre_program_value" in op:
            width = int(op["width"])
            observed = _little_endian_int(
                prefix.read("nvm", int(op["offset"]), width)
            )
            if observed != int(op["pre_program_value"]):
                raise ProfileError(
                    "MRAM program trace pre-program bytes disagree with "
                    "persistent prefix at write {}".format(op.get("write_index"))
                )
        prefix = apply_completed_operation(
            prefix, op, erase_fill=erase_fill
        )


def extract_profile_region_descriptors(profile):
    """Extract region bounds from ``profile`` for phase segmentation."""
    memory = getattr(profile, "memory", None)
    slots = {
        name: (int(slot.base), int(slot.base) + int(slot.size))
        for name, slot in ((getattr(memory, "slots", None) or {}).items())
    }
    partitions = [
        (str(part.name or "partition"), int(part.base), int(part.base) + int(part.size))
        for part in (getattr(memory, "postmortem_partitions", None) or ())
    ]
    metadata_regions = [
        (str(reg.name), int(reg.start), int(reg.end))
        for reg in (getattr(profile, "metadata_fault_regions", None) or ())
    ]
    boot_reg = getattr(profile, "bootloader_region", None)
    bootloader_region = (
        (int(boot_reg.base), int(boot_reg.base) + int(boot_reg.size))
        if boot_reg is not None
        else None
    )
    nvs_reg = getattr(profile, "nvs_region", None)
    nvs_region = (
        (int(nvs_reg.address), int(nvs_reg.address) + int(nvs_reg.size))
        if nvs_reg is not None
        else None
    )
    return {
        "slots": slots,
        "partitions": partitions,
        "metadata_regions": metadata_regions,
        "bootloader_region": bootloader_region,
        "nvs_region": nvs_region,
    }


def analyze_profile_first_cut_states(
    profile,
    trace_file=None,
    erase_trace_file=None,
    program_trace_file=None,
    tracking_base_file=None,
    total_writes=0,
    total_erases=0,
    include_writes=True,
    include_erases=False,
    backend_name=None,
    cap=None,
    allowed_write_indices=None,
    allowed_erase_indices=None,
    repo_root=None,
):
    """Run first-cut state computation and optional phase-spread capping for a profile."""
    operations = load_calibration_operations_for_profile(
        profile,
        trace_file=trace_file,
        erase_trace_file=erase_trace_file,
        program_trace_file=program_trace_file,
        total_writes=total_writes,
        total_erases=total_erases,
        include_erases=include_erases,
        backend_name=backend_name,
        repo_root=repo_root,
    )
    backend_kind = infer_backend_kind_for_profile(
        profile, backend_name=backend_name, repo_root=repo_root
    )
    program_unit = infer_program_unit_for_profile(
        profile, operations=operations, repo_root=repo_root
    )
    flash_base, _flash_size, page_size, erase_fill = infer_flash_geometry_for_profile(
        profile, operations=operations, repo_root=repo_root
    )
    initial_state = build_initial_state_for_profile(
        profile,
        operations=operations,
        repo_root=repo_root,
        tracking_base_file=tracking_base_file,
        program_trace_file=program_trace_file,
    )

    fs = getattr(profile, "fault_sweep", None)
    torn_explicit = bool(getattr(fs, "torn_word_explicit", False))
    if torn_explicit:
        torn_mode = str(getattr(fs, "torn_word", "fixed"))
        torn_choices = tuple(getattr(fs, "torn_word_choices", ()) or ())
        torn_seed = int(getattr(fs, "torn_word_seed", 0) or 0)
    elif backend_kind == "mram" or bool(getattr(fs, "mram_torn_word_explicit", False)):
        torn_mode = str(getattr(fs, "mram_torn_word", "half"))
        torn_choices = tuple(getattr(fs, "mram_torn_word_choices", ()) or ())
        torn_seed = int(getattr(fs, "mram_torn_word_seed", 0) or 0)
    else:
        torn_mode = str(getattr(fs, "torn_word", "fixed"))
        torn_choices = tuple(getattr(fs, "torn_word_choices", ()) or ())
        torn_seed = int(getattr(fs, "torn_word_seed", 0) or 0)

    effective_cap = (
        cap
        if cap is not None
        else getattr(fs, "max_distinct_states", None)
    )
    if allowed_write_indices is None and int(total_writes or 0) > 0:
        allowed_write_indices = set(range(int(total_writes)))
    if allowed_erase_indices is None and int(total_erases or 0) > 0:
        allowed_erase_indices = set(range(int(total_erases)))
    regions = extract_profile_region_descriptors(profile)

    return compute_first_cut_states(
        initial_state,
        operations,
        include_writes=include_writes,
        include_erases=include_erases,
        write_fault_type="w",
        erase_fault_type="e",
        backend_kind=backend_kind,
        torn_word_mode=torn_mode,
        torn_word_choices=torn_choices,
        torn_word_seed=torn_seed,
        erase_fill=erase_fill,
        corruption_seed=torn_seed,
        page_size=page_size,
        program_unit=program_unit,
        flash_base=flash_base,
        cap=effective_cap,
        slots=regions["slots"],
        partitions=regions["partitions"],
        metadata_regions=regions["metadata_regions"],
        bootloader_region=regions["bootloader_region"],
        nvs_region=regions["nvs_region"],
        allowed_write_indices=allowed_write_indices,
        allowed_erase_indices=allowed_erase_indices,
    )
