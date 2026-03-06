#!/usr/bin/env python3
"""YAML profile loader for OTA bootloader fault-injection testing.

Parses declarative bootloader profiles, validates against schema_version 1,
and emits robot variables / temp files for the fault-injection harness.

Usage as library::

    from profile_loader import load_profile, ProfileConfig

    profile = load_profile("profiles/naive_bare_copy.yaml")
    robot_vars = profile.robot_vars(repo_root)

Usage as CLI (for debugging)::

    python3 scripts/profile_loader.py profiles/naive_bare_copy.yaml
"""

from __future__ import annotations

import json
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


SUPPORTED_SCHEMA_VERSIONS = {1}

KNOWN_FAULT_TYPES = {
    "power_loss",
    "interrupted_erase",
    "bit_corruption",
    "silent_write_failure",
    "write_disturb",
    "multi_sector_atomicity",
    "wear_leveling_corruption",
    "write_rejection",
    "reset_at_time",
}
IMPLEMENTED_FAULT_TYPES = {
    "power_loss",
    "interrupted_erase",
    "bit_corruption",
    "silent_write_failure",
    "write_disturb",
    "multi_sector_atomicity",
    "wear_leveling_corruption",
    "write_rejection",
    "reset_at_time",
}


class ProfileError(Exception):
    """Raised when a profile is invalid or unsupported."""


# ---------------------------------------------------------------------------
# Profile data model
# ---------------------------------------------------------------------------

class SlotConfig:
    __slots__ = ("base", "size")

    def __init__(self, base: int, size: int) -> None:
        self.base = base
        self.size = size


class MemoryConfig:
    __slots__ = ("sram_start", "sram_end", "write_granularity", "slots")

    def __init__(
        self,
        sram_start: int,
        sram_end: int,
        write_granularity: int,
        slots: Dict[str, SlotConfig],
    ) -> None:
        self.sram_start = sram_start
        self.sram_end = sram_end
        self.write_granularity = write_granularity
        self.slots = slots


class SuccessCriteria:
    __slots__ = (
        "vtor_in_slot",
        "pc_in_slot",
        "marker_address",
        "marker_value",
        "image_hash",
        "expected_image",
        "image_hash_slot",
        "otadata_expect",
        "otadata_expect_scope",
    )

    def __init__(
        self,
        vtor_in_slot: Optional[str] = None,
        pc_in_slot: Optional[str] = None,
        marker_address: Optional[int] = None,
        marker_value: Optional[int] = None,
        image_hash: bool = False,
        expected_image: Optional[str] = None,
        image_hash_slot: Optional[str] = None,
        otadata_expect: Optional[Dict[str, List[str]]] = None,
        otadata_expect_scope: str = "always",
    ) -> None:
        self.vtor_in_slot = vtor_in_slot
        self.pc_in_slot = pc_in_slot
        self.marker_address = marker_address
        self.marker_value = marker_value
        self.image_hash = image_hash
        self.expected_image = expected_image
        self.image_hash_slot = image_hash_slot
        self.otadata_expect = otadata_expect or {}
        self.otadata_expect_scope = otadata_expect_scope


class FaultSweepConfig:
    __slots__ = ("mode", "max_writes", "max_writes_cap", "max_step_limit", "run_duration", "fault_types", "evaluation_mode", "sweep_strategy", "hash_bypass_symbols", "progress_stall_timeout_s", "boot_cycles")

    def __init__(
        self,
        mode: str = "runtime",
        max_writes: Any = "auto",
        max_writes_cap: int = 100000,
        max_step_limit: int = 500000,
        run_duration: str = "0.5",
        fault_types: Optional[List[str]] = None,
        evaluation_mode: Optional[str] = None,
        sweep_strategy: str = "heuristic",
        hash_bypass_symbols: Optional[List[str]] = None,
        progress_stall_timeout_s: Optional[float] = None,
        boot_cycles: int = 1,
    ) -> None:
        self.mode = mode
        self.max_writes = max_writes
        self.max_writes_cap = max_writes_cap
        self.max_step_limit = max_step_limit
        self.run_duration = run_duration
        self.fault_types = fault_types or ["power_loss"]
        self.evaluation_mode = evaluation_mode
        self.sweep_strategy = sweep_strategy
        self.hash_bypass_symbols = hash_bypass_symbols or []
        self.progress_stall_timeout_s = progress_stall_timeout_s
        self.boot_cycles = max(1, int(boot_cycles))


class StateFuzzerConfig:
    __slots__ = ("enabled", "metadata_model")

    def __init__(self, enabled: bool = False, metadata_model: str = "ab_replica") -> None:
        self.enabled = enabled
        self.metadata_model = metadata_model


class ExpectConfig:
    __slots__ = ("should_find_issues", "control_outcome")

    def __init__(
        self,
        should_find_issues: bool = True,
        control_outcome: str = "success",
    ) -> None:
        self.should_find_issues = should_find_issues
        self.control_outcome = control_outcome


class PreBootWrite:
    __slots__ = ("address", "u32")

    def __init__(self, address: int, u32: int) -> None:
        self.address = address
        self.u32 = u32


class UpdateTrigger:
    """Declarative update trigger -- generates pre_boot_state writes automatically."""
    __slots__ = ("type", "slot", "fields")

    def __init__(self, type: str, slot: str, fields: Optional[Dict[str, Any]] = None) -> None:
        self.type = type
        self.slot = slot
        self.fields = fields or {}


# MCUboot trailer magic: 4 words written at (slot_end - 16).
MCUBOOT_GOOD_MAGIC = [0xF395C277, 0x7FEFD260, 0x0F505235, 0x8079B62C]


def _fletcher32(data: bytes) -> int:
    """Fletcher32 checksum (RIOT OS compatible)."""
    assert len(data) % 2 == 0
    words = struct.unpack("<{}H".format(len(data) // 2), data)
    sum1, sum2 = 0xFFFF, 0xFFFF
    i = 0
    while i < len(words):
        batch = min(359, len(words) - i)
        for j in range(batch):
            sum1 += words[i + j]
            sum2 += sum1
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
        i += batch
    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16)
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16)
    return (sum2 << 16) | sum1


VALID_SCENARIOS = {"runtime"}


class ProfileConfig:
    """Fully-parsed bootloader profile."""

    def __init__(
        self,
        schema_version: int,
        name: str,
        description: str,
        platform: str,
        bootloader_elf: str,
        bootloader_entry: int,
        memory: MemoryConfig,
        images: Dict[str, str],
        pre_boot_state: List[PreBootWrite],
        setup_script: Optional[str],
        success_criteria: SuccessCriteria,
        fault_sweep: FaultSweepConfig,
        state_fuzzer: StateFuzzerConfig,
        expect: ExpectConfig,
        profile_path: Optional[Path] = None,
        scenario: str = "runtime",
        update_trigger: Optional[UpdateTrigger] = None,
        state_probe_script: Optional[str] = None,
        semantic_assertions: Optional[Dict[str, Dict[str, Any]]] = None,
        invariants: Optional[List[str]] = None,
    ) -> None:
        self.schema_version = schema_version
        self.name = name
        self.description = description
        self.platform = platform
        self.bootloader_elf = bootloader_elf
        self.bootloader_entry = bootloader_entry
        self.memory = memory
        self.images = images
        self.pre_boot_state = pre_boot_state
        self.setup_script = setup_script
        self.success_criteria = success_criteria
        self.fault_sweep = fault_sweep
        self.state_fuzzer = state_fuzzer
        self.expect = expect
        self.profile_path = profile_path
        self.scenario = scenario
        self.update_trigger = update_trigger
        self.state_probe_script = state_probe_script
        self.semantic_assertions = semantic_assertions or {}
        self.invariants = invariants or []

    def resolve_path(self, repo_root: Path, value: str) -> str:
        """Resolve a path relative to the repo root."""
        p = Path(value)
        if p.is_absolute():
            return str(p)
        return str((repo_root / p).resolve())

    def generate_pre_boot_bin(self) -> Optional[str]:
        """Write pre_boot_state entries to a temp .bin file.

        Returns the temp file path, or None if no pre_boot_state.
        The caller is responsible for cleanup.
        """
        if not self.pre_boot_state:
            return None

        # Format: sequence of (u32 address, u32 value) pairs.
        data = bytearray()
        for write in self.pre_boot_state:
            data.extend(struct.pack("<II", write.address, write.u32))

        tmp = tempfile.NamedTemporaryFile(
            prefix="pre_boot_state_", suffix=".bin", delete=False
        )
        tmp.write(bytes(data))
        tmp.close()
        return tmp.name

    def expand_update_trigger(self) -> List[PreBootWrite]:
        """Expand update_trigger into PreBootWrite entries.

        Returns empty list if no update_trigger is set.
        """
        if self.update_trigger is None:
            return []

        trigger = self.update_trigger
        if trigger.slot not in self.memory.slots:
            raise ProfileError(
                "update_trigger.slot '{}' not found in memory.slots".format(trigger.slot)
            )
        slot = self.memory.slots[trigger.slot]
        slot_end = slot.base + slot.size

        if trigger.type == "mcuboot_trailer_magic":
            # MCUboot GOOD magic: 4 words at slot_end - 16.
            magic_base = slot_end - 16
            writes: List[PreBootWrite] = []
            for i, val in enumerate(MCUBOOT_GOOD_MAGIC):
                writes.append(PreBootWrite(address=magic_base + i * 4, u32=val))
            # Optional copy_done field for revert scenarios.
            align = int(trigger.fields.get("max_align", 8))
            if trigger.fields.get("copy_done") is not None:
                # MCUboot trailer: magic at -16, image_ok at -16-align,
                # copy_done at -16-2*align.
                copy_done_addr = slot_end - 16 - 2 * align
                writes.append(PreBootWrite(
                    address=copy_done_addr,
                    u32=_parse_int(trigger.fields["copy_done"], "update_trigger.copy_done"),
                ))
            return writes

        if trigger.type == "riotboot_header":
            # riotboot header: 16-byte struct at slot base.
            # Fields: magic (0x544F4952), version, start_addr, fletcher32 checksum.
            # start_addr = slot.base + hdr_len (default 0x100 = 256).
            hdr_len = int(trigger.fields.get("hdr_len", 0x100))
            version = _parse_int(trigger.fields.get("version", 2), "update_trigger.version")
            start_addr = slot.base + hdr_len
            # Build the 12-byte payload for Fletcher32.
            payload = struct.pack("<III", 0x544F4952, version, start_addr)
            chksum = _fletcher32(payload)
            writes = [
                PreBootWrite(address=slot.base + 0, u32=0x544F4952),
                PreBootWrite(address=slot.base + 4, u32=version),
                PreBootWrite(address=slot.base + 8, u32=start_addr),
                PreBootWrite(address=slot.base + 12, u32=chksum),
            ]
            return writes

        raise ProfileError(
            "Unknown update_trigger type '{}'.".format(trigger.type)
        )

    def robot_vars(self, repo_root: Path) -> List[str]:
        """Generate Robot Framework --variable arguments for this profile."""
        mem = self.memory
        sc = self.success_criteria
        fs = self.fault_sweep

        vars_list: List[str] = [
            "PLATFORM_REPL:{}".format(self.resolve_path(repo_root, self.platform)),
            "BOOTLOADER_ELF:{}".format(self.resolve_path(repo_root, self.bootloader_elf)),
            "BOOTLOADER_ENTRY:0x{:08X}".format(self.bootloader_entry),
            "SRAM_START:0x{:08X}".format(mem.sram_start),
            "SRAM_END:0x{:08X}".format(mem.sram_end),
            "WRITE_GRANULARITY:{}".format(mem.write_granularity),
            "RUN_DURATION:{}".format(fs.run_duration),
            "MAX_STEP_LIMIT:{}".format(fs.max_step_limit),
            "MAX_WRITES_CAP:{}".format(fs.max_writes_cap),
            "BOOT_CYCLES:{}".format(fs.boot_cycles),
            "RUNTIME_MODE:true",
        ]

        # Slot info.
        for slot_name, slot_cfg in mem.slots.items():
            prefix = "SLOT_{}_".format(slot_name.upper())
            vars_list.append("{}BASE:0x{:08X}".format(prefix, slot_cfg.base))
            vars_list.append("{}SIZE:0x{:08X}".format(prefix, slot_cfg.size))

        # Images (robot variables for Load Runtime Scenario + paths for batch reload).
        for img_name, img_path in self.images.items():
            resolved = self.resolve_path(repo_root, img_path)
            vars_list.append("IMAGE_{}:{}".format(img_name.upper(), resolved))
            vars_list.append("IMAGE_{}_PATH:{}".format(img_name.upper(), resolved))

        # Success criteria.
        if sc.vtor_in_slot:
            vars_list.append("SUCCESS_VTOR_SLOT:{}".format(sc.vtor_in_slot))
        else:
            vars_list.append("SUCCESS_VTOR_SLOT:")
        if sc.pc_in_slot:
            vars_list.append("SUCCESS_PC_SLOT:{}".format(sc.pc_in_slot))
        if sc.marker_address is not None:
            vars_list.append("SUCCESS_MARKER_ADDR:0x{:08X}".format(sc.marker_address))
        if sc.marker_value is not None:
            vars_list.append("SUCCESS_MARKER_VALUE:0x{:08X}".format(sc.marker_value))
        if sc.otadata_expect:
            encoded_entries: List[str] = []
            for key in sorted(sc.otadata_expect.keys()):
                values = [v for v in sc.otadata_expect[key] if v]
                if not values:
                    continue
                encoded_entries.append("{}={}".format(key, "|".join(values)))
            vars_list.append("SUCCESS_OTADATA_EXPECT:{}".format(";".join(encoded_entries)))
        else:
            vars_list.append("SUCCESS_OTADATA_EXPECT:")
        vars_list.append(
            "SUCCESS_OTADATA_EXPECT_SCOPE:{}".format(sc.otadata_expect_scope or "always")
        )

        # Image hash mode: pre-compute SHA-256 of each image binary.
        # Hash only the data portion (slot_size - page_size), excluding the
        # last page where bootloaders store trailer metadata.
        if sc.image_hash:
            import hashlib
            vars_list.append("SUCCESS_IMAGE_HASH:true")
            if sc.image_hash_slot:
                vars_list.append("SUCCESS_IMAGE_HASH_SLOT:{}".format(sc.image_hash_slot))
            page_size = 4096
            exec_slot = mem.slots.get("exec")
            data_size = (exec_slot.size - page_size) if exec_slot and exec_slot.size > page_size else None
            image_digests: Dict[str, str] = {}
            for img_name, img_path in self.images.items():
                resolved = self.resolve_path(repo_root, img_path)
                try:
                    with open(resolved, "rb") as fh:
                        raw = fh.read()
                    # Normalize to slot data length: truncate oversized images
                    # and pad short images with erased flash bytes.
                    if data_size:
                        if len(raw) >= data_size:
                            raw = raw[:data_size]
                        else:
                            raw = raw + (b"\xFF" * (data_size - len(raw)))
                    digest = hashlib.sha256(raw).hexdigest()
                    vars_list.append("IMAGE_{}_SHA256:{}".format(img_name.upper(), digest))
                    image_digests[img_name] = digest
                except FileNotFoundError:
                    pass
            # expected_image: which image should be in exec after a successful operation.
            expected = sc.expected_image or "staging"
            if expected in image_digests:
                vars_list.append("EXPECTED_EXEC_SHA256:{}".format(image_digests[expected]))
            else:
                vars_list.append("EXPECTED_EXEC_SHA256:")

        # Pre-boot state.
        pre_boot_bin = self.generate_pre_boot_bin()
        if pre_boot_bin:
            vars_list.append("PRE_BOOT_STATE_BIN:{}".format(pre_boot_bin))

        # Setup script.
        if self.setup_script:
            vars_list.append(
                "SETUP_SCRIPT:{}".format(self.resolve_path(repo_root, self.setup_script))
            )
        if self.state_probe_script:
            vars_list.append(
                "STATE_PROBE_SCRIPT:{}".format(
                    self.resolve_path(repo_root, self.state_probe_script)
                )
            )

        # Hash bypass: comma-separated list of function symbols to short-circuit.
        if fs.hash_bypass_symbols:
            vars_list.append(
                "HASH_BYPASS_SYMBOLS:{}".format(",".join(fs.hash_bypass_symbols))
            )

        # Per-profile stall timeout override.
        if fs.progress_stall_timeout_s is not None:
            vars_list.append(
                "PROGRESS_STALL_TIMEOUT_S:{}".format(fs.progress_stall_timeout_s)
            )

        return vars_list
# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_int(value: Any, field_name: str) -> int:
    """Parse an integer from YAML (handles hex strings like 0x10000000)."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise ProfileError("{}: expected integer, got {!r}".format(field_name, value))


def _normalize_criterion_token(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return "0x{:08X}".format(value & 0xFFFFFFFF)
    text = str(value).strip()
    if not text:
        return ""
    if text.lower() in ("true", "false"):
        return text.lower()
    try:
        parsed = int(text, 0)
    except ValueError:
        return text
    return "0x{:08X}".format(parsed & 0xFFFFFFFF)


def _parse_otadata_expect(raw: Any) -> Dict[str, List[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError("success_criteria.otadata_expect: expected mapping")

    parsed: Dict[str, List[str]] = {}
    for key, value in raw.items():
        token_key = str(key).strip()
        if not token_key:
            continue

        values: List[Any]
        if isinstance(value, list):
            values = value
        else:
            values = [value]

        token_values: List[str] = []
        for item in values:
            token = _normalize_criterion_token(item)
            if token:
                token_values.append(token)
        if not token_values:
            raise ProfileError(
                "success_criteria.otadata_expect.{}: expected non-empty value list".format(
                    token_key
                )
            )
        parsed[token_key] = token_values

    return parsed


def _require(data: Dict[str, Any], key: str, context: str = "") -> Any:
    """Require a key to exist in a dict."""
    if key not in data:
        where = " in {}".format(context) if context else ""
        raise ProfileError("missing required field '{}'{}.".format(key, where))
    return data[key]


def _parse_slots(raw: Dict[str, Any]) -> Dict[str, SlotConfig]:
    slots: Dict[str, SlotConfig] = {}
    for name, slot_data in raw.items():
        base = _parse_int(_require(slot_data, "base", "slots.{}".format(name)), "slots.{}.base".format(name))
        size = _parse_int(_require(slot_data, "size", "slots.{}".format(name)), "slots.{}.size".format(name))
        slots[name] = SlotConfig(base=base, size=size)
    return slots


def _parse_memory(raw: Dict[str, Any]) -> MemoryConfig:
    sram = _require(raw, "sram", "memory")
    sram_start = _parse_int(_require(sram, "start", "memory.sram"), "memory.sram.start")
    sram_end = _parse_int(_require(sram, "end", "memory.sram"), "memory.sram.end")
    write_granularity = _parse_int(raw.get("write_granularity", 8), "memory.write_granularity")
    slots = _parse_slots(_require(raw, "slots", "memory"))
    return MemoryConfig(
        sram_start=sram_start,
        sram_end=sram_end,
        write_granularity=write_granularity,
        slots=slots,
    )


def _parse_success_criteria(raw: Optional[Dict[str, Any]]) -> SuccessCriteria:
    if raw is None:
        return SuccessCriteria()
    otadata_expect_scope = str(raw.get("otadata_expect_scope", "always")).strip().lower()
    if otadata_expect_scope not in ("always", "control"):
        raise ProfileError(
            "success_criteria.otadata_expect_scope: expected 'always' or 'control'"
        )
    return SuccessCriteria(
        vtor_in_slot=raw.get("vtor_in_slot"),
        pc_in_slot=raw.get("pc_in_slot"),
        marker_address=_parse_int(raw["marker_address"], "success_criteria.marker_address") if "marker_address" in raw else None,
        marker_value=_parse_int(raw["marker_value"], "success_criteria.marker_value") if "marker_value" in raw else None,
        image_hash=bool(raw.get("image_hash", False)),
        expected_image=raw.get("expected_image"),
        image_hash_slot=raw.get("image_hash_slot"),
        otadata_expect=_parse_otadata_expect(raw.get("otadata_expect")),
        otadata_expect_scope=otadata_expect_scope,
    )


def _parse_fault_sweep(raw: Optional[Dict[str, Any]]) -> FaultSweepConfig:
    if raw is None:
        return FaultSweepConfig()
    fault_types = raw.get("fault_types", ["power_loss"])
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            import warnings
            warnings.warn("Unknown fault type '{}' in profile; ignoring.".format(ft))
        if ft in KNOWN_FAULT_TYPES and ft not in IMPLEMENTED_FAULT_TYPES:
            import warnings
            warnings.warn("Fault type '{}' is not yet implemented; skipping.".format(ft))
    eval_mode = raw.get("evaluation_mode")
    if eval_mode is not None:
        eval_mode = str(eval_mode)
    hash_bypass = raw.get("hash_bypass_symbols")
    if hash_bypass is not None and not isinstance(hash_bypass, list):
        hash_bypass = [str(hash_bypass)]
    stall_timeout = raw.get("progress_stall_timeout_s")
    if stall_timeout is not None:
        stall_timeout = float(stall_timeout)
    boot_cycles = int(raw.get("boot_cycles", 1))
    if boot_cycles < 1:
        raise ProfileError("fault_sweep.boot_cycles: expected integer >= 1")
    return FaultSweepConfig(
        mode=raw.get("mode", "runtime"),
        max_writes=raw.get("max_writes", "auto"),
        max_writes_cap=int(raw.get("max_writes_cap", 100000)),
        max_step_limit=int(raw.get("max_step_limit", 500000)),
        run_duration=str(raw.get("run_duration", "0.5")),
        fault_types=fault_types,
        evaluation_mode=eval_mode,
        sweep_strategy=str(raw.get("sweep_strategy", "heuristic")),
        hash_bypass_symbols=hash_bypass,
        progress_stall_timeout_s=stall_timeout,
        boot_cycles=boot_cycles,
    )


def _parse_state_fuzzer(raw: Optional[Dict[str, Any]]) -> StateFuzzerConfig:
    if raw is None:
        return StateFuzzerConfig()
    return StateFuzzerConfig(
        enabled=bool(raw.get("enabled", False)),
        metadata_model=str(raw.get("metadata_model", "ab_replica")),
    )


def _parse_expect(raw: Optional[Dict[str, Any]]) -> ExpectConfig:
    if raw is None:
        return ExpectConfig()
    return ExpectConfig(
        should_find_issues=bool(raw.get("should_find_issues", True)),
        control_outcome=str(raw.get("control_outcome", "success")),
    )


def _parse_update_trigger(raw: Optional[Dict[str, Any]]) -> Optional[UpdateTrigger]:
    if raw is None:
        return None
    trigger_type = str(_require(raw, "type", "update_trigger"))
    slot = str(_require(raw, "slot", "update_trigger"))
    fields: Dict[str, Any] = {}
    for k, v in raw.items():
        if k not in ("type", "slot"):
            fields[k] = v
    return UpdateTrigger(type=trigger_type, slot=slot, fields=fields)


def _parse_pre_boot_state(raw: Optional[list]) -> List[PreBootWrite]:
    if raw is None:
        return []
    writes: List[PreBootWrite] = []
    for i, entry in enumerate(raw):
        addr = _parse_int(_require(entry, "address", "pre_boot_state[{}]".format(i)), "pre_boot_state[{}].address".format(i))
        val = _parse_int(_require(entry, "u32", "pre_boot_state[{}]".format(i)), "pre_boot_state[{}].u32".format(i))
        writes.append(PreBootWrite(address=addr, u32=val))
    return writes


def _parse_semantic_assertions(raw: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError("semantic_assertions: expected mapping")
    parsed: Dict[str, Dict[str, Any]] = {}
    for scope in ("always", "control", "faulted"):
        scope_raw = raw.get(scope)
        if scope_raw is None:
            continue
        if not isinstance(scope_raw, dict):
            raise ProfileError(
                "semantic_assertions.{}: expected mapping of path -> expected value".format(
                    scope
                )
            )
        parsed_scope: Dict[str, Any] = {}
        for key, value in scope_raw.items():
            path = str(key).strip()
            if not path:
                raise ProfileError(
                    "semantic_assertions.{}: expected non-empty assertion path".format(
                        scope
                    )
                )
            parsed_scope[path] = value
        if parsed_scope:
            parsed[scope] = parsed_scope
    unknown_scopes = sorted(set(raw.keys()) - {"always", "control", "faulted"})
    if unknown_scopes:
        raise ProfileError(
            "semantic_assertions: unknown scope(s): {}".format(", ".join(unknown_scopes))
        )
    return parsed


def _parse_invariants(raw: Optional[Any]) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        value = raw.strip()
        return [value] if value else []
    if isinstance(raw, list):
        parsed: List[str] = []
        for i, entry in enumerate(raw):
            value = str(entry).strip()
            if not value:
                raise ProfileError("invariants[{}]: expected non-empty string".format(i))
            parsed.append(value)
        return parsed
    raise ProfileError("invariants: expected string or list of strings")


# ---------------------------------------------------------------------------
# Main loader
# ---------------------------------------------------------------------------

def load_profile(path: str | Path) -> ProfileConfig:
    """Load and validate a YAML profile.

    Args:
        path: Path to the .yaml profile file.

    Returns:
        A validated ProfileConfig.

    Raises:
        ProfileError: If the profile is invalid.
        FileNotFoundError: If the profile doesn't exist.
    """
    if yaml is None:
        raise ProfileError(
            "PyYAML is required for profile loading. Install it: pip install pyyaml"
        )

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("Profile not found: {}".format(path))

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ProfileError("Profile must be a YAML mapping, got {}".format(type(data).__name__))

    # Schema version validation.
    schema_version = _parse_int(
        _require(data, "schema_version"), "schema_version"
    )
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ProfileError(
            "Unsupported schema_version {}. Supported: {}".format(
                schema_version, sorted(SUPPORTED_SCHEMA_VERSIONS)
            )
        )

    # Required fields.
    name = str(_require(data, "name"))
    description = str(data.get("description", ""))
    platform = str(_require(data, "platform"))

    bootloader = _require(data, "bootloader")
    bootloader_elf = str(_require(bootloader, "elf", "bootloader"))
    bootloader_entry = _parse_int(
        _require(bootloader, "entry", "bootloader"), "bootloader.entry"
    )

    memory = _parse_memory(_require(data, "memory"))
    images = {}
    raw_images = data.get("images", {})
    if isinstance(raw_images, dict):
        images = {str(k): str(v) for k, v in raw_images.items()}

    pre_boot_state = _parse_pre_boot_state(data.get("pre_boot_state"))
    update_trigger = _parse_update_trigger(data.get("update_trigger"))
    setup_script = data.get("setup_script")
    if setup_script is not None:
        setup_script = str(setup_script)
    state_probe_script = data.get("state_probe_script")
    if state_probe_script is not None:
        state_probe_script = str(state_probe_script)

    success_criteria = _parse_success_criteria(data.get("success_criteria"))
    fault_sweep = _parse_fault_sweep(data.get("fault_sweep"))
    state_fuzzer = _parse_state_fuzzer(data.get("state_fuzzer"))
    expect = _parse_expect(data.get("expect"))
    semantic_assertions = _parse_semantic_assertions(data.get("semantic_assertions"))
    invariants = _parse_invariants(data.get("invariants"))

    scenario = str(data.get("scenario", "runtime"))
    if scenario not in VALID_SCENARIOS:
        raise ProfileError(
            "Invalid scenario '{}'. Valid: {}".format(scenario, sorted(VALID_SCENARIOS))
        )

    # Guard: execute mode on pure NVMemory platforms is unfeasible — every CPU
    # instruction fetch crosses the tlib↔C# boundary, making emulation
    # ~300x slower than MappedMemory.  Hybrid platforms (MappedMemory for code,
    # NVMemory only for metadata) are fine.
    if (
        fault_sweep.evaluation_mode == "execute"
        and "nvm" in platform
        and "flash_fast" not in platform
        and "hybrid" not in platform
    ):
        raise ProfileError(
            "evaluation_mode 'execute' is incompatible with NVMemory platform '{}'. "
            "NVMemory instruction fetch is too slow for CPU emulation. "
            "Use evaluation_mode 'state' or switch to a MappedMemory/hybrid platform.".format(platform)
        )

    profile = ProfileConfig(
        schema_version=schema_version,
        name=name,
        description=description,
        platform=platform,
        bootloader_elf=bootloader_elf,
        bootloader_entry=bootloader_entry,
        memory=memory,
        images=images,
        pre_boot_state=pre_boot_state,
        setup_script=setup_script,
        success_criteria=success_criteria,
        fault_sweep=fault_sweep,
        state_fuzzer=state_fuzzer,
        expect=expect,
        profile_path=path,
        scenario=scenario,
        update_trigger=update_trigger,
        state_probe_script=state_probe_script,
        semantic_assertions=semantic_assertions,
        invariants=invariants,
    )

    # If update_trigger is set and pre_boot_state is empty, expand the trigger.
    if update_trigger and not profile.pre_boot_state:
        profile.pre_boot_state = profile.expand_update_trigger()

    return profile


def load_profile_raw(path: str | Path) -> Dict[str, Any]:
    """Load a profile as raw dict (for self_test.py to read expect section)."""
    if yaml is None:
        raise ProfileError("PyYAML is required.")
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# CLI for debugging
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/profile_loader.py <profile.yaml>", file=sys.stderr)
        return 1

    profile = load_profile(sys.argv[1])
    info = {
        "name": profile.name,
        "description": profile.description,
        "platform": profile.platform,
        "bootloader_elf": profile.bootloader_elf,
        "bootloader_entry": "0x{:08X}".format(profile.bootloader_entry),
        "slots": {
            name: {"base": "0x{:08X}".format(s.base), "size": "0x{:08X}".format(s.size)}
            for name, s in profile.memory.slots.items()
        },
        "images": profile.images,
        "fault_sweep_mode": profile.fault_sweep.mode,
        "max_writes": profile.fault_sweep.max_writes,
        "boot_cycles": profile.fault_sweep.boot_cycles,
        "state_fuzzer_enabled": profile.state_fuzzer.enabled,
        "expect_should_find_issues": profile.expect.should_find_issues,
        "image_hash": profile.success_criteria.image_hash,
        "image_hash_slot": profile.success_criteria.image_hash_slot,
        "otadata_expect": profile.success_criteria.otadata_expect,
        "otadata_expect_scope": profile.success_criteria.otadata_expect_scope,
        "state_probe_script": profile.state_probe_script,
        "semantic_assertions": profile.semantic_assertions,
        "invariants": profile.invariants,
        "update_trigger": profile.update_trigger.type if profile.update_trigger else None,
        "pre_boot_state_count": len(profile.pre_boot_state),
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
