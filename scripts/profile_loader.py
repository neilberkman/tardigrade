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

import base64
import fnmatch
import hashlib
import json
import math
import re
import struct
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import BootloaderRegionConfig, FaultDistributionConfig, MetadataFaultRegion
from fault_types import (
    CLASSIFICATION_ONLY_FAULT_TYPES,
    I2C_FAULT_TYPE_CODES,
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    OTP_FAULT_TYPE_CODES,
    PHASE2_FAULT_TYPES,
)
from thumb_instructions import enumerate_instruction_skip_addresses, make_elf_halfword_reader
from boot_outcomes import DEVICE_BOOT_OUTCOMES
from update_protocol_analyzer import (
    UpdateProtocolError,
    UpdateProtocolModel,
    analyze_update_protocol,
    parse_update_protocol,
)
from authorization_review_analyzer import (
    AuthorizationReviewError,
    AuthorizationReviewModel,
    analyze_authorization_review,
    parse_authorization_review,
)
from security_state_layout import (
    analyze_persistent_state_layout,
    PersistentStateLayout,
    SecurityStateLayoutError,
    parse_persistent_state_layout,
)
from terminal_error_escape import (
    TerminalErrorPathConfig,
    build_terminal_runtime_payload,
    discover_terminal_error_paths,
    parse_terminal_error_paths,
    terminal_snapshot_identity,
)
from boundary_campaigns import (
    BoundaryCampaign,
    BoundaryCampaignError,
    boundary_campaign_dict,
    parse_boundary_campaign,
    resolve_boundary_capacity,
    resolve_boundary_values,
    resolve_followup_value,
)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None  # type: ignore[assignment]


SUPPORTED_SCHEMA_VERSIONS = {1}

MAX_PROFILE_FAULT_POINTS = 1_000_000
MAX_PROFILE_STEP_LIMIT = 2_000_000_000
MAX_STATE_FUZZ_ITERATIONS = 100_000
MAX_MULTI_FAULT_PAIRS = 100_000
MAX_MULTI_FAULTS_PER_RUN = 64
MAX_BOOT_CYCLES = 1_000

_MAX_INHERITANCE_DEPTH = 10

# GCC clone suffixes, in the order the compiler appends them.
# A single symbol may chain multiple suffixes (e.g. ``foo.constprop.0.isra.1``),
# so stripping is applied iteratively.  Keep this list in sync with GCC's
# ``cgraph_node::create_clone`` and ``symtab_node::clone_alias_target``.
_GCC_CLONE_SUFFIX_TAGS = (
    "constprop",
    "part",
    "isra",
    "cold",
    "localalias",
    "lto_priv",
)

# ``cold`` is emitted both numbered (``foo.cold.0``) and unnumbered
# (``foo.cold``) depending on GCC version; everything else is always
# followed by a decimal counter.
_CLONE_SUFFIX_PATTERN = re.compile(
    r"(?:"
    r"\.(?:constprop|part|isra|localalias|lto_priv)\.\d+"
    r"|\.cold(?:\.\d+)?"
    r")$"
)


def _deep_merge_profile_data(base: Any, override: Any) -> Any:
    """Deep-merge two profile data structures.

    Semantics:
    - dicts merge recursively (override keys win)
    - lists replace (not append)
    - scalars replace
    """
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            if key in merged:
                merged[key] = _deep_merge_profile_data(merged[key], value)
            else:
                merged[key] = value
        return merged
    return override


def _resolve_base_profile(
    data: Dict[str, Any],
    profile_path: Path,
    _seen: Optional[tuple] = None,
    *,
    _strict_root: Optional[Path] = None,
    _base_chain: Optional[List[Tuple[str, Path]]] = None,
) -> Dict[str, Any]:
    """Resolve ``base_profile`` inheritance chain.

    If *data* contains a ``base_profile`` key, the referenced profile is loaded,
    its own ``base_profile`` chain is resolved first, and then *data* is
    deep-merged on top of the base.

    Cycle detection uses a set of resolved absolute paths.  Chains deeper than
    ``_MAX_INHERITANCE_DEPTH`` are rejected to catch indirect cycles.
    """
    base_rel = data.pop("base_profile", None)
    if base_rel is None:
        return data

    if yaml is None:
        raise ProfileError("PyYAML is required for profile loading.")

    if _strict_root is not None:
        _validate_strict_relative_path(base_rel, "base_profile")

    # Resolve the base path relative to the directory of the current profile.
    base_path = (profile_path.parent / base_rel).resolve()
    if _strict_root is not None:
        strict_root = _strict_root.resolve()
        try:
            base_path.relative_to(strict_root)
        except ValueError as exc:
            raise ProfileError(
                "base_profile {!r} escapes strict profile boundary {} "
                "(resolved to {})".format(base_rel, strict_root, base_path)
            ) from exc
    if _base_chain is not None:
        _base_chain.append((str(base_rel), base_path))
    if not base_path.exists():
        raise ProfileError(
            "base_profile '{}' not found (resolved to {})".format(base_rel, base_path)
        )

    seen = set(_seen) if _seen else set()
    current_resolved = profile_path.resolve()
    seen.add(current_resolved)

    if base_path in seen:
        raise ProfileError(
            "base_profile cycle detected: {} -> {}".format(current_resolved, base_path)
        )

    if len(seen) >= _MAX_INHERITANCE_DEPTH:
        raise ProfileError(
            "base_profile chain too deep (>{} levels)".format(_MAX_INHERITANCE_DEPTH)
        )

    with open(base_path, "r", encoding="utf-8") as f:
        base_data = yaml.safe_load(f)

    if not isinstance(base_data, dict):
        raise ProfileError(
            "base_profile '{}' must be a YAML mapping, got {}".format(
                base_rel, type(base_data).__name__
            )
        )

    # Recursively resolve the base's own base_profile, passing the growing
    # set of seen paths.
    base_data = _resolve_base_profile(
        base_data,
        base_path,
        _seen=tuple(seen),
        _strict_root=_strict_root,
        _base_chain=_base_chain,
    )

    # Deep-merge: child overrides base.
    return _deep_merge_profile_data(base_data, data)

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


class MemoryRegionConfig:
    """A declared flash region and its erase-sector granularity.

    ``sector_size`` is optional for postmortem-only regions, but is required
    for erase geometry entries.  Keeping this small mapping generic avoids
    coupling evidence collection to a particular bootloader.
    """

    __slots__ = ("name", "base", "size", "sector_size")

    def __init__(
        self,
        base: int,
        size: int,
        sector_size: Optional[int] = None,
        name: Optional[str] = None,
    ) -> None:
        self.name = str(name) if name is not None else None
        self.base = int(base)
        self.size = int(size)
        self.sector_size = int(sector_size) if sector_size is not None else None


class MemoryConfig:
    __slots__ = (
        "sram_start",
        "sram_end",
        "write_granularity",
        "page_size",
        "slots",
        "bootloader_region",
        "trace_address_map",
        "erase_regions",
        "postmortem_partitions",
    )

    def __init__(
        self,
        sram_start: int,
        sram_end: int,
        write_granularity: int,
        slots: Dict[str, SlotConfig],
        page_size: int = 4096,
        bootloader_region: Optional[BootloaderRegionConfig] = None,
        trace_address_map: Optional[List[Dict[str, int]]] = None,
        erase_regions: Optional[List[MemoryRegionConfig]] = None,
        postmortem_partitions: Optional[List[MemoryRegionConfig]] = None,
    ) -> None:
        self.sram_start = sram_start
        self.sram_end = sram_end
        self.write_granularity = write_granularity
        self.page_size = page_size
        self.slots = slots
        self.bootloader_region = bootloader_region
        # Optional mapping from backend trace offsets to CPU-visible absolute
        # addresses.  This is needed for aliased memories while preserving
        # the historical zero-based trace format.
        self.trace_address_map = trace_address_map or []
        self.erase_regions = erase_regions or []
        self.postmortem_partitions = postmortem_partitions or []


class ResidualImageConfig:
    """Configuration for residual-image testing on direct-XIP bootloaders.

    When a smaller image replaces a larger one in-place, stale bytes from the
    previous image may remain in the slot tail.  On MRAM (no erase cycle) this
    is guaranteed; on flash it depends on whether the OTA process erases the
    full slot before writing.

    ``slot`` names the memory slot to contaminate (must exist in memory.slots).
    ``prior_image`` is the path to the larger (old) image binary (optional if
    ``fill_pattern`` is set -- the fill alone can model an erased slot).
    ``fill_pattern`` optionally fills the slot before any image load.  When set
    WITHOUT ``prior_image``, it fills the full slot then the actual image is
    loaded on top.  When set WITH ``prior_image``, the prior image is loaded
    first, then the region from actual_image_size to prior_image_size is filled
    (the residual tail only).
    """

    __slots__ = ("slot", "prior_image", "fill_pattern")

    def __init__(
        self,
        slot: str,
        prior_image: Optional[str] = None,
        fill_pattern: Optional[int] = None,
    ) -> None:
        self.slot = slot
        self.prior_image = prior_image
        if fill_pattern is not None:
            fill_pattern = int(fill_pattern)
            if not (0 <= fill_pattern <= 0xFF):
                raise ProfileError(
                    "residual_image.fill_pattern must be 0x00-0xFF, got 0x{:02X}".format(
                        fill_pattern
                    )
                )
        self.fill_pattern = fill_pattern


class MemoryCheck:
    """Post-execution memory assertion."""

    __slots__ = ("address", "expected_value", "mask", "op")

    def __init__(
        self,
        address: int,
        expected_value: Optional[int] = None,
        mask: int = 0xFFFFFFFF,
        op: str = "eq",
    ) -> None:
        self.address = int(address)
        self.expected_value = int(expected_value) if expected_value is not None else None
        self.mask = int(mask)
        if op not in ("eq", "ne", "ge", "le", "nonzero"):
            raise ProfileError(
                "memory_check: op must be one of eq, ne, ge, le, nonzero; got '{}'".format(op)
            )
        self.op = op


class SuccessCriteria:
    __slots__ = (
        "vtor_in_slot",
        "vector_table_offset",
        "pc_in_slot",
        "marker_address",
        "marker_value",
        "image_hash",
        "expected_image",
        "image_hash_slot",
        "otadata_expect",
        "otadata_expect_scope",
        "bootloader_integrity",
        "config_checks",
        "boot_register_values",
        "max_reset_vector_offset",
        "memory_checks",
    )

    def __init__(
        self,
        vtor_in_slot: Optional[str] = None,
        vector_table_offset: int = 0,
        pc_in_slot: Optional[str] = None,
        marker_address: Optional[int] = None,
        marker_value: Optional[int] = None,
        image_hash: bool = False,
        expected_image: Optional[str] = None,
        image_hash_slot: Optional[str] = None,
        otadata_expect: Optional[Dict[str, List[str]]] = None,
        otadata_expect_scope: str = "always",
        bootloader_integrity: bool = False,
        config_checks: Optional[List[ConfigCheck]] = None,
        boot_register_values: Optional[Dict[str, int]] = None,
        max_reset_vector_offset: Optional[int] = None,
        memory_checks: Optional[List["MemoryCheck"]] = None,
    ) -> None:
        self.vtor_in_slot = vtor_in_slot
        self.vector_table_offset = max(0, int(vector_table_offset))
        self.pc_in_slot = pc_in_slot
        self.marker_address = marker_address
        self.marker_value = marker_value
        self.image_hash = image_hash
        self.expected_image = expected_image
        self.image_hash_slot = image_hash_slot
        self.otadata_expect = otadata_expect or {}
        self.otadata_expect_scope = otadata_expect_scope
        self.bootloader_integrity = bootloader_integrity
        self.config_checks = config_checks or []
        self.boot_register_values = boot_register_values or {}
        if max_reset_vector_offset is not None:
            max_reset_vector_offset = int(max_reset_vector_offset)
            if max_reset_vector_offset < 0:
                raise ProfileError(
                    "success_criteria.max_reset_vector_offset must be >= 0, got {}".format(
                        max_reset_vector_offset
                    )
                )
        self.max_reset_vector_offset = max_reset_vector_offset
        self.memory_checks = memory_checks or []



class MultiFaultConfig:
    """Configuration for multi-fault (sequential interruption) sweeps."""

    __slots__ = (
        "enabled",
        "max_faults_per_run",
        "strategy",
        "fallback_strategy",
        "max_pairs",
        "seed",
        "sequences",
    )

    def __init__(
        self,
        enabled: bool = False,
        max_faults_per_run: int = 2,
        strategy: str = "pairwise_interesting",
        fallback_strategy: str = "boundary_pairs",
        max_pairs: int = 5000,
        seed=None,
        sequences=None,
    ) -> None:
        self.enabled = enabled
        self.max_faults_per_run = max(2, int(max_faults_per_run))
        if self.max_faults_per_run > MAX_MULTI_FAULTS_PER_RUN:
            raise ProfileError(
                "fault_sweep.multi_fault.max_faults_per_run exceeds safety "
                "limit {}".format(MAX_MULTI_FAULTS_PER_RUN)
            )
        self.strategy = strategy
        self.fallback_strategy = fallback_strategy
        self.max_pairs = max(1, int(max_pairs))
        if self.max_pairs > MAX_MULTI_FAULT_PAIRS:
            raise ProfileError(
                "fault_sweep.multi_fault.max_pairs exceeds safety limit {}".format(
                    MAX_MULTI_FAULT_PAIRS
                )
            )
        self.seed = seed
        self.sequences = sequences or []


class Phase2FaultConfig:
    """Configuration for injecting faults during Phase 2 recovery writes."""

    __slots__ = ("enabled", "fault_types", "max_points")

    def __init__(
        self,
        enabled: bool = False,
        fault_types: Optional[List[str]] = None,
        max_points: int = 0,
    ) -> None:
        self.enabled = enabled
        self.fault_types = fault_types or ["power_loss"]
        self.max_points = max(0, int(max_points))
        if self.max_points > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "fault_sweep.phase2_fault.max_points exceeds safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )


class HookFaultConfig:
    """Configuration for injecting faults during boot-cycle hook writes."""

    __slots__ = ("enabled", "fault_types", "max_points")

    def __init__(
        self,
        enabled: bool = False,
        fault_types: Optional[List[str]] = None,
        max_points: int = 0,
    ) -> None:
        self.enabled = enabled
        self.fault_types = fault_types or ["power_loss"]
        self.max_points = max(0, int(max_points))
        if self.max_points > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "fault_sweep.hook_fault.max_points exceeds safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )


class ConfirmCycleConfig:
    """Configuration for confirm-phase fault injection.

    Models the two-phase update pattern where firmware calls a confirm
    function after self-test to promote PENDING_TEST to ACCEPTED and
    ratchet the rollback floor.  Faults are injected during the NVM
    writes that the confirm function performs.
    """

    __slots__ = (
        "enabled",
        "confirm_function",
        "post_confirm_assertions",
        "expected_ratchet_version",
        "fault_types",
        "max_points",
    )

    def __init__(
        self,
        enabled: bool = False,
        confirm_function: Optional[str] = None,
        post_confirm_assertions: Optional[List[Dict[str, Any]]] = None,
        expected_ratchet_version: Optional[int] = None,
        fault_types: Optional[List[str]] = None,
        max_points: int = 0,
    ) -> None:
        self.enabled = enabled
        self.confirm_function = confirm_function
        self.post_confirm_assertions = post_confirm_assertions or []
        self.expected_ratchet_version = expected_ratchet_version
        self.fault_types = fault_types or ["power_loss"]
        self.max_points = max(0, int(max_points))
        if self.max_points > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "fault_sweep.confirm_cycle.max_points exceeds safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )


class ReadFaultConfig:
    """Configuration for read-time bit-flip fault injection."""

    __slots__ = ("target_regions", "bit_flip_count", "fault_probability", "seed")

    def __init__(
        self,
        target_regions: Optional[List[Tuple[int, int]]] = None,
        bit_flip_count: int = 1,
        fault_probability: float = 1.0,
        seed: int = 0,
    ) -> None:
        self.target_regions: List[Tuple[int, int]] = target_regions or []
        self.bit_flip_count = max(1, int(bit_flip_count))
        if not (0.0 <= fault_probability <= 1.0):
            raise ProfileError(
                "read_fault_config.fault_probability must be in [0.0, 1.0], got {}".format(
                    fault_probability
                )
            )
        self.fault_probability = float(fault_probability)
        self.seed = int(seed)
        for i, (start, end) in enumerate(self.target_regions):
            if end <= start:
                raise ProfileError(
                    "read_fault_config.target_regions[{}]: end (0x{:X}) must be > start (0x{:X})".format(
                        i, end, start
                    )
                )

class I2CFaultConfig:
    """Configuration for I2C bus fault injection via I2CFaultProxy.

    Models faults on the I2C bus between the CPU and an external device
    (e.g. a secure element used for signature verification during boot).
    The proxy peripheral intercepts I2C transactions and injects the
    configured fault at a specified transaction index.
    """

    __slots__ = (
        "peripheral_name",
        "target_address",
        "fault_types",
        "fault_at_transaction",
        "fault_seed",
    )

    def __init__(
        self,
        peripheral_name: str = "i2cProxy",
        target_address: int = 0,
        fault_types: Optional[List[str]] = None,
        fault_at_transaction: int = 0,
        fault_seed: int = 0,
    ) -> None:
        self.peripheral_name = peripheral_name
        if not (0 <= target_address <= 127):
            raise ProfileError(
                "i2c_fault_config.target_address must be 0-127 (7-bit I2C address), got {}".format(
                    target_address
                )
            )
        self.target_address = target_address
        valid_i2c = {"i2c_nack", "i2c_timeout", "i2c_bit_flip", "i2c_truncated", "i2c_wrong_address"}
        supplied = fault_types or ["i2c_nack"]
        for ft in supplied:
            if ft not in valid_i2c:
                raise ProfileError(
                    "i2c_fault_config.fault_types: unknown I2C fault type {!r}. "
                    "Valid: {}".format(ft, sorted(valid_i2c))
                )
        self.fault_types: List[str] = supplied
        self.fault_at_transaction = max(0, int(fault_at_transaction))
        self.fault_seed = int(fault_seed)


class InstructionSkipConfig:
    """Configuration for instruction-skip (voltage glitch) fault injection.

    Models a voltage glitch that causes the CPU to skip one or more
    instructions.  Each fault point is an instruction address; the sweep
    replaces the instruction at that address with a Thumb NOP (``0xBF00``)
    and verifies the system still boots correctly.

    ``target_addresses`` is a list of ``(start, end)`` address ranges to
    scan.  Fault points are instruction addresses, not arbitrary halfword
    offsets: the planner skips second halfwords of 32-bit Thumb
    instructions.  ``skip_count`` controls how many consecutive
    instructions to NOP (default 1).
    """

    __slots__ = ("target_addresses", "skip_count", "include_literal_pools", "severity_model")

    def __init__(
        self,
        target_addresses: Optional[List[Tuple[int, int]]] = None,
        skip_count: int = 1,
        include_literal_pools: bool = False,
        severity_model: str = "security",
    ) -> None:
        self.target_addresses: List[Tuple[int, int]] = target_addresses or []
        self.skip_count = max(1, int(skip_count))
        self.include_literal_pools = bool(include_literal_pools)
        self.severity_model = str(severity_model or "security").strip().lower() or "security"
        if self.severity_model not in {"security", "availability"}:
            raise ProfileError(
                "instruction_skip_config.severity_model: expected 'security' or 'availability'"
            )
        for i, (start, end) in enumerate(self.target_addresses):
            if end <= start:
                raise ProfileError(
                    "instruction_skip_config.target_addresses[{}]: "
                    "end (0x{:X}) must be > start (0x{:X})".format(i, end, start)
                )
            if start % 2 != 0:
                raise ProfileError(
                    "instruction_skip_config.target_addresses[{}]: "
                    "start (0x{:X}) must be halfword-aligned".format(i, start)
                )


class TimedBitCorruptionConfig:
    """Configuration for timed bit-corruption (TOCTOU) fault injection.

    Models time-of-check-to-time-of-use vulnerabilities where memory is
    re-read after validation.  Each pair specifies a trigger address
    (code point where the read-fault is armed) and a corrupt address
    (memory address that returns corrupted data on next read).
    """

    __slots__ = ("pairs",)

    def __init__(self, pairs=None):
        self.pairs = pairs or []
        for i, pair in enumerate(self.pairs):
            if "trigger" not in pair:
                raise ProfileError(
                    "timed_bit_corruption_config.pairs[{}]: missing 'trigger'".format(i)
                )
            if "corrupt_address" not in pair:
                raise ProfileError(
                    "timed_bit_corruption_config.pairs[{}]: missing 'corrupt_address'".format(i)
                )


class VerificationProbeConfig:
    """Configuration for deterministic verification-layer return probes."""

    __slots__ = (
        "symbol",
        "return_register",
        "return_register_index",
        "success_value",
        "label",
    )

    def __init__(
        self,
        *,
        symbol: str,
        return_register: str = "r0",
        return_register_index: int = 0,
        success_value: int = 0,
        label: Optional[str] = None,
    ) -> None:
        self.symbol = str(symbol).strip()
        if not self.symbol:
            raise ProfileError("verification_probes.symbol: expected non-empty string")
        self.return_register = str(return_register).strip().lower()
        self.return_register_index = int(return_register_index)
        self.success_value = int(success_value)
        self.label = str(label or self.symbol).strip()
        if not self.label:
            raise ProfileError("verification_probes.label: expected non-empty string")

    def to_runtime_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "return_register": self.return_register,
            "return_register_index": self.return_register_index,
            "success_value": self.success_value,
            "label": self.label,
        }


class FunctionReturnProbeConfig:
    """Capture return values from a function on every execute-mode run.

    This deliberately shares the runtime entry/return hook used by
    ``verification_probes``.  Verification probes remain instruction-skip
    telemetry; these probes are general return telemetry and are independent
    of the selected fault type.
    """

    __slots__ = (
        "symbol", "return_register", "return_register_index", "label", "capture"
    )

    def __init__(
        self,
        *,
        symbol: str,
        return_register: str = "r0",
        return_register_index: int = 0,
        label: Optional[str] = None,
        capture: str = "last",
    ) -> None:
        self.symbol = str(symbol).strip()
        if not self.symbol:
            raise ProfileError("fault_sweep.function_return_probes.symbol: expected non-empty string")
        self.return_register = str(return_register).strip().lower()
        self.return_register_index = int(return_register_index)
        self.label = str(label or self.symbol).strip()
        if not self.label:
            raise ProfileError("fault_sweep.function_return_probes.label: expected non-empty string")
        self.capture = str(capture or "last").strip().lower()
        if self.capture not in {"first", "last", "all"}:
            raise ProfileError(
                "fault_sweep.function_return_probes.capture: expected 'first', 'last', or 'all'"
            )

    def to_runtime_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "return_register": self.return_register,
            "return_register_index": self.return_register_index,
            "label": self.label,
            "capture": self.capture,
        }


class MetadataFaultConfig:
    """Configuration for faulting host-side metadata/setup writes before boot."""

    __slots__ = ("enabled", "fault_types")

    def __init__(
        self,
        enabled: bool = False,
        fault_types: Optional[List[str]] = None,
    ) -> None:
        self.enabled = enabled
        self.fault_types = fault_types or ["power_loss"]


class MetadataDeltaFieldConfig:
    """A single metadata field to track across boot cycles."""

    __slots__ = ("address", "name", "min_delta", "max_delta", "when")

    def __init__(
        self,
        address: int,
        name: str,
        min_delta: Optional[int] = None,
        max_delta: Optional[int] = None,
        when: Optional[str] = None,
    ) -> None:
        self.address = address
        self.name = name
        self.min_delta = min_delta
        self.max_delta = max_delta
        self.when = when


class MetadataDeltaConfig:
    """Configuration for tracking metadata field changes across fault recovery.

    After each fault point's recovery boot, metadata fields at specified NVM
    addresses are read and compared against their pre-fault values.  Delta
    assertions (min_delta, max_delta) detect boot count suppression, boot
    count exhaustion, and rollback floor regression.
    """

    __slots__ = ("enabled", "fields")

    def __init__(
        self,
        enabled: bool = False,
        fields: Optional[List["MetadataDeltaFieldConfig"]] = None,
    ) -> None:
        self.enabled = enabled
        self.fields = fields or []


class ComponentConfig:
    """Configuration for a single component in a multi-component profile.

    Each component represents an independently updatable firmware image
    (e.g. application MCU, radio coprocessor) with its own platform,
    bootloader, memory layout, images, and success criteria.
    """

    __slots__ = (
        "name",
        "platform",
        "bootloader_elf",
        "bootloader_entry",
        "memory",
        "images",
        "pre_boot_state",
        "setup_script",
        "extra_peripherals",
        "success_criteria",
        "fault_sweep",
        "flash_backend",
    )

    def __init__(
        self,
        name: str,
        platform: str,
        bootloader_elf: str,
        bootloader_entry: int,
        memory: "MemoryConfig",
        images: Dict[str, str],
        pre_boot_state: List["PreBootWrite"],
        setup_script: Optional[str] = None,
        extra_peripherals: Optional[List[str]] = None,
        success_criteria: Optional["SuccessCriteria"] = None,
        fault_sweep: Optional["FaultSweepConfig"] = None,
        flash_backend: Optional[str] = None,
    ) -> None:
        self.name = name
        self.platform = platform
        self.bootloader_elf = bootloader_elf
        self.bootloader_entry = bootloader_entry
        self.memory = memory
        self.images = images
        self.pre_boot_state = pre_boot_state
        self.setup_script = setup_script
        self.extra_peripherals = extra_peripherals or []
        self.success_criteria = success_criteria or SuccessCriteria()
        self.fault_sweep = fault_sweep
        self.flash_backend = flash_backend

    def to_profile_config(
        self,
        parent: "ProfileConfig",
    ) -> "ProfileConfig":
        """Convert this component into a standalone ProfileConfig.

        Inherits expect, invariants, and other top-level settings from
        the parent multi-component profile.
        """
        # Component-local execution inputs win when present.  Otherwise carry
        # the fully resolved parent contract (including a selected initial
        # state) into the standalone component campaign.
        has_resolved_initial_state = bool(
            getattr(parent, "resolved_initial_state_name", None)
        )
        component_pre_boot_state = (
            list(parent.pre_boot_state)
            if has_resolved_initial_state
            else (
                list(self.pre_boot_state)
                if self.pre_boot_state
                else list(parent.pre_boot_state)
            )
        )
        component_setup_script = (
            parent.setup_script
            if has_resolved_initial_state
            else (self.setup_script or parent.setup_script)
        )
        component_extra_peripherals = list(parent.extra_peripherals)
        for peripheral in self.extra_peripherals:
            if peripheral not in component_extra_peripherals:
                component_extra_peripherals.append(peripheral)
        component_bootloader_region = (
            getattr(self.memory, "bootloader_region", None)
            or parent.bootloader_region
        )

        resolved = ProfileConfig(
            schema_version=parent.schema_version,
            name="{}/{}".format(parent.name, self.name),
            description="Component '{}' of {}".format(self.name, parent.name),
            platform=self.platform,
            bootloader_elf=self.bootloader_elf,
            bootloader_entry=self.bootloader_entry,
            memory=self.memory,
            images=self.images,
            pre_boot_state=component_pre_boot_state,
            setup_script=component_setup_script,
            extra_peripherals=component_extra_peripherals,
            success_criteria=self.success_criteria,
            fault_sweep=self.fault_sweep or parent.fault_sweep,
            state_fuzzer=parent.state_fuzzer,
            expect=parent.expect,
            profile_path=parent.profile_path,
            scenario=parent.scenario,
            update_trigger=parent.update_trigger,
            update_sequence=parent.update_sequence,
            state_probe=parent.state_probe,
            semantic_assertions=parent.semantic_assertions,
            invariants=parent.invariants,
            invariant_providers=parent.invariant_providers,
            invariant_config=parent.invariant_config,
            flash_backend=self.flash_backend or parent.flash_backend,
            nvm_controller=parent.nvm_controller,
            otp_peripheral=parent.otp_peripheral,
            initial_states=[],
            metadata_fault_regions=parent.metadata_fault_regions,
            nvs_region=parent.nvs_region,
            security_policy=parent.security_policy,
            update_protocol=parent.update_protocol,
            authorization_review=getattr(parent, "authorization_review", None),
            bootloader_region=component_bootloader_region,
            success_criteria_overrides=parent.success_criteria_overrides,
            boot_register_pre_writes=parent.boot_register_pre_writes,
            boot_registers=parent.boot_registers,
            write_order_constraints=parent.write_order_constraints,
            fuzz_corpus=parent.fuzz_corpus,
            residual_image=parent.residual_image,
            firmware_elf=parent.firmware_elf,
            persistent_state_layout=getattr(parent, "persistent_state_layout", None),
            terminal_error_paths=getattr(parent, "terminal_error_paths", []),
            boundary_campaigns=getattr(parent, "boundary_campaigns", []),
            boundary_campaign=getattr(parent, "boundary_campaign", None),
            boundary_value=getattr(parent, "boundary_value", None),
            boundary_previous_value=getattr(parent, "boundary_previous_value", None),
        )
        resolved.auto_update_trigger = bool(
            getattr(parent, "auto_update_trigger", False)
        )
        resolved.image_load_addresses = dict(
            getattr(parent, "image_load_addresses", {}) or {}
        )
        resolved.resolved_initial_state_name = getattr(
            parent,
            "resolved_initial_state_name",
            None,
        )
        return resolved


class MultiComponentConfig:
    """Top-level configuration for multi-component fault injection."""

    __slots__ = ("components", "fault_matrix")

    def __init__(
        self,
        components: List[ComponentConfig],
        fault_matrix: str = "cross_product",
    ) -> None:
        self.components = components
        self.fault_matrix = fault_matrix
class NvsRegionConfig:
    """Configuration for an NVS (non-volatile storage) region on flash."""
    __slots__ = ("address", "size", "snapshot")

    def __init__(
        self,
        address: int,
        size: int,
        snapshot: Optional[str] = None,
    ) -> None:
        self.address = address
        self.size = size
        self.snapshot = snapshot


class ConfigCheck:
    """A single post-boot config check: verify memory at an address."""
    __slots__ = ("address", "expected", "nonzero", "range_min", "range_max", "mask", "expected_masked")
    def __init__(self, address: int, expected: Optional[int] = None, nonzero: bool = False,
                 range_min: Optional[int] = None, range_max: Optional[int] = None,
                 mask: Optional[int] = None, expected_masked: Optional[int] = None) -> None:
        self.address = address
        self.expected = expected
        self.nonzero = nonzero
        self.range_min = range_min
        self.range_max = range_max
        self.mask = mask
        self.expected_masked = expected_masked

    def evaluate(self, actual_value: int) -> bool:
        """Evaluate this check against an actual memory value."""
        if self.expected is not None and actual_value != self.expected:
            return False
        if self.nonzero and actual_value == 0:
            return False
        if self.range_min is not None and actual_value < self.range_min:
            return False
        if self.range_max is not None and actual_value > self.range_max:
            return False
        if self.mask is not None and self.expected_masked is not None:
            if (actual_value & self.mask) != (self.expected_masked & self.mask):
                return False
        return True

    def describe_failure(self, actual_value: int) -> str:
        """Return a human-readable failure description."""
        parts = ["config check at 0x{:X} failed:".format(self.address)]
        parts.append("actual=0x{:X}".format(actual_value))
        if self.expected is not None:
            parts.append("expected=0x{:X}".format(self.expected))
        if self.nonzero:
            parts.append("expected nonzero")
        if self.range_min is not None or self.range_max is not None:
            parts.append("expected range [{}, {}]".format(
                "0x{:X}".format(self.range_min) if self.range_min is not None else "-inf",
                "0x{:X}".format(self.range_max) if self.range_max is not None else "+inf"))
        if self.mask is not None:
            parts.append("mask=0x{:X} expected_masked=0x{:X}".format(
                self.mask, self.expected_masked if self.expected_masked is not None else 0))
        return " ".join(parts)


class NvsCorruptionConfig:
    """Configuration for NVS corruption fault injection."""
    __slots__ = (
        "enabled",
        "modes",
        "bit_flip_counts",
        "erase_fractions",
        "truncate_offsets",
        "seed",
    )

    def __init__(
        self,
        enabled: bool = False,
        modes: Optional[List[str]] = None,
        bit_flip_counts: Optional[List[int]] = None,
        erase_fractions: Optional[List[float]] = None,
        truncate_offsets: Optional[List[Optional[int]]] = None,
        seed: int = 0,
    ) -> None:
        self.enabled = enabled
        self.modes = modes or ["bit_flip", "partial_erase", "truncate"]
        self.bit_flip_counts = bit_flip_counts or [1, 4, 16]
        self.erase_fractions = erase_fractions or [0.25, 0.5, 1.0]
        self.truncate_offsets = truncate_offsets
        self.seed = seed

    def variant_specs(self) -> List[Dict[str, Any]]:
        """Expand configured NVS tuning values into runtime fault variants."""
        variants: List[Dict[str, Any]] = []
        for mode in self.modes:
            if mode == "bit_flip":
                variants.extend(
                    {"mode": mode, "bit_flip_count": int(count)}
                    for count in self.bit_flip_counts
                )
            elif mode == "partial_erase":
                variants.extend(
                    {"mode": mode, "erase_fraction": float(fraction)}
                    for fraction in self.erase_fractions
                )
            elif mode == "truncate":
                offsets = (
                    self.truncate_offsets
                    if self.truncate_offsets is not None
                    else [16]
                )
                variants.extend(
                    {"mode": mode, "truncate_offset": offset}
                    for offset in offsets
                )
            elif mode == "scramble":
                variants.append({"mode": mode})

        if len(variants) > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "fault_sweep.nvs_corruption expands beyond safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )
        return variants


class HeuristicConfig:
    """Configuration knobs for the heuristic write-trace classifier."""

    __slots__ = (
        "tier2_step",
        "tier3_step",
        "discontinuity_window",
        "target_points",
        "preserve_critical_tiers",
        "shard_count",
        "shard_index",
        "random_tail_budget",
        "critical_regions",
    )

    def __init__(
        self,
        tier2_step: int = 3,
        tier3_step: int = 100,
        discontinuity_window: int = 3,
        target_points: Optional[int] = None,
        preserve_critical_tiers: bool = True,
        shard_count: int = 1,
        shard_index: int = 0,
        random_tail_budget: int = 0,
        critical_regions: Optional[List[Tuple[int, int]]] = None,
    ) -> None:
        self.tier2_step = int(tier2_step)
        self.tier3_step = int(tier3_step)
        self.discontinuity_window = int(discontinuity_window)
        self.target_points = None if target_points is None else int(target_points)
        self.preserve_critical_tiers = bool(preserve_critical_tiers)
        self.shard_count = int(shard_count)
        self.shard_index = int(shard_index)
        self.random_tail_budget = int(random_tail_budget)
        self.critical_regions = critical_regions or []
        self._validate()

    def _validate(self) -> None:
        if self.tier2_step < 1:
            raise ValueError(
                "heuristic.tier2_step must be >= 1, got {}".format(self.tier2_step)
            )
        if self.tier3_step < 1:
            raise ValueError(
                "heuristic.tier3_step must be >= 1, got {}".format(self.tier3_step)
            )
        if self.discontinuity_window < 0:
            raise ValueError(
                "heuristic.discontinuity_window must be >= 0, got {}".format(
                    self.discontinuity_window
                )
            )
        if self.target_points is not None and self.target_points < 1:
            raise ValueError(
                "heuristic.target_points must be >= 1 or None, got {}".format(
                    self.target_points
                )
            )
        if self.shard_count < 1:
            raise ValueError(
                "heuristic.shard_count must be >= 1, got {}".format(self.shard_count)
            )
        if not (0 <= self.shard_index < self.shard_count):
            raise ValueError(
                "heuristic.shard_index must be in [0, shard_count), got {} with shard_count={}".format(
                    self.shard_index, self.shard_count
                )
            )
        if self.random_tail_budget < 0:
            raise ValueError(
                "heuristic.random_tail_budget must be >= 0, got {}".format(
                    self.random_tail_budget
                )
            )
        for idx, (start, end) in enumerate(self.critical_regions):
            if end <= start:
                raise ValueError(
                    "heuristic.critical_regions[{}]: end (0x{:X}) must be > start (0x{:X})".format(
                        idx, end, start
                    )
                )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "tier2_step": self.tier2_step,
            "tier3_step": self.tier3_step,
            "discontinuity_window": self.discontinuity_window,
            "target_points": self.target_points,
            "preserve_critical_tiers": self.preserve_critical_tiers,
            "shard_count": self.shard_count,
            "shard_index": self.shard_index,
            "random_tail_budget": self.random_tail_budget,
            "critical_regions": list(self.critical_regions),
        }


class WritebackConfig:
    """Configuration for the writeback-cache durability model."""

    __slots__ = ("buffer_capacity", "domains", "barriers", "erase_flushes_domain")

    def __init__(
        self,
        buffer_capacity: Any = "auto",
        domains: Any = "auto",
        barriers: Optional[List[Dict[str, Any]]] = None,
        erase_flushes_domain: bool = False,
    ) -> None:
        self.buffer_capacity = buffer_capacity
        self.domains = domains
        self.barriers: List[Dict[str, Any]] = barriers if barriers is not None else []
        self.erase_flushes_domain = bool(erase_flushes_domain)


class RcInjectionConfig:
    """Configuration for non-halting return-code injection faults.

    Values are kept in the representation used by the target CPU: the return
    value is always an unsigned 32-bit word, while ``return_register`` is the
    Arm register number to overwrite on return.
    """

    __slots__ = ("symbols", "return_value", "return_register", "require_applied")

    def __init__(
        self,
        symbols: Optional[List[str]] = None,
        return_value: int = -5,
        return_register: int = 0,
        require_applied: bool = True,
    ) -> None:
        raw_symbols = symbols if symbols is not None else ["flash_area_write"]
        if not isinstance(raw_symbols, list):
            raise ProfileError(
                "fault_sweep.rc_injection_config.symbols: expected non-empty list"
            )
        if any(not isinstance(symbol, str) for symbol in raw_symbols):
            raise ProfileError(
                "fault_sweep.rc_injection_config.symbols: expected ELF symbol names"
            )
        values = [symbol.strip() for symbol in raw_symbols]
        if not values or any(not symbol for symbol in values):
            raise ProfileError(
                "fault_sweep.rc_injection_config.symbols: expected a non-empty list"
            )
        if len(values) != len(set(values)):
            raise ProfileError(
                "fault_sweep.rc_injection_config.symbols: symbols must be unique"
            )
        self.symbols = values

        if type(return_value) is bool or not isinstance(return_value, int):
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_value: expected a 32-bit integer"
            )
        if return_value < -0x80000000 or return_value > 0xFFFFFFFF:
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_value: expected -2147483648..4294967295"
            )
        self.return_value = int(return_value) & 0xFFFFFFFF

        if type(return_register) is bool or not isinstance(return_register, int):
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_register: expected integer 0..15"
            )
        if return_register < 0 or return_register > 15:
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_register: expected integer 0..15"
            )
        self.return_register = int(return_register)
        if type(require_applied) is not bool:
            raise ProfileError(
                "fault_sweep.rc_injection_config.require_applied: expected boolean"
            )
        self.require_applied = require_applied

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbols": list(self.symbols),
            "return_value": self.return_value,
            "return_register": self.return_register,
            "require_applied": self.require_applied,
        }

    def to_runtime_dict(self) -> Dict[str, Any]:
        """Alias used by profile-to-runtime serializers."""
        return self.to_dict()


# Descriptive alias for callers that prefer the long configuration name.
ReturnCodeInjectionConfig = RcInjectionConfig


class FaultSweepConfig:
    __slots__ = (
        "mode",
        "max_writes",
        "max_otp_blows",
        "max_writes_cap",
        "max_step_limit",
        "run_duration",
        "calibration_time_slice",
        "phase1_time_slice",
        "phase2_time_slice",
        "phase2_wall_timeout_s",
        "fault_types",
        "evaluation_mode",
        "sweep_strategy",
        "sweep_hash_bypass_symbols",
        "progress_stall_timeout_s",
        "boot_cycles",
        "boot_cycle_hook",
        "vtor_settle_iters",
        "tracking_start_address",
        "expected_rollback_at_cycle",
        "phase2_fault",
        "hook_fault",
        "confirm_cycle",
        "multi_fault",
        "read_fault_config",
        "instruction_skip_config",
        "timed_bit_corruption_config",
        "verification_probes",
        "function_return_probes",
        "metadata_fault",
        "metadata_delta",
        "partial_staging",
        "nvs_corruption",
        "fault_distribution",
        "heuristic_config",
        "max_heuristic_points",
        "quick_use_heuristic",
        "boot_registers",
        "reset_mode",
        "write_order_constraints",
        "i2c_fault_config",
        "durability_model",
        "writeback",
        "rc_injection_config",
    )

    def __init__(
        self,
        mode: str = "runtime",
        max_writes: Any = "auto",
        max_otp_blows: Optional[int] = None,
        max_writes_cap: int = 100000,
        max_step_limit: int = 500000,
        run_duration: str = "0.5",
        calibration_time_slice: Optional[str] = None,
        phase1_time_slice: Optional[str] = None,
        phase2_time_slice: Optional[str] = None,
        fault_types: Optional[List[str]] = None,
        evaluation_mode: Optional[str] = None,
        sweep_strategy: str = "heuristic",
        sweep_hash_bypass_symbols: Optional[List[str]] = None,
        progress_stall_timeout_s: Optional[float] = None,
        boot_cycles: int = 1,
        boot_cycle_hook: Optional[str] = None,
        vtor_settle_iters: int = 0,
        tracking_start_address: int = 0,
        expected_rollback_at_cycle: Optional[int] = None,
        phase2_fault: Optional["Phase2FaultConfig"] = None,
        hook_fault: Optional["HookFaultConfig"] = None,
        confirm_cycle: Optional["ConfirmCycleConfig"] = None,
        multi_fault=None,
        read_fault_config: Optional["ReadFaultConfig"] = None,
        instruction_skip_config: Optional["InstructionSkipConfig"] = None,
        timed_bit_corruption_config: Optional["TimedBitCorruptionConfig"] = None,
        verification_probes: Optional[List["VerificationProbeConfig"]] = None,
        function_return_probes: Optional[List["FunctionReturnProbeConfig"]] = None,
        metadata_fault: Optional["MetadataFaultConfig"] = None,
        metadata_delta: Optional["MetadataDeltaConfig"] = None,
        partial_staging: Optional[Any] = None,
        nvs_corruption: Optional["NvsCorruptionConfig"] = None,
        fault_distribution: Optional["FaultDistributionConfig"] = None,
        heuristic_config: Optional["HeuristicConfig"] = None,
        max_heuristic_points: Optional[int] = 2000,
        quick_use_heuristic: bool = False,
        boot_registers: Optional[List[Dict[str, Any]]] = None,
        reset_mode: str = "warm",
        write_order_constraints: Optional[List[Dict[str, Any]]] = None,
        i2c_fault_config: Optional["I2CFaultConfig"] = None,
        durability_model: str = "direct",
        writeback: Optional["WritebackConfig"] = None,
        rc_injection_config: Optional["RcInjectionConfig"] = None,
        phase2_wall_timeout_s: Optional[float] = 30.0,
    ) -> None:
        self.mode = mode
        self.max_writes = max_writes
        if not (
            isinstance(max_writes, str)
            and max_writes.strip().lower() == "auto"
        ):
            try:
                fixed_writes = int(max_writes)
            except (TypeError, ValueError) as exc:
                raise ProfileError(
                    "fault_sweep.max_writes must be 'auto' or an integer"
                ) from exc
            if fixed_writes < 0 or fixed_writes > MAX_PROFILE_FAULT_POINTS:
                raise ProfileError(
                    "fault_sweep.max_writes must be between 0 and {}".format(
                        MAX_PROFILE_FAULT_POINTS
                    )
                )
        self.max_otp_blows = (
            None if max_otp_blows is None else int(max_otp_blows)
        )
        if self.max_otp_blows is not None and self.max_otp_blows < 1:
            raise ProfileError(
                "fault_sweep.max_otp_blows must be >= 1 when configured"
            )
        if (
            self.max_otp_blows is not None
            and self.max_otp_blows > MAX_PROFILE_FAULT_POINTS
        ):
            raise ProfileError(
                "fault_sweep.max_otp_blows exceeds safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )
        self.max_writes_cap = int(max_writes_cap)
        if self.max_writes_cap < 1 or self.max_writes_cap > MAX_PROFILE_FAULT_POINTS:
            raise ProfileError(
                "fault_sweep.max_writes_cap must be between 1 and {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )
        self.max_step_limit = int(max_step_limit)
        if self.max_step_limit < 1 or self.max_step_limit > MAX_PROFILE_STEP_LIMIT:
            raise ProfileError(
                "fault_sweep.max_step_limit must be between 1 and {}".format(
                    MAX_PROFILE_STEP_LIMIT
                )
            )
        self.run_duration = run_duration
        self.vtor_settle_iters = max(0, int(vtor_settle_iters))
        self.tracking_start_address = int(tracking_start_address)
        if self.tracking_start_address < 0 or self.tracking_start_address > 0xFFFFFFFF:
            raise ProfileError(
                "fault_sweep.tracking_start_address must be a 32-bit address"
            )
        self.calibration_time_slice = (
            str(calibration_time_slice).strip()
            if calibration_time_slice
            else None
        )
        self.phase1_time_slice = (
            str(phase1_time_slice).strip() if phase1_time_slice else None
        )
        self.phase2_time_slice = (
            str(phase2_time_slice).strip() if phase2_time_slice else None
        )
        if phase2_wall_timeout_s is None:
            phase2_wall_timeout_s = 30.0
        try:
            phase2_wall_timeout_s = float(phase2_wall_timeout_s)
        except (TypeError, ValueError) as exc:
            raise ProfileError(
                "fault_sweep.phase2_wall_timeout_s: expected positive number"
            ) from exc
        if not math.isfinite(phase2_wall_timeout_s) or phase2_wall_timeout_s <= 0:
            raise ProfileError(
                "fault_sweep.phase2_wall_timeout_s: expected positive number"
            )
        self.phase2_wall_timeout_s = phase2_wall_timeout_s
        self.fault_types = fault_types or ["power_loss"]
        self.evaluation_mode = evaluation_mode
        self.sweep_strategy = sweep_strategy
        self.sweep_hash_bypass_symbols = sweep_hash_bypass_symbols or []
        self.progress_stall_timeout_s = progress_stall_timeout_s
        self.boot_cycles = max(1, int(boot_cycles))
        if self.boot_cycles > MAX_BOOT_CYCLES:
            raise ProfileError(
                "fault_sweep.boot_cycles exceeds safety limit {}".format(
                    MAX_BOOT_CYCLES
                )
            )
        self.boot_cycle_hook = str(boot_cycle_hook).strip() if boot_cycle_hook else None
        self.expected_rollback_at_cycle = (
            None
            if expected_rollback_at_cycle is None
            else max(1, int(expected_rollback_at_cycle))
        )
        self.phase2_fault = phase2_fault or Phase2FaultConfig()
        self.hook_fault = hook_fault or HookFaultConfig()
        self.confirm_cycle = confirm_cycle or ConfirmCycleConfig()
        self.multi_fault = multi_fault or MultiFaultConfig()
        self.read_fault_config = read_fault_config
        self.instruction_skip_config = instruction_skip_config
        self.timed_bit_corruption_config = timed_bit_corruption_config
        self.verification_probes = verification_probes or []
        self.function_return_probes = function_return_probes or []
        self.metadata_fault = metadata_fault or MetadataFaultConfig()
        self.metadata_delta = metadata_delta or MetadataDeltaConfig()
        self.partial_staging = partial_staging
        self.nvs_corruption = nvs_corruption or NvsCorruptionConfig()
        self.fault_distribution = fault_distribution or FaultDistributionConfig()
        self.heuristic_config = heuristic_config
        self.max_heuristic_points = (
            None if max_heuristic_points is None else int(max_heuristic_points)
        )
        self.quick_use_heuristic = bool(quick_use_heuristic)
        if self.max_heuristic_points is not None and self.max_heuristic_points < 1:
            raise ValueError(
                "fault_sweep.max_heuristic_points must be >= 1 or None, got {}".format(
                    self.max_heuristic_points
                )
            )
        if (
            self.max_heuristic_points is not None
            and self.max_heuristic_points > MAX_PROFILE_FAULT_POINTS
        ):
            raise ProfileError(
                "fault_sweep.max_heuristic_points exceeds safety limit {}".format(
                    MAX_PROFILE_FAULT_POINTS
                )
            )
        self.boot_registers = boot_registers or []
        self.reset_mode = reset_mode if reset_mode in ("warm", "cold") else "warm"
        self.write_order_constraints = write_order_constraints or []
        self.i2c_fault_config = i2c_fault_config
        self.durability_model = durability_model
        self.writeback = writeback
        self.rc_injection_config = rc_injection_config or RcInjectionConfig()


class StateFuzzerConfig:
    __slots__ = ("enabled", "metadata_model", "iterations", "seed")

    def __init__(
        self,
        enabled: bool = False,
        metadata_model: Any = "ab_replica",
        iterations: int = 100,
        seed: int = 0,
    ) -> None:
        self.enabled = bool(enabled)
        self.metadata_model = metadata_model
        self.iterations = max(1, int(iterations))
        if self.iterations > MAX_STATE_FUZZ_ITERATIONS:
            raise ProfileError(
                "state_fuzzer.iterations exceeds safety limit {}".format(
                    MAX_STATE_FUZZ_ITERATIONS
                )
            )
        self.seed = int(seed)


class SecurityPolicyConfig:
    """Security policy declarations for adversarial fault scenarios.

    Models security-relevant properties from the Uptane/SUIT threat model
    at the flash level: rollback protection and TOCTOU race conditions.
    """

    __slots__ = ("anti_rollback", "minimum_version", "toctou_protection")

    def __init__(
        self,
        anti_rollback: bool = False,
        minimum_version: Optional[int] = None,
        toctou_protection: bool = False,
    ) -> None:
        self.anti_rollback = anti_rollback
        self.minimum_version = minimum_version
        self.toctou_protection = toctou_protection


class StateProbeConfig:
    __slots__ = ("script", "format", "contract_version", "required_paths")

    def __init__(
        self,
        script: str,
        format: str = "tardigrade.semantic-state/v1",
        contract_version: int = 1,
        required_paths: Optional[List[str]] = None,
    ) -> None:
        self.script = script
        self.format = format
        self.contract_version = max(1, int(contract_version))
        self.required_paths = required_paths or []


class ExpectConfig:
    __slots__ = (
        "should_find_issues",
        "control_outcome",
        "allow_semantic_only_issues",
        "allow_control_only_issues",
        "required_issue_reasons",
        "ignored_issue_fault_types",
    )

    def __init__(
        self,
        should_find_issues: bool = False,
        control_outcome: str = "success",
        allow_semantic_only_issues: bool = False,
        allow_control_only_issues: bool = False,
        required_issue_reasons: Optional[List[str]] = None,
        ignored_issue_fault_types: Optional[List[str]] = None,
    ) -> None:
        for field_name, value in (
            ("should_find_issues", should_find_issues),
            ("allow_semantic_only_issues", allow_semantic_only_issues),
            ("allow_control_only_issues", allow_control_only_issues),
        ):
            if type(value) is not bool:
                raise ProfileError(
                    "expect.{}: expected boolean, got {}".format(
                        field_name, type(value).__name__
                    )
                )
        self.should_find_issues = should_find_issues
        self.control_outcome = control_outcome
        self.allow_semantic_only_issues = allow_semantic_only_issues
        self.allow_control_only_issues = allow_control_only_issues
        self.required_issue_reasons = required_issue_reasons or []
        self.ignored_issue_fault_types = ignored_issue_fault_types or []


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


class UpdatePhase:
    """One phase in a multi-update runtime sequence."""

    __slots__ = (
        "name",
        "description",
        "images",
        "start_images",
        "setup_script",
        "pre_boot_state",
        "success_criteria",
        "boot_cycles",
        "boot_cycle_hook",
        "expected_rollback_at_cycle",
        "fault_injection",
        "fault_types",
    )

    def __init__(
        self,
        name: str,
        description: str = "",
        images: Optional[Dict[str, str]] = None,
        start_images: Optional[Dict[str, str]] = None,
        setup_script: Optional[str] = None,
        pre_boot_state: Optional[List["PreBootWrite"]] = None,
        success_criteria: Optional["SuccessCriteria"] = None,
        boot_cycles: int = 1,
        boot_cycle_hook: Optional[str] = None,
        expected_rollback_at_cycle: Optional[int] = None,
        fault_injection: bool = False,
        fault_types: Optional[List[str]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.images = images or {}
        self.start_images = start_images or {}
        self.setup_script = str(setup_script).strip() if setup_script else None
        self.pre_boot_state = pre_boot_state or []
        self.success_criteria = success_criteria or SuccessCriteria()
        self.boot_cycles = max(1, int(boot_cycles))
        if self.boot_cycles > MAX_BOOT_CYCLES:
            raise ProfileError(
                "update_sequence.boot_cycles exceeds safety limit {}".format(
                    MAX_BOOT_CYCLES
                )
            )
        self.boot_cycle_hook = str(boot_cycle_hook).strip() if boot_cycle_hook else None
        self.expected_rollback_at_cycle = (
            None
            if expected_rollback_at_cycle is None
            else max(1, int(expected_rollback_at_cycle))
        )
        self.fault_injection = bool(fault_injection)
        self.fault_types = fault_types or ["power_loss"]


class InitialStateConfig:
    """A named initial-state seed for sweep matrix expansion."""
    __slots__ = ("name", "description", "pre_boot_state", "setup_script",
                 "update_trigger", "expect_overrides", "boundary_campaign",
                 "boundary_value", "boundary_previous_value")

    def __init__(self, name: str, description: str = "",
                 pre_boot_state: Optional[List[PreBootWrite]] = None,
                 setup_script: Optional[str] = None,
                 update_trigger: Optional[UpdateTrigger] = None,
                 expect_overrides: Optional[Dict[str, Any]] = None,
                 boundary_campaign: Optional[BoundaryCampaign] = None,
                 boundary_value: Optional[int] = None,
                 boundary_previous_value: Optional[int] = None) -> None:
        self.name = name
        self.description = description
        self.pre_boot_state = pre_boot_state
        self.setup_script = setup_script
        self.update_trigger = update_trigger
        self.expect_overrides = expect_overrides or {}
        self.boundary_campaign = boundary_campaign
        self.boundary_value = boundary_value
        self.boundary_previous_value = boundary_previous_value


class BootRegisterPreWrite:
    """An address/value pair to write before capturing boot registers."""
    __slots__ = ("address", "value")

    def __init__(self, address: int, value: int) -> None:
        self.address = address
        self.value = value


class BootRegisterDef:
    """A register to capture at boot-detection time."""
    __slots__ = ("address", "name")

    def __init__(self, address: int, name: str) -> None:
        self.address = address
        self.name = name


class WriteOrderConstraint:
    """Assert that writes to one region precede writes to another."""
    __slots__ = ("first_start", "first_size", "then_start", "then_size", "label", "bidirectional")

    def __init__(
        self,
        first_start: int,
        first_size: int,
        then_start: int,
        then_size: int,
        label: str = "",
        bidirectional: bool = False,
    ) -> None:
        self.first_start = first_start
        self.first_size = first_size
        self.then_start = then_start
        self.then_size = then_size
        self.label = label
        self.bidirectional = bidirectional


# MCUboot trailer magic: 4 words written at (slot_end - 16).
MCUBOOT_GOOD_MAGIC = [0xF395C277, 0x7FEFD260, 0x0F505235, 0x8079B62C]
MCUBOOT_ALIGNED_MAGIC_SUFFIX = bytes(
    [0x2D, 0xE1, 0x5D, 0x29, 0x41, 0x0B, 0x8D, 0x77, 0x67, 0x9C, 0x11, 0x0F, 0x1F, 0x8A]
)


def _mcuboot_good_magic_words(max_align: int) -> List[int]:
    """Return the MCUboot GOOD magic words for a given BOOT_MAX_ALIGN."""
    if max_align == 8:
        return list(MCUBOOT_GOOD_MAGIC)
    if max_align <= 0 or max_align > 0xFFFF:
        raise ProfileError(
            "update_trigger.max_align must fit in a 16-bit MCUboot trailer magic field"
        )
    magic_bytes = struct.pack("<H", max_align) + MCUBOOT_ALIGNED_MAGIC_SUFFIX
    return list(struct.unpack("<4I", magic_bytes))


def _align_down(value: int, align: int) -> int:
    if align <= 0:
        raise ProfileError("alignment must be > 0")
    return value - (value % align)


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
        extra_peripherals: Optional[List[str]],
        success_criteria: SuccessCriteria,
        fault_sweep: FaultSweepConfig,
        state_fuzzer: StateFuzzerConfig,
        expect: ExpectConfig,
        profile_path: Optional[Path] = None,
        scenario: str = "runtime",
        update_trigger: Optional[UpdateTrigger] = None,
        update_sequence: Optional[List["UpdatePhase"]] = None,
        state_probe: Optional[StateProbeConfig] = None,
        semantic_assertions: Optional[Dict[str, Dict[str, Any]]] = None,
        invariants: Optional[List[str]] = None,
        invariant_providers: Optional[List[str]] = None,
        invariant_config: Optional[Dict[str, Any]] = None,
        flash_backend: Optional[str] = None,
        nvm_controller: Optional[str] = None,
        otp_peripheral: Optional[str] = None,
        initial_states: Optional[List["InitialStateConfig"]] = None,
        metadata_fault_regions: Optional[List[MetadataFaultRegion]] = None,
        multi_component: Optional["MultiComponentConfig"] = None,
        nvs_region: Optional[NvsRegionConfig] = None,
        security_policy: Optional["SecurityPolicyConfig"] = None,
        update_protocol: Optional[UpdateProtocolModel] = None,
        authorization_review: Optional[AuthorizationReviewModel] = None,
        bootloader_region: Optional[BootloaderRegionConfig] = None,
        success_criteria_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
        boot_register_pre_writes: Optional[List[BootRegisterPreWrite]] = None,
        boot_registers: Optional[List[BootRegisterDef]] = None,
        write_order_constraints: Optional[List[WriteOrderConstraint]] = None,
        fuzz_corpus: Optional[str] = None,

        residual_image: Optional["ResidualImageConfig"] = None,

        firmware_elf: Optional[str] = None,
        persistent_state_layout: Optional[PersistentStateLayout] = None,
        terminal_error_paths: Optional[List[TerminalErrorPathConfig]] = None,
        boundary_campaigns: Optional[List[BoundaryCampaign]] = None,
        boundary_campaign: Optional[BoundaryCampaign] = None,
        boundary_value: Optional[int] = None,
        boundary_previous_value: Optional[int] = None,

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
        self.extra_peripherals = extra_peripherals or []
        self.success_criteria = success_criteria
        self.fault_sweep = fault_sweep
        self.state_fuzzer = state_fuzzer
        self.expect = expect
        self.profile_path = profile_path
        self.scenario = scenario
        self.update_trigger = update_trigger
        self.auto_update_trigger = False
        self.resolved_initial_state_name: Optional[str] = None
        self.image_load_addresses: Dict[str, int] = {}
        self.update_sequence: List[UpdatePhase] = update_sequence or []
        self.state_probe = state_probe
        self.semantic_assertions = semantic_assertions or {}
        self.invariants = invariants or []
        self.invariant_providers = invariant_providers or []
        self.invariant_config = invariant_config or {}
        self.flash_backend = flash_backend
        self.nvm_controller = nvm_controller
        self.otp_peripheral = otp_peripheral
        self.security_policy = security_policy or SecurityPolicyConfig()
        self.update_protocol = update_protocol
        self.authorization_review = authorization_review
        self.initial_states: List[InitialStateConfig] = initial_states or []
        self.metadata_fault_regions: List[MetadataFaultRegion] = metadata_fault_regions or []
        self.multi_component: Optional[MultiComponentConfig] = multi_component
        self.nvs_region = nvs_region
        memory_bootloader_region = getattr(memory, "bootloader_region", None)
        if bootloader_region is not None and memory_bootloader_region is not None:
            top_level_range = (bootloader_region.base, bootloader_region.size)
            memory_range = (
                memory_bootloader_region.base,
                memory_bootloader_region.size,
            )
            if top_level_range != memory_range:
                raise ProfileError(
                    "bootloader_region conflicts with memory.bootloader_region: "
                    "top-level is base=0x{:X}, size=0x{:X}; memory is "
                    "base=0x{:X}, size=0x{:X}".format(
                        bootloader_region.base,
                        bootloader_region.size,
                        memory_bootloader_region.base,
                        memory_bootloader_region.size,
                    )
                )
        canonical_bootloader_region = bootloader_region or memory_bootloader_region
        self.bootloader_region: Optional[BootloaderRegionConfig] = (
            canonical_bootloader_region
        )
        # ``memory.bootloader_region`` was the original spelling.  Preserve it
        # as a compatibility alias while all production consumers use the
        # canonical top-level property.
        self.memory.bootloader_region = canonical_bootloader_region
        self.success_criteria_overrides: Dict[str, Dict[str, Any]] = success_criteria_overrides or {}
        self.boot_register_pre_writes: List[BootRegisterPreWrite] = boot_register_pre_writes or []
        self.boot_registers: List[BootRegisterDef] = boot_registers or []
        self.write_order_constraints: List[WriteOrderConstraint] = write_order_constraints or []
        self.fuzz_corpus: Optional[str] = fuzz_corpus

        self.residual_image: Optional[ResidualImageConfig] = residual_image

        self.firmware_elf: Optional[str] = firmware_elf
        self.persistent_state_layout: Optional[PersistentStateLayout] = persistent_state_layout
        self.terminal_error_paths: List[TerminalErrorPathConfig] = terminal_error_paths or []
        self.boundary_campaigns: List[BoundaryCampaign] = boundary_campaigns or []
        self.boundary_campaign = boundary_campaign
        self.boundary_value = boundary_value
        self.boundary_previous_value = boundary_previous_value


    @property
    def is_multi_component(self) -> bool:
        """Return True if this profile defines a multi-component scenario."""
        return (
            self.multi_component is not None
            and len(self.multi_component.components) >= 2
        )

    @property
    def has_update_sequence(self) -> bool:
        """Return True if this profile defines multi-phase runtime updates."""
        return bool(self.update_sequence)

    @property
    def faulted_update_phase(self) -> Optional["UpdatePhase"]:
        """Return the phase that injects runtime faults, if configured."""
        for phase in self.update_sequence:
            if phase.fault_injection:
                return phase
        return None

    def component_profiles(self) -> List["ProfileConfig"]:
        """Return per-component ProfileConfig instances.

        Each component is converted into a standalone ProfileConfig that
        can be individually calibrated and swept.  Returns an empty list
        for single-component profiles.
        """
        if not self.is_multi_component:
            return []
        return [
            comp.to_profile_config(self)
            for comp in self.multi_component.components
        ]

    def resolve_initial_state(self, state: "InitialStateConfig") -> "ProfileConfig":
        """Return a new ProfileConfig with the given initial state applied."""
        new_pre_boot = (list(state.pre_boot_state) if state.pre_boot_state is not None
                        else list(self.pre_boot_state))
        new_setup = state.setup_script if state.setup_script is not None else self.setup_script
        new_trigger = state.update_trigger if state.update_trigger is not None else self.update_trigger
        new_expect = self.expect
        if state.expect_overrides:
            eo = state.expect_overrides
            new_expect = ExpectConfig(
                should_find_issues=eo.get("should_find_issues", self.expect.should_find_issues),
                control_outcome=eo.get("control_outcome", self.expect.control_outcome),
                allow_semantic_only_issues=eo.get("allow_semantic_only_issues", self.expect.allow_semantic_only_issues),
                allow_control_only_issues=eo.get("allow_control_only_issues", self.expect.allow_control_only_issues),
                required_issue_reasons=eo.get("required_issue_reasons", self.expect.required_issue_reasons),
                ignored_issue_fault_types=eo.get(
                    "ignored_issue_fault_types",
                    self.expect.ignored_issue_fault_types,
                ),
            )
        resolved = ProfileConfig(
            schema_version=self.schema_version, name="{}/{}".format(self.name, state.name),
            description=state.description or self.description, platform=self.platform,
            bootloader_elf=self.bootloader_elf, bootloader_entry=self.bootloader_entry,
            memory=self.memory, images=self.images, pre_boot_state=new_pre_boot,
            setup_script=new_setup, extra_peripherals=self.extra_peripherals,
            success_criteria=self.success_criteria, fault_sweep=self.fault_sweep,
            state_fuzzer=self.state_fuzzer, expect=new_expect, profile_path=self.profile_path,
            scenario=self.scenario, update_trigger=new_trigger, update_sequence=self.update_sequence,
            state_probe=self.state_probe,
            semantic_assertions=self.semantic_assertions,
            invariants=self.invariants, invariant_providers=self.invariant_providers,
            invariant_config=self.invariant_config,
            flash_backend=self.flash_backend,
            nvm_controller=self.nvm_controller,
            otp_peripheral=self.otp_peripheral,
            initial_states=[],
            metadata_fault_regions=self.metadata_fault_regions,
            multi_component=self.multi_component,
            nvs_region=self.nvs_region,
            security_policy=self.security_policy,
            update_protocol=self.update_protocol,
            authorization_review=self.authorization_review,
            bootloader_region=self.bootloader_region,
            success_criteria_overrides=self.success_criteria_overrides,
            boot_register_pre_writes=self.boot_register_pre_writes,
            boot_registers=self.boot_registers,
            write_order_constraints=self.write_order_constraints,
            fuzz_corpus=self.fuzz_corpus,

            residual_image=self.residual_image,

            firmware_elf=self.firmware_elf,
            persistent_state_layout=self.persistent_state_layout,
            terminal_error_paths=self.terminal_error_paths,
            boundary_campaigns=self.boundary_campaigns,
            boundary_campaign=state.boundary_campaign or getattr(self, "boundary_campaign", None),
            boundary_value=(state.boundary_value if state.boundary_value is not None
                            else getattr(self, "boundary_value", None)),
            boundary_previous_value=(
                state.boundary_previous_value
                if state.boundary_previous_value is not None
                else getattr(self, "boundary_previous_value", None)
            ),

        )
        if state.update_trigger is not None and state.pre_boot_state is None:
            resolved.pre_boot_state = resolved.expand_update_trigger()
        resolved.auto_update_trigger = bool(getattr(self, "auto_update_trigger", False))
        resolved.resolved_initial_state_name = state.name
        resolved.image_load_addresses = dict(
            getattr(self, "image_load_addresses", {}) or {}
        )
        return resolved

    def effective_image_load_addresses(self) -> Dict[str, int]:
        """Return the runtime image load base for each declared slot."""
        overrides = dict(getattr(self, "image_load_addresses", {}) or {})
        return {
            slot_name: int(overrides.get(slot_name, slot_cfg.base))
            for slot_name, slot_cfg in self.memory.slots.items()
        }

    def resolve_path(self, repo_root: Path, value: str) -> str:
        """Resolve a path relative to the repo root."""
        p = Path(value)
        if p.is_absolute():
            return str(p)
        # Use absolute() not resolve() to preserve symlinks — resolve()
        # follows symlinks, breaking paths through /tmp symlinks used to
        # avoid space-in-path issues on "External SSD" volumes.
        result = repo_root / p
        if not result.is_absolute():
            result = Path.cwd() / result
        return str(result)

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

    def _compute_image_digests(
        self,
        repo_root: Path,
        images: Dict[str, str],
    ) -> Dict[str, str]:
        import hashlib

        exec_slot = self.memory.slots.get("exec")
        page_size = 4096
        data_size = None
        if exec_slot is not None and exec_slot.size > page_size:
            data_size = exec_slot.size - page_size
        pad_byte = 0x00 if str(self.flash_backend or "").strip().lower() == "mram" else 0xFF

        digests: Dict[str, str] = {}
        for img_name, img_path in images.items():
            resolved = self.resolve_path(repo_root, img_path)
            with open(resolved, "rb") as fh:
                raw = fh.read()
            if data_size is not None:
                if len(raw) >= data_size:
                    raw = raw[:data_size]
                else:
                    raw = raw + (bytes([pad_byte]) * (data_size - len(raw)))
            digests[img_name] = hashlib.sha256(raw).hexdigest()
        return digests

    def _success_criteria_runtime_dict(
        self,
        repo_root: Path,
        criteria: "SuccessCriteria",
        images: Dict[str, str],
    ) -> Dict[str, Any]:
        digests = self._compute_image_digests(repo_root, images) if criteria.image_hash else {}
        expected_exec_sha256 = ""
        expected_name = criteria.expected_image or "staging"
        if expected_name in digests:
            expected_exec_sha256 = digests[expected_name]

        return {
            "vtor_in_slot": criteria.vtor_in_slot or "",
            "vector_table_offset": int(criteria.vector_table_offset),
            "pc_in_slot": criteria.pc_in_slot or "",
            "marker_address": criteria.marker_address,
            "marker_value": criteria.marker_value,
            "image_hash": bool(criteria.image_hash),
            "expected_image": criteria.expected_image or "",
            "image_hash_slot": criteria.image_hash_slot or "",
            "image_exec_sha256": digests.get("exec", ""),
            "image_staging_sha256": digests.get("staging", ""),
            "expected_exec_sha256": expected_exec_sha256,
            "otadata_expect": criteria.otadata_expect,
            "otadata_expect_scope": criteria.otadata_expect_scope or "always",
            "success_checks": self._success_checks_runtime_dict(criteria),
        }

    def _success_checks_runtime_dict(
        self,
        criteria: "SuccessCriteria",
    ) -> Dict[str, Any]:
        """Return the versioned structured post-boot check contract."""
        return {
            "contract_version": 1,
            "memory_checks": [
                {
                    "address": check.address,
                    "expected_value": check.expected_value,
                    "mask": check.mask,
                    "op": check.op,
                }
                for check in criteria.memory_checks
            ],
            "config_checks": [
                {
                    "address": check.address,
                    "expected": check.expected,
                    "nonzero": check.nonzero,
                    "range_min": check.range_min,
                    "range_max": check.range_max,
                    "mask": check.mask,
                    "expected_masked": check.expected_masked,
                }
                for check in criteria.config_checks
            ],
            "bootloader_integrity": bool(criteria.bootloader_integrity),
            "bootloader_region": (
                {
                    "base": self.bootloader_region.base,
                    "size": self.bootloader_region.size,
                }
                if self.bootloader_region is not None
                else None
            ),
        }

    def update_sequence_runtime_payload(self, repo_root: Path) -> Optional[Dict[str, Any]]:
        """Serialize update_sequence for the Renode runtime script."""
        if not self.update_sequence:
            return None

        phases_payload: List[Dict[str, Any]] = []
        fault_phase_index = -1
        for idx, phase in enumerate(self.update_sequence):
            if phase.fault_injection:
                fault_phase_index = idx
            resolved_delta = {
                name: self.resolve_path(repo_root, path)
                for name, path in phase.images.items()
            }
            resolved_start = {
                name: self.resolve_path(repo_root, path)
                for name, path in phase.start_images.items()
            }
            phases_payload.append(
                {
                    "index": idx,
                    "name": phase.name,
                    "description": phase.description,
                    "images": resolved_delta,
                    "start_images": resolved_start,
                    "setup_script": (
                        self.resolve_path(repo_root, phase.setup_script)
                        if phase.setup_script
                        else ""
                    ),
                    "pre_boot_state": [
                        {"address": int(write.address), "u32": int(write.u32)}
                        for write in phase.pre_boot_state
                    ],
                    "success_criteria": self._success_criteria_runtime_dict(
                        repo_root,
                        phase.success_criteria,
                        phase.start_images,
                    ),
                    "boot_cycles": int(phase.boot_cycles),
                    "boot_cycle_hook": (
                        self.resolve_path(repo_root, phase.boot_cycle_hook)
                        if phase.boot_cycle_hook
                        else ""
                    ),
                    "expected_rollback_at_cycle": phase.expected_rollback_at_cycle,
                    "fault_injection": bool(phase.fault_injection),
                    "fault_types": list(phase.fault_types),
                }
            )

        return {
            "fault_phase_index": fault_phase_index,
            "phases": phases_payload,
        }

    def generate_update_sequence_file(self, repo_root: Path) -> Optional[str]:
        """Write the runtime update_sequence payload to a temp JSON file."""
        payload = self.update_sequence_runtime_payload(repo_root)
        if payload is None:
            return None
        tmp = tempfile.NamedTemporaryFile(
            prefix="update_sequence_", suffix=".json", delete=False
        )
        tmp.write(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
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
            align = _parse_int(trigger.fields.get("max_align", 8), "update_trigger.max_align")
            magic_base = slot_end - 16
            image_ok_addr = _align_down(magic_base - align, align)
            copy_done_addr = image_ok_addr - align
            swap_info_addr = copy_done_addr - align
            unprotected_tlv_sizes_addr = swap_info_addr - align
            swap_size_addr = swap_info_addr - align
            if trigger.fields.get("unprotected_tlv_sizes") is not None:
                # Swap-offset stores unprotected TLV sizes between swap_info and
                # swap_size in the trailer metadata area.
                swap_size_addr = unprotected_tlv_sizes_addr - align
            writes: List[PreBootWrite] = []
            for i, val in enumerate(_mcuboot_good_magic_words(align)):
                writes.append(PreBootWrite(address=magic_base + i * 4, u32=val))
            if trigger.fields.get("image_ok") is not None:
                writes.append(PreBootWrite(
                    address=image_ok_addr,
                    u32=_parse_int(trigger.fields["image_ok"], "update_trigger.image_ok"),
                ))
            # Optional copy_done field for revert / resume scenarios.
            if trigger.fields.get("copy_done") is not None:
                writes.append(PreBootWrite(
                    address=copy_done_addr,
                    u32=_parse_int(trigger.fields["copy_done"], "update_trigger.copy_done"),
                ))
            if trigger.fields.get("swap_info") is not None and trigger.fields.get("swap_type") is not None:
                raise ProfileError(
                    "update_trigger may specify either swap_info or swap_type, not both"
                )
            swap_info = None
            if trigger.fields.get("swap_info") is not None:
                swap_info = _parse_int(trigger.fields["swap_info"], "update_trigger.swap_info")
            elif trigger.fields.get("swap_type") is not None:
                swap_type = _parse_int(trigger.fields["swap_type"], "update_trigger.swap_type")
                image_num = _parse_int(trigger.fields.get("image_num", 0), "update_trigger.image_num")
                if swap_type < 0 or swap_type > 0xF:
                    raise ProfileError("update_trigger.swap_type must fit in 4 bits")
                if image_num < 0 or image_num > 0xF:
                    raise ProfileError("update_trigger.image_num must fit in 4 bits")
                swap_info = (image_num << 4) | swap_type
            if swap_info is not None:
                writes.append(PreBootWrite(address=swap_info_addr, u32=swap_info))
            if trigger.fields.get("unprotected_tlv_sizes") is not None:
                writes.append(PreBootWrite(
                    address=unprotected_tlv_sizes_addr,
                    u32=_parse_int(
                        trigger.fields["unprotected_tlv_sizes"],
                        "update_trigger.unprotected_tlv_sizes",
                    ),
                ))
            if trigger.fields.get("swap_size") is not None:
                writes.append(PreBootWrite(
                    address=swap_size_addr,
                    u32=_parse_int(trigger.fields["swap_size"], "update_trigger.swap_size"),
                ))
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
            "VTOR_SETTLE_ITERS:{}".format(fs.vtor_settle_iters),
            "TRACKING_START_ADDRESS:0x{:08X}".format(fs.tracking_start_address),
            "RUNTIME_MODE:true",
        ]
        if fs.calibration_time_slice:
            vars_list.append(
                "CALIBRATION_TIME_SLICE:{}".format(fs.calibration_time_slice)
            )
        if fs.phase1_time_slice:
            vars_list.append("PHASE1_TIME_SLICE:{}".format(fs.phase1_time_slice))
        if fs.phase2_time_slice:
            vars_list.append("PHASE2_TIME_SLICE:{}".format(fs.phase2_time_slice))
        vars_list.append(
            "PHASE2_WALL_TIMEOUT_S:{}".format(fs.phase2_wall_timeout_s)
        )
        if fs.boot_cycle_hook:
            vars_list.append(
                "BOOT_CYCLE_HOOK:{}".format(
                    self.resolve_path(repo_root, fs.boot_cycle_hook)
                )
            )
        if fs.expected_rollback_at_cycle is not None:
            vars_list.append(
                "EXPECTED_ROLLBACK_AT_CYCLE:{}".format(
                    fs.expected_rollback_at_cycle
                )
            )
        if fs.phase2_fault.enabled:
            vars_list.append("PHASE2_FAULT_ENABLED:true")
            if fs.phase2_fault.max_points > 0:
                vars_list.append(
                    "PHASE2_FAULT_MAX_POINTS:{}".format(fs.phase2_fault.max_points)
                )

        if fs.confirm_cycle.enabled:
            vars_list.append("CONFIRM_CYCLE_ENABLED:true")
            if fs.confirm_cycle.confirm_function:
                vars_list.append(
                    "CONFIRM_CYCLE_FUNCTION:{}".format(
                        fs.confirm_cycle.confirm_function
                    )
                )
            if fs.confirm_cycle.max_points > 0:
                vars_list.append(
                    "CONFIRM_CYCLE_MAX_POINTS:{}".format(
                        fs.confirm_cycle.max_points
                    )
                )
            if fs.confirm_cycle.post_confirm_assertions:
                import json as _json

                vars_list.append(
                    "CONFIRM_CYCLE_ASSERTIONS:{}".format(
                        _json.dumps(fs.confirm_cycle.post_confirm_assertions)
                    )
                )
            if fs.confirm_cycle.expected_ratchet_version is not None:
                vars_list.append(
                    "CONFIRM_CYCLE_RATCHET_VERSION:{}".format(
                        fs.confirm_cycle.expected_ratchet_version
                    )
                )
            if self.firmware_elf:
                vars_list.append(
                    "FIRMWARE_ELF:{}".format(
                        self.resolve_path(repo_root, self.firmware_elf)
                    )
                )

        if self.boot_register_pre_writes:
            pw_parts = []
            for pw in self.boot_register_pre_writes:
                pw_parts.append("0x{:08X}=0x{:08X}".format(pw.address, pw.value))
            vars_list.append("BOOT_REGISTER_PRE_WRITES:{}".format(",".join(pw_parts)))
        if self.boot_registers:
            parts = []
            for reg in self.boot_registers:
                parts.append("0x{:08X}={}".format(reg.address, reg.name))
            vars_list.append("BOOT_REGISTERS:{}".format(",".join(parts)))
        if fs.reset_mode != "warm":
            vars_list.append("RESET_MODE:{}".format(fs.reset_mode))

        # Slot info.
        for slot_name, slot_cfg in mem.slots.items():
            prefix = "SLOT_{}_".format(slot_name.upper())
            vars_list.append("{}BASE:0x{:08X}".format(prefix, slot_cfg.base))
            vars_list.append("{}SIZE:0x{:08X}".format(prefix, slot_cfg.size))

        load_addresses = self.effective_image_load_addresses()
        for slot_name, load_addr in load_addresses.items():
            vars_list.append(
                "IMAGE_{}_LOAD_ADDR:0x{:08X}".format(slot_name.upper(), int(load_addr))
            )

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
        vars_list.append(
            "SUCCESS_VECTOR_OFFSET:0x{:08X}".format(sc.vector_table_offset)
        )
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

        # Postmortem evidence layout.  Base64-encoded JSON keeps nested
        # geometry and optional non-image partitions safe across Robot and
        # Renode command parsing.  Empty layouts are omitted for compatibility.
        if mem.erase_regions or mem.postmortem_partitions:
            layout = {
                "contract_version": 1,
                "erase_regions": [
                    {
                        "base": region.base,
                        "size": region.size,
                        "sector_size": region.sector_size,
                    }
                    for region in mem.erase_regions
                ],
                "partitions": [
                    {
                        "name": region.name,
                        "base": region.base,
                        "size": region.size,
                    }
                    for region in mem.postmortem_partitions
                ],
            }
            encoded_layout = base64.b64encode(
                json.dumps(layout, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            vars_list.append("POSTMORTEM_LAYOUT_B64:{}".format(encoded_layout))

        # Image hash mode: pre-compute SHA-256 of each image binary.
        # Hash only the data portion (slot_size - page_size), excluding the
        # last page where bootloaders store trailer metadata.
        if sc.image_hash:
            vars_list.append("SUCCESS_IMAGE_HASH:true")
            if sc.image_hash_slot:
                vars_list.append("SUCCESS_IMAGE_HASH_SLOT:{}".format(sc.image_hash_slot))
            image_digests = self._compute_image_digests(repo_root, self.images)
            for img_name, digest in image_digests.items():
                vars_list.append("IMAGE_{}_SHA256:{}".format(img_name.upper(), digest))
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
        update_sequence_file = self.generate_update_sequence_file(repo_root)
        if update_sequence_file:
            vars_list.append("UPDATE_SEQUENCE_FILE:{}".format(update_sequence_file))

        # Setup script.
        if self.setup_script:
            vars_list.append(
                "SETUP_SCRIPT:{}".format(self.resolve_path(repo_root, self.setup_script))
            )
        # Boundary campaigns use fixed harness variables for transport.  The
        # runner materializes the validated declared name inside Renode just
        # before including the setup script; exposing an arbitrary Robot
        # variable here could collide with FAULT_AT/RESULT_FILE/etc.
        boundary = getattr(self, "boundary_campaign", None)
        boundary_value = getattr(self, "boundary_value", None)
        if boundary is not None and boundary_value is not None:
            vars_list.append(
                "BOUNDARY_SETUP_ENV:{}".format(boundary.setup_environment)
            )
            vars_list.append("BOUNDARY_VALUE:{}".format(int(boundary_value)))
        boundary_state_file = getattr(self, "boundary_durable_state_file", None)
        if boundary_state_file:
            vars_list.append("BOUNDARY_DURABLE_STATE_FILE:{}".format(boundary_state_file))
        boundary_phase = getattr(self, "boundary_phase", None)
        if boundary_phase:
            vars_list.append("BOUNDARY_PHASE:{}".format(boundary_phase))
        if self.state_probe is not None:
            vars_list.append(
                "STATE_PROBE:{}".format(
                    self.resolve_path(repo_root, self.state_probe.script)
                )
            )

        # Bootloader integrity check.
        if sc.bootloader_integrity:
            vars_list.append("SUCCESS_BOOTLOADER_INTEGRITY:true")

        # Bootloader region.
        if self.bootloader_region is not None:
            vars_list.append(
                "BOOTLOADER_REGION_BASE:0x{:08X}".format(
                    self.bootloader_region.base
                )
            )
            vars_list.append(
                "BOOTLOADER_REGION_SIZE:0x{:08X}".format(
                    self.bootloader_region.size
                )
            )

        # Structured post-boot observations.  Base64-encoded JSON avoids Robot
        # and Renode quoting ambiguities while retaining a versioned contract.
        success_checks = self._success_checks_runtime_dict(sc)
        if (
            success_checks["memory_checks"]
            or success_checks["config_checks"]
            or success_checks["bootloader_integrity"]
        ):
            encoded_success_checks = base64.b64encode(
                json.dumps(
                    success_checks,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii")
            vars_list.append("SUCCESS_CHECKS_B64:{}".format(encoded_success_checks))

        # Flash backend: explicit sysbus name for the fault-injectable controller.
        if self.flash_backend:
            vars_list.append("FLASH_BACKEND:{}".format(self.flash_backend))

        # NVM controller: optional separate command-based controller peripheral
        # (e.g. for MRAM platforms where flash_backend is the memory, not the
        # controller).  Enables command_drop fault injection on MRAM paths.
        if self.nvm_controller:
            vars_list.append("NVM_CONTROLLER:{}".format(self.nvm_controller))

        # OTP peripheral: sysbus name for OTP/eFuse memory region.
        if self.otp_peripheral:
            vars_list.append("OTP_PERIPHERAL:{}".format(self.otp_peripheral))

        # Extra peripherals: comma-separated list of .cs files to compile
        # before platform loading (e.g. controller stubs for custom SoCs).
        if self.extra_peripherals:
            resolved = [
                self.resolve_path(repo_root, p) for p in self.extra_peripherals
            ]
            vars_list.append("EXTRA_PERIPHERALS:{}".format(",".join(resolved)))

        # Read fault config: emit when read_bit_flip is an active fault type.
        if "read_bit_flip" in fs.fault_types and fs.read_fault_config is not None:
            rfc = fs.read_fault_config
            if rfc.target_regions:
                region_strs = [
                    "0x{:08X}-0x{:08X}".format(s, e) for s, e in rfc.target_regions
                ]
                vars_list.append(
                    "READ_FAULT_REGIONS:{}".format(",".join(region_strs))
                )
            vars_list.append(
                "READ_FAULT_BIT_FLIPS:{}".format(rfc.bit_flip_count)
            )
            vars_list.append(
                "READ_FAULT_PROBABILITY:{}".format(rfc.fault_probability)
            )
            vars_list.append("READ_FAULT_SEED:{}".format(rfc.seed))

        # Return-code injection configuration.  These scalar variables are
        # consumed by the Renode runtime and preserve arbitrary ELF symbols.
        rci = fs.rc_injection_config
        vars_list.append("RC_INJECTION_SYMBOLS:{}".format(",".join(rci.symbols)))
        vars_list.append("RC_INJECTION_RETURN_VALUE:{}".format(rci.return_value))
        vars_list.append("RC_INJECTION_RETURN_REGISTER:{}".format(rci.return_register))
        vars_list.append(
            "RC_INJECTION_REQUIRE_APPLIED:{}".format(
                "true" if rci.require_applied else "false"
            )
        )

        # Instruction skip config: emit target address ranges and skip count.
        if "instruction_skip" in fs.fault_types and fs.instruction_skip_config is not None:
            isc = fs.instruction_skip_config
            if isc.target_addresses:
                region_strs = [
                    "0x{:08X}-0x{:08X}".format(s, e)
                    for s, e in isc.target_addresses
                ]
                vars_list.append(
                    "INSTRUCTION_SKIP_REGIONS:{}".format(",".join(region_strs))
                )
            vars_list.append(
                "INSTRUCTION_SKIP_COUNT:{}".format(isc.skip_count)
            )
        if fs.verification_probes:
            encoded = base64.b64encode(
                json.dumps(
                    [probe.to_runtime_dict() for probe in fs.verification_probes],
                    sort_keys=True,
                ).encode("utf-8")
            ).decode("ascii")
            vars_list.append("VERIFICATION_PROBES:{}".format(encoded))
        if fs.function_return_probes:
            encoded = base64.b64encode(
                json.dumps(
                    [probe.to_runtime_dict() for probe in fs.function_return_probes],
                    sort_keys=True,
                ).encode("utf-8")
            ).decode("ascii")
            vars_list.append("FUNCTION_RETURN_PROBES:{}".format(encoded))

        # Terminal-error campaigns receive the declarative contract.  The
        # campaign runner may replace this with the emitted-ELF-resolved
        # payload; retaining the declaration here also makes ordinary runtime
        # results self-describing.
        if self.terminal_error_paths:
            terminal_elf = self.resolve_path(repo_root, self.bootloader_elf)
            terminal_discovery = discover_terminal_error_paths(
                terminal_elf, self.terminal_error_paths
            )
            terminal_payload = json.dumps(
                build_terminal_runtime_payload(
                    terminal_discovery, self.terminal_error_paths
                ),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            encoded = base64.b64encode(terminal_payload).decode("ascii")
            vars_list.append("TERMINAL_ERROR_PATHS_B64:{}".format(encoded))
            vars_list.append(
                "TERMINAL_ERROR_ARTIFACT_HASH:{}".format(
                    hashlib.sha256(terminal_payload).hexdigest()
                )
            )
            vars_list.append(
                "TERMINAL_ERROR_SNAPSHOT_HASH:{}".format(
                    terminal_snapshot_identity(
                        terminal_elf,
                        {
                            name: self.resolve_path(repo_root, image)
                            for name, image in self.images.items()
                        },
                        self.pre_boot_state,
                    )
                )
            )

        # I2C fault config: emit when any i2c_* fault type is active.
        i2c_types_active = [ft for ft in fs.fault_types if ft.startswith("i2c_")]
        if i2c_types_active and fs.i2c_fault_config is not None:
            ifc = fs.i2c_fault_config
            vars_list.append("I2C_FAULT_PERIPHERAL:{}".format(ifc.peripheral_name))
            vars_list.append("I2C_FAULT_TARGET_ADDRESS:{}".format(ifc.target_address))
            # Encode fault types as comma-separated type codes.
            i2c_codes = ",".join(
                str(I2C_FAULT_TYPE_CODES.get(ft, 0)) for ft in i2c_types_active
            )
            vars_list.append("I2C_FAULT_TYPE_CODES:{}".format(i2c_codes))
            vars_list.append("I2C_FAULT_TYPES:{}".format(",".join(i2c_types_active)))
            if ifc.fault_at_transaction > 0:
                vars_list.append(
                    "I2C_FAULT_AT_TRANSACTION:{}".format(ifc.fault_at_transaction)
                )
            vars_list.append("I2C_FAULT_SEED:{}".format(ifc.fault_seed))

        # Per-profile stall timeout override.
        if fs.progress_stall_timeout_s is not None:
            vars_list.append(
                "PROGRESS_STALL_TIMEOUT_S:{}".format(fs.progress_stall_timeout_s)
            )

        # Metadata fault regions: semicolon-separated list of name,start,end triples.
        if self.metadata_fault_regions:
            encoded = ";".join(
                "{},0x{:X},0x{:X}".format(r.name, r.start, r.end)
                for r in self.metadata_fault_regions
            )
            vars_list.append("METADATA_FAULT_REGIONS:{}".format(encoded))

        # Metadata delta tracking: semicolon-separated field specs.
        md = fs.metadata_delta
        if md.enabled and md.fields:
            field_specs: List[str] = []
            for f in md.fields:
                parts = ["0x{:08X}".format(f.address), f.name]
                if f.min_delta is not None:
                    parts.append("min={}".format(f.min_delta))
                if f.max_delta is not None:
                    parts.append("max={}".format(f.max_delta))
                if f.when is not None:
                    parts.append("when={}".format(f.when))
                field_specs.append(",".join(parts))
            vars_list.append(
                "METADATA_DELTA_FIELDS:{}".format(";".join(field_specs))
            )

        # NVS region config.
        if self.nvs_region:
            vars_list.append(
                "NVS_REGION_ADDR:0x{:08X}".format(self.nvs_region.address)
            )
            vars_list.append(
                "NVS_REGION_SIZE:0x{:08X}".format(self.nvs_region.size)
            )
            if self.nvs_region.snapshot:
                vars_list.append(
                    "NVS_REGION_SNAPSHOT:{}".format(
                        self.resolve_path(repo_root, self.nvs_region.snapshot)
                    )
                )

        # NVS corruption config (modes + seed for runtime dispatch).
        nvs_cfg = self.fault_sweep.nvs_corruption
        if nvs_cfg.enabled and self.nvs_region:
            variant_specs = nvs_cfg.variant_specs()
            vars_list.append(
                "NVS_CORRUPTION_MODES:{}".format(",".join(nvs_cfg.modes))
            )
            vars_list.append(
                "NVS_CORRUPTION_SEED:{}".format(nvs_cfg.seed)
            )
            encoded_variants = base64.b64encode(
                json.dumps(
                    variant_specs,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii")
            vars_list.append(
                "NVS_CORRUPTION_VARIANTS_B64:{}".format(encoded_variants)
            )

        # Writeback durability model.
        vars_list.append("DURABILITY_MODEL:{}".format(fs.durability_model))
        if fs.writeback is not None:
            wb = fs.writeback
            vars_list.append("WRITEBACK_BUFFER_CAPACITY:{}".format(wb.buffer_capacity))
            barrier_strs = []
            for b in wb.barriers:
                barrier_strs.append(str(b.get("address", b.get("symbol", ""))))
            vars_list.append("WRITEBACK_BARRIERS:{}".format(",".join(barrier_strs)))
            vars_list.append(
                "WRITEBACK_ERASE_FLUSHES:{}".format("true" if wb.erase_flushes_domain else "false")
            )

        # Config checks: semicolon-separated list of check specs.
        if sc.config_checks:
            check_parts: List[str] = []
            for chk in sc.config_checks:
                parts: List[str] = ["addr=0x{:X}".format(chk.address)]
                if chk.expected is not None:
                    parts.append("expected=0x{:08X}".format(chk.expected))
                if chk.nonzero:
                    parts.append("nonzero=true")
                if chk.mask is not None:
                    parts.append("mask=0x{:08X}".format(chk.mask))
                if chk.expected_masked is not None:
                    parts.append(
                        "expected_masked=0x{:08X}".format(chk.expected_masked)
                    )
                check_parts.append(",".join(parts))
            vars_list.append(
                "CONFIG_CHECKS:{}".format(";".join(check_parts))
            )
        # Security policy: advisory fields for adversarial fault classification.
        sp = self.security_policy
        if sp.anti_rollback:
            vars_list.append("SECURITY_ANTI_ROLLBACK:true")
        if sp.minimum_version is not None:
            vars_list.append(
                "SECURITY_MINIMUM_VERSION:{}".format(sp.minimum_version)
            )
        if sp.toctou_protection:
            vars_list.append("SECURITY_TOCTOU_PROTECTION:true")

        # Success criteria overrides: per-fault-type criteria as base64-encoded
        # JSON.  Base64 avoids brace/quote escaping issues in Robot→Renode
        # variable passing.
        if self.success_criteria_overrides:
            raw_json = json.dumps(self.success_criteria_overrides, separators=(",", ":"))
            b64 = base64.b64encode(raw_json.encode()).decode().rstrip("=")
            vars_list.append("SUCCESS_CRITERIA_OVERRIDES:{}".format(b64))

        # Residual image: load a prior (larger) image before the actual image
        # to simulate stale tail bytes left after an in-place update.
        if self.residual_image is not None:
            ri = self.residual_image
            vars_list.append(
                "RESIDUAL_IMAGE_SLOT:{}".format(ri.slot)
            )
            if ri.prior_image is not None:
                vars_list.append(
                    "RESIDUAL_IMAGE_PRIOR:{}".format(
                        self.resolve_path(repo_root, ri.prior_image)
                    )
                )
            if ri.fill_pattern is not None:
                vars_list.append(
                    "RESIDUAL_IMAGE_FILL:0x{:02X}".format(ri.fill_pattern)
                )

        # Max reset vector offset: flag if the reset vector points beyond the
        # authenticated image boundary.
        if sc.max_reset_vector_offset is not None:
            vars_list.append(
                "MAX_RESET_VECTOR_OFFSET:0x{:08X}".format(sc.max_reset_vector_offset)
            )

        return vars_list

    def boundary_followup_robot_vars(self) -> List[str]:
        """Return fixed transport variables for the previous phase."""
        campaign = getattr(self, "boundary_campaign", None)
        previous = getattr(self, "boundary_previous_value", None)
        candidate = getattr(self, "boundary_value", None)
        if campaign is None or candidate is None or previous is None or campaign.follow_up is None:
            return []
        resolve_followup_value(int(candidate))
        return ["BOUNDARY_VALUE:{}".format(int(previous)), "BOUNDARY_PHASE:follow_up"]
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


def _parse_positive_float(value: Any, field_name: str) -> float:
    """Parse a finite, strictly positive floating-point value."""
    if isinstance(value, bool):
        raise ProfileError("{}: expected positive number, got {!r}".format(field_name, value))
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ProfileError("{}: expected positive number, got {!r}".format(field_name, value))
    if not math.isfinite(parsed) or parsed <= 0:
        raise ProfileError("{}: expected positive number, got {!r}".format(field_name, value))
    return parsed


def _parse_bool(value: Any, field_name: str) -> bool:
    """Parse a YAML boolean without accepting truthy strings or integers."""
    if type(value) is not bool:
        raise ProfileError(
            "{}: expected boolean, got {}".format(
                field_name, type(value).__name__
            )
        )
    return value


_PROFILE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _parse_profile_identifier(value: Any, field_name: str) -> str:
    """Parse a profile-controlled identifier that is safe in path names."""
    if not isinstance(value, str) or not _PROFILE_IDENTIFIER_RE.fullmatch(value):
        raise ProfileError(
            "{}: expected safe identifier matching {}, got {!r}".format(
                field_name,
                _PROFILE_IDENTIFIER_RE.pattern,
                value,
            )
        )
    return value


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


def _parse_bootloader_region(raw: Optional[Dict[str, Any]]) -> Optional[BootloaderRegionConfig]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("bootloader_region: expected mapping with base and size")
    base = _parse_int(_require(raw, "base", "bootloader_region"), "bootloader_region.base")
    size = _parse_int(_require(raw, "size", "bootloader_region"), "bootloader_region.size")
    if size <= 0:
        raise ProfileError("bootloader_region.size must be > 0, got 0x{:X}".format(size))
    return BootloaderRegionConfig(base=base, size=size)


def _parse_memory_regions(
    raw: Optional[Any], field: str, require_sector_size: bool = False
) -> List[MemoryRegionConfig]:
    """Parse generic flash-geometry or postmortem partition declarations."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("{}: expected list".format(field))
    regions: List[MemoryRegionConfig] = []
    names = set()
    for index, entry in enumerate(raw):
        path = "{}[{}]".format(field, index)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(path))
        base = _parse_int(_require(entry, "base", path), "{}.base".format(path))
        size = _parse_int(_require(entry, "size", path), "{}.size".format(path))
        if base < 0 or size <= 0 or base + size > 0x100000000:
            raise ProfileError("{}: invalid 32-bit range".format(path))
        sector_raw = entry.get("sector_size", entry.get("erase_size"))
        sector_size = None
        if sector_raw is not None:
            sector_size = _parse_int(sector_raw, "{}.sector_size".format(path))
            if sector_size <= 0 or sector_size > size:
                raise ProfileError("{}.sector_size must be in 1..size".format(path))
        if require_sector_size and sector_size is None:
            raise ProfileError("{}: missing sector_size".format(path))
        name = entry.get("name")
        if name is not None:
            name = str(name).strip()
            if not name or name in names:
                raise ProfileError("{}: name must be non-empty and unique".format(path))
            names.add(name)
        regions.append(
            MemoryRegionConfig(
                base=base, size=size, sector_size=sector_size, name=name
            )
        )
    regions.sort(key=lambda region: (region.base, region.size))
    for index, current in enumerate(regions):
        prior = regions[index - 1] if index else None
        if prior is not None and current.base < prior.base + prior.size:
            raise ProfileError("{}: overlapping ranges".format(field))
    return regions


def _parse_memory(raw: Dict[str, Any]) -> MemoryConfig:
    sram = _require(raw, "sram", "memory")
    sram_start = _parse_int(_require(sram, "start", "memory.sram"), "memory.sram.start")
    sram_end = _parse_int(_require(sram, "end", "memory.sram"), "memory.sram.end")
    write_granularity = _parse_int(raw.get("write_granularity", 8), "memory.write_granularity")
    page_size = _parse_int(raw.get("page_size", 4096), "memory.page_size")
    if page_size <= 0:
        raise ProfileError("memory.page_size must be > 0")
    slots = _parse_slots(_require(raw, "slots", "memory"))
    bootloader_region = _parse_bootloader_region(raw.get("bootloader_region"))
    erase_regions = _parse_memory_regions(
        raw.get("erase_regions"), "memory.erase_regions", require_sector_size=True
    )
    postmortem_partitions = _parse_memory_regions(
        raw.get("postmortem_partitions"), "memory.postmortem_partitions"
    )
    for index, partition in enumerate(postmortem_partitions):
        if not partition.name:
            raise ProfileError(
                "memory.postmortem_partitions[{}]: missing name".format(index)
            )
    trace_address_map = []
    raw_trace_map = raw.get("trace_address_map", [])
    if not isinstance(raw_trace_map, list):
        raise ProfileError("memory.trace_address_map: expected list")
    for index, entry in enumerate(raw_trace_map):
        if not isinstance(entry, dict):
            raise ProfileError(
                "memory.trace_address_map[{}]: expected mapping".format(index)
            )
        for key in ("offset_start", "offset_end", "address_addend"):
            if key not in entry:
                raise ProfileError(
                    "memory.trace_address_map[{}]: missing {}".format(index, key)
                )
        offset_start = _parse_int(
            entry["offset_start"],
            "memory.trace_address_map[{}].offset_start".format(index),
        )
        offset_end = _parse_int(
            entry["offset_end"],
            "memory.trace_address_map[{}].offset_end".format(index),
        )
        address_addend = _parse_int(
            entry["address_addend"],
            "memory.trace_address_map[{}].address_addend".format(index),
        )
        if (
            offset_start < 0
            or offset_end <= offset_start
            or offset_end > 0x100000000
            or address_addend < 0
            or address_addend + offset_end > 0x100000000
        ):
            raise ProfileError(
                "memory.trace_address_map[{}]: invalid range or 32-bit address bound".format(index)
            )
        trace_address_map.append({
            "offset_start": offset_start,
            "offset_end": offset_end,
            "address_addend": address_addend,
        })
    for index, current in enumerate(trace_address_map):
        for prior in trace_address_map[:index]:
            if max(current["offset_start"], prior["offset_start"]) < min(
                current["offset_end"], prior["offset_end"]
            ):
                raise ProfileError(
                    "memory.trace_address_map: overlapping offset ranges"
                )
    return MemoryConfig(
        sram_start=sram_start,
        sram_end=sram_end,
        write_granularity=write_granularity,
        page_size=page_size,
        slots=slots,
        bootloader_region=bootloader_region,
        trace_address_map=trace_address_map,
        erase_regions=erase_regions,
        postmortem_partitions=postmortem_partitions,
    )


def _parse_success_criteria(raw: Optional[Dict[str, Any]]) -> SuccessCriteria:
    if raw is None:
        return SuccessCriteria()
    if not isinstance(raw, dict):
        raise ProfileError("success_criteria: expected mapping")
    otadata_expect_scope = str(raw.get("otadata_expect_scope", "always")).strip().lower()
    if otadata_expect_scope not in ("always", "control"):
        raise ProfileError(
            "success_criteria.otadata_expect_scope: expected 'always' or 'control'"
        )
    return SuccessCriteria(
        vtor_in_slot=raw.get("vtor_in_slot"),
        vector_table_offset=_parse_int(raw.get("vector_table_offset", 0), "success_criteria.vector_table_offset"),
        pc_in_slot=raw.get("pc_in_slot"),
        marker_address=_parse_int(raw["marker_address"], "success_criteria.marker_address") if "marker_address" in raw else None,
        marker_value=_parse_int(raw["marker_value"], "success_criteria.marker_value") if "marker_value" in raw else None,
        image_hash=_parse_bool(
            raw.get("image_hash", False), "success_criteria.image_hash"
        ),
        expected_image=raw.get("expected_image"),
        image_hash_slot=raw.get("image_hash_slot"),
        otadata_expect=_parse_otadata_expect(raw.get("otadata_expect")),
        otadata_expect_scope=otadata_expect_scope,
        bootloader_integrity=_parse_bool(
            raw.get("bootloader_integrity", False),
            "success_criteria.bootloader_integrity",
        ),
        config_checks=_parse_config_checks(raw.get("config_checks")),
        boot_register_values=_parse_boot_register_values(raw.get("boot_register_values")),
        max_reset_vector_offset=(
            _parse_int(raw["max_reset_vector_offset"], "success_criteria.max_reset_vector_offset")
            if "max_reset_vector_offset" in raw else None
        ),
        memory_checks=_parse_memory_checks(raw.get("memory_checks")),
    )


def _parse_terminal_error_paths(raw: Optional[Any]) -> List[TerminalErrorPathConfig]:
    """Parse binary-driven terminal-error escape declarations."""
    try:
        return parse_terminal_error_paths(raw)
    except (TypeError, ValueError, KeyError) as exc:
        raise ProfileError(str(exc)) from exc


def _parse_memory_checks(raw: Optional[list]) -> List[MemoryCheck]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("success_criteria.memory_checks: expected list")
    if not raw:
        return []
    checks = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ProfileError(
                "memory_checks[{}]: expected mapping".format(i)
            )
        if "address" not in entry:
            raise ProfileError("memory_checks[{}]: missing 'address'".format(i))
        op = str(entry.get("op", "eq")).strip().lower()
        if op not in {"eq", "ne", "ge", "le", "nonzero"}:
            raise ProfileError(
                "memory_checks[{}].op: expected one of eq, ne, ge, le, "
                "nonzero; got '{}'".format(i, op)
            )
        if op != "nonzero" and "expected_value" not in entry:
            raise ProfileError(
                "memory_checks[{}].expected_value is required for op '{}'".format(
                    i, op
                )
            )
        checks.append(MemoryCheck(
            address=_parse_int(entry["address"], "memory_checks[{}].address".format(i)),
            expected_value=(
                _parse_int(entry["expected_value"], "memory_checks[{}].expected_value".format(i))
                if "expected_value" in entry else None
            ),
            mask=_parse_int(entry.get("mask", 0xFFFFFFFF), "memory_checks[{}].mask".format(i)),
            op=op,
        ))
    return checks


def _parse_success_criteria_overrides(
    raw: Optional[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Parse per-fault-type success criteria overrides.

    Returns a dict mapping fault type names (e.g. 'read_bit_flip') to
    partial success criteria dicts that merge over the global criteria
    at evaluation time.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError(
            "success_criteria_overrides: expected mapping, got {}".format(
                type(raw).__name__
            )
        )
    result: Dict[str, Dict[str, Any]] = {}
    for fault_type_name, overrides in raw.items():
        fault_type_name = str(fault_type_name)
        if fault_type_name not in KNOWN_FAULT_TYPES:
            raise ProfileError(
                "success_criteria_overrides: unknown fault type '{}'. "
                "Known types: {}".format(
                    fault_type_name, sorted(KNOWN_FAULT_TYPES)
                )
            )
        if not isinstance(overrides, dict):
            raise ProfileError(
                "success_criteria_overrides.{}: expected mapping, got {}".format(
                    fault_type_name, type(overrides).__name__
                )
            )
        result[fault_type_name] = dict(overrides)
    return result


def _parse_heuristic_config(
    raw: Optional[Dict[str, Any]],
    *,
    bootloader_elf: Optional[str] = None,
    profile_path: Optional[Path] = None,
) -> Optional[HeuristicConfig]:
    """Parse the optional heuristic sub-config from fault_sweep."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.heuristic: expected mapping")
    critical_regions_raw = raw.get("critical_regions", [])
    if not isinstance(critical_regions_raw, list):
        raise ProfileError("fault_sweep.heuristic.critical_regions: expected list")
    critical_regions: List[Tuple[int, int]] = []
    for i, region in enumerate(critical_regions_raw):
        ctx = "fault_sweep.heuristic.critical_regions[{}]".format(i)
        if not isinstance(region, dict):
            raise ProfileError("{}: expected mapping with start/end or symbol".format(ctx))
        has_symbol = "symbol" in region
        has_start = "start" in region
        has_end = "end" in region
        if has_symbol:
            if has_start or has_end:
                raise ProfileError("{}: use either symbol or start/end, not both".format(ctx))
            symbol_query = str(_require(region, "symbol", ctx)).strip()
            if not symbol_query:
                raise ProfileError("{}.symbol: expected non-empty string".format(ctx))
            critical_regions.extend(
                _resolve_instruction_skip_symbol_targets(
                    symbol_query,
                    bootloader_elf=bootloader_elf,
                    profile_path=profile_path,
                    skip_count=1,
                    ctx="{}.symbol".format(ctx),
                )
            )
            continue
        start = _parse_int(_require(region, "start", ctx), "{}.start".format(ctx))
        end = _parse_int(_require(region, "end", ctx), "{}.end".format(ctx))
        critical_regions.append((start, end))
    return HeuristicConfig(
        tier2_step=int(raw.get("tier2_step", 3)),
        tier3_step=int(raw.get("tier3_step", 100)),
        discontinuity_window=int(raw.get("discontinuity_window", 3)),
        target_points=int(raw["target_points"]) if "target_points" in raw else None,
        preserve_critical_tiers=_parse_bool(
            raw.get("preserve_critical_tiers", True),
            "fault_sweep.heuristic.preserve_critical_tiers",
        ),
        shard_count=int(raw.get("shard_count", 1)),
        shard_index=int(raw.get("shard_index", 0)),
        random_tail_budget=int(raw.get("random_tail_budget", 0)),
        critical_regions=critical_regions,
    )


def _warn_fault_backend_compat(
    fs: FaultSweepConfig,
    platform: str,
    flash_backend: Optional[str],
    nvm_controller: Optional[str] = None,
    otp_peripheral: Optional[str] = None,
) -> None:
    """Emit warnings when fault_types are likely incompatible with the backend.

    ``read_bit_flip`` requires a backend that intercepts CPU reads --
    NVMemory (slow-path) or MRAMMemory.  Fast-path backends
    (MappedMemory + NVMC/STM32) expose flash via a backing
    MappedMemory that the CPU reads directly, so read faults cannot be
    injected.  ``command_drop`` requires a GenericNvmController
    (command-based flash controller).

    The profile loader cannot definitively determine the Renode peripheral
    class — that is resolved at runtime from the .repl file.  This check
    uses heuristics on ``platform`` and ``flash_backend`` to catch obvious
    mismatches early.  A runtime preflight in the audit harness could
    query ``sysbus.WhatIsAt`` for a definitive check, but that is outside
    the profile loader's scope.
    """
    import warnings

    # Collect every fault_type referenced across all sub-configs.
    all_types: set = set(fs.fault_types)
    if fs.phase2_fault:
        all_types.update(fs.phase2_fault.fault_types)
    if fs.hook_fault:
        all_types.update(fs.hook_fault.fault_types)
    if fs.metadata_fault:
        all_types.update(fs.metadata_fault.fault_types)

    platform_lower = platform.lower()
    backend_lower = flash_backend.lower() if flash_backend else ""

    # read_bit_flip: supported on NVMemory (slow-path) and MRAMMemory --
    # both intercept CPU reads.  Fast-path backends (MappedMemory + NVMC,
    # STM32 controllers) expose flash via a backing MappedMemory that the
    # CPU reads directly, so read faults cannot be injected.
    if "read_bit_flip" in all_types:
        is_read_capable = "mram" in platform_lower
        if not is_read_capable:
            is_read_capable = (
                "nvm" in platform_lower and "nvmc" not in platform_lower
            )
        if backend_lower:
            # If flash_backend is explicitly set, check it directly.
            is_read_capable = "mram" in backend_lower or (
                "nvm" in backend_lower and "nvmc" not in backend_lower
            )
        if not is_read_capable:
            warnings.warn(
                "fault_type 'read_bit_flip' requires a backend that "
                "intercepts CPU reads (NVMemory or MRAMMemory), but "
                "platform '{}' / flash_backend '{}' does not appear to "
                "use one. Read-fault injection may silently do "
                "nothing.".format(platform, flash_backend or "(not set)")
            )

    # interrupted_erase / multi_sector_atomicity: MRAM has no page erases.
    # Erase faults will silently no-op on MRAM backends.
    erase_types = {"interrupted_erase", "multi_sector_atomicity"}
    if all_types & erase_types:
        is_mram = "mram" in platform_lower or "mram" in backend_lower
        if is_mram:
            warnings.warn(
                "Erase fault types {} are configured but platform '{}' / "
                "flash_backend '{}' appears to be MRAM, which has no page "
                "erases. Erase fault points will be skipped.".format(
                    sorted(all_types & erase_types),
                    platform,
                    flash_backend or "(not set)",
                )
            )

    # read_fault_config without read_bit_flip in fault_types is likely a
    # user error -- the config will be parsed but never used.
    if fs.read_fault_config is not None and "read_bit_flip" not in all_types:
        warnings.warn(
            "read_fault_config is set but 'read_bit_flip' is not in "
            "fault_types. The read fault configuration will have no effect."
        )

    # command_drop: only supported on GenericNvmController (command-based)
    # for main/phase2/metadata faults.  hook_fault command_drop operates on
    # the hook bus, not the flash backend, so it works on any platform.
    # Also satisfied by an explicit nvm_controller field (separate controller
    # peripheral on MRAM platforms).
    non_hook_types = set(fs.fault_types)
    if fs.phase2_fault:
        non_hook_types.update(fs.phase2_fault.fault_types)
    if fs.metadata_fault:
        non_hook_types.update(fs.metadata_fault.fault_types)
    if "command_drop" in non_hook_types:
        looks_gfc = (
            nvm_controller is not None
            or "gfc" in platform_lower or "gfc" in backend_lower
            or "nvm_ctrl" in backend_lower or "generic_nvm" in backend_lower
            or "nvm_ctrl" in platform_lower or "generic_nvm" in platform_lower
        )
        if not looks_gfc:
            warnings.warn(
                "fault_type 'command_drop' requires a GenericNvmController "
                "(command-based) backend, but platform '{}' / flash_backend "
                "'{}' does not appear to use one. Command-drop fault "
                "injection may silently do nothing.".format(
                    platform, flash_backend or "(not set)"
                )
            )

    # instruction_skip_config without instruction_skip in fault_types is
    # likely a user error.
    if fs.instruction_skip_config is not None and "instruction_skip" not in all_types:
        warnings.warn(
            "instruction_skip_config is set but 'instruction_skip' is not in "
            "fault_types. The instruction skip configuration will have no effect."
        )

    # instruction_skip without instruction_skip_config is a user error --
    # target addresses are required.
    if "instruction_skip" in all_types and fs.instruction_skip_config is None:
        warnings.warn(
            "fault_type 'instruction_skip' is enabled but no "
            "instruction_skip_config is set. No instruction-skip fault "
            "points will be generated."
        )
    if fs.verification_probes and "instruction_skip" not in all_types:
        warnings.warn(
            "verification_probes is set but 'instruction_skip' is not in "
            "fault_types. The verification probes will have no effect."
        )
    if fs.metadata_delta and fs.metadata_delta.enabled and fs.metadata_delta.fields:
        metadata_delta_unsupported = []
        if getattr(fs, "mode", "runtime") != "runtime":
            metadata_delta_unsupported.append("fault_sweep.mode={!r}".format(fs.mode))
        if getattr(fs, "evaluation_mode", None) == "state":
            metadata_delta_unsupported.append("evaluation_mode='state'")
        if "instruction_skip" in all_types:
            metadata_delta_unsupported.append("instruction_skip fault type")
        if fs.hook_fault and fs.hook_fault.enabled:
            metadata_delta_unsupported.append("hook_fault")
        if metadata_delta_unsupported:
            warnings.warn(
                "metadata_delta only records execute/trace-replay boot cycles and "
                "will not run for {}. Remove metadata_delta or switch to a "
                "supported runtime execute/trace-replay configuration.".format(
                    ", ".join(metadata_delta_unsupported)
                )
            )

    # OTP fault types require an OTPMemory peripheral on the platform.
    otp_types = {"otp_partial_program", "otp_stuck_bit", "otp_read_disturb", "otp_overblow", "otp_blow_nop"}
    if all_types & otp_types:
        has_otp = (
            otp_peripheral is not None
            or "otp" in platform_lower
            or "otp" in backend_lower
        )
        if not has_otp:
            warnings.warn(
                "OTP fault types {} are configured but platform '{}' / "
                "flash_backend '{}' does not appear to include an OTP "
                "peripheral. OTP fault injection may silently do "
                "nothing.".format(
                    sorted(all_types & otp_types),
                    platform,
                    flash_backend or "(not set)",
                )
            )


def _parse_fault_sweep(
    raw: Optional[Dict[str, Any]],
    *,
    bootloader_elf: Optional[str] = None,
    profile_path: Optional[Path] = None,
) -> FaultSweepConfig:
    if raw is None:
        return FaultSweepConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep: expected mapping")
    partial_staging = raw.get("partial_staging")
    if partial_staging is not None:
        if not isinstance(partial_staging, dict):
            raise ProfileError("fault_sweep.partial_staging: expected mapping")
        partial_staging_enabled = _parse_bool(
            partial_staging.get("enabled", True),
            "fault_sweep.partial_staging.enabled",
        )
        if not partial_staging_enabled:
            partial_staging = None
    fault_types = _normalize_fault_types(
        raw.get("fault_types", ["power_loss"]),
        "fault_sweep.fault_types",
    )
    eval_mode = raw.get("evaluation_mode")
    if eval_mode is not None:
        eval_mode = str(eval_mode)
    if "hash_bypass_symbols" in raw:
        raise ProfileError(
            "fault_sweep.hash_bypass_symbols was renamed to "
            "fault_sweep.sweep_hash_bypass_symbols"
        )
    sweep_hash_bypass = raw.get("sweep_hash_bypass_symbols")
    if sweep_hash_bypass is not None and not isinstance(sweep_hash_bypass, list):
        sweep_hash_bypass = [str(sweep_hash_bypass)]
    stall_timeout = raw.get("progress_stall_timeout_s")
    if stall_timeout is not None:
        stall_timeout = float(stall_timeout)
    boot_cycles = int(raw.get("boot_cycles", 1))
    if boot_cycles < 1:
        raise ProfileError("fault_sweep.boot_cycles: expected integer >= 1")
    boot_cycle_hook = raw.get("boot_cycle_hook")
    if boot_cycle_hook is not None:
        boot_cycle_hook = str(boot_cycle_hook).strip()
        if not boot_cycle_hook:
            raise ProfileError("fault_sweep.boot_cycle_hook: expected non-empty path")
    expected_rollback_at_cycle = raw.get("expected_rollback_at_cycle")
    if expected_rollback_at_cycle is not None:
        expected_rollback_at_cycle = int(expected_rollback_at_cycle)
        if expected_rollback_at_cycle < 1:
            raise ProfileError(
                "fault_sweep.expected_rollback_at_cycle: expected integer >= 1"
            )
    hook_fault = _parse_hook_fault(raw.get("hook_fault"))
    confirm_cycle = _parse_confirm_cycle(raw.get("confirm_cycle"))

    # -- Boot-cycle config consistency checks --
    if expected_rollback_at_cycle is not None and boot_cycles <= 1:
        raise ProfileError(
            "fault_sweep.expected_rollback_at_cycle requires boot_cycles >= 2 "
            "(currently boot_cycles={})".format(boot_cycles)
        )
    if boot_cycle_hook is not None and boot_cycles <= 1:
        import warnings

        warnings.warn(
            "fault_sweep.boot_cycle_hook is set but boot_cycles=1; "
            "the hook will never run. Set boot_cycles >= 2."
        )
    if hook_fault.enabled and not boot_cycle_hook:
        raise ProfileError(
            "fault_sweep.hook_fault.enabled requires boot_cycle_hook to be set"
        )
    if hook_fault.enabled and boot_cycles <= 1:
        raise ProfileError(
            "fault_sweep.hook_fault.enabled requires boot_cycles >= 2 "
            "(currently boot_cycles={})".format(boot_cycles)
        )
    multi_fault_config = _parse_multi_fault(raw.get("multi_fault"))
    if hook_fault.enabled and multi_fault_config.enabled:
        import warnings

        warnings.warn(
            "fault_sweep: both hook_fault and multi_fault are enabled. "
            "Compound fault sequences during hook writes are experimental "
            "and may produce unexpected interactions."
        )
    if expected_rollback_at_cycle is not None and expected_rollback_at_cycle >= boot_cycles:
        import warnings

        warnings.warn(
            "fault_sweep.expected_rollback_at_cycle={} but boot_cycles={}; "
            "rollback must happen before the last cycle to be observable".format(
                expected_rollback_at_cycle, boot_cycles
            )
        )
    if confirm_cycle.enabled and not boot_cycle_hook:
        raise ProfileError(
            "fault_sweep.confirm_cycle.enabled requires boot_cycle_hook to be set"
        )

    durability_model = str(raw.get("durability_model", "direct"))
    if durability_model not in ("direct", "writeback"):
        raise ProfileError(
            "fault_sweep.durability_model: expected 'direct' or 'writeback', "
            "got '{}'".format(durability_model)
        )
    if (
        durability_model == "writeback"
        and str(eval_mode or "").strip().lower() != "execute"
    ):
        raise ProfileError(
            "fault_sweep.durability_model=writeback requires "
            "fault_sweep.evaluation_mode 'execute'"
        )
    writeback = None
    if durability_model == "writeback":
        wb_raw = raw.get("writeback") or {}
        barriers = wb_raw.get("barriers", [])
        domains = wb_raw.get("domains", "auto")
        if domains not in ("auto", None):
            raise ProfileError(
                "fault_sweep.writeback.domains: custom domains are not supported; "
                "use 'auto'"
            )
        writeback = WritebackConfig(
            buffer_capacity=wb_raw.get("buffer_capacity", "auto"),
            domains="auto",
            barriers=barriers,
            erase_flushes_domain=_parse_bool(
                wb_raw.get("erase_flushes_domain", False),
                "fault_sweep.writeback.erase_flushes_domain",
            ),
        )

    return FaultSweepConfig(
        mode=raw.get("mode", "runtime"),
        max_writes=raw.get("max_writes", "auto"),
        max_otp_blows=(
            None
            if raw.get("max_otp_blows") is None
            else int(raw.get("max_otp_blows"))
        ),
        max_writes_cap=int(raw.get("max_writes_cap", 100000)),
        max_step_limit=int(raw.get("max_step_limit", 500000)),
        run_duration=str(raw.get("run_duration", "0.5")),
        calibration_time_slice=raw.get("calibration_time_slice"),
        phase1_time_slice=raw.get("phase1_time_slice"),
        phase2_time_slice=raw.get("phase2_time_slice"),
        phase2_wall_timeout_s=(
            30.0
            if raw.get("phase2_wall_timeout_s") is None
            else _parse_positive_float(
                raw.get("phase2_wall_timeout_s"),
                "fault_sweep.phase2_wall_timeout_s",
            )
        ),
        fault_types=fault_types,
        evaluation_mode=eval_mode,
        sweep_strategy=str(raw.get("sweep_strategy", "heuristic")),
        sweep_hash_bypass_symbols=sweep_hash_bypass,
        progress_stall_timeout_s=stall_timeout,
        boot_cycles=boot_cycles,
        boot_cycle_hook=boot_cycle_hook,
        vtor_settle_iters=int(raw.get("vtor_settle_iters", 0)),
        tracking_start_address=_parse_int(
            raw.get("tracking_start_address", 0),
            "fault_sweep.tracking_start_address",
        ),
        expected_rollback_at_cycle=expected_rollback_at_cycle,
        phase2_fault=_parse_phase2_fault(raw.get("phase2_fault")),
        hook_fault=hook_fault,
        confirm_cycle=confirm_cycle,
        multi_fault=multi_fault_config,
        read_fault_config=_parse_read_fault_config(raw.get("read_fault_config")),
        instruction_skip_config=_parse_instruction_skip_config(
            raw.get("instruction_skip_config"),
            bootloader_elf=bootloader_elf,
            profile_path=profile_path,
        ),
        timed_bit_corruption_config=_parse_timed_bit_corruption_config(
            raw.get("timed_bit_corruption_config"),
        ),
        verification_probes=_parse_verification_probe_config(raw),
        function_return_probes=_parse_function_return_probes(
            raw.get("function_return_probes")
        ),
        metadata_fault=_parse_metadata_fault(raw.get("metadata_fault")),
        metadata_delta=_parse_metadata_delta(raw.get("metadata_delta")),
        partial_staging=partial_staging,
        nvs_corruption=_parse_nvs_corruption(raw.get("nvs_corruption")),
        fault_distribution=_parse_fault_distribution(raw.get("fault_distribution")),
        heuristic_config=_parse_heuristic_config(
            raw.get("heuristic"),
            bootloader_elf=bootloader_elf,
            profile_path=profile_path,
        ),
        max_heuristic_points=(
            2000
            if "max_heuristic_points" not in raw
            else (
                None
                if raw.get("max_heuristic_points") is None
                else int(raw.get("max_heuristic_points"))
            )
        ),
        quick_use_heuristic=_parse_bool(
            raw.get("quick_use_heuristic", False),
            "fault_sweep.quick_use_heuristic",
        ),
        reset_mode=str(raw.get("reset_mode", "warm")),
        i2c_fault_config=_parse_i2c_fault_config(raw.get("i2c_fault_config")),
        durability_model=durability_model,
        writeback=writeback,
        rc_injection_config=_parse_rc_injection_config(
            raw.get("rc_injection_config")
        ),
    )


def _parse_phase2_fault(raw: Optional[Dict[str, Any]]) -> Phase2FaultConfig:
    if raw is None:
        return Phase2FaultConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.phase2_fault: expected mapping")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.phase2_fault.enabled")
    fault_types = _normalize_fault_types(
        raw.get("fault_types", ["power_loss"]),
        "fault_sweep.phase2_fault.fault_types",
    )
    unsupported = sorted(set(fault_types) - PHASE2_FAULT_TYPES)
    if unsupported:
        raise ProfileError(
            "fault_sweep.phase2_fault.fault_types: unsupported recovery-phase "
            "fault type(s) {}. Supported: {}".format(
                unsupported,
                sorted(PHASE2_FAULT_TYPES),
            )
        )
    max_points = int(raw.get("max_points", 0))
    if max_points < 0:
        raise ProfileError(
            "fault_sweep.phase2_fault.max_points: expected non-negative integer"
        )
    return Phase2FaultConfig(
        enabled=enabled,
        fault_types=fault_types,
        max_points=max_points,
    )


def _parse_hook_fault(raw: Optional[Dict[str, Any]]) -> HookFaultConfig:
    if raw is None:
        return HookFaultConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.hook_fault: expected mapping")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.hook_fault.enabled")
    fault_types = _normalize_fault_types(
        raw.get("fault_types", ["power_loss"]),
        "fault_sweep.hook_fault.fault_types",
    )
    valid_hook_types = {"power_loss", "bit_corruption", "command_drop"}
    parsed_types: List[str] = []
    for ft in fault_types:
        if ft not in valid_hook_types:
            raise ProfileError(
                "fault_sweep.hook_fault.fault_types: unsupported type '{}'; "
                "only {} are supported.".format(
                    ft, sorted(valid_hook_types)
                )
            )
        parsed_types.append(ft)
    max_points = int(raw.get("max_points", 0))
    if max_points < 0:
        raise ProfileError(
            "fault_sweep.hook_fault.max_points: expected non-negative integer"
        )
    return HookFaultConfig(
        enabled=enabled,
        fault_types=parsed_types,
        max_points=max_points,
    )


def _parse_confirm_cycle(raw: Optional[Dict[str, Any]]) -> "ConfirmCycleConfig":
    if raw is None:
        return ConfirmCycleConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.confirm_cycle: expected mapping")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.confirm_cycle.enabled")
    confirm_function = raw.get("confirm_function")
    if confirm_function is not None:
        confirm_function = str(confirm_function).strip()
        if not confirm_function:
            raise ProfileError(
                "fault_sweep.confirm_cycle.confirm_function: expected non-empty "
                "symbol name or address"
            )
    if enabled and not confirm_function:
        raise ProfileError(
            "fault_sweep.confirm_cycle.confirm_function is required when "
            "confirm_cycle is enabled"
        )
    post_confirm_assertions = raw.get("post_confirm_assertions")
    if post_confirm_assertions is not None:
        if not isinstance(post_confirm_assertions, list):
            raise ProfileError(
                "fault_sweep.confirm_cycle.post_confirm_assertions: expected list"
            )
        for idx, assertion in enumerate(post_confirm_assertions):
            if not isinstance(assertion, dict):
                raise ProfileError(
                    "fault_sweep.confirm_cycle.post_confirm_assertions[{}]: "
                    "expected mapping".format(idx)
                )
            if "address" not in assertion:
                raise ProfileError(
                    "fault_sweep.confirm_cycle.post_confirm_assertions[{}]: "
                    "missing 'address'".format(idx)
                )
            if "expected" not in assertion:
                raise ProfileError(
                    "fault_sweep.confirm_cycle.post_confirm_assertions[{}]: "
                    "missing 'expected'".format(idx)
                )
    expected_ratchet_version = raw.get("expected_ratchet_version")
    if expected_ratchet_version is not None:
        expected_ratchet_version = int(expected_ratchet_version)
        if expected_ratchet_version < 0:
            raise ProfileError(
                "fault_sweep.confirm_cycle.expected_ratchet_version: "
                "expected non-negative integer"
            )
    fault_types = _normalize_fault_types(
        raw.get("fault_types", ["power_loss"]),
        "fault_sweep.confirm_cycle.fault_types",
    )
    valid_confirm_types = {"power_loss", "bit_corruption", "command_drop"}
    parsed_types: List[str] = []
    for ft in fault_types:
        if ft not in valid_confirm_types:
            raise ProfileError(
                "fault_sweep.confirm_cycle.fault_types: unsupported type '{}'; "
                "only {} are "
                "supported.".format(ft, sorted(valid_confirm_types))
            )
        parsed_types.append(ft)
    max_points = int(raw.get("max_points", 0))
    if max_points < 0:
        raise ProfileError(
            "fault_sweep.confirm_cycle.max_points: expected non-negative integer"
        )
    return ConfirmCycleConfig(
        enabled=enabled,
        confirm_function=confirm_function,
        post_confirm_assertions=post_confirm_assertions or [],
        expected_ratchet_version=expected_ratchet_version,
        fault_types=parsed_types,
        max_points=max_points,
    )


def _parse_multi_fault(raw):
    """Parse multi_fault configuration from profile YAML."""
    if raw is None:
        return MultiFaultConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.multi_fault: expected mapping")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.multi_fault.enabled")
    max_faults_per_run = int(raw.get("max_faults_per_run", 2))
    if max_faults_per_run < 2:
        raise ProfileError(
            "fault_sweep.multi_fault.max_faults_per_run: expected integer >= 2"
        )
    if max_faults_per_run > MAX_MULTI_FAULTS_PER_RUN:
        raise ProfileError(
            "fault_sweep.multi_fault.max_faults_per_run exceeds safety limit {}".format(
                MAX_MULTI_FAULTS_PER_RUN
            )
        )
    strategy = str(raw.get("strategy", "pairwise_interesting"))
    known_strategies = {"explicit", "pairwise_interesting", "random_sample"}
    if strategy not in known_strategies:
        raise ProfileError(
            "fault_sweep.multi_fault.strategy: must be one of {}, got {!r}".format(
                sorted(known_strategies), strategy
            )
        )
    fallback_strategy = str(raw.get("fallback_strategy", "boundary_pairs"))
    known_fallback = {"none", "boundary_pairs", "random_sample"}
    if fallback_strategy not in known_fallback:
        raise ProfileError(
            "fault_sweep.multi_fault.fallback_strategy: must be one of {}, got {!r}".format(
                sorted(known_fallback), fallback_strategy
            )
        )
    max_pairs = int(raw.get("max_pairs", 5000))
    if max_pairs < 1:
        raise ProfileError(
            "fault_sweep.multi_fault.max_pairs: expected positive integer"
        )
    seed_raw = raw.get("seed")
    seed = int(seed_raw) if seed_raw is not None else None
    sequences_raw = raw.get("sequences")
    sequences = None
    if sequences_raw is not None:
        if not isinstance(sequences_raw, list):
            raise ProfileError(
                "fault_sweep.multi_fault.sequences: expected list of lists"
            )
        if len(sequences_raw) > max_pairs:
            raise ProfileError(
                "fault_sweep.multi_fault.sequences contains {} entries, exceeding "
                "max_pairs={}".format(len(sequences_raw), max_pairs)
            )
        sequences = []
        for i, seq in enumerate(sequences_raw):
            if not isinstance(seq, list) or len(seq) < 2:
                raise ProfileError(
                    "fault_sweep.multi_fault.sequences[{}]: expected list of >= 2 integers".format(i)
                )
            if len(seq) > max_faults_per_run:
                raise ProfileError(
                    "fault_sweep.multi_fault.sequences[{}] exceeds "
                    "max_faults_per_run={}".format(i, max_faults_per_run)
                )
            parsed_sequence = [int(x) for x in seq]
            if any(point < 0 for point in parsed_sequence):
                raise ProfileError(
                    "fault_sweep.multi_fault.sequences[{}] contains a negative "
                    "fault point".format(i)
                )
            sequences.append(parsed_sequence)
    return MultiFaultConfig(
        enabled=enabled,
        max_faults_per_run=max_faults_per_run,
        strategy=strategy,
        fallback_strategy=fallback_strategy,
        max_pairs=max_pairs,
        seed=seed,
        sequences=sequences,
    )


def _parse_read_fault_config(raw: Optional[Dict[str, Any]]) -> Optional[ReadFaultConfig]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("read_fault_config: expected mapping")
    target_regions_raw = raw.get("target_regions", [])
    if not isinstance(target_regions_raw, list):
        raise ProfileError("read_fault_config.target_regions: expected list")
    target_regions: List[Tuple[int, int]] = []
    for i, region in enumerate(target_regions_raw):
        ctx = "read_fault_config.target_regions[{}]".format(i)
        if not isinstance(region, dict):
            raise ProfileError("{}: expected mapping with start/end".format(ctx))
        start = _parse_int(_require(region, "start", ctx), "{}.start".format(ctx))
        end = _parse_int(_require(region, "end", ctx), "{}.end".format(ctx))
        target_regions.append((start, end))
    bit_flip_count = int(raw.get("bit_flip_count", 1))
    if bit_flip_count < 1:
        raise ProfileError(
            "read_fault_config.bit_flip_count: expected integer >= 1"
        )
    fault_probability = float(raw.get("fault_probability", 1.0))
    seed = int(raw.get("seed", 0))
    return ReadFaultConfig(
        target_regions=target_regions,
        bit_flip_count=bit_flip_count,
        fault_probability=fault_probability,
        seed=seed,
    )


def _count_instruction_skip_fault_points(
    start: int,
    end: int,
    skip_count: int,
    *,
    elf_path: Optional[str] = None,
) -> int:
    if elf_path:
        try:
            read_halfword = make_elf_halfword_reader(elf_path)
            return len(
                enumerate_instruction_skip_addresses(
                    read_halfword,
                    start,
                    end,
                    skip_count=skip_count,
                )
            )
        except Exception:
            pass
    stop = max(end - (max(1, skip_count) - 1) * 2, start)
    return len(range(start, stop, 2))


def _resolve_existing_profile_path(
    value: str,
    *,
    profile_path: Optional[Path],
    ctx: str,
) -> Path:
    candidate = Path(value)
    candidates: List[Path] = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        candidates.append(Path.cwd() / candidate)
        if profile_path is not None:
            profile_candidate = profile_path.parent / candidate
            if profile_candidate not in candidates:
                candidates.append(profile_candidate)
    tried = []
    for path_candidate in candidates:
        tried.append(str(path_candidate))
        if path_candidate.exists():
            return path_candidate.resolve()
    raise ProfileError(
        "{}: could not resolve path {!r}; tried {}".format(
            ctx,
            value,
            ", ".join(tried),
        )
    )


@lru_cache(maxsize=None)
def _load_elf_function_symbols(elf_path: str) -> List[Tuple[str, int, Optional[int]]]:
    if ELFFile is None:
        raise ProfileError(
            "instruction_skip_config symbol resolution requires pyelftools. "
            "Install it with: pip install -r requirements.txt"
        )
    elf_file_path = Path(elf_path)
    try:
        with elf_file_path.open("rb") as handle:
            elf = ELFFile(handle)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                raise ProfileError(
                    "bootloader ELF '{}' has no .symtab; symbol-based "
                    "instruction_skip targets require function symbols".format(elf_file_path)
                )
            raw_symbols: List[Tuple[str, int, int]] = []
            for symbol in symtab.iter_symbols():
                if not symbol.name or symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF":
                    continue
                # Clear the Thumb-state bit so address ranges stay halfword-aligned.
                start = int(symbol["st_value"]) & ~1
                size = int(symbol["st_size"])
                raw_symbols.append((symbol.name, start, size))
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(
            "failed to read function symbols from '{}': {}".format(elf_file_path, exc)
        ) from exc

    raw_symbols.sort(key=lambda item: (item[1], item[0]))
    resolved_symbols: List[Tuple[str, int, Optional[int]]] = []
    for idx, (name, start, size) in enumerate(raw_symbols):
        end: Optional[int] = None
        if size > 0:
            end = start + size
        else:
            for _, next_start, _ in raw_symbols[idx + 1:]:
                if next_start > start:
                    end = next_start
                    break
        resolved_symbols.append((name, start, end))
    return resolved_symbols


def _is_glob_pattern(query: str) -> bool:
    """Return True if *query* contains glob metacharacters (``*``, ``?``, ``[``)."""
    return any(ch in query for ch in ("*", "?", "["))


def _match_symbol_query(query: str, name: str) -> bool:
    """Match a symbol query against a symbol name.

    * If *query* contains glob metacharacters it is matched with
      :func:`fnmatch.fnmatchcase` (case-sensitive).
    * Otherwise it falls back to a plain substring test (``query in name``),
      which preserves backward compatibility.
    """
    if _is_glob_pattern(query):
        return fnmatch.fnmatchcase(name, query)
    return query in name


def _strip_gcc_clone_suffixes(name: str) -> str:
    """Return *name* with any trailing GCC clone suffixes removed.

    GCC appends suffixes such as ``.constprop.0`` or ``.isra.1`` to clones
    of a base function.  Multiple suffixes may chain
    (``foo.constprop.0.isra.1``), so we strip iteratively until no
    recognised suffix remains.
    """
    stripped = name
    while True:
        next_name = _CLONE_SUFFIX_PATTERN.sub("", stripped)
        if next_name == stripped:
            return stripped
        stripped = next_name


def _find_clone_siblings(
    base_name: str,
    symbols: List[Tuple[str, int, Optional[int]]],
    already_matched: set,
) -> List[Tuple[str, int, Optional[int]]]:
    """Return symbols whose name strips to *base_name* and are not yet matched.

    Used to auto-include compiler-generated clones (``<base>.constprop.N``,
    ``<base>.part.N``, ``<base>.isra.N``, ``<base>.cold.N``, ...) whenever
    the user's query resolves to a base function.  Without this, the
    ``-Os -ffunction-sections`` compiler pass can silently move a portion
    of the target function into a sibling clone that the sweep never
    touches.
    """
    if not base_name:
        return []
    out: List[Tuple[str, int, Optional[int]]] = []
    for sym_name, start, end in symbols:
        if sym_name in already_matched:
            continue
        if _strip_gcc_clone_suffixes(sym_name) != base_name:
            continue
        out.append((sym_name, start, end))
    return out


def _resolve_instruction_skip_symbol_targets(
    symbol_query: str,
    *,
    bootloader_elf: Optional[str],
    profile_path: Optional[Path],
    skip_count: int,
    ctx: str,
) -> List[Tuple[int, int]]:
    if not bootloader_elf:
        raise ProfileError(
            "{}: symbol resolution requires bootloader.elf".format(ctx)
        )
    elf_path = _resolve_existing_profile_path(
        bootloader_elf,
        profile_path=profile_path,
        ctx="bootloader.elf",
    )
    functions = _load_elf_function_symbols(str(elf_path))
    available_symbols = sorted({name for name, _, _ in functions})
    query_matches = [
        (name, start, end)
        for name, start, end in functions
        if _match_symbol_query(symbol_query, name)
    ]
    if not query_matches:
        raise ProfileError(
            "{}: no function symbols matching {!r} in {}. "
            "Available function symbols: {}".format(
                ctx,
                symbol_query,
                elf_path,
                ", ".join(available_symbols),
            )
        )

    # Auto-include compiler-generated clone siblings so -Os/-ffunction-sections
    # cannot silently move part of a target function into a clone that the
    # sweep never touches.  For every function the query matches, find all
    # symbols whose name strips down to the same base and include them.
    matched_names: set = {name for name, _, _ in query_matches}
    clone_additions: List[Tuple[str, int, Optional[int]]] = []
    clone_base_to_adds: Dict[str, List[str]] = {}
    seen_bases: set = set()
    for name, _, _ in query_matches:
        base = _strip_gcc_clone_suffixes(name)
        if base in seen_bases:
            continue
        seen_bases.add(base)
        siblings = _find_clone_siblings(base, functions, matched_names)
        if not siblings:
            continue
        clone_additions.extend(siblings)
        matched_names.update(s[0] for s in siblings)
        clone_base_to_adds[base] = [s[0] for s in siblings]

    matches = list(query_matches) + clone_additions

    resolved_ranges: List[Tuple[int, int]] = []
    seen_ranges: set = set()
    unresolved_symbols: List[str] = []
    total_bytes = 0
    total_points = 0
    query_match_names = {n for n, _, _ in query_matches}
    for name, start, end in matches:
        if end is None or end <= start:
            unresolved_symbols.append(name)
            continue
        if (start, end) in seen_ranges:
            continue
        seen_ranges.add((start, end))
        resolved_ranges.append((start, end))
        is_clone = name not in query_match_names
        points = _count_instruction_skip_fault_points(
            start,
            end,
            skip_count,
            elf_path=str(elf_path),
        )
        total_bytes += end - start
        total_points += points
        print(
            "Resolved {!r} -> {}{} [0x{:x}, 0x{:x}) ({} bytes, {} fault points)".format(
                symbol_query,
                name,
                " (clone sibling)" if is_clone else "",
                start,
                end,
                end - start,
                points,
            ),
            file=sys.stderr,
        )
    if unresolved_symbols:
        raise ProfileError(
            "{}: matched function symbols without a resolvable end address in {}: {}".format(
                ctx,
                elf_path,
                ", ".join(unresolved_symbols),
            )
        )
    # Summary line makes coverage totals visible in audit logs so a
    # run-over-run comparison catches silent coverage shrinkage.
    print(
        "Resolved {!r} -> {} symbol range(s), {} bytes, {} fault points total{}".format(
            symbol_query,
            len(resolved_ranges),
            total_bytes,
            total_points,
            " (incl. {} clone sibling(s): {})".format(
                sum(len(v) for v in clone_base_to_adds.values()),
                ", ".join(sorted(s for v in clone_base_to_adds.values() for s in v)),
            ) if clone_base_to_adds else "",
        ),
        file=sys.stderr,
    )
    return resolved_ranges


def _parse_timed_bit_corruption_config(
    raw: Optional[Dict[str, Any]],
) -> Optional[TimedBitCorruptionConfig]:
    """Parse timed_bit_corruption_config from profile YAML."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError(
            "fault_sweep.timed_bit_corruption_config: expected mapping"
        )
    pairs_raw = raw.get("pairs", [])
    if not isinstance(pairs_raw, list):
        raise ProfileError(
            "fault_sweep.timed_bit_corruption_config.pairs: expected list"
        )
    pairs = []
    for index, entry in enumerate(pairs_raw):
        context = "fault_sweep.timed_bit_corruption_config.pairs[{}]".format(
            index
        )
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(context))
        trigger = entry.get("trigger", {})
        if isinstance(trigger, int):
            trigger = {"address": trigger}
        if not isinstance(trigger, dict):
            raise ProfileError("{}.trigger: expected mapping".format(context))
        if "symbol" in trigger:
            raise ProfileError(
                "{}.trigger.symbol is not supported; use an explicit address".format(
                    context
                )
            )
        if "address" not in trigger:
            raise ProfileError("{}.trigger.address is required".format(context))
        if "corrupt_address" not in entry:
            raise ProfileError("{}.corrupt_address is required".format(context))
        bit_flips = int(entry.get("bit_flips", 1))
        if bit_flips < 1:
            raise ProfileError("{}.bit_flips must be >= 1".format(context))
        pairs.append({
            "trigger": {
                "address": _parse_int(
                    trigger["address"],
                    "{}.trigger.address".format(context),
                )
            },
            "corrupt_address": _parse_int(
                entry["corrupt_address"],
                "{}.corrupt_address".format(context),
            ),
            "bit_flips": bit_flips,
        })
    return TimedBitCorruptionConfig(pairs=pairs)


def _parse_instruction_skip_config(
    raw: Optional[Dict[str, Any]],
    *,
    bootloader_elf: Optional[str] = None,
    profile_path: Optional[Path] = None,
) -> Optional[InstructionSkipConfig]:
    """Parse instruction_skip_config from fault_sweep YAML block."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("instruction_skip_config: expected mapping")
    skip_count = int(raw.get("skip_count", 1))
    if skip_count < 1:
        raise ProfileError(
            "instruction_skip_config.skip_count: expected integer >= 1"
        )
    target_addresses_raw = raw.get("target_addresses", [])
    if not isinstance(target_addresses_raw, list):
        raise ProfileError("instruction_skip_config.target_addresses: expected list")
    target_addresses: List[Tuple[int, int]] = []
    for i, region in enumerate(target_addresses_raw):
        ctx = "instruction_skip_config.target_addresses[{}]".format(i)
        if not isinstance(region, dict):
            raise ProfileError("{}: expected mapping with start/end or symbol".format(ctx))
        has_symbol = "symbol" in region
        has_start = "start" in region
        has_end = "end" in region
        if has_symbol:
            if has_start or has_end:
                raise ProfileError(
                    "{}: use either symbol or start/end, not both".format(ctx)
                )
            symbol_query = str(_require(region, "symbol", ctx)).strip()
            if not symbol_query:
                raise ProfileError("{}.symbol: expected non-empty string".format(ctx))
            target_addresses.extend(
                _resolve_instruction_skip_symbol_targets(
                    symbol_query,
                    bootloader_elf=bootloader_elf,
                    profile_path=profile_path,
                    skip_count=skip_count,
                    ctx="{}.symbol".format(ctx),
                )
            )
            continue
        start = _parse_int(_require(region, "start", ctx), "{}.start".format(ctx))
        end = _parse_int(_require(region, "end", ctx), "{}.end".format(ctx))
        target_addresses.append((start, end))
    include_literal_pools = _parse_bool(
        raw.get("include_literal_pools", False),
        "fault_sweep.instruction_skip.include_literal_pools",
    )
    severity_model = str(raw.get("severity_model", "security") or "security").strip().lower()
    return InstructionSkipConfig(
        target_addresses=target_addresses,
        skip_count=skip_count,
        include_literal_pools=include_literal_pools,
        severity_model=severity_model,
    )



def _parse_probe_register(raw: Any, ctx: str) -> Tuple[str, int]:
    if isinstance(raw, int) and not isinstance(raw, bool):
        raw = "r{}".format(raw)
    text = str(raw or "r0").strip().lower()
    if not text:
        raise ProfileError("{}.return_register: expected non-empty register name".format(ctx))
    prefix = text[0]
    if prefix not in ("r", "w", "x"):
        raise ProfileError(
            "{}.return_register: expected rN/wN/xN register, got {!r}".format(ctx, text)
        )
    try:
        index = int(text[1:], 10)
    except Exception:
        raise ProfileError(
            "{}.return_register: expected numeric register suffix, got {!r}".format(
                ctx, text
            )
        )
    if not (0 <= index <= 15):
        raise ProfileError(
            "{}.return_register: expected register index 0-15, got {}".format(ctx, index)
        )
    return "r{}".format(index), index


def _parse_verification_probes(raw: Optional[Any]) -> List[VerificationProbeConfig]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("fault_sweep.verification_probes: expected list")
    probes: List[VerificationProbeConfig] = []
    seen_labels = set()
    for i, entry in enumerate(raw):
        ctx = "fault_sweep.verification_probes[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        symbol = str(_require(entry, "symbol", ctx)).strip()
        reg_name, reg_index = _parse_probe_register(
            entry.get("return_register", "r0"), ctx
        )
        success_value = _parse_int(
            entry.get("success_value", 0), "{}.success_value".format(ctx)
        )
        label = str(entry.get("label", symbol)).strip()
        if label in seen_labels:
            raise ProfileError(
                "{}.label: duplicate verification probe label {!r}".format(ctx, label)
            )
        seen_labels.add(label)
        probes.append(
            VerificationProbeConfig(
                symbol=symbol,
                return_register=reg_name,
                return_register_index=reg_index,
                success_value=success_value,
                label=label,
            )
        )
    return probes


def _parse_verification_bypass_probe(raw: Optional[Any]) -> List[VerificationProbeConfig]:
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.verification_bypass_probe: expected mapping")
    enabled = _parse_bool(
        raw.get("enabled", False),
        "fault_sweep.verification_bypass_probe.enabled",
    )
    if not enabled:
        return []
    probe_functions = raw.get("probe_functions", [])
    if not isinstance(probe_functions, list):
        raise ProfileError(
            "fault_sweep.verification_bypass_probe.probe_functions: expected list"
        )
    normalized: List[Dict[str, Any]] = []
    for i, entry in enumerate(probe_functions):
        ctx = "fault_sweep.verification_bypass_probe.probe_functions[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        normalized.append(
            {
                "symbol": _require(entry, "symbol", ctx),
                "return_register": entry.get("return_register", "r0"),
                "success_value": entry.get(
                    "success_value",
                    entry.get("expected_success_value", 0),
                ),
                "label": entry.get("label", entry.get("layer")),
            }
        )
    return _parse_verification_probes(normalized)


def _parse_verification_probe_config(raw: Dict[str, Any]) -> List[VerificationProbeConfig]:
    has_new = "verification_probes" in raw
    has_old = "verification_bypass_probe" in raw
    if has_new and has_old:
        raise ProfileError(
            "fault_sweep: use either verification_probes or "
            "verification_bypass_probe, not both"
        )
    if has_new:
        return _parse_verification_probes(raw.get("verification_probes"))
    if has_old:
        return _parse_verification_bypass_probe(raw.get("verification_bypass_probe"))
    return []


def _parse_function_return_probes(raw: Optional[Any]) -> List[FunctionReturnProbeConfig]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("fault_sweep.function_return_probes: expected list")
    probes: List[FunctionReturnProbeConfig] = []
    seen_labels = set()
    for i, entry in enumerate(raw):
        ctx = "fault_sweep.function_return_probes[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        symbol = str(_require(entry, "symbol", ctx)).strip()
        reg_name, reg_index = _parse_probe_register(
            entry.get("return_register", "r0"), ctx
        )
        label = str(entry.get("label", symbol)).strip()
        if label in seen_labels:
            raise ProfileError("{}.label: duplicate function return probe label {!r}".format(ctx, label))
        seen_labels.add(label)
        capture = str(entry.get("capture", "last") or "last").strip().lower()
        probes.append(
            FunctionReturnProbeConfig(
                symbol=symbol,
                return_register=reg_name,
                return_register_index=reg_index,
                label=label,
                capture=capture,
            )
        )
    return probes


def _parse_i2c_fault_config(raw):
    # type: (Optional[Dict[str, Any]]) -> Optional[I2CFaultConfig]
    """Parse i2c_fault_config block from fault_sweep YAML."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.i2c_fault_config: expected mapping")
    peripheral_name = str(raw.get("peripheral_name", "i2cProxy")).strip()
    if not peripheral_name:
        raise ProfileError("fault_sweep.i2c_fault_config.peripheral_name: must be non-empty")
    target_address = int(raw.get("target_address", 0))
    fault_types_raw = raw.get("fault_types", ["i2c_nack"])
    if not isinstance(fault_types_raw, list):
        fault_types_raw = [str(fault_types_raw)]
    else:
        fault_types_raw = [str(ft) for ft in fault_types_raw]
    fault_at = int(raw.get("fault_at_transaction", 0))
    seed = int(raw.get("fault_seed", 0))
    return I2CFaultConfig(
        peripheral_name=peripheral_name,
        target_address=target_address,
        fault_types=fault_types_raw,
        fault_at_transaction=fault_at,
        fault_seed=seed,
    )


def _parse_metadata_fault(raw):
    """Parse metadata_fault config from fault_sweep YAML block."""
    if raw is None:
        return MetadataFaultConfig()
    if isinstance(raw, bool):
        return MetadataFaultConfig(enabled=raw)
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.metadata_fault: expected mapping or bool")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.metadata_fault.enabled")
    raw_types = raw.get("fault_types")
    fault_types = None
    if raw_types is not None:
        if isinstance(raw_types, str):
            raw_types = [raw_types]
        if not isinstance(raw_types, list):
            raise ProfileError("metadata_fault.fault_types: expected list of strings")
        valid_mf_types = {"power_loss", "bit_corruption", "command_drop"}
        fault_types = []
        for ft in raw_types:
            ft_str = str(ft).strip()
            if ft_str not in valid_mf_types:
                raise ProfileError(
                    "fault_sweep.metadata_fault.fault_types: unsupported type "
                    "'{}'; only {} are supported".format(
                        ft_str,
                        sorted(valid_mf_types),
                    )
                )
            fault_types.append(ft_str)
        if not fault_types:
            raise ProfileError(
                "fault_sweep.metadata_fault.fault_types: expected non-empty list"
            )
    return MetadataFaultConfig(enabled=enabled, fault_types=fault_types)


def _parse_metadata_delta(raw: Optional[Dict[str, Any]]) -> MetadataDeltaConfig:
    """Parse metadata_delta config from fault_sweep YAML block.

    Example YAML::

        metadata_delta:
          fields:
            - address: 0x000FC010
              name: boot_count
              min_delta: 1
              max_delta: 1
            - address: 0x000FC014
              name: rollback_min_version
              min_delta: 0
              when: "marker_written"
    """
    if raw is None:
        return MetadataDeltaConfig()
    if isinstance(raw, bool):
        return MetadataDeltaConfig(enabled=raw)
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.metadata_delta: expected mapping or bool")
    raw_fields = raw.get("fields")
    if raw_fields is None:
        return MetadataDeltaConfig(
            enabled=_parse_bool(
                raw.get("enabled", False), "fault_sweep.metadata_delta.enabled"
            )
        )
    if not isinstance(raw_fields, list):
        raise ProfileError("fault_sweep.metadata_delta.fields: expected list")
    fields: List[MetadataDeltaFieldConfig] = []
    for i, entry in enumerate(raw_fields):
        if not isinstance(entry, dict):
            raise ProfileError(
                "fault_sweep.metadata_delta.fields[{}]: expected mapping".format(i)
            )
        address_raw = entry.get("address")
        if address_raw is None:
            raise ProfileError(
                "fault_sweep.metadata_delta.fields[{}]: 'address' is required".format(i)
            )
        address = _parse_int(address_raw, "metadata_delta.fields[{}].address".format(i))
        name = str(entry.get("name", "field_{}".format(i))).strip()
        min_delta = entry.get("min_delta")
        max_delta = entry.get("max_delta")
        when = entry.get("when")
        if min_delta is not None:
            min_delta = int(min_delta)
        if max_delta is not None:
            max_delta = int(max_delta)
        if when is not None:
            when = str(when).strip()
            valid_when = {"always", "marker_written", "marker_not_written"}
            if when not in valid_when:
                raise ProfileError(
                    "fault_sweep.metadata_delta.fields[{}].when: expected one of {}, "
                    "got '{}'".format(i, sorted(valid_when), when)
                )
        fields.append(MetadataDeltaFieldConfig(
            address=address,
            name=name,
            min_delta=min_delta,
            max_delta=max_delta,
            when=when,
        ))
    enabled = _parse_bool(
        raw.get("enabled", len(fields) > 0),
        "fault_sweep.metadata_delta.enabled",
    )
    return MetadataDeltaConfig(enabled=enabled, fields=fields)


def _parse_config_checks(raw: Optional[List[Any]]) -> List[ConfigCheck]:
    """Parse config_checks from success_criteria YAML block."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("success_criteria.config_checks: expected list")
    checks: List[ConfigCheck] = []
    for i, entry in enumerate(raw):
        ctx = "success_criteria.config_checks[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        address = _parse_int(
            _require(entry, "address", ctx), "{}.address".format(ctx)
        )
        expected: Optional[int] = None
        if "expected" in entry:
            expected = _parse_int(entry["expected"], "{}.expected".format(ctx))
        nonzero = _parse_bool(
            entry.get("nonzero", False), "{}.nonzero".format(ctx)
        )
        mask: Optional[int] = None
        if "mask" in entry:
            mask = _parse_int(entry["mask"], "{}.mask".format(ctx))
        expected_masked: Optional[int] = None
        if "expected_masked" in entry:
            expected_masked = _parse_int(
                entry["expected_masked"], "{}.expected_masked".format(ctx)
            )
        range_min: Optional[int] = None
        range_max: Optional[int] = None
        if "range" in entry:
            rng = entry["range"]
            if isinstance(rng, dict):
                if "min" in rng:
                    range_min = _parse_int(rng["min"], "{}.range.min".format(ctx))
                if "max" in rng:
                    range_max = _parse_int(rng["max"], "{}.range.max".format(ctx))
            else:
                raise ProfileError("{}.range: expected mapping".format(ctx))
        if range_min is not None and range_max is not None and range_min > range_max:
            raise ProfileError("{}.range: min must be <= max".format(ctx))
        if (mask is None) != (expected_masked is None):
            raise ProfileError(
                "{}: mask and expected_masked must be configured together".format(ctx)
            )
        if expected is None and not nonzero and mask is None and range_min is None and range_max is None:
            raise ProfileError(
                "{}: must specify at least one of expected, nonzero, mask+expected_masked, or range".format(
                    ctx
                )
            )
        checks.append(ConfigCheck(
            address=address,
            expected=expected,
            nonzero=nonzero,
            mask=mask,
            expected_masked=expected_masked,
            range_min=range_min,
            range_max=range_max,
        ))
    return checks


def _parse_boot_register_values(
    raw: Optional[Dict[str, Any]],
) -> Optional[Dict[str, int]]:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("success_criteria.boot_register_values: expected mapping")
    result: Dict[str, int] = {}
    for name, val in raw.items():
        result[str(name)] = _parse_int(val, "boot_register_values.{}".format(name))
    return result


def _parse_boot_register_pre_writes_list(
    raw: Optional[List[Any]],
) -> List[BootRegisterPreWrite]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("boot_register_pre_writes: expected list")
    writes: List[BootRegisterPreWrite] = []
    for i, entry in enumerate(raw):
        ctx = "boot_register_pre_writes[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        address = _parse_int(
            _require(entry, "address", ctx), "{}.address".format(ctx)
        )
        value = _parse_int(
            _require(entry, "value", ctx), "{}.value".format(ctx)
        )
        writes.append(BootRegisterPreWrite(address=address, value=value))
    return writes


def _parse_boot_registers_list(
    raw: Optional[List[Any]],
) -> List[BootRegisterDef]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("boot_registers: expected list")
    regs: List[BootRegisterDef] = []
    for i, entry in enumerate(raw):
        ctx = "boot_registers[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        address = _parse_int(
            _require(entry, "address", ctx), "{}.address".format(ctx)
        )
        name = str(_require(entry, "name", ctx))
        regs.append(BootRegisterDef(address=address, name=name))
    return regs


def _parse_write_order_constraints_list(
    raw: Optional[List[Any]],
) -> List[WriteOrderConstraint]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("write_order_constraints: expected list")
    constraints: List[WriteOrderConstraint] = []
    for i, entry in enumerate(raw):
        ctx = "write_order_constraints[{}]".format(i)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        first = entry.get("first")
        then = entry.get("then")
        if not isinstance(first, dict) or not isinstance(then, dict):
            raise ProfileError("{}: 'first' and 'then' must be mappings".format(ctx))
        constraints.append(WriteOrderConstraint(
            first_start=_parse_int(
                _require(first, "start", ctx + ".first"), ctx + ".first.start"
            ),
            first_size=_parse_int(
                _require(first, "size", ctx + ".first"), ctx + ".first.size"
            ),
            then_start=_parse_int(
                _require(then, "start", ctx + ".then"), ctx + ".then.start"
            ),
            then_size=_parse_int(
                _require(then, "size", ctx + ".then"), ctx + ".then.size"
            ),
            label=str(entry.get("label", "")),
            bidirectional=_parse_bool(
                entry.get("bidirectional", False),
                "{}.bidirectional".format(ctx),
            ),
        ))
    return constraints


def _parse_nvs_region(raw: Optional[Dict[str, Any]]) -> Optional[NvsRegionConfig]:
    """Parse nvs_region from profile YAML."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("nvs_region: expected mapping")
    address = _parse_int(
        _require(raw, "address", "nvs_region"), "nvs_region.address"
    )
    size = _parse_int(
        _require(raw, "size", "nvs_region"), "nvs_region.size"
    )
    if size <= 0:
        raise ProfileError("nvs_region.size: must be > 0, got {}".format(size))
    snapshot = raw.get("snapshot")
    if snapshot is not None:
        snapshot = str(snapshot)
    return NvsRegionConfig(address=address, size=size, snapshot=snapshot)


def _parse_nvs_corruption(raw: Optional[Dict[str, Any]]) -> NvsCorruptionConfig:
    """Parse nvs_corruption config from fault_sweep YAML block."""
    if raw is None:
        return NvsCorruptionConfig()
    if isinstance(raw, bool):
        return NvsCorruptionConfig(enabled=raw)
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.nvs_corruption: expected mapping or bool")
    enabled = _parse_bool(raw.get("enabled", False), "fault_sweep.nvs_corruption.enabled")
    modes = raw.get("modes")
    if modes is not None:
        if isinstance(modes, str):
            modes = [modes]
        if not isinstance(modes, list):
            raise ProfileError("nvs_corruption.modes: expected list of strings")
        valid_modes = {"bit_flip", "partial_erase", "truncate", "truncation", "scramble"}
        normalized = []
        for m in modes:
            if m not in valid_modes:
                raise ProfileError(
                    "nvs_corruption.modes: unknown mode '{}', expected one of {}".format(
                        m, sorted(valid_modes)
                    )
                )
            # Normalize 'truncation' -> 'truncate' for consistency with fault_inject.py.
            normalized.append("truncate" if m == "truncation" else m)
        modes = normalized
    bit_flip_counts = raw.get("bit_flip_counts")
    if bit_flip_counts is not None:
        if not isinstance(bit_flip_counts, list):
            raise ProfileError(
                "nvs_corruption.bit_flip_counts: expected list of integers"
            )
        bit_flip_counts = [int(x) for x in bit_flip_counts]
        for c in bit_flip_counts:
            if c < 1:
                raise ProfileError(
                    "nvs_corruption.bit_flip_counts: values must be >= 1"
                )
    erase_fractions = raw.get("erase_fractions")
    if erase_fractions is not None:
        if not isinstance(erase_fractions, list):
            raise ProfileError(
                "nvs_corruption.erase_fractions: expected list of floats"
            )
        erase_fractions = [float(x) for x in erase_fractions]
        for f in erase_fractions:
            if not (0.0 < f <= 1.0):
                raise ProfileError(
                    "nvs_corruption.erase_fractions: values must be in (0.0, 1.0]"
                )
    truncate_offsets = raw.get("truncate_offsets")
    if truncate_offsets is not None:
        if not isinstance(truncate_offsets, list):
            raise ProfileError(
                "nvs_corruption.truncate_offsets: expected list of integers or null"
            )
        truncate_offsets = [
            int(x) if x is not None else None for x in truncate_offsets
        ]
        for offset in truncate_offsets:
            if offset is not None and offset < 0:
                raise ProfileError(
                    "nvs_corruption.truncate_offsets: values must be "
                    "non-negative integers or null"
                )
    seed = int(raw.get("seed", 0))
    return NvsCorruptionConfig(
        enabled=enabled,
        modes=modes,
        bit_flip_counts=bit_flip_counts,
        erase_fractions=erase_fractions,
        truncate_offsets=truncate_offsets,
        seed=seed,
    )


def _parse_security_policy(raw: Optional[Dict[str, Any]]) -> SecurityPolicyConfig:
    if raw is None:
        return SecurityPolicyConfig()
    if not isinstance(raw, dict):
        raise ProfileError("security_policy: expected mapping")
    anti_rollback = _parse_bool(
        raw.get("anti_rollback", False), "security_policy.anti_rollback"
    )
    minimum_version_raw = raw.get("minimum_version")
    minimum_version: Optional[int] = None
    if minimum_version_raw is not None:
        minimum_version = int(minimum_version_raw)
        if minimum_version < 0:
            raise ProfileError(
                "security_policy.minimum_version: expected non-negative integer, got {}".format(
                    minimum_version
                )
            )
    toctou_protection = _parse_bool(
        raw.get("toctou_protection", False),
        "security_policy.toctou_protection",
    )
    return SecurityPolicyConfig(
        anti_rollback=anti_rollback,
        minimum_version=minimum_version,
        toctou_protection=toctou_protection,
    )

def _parse_residual_image(
    raw: Optional[Dict[str, Any]],
    slots: Dict[str, SlotConfig],
    images: Optional[Dict[str, str]] = None,
) -> Optional[ResidualImageConfig]:
    """Parse the optional residual_image section from profile YAML."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("residual_image: expected mapping")
    slot = str(raw.get("slot", "")).strip()
    if not slot:
        raise ProfileError("residual_image.slot: required field")
    if slot not in slots:
        raise ProfileError(
            "residual_image.slot: '{}' not found in memory.slots. "
            "Available: {}".format(slot, sorted(slots.keys()))
        )
    prior_image = raw.get("prior_image")
    if prior_image:
        prior_image = str(prior_image)
    else:
        prior_image = None
    fill_pattern: Optional[int] = None
    if "fill_pattern" in raw:
        fill_pattern = _parse_int(raw["fill_pattern"], "residual_image.fill_pattern")
    # At least one of prior_image or fill_pattern is required.
    if not prior_image and fill_pattern is None:
        raise ProfileError(
            "residual_image: at least one of prior_image or fill_pattern is required"
        )
    actual_image = None
    if images is not None:
        actual_image = images.get(slot)
        if actual_image is not None:
            actual_image = str(actual_image).strip()
    if images is not None and not actual_image:
        raise ProfileError(
            "residual_image.slot: '{}' has no image configured in the images "
            "section. residual_image requires an actual image in the target "
            "slot to overwrite the residual data.".format(slot)
        )
    return ResidualImageConfig(
        slot=slot,
        prior_image=prior_image,
        fill_pattern=fill_pattern,
    )


def _parse_fault_distribution(raw: Optional[Dict[str, Any]]) -> Optional[FaultDistributionConfig]:
    """Parse fault_distribution config from fault_sweep YAML block."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.fault_distribution: expected mapping")
    mode = str(raw.get("mode", "uniform")).strip().lower()
    if mode not in ("uniform", "clustered"):
        raise ProfileError(
            "fault_sweep.fault_distribution.mode: must be 'uniform' or 'clustered', got {!r}".format(
                mode
            )
        )
    cluster_start = 0
    cluster_end = 0
    if mode == "clustered":
        cluster_sectors = raw.get("cluster_sectors")
        if cluster_sectors is not None:
            if not isinstance(cluster_sectors, list) or len(cluster_sectors) != 2:
                raise ProfileError(
                    "fault_sweep.fault_distribution.cluster_sectors: expected [start, end] pair"
                )
            cluster_start = _parse_int(cluster_sectors[0], "fault_distribution.cluster_sectors[0]")
            cluster_end = _parse_int(cluster_sectors[1], "fault_distribution.cluster_sectors[1]")
        else:
            cluster_start = _parse_int(
                raw.get("cluster_start", 0), "fault_distribution.cluster_start"
            )
            cluster_end = _parse_int(
                raw.get("cluster_end", 0), "fault_distribution.cluster_end"
            )
        if cluster_end <= cluster_start:
            raise ProfileError(
                "fault_sweep.fault_distribution: cluster_end (0x{:X}) must be > cluster_start (0x{:X})".format(
                    cluster_end, cluster_start
                )
            )
    flip_in = float(raw.get("flip_probability_in_cluster", 0.1))
    flip_out = float(raw.get("flip_probability_outside", 0.001))
    seed = int(raw.get("seed", 0))
    return FaultDistributionConfig(
        mode=mode,
        cluster_start=cluster_start,
        cluster_end=cluster_end,
        flip_probability_in_cluster=flip_in,
        flip_probability_outside=flip_out,
        seed=seed,
    )


def _normalize_state_fuzzer_metadata_model(raw: Any) -> Any:
    if raw is None:
        return "ab_replica"
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise ProfileError("state_fuzzer.metadata_model: expected non-empty string or mapping")
        return text
    if not isinstance(raw, dict):
        raise ProfileError("state_fuzzer.metadata_model: expected string or mapping")

    base_address = _parse_int(
        _require(raw, "base_address", "state_fuzzer.metadata_model"),
        "state_fuzzer.metadata_model.base_address",
    )
    fields_raw = raw.get("fields")
    if not isinstance(fields_raw, list) or not fields_raw:
        raise ProfileError("state_fuzzer.metadata_model.fields: expected non-empty list")

    normalized_fields: List[Dict[str, Any]] = []
    crc_fields = 0
    for i, entry in enumerate(fields_raw):
        if not isinstance(entry, dict):
            raise ProfileError(
                "state_fuzzer.metadata_model.fields[{}]: expected mapping".format(i)
            )
        name = str(_require(entry, "name", "state_fuzzer.metadata_model.fields[{}]".format(i))).strip()
        if not name:
            raise ProfileError(
                "state_fuzzer.metadata_model.fields[{}].name: expected non-empty string".format(i)
            )
        offset = _parse_int(
            _require(entry, "offset", "state_fuzzer.metadata_model.fields[{}]".format(i)),
            "state_fuzzer.metadata_model.fields[{}].offset".format(i),
        )
        size = _parse_int(
            _require(entry, "size", "state_fuzzer.metadata_model.fields[{}]".format(i)),
            "state_fuzzer.metadata_model.fields[{}].size".format(i),
        )
        if offset < 0:
            raise ProfileError(
                "state_fuzzer.metadata_model.fields[{}].offset: expected >= 0".format(i)
            )
        if size <= 0:
            raise ProfileError(
                "state_fuzzer.metadata_model.fields[{}].size: expected > 0".format(i)
            )

        normalized: Dict[str, Any] = {
            "name": name,
            "offset": offset,
            "size": size,
        }
        if "type" in entry:
            field_type = str(entry.get("type", "")).strip()
            if not field_type:
                raise ProfileError(
                    "state_fuzzer.metadata_model.fields[{}].type: expected non-empty string".format(i)
                )
            normalized["type"] = field_type
            if field_type == "computed_crc32":
                crc_fields += 1
        if "valid" in entry:
            valid_raw = entry.get("valid")
            if not isinstance(valid_raw, list) or not valid_raw:
                raise ProfileError(
                    "state_fuzzer.metadata_model.fields[{}].valid: expected non-empty list".format(i)
                )
            normalized["valid"] = [
                _parse_int(v, "state_fuzzer.metadata_model.fields[{}].valid".format(i))
                for v in valid_raw
            ]
        if "valid_range" in entry:
            range_raw = entry.get("valid_range")
            if not isinstance(range_raw, list) or len(range_raw) != 2:
                raise ProfileError(
                    "state_fuzzer.metadata_model.fields[{}].valid_range: expected [min, max]".format(i)
                )
            lo = _parse_int(
                range_raw[0],
                "state_fuzzer.metadata_model.fields[{}].valid_range[0]".format(i),
            )
            hi = _parse_int(
                range_raw[1],
                "state_fuzzer.metadata_model.fields[{}].valid_range[1]".format(i),
            )
            if hi < lo:
                raise ProfileError(
                    "state_fuzzer.metadata_model.fields[{}].valid_range: max must be >= min".format(i)
                )
            normalized["valid_range"] = [lo, hi]
        normalized_fields.append(normalized)

    # Check for overlapping fields.
    sorted_fields = sorted(normalized_fields, key=lambda f: f["offset"])
    for j in range(1, len(sorted_fields)):
        prev = sorted_fields[j - 1]
        curr = sorted_fields[j]
        if curr["offset"] < prev["offset"] + prev["size"]:
            raise ProfileError(
                "state_fuzzer.metadata_model: fields '{}' and '{}' overlap".format(
                    prev["name"], curr["name"]
                )
            )

    if crc_fields > 1:
        raise ProfileError("state_fuzzer.metadata_model: at most one computed_crc32 field is supported")
    if crc_fields == 1:
        model_size = max(
            field["offset"] + field["size"] for field in normalized_fields
        )
        crc_field = next(
            field for field in normalized_fields
            if field.get("type") == "computed_crc32"
        )
        if crc_field["offset"] + crc_field["size"] != model_size:
            raise ProfileError(
                "state_fuzzer.metadata_model: computed_crc32 field must be the final field"
            )

    normalized_model: Dict[str, Any] = {
        "base_address": base_address,
        "fields": normalized_fields,
    }
    if "fill" in raw:
        fill = _parse_int(raw.get("fill"), "state_fuzzer.metadata_model.fill")
        if not 0 <= fill <= 0xFF:
            raise ProfileError("state_fuzzer.metadata_model.fill: expected byte value 0..255")
        normalized_model["fill"] = fill
    return normalized_model


def _parse_state_fuzzer(raw: Optional[Dict[str, Any]]) -> StateFuzzerConfig:
    if raw is None:
        return StateFuzzerConfig()
    if not isinstance(raw, dict):
        raise ProfileError("state_fuzzer: expected mapping")
    iterations = _parse_int(raw.get("iterations", 100), "state_fuzzer.iterations")
    if iterations <= 0:
        raise ProfileError("state_fuzzer.iterations: expected integer > 0")
    return StateFuzzerConfig(
        enabled=_parse_bool(raw.get("enabled", False), "state_fuzzer.enabled"),
        metadata_model=_normalize_state_fuzzer_metadata_model(raw.get("metadata_model")),
        iterations=iterations,
        seed=_parse_int(raw.get("seed", 0), "state_fuzzer.seed"),
    )


def _parse_state_probe(raw: Optional[Any]) -> Optional[StateProbeConfig]:
    if raw is None:
        return None
    if isinstance(raw, str):
        text = raw.strip()
        return StateProbeConfig(script=text) if text else None
    if not isinstance(raw, dict):
        raise ProfileError("state_probe: expected mapping or string path")
    script = str(_require(raw, "script", "state_probe")).strip()
    if not script:
        raise ProfileError("state_probe.script: expected non-empty path")
    required_paths_raw = raw.get("required_paths", [])
    if isinstance(required_paths_raw, str):
        required_paths = [required_paths_raw.strip()] if required_paths_raw.strip() else []
    elif isinstance(required_paths_raw, list):
        required_paths = []
        for i, entry in enumerate(required_paths_raw):
            value = str(entry).strip()
            if not value:
                raise ProfileError(
                    "state_probe.required_paths[{}]: expected non-empty string".format(i)
                )
            required_paths.append(value)
    else:
        raise ProfileError("state_probe.required_paths: expected string or list of strings")
    contract_version = int(raw.get("contract_version", 1))
    if contract_version < 1:
        raise ProfileError("state_probe.contract_version: expected integer >= 1")
    format_name = str(raw.get("format", "tardigrade.semantic-state/v1")).strip()
    if not format_name:
        raise ProfileError("state_probe.format: expected non-empty string")
    return StateProbeConfig(
        script=script,
        format=format_name,
        contract_version=contract_version,
        required_paths=required_paths,
    )


_EXPECT_BOOLEAN_FIELDS = frozenset(
    {
        "should_find_issues",
        "allow_semantic_only_issues",
        "allow_control_only_issues",
    }
)
_EXPECT_LIST_FIELDS = frozenset(
    {"required_issue_reasons", "ignored_issue_fault_types"}
)
_EXPECT_KEYS = frozenset(
    set(_EXPECT_BOOLEAN_FIELDS) | set(_EXPECT_LIST_FIELDS) | {"control_outcome"}
)


def _parse_expect_values(
    raw: Any,
    *,
    context: str,
    partial: bool,
) -> Dict[str, Any]:
    """Validate and normalize an expect mapping.

    ``partial`` preserves omission for initial-state overrides; the top-level
    mapping instead receives the documented defaults.
    """
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ProfileError("{}: expected mapping".format(context))

    parsed: Dict[str, Any] = {}
    for field_name in sorted(_EXPECT_BOOLEAN_FIELDS):
        if field_name not in raw:
            if not partial:
                parsed[field_name] = False
            continue
        value = raw[field_name]
        if type(value) is not bool:
            raise ProfileError(
                "{}.{}: expected boolean, got {}".format(
                    context, field_name, type(value).__name__
                )
            )
        parsed[field_name] = value

    if "control_outcome" in raw:
        control_outcome = raw["control_outcome"]
        if not isinstance(control_outcome, str) or control_outcome not in DEVICE_BOOT_OUTCOMES:
            raise ProfileError(
                "{}.control_outcome: expected one of {}, got {!r}".format(
                    context,
                    ", ".join(sorted(DEVICE_BOOT_OUTCOMES)),
                    control_outcome,
                )
            )
        parsed["control_outcome"] = control_outcome
    elif not partial:
        parsed["control_outcome"] = "success"

    for field_name in sorted(_EXPECT_LIST_FIELDS):
        if field_name not in raw:
            if not partial:
                parsed[field_name] = []
            continue
        values = raw[field_name]
        if not isinstance(values, list):
            raise ProfileError(
                "{}.{}: expected list of non-empty strings".format(
                    context, field_name
                )
            )
        normalized: List[str] = []
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value.strip():
                raise ProfileError(
                    "{}.{}[{}]: expected non-empty string".format(
                        context, field_name, index
                    )
                )
            normalized.append(value.strip())
        parsed[field_name] = normalized

    return parsed


def _parse_expect(raw: Optional[Dict[str, Any]]) -> ExpectConfig:
    parsed = _parse_expect_values(raw, context="expect", partial=False)
    return ExpectConfig(**parsed)


def _parse_update_trigger_config(raw: Optional[Any]) -> Tuple[Optional[UpdateTrigger], bool]:
    if raw is None:
        return None, False
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value == "auto":
            return None, True
        raise ProfileError(
            "update_trigger: expected mapping or 'auto', got {!r}".format(raw)
        )
    if not isinstance(raw, dict):
        raise ProfileError(
            "update_trigger: expected mapping or 'auto', got {}".format(
                type(raw).__name__
            )
        )
    trigger_type = str(_require(raw, "type", "update_trigger"))
    slot = str(_require(raw, "slot", "update_trigger"))
    fields: Dict[str, Any] = {}
    for k, v in raw.items():
        if k not in ("type", "slot"):
            fields[k] = v
    return UpdateTrigger(type=trigger_type, slot=slot, fields=fields), False


def _parse_update_trigger(raw: Optional[Any]) -> Optional[UpdateTrigger]:
    trigger, _auto = _parse_update_trigger_config(raw)
    return trigger


def _normalize_fault_types(raw: Any, field_name: str) -> List[str]:
    if raw is None:
        fault_types = ["power_loss"]
    elif isinstance(raw, list):
        if not raw:
            raise ProfileError("{}: expected non-empty list".format(field_name))
        fault_types = [str(ft) for ft in raw]
    else:
        fault_types = [str(raw)]

    normalized: List[str] = []
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            raise ProfileError(
                "{}: unknown fault type '{}'. Known injectable types: {}".format(
                    field_name,
                    ft,
                    sorted(IMPLEMENTED_FAULT_TYPES),
                )
            )
        if ft in CLASSIFICATION_ONLY_FAULT_TYPES:
            raise ProfileError(
                "{}: fault type '{}' is a classification label, not an "
                "injectable mechanism".format(field_name, ft)
            )
        if ft not in IMPLEMENTED_FAULT_TYPES:
            raise ProfileError(
                "{}: fault type '{}' is not implemented".format(field_name, ft)
            )
        if ft in normalized:
            raise ProfileError(
                "{}: duplicate fault type '{}'".format(field_name, ft)
            )
        normalized.append(ft)

    return normalized


def _parse_rc_injection_config(raw: Optional[Any]) -> RcInjectionConfig:
    """Parse the target-configurable return-code injection block."""
    if raw is None:
        return RcInjectionConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.rc_injection_config: expected mapping")
    unknown = sorted(set(raw) - {"symbols", "return_value", "return_register", "require_applied"})
    if unknown:
        raise ProfileError(
            "fault_sweep.rc_injection_config: unknown field(s): {}".format(
                ", ".join(str(key) for key in unknown)
            )
        )
    symbols = raw.get("symbols", ["flash_area_write"])
    if not isinstance(symbols, list):
        raise ProfileError(
            "fault_sweep.rc_injection_config.symbols: expected non-empty list"
        )
    parsed_symbols = []
    for index, symbol in enumerate(symbols):
        if not isinstance(symbol, str) or not symbol.strip():
            raise ProfileError(
                "fault_sweep.rc_injection_config.symbols[{}]: expected non-empty string".format(index)
            )
        parsed_symbols.append(symbol.strip())
    value = raw.get("return_value", -5)
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_value: expected 32-bit integer"
            ) from exc
    register = raw.get("return_register", 0)
    if isinstance(register, str):
        try:
            register = int(register, 0)
        except ValueError as exc:
            raise ProfileError(
                "fault_sweep.rc_injection_config.return_register: expected integer 0..15"
            ) from exc
    return RcInjectionConfig(
        symbols=parsed_symbols,
        return_value=value,
        return_register=register,
        require_applied=_parse_bool(
            raw.get("require_applied", True),
            "fault_sweep.rc_injection_config.require_applied",
        ),
    )


def _parse_update_sequence(
    raw: Optional[Any],
    *,
    images: Dict[str, str],
    success_criteria: SuccessCriteria,
    fault_sweep: FaultSweepConfig,
) -> List[UpdatePhase]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise ProfileError("update_sequence: expected non-empty list of phase mappings")

    phases: List[UpdatePhase] = []
    seen_names: set[str] = set()
    for idx, entry in enumerate(raw):
        ctx = "update_sequence[{}]".format(idx)
        if not isinstance(entry, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        name = str(_require(entry, "name", ctx)).strip()
        if not name:
            raise ProfileError("{}.name: expected non-empty string".format(ctx))
        if name in seen_names:
            raise ProfileError("update_sequence: duplicate phase name '{}'".format(name))
        seen_names.add(name)

        raw_images = entry.get("images", {})
        if raw_images is None:
            raw_images = {}
        if not isinstance(raw_images, dict):
            raise ProfileError("{}.images: expected mapping".format(ctx))
        phase_images = {str(k): str(v) for k, v in raw_images.items()}

        phase_success = (
            _parse_success_criteria(entry.get("success_criteria"))
            if "success_criteria" in entry
            else success_criteria
        )
        phase_boot_cycles = int(entry.get("boot_cycles", fault_sweep.boot_cycles))
        if phase_boot_cycles < 1:
            raise ProfileError("{}.boot_cycles: expected integer >= 1".format(ctx))
        if "boot_cycle_hook" in entry:
            phase_hook_raw = entry.get("boot_cycle_hook")
            if phase_hook_raw is None:
                phase_hook = None
            else:
                phase_hook = str(phase_hook_raw).strip()
                if not phase_hook:
                    phase_hook = None
        else:
            phase_hook = fault_sweep.boot_cycle_hook
        expected_rollback_at_cycle = entry.get(
            "expected_rollback_at_cycle",
            fault_sweep.expected_rollback_at_cycle,
        )
        if expected_rollback_at_cycle is not None:
            expected_rollback_at_cycle = int(expected_rollback_at_cycle)
            if expected_rollback_at_cycle < 1:
                raise ProfileError(
                    "{}.expected_rollback_at_cycle: expected integer >= 1".format(ctx)
                )
        phase_fault_types = _normalize_fault_types(
            entry.get("fault_types", list(fault_sweep.fault_types)),
            "{}.fault_types".format(ctx),
        )
        phase_setup_script = entry.get("setup_script")
        if phase_setup_script is not None:
            phase_setup_script = str(phase_setup_script).strip()
            if not phase_setup_script:
                raise ProfileError("{}.setup_script: expected non-empty path".format(ctx))
        phases.append(
            UpdatePhase(
                name=name,
                description=str(entry.get("description", "")),
                images=phase_images,
                setup_script=phase_setup_script,
                pre_boot_state=_parse_pre_boot_state(entry.get("pre_boot_state")),
                success_criteria=phase_success,
                boot_cycles=phase_boot_cycles,
                boot_cycle_hook=phase_hook,
                expected_rollback_at_cycle=expected_rollback_at_cycle,
                fault_injection=_parse_bool(
                    entry.get("fault_injection", False),
                    "{}.fault_injection".format(ctx),
                ),
                fault_types=phase_fault_types,
            )
        )

    faulted_indices = [idx for idx, phase in enumerate(phases) if phase.fault_injection]
    if len(faulted_indices) != 1:
        raise ProfileError(
            "update_sequence: expected exactly one phase with fault_injection=true, got {}".format(
                len(faulted_indices)
            )
        )
    faulted_idx = faulted_indices[0]
    if faulted_idx != len(phases) - 1:
        raise ProfileError(
            "update_sequence: the fault_injection phase must currently be the last phase"
        )

    current_images = dict(images)
    if not current_images and not phases[0].images:
        raise ProfileError(
            "update_sequence[0]: no initial images available; add top-level images or phase images"
        )
    for idx, phase in enumerate(phases):
        start_images = dict(current_images)
        start_images.update(phase.images)
        if not start_images:
            raise ProfileError(
                "update_sequence[{}]: phase has no effective start images".format(idx)
            )
        phase.start_images = start_images
        current_images = dict(start_images)
        expected_name = phase.success_criteria.expected_image
        is_last = idx == len(phases) - 1
        if expected_name:
            if expected_name not in start_images:
                raise ProfileError(
                    "update_sequence[{}].success_criteria.expected_image='{}' "
                    "is not present in the phase images".format(idx, expected_name)
                )
            current_images["exec"] = start_images[expected_name]
        elif not is_last and not phase.fault_injection:
            # Clean phases that feed into subsequent phases MUST declare
            # expected_image so the next phase knows which image ended up
            # in the exec slot.  Without it, phase N+1 hashes against
            # stale images.
            raise ProfileError(
                "update_sequence[{}] ('{}'): clean phases that precede another phase "
                "must set success_criteria.expected_image so the next phase can "
                "infer the post-swap exec image".format(idx, phase.name)
            )

        # Validate image paths exist at parse time.
        for slot_name, img_path in phase.images.items():
            if not Path(img_path).is_file():
                raise ProfileError(
                    "update_sequence[{}].images.{}: file not found: {}".format(
                        idx, slot_name, img_path
                    )
                )
        if phase.boot_cycle_hook and not Path(phase.boot_cycle_hook).is_file():
            raise ProfileError(
                "update_sequence[{}].boot_cycle_hook: file not found: {}".format(
                    idx, phase.boot_cycle_hook
                )
            )

    return phases


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


def _parse_initial_states(raw: Optional[List[Any]]) -> List[InitialStateConfig]:
    """Parse the initial_states list from a profile YAML."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("initial_states: expected list of state definitions")
    states: List[InitialStateConfig] = []
    seen_names: set = set()
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ProfileError("initial_states[{}]: expected mapping".format(idx))
        name = _parse_profile_identifier(
            entry.get("name"),
            "initial_states[{}].name".format(idx),
        )
        if name in seen_names:
            raise ProfileError("initial_states: duplicate name '{}'".format(name))
        seen_names.add(name)
        description = str(entry.get("description", ""))
        pre_boot = _parse_pre_boot_state(entry.get("pre_boot_state"))
        setup_script = entry.get("setup_script")
        if setup_script is not None:
            setup_script = str(setup_script)
        trigger = _parse_update_trigger(entry.get("update_trigger"))
        expect_overrides = _parse_expect_values(
            entry.get("expect"),
            context="initial_states[{}].expect".format(idx),
            partial=True,
        )
        parsed_pre_boot: Optional[List[PreBootWrite]] = None
        if "pre_boot_state" in entry:
            parsed_pre_boot = pre_boot
        states.append(InitialStateConfig(name=name, description=description,
            pre_boot_state=parsed_pre_boot, setup_script=setup_script,
            update_trigger=trigger, expect_overrides=expect_overrides))
    return states


def _parse_boundary_campaigns(raw: Optional[List[Any]]) -> List[BoundaryCampaign]:
    """Parse top-level deterministic counter boundary campaigns."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("boundary_campaigns: expected list of campaign definitions")
    campaigns: List[BoundaryCampaign] = []
    names: set[str] = set()
    for index, entry in enumerate(raw):
        try:
            campaign = parse_boundary_campaign(entry, index)
        except BoundaryCampaignError as exc:
            raise ProfileError(str(exc)) from exc
        if campaign.name in names:
            raise ProfileError("boundary_campaigns: duplicate name '{}'".format(campaign.name))
        names.add(campaign.name)
        campaigns.append(campaign)
    return campaigns


def _boundary_initial_states(
    campaigns: List[BoundaryCampaign],
    existing: List[InitialStateConfig],
) -> List[InitialStateConfig]:
    """Materialize campaigns as ordinary named initial-state runs."""
    names = {state.name for state in existing}
    generated: List[InitialStateConfig] = []
    for campaign in campaigns:
        for value in resolve_boundary_values(campaign):
            name = "{}__{}".format(campaign.name, value)
            if name in names:
                raise ProfileError(
                    "boundary campaign run name '{}' conflicts with an initial state".format(name)
                )
            names.add(name)
            generated.append(
                InitialStateConfig(
                    name=name,
                    description="{}={} (logical capacity {})".format(
                        campaign.parameter, value, campaign.logical_capacity
                    ),
                    boundary_campaign=campaign,
                    boundary_value=value,
                    boundary_previous_value=(value - 1 if value > 0 else None),
                )
            )
    return generated


def _parse_component(
    raw: Dict[str, Any],
    idx: int,
    *,
    profile_path: Optional[Path] = None,
) -> ComponentConfig:
    """Parse a single component definition from the components list."""
    ctx = "multi_component.components[{}]".format(idx)
    name = _parse_profile_identifier(
        _require(raw, "name", ctx),
        "{}.name".format(ctx),
    )

    platform = str(_require(raw, "platform", ctx))

    bootloader = _require(raw, "bootloader", ctx)
    bootloader_elf = str(_require(bootloader, "elf", "{}.bootloader".format(ctx)))
    bootloader_entry = _parse_int(
        _require(bootloader, "entry", "{}.bootloader".format(ctx)),
        "{}.bootloader.entry".format(ctx),
    )

    memory = _parse_memory(_require(raw, "memory", ctx))

    images: Dict[str, str] = {}
    raw_images = raw.get("images", {})
    if isinstance(raw_images, dict):
        images = {str(k): str(v) for k, v in raw_images.items()}

    pre_boot_state = _parse_pre_boot_state(raw.get("pre_boot_state"))
    setup_script = raw.get("setup_script")
    if setup_script is not None:
        setup_script = str(setup_script)

    extra_peripherals_raw = raw.get("extra_peripherals")
    extra_peripherals: Optional[List[str]] = None
    if extra_peripherals_raw is not None:
        if isinstance(extra_peripherals_raw, list):
            extra_peripherals = [str(p) for p in extra_peripherals_raw]
        else:
            extra_peripherals = [str(extra_peripherals_raw)]

    success_criteria = _parse_success_criteria(raw.get("success_criteria"))
    fault_sweep = (
        _parse_fault_sweep(
            raw.get("fault_sweep"),
            bootloader_elf=bootloader_elf,
            profile_path=profile_path,
        )
        if "fault_sweep" in raw
        else None
    )

    flash_backend_raw = raw.get("flash_backend")
    flash_backend: Optional[str] = str(flash_backend_raw) if flash_backend_raw is not None else None

    return ComponentConfig(
        name=name,
        platform=platform,
        bootloader_elf=bootloader_elf,
        bootloader_entry=bootloader_entry,
        memory=memory,
        images=images,
        pre_boot_state=pre_boot_state,
        setup_script=setup_script,
        extra_peripherals=extra_peripherals,
        success_criteria=success_criteria,
        fault_sweep=fault_sweep,
        flash_backend=flash_backend,
    )


def _parse_components(
    raw: Optional[Any],
    *,
    profile_path: Optional[Path] = None,
) -> Optional[MultiComponentConfig]:
    """Parse the components list from a multi-component profile."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("multi_component: expected mapping with 'components' list")
    components_raw = raw.get("components")
    if components_raw is None or not isinstance(components_raw, list):
        raise ProfileError("multi_component.components: expected non-empty list")
    if len(components_raw) < 2:
        raise ProfileError(
            "multi_component.components: need at least 2 components, got {}".format(
                len(components_raw)
            )
        )
    components: List[ComponentConfig] = []
    seen_names: set = set()
    for idx, entry in enumerate(components_raw):
        if not isinstance(entry, dict):
            raise ProfileError("multi_component.components[{}]: expected mapping".format(idx))
        comp = _parse_component(entry, idx, profile_path=profile_path)
        if comp.name in seen_names:
            raise ProfileError(
                "multi_component.components: duplicate name '{}'".format(comp.name)
            )
        seen_names.add(comp.name)
        components.append(comp)
    fault_matrix = str(raw.get("fault_matrix", "cross_product"))
    valid_matrices = {"cross_product"}
    if fault_matrix not in valid_matrices:
        raise ProfileError(
            "multi_component.fault_matrix: must be one of {}, got {!r}".format(
                sorted(valid_matrices), fault_matrix
            )
        )
    return MultiComponentConfig(
        components=components,
        fault_matrix=fault_matrix,
    )


def _parse_invariant_providers(raw: Optional[Any]) -> List[str]:
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
                raise ProfileError(
                    "invariant_providers[{}]: expected non-empty string".format(i)
                )
            parsed.append(value)
        return parsed
    raise ProfileError("invariant_providers: expected string or list of strings")


def _parse_invariant_config(raw: Optional[Any]) -> Dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProfileError("invariant_config: expected mapping")
    parsed = dict(raw)
    stage = parsed.get("semantic_state_stage")
    if stage is not None and stage not in ("final", "fault_snapshot"):
        raise ProfileError(
            "invariant_config.semantic_state_stage: expected 'final' or "
            "'fault_snapshot'"
        )
    contracts = parsed.get("success_implies_effect")
    if contracts is not None:
        _validate_success_implies_effect_config(contracts)
        names = set()
        for index, contract in enumerate(contracts):
            if isinstance(contract, dict):
                name = str(contract.get("name") or "").strip()
                if name in names:
                    raise ProfileError(
                        "invariant_config.success_implies_effect[{}].name: duplicate contract name {!r}".format(
                            index, name
                        )
                    )
                names.add(name)
    if "state_relations" in parsed:
        _validate_state_relations_config(parsed["state_relations"])
    return parsed


_SUCCESS_EFFECT_OPS = {
    "eq", "ne", "lt", "le", "gt", "ge", "gt_pre", "ge_pre",
    "lt_pre", "le_pre", "changed", "unchanged",
}

_STATE_RELATION_OPS = {"eq", "ne", "lt", "le", "gt", "ge"}


def _relation_value_type(value: Any) -> str:
    """Return the strict YAML value category used by tuple validation."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return type(value).__name__


def _validate_state_relation_operand(raw: Any, context: str) -> None:
    if not isinstance(raw, dict):
        raise ProfileError("{}: expected operand mapping".format(context))
    has_path = "path" in raw
    has_value = "value" in raw
    if has_path == has_value:
        raise ProfileError(
            "{}: operand must contain exactly one of path or value".format(context)
        )
    if has_path:
        unknown = sorted(set(raw) - {"source", "path"})
        if unknown:
            raise ProfileError(
                "{}: path operand has unknown field(s): {}".format(
                    context, ", ".join(map(str, unknown))
                )
            )
        if raw.get("source") not in {"pre", "post"}:
            raise ProfileError("{}.source: expected pre or post".format(context))
        if not isinstance(raw.get("path"), str) or not raw.get("path", "").strip():
            raise ProfileError("{}.path: expected non-empty string".format(context))
    else:
        unknown = sorted(set(raw) - {"value"})
        if unknown:
            raise ProfileError(
                "{}: literal operand has unknown field(s): {}".format(
                    context, ", ".join(map(str, unknown))
                )
            )


def _validate_state_relation_comparison(raw: Any, context: str) -> None:
    if not isinstance(raw, dict) or set(raw) != {"left", "op", "right"}:
        raise ProfileError("{}: expected exactly left, op, and right".format(context))
    _validate_state_relation_operand(raw["left"], context + ".left")
    _validate_state_relation_operand(raw["right"], context + ".right")
    op = str(raw.get("op") or "").strip().lower()
    if op not in _STATE_RELATION_OPS:
        raise ProfileError("{}.op: unsupported operator {!r}".format(context, op))


def _validate_state_relations_config(raw: Any) -> None:
    if not isinstance(raw, list) or not raw:
        raise ProfileError("invariant_config.state_relations: expected non-empty list")
    names = set()
    for index, relation in enumerate(raw):
        context = "invariant_config.state_relations[{}]".format(index)
        if not isinstance(relation, dict):
            raise ProfileError("{}: expected mapping".format(context))
        unknown = sorted(set(relation) - {"name", "compare", "allowed_tuples", "when"})
        if unknown:
            raise ProfileError(
                "{}: unknown field(s): {}".format(context, ", ".join(map(str, unknown)))
            )
        name = str(relation.get("name") or "").strip()
        if not name:
            raise ProfileError("{}.name: expected non-empty string".format(context))
        if name in names:
            raise ProfileError("{}.name: duplicate relation name {!r}".format(context, name))
        names.add(name)
        has_compare = "compare" in relation
        has_tuples = "allowed_tuples" in relation
        if has_compare == has_tuples:
            raise ProfileError(
                "{}: expected exactly one of compare or allowed_tuples".format(context)
            )
        if "when" in relation:
            _validate_state_relation_comparison(relation["when"], context + ".when")
        if has_compare:
            _validate_state_relation_comparison(relation["compare"], context + ".compare")
            continue

        tuples = relation["allowed_tuples"]
        if not isinstance(tuples, dict) or set(tuples) != {"fields", "values"}:
            raise ProfileError(
                "{}.allowed_tuples: expected exactly fields and values".format(context)
            )
        fields = tuples["fields"]
        values = tuples["values"]
        if not isinstance(fields, list) or len(fields) < 2:
            raise ProfileError(
                "{}.allowed_tuples.fields: expected at least two fields".format(context)
            )
        if not isinstance(values, list) or not values:
            raise ProfileError(
                "{}.allowed_tuples.values: expected at least one tuple".format(context)
            )
        for field_index, field in enumerate(fields):
            _validate_state_relation_operand(
                field, "{}.allowed_tuples.fields[{}]".format(context, field_index)
            )
        expected_types: Optional[List[str]] = None
        seen_tuples = set()
        for tuple_index, item in enumerate(values):
            tuple_context = "{}.allowed_tuples.values[{}]".format(context, tuple_index)
            if not isinstance(item, (list, tuple)) or len(item) != len(fields):
                raise ProfileError(
                    "{}: expected tuple with {} values".format(tuple_context, len(fields))
                )
            item_types = [_relation_value_type(value) for value in item]
            if expected_types is None:
                expected_types = item_types
            elif item_types != expected_types:
                raise ProfileError(
                    "{}: value types must match other allowed tuples".format(tuple_context)
                )
            # Include type tags so Python's bool/int equivalence cannot hide a duplicate.
            duplicate_key = tuple((item_types[i], item[i]) for i in range(len(item)))
            try:
                duplicate = duplicate_key in seen_tuples
                seen_tuples.add(duplicate_key)
            except TypeError as exc:
                raise ProfileError("{}: values must be scalar".format(tuple_context)) from exc
            if duplicate:
                raise ProfileError("{}: duplicate allowed tuple".format(tuple_context))


def _validate_success_implies_effect_config(raw: Any) -> None:
    if not isinstance(raw, list):
        raise ProfileError("invariant_config.success_implies_effect: expected list")
    for index, contract in enumerate(raw):
        ctx = "invariant_config.success_implies_effect[{}]".format(index)
        if not isinstance(contract, dict):
            raise ProfileError("{}: expected mapping".format(ctx))
        allowed = {"name", "probe", "success_values", "call", "evaluate_control", "require"}
        unknown = sorted(set(contract) - allowed)
        if unknown:
            raise ProfileError("{}: unknown field(s): {}".format(ctx, ", ".join(map(str, unknown))))
        for key in ("name", "probe"):
            if not str(contract.get(key) or "").strip():
                raise ProfileError("{}.{}: expected non-empty string".format(ctx, key))
        values = contract.get("success_values")
        if not isinstance(values, list) or not values:
            raise ProfileError("{}.success_values: expected non-empty list".format(ctx))
        for value_index, value in enumerate(values):
            if isinstance(value, bool):
                raise ProfileError("{}.success_values[{}]: expected integer, got boolean".format(ctx, value_index))
            try:
                _parse_int(value, "{}.success_values[{}]".format(ctx, value_index))
            except (TypeError, ValueError, ProfileError) as exc:
                raise ProfileError(str(exc)) from exc
        if "evaluate_control" in contract and type(contract["evaluate_control"]) is not bool:
            raise ProfileError("{}.evaluate_control: expected boolean".format(ctx))
        if "call" in contract:
            call = contract["call"]
            if isinstance(call, bool):
                raise ProfileError("{}.call: expected first, last, or non-negative integer".format(ctx))
            if isinstance(call, str) and call.strip().lower() in {"first", "last"}:
                pass
            else:
                try:
                    parsed_call = int(call, 0) if isinstance(call, str) else int(call)
                except (TypeError, ValueError) as exc:
                    raise ProfileError("{}.call: expected first, last, or non-negative integer".format(ctx)) from exc
                if parsed_call < 0:
                    raise ProfileError("{}.call: expected non-negative integer".format(ctx))
        require = contract.get("require")
        if not isinstance(require, dict) or set(require) not in ({"all"}, {"any"}):
            raise ProfileError("{}.require: expected exactly one of all or any".format(ctx))
        conditions = next(iter(require.values()))
        if not isinstance(conditions, list) or not conditions:
            raise ProfileError("{}.require: condition group must be a non-empty list".format(ctx))
        for condition_index, condition in enumerate(conditions):
            cctx = "{}.require[{}]".format(ctx, condition_index)
            if not isinstance(condition, dict):
                raise ProfileError("{}: expected condition mapping".format(cctx))
            unknown_condition = sorted(set(condition) - {"source", "path", "op", "value"})
            if unknown_condition:
                raise ProfileError("{}: unknown field(s): {}".format(cctx, ", ".join(map(str, unknown_condition))))
            if condition.get("source") not in {"pre", "post"}:
                raise ProfileError("{}.source: expected pre or post".format(cctx))
            if not str(condition.get("path") or "").strip():
                raise ProfileError("{}.path: expected non-empty string".format(cctx))
            op = str(condition.get("op") or "").strip().lower()
            if op not in _SUCCESS_EFFECT_OPS:
                raise ProfileError("{}.op: unsupported operator {!r}".format(cctx, op))
            if op not in {"changed", "unchanged", "gt_pre", "ge_pre", "lt_pre", "le_pre"} and "value" not in condition:
                raise ProfileError("{}.value: required for {}".format(cctx, op))
            if "value" in condition and op not in {"changed", "unchanged"}:
                try:
                    _parse_int(condition["value"], "{}.value".format(cctx))
                except (TypeError, ValueError, ProfileError) as exc:
                    raise ProfileError(str(exc)) from exc


def _validate_success_effect_runtime_compatibility(
    fault_sweep: FaultSweepConfig,
    invariants: List[str],
    effect_contracts: List[Any],
) -> None:
    """Reject effect telemetry configurations that cannot run in execute mode."""
    features = []
    if fault_sweep.function_return_probes:
        features.append("function_return_probes")
    if "success_implies_effect" in invariants or effect_contracts:
        features.append("success_implies_effect")
    if not features:
        return
    feature_text = " and ".join(features)
    if str(fault_sweep.mode).strip().lower() != "runtime":
        raise ProfileError(
            "{} requires fault_sweep.mode 'runtime'".format(feature_text)
        )
    if str(fault_sweep.evaluation_mode).strip().lower() != "execute":
        raise ProfileError(
            "{} requires fault_sweep.evaluation_mode 'execute'".format(feature_text)
        )


def _validate_success_effect_selectors(
    effect_contracts: List[Any],
    probe_captures: Dict[str, str],
) -> None:
    """Validate contract call selectors against their probe capture policy."""
    for index, contract in enumerate(effect_contracts):
        if not isinstance(contract, dict):
            continue
        probe_name = str(contract.get("probe") or "").strip()
        capture = probe_captures.get(probe_name)
        if capture is None:
            continue  # The undefined-probe error is reported by the caller.
        call = contract.get("call")
        ctx = "invariant_config.success_implies_effect[{}]".format(index)
        if capture == "all":
            if call is None:
                raise ProfileError(
                    "{}.call is required when probe capture is 'all'".format(ctx)
                )
            continue
        if call is None:
            continue
        if isinstance(call, str) and call.strip().lower() in {"first", "last"}:
            selector = call.strip().lower()
        else:
            selector = int(call, 0) if isinstance(call, str) else int(call)
        if capture == "first" and selector not in {"first", 0}:
            raise ProfileError(
                "{}.call={!r} is incompatible with probe capture='first'; "
                "use omitted, 'first', or 0".format(ctx, call)
            )
        if capture == "last" and selector != "last":
            raise ProfileError(
                "{}.call={!r} is incompatible with probe capture='last'; "
                "use omitted or 'last'".format(ctx, call)
            )


def _parse_metadata_fault_regions(raw, slots=None):
    # type: (Optional[List[Any]], Optional[Dict[str, SlotConfig]]) -> List[MetadataFaultRegion]
    """Parse metadata_fault_regions from profile YAML."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("metadata_fault_regions: expected list of region definitions")
    regions = []  # type: List[MetadataFaultRegion]
    seen_names = set()  # type: set
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ProfileError(
                "metadata_fault_regions[{}]: expected mapping".format(idx)
            )
        name = str(entry.get("name", "")).strip()
        if not name:
            raise ProfileError(
                "metadata_fault_regions[{}].name: expected non-empty string".format(idx)
            )
        if name in seen_names:
            raise ProfileError(
                "metadata_fault_regions: duplicate name '{}'".format(name)
            )
        seen_names.add(name)

        has_absolute = "start" in entry or "end" in entry
        has_relative = "slot" in entry or "offset" in entry or "size" in entry or "end_offset" in entry
        if has_absolute and has_relative:
            raise ProfileError(
                "metadata_fault_regions[{}]: choose either absolute (start/end) or relative (slot/offset/size) form".format(
                    idx
                )
            )

        if has_relative:
            slot_name = str(_require(entry, "slot", "metadata_fault_regions[{}]".format(idx))).strip()
            if not slot_name:
                raise ProfileError(
                    "metadata_fault_regions[{}].slot: expected non-empty string".format(idx)
                )
            if slots is None or slot_name not in slots:
                raise ProfileError(
                    "metadata_fault_regions[{}].slot: unknown slot '{}'".format(idx, slot_name)
                )
            slot = slots[slot_name]
            offset = _parse_int(
                _require(entry, "offset", "metadata_fault_regions[{}]".format(idx)),
                "metadata_fault_regions[{}].offset".format(idx),
            )
            if "size" in entry and "end_offset" in entry:
                raise ProfileError(
                    "metadata_fault_regions[{}]: specify only one of size or end_offset".format(idx)
                )
            if "size" in entry:
                size = _parse_int(
                    entry["size"],
                    "metadata_fault_regions[{}].size".format(idx),
                )
                start = slot.base + offset
                end = start + size
            elif "end_offset" in entry:
                start = slot.base + offset
                end = slot.base + _parse_int(
                    entry["end_offset"],
                    "metadata_fault_regions[{}].end_offset".format(idx),
                )
            else:
                raise ProfileError(
                    "metadata_fault_regions[{}]: relative form requires size or end_offset".format(idx)
                )
        else:
            start = _parse_int(
                _require(entry, "start", "metadata_fault_regions[{}]".format(idx)),
                "metadata_fault_regions[{}].start".format(idx),
            )
            end = _parse_int(
                _require(entry, "end", "metadata_fault_regions[{}]".format(idx)),
                "metadata_fault_regions[{}].end".format(idx),
            )
        if end <= start:
            raise ProfileError(
                "metadata_fault_regions[{}]: end (0x{:X}) must be greater than start (0x{:X})".format(
                    idx, end, start
                )
            )
        regions.append(MetadataFaultRegion(name=name, start=start, end=end))
    return regions


# ---------------------------------------------------------------------------
# Main loader
# ---------------------------------------------------------------------------

_STRICT_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version", "name", "description", "platform", "bootloader",
        "memory", "images", "pre_boot_state", "update_trigger", "setup_script",
        "flash_backend", "nvm_controller", "otp_peripheral", "extra_peripherals",
        "state_probe", "success_criteria", "success_criteria_overrides",
        "fault_sweep", "update_sequence", "state_fuzzer", "security_policy",
        "update_protocol", "authorization_review",
        "firmware_elf", "fuzz_corpus", "expect", "semantic_assertions",
        "invariants", "invariant_providers", "invariant_config", "initial_states",
        "metadata_fault_regions", "multi_component", "nvs_region",
        "bootloader_region", "boot_register_pre_writes", "boot_registers",
        "write_order_constraints", "residual_image", "scenario",
        "skip_self_test", "strict_validation",
        "persistent_state_layout",
        "terminal_error_paths",
        "boundary_campaigns",
    }
)

_STRICT_SUCCESS_CRITERIA_KEYS = frozenset(
    {
        "vtor_in_slot", "vector_table_offset", "pc_in_slot", "marker_address",
        "marker_value", "image_hash", "expected_image", "image_hash_slot",
        "otadata_expect", "otadata_expect_scope", "bootloader_integrity",
        "config_checks", "boot_register_values", "max_reset_vector_offset",
        "memory_checks",
    }
)

_STRICT_FAULT_SWEEP_KEYS = frozenset(
    {
        "mode", "max_writes", "max_otp_blows", "max_writes_cap",
        "max_step_limit", "run_duration", "calibration_time_slice",
        "phase1_time_slice", "phase2_time_slice", "phase2_wall_timeout_s",
        "fault_types",
        "evaluation_mode", "sweep_strategy", "sweep_hash_bypass_symbols",
        "progress_stall_timeout_s", "boot_cycles", "boot_cycle_hook",
        "vtor_settle_iters",
        "tracking_start_address",
        "expected_rollback_at_cycle", "phase2_fault", "hook_fault",
        "confirm_cycle", "multi_fault", "read_fault_config",
        "instruction_skip_config", "timed_bit_corruption_config",
        "verification_probes", "function_return_probes", "verification_bypass_probe", "metadata_fault",
        "metadata_delta", "partial_staging", "nvs_corruption",
        "fault_distribution", "heuristic", "max_heuristic_points",
        "quick_use_heuristic", "reset_mode", "i2c_fault_config",
        "durability_model", "writeback",
        "rc_injection_config",
    }
)

_STRICT_UPDATE_TRIGGER_KEYS = frozenset(
    {
        "type", "slot", "max_align", "unprotected_tlv_sizes", "image_ok",
        "copy_done", "swap_info", "swap_type", "image_num", "swap_size",
        "hdr_len", "version",
    }
)

_STRICT_UPDATE_PHASE_KEYS = frozenset(
    {
        "name", "description", "images", "setup_script", "pre_boot_state",
        "success_criteria", "boot_cycles", "boot_cycle_hook",
        "expected_rollback_at_cycle", "fault_injection", "fault_types",
    }
)

_STRICT_COMPONENT_KEYS = frozenset(
    {
        "name", "platform", "bootloader", "memory", "images",
        "pre_boot_state", "setup_script", "extra_peripherals",
        "success_criteria", "fault_sweep", "flash_backend",
    }
)


def _reject_unknown_keys(
    value: Any,
    allowed: frozenset[str],
    context: str,
) -> None:
    if not isinstance(value, dict):
        raise ProfileError("{}: expected mapping".format(context))
    unknown = sorted(str(key) for key in set(value) - allowed)
    if unknown:
        raise ProfileError(
            "{}: unknown field(s): {}".format(context, ", ".join(unknown))
        )


def _validate_strict_bootloader(raw: Any, context: str) -> None:
    _reject_unknown_keys(raw, frozenset({"elf", "entry"}), context)


def _validate_strict_memory(raw: Any, context: str) -> None:
    _reject_unknown_keys(
        raw,
        frozenset(
            {
                "sram", "write_granularity", "page_size", "slots",
                "bootloader_region", "trace_address_map", "erase_regions",
                "postmortem_partitions",
            }
        ),
        context,
    )
    _reject_unknown_keys(
        raw.get("sram"),
        frozenset({"start", "end"}),
        "{}.sram".format(context),
    )
    slots = raw.get("slots")
    if not isinstance(slots, dict):
        raise ProfileError("{}.slots: expected mapping".format(context))
    for slot_name, slot in slots.items():
        _reject_unknown_keys(
            slot,
            frozenset({"base", "size"}),
            "{}.slots.{}".format(context, slot_name),
        )
    for field_name in ("erase_regions", "postmortem_partitions"):
        regions = raw.get(field_name)
        if regions is None:
            continue
        if not isinstance(regions, list):
            raise ProfileError("{}.{}: expected list".format(context, field_name))
        for index, region in enumerate(regions):
            _reject_unknown_keys(
                region,
                frozenset({"base", "size", "sector_size", "erase_size", "name"}),
                "{}.{}[{}]".format(context, field_name, index),
            )
    if "bootloader_region" in raw:
        _reject_unknown_keys(
            raw.get("bootloader_region"),
            frozenset({"base", "size"}),
            "{}.bootloader_region".format(context),
        )
    trace_address_map = raw.get("trace_address_map", [])
    if not isinstance(trace_address_map, list):
        raise ProfileError("{}.trace_address_map: expected list".format(context))
    for index, entry in enumerate(trace_address_map):
        _reject_unknown_keys(
            entry,
            frozenset({"offset_start", "offset_end", "address_addend"}),
            "{}.trace_address_map[{}]".format(context, index),
        )


def _validate_strict_pre_boot_state(raw: Any, context: str) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        raise ProfileError("{}: expected list".format(context))
    for index, write in enumerate(raw):
        _reject_unknown_keys(
            write,
            frozenset({"address", "u32"}),
            "{}[{}]".format(context, index),
        )


def _validate_strict_update_trigger(raw: Any, context: str) -> None:
    if raw is None or isinstance(raw, str):
        return
    _reject_unknown_keys(raw, _STRICT_UPDATE_TRIGGER_KEYS, context)


def _validate_strict_success_criteria(
    raw: Any,
    context: str,
    *,
    require_meaningful: bool = True,
) -> None:
    _reject_unknown_keys(raw, _STRICT_SUCCESS_CRITERIA_KEYS, context)
    if require_meaningful and not _strict_success_criteria_is_meaningful(raw):
        raise ProfileError(
            "{}: strict validation requires at least one observable success "
            "check".format(context)
        )

    for check_name, allowed in (
        ("memory_checks", {"address", "expected_value", "mask", "op"}),
        (
            "config_checks",
            {"address", "expected", "nonzero", "range", "mask", "expected_masked"},
        ),
    ):
        checks = raw.get(check_name) or []
        if not isinstance(checks, list):
            raise ProfileError("{}.{}: expected list".format(context, check_name))
        for index, check in enumerate(checks):
            _reject_unknown_keys(
                check,
                frozenset(allowed),
                "{}.{}[{}]".format(context, check_name, index),
            )
            if check_name == "config_checks" and "range" in check:
                _reject_unknown_keys(
                    check.get("range"),
                    frozenset({"min", "max"}),
                    "{}.config_checks[{}].range".format(context, index),
                )


def _validate_strict_terminal_error_paths(raw: Any, context: str) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        raise ProfileError("{}: expected list".format(context))
    allowed = frozenset({
        "name", "handler_symbols", "containing_symbols", "forbidden_sink_symbols",
        "expected_control", "required_failure_marker", "observation_window",
    })
    marker_allowed = frozenset({"address", "expected_value", "mask", "op"})
    for index, entry in enumerate(raw):
        item_context = "{}[{}]".format(context, index)
        _reject_unknown_keys(entry, allowed, item_context)
        marker = entry.get("required_failure_marker")
        if marker is not None:
            _reject_unknown_keys(marker, marker_allowed, item_context + ".required_failure_marker")


def _validate_strict_relative_path(value: Any, context: str) -> None:
    text = str(value or "").strip()
    normalized = text.replace("\\", "/")
    if (
        not text
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized)
        or ".." in normalized.split("/")
    ):
        raise ProfileError(
            "{}: strict validation requires a non-empty relative path "
            "without '..'; got {!r}".format(context, text)
        )


def _validate_strict_path_list(raw: Any, context: str) -> None:
    if raw is None:
        return
    values = raw if isinstance(raw, list) else [raw]
    for index, value in enumerate(values):
        _validate_strict_relative_path(
            value,
            "{}[{}]".format(context, index),
        )


def _strict_success_criteria_is_meaningful(raw: Dict[str, Any]) -> bool:
    marker_pair = "marker_address" in raw and "marker_value" in raw
    return bool(
        raw.get("vtor_in_slot")
        or raw.get("pc_in_slot")
        or marker_pair
        or raw.get("image_hash")
        or raw.get("otadata_expect")
        or raw.get("bootloader_integrity")
        or raw.get("config_checks")
        or raw.get("boot_register_values")
        or raw.get("memory_checks")
        or raw.get("max_reset_vector_offset") is not None
    )


def _validate_strict_profile_data(data: Dict[str, Any]) -> None:
    """Reject ignored fields and profiles with no observable success check."""
    _reject_unknown_keys(data, _STRICT_TOP_LEVEL_KEYS, "profile")
    _validate_strict_bootloader(data.get("bootloader"), "bootloader")

    memory = data.get("memory")
    _validate_strict_memory(memory, "memory")

    criteria = data.get("success_criteria")
    _validate_strict_success_criteria(criteria, "success_criteria")
    _validate_strict_terminal_error_paths(
        data.get("terminal_error_paths"), "terminal_error_paths"
    )

    if "fault_sweep" in data:
        _reject_unknown_keys(
            data.get("fault_sweep"),
            _STRICT_FAULT_SWEEP_KEYS,
            "fault_sweep",
        )
        fault_sweep = data.get("fault_sweep")
        nested_fault_schemas = {
            "phase2_fault": {"enabled", "fault_types", "max_points"},
            "hook_fault": {"enabled", "fault_types", "max_points"},
            "confirm_cycle": {
                "enabled", "confirm_function", "post_confirm_assertions",
                "expected_ratchet_version", "fault_types", "max_points",
            },
            "multi_fault": {
                "enabled", "max_faults_per_run", "strategy",
                "fallback_strategy", "max_pairs", "seed", "sequences",
            },
            "read_fault_config": {
                "target_regions", "bit_flip_count", "fault_probability", "seed",
            },
            "instruction_skip_config": {
                "skip_count", "target_addresses", "include_literal_pools",
                "severity_model",
            },
            "timed_bit_corruption_config": {"pairs"},
            "verification_bypass_probe": {"enabled", "probe_functions"},
            "metadata_fault": {"enabled", "fault_types"},
            "metadata_delta": {"enabled", "fields"},
            "partial_staging": {
                "enabled", "staging_slot", "staging_image", "fill_pattern", "header_size",
                "trailer_size", "truncation_points", "offsets", "max_points",
                "sector_size",
            },
            "nvs_corruption": {
                "enabled", "modes", "bit_flip_counts", "erase_fractions",
                "truncate_offsets", "seed",
            },
            "fault_distribution": {
                "mode", "cluster_sectors", "cluster_start", "cluster_end",
                "flip_probability_in_cluster", "flip_probability_outside", "seed",
            },
            "heuristic": {
                "tier2_step", "tier3_step", "discontinuity_window",
                "target_points", "preserve_critical_tiers", "shard_count",
                "shard_index", "random_tail_budget", "critical_regions",
            },
            "i2c_fault_config": {
                "peripheral_name", "target_address", "fault_types",
                "fault_at_transaction", "fault_seed",
            },
            "writeback": {
                "buffer_capacity", "domains", "barriers", "erase_flushes_domain",
            },
            "rc_injection_config": {
                "symbols", "return_value", "return_register", "require_applied",
            },
        }
        for field_name, allowed in nested_fault_schemas.items():
            nested = fault_sweep.get(field_name)
            if nested is None or isinstance(nested, bool):
                continue
            _reject_unknown_keys(
                nested,
                frozenset(allowed),
                "fault_sweep.{}".format(field_name),
            )

        probes = fault_sweep.get("verification_probes") or []
        if not isinstance(probes, list):
            raise ProfileError("fault_sweep.verification_probes: expected list")
        for index, probe in enumerate(probes):
            _reject_unknown_keys(
                probe,
                frozenset({"symbol", "return_register", "success_value", "label"}),
                "fault_sweep.verification_probes[{}]".format(index),
            )

        function_probes = fault_sweep.get("function_return_probes") or []
        if not isinstance(function_probes, list):
            raise ProfileError("fault_sweep.function_return_probes: expected list")
        for index, probe in enumerate(function_probes):
            _reject_unknown_keys(
                probe,
                frozenset({"symbol", "return_register", "label", "capture"}),
                "fault_sweep.function_return_probes[{}]".format(index),
            )

        bypass_probe = fault_sweep.get("verification_bypass_probe")
        if isinstance(bypass_probe, dict):
            probe_functions = bypass_probe.get("probe_functions") or []
            if not isinstance(probe_functions, list):
                raise ProfileError(
                    "fault_sweep.verification_bypass_probe.probe_functions: "
                    "expected list"
                )
            for index, probe in enumerate(probe_functions):
                _reject_unknown_keys(
                    probe,
                    frozenset(
                        {
                            "symbol", "return_register",
                            "expected_success_value", "layer",
                        }
                    ),
                    "fault_sweep.verification_bypass_probe.probe_functions[{}]".format(
                        index
                    ),
                )

        confirm_cycle = fault_sweep.get("confirm_cycle")
        if isinstance(confirm_cycle, dict):
            assertions = confirm_cycle.get("post_confirm_assertions") or []
            if not isinstance(assertions, list):
                raise ProfileError(
                    "fault_sweep.confirm_cycle.post_confirm_assertions: expected list"
                )
            for index, assertion in enumerate(assertions):
                _reject_unknown_keys(
                    assertion,
                    frozenset({"address", "expected", "label"}),
                    "fault_sweep.confirm_cycle.post_confirm_assertions[{}]".format(
                        index
                    ),
                )

        timed_config = fault_sweep.get("timed_bit_corruption_config")
        if isinstance(timed_config, dict):
            pairs = timed_config.get("pairs") or []
            if not isinstance(pairs, list):
                raise ProfileError(
                    "fault_sweep.timed_bit_corruption_config.pairs: expected list"
                )
            for index, pair in enumerate(pairs):
                context = "fault_sweep.timed_bit_corruption_config.pairs[{}]".format(
                    index
                )
                _reject_unknown_keys(
                    pair,
                    frozenset({"trigger", "corrupt_address", "bit_flips"}),
                    context,
                )
                trigger = pair.get("trigger")
                if isinstance(trigger, dict):
                    _reject_unknown_keys(
                        trigger,
                        frozenset({"address"}),
                        "{}.trigger".format(context),
                    )

        for config_name, region_key, allowed_region_keys in (
            ("read_fault_config", "target_regions", {"start", "end"}),
            ("instruction_skip_config", "target_addresses", {"start", "end", "symbol"}),
            ("heuristic", "critical_regions", {"start", "end", "symbol"}),
        ):
            nested = fault_sweep.get(config_name)
            if not isinstance(nested, dict):
                continue
            regions = nested.get(region_key) or []
            if not isinstance(regions, list):
                raise ProfileError(
                    "fault_sweep.{}.{}: expected list".format(config_name, region_key)
                )
            for index, region in enumerate(regions):
                _reject_unknown_keys(
                    region,
                    frozenset(allowed_region_keys),
                    "fault_sweep.{}.{}[{}]".format(config_name, region_key, index),
                )

        metadata_delta = fault_sweep.get("metadata_delta")
        if isinstance(metadata_delta, dict):
            fields = metadata_delta.get("fields") or []
            if not isinstance(fields, list):
                raise ProfileError("fault_sweep.metadata_delta.fields: expected list")
            for index, field in enumerate(fields):
                _reject_unknown_keys(
                    field,
                    frozenset({"address", "name", "min_delta", "max_delta", "when"}),
                    "fault_sweep.metadata_delta.fields[{}]".format(index),
                )

    if "bootloader_region" in data:
        _reject_unknown_keys(
            data.get("bootloader_region"),
            frozenset({"base", "size"}),
            "bootloader_region",
        )
    if "nvs_region" in data:
        _reject_unknown_keys(
            data.get("nvs_region"),
            frozenset({"address", "size", "snapshot"}),
            "nvs_region",
        )

    for field_name, allowed in (
        ("expect", _EXPECT_KEYS),
        ("security_policy", {"anti_rollback", "minimum_version", "toctou_protection"}),
        ("state_fuzzer", {"enabled", "metadata_model", "iterations", "seed"}),
        ("residual_image", {"slot", "prior_image", "fill_pattern"}),
    ):
        nested = data.get(field_name)
        if nested is not None:
            _reject_unknown_keys(nested, frozenset(allowed), field_name)

    state_fuzzer = data.get("state_fuzzer")
    if isinstance(state_fuzzer, dict) and isinstance(
        state_fuzzer.get("metadata_model"), dict
    ):
        metadata_model = state_fuzzer.get("metadata_model")
        _reject_unknown_keys(
            metadata_model,
            frozenset({"base_address", "fields", "fill"}),
            "state_fuzzer.metadata_model",
        )
        fields = metadata_model.get("fields") or []
        if not isinstance(fields, list):
            raise ProfileError("state_fuzzer.metadata_model.fields: expected list")
        for index, field in enumerate(fields):
            _reject_unknown_keys(
                field,
                frozenset({"name", "offset", "size", "type", "valid", "valid_range"}),
                "state_fuzzer.metadata_model.fields[{}]".format(index),
            )

    criteria_overrides = data.get("success_criteria_overrides") or {}
    if not isinstance(criteria_overrides, dict):
        raise ProfileError("success_criteria_overrides: expected mapping")
    for fault_type, overrides in criteria_overrides.items():
        _reject_unknown_keys(
            overrides,
            frozenset({"vtor_in_slot", "image_hash", "image_hash_slot"}),
            "success_criteria_overrides.{}".format(fault_type),
        )

    metadata_regions = data.get("metadata_fault_regions") or []
    if not isinstance(metadata_regions, list):
        raise ProfileError("metadata_fault_regions: expected list")
    for index, region in enumerate(metadata_regions):
        _reject_unknown_keys(
            region,
            frozenset({"name", "start", "end", "slot", "offset", "size", "end_offset"}),
            "metadata_fault_regions[{}]".format(index),
        )

    _validate_strict_pre_boot_state(data.get("pre_boot_state"), "pre_boot_state")
    _validate_strict_update_trigger(data.get("update_trigger"), "update_trigger")

    for field_name, allowed in (
        ("boot_register_pre_writes", {"address", "value"}),
        ("boot_registers", {"address", "name"}),
    ):
        entries = data.get(field_name) or []
        if not isinstance(entries, list):
            raise ProfileError("{}: expected list".format(field_name))
        for index, entry in enumerate(entries):
            _reject_unknown_keys(
                entry,
                frozenset(allowed),
                "{}[{}]".format(field_name, index),
            )

    write_constraints = data.get("write_order_constraints") or []
    if not isinstance(write_constraints, list):
        raise ProfileError("write_order_constraints: expected list")
    for index, constraint in enumerate(write_constraints):
        context = "write_order_constraints[{}]".format(index)
        _reject_unknown_keys(
            constraint,
            frozenset({"first", "then", "label", "bidirectional"}),
            context,
        )
        for relation in ("first", "then"):
            _reject_unknown_keys(
                constraint.get(relation),
                frozenset({"start", "size"}),
                "{}.{}".format(context, relation),
            )

    state_probe_value = data.get("state_probe")
    if isinstance(state_probe_value, dict):
        _reject_unknown_keys(
            state_probe_value,
            frozenset({"script", "required_paths", "contract_version", "format"}),
            "state_probe",
        )

    _validate_strict_relative_path(data.get("platform"), "platform")
    _validate_strict_relative_path(data.get("bootloader", {}).get("elf"), "bootloader.elf")
    images = data.get("images") or {}
    if not isinstance(images, dict):
        raise ProfileError("images: expected mapping")
    for slot_name, image_path in images.items():
        _validate_strict_relative_path(
            image_path,
            "images.{}".format(slot_name),
        )
    for field_name in ("setup_script", "firmware_elf", "fuzz_corpus"):
        if data.get(field_name):
            _validate_strict_relative_path(data.get(field_name), field_name)
    _validate_strict_path_list(data.get("extra_peripherals"), "extra_peripherals")
    _validate_strict_path_list(data.get("invariant_providers"), "invariant_providers")
    if "invariant_config" in data and isinstance(data.get("invariant_config"), dict):
        if "success_implies_effect" in data["invariant_config"]:
            _validate_success_implies_effect_config(
                data["invariant_config"].get("success_implies_effect")
            )

    state_probe = data.get("state_probe")
    if isinstance(state_probe, dict) and state_probe.get("script"):
        _validate_strict_relative_path(state_probe.get("script"), "state_probe.script")
    nvs_region = data.get("nvs_region")
    if isinstance(nvs_region, dict) and nvs_region.get("snapshot"):
        _validate_strict_relative_path(nvs_region.get("snapshot"), "nvs_region.snapshot")
    residual = data.get("residual_image")
    if isinstance(residual, dict) and residual.get("prior_image"):
        _validate_strict_relative_path(
            residual.get("prior_image"),
            "residual_image.prior_image",
        )

    fault_sweep = data.get("fault_sweep") or {}
    if fault_sweep.get("boot_cycle_hook"):
        _validate_strict_relative_path(
            fault_sweep.get("boot_cycle_hook"),
            "fault_sweep.boot_cycle_hook",
        )
    partial_staging = fault_sweep.get("partial_staging")
    partial_staging_enabled = True
    if isinstance(partial_staging, dict):
        partial_staging_enabled = _parse_bool(
            partial_staging.get("enabled", True),
            "fault_sweep.partial_staging.enabled",
        )
    if (
        partial_staging_enabled
        and isinstance(partial_staging, dict)
        and partial_staging.get("staging_image")
    ):
        _validate_strict_relative_path(
            partial_staging.get("staging_image"),
            "fault_sweep.partial_staging.staging_image",
        )

    initial_states = data.get("initial_states") or []
    if not isinstance(initial_states, list):
        raise ProfileError("initial_states: expected list")
    for index, state in enumerate(initial_states):
        context = "initial_states[{}]".format(index)
        _reject_unknown_keys(
            state,
            frozenset(
                {
                    "name", "description", "pre_boot_state", "setup_script",
                    "update_trigger", "expect",
                }
            ),
            context,
        )
        _validate_strict_pre_boot_state(
            state.get("pre_boot_state"),
            "{}.pre_boot_state".format(context),
        )
        _validate_strict_update_trigger(
            state.get("update_trigger"),
            "{}.update_trigger".format(context),
        )
        if state.get("expect") is not None:
            _reject_unknown_keys(
                state.get("expect"),
                _EXPECT_KEYS,
                "{}.expect".format(context),
            )
        if state.get("setup_script"):
            _validate_strict_relative_path(
                state.get("setup_script"),
                "{}.setup_script".format(context),
            )

    update_sequence = data.get("update_sequence") or []
    if not isinstance(update_sequence, list):
        raise ProfileError("update_sequence: expected list")
    for index, phase in enumerate(update_sequence):
        context = "update_sequence[{}]".format(index)
        _reject_unknown_keys(phase, _STRICT_UPDATE_PHASE_KEYS, context)
        phase_images = phase.get("images") or {}
        if not isinstance(phase_images, dict):
            raise ProfileError("{}.images: expected mapping".format(context))
        for slot_name, image_path in phase_images.items():
            _validate_strict_relative_path(
                image_path,
                "{}.images.{}".format(context, slot_name),
            )
        _validate_strict_pre_boot_state(
            phase.get("pre_boot_state"),
            "{}.pre_boot_state".format(context),
        )
        if phase.get("success_criteria") is not None:
            _validate_strict_success_criteria(
                phase.get("success_criteria"),
                "{}.success_criteria".format(context),
            )
        for field_name in ("setup_script", "boot_cycle_hook"):
            if phase.get(field_name):
                _validate_strict_relative_path(
                    phase.get(field_name),
                    "{}.{}".format(context, field_name),
                )

    boundary_campaigns = data.get("boundary_campaigns") or []
    if not isinstance(boundary_campaigns, list):
        raise ProfileError("boundary_campaigns: expected list")
    for index, campaign in enumerate(boundary_campaigns):
        context = "boundary_campaigns[{}]".format(index)
        _reject_unknown_keys(
            campaign,
            frozenset({
                "name", "parameter", "type", "width_bits", "capacity",
                "values", "setup_environment", "follow_up",
            }),
            context,
        )
        follow_up = campaign.get("follow_up")
        if follow_up is not None:
            _reject_unknown_keys(
                follow_up,
                frozenset({"parameter_value", "expect"}),
                context + ".follow_up",
            )

    multi_component = data.get("multi_component") or {}
    if not isinstance(multi_component, dict):
        raise ProfileError("multi_component: expected mapping")
    if multi_component:
        _reject_unknown_keys(
            multi_component,
            frozenset({"components", "fault_matrix"}),
            "multi_component",
        )
    components = multi_component.get("components", []) or []
    if not isinstance(components, list):
        raise ProfileError("multi_component.components: expected list")
    for index, component in enumerate(components):
        context = "multi_component.components[{}]".format(index)
        _reject_unknown_keys(component, _STRICT_COMPONENT_KEYS, context)
        _validate_strict_bootloader(
            component.get("bootloader"),
            "{}.bootloader".format(context),
        )
        _validate_strict_memory(
            component.get("memory"),
            "{}.memory".format(context),
        )
        component_criteria = component.get("success_criteria")
        _validate_strict_success_criteria(
            component_criteria,
            "{}.success_criteria".format(context),
        )
        _validate_strict_pre_boot_state(
            component.get("pre_boot_state"),
            "{}.pre_boot_state".format(context),
        )
        if component.get("fault_sweep") is not None:
            # Reuse the complete strict validator on a standalone component
            # view so every nested fault block receives the same recursive
            # checks as the parent profile.
            component_view = {
                "schema_version": data.get("schema_version", 1),
                "name": component.get("name"),
                "platform": component.get("platform"),
                "bootloader": component.get("bootloader"),
                "memory": component.get("memory"),
                "images": component.get("images", {}),
                "pre_boot_state": component.get("pre_boot_state"),
                "setup_script": component.get("setup_script"),
                "extra_peripherals": component.get("extra_peripherals"),
                "success_criteria": component.get("success_criteria"),
                "fault_sweep": component.get("fault_sweep"),
            }
            try:
                _validate_strict_profile_data(component_view)
            except ProfileError as exc:
                raise ProfileError("{}: {}".format(context, exc)) from exc
        _validate_strict_relative_path(
            component.get("platform"),
            "{}.platform".format(context),
        )
        _validate_strict_relative_path(
            (component.get("bootloader") or {}).get("elf"),
            "{}.bootloader.elf".format(context),
        )
        component_images = component.get("images") or {}
        if not isinstance(component_images, dict):
            raise ProfileError("{}.images: expected mapping".format(context))
        for slot_name, image_path in component_images.items():
            _validate_strict_relative_path(
                image_path,
                "{}.images.{}".format(context, slot_name),
            )
        if component.get("setup_script"):
            _validate_strict_relative_path(
                component.get("setup_script"),
                "{}.setup_script".format(context),
            )
        _validate_strict_path_list(
            component.get("extra_peripherals"),
            "{}.extra_peripherals".format(context),
        )


def load_profile(path: str | Path, *, strict: bool = False) -> ProfileConfig:
    """Load and validate a YAML profile.

    Args:
        path: Path to the .yaml profile file.
        strict: Reject unknown fields and profiles without an observable
            success check. A profile may also opt in with
            ``strict_validation: true``.

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

    raw_strict_value = data.get("strict_validation", False)
    if not isinstance(raw_strict_value, bool):
        raise ProfileError("strict_validation: expected boolean")
    strict_requested = strict or raw_strict_value
    strict_root = path.parent.resolve()

    # Resolve base_profile inheritance before parsing fields.
    base_chain: List[Tuple[str, Path]] = []
    data = _resolve_base_profile(
        data,
        path,
        _strict_root=strict_root if strict_requested else None,
        _base_chain=base_chain,
    )

    strict_value = data.get("strict_validation", False)
    if not isinstance(strict_value, bool):
        raise ProfileError("strict_validation: expected boolean")
    if strict or strict_value:
        # A profile can inherit strict_validation from a base.  Recheck the
        # complete resolved chain here so inherited strict mode cannot use a
        # symlink or an earlier reference to leave the caller's profile tree.
        for base_rel, base_path in base_chain:
            _validate_strict_relative_path(base_rel, "base_profile")
            try:
                base_path.relative_to(strict_root)
            except ValueError as exc:
                raise ProfileError(
                    "base_profile {!r} escapes strict profile boundary {} "
                    "(resolved to {})".format(base_rel, strict_root, base_path)
                ) from exc
        _validate_strict_profile_data(data)

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
    name = _parse_profile_identifier(_require(data, "name"), "name")
    description = str(data.get("description", ""))
    platform = str(_require(data, "platform"))

    bootloader = _require(data, "bootloader")
    bootloader_elf = str(_require(bootloader, "elf", "bootloader"))
    bootloader_entry = _parse_int(
        _require(bootloader, "entry", "bootloader"), "bootloader.entry"
    )

    memory = _parse_memory(_require(data, "memory"))
    try:
        persistent_state_layout = parse_persistent_state_layout(
            data.get("persistent_state_layout")
        )
    except SecurityStateLayoutError as exc:
        raise ProfileError(str(exc)) from exc
    terminal_error_paths = _parse_terminal_error_paths(data.get("terminal_error_paths"))
    images = {}
    raw_images = data.get("images", {})
    if isinstance(raw_images, dict):
        images = {str(k): str(v) for k, v in raw_images.items()}

    pre_boot_state = _parse_pre_boot_state(data.get("pre_boot_state"))
    update_trigger, auto_update_trigger = _parse_update_trigger_config(
        data.get("update_trigger")
    )
    setup_script = data.get("setup_script")
    if setup_script is not None:
        setup_script = str(setup_script)
    flash_backend_raw = data.get("flash_backend")
    flash_backend: Optional[str] = str(flash_backend_raw) if flash_backend_raw is not None else None

    nvm_controller_raw = data.get("nvm_controller")
    nvm_controller: Optional[str] = str(nvm_controller_raw) if nvm_controller_raw is not None else None

    otp_peripheral_raw = data.get("otp_peripheral")
    otp_peripheral: Optional[str] = str(otp_peripheral_raw) if otp_peripheral_raw is not None else None

    extra_peripherals_raw = data.get("extra_peripherals")
    extra_peripherals: Optional[List[str]] = None
    if extra_peripherals_raw is not None:
        if isinstance(extra_peripherals_raw, list):
            extra_peripherals = [str(p) for p in extra_peripherals_raw]
        else:
            extra_peripherals = [str(extra_peripherals_raw)]
    if "state_probe_script" in data:
        raise ProfileError(
            "state_probe_script is no longer supported; use state_probe.script"
        )
    state_probe = _parse_state_probe(data.get("state_probe"))

    success_criteria = _parse_success_criteria(data.get("success_criteria"))
    success_criteria_overrides = _parse_success_criteria_overrides(
        data.get("success_criteria_overrides")
    )
    fault_sweep = _parse_fault_sweep(
        data.get("fault_sweep"),
        bootloader_elf=bootloader_elf,
        profile_path=path,
    )
    update_sequence = _parse_update_sequence(
        data.get("update_sequence"),
        images=images,
        success_criteria=success_criteria,
        fault_sweep=fault_sweep,
    )
    if update_sequence and setup_script:
        raise ProfileError(
            "setup_script is not supported with update_sequence — "
            "per-phase state preparation does not run the setup script"
        )
    state_fuzzer = _parse_state_fuzzer(data.get("state_fuzzer"))
    security_policy = _parse_security_policy(data.get("security_policy"))
    try:
        update_protocol = parse_update_protocol(data.get("update_protocol"))
    except UpdateProtocolError as exc:
        raise ProfileError(str(exc)) from exc
    try:
        authorization_review = parse_authorization_review(data.get("authorization_review"))
    except AuthorizationReviewError as exc:
        raise ProfileError(str(exc)) from exc

    firmware_elf_raw = data.get("firmware_elf")
    firmware_elf: Optional[str] = str(firmware_elf_raw).strip() if firmware_elf_raw is not None else None

    fuzz_corpus_raw = data.get("fuzz_corpus")
    fuzz_corpus: Optional[str] = str(fuzz_corpus_raw) if fuzz_corpus_raw is not None else None
    expect = _parse_expect(data.get("expect"))
    semantic_assertions = _parse_semantic_assertions(data.get("semantic_assertions"))
    invariants = _parse_invariants(data.get("invariants"))
    invariant_providers = _parse_invariant_providers(data.get("invariant_providers"))
    invariant_config = _parse_invariant_config(data.get("invariant_config"))
    effect_contracts = invariant_config.get("success_implies_effect") or []
    probe_captures = {
        probe.label: probe.capture for probe in fault_sweep.function_return_probes
    }
    verification_labels = {probe.label for probe in fault_sweep.verification_probes}
    function_labels = set(probe_captures)
    collisions = sorted(verification_labels & function_labels)
    if collisions:
        raise ProfileError(
            "fault_sweep: verification_probes and function_return_probes label collision(s): {}".format(
                ", ".join(collisions)
            )
        )
    if "success_implies_effect" in invariants and not effect_contracts:
        raise ProfileError(
            "invariants includes success_implies_effect but invariant_config.success_implies_effect is missing"
        )
    state_relations = invariant_config.get("state_relations")
    if "state_relations" in invariants and not state_relations:
        raise ProfileError(
            "invariants includes state_relations but invariant_config.state_relations is missing"
        )
    _validate_success_effect_runtime_compatibility(
        fault_sweep, invariants, effect_contracts
    )
    contract_names = set()
    for index, contract in enumerate(effect_contracts):
        if isinstance(contract, dict):
            contract_name = str(contract.get("name") or "").strip()
            if contract_name in contract_names:
                raise ProfileError(
                    "invariant_config.success_implies_effect[{}].name: duplicate contract name {!r}".format(
                        index, contract_name
                    )
                )
            contract_names.add(contract_name)
            probe_name = str(contract.get("probe") or "").strip()
            if probe_name not in function_labels:
                raise ProfileError(
                    "invariant_config.success_implies_effect[{}].probe references undefined function_return_probe {!r}".format(
                        index, probe_name
                    )
                )
        if (
            isinstance(contract, dict)
            and contract.get("call") is None
            and probe_captures.get(str(contract.get("probe") or "").strip()) == "all"
        ):
            raise ProfileError(
                "invariant_config.success_implies_effect[{}].call is required "
                "when probe capture is 'all'".format(index)
            )
    _validate_success_effect_selectors(effect_contracts, probe_captures)
    initial_states = _parse_initial_states(data.get("initial_states"))
    boundary_campaigns = _parse_boundary_campaigns(data.get("boundary_campaigns"))
    if any(campaign.follow_up is not None for campaign in boundary_campaigns):
        if not update_sequence:
            raise ProfileError(
                "boundary campaign follow_up requires a real update_sequence"
            )
        if str(fault_sweep.evaluation_mode or "").strip().lower() != "execute":
            raise ProfileError(
                "boundary campaign follow_up requires fault_sweep.evaluation_mode: execute"
            )
    initial_states = initial_states + _boundary_initial_states(
        boundary_campaigns, initial_states
    )
    metadata_fault_regions = _parse_metadata_fault_regions(
        data.get("metadata_fault_regions"), slots=memory.slots
    )
    multi_component = _parse_components(
        data.get("multi_component"),
        profile_path=path,
    )
    if boundary_campaigns and multi_component is not None:
        raise ProfileError(
            "boundary_campaigns cannot be combined with multi_component profiles"
        )
    nvs_region = _parse_nvs_region(data.get("nvs_region"))
    bootloader_region = _parse_bootloader_region(data.get("bootloader_region"))
    boot_register_pre_writes = _parse_boot_register_pre_writes_list(
        data.get("boot_register_pre_writes")
    )
    boot_registers = _parse_boot_registers_list(data.get("boot_registers"))
    write_order_constraints = _parse_write_order_constraints_list(
        data.get("write_order_constraints")
    )
    residual_image = _parse_residual_image(
        data.get("residual_image"), memory.slots, images=images
    )

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

    # Warn when fault_types require a specific backend that the profile hints
    # it doesn't have.  The actual Renode peripheral class is only known at
    # runtime (determined by the .repl/.resc files), so this is best-effort
    # based on the ``platform`` and ``flash_backend`` strings.  A definitive
    # check would require querying Renode's sysbus after machine creation,
    # which is outside the scope of the profile loader.
    _warn_fault_backend_compat(fault_sweep, platform, flash_backend, nvm_controller, otp_peripheral)

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
        extra_peripherals=extra_peripherals,
        success_criteria=success_criteria,
        fault_sweep=fault_sweep,
        state_fuzzer=state_fuzzer,
        expect=expect,
        profile_path=path,
        scenario=scenario,
        update_trigger=update_trigger,
        update_sequence=update_sequence,
        state_probe=state_probe,
        semantic_assertions=semantic_assertions,
        invariants=invariants,
        invariant_providers=invariant_providers,
        invariant_config=invariant_config,
        flash_backend=flash_backend,
        nvm_controller=nvm_controller,
        otp_peripheral=otp_peripheral,
        initial_states=initial_states,
        metadata_fault_regions=metadata_fault_regions,
        multi_component=multi_component,
        nvs_region=nvs_region,
        security_policy=security_policy,
        update_protocol=update_protocol,
        authorization_review=authorization_review,
        bootloader_region=bootloader_region,
        success_criteria_overrides=success_criteria_overrides,
        boot_register_pre_writes=boot_register_pre_writes,
        boot_registers=boot_registers,
        write_order_constraints=write_order_constraints,
        fuzz_corpus=fuzz_corpus,

        residual_image=residual_image,

        firmware_elf=firmware_elf,
        persistent_state_layout=persistent_state_layout,
        terminal_error_paths=terminal_error_paths,
        boundary_campaigns=boundary_campaigns,

    )
    profile.auto_update_trigger = auto_update_trigger

    # If update_trigger is set and pre_boot_state is empty, expand the trigger.
    if update_trigger and not profile.pre_boot_state:
        profile.pre_boot_state = profile.expand_update_trigger()

    if profile.has_update_sequence:
        faulted_phase = profile.faulted_update_phase
        if faulted_phase is None:
            raise ProfileError(
                "update_sequence: missing phase with fault_injection=true after parsing"
            )
        profile.images = dict(faulted_phase.start_images)
        profile.pre_boot_state = list(faulted_phase.pre_boot_state)
        profile.success_criteria = faulted_phase.success_criteria
        profile.fault_sweep.boot_cycles = int(faulted_phase.boot_cycles)
        profile.fault_sweep.boot_cycle_hook = faulted_phase.boot_cycle_hook
        profile.fault_sweep.expected_rollback_at_cycle = (
            faulted_phase.expected_rollback_at_cycle
        )
        profile.fault_sweep.fault_types = list(faulted_phase.fault_types)

    if "nvs_corruption" in profile.fault_sweep.fault_types:
        if profile.nvs_region is None:
            raise ProfileError(
                "fault_sweep.fault_types includes nvs_corruption but no "
                "top-level nvs_region is configured"
            )
        if not profile.fault_sweep.nvs_corruption.enabled:
            raise ProfileError(
                "fault_sweep.fault_types includes nvs_corruption but "
                "fault_sweep.nvs_corruption.enabled is not true"
            )

    if (
        profile.success_criteria.bootloader_integrity
        and profile.bootloader_region is None
    ):
        raise ProfileError(
            "success_criteria.bootloader_integrity requires bootloader_region"
        )

    return profile


def expand_initial_states(profile: ProfileConfig) -> List[ProfileConfig]:
    """Expand a profile into per-state profiles for sweep matrix."""
    if not profile.initial_states:
        return [profile]
    return [profile.resolve_initial_state(s) for s in profile.initial_states]


def expand_boundary_campaigns(profile: ProfileConfig) -> List[ProfileConfig]:
    """Return one ordinary resolved profile per boundary value.

    This helper is useful to scenario runners that want campaign children
    without also selecting manually enumerated initial states.
    """
    states = [
        state for state in profile.initial_states
        if getattr(state, "boundary_campaign", None) is not None
    ]
    return [profile.resolve_initial_state(state) for state in states]


def load_profile_raw(path: str | Path) -> Dict[str, Any]:
    """Load a profile as raw dict (for self_test.py to read expect section).

    Resolves ``base_profile`` inheritance so that the returned dict contains
    all inherited fields.
    """
    if yaml is None:
        raise ProfileError("PyYAML is required.")
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict):
        data = _resolve_base_profile(data, path)
    return data


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
        "fault_types": profile.fault_sweep.fault_types,
        "rc_injection_config": profile.fault_sweep.rc_injection_config.to_dict(),
        "function_return_probes": [
            probe.to_runtime_dict()
            for probe in profile.fault_sweep.function_return_probes
        ],
        "max_writes": profile.fault_sweep.max_writes,
        "boot_cycles": profile.fault_sweep.boot_cycles,
        "calibration_time_slice": profile.fault_sweep.calibration_time_slice,
        "phase1_time_slice": profile.fault_sweep.phase1_time_slice,
        "phase2_time_slice": profile.fault_sweep.phase2_time_slice,
        "phase2_wall_timeout_s": profile.fault_sweep.phase2_wall_timeout_s,
        "boot_cycle_hook": profile.fault_sweep.boot_cycle_hook,
        "expected_rollback_at_cycle": profile.fault_sweep.expected_rollback_at_cycle,
        "phase2_fault_enabled": profile.fault_sweep.phase2_fault.enabled,
        "phase2_fault_max_points": profile.fault_sweep.phase2_fault.max_points,
        "phase2_fault_types": profile.fault_sweep.phase2_fault.fault_types,
        "sweep_hash_bypass_symbols": profile.fault_sweep.sweep_hash_bypass_symbols,
        "hook_fault_enabled": profile.fault_sweep.hook_fault.enabled,
        "hook_fault_max_points": profile.fault_sweep.hook_fault.max_points,
        "hook_fault_types": profile.fault_sweep.hook_fault.fault_types,
        "confirm_cycle_enabled": profile.fault_sweep.confirm_cycle.enabled,
        "confirm_cycle_function": profile.fault_sweep.confirm_cycle.confirm_function,
        "confirm_cycle_max_points": profile.fault_sweep.confirm_cycle.max_points,
        "confirm_cycle_fault_types": profile.fault_sweep.confirm_cycle.fault_types,
        "confirm_cycle_expected_ratchet_version": profile.fault_sweep.confirm_cycle.expected_ratchet_version,
        "firmware_elf": profile.firmware_elf,
        "state_fuzzer_enabled": profile.state_fuzzer.enabled,
        "state_fuzzer_iterations": profile.state_fuzzer.iterations,
        "state_fuzzer_metadata_model": profile.state_fuzzer.metadata_model,
        "expect_should_find_issues": profile.expect.should_find_issues,
        "expect_control_outcome": profile.expect.control_outcome,
        "expect_allow_semantic_only_issues": profile.expect.allow_semantic_only_issues,
        "expect_allow_control_only_issues": profile.expect.allow_control_only_issues,
        "expect_required_issue_reasons": profile.expect.required_issue_reasons,
        "expect_ignored_issue_fault_types": profile.expect.ignored_issue_fault_types,
        "image_hash": profile.success_criteria.image_hash,
        "image_hash_slot": profile.success_criteria.image_hash_slot,
        "otadata_expect": profile.success_criteria.otadata_expect,
        "otadata_expect_scope": profile.success_criteria.otadata_expect_scope,
        "state_probe": (
            {
                "script": profile.state_probe.script,
                "format": profile.state_probe.format,
                "contract_version": profile.state_probe.contract_version,
                "required_paths": profile.state_probe.required_paths,
            }
            if profile.state_probe is not None
            else None
        ),
        "semantic_assertions": profile.semantic_assertions,
        "invariants": profile.invariants,
        "invariant_providers": profile.invariant_providers,
        "invariant_config": profile.invariant_config,
        "update_trigger": profile.update_trigger.type if profile.update_trigger else None,
        "update_sequence": [
            {
                "name": phase.name,
                "fault_injection": phase.fault_injection,
                "boot_cycles": phase.boot_cycles,
                "boot_cycle_hook": phase.boot_cycle_hook,
                "fault_types": phase.fault_types,
            }
            for phase in profile.update_sequence
        ],
        "pre_boot_state_count": len(profile.pre_boot_state),
        "initial_states": [{"name": s.name, "description": s.description}
                           for s in profile.initial_states],
        "boundary_campaigns": [boundary_campaign_dict(campaign)
                               for campaign in profile.boundary_campaigns],
        "multi_fault": {
            "enabled": profile.fault_sweep.multi_fault.enabled,
            "strategy": profile.fault_sweep.multi_fault.strategy,
            "fallback_strategy": profile.fault_sweep.multi_fault.fallback_strategy,
            "max_faults_per_run": profile.fault_sweep.multi_fault.max_faults_per_run,
            "max_pairs": profile.fault_sweep.multi_fault.max_pairs,
            "seed": profile.fault_sweep.multi_fault.seed,
            "sequences_count": len(profile.fault_sweep.multi_fault.sequences),
        },
        "read_fault_config": (
            {
                "target_regions": [
                    {"start": "0x{:08X}".format(s), "end": "0x{:08X}".format(e)}
                    for s, e in profile.fault_sweep.read_fault_config.target_regions
                ],
                "bit_flip_count": profile.fault_sweep.read_fault_config.bit_flip_count,
                "fault_probability": profile.fault_sweep.read_fault_config.fault_probability,
                "seed": profile.fault_sweep.read_fault_config.seed,
            }
            if profile.fault_sweep.read_fault_config is not None
            else None
        ),
        "metadata_fault_regions": [
            {"name": r.name, "start": "0x{:X}".format(r.start), "end": "0x{:X}".format(r.end)}
            for r in profile.metadata_fault_regions
        ],
        "multi_component": (
            {
                "fault_matrix": profile.multi_component.fault_matrix,
                "components": [
                    {"name": c.name, "platform": c.platform}
                    for c in profile.multi_component.components
                ],
            }
            if profile.multi_component is not None
            else None
        ),
        "partial_staging": profile.fault_sweep.partial_staging is not None,
        "security_policy": {
            "anti_rollback": profile.security_policy.anti_rollback,
            "minimum_version": profile.security_policy.minimum_version,
            "toctou_protection": profile.security_policy.toctou_protection,
        },
        "persistent_state_layout": (
            analyze_persistent_state_layout(profile.persistent_state_layout)
            if profile.persistent_state_layout is not None
            else None
        ),
        "update_protocol_analysis": (
            analyze_update_protocol(profile.update_protocol, profile.security_policy)
            if profile.update_protocol is not None
            else None
        ),
        "authorization_review_analysis": (
            analyze_authorization_review(profile.authorization_review)
            if getattr(profile, "authorization_review", None) is not None
            else None
        ),
        "residual_image": (
            {
                "slot": profile.residual_image.slot,
                "prior_image": profile.residual_image.prior_image,
                "fill_pattern": (
                    "0x{:02X}".format(profile.residual_image.fill_pattern)
                    if profile.residual_image.fill_pattern is not None
                    else None
                ),
            }
            if profile.residual_image is not None
            else None
        ),
        "max_reset_vector_offset": (
            "0x{:X}".format(profile.success_criteria.max_reset_vector_offset)
            if profile.success_criteria.max_reset_vector_offset is not None
            else None
        ),
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
