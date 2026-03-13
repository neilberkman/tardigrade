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
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fault_inject import BootloaderRegionConfig, FaultDistributionConfig, MetadataFaultRegion

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None  # type: ignore[assignment]


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
    "read_bit_flip",
    "command_drop",
    "bootloader_region_write",
    "nvs_corruption",
    "instruction_skip",
    "i2c_nack",
    "i2c_timeout",
    "i2c_bit_flip",
    "i2c_truncated",
    "i2c_wrong_address",
    "otp_partial_program",
    "otp_stuck_bit",
    "otp_read_disturb",
    "otp_overblow",
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
    "read_bit_flip",
    "command_drop",
    "nvs_corruption",
    "instruction_skip",
    "i2c_nack",
    "i2c_timeout",
    "i2c_bit_flip",
    "i2c_truncated",
    "i2c_wrong_address",
    "otp_partial_program",
    "otp_stuck_bit",
    "otp_read_disturb",
    "otp_overblow",
}

# Fault types that are classification/heuristic labels, not injectable fault
# mechanisms.  They appear in KNOWN_FAULT_TYPES (so profiles can reference them
# for heuristic tuning) but are NOT in IMPLEMENTED_FAULT_TYPES because the
# sweep planner does not generate fault points for them directly.
CLASSIFICATION_ONLY_FAULT_TYPES = {
    "bootloader_region_write",
}

# Map OTP fault type names to their OTPMemory BlowFaultMode codes.
OTP_FAULT_TYPE_CODES = {
    "otp_partial_program": 0,
    "otp_stuck_bit": 1,
    "otp_read_disturb": 2,
    "otp_overblow": 3,
}

# Map I2C fault type names to their I2CFaultProxy FaultType codes.
I2C_FAULT_TYPE_CODES = {
    "i2c_nack": 1,
    "i2c_timeout": 2,
    "i2c_bit_flip": 3,
    "i2c_truncated": 4,
    "i2c_wrong_address": 5,
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
    __slots__ = ("sram_start", "sram_end", "write_granularity", "slots", "bootloader_region")

    def __init__(
        self,
        sram_start: int,
        sram_end: int,
        write_granularity: int,
        slots: Dict[str, SlotConfig],
        bootloader_region: Optional[BootloaderRegionConfig] = None,
    ) -> None:
        self.sram_start = sram_start
        self.sram_end = sram_end
        self.write_granularity = write_granularity
        self.slots = slots
        self.bootloader_region = bootloader_region


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
        self.strategy = strategy
        self.fallback_strategy = fallback_strategy
        self.max_pairs = max(1, int(max_pairs))
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
    scan.  Every halfword-aligned address in each range is a potential
    fault point.  ``skip_count`` controls how many consecutive halfwords
    to NOP (default 1, i.e. one 16-bit Thumb instruction).
    """

    __slots__ = ("target_addresses", "skip_count")

    def __init__(
        self,
        target_addresses: Optional[List[Tuple[int, int]]] = None,
        skip_count: int = 1,
    ) -> None:
        self.target_addresses: List[Tuple[int, int]] = target_addresses or []
        self.skip_count = max(1, int(skip_count))
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
        return ProfileConfig(
            schema_version=parent.schema_version,
            name="{}/{}".format(parent.name, self.name),
            description="Component '{}' of {}".format(self.name, parent.name),
            platform=self.platform,
            bootloader_elf=self.bootloader_elf,
            bootloader_entry=self.bootloader_entry,
            memory=self.memory,
            images=self.images,
            pre_boot_state=list(self.pre_boot_state),
            setup_script=self.setup_script,
            extra_peripherals=self.extra_peripherals,
            success_criteria=self.success_criteria,
            fault_sweep=self.fault_sweep or parent.fault_sweep,
            state_fuzzer=parent.state_fuzzer,
            expect=parent.expect,
            profile_path=parent.profile_path,
            scenario=parent.scenario,
            update_sequence=parent.update_sequence,
            flash_backend=self.flash_backend,
            success_criteria_overrides=parent.success_criteria_overrides,
        )


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
    ) -> None:
        self.tier2_step = int(tier2_step)
        self.tier3_step = int(tier3_step)
        self.discontinuity_window = int(discontinuity_window)
        self.target_points = None if target_points is None else int(target_points)
        self.preserve_critical_tiers = bool(preserve_critical_tiers)
        self.shard_count = int(shard_count)
        self.shard_index = int(shard_index)
        self.random_tail_budget = int(random_tail_budget)
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
        }


class FaultSweepConfig:
    __slots__ = (
        "mode",
        "max_writes",
        "max_writes_cap",
        "max_step_limit",
        "run_duration",
        "phase2_time_slice",
        "fault_types",
        "evaluation_mode",
        "sweep_strategy",
        "sweep_hash_bypass_symbols",
        "progress_stall_timeout_s",
        "boot_cycles",
        "boot_cycle_hook",
        "expected_rollback_at_cycle",
        "phase2_fault",
        "hook_fault",
        "multi_fault",
        "read_fault_config",
        "instruction_skip_config",
        "metadata_fault",
        "partial_staging",
        "nvs_corruption",
        "fault_distribution",
        "heuristic_config",
        "boot_registers",
        "reset_mode",
        "write_order_constraints",
        "i2c_fault_config",
    )

    def __init__(
        self,
        mode: str = "runtime",
        max_writes: Any = "auto",
        max_writes_cap: int = 100000,
        max_step_limit: int = 500000,
        run_duration: str = "0.5",
        phase2_time_slice: Optional[str] = None,
        fault_types: Optional[List[str]] = None,
        evaluation_mode: Optional[str] = None,
        sweep_strategy: str = "heuristic",
        sweep_hash_bypass_symbols: Optional[List[str]] = None,
        progress_stall_timeout_s: Optional[float] = None,
        boot_cycles: int = 1,
        boot_cycle_hook: Optional[str] = None,
        expected_rollback_at_cycle: Optional[int] = None,
        phase2_fault: Optional["Phase2FaultConfig"] = None,
        hook_fault: Optional["HookFaultConfig"] = None,
        multi_fault=None,
        read_fault_config: Optional["ReadFaultConfig"] = None,
        instruction_skip_config: Optional["InstructionSkipConfig"] = None,
        metadata_fault: Optional["MetadataFaultConfig"] = None,
        partial_staging: Optional[Any] = None,
        nvs_corruption: Optional["NvsCorruptionConfig"] = None,
        fault_distribution: Optional["FaultDistributionConfig"] = None,
        heuristic_config: Optional["HeuristicConfig"] = None,
        boot_registers: Optional[List[Dict[str, Any]]] = None,
        reset_mode: str = "warm",
        write_order_constraints: Optional[List[Dict[str, Any]]] = None,
        i2c_fault_config: Optional["I2CFaultConfig"] = None,
    ) -> None:
        self.mode = mode
        self.max_writes = max_writes
        self.max_writes_cap = max_writes_cap
        self.max_step_limit = max_step_limit
        self.run_duration = run_duration
        self.phase2_time_slice = (
            str(phase2_time_slice).strip() if phase2_time_slice else None
        )
        self.fault_types = fault_types or ["power_loss"]
        self.evaluation_mode = evaluation_mode
        self.sweep_strategy = sweep_strategy
        self.sweep_hash_bypass_symbols = sweep_hash_bypass_symbols or []
        self.progress_stall_timeout_s = progress_stall_timeout_s
        self.boot_cycles = max(1, int(boot_cycles))
        self.boot_cycle_hook = str(boot_cycle_hook).strip() if boot_cycle_hook else None
        self.expected_rollback_at_cycle = (
            None
            if expected_rollback_at_cycle is None
            else max(1, int(expected_rollback_at_cycle))
        )
        self.phase2_fault = phase2_fault or Phase2FaultConfig()
        self.hook_fault = hook_fault or HookFaultConfig()
        self.multi_fault = multi_fault or MultiFaultConfig()
        self.read_fault_config = read_fault_config
        self.instruction_skip_config = instruction_skip_config
        self.metadata_fault = metadata_fault or MetadataFaultConfig()
        self.partial_staging = partial_staging
        self.nvs_corruption = nvs_corruption or NvsCorruptionConfig()
        self.fault_distribution = fault_distribution or FaultDistributionConfig()
        self.heuristic_config = heuristic_config
        self.boot_registers = boot_registers or []
        self.reset_mode = reset_mode if reset_mode in ("warm", "cold") else "warm"
        self.write_order_constraints = write_order_constraints or []
        self.i2c_fault_config = i2c_fault_config


class StateFuzzerConfig:
    __slots__ = ("enabled", "metadata_model")

    def __init__(self, enabled: bool = False, metadata_model: str = "ab_replica") -> None:
        self.enabled = enabled
        self.metadata_model = metadata_model


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
    __slots__ = ("should_find_issues", "control_outcome", "allow_semantic_only_issues", "required_issue_reasons")

    def __init__(
        self,
        should_find_issues: bool = True,
        control_outcome: str = "success",
        allow_semantic_only_issues: bool = False,
        required_issue_reasons: Optional[List[str]] = None,
    ) -> None:
        self.should_find_issues = should_find_issues
        self.control_outcome = control_outcome
        self.allow_semantic_only_issues = allow_semantic_only_issues
        self.required_issue_reasons = required_issue_reasons or []


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
        self.pre_boot_state = pre_boot_state or []
        self.success_criteria = success_criteria or SuccessCriteria()
        self.boot_cycles = max(1, int(boot_cycles))
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
                 "update_trigger", "expect_overrides")

    def __init__(self, name: str, description: str = "",
                 pre_boot_state: Optional[List[PreBootWrite]] = None,
                 setup_script: Optional[str] = None,
                 update_trigger: Optional[UpdateTrigger] = None,
                 expect_overrides: Optional[Dict[str, Any]] = None) -> None:
        self.name = name
        self.description = description
        self.pre_boot_state = pre_boot_state
        self.setup_script = setup_script
        self.update_trigger = update_trigger
        self.expect_overrides = expect_overrides or {}


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
        bootloader_region: Optional[BootloaderRegionConfig] = None,
        success_criteria_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
        boot_register_pre_writes: Optional[List[BootRegisterPreWrite]] = None,
        boot_registers: Optional[List[BootRegisterDef]] = None,
        write_order_constraints: Optional[List[WriteOrderConstraint]] = None,
        fuzz_corpus: Optional[str] = None,
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
        self.initial_states: List[InitialStateConfig] = initial_states or []
        self.metadata_fault_regions: List[MetadataFaultRegion] = metadata_fault_regions or []
        self.multi_component: Optional[MultiComponentConfig] = multi_component
        self.nvs_region = nvs_region
        self.bootloader_region: Optional[BootloaderRegionConfig] = bootloader_region
        self.success_criteria_overrides: Dict[str, Dict[str, Any]] = success_criteria_overrides or {}
        self.boot_register_pre_writes: List[BootRegisterPreWrite] = boot_register_pre_writes or []
        self.boot_registers: List[BootRegisterDef] = boot_registers or []
        self.write_order_constraints: List[WriteOrderConstraint] = write_order_constraints or []
        self.fuzz_corpus: Optional[str] = fuzz_corpus

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
                required_issue_reasons=eo.get("required_issue_reasons", self.expect.required_issue_reasons),
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
            flash_backend=self.flash_backend, initial_states=[],
            metadata_fault_regions=self.metadata_fault_regions,
            nvs_region=self.nvs_region,
            security_policy=self.security_policy,
            success_criteria_overrides=self.success_criteria_overrides,
            fuzz_corpus=self.fuzz_corpus,
        )
        if state.update_trigger is not None and state.pre_boot_state is None:
            resolved.pre_boot_state = resolved.expand_update_trigger()
        return resolved

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

        digests: Dict[str, str] = {}
        for img_name, img_path in images.items():
            resolved = self.resolve_path(repo_root, img_path)
            with open(resolved, "rb") as fh:
                raw = fh.read()
            if data_size is not None:
                if len(raw) >= data_size:
                    raw = raw[:data_size]
                else:
                    raw = raw + (b"\xFF" * (data_size - len(raw)))
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
        if fs.phase2_time_slice:
            vars_list.append("PHASE2_TIME_SLICE:{}".format(fs.phase2_time_slice))
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
        update_sequence_file = self.generate_update_sequence_file(repo_root)
        if update_sequence_file:
            vars_list.append("UPDATE_SEQUENCE_FILE:{}".format(update_sequence_file))

        # Setup script.
        if self.setup_script:
            vars_list.append(
                "SETUP_SCRIPT:{}".format(self.resolve_path(repo_root, self.setup_script))
            )
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
        if mem.bootloader_region is not None:
            vars_list.append(
                "BOOTLOADER_REGION_BASE:0x{:08X}".format(mem.bootloader_region.base)
            )
            vars_list.append(
                "BOOTLOADER_REGION_SIZE:0x{:08X}".format(mem.bootloader_region.size)
            )

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
            vars_list.append(
                "NVS_CORRUPTION_MODES:{}".format(",".join(nvs_cfg.modes))
            )
            vars_list.append(
                "NVS_CORRUPTION_SEED:{}".format(nvs_cfg.seed)
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
            import base64
            raw_json = json.dumps(self.success_criteria_overrides, separators=(",", ":"))
            b64 = base64.b64encode(raw_json.encode()).decode().rstrip("=")
            vars_list.append("SUCCESS_CRITERIA_OVERRIDES:{}".format(b64))

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


def _parse_memory(raw: Dict[str, Any]) -> MemoryConfig:
    sram = _require(raw, "sram", "memory")
    sram_start = _parse_int(_require(sram, "start", "memory.sram"), "memory.sram.start")
    sram_end = _parse_int(_require(sram, "end", "memory.sram"), "memory.sram.end")
    write_granularity = _parse_int(raw.get("write_granularity", 8), "memory.write_granularity")
    slots = _parse_slots(_require(raw, "slots", "memory"))
    bootloader_region = _parse_bootloader_region(raw.get("bootloader_region"))
    return MemoryConfig(
        sram_start=sram_start,
        sram_end=sram_end,
        write_granularity=write_granularity,
        slots=slots,
        bootloader_region=bootloader_region,
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
        vector_table_offset=_parse_int(raw.get("vector_table_offset", 0), "success_criteria.vector_table_offset"),
        pc_in_slot=raw.get("pc_in_slot"),
        marker_address=_parse_int(raw["marker_address"], "success_criteria.marker_address") if "marker_address" in raw else None,
        marker_value=_parse_int(raw["marker_value"], "success_criteria.marker_value") if "marker_value" in raw else None,
        image_hash=bool(raw.get("image_hash", False)),
        expected_image=raw.get("expected_image"),
        image_hash_slot=raw.get("image_hash_slot"),
        otadata_expect=_parse_otadata_expect(raw.get("otadata_expect")),
        otadata_expect_scope=otadata_expect_scope,
        bootloader_integrity=bool(raw.get("bootloader_integrity", False)),
        config_checks=_parse_config_checks(raw.get("config_checks")),
        boot_register_values=_parse_boot_register_values(raw.get("boot_register_values")),
    )


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


def _parse_heuristic_config(raw: Optional[Dict[str, Any]]) -> Optional[HeuristicConfig]:
    """Parse the optional heuristic sub-config from fault_sweep."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.heuristic: expected mapping")
    return HeuristicConfig(
        tier2_step=int(raw.get("tier2_step", 3)),
        tier3_step=int(raw.get("tier3_step", 100)),
        discontinuity_window=int(raw.get("discontinuity_window", 3)),
        target_points=int(raw["target_points"]) if "target_points" in raw else None,
        preserve_critical_tiers=bool(raw.get("preserve_critical_tiers", True)),
        shard_count=int(raw.get("shard_count", 1)),
        shard_index=int(raw.get("shard_index", 0)),
        random_tail_budget=int(raw.get("random_tail_budget", 0)),
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

    # OTP fault types require an OTPMemory peripheral on the platform.
    otp_types = {"otp_partial_program", "otp_stuck_bit", "otp_read_disturb", "otp_overblow"}
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
    fault_types = raw.get("fault_types", ["power_loss"])
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            import warnings
            warnings.warn("Unknown fault type '{}' in profile; ignoring.".format(ft))
        elif ft in CLASSIFICATION_ONLY_FAULT_TYPES:
            import warnings
            warnings.warn(
                "Fault type '{}' is a classification/heuristic label, not an "
                "injectable fault type. It does not generate fault points in "
                "the sweep planner. Remove it from fault_types.".format(ft)
            )
        elif ft not in IMPLEMENTED_FAULT_TYPES:
            import warnings
            warnings.warn("Fault type '{}' is not yet implemented; skipping.".format(ft))
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

    return FaultSweepConfig(
        mode=raw.get("mode", "runtime"),
        max_writes=raw.get("max_writes", "auto"),
        max_writes_cap=int(raw.get("max_writes_cap", 100000)),
        max_step_limit=int(raw.get("max_step_limit", 500000)),
        run_duration=str(raw.get("run_duration", "0.5")),
        phase2_time_slice=raw.get("phase2_time_slice"),
        fault_types=fault_types,
        evaluation_mode=eval_mode,
        sweep_strategy=str(raw.get("sweep_strategy", "heuristic")),
        sweep_hash_bypass_symbols=sweep_hash_bypass,
        progress_stall_timeout_s=stall_timeout,
        boot_cycles=boot_cycles,
        boot_cycle_hook=boot_cycle_hook,
        expected_rollback_at_cycle=expected_rollback_at_cycle,
        phase2_fault=_parse_phase2_fault(raw.get("phase2_fault")),
        hook_fault=hook_fault,
        multi_fault=multi_fault_config,
        read_fault_config=_parse_read_fault_config(raw.get("read_fault_config")),
        instruction_skip_config=_parse_instruction_skip_config(
            raw.get("instruction_skip_config"),
            bootloader_elf=bootloader_elf,
            profile_path=profile_path,
        ),
        metadata_fault=_parse_metadata_fault(raw.get("metadata_fault")),
        partial_staging=raw.get("partial_staging"),
        nvs_corruption=_parse_nvs_corruption(raw.get("nvs_corruption")),
        fault_distribution=_parse_fault_distribution(raw.get("fault_distribution")),
        heuristic_config=_parse_heuristic_config(raw.get("heuristic")),
        reset_mode=str(raw.get("reset_mode", "warm")),
        i2c_fault_config=_parse_i2c_fault_config(raw.get("i2c_fault_config")),
    )


def _parse_phase2_fault(raw: Optional[Dict[str, Any]]) -> Phase2FaultConfig:
    if raw is None:
        return Phase2FaultConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.phase2_fault: expected mapping")
    enabled = bool(raw.get("enabled", False))
    fault_types = raw.get("fault_types", ["power_loss"])
    if not isinstance(fault_types, list):
        fault_types = [str(fault_types)]
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            import warnings

            warnings.warn("Unknown phase2_fault type '{}'; ignoring.".format(ft))
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
    enabled = bool(raw.get("enabled", False))
    fault_types = raw.get("fault_types", ["power_loss"])
    if not isinstance(fault_types, list):
        fault_types = [str(fault_types)]
    valid_hook_types = {"power_loss", "bit_corruption", "command_drop"}
    parsed_types: List[str] = []
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            import warnings

            warnings.warn("Unknown hook_fault type '{}'; ignoring.".format(ft))
            continue
        if ft not in valid_hook_types:
            import warnings

            warnings.warn(
                "Unsupported hook_fault type '{}'; only {} are supported.".format(
                    ft, sorted(valid_hook_types)
                )
            )
            continue
        parsed_types.append(ft)
    if not parsed_types:
        parsed_types = ["power_loss"]
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

def _parse_multi_fault(raw):
    """Parse multi_fault configuration from profile YAML."""
    if raw is None:
        return MultiFaultConfig()
    if not isinstance(raw, dict):
        raise ProfileError("fault_sweep.multi_fault: expected mapping")
    enabled = bool(raw.get("enabled", False))
    max_faults_per_run = int(raw.get("max_faults_per_run", 2))
    if max_faults_per_run < 2:
        raise ProfileError(
            "fault_sweep.multi_fault.max_faults_per_run: expected integer >= 2"
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
        sequences = []
        for i, seq in enumerate(sequences_raw):
            if not isinstance(seq, list) or len(seq) < 2:
                raise ProfileError(
                    "fault_sweep.multi_fault.sequences[{}]: expected list of >= 2 integers".format(i)
                )
            sequences.append([int(x) for x in seq])
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


def _count_instruction_skip_fault_points(start: int, end: int, skip_count: int) -> int:
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
    matches = [
        (name, start, end)
        for name, start, end in functions
        if symbol_query in name
    ]
    if not matches:
        raise ProfileError(
            "{}: no function symbols matching {!r} in {}. "
            "Available function symbols: {}".format(
                ctx,
                symbol_query,
                elf_path,
                ", ".join(available_symbols),
            )
        )

    resolved_ranges: List[Tuple[int, int]] = []
    seen_ranges: set[Tuple[int, int]] = set()
    unresolved_symbols: List[str] = []
    for name, start, end in matches:
        if end is None or end <= start:
            unresolved_symbols.append(name)
            continue
        if (start, end) not in seen_ranges:
            seen_ranges.add((start, end))
            resolved_ranges.append((start, end))
        print(
            "Resolved {!r} -> {} [0x{:x}, 0x{:x}) ({} bytes, {} fault points)".format(
                symbol_query,
                name,
                start,
                end,
                end - start,
                _count_instruction_skip_fault_points(start, end, skip_count),
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
    return resolved_ranges


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
    return InstructionSkipConfig(
        target_addresses=target_addresses,
        skip_count=skip_count,
    )



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
    enabled = bool(raw.get("enabled", False))
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
                import warnings
                warnings.warn(
                    "metadata_fault.fault_types: unknown type '{}', ignoring".format(ft_str)
                )
                continue
            fault_types.append(ft_str)
        if not fault_types:
            fault_types = ["power_loss"]
    return MetadataFaultConfig(enabled=enabled, fault_types=fault_types)


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
        nonzero = bool(entry.get("nonzero", False))
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
                    range_min = int(rng["min"])
                if "max" in rng:
                    range_max = int(rng["max"])
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
            bidirectional=bool(entry.get("bidirectional", False)),
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
    enabled = bool(raw.get("enabled", False))
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
    anti_rollback = bool(raw.get("anti_rollback", False))
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
    toctou_protection = bool(raw.get("toctou_protection", False))
    return SecurityPolicyConfig(
        anti_rollback=anti_rollback,
        minimum_version=minimum_version,
        toctou_protection=toctou_protection,
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


def _parse_state_fuzzer(raw: Optional[Dict[str, Any]]) -> StateFuzzerConfig:
    if raw is None:
        return StateFuzzerConfig()
    return StateFuzzerConfig(
        enabled=bool(raw.get("enabled", False)),
        metadata_model=str(raw.get("metadata_model", "ab_replica")),
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


def _parse_expect(raw: Optional[Dict[str, Any]]) -> ExpectConfig:
    if raw is None:
        return ExpectConfig()
    required_issue_reasons = [
        str(reason).strip()
        for reason in raw.get("required_issue_reasons", [])
        if str(reason).strip()
    ]
    return ExpectConfig(
        should_find_issues=bool(raw.get("should_find_issues", True)),
        control_outcome=str(raw.get("control_outcome", "success")),
        allow_semantic_only_issues=bool(raw.get("allow_semantic_only_issues", False)),
        required_issue_reasons=required_issue_reasons,
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


def _normalize_fault_types(raw: Any, field_name: str) -> List[str]:
    if raw is None:
        fault_types = ["power_loss"]
    elif isinstance(raw, list):
        fault_types = [str(ft) for ft in raw]
    else:
        fault_types = [str(raw)]

    import warnings

    normalized: List[str] = []
    for ft in fault_types:
        if ft not in KNOWN_FAULT_TYPES:
            warnings.warn("Unknown fault type '{}' in {}; ignoring.".format(ft, field_name))
            continue
        if ft in CLASSIFICATION_ONLY_FAULT_TYPES:
            warnings.warn(
                "Fault type '{}' in {} is a classification label only and "
                "does not generate runtime fault points.".format(ft, field_name)
            )
            continue
        if ft not in IMPLEMENTED_FAULT_TYPES:
            warnings.warn("Fault type '{}' in {} is not yet implemented; skipping.".format(ft, field_name))
            continue
        normalized.append(ft)

    return normalized or ["power_loss"]


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
        phase_hook = entry.get("boot_cycle_hook", fault_sweep.boot_cycle_hook)
        if phase_hook is not None:
            phase_hook = str(phase_hook).strip()
            if not phase_hook:
                raise ProfileError("{}.boot_cycle_hook: expected non-empty path".format(ctx))
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
        phases.append(
            UpdatePhase(
                name=name,
                description=str(entry.get("description", "")),
                images=phase_images,
                pre_boot_state=_parse_pre_boot_state(entry.get("pre_boot_state")),
                success_criteria=phase_success,
                boot_cycles=phase_boot_cycles,
                boot_cycle_hook=phase_hook,
                expected_rollback_at_cycle=expected_rollback_at_cycle,
                fault_injection=bool(entry.get("fault_injection", False)),
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
        name = str(entry.get("name", "")).strip()
        if not name:
            raise ProfileError("initial_states[{}].name: expected non-empty string".format(idx))
        if name in seen_names:
            raise ProfileError("initial_states: duplicate name '{}'".format(name))
        seen_names.add(name)
        description = str(entry.get("description", ""))
        pre_boot = _parse_pre_boot_state(entry.get("pre_boot_state"))
        setup_script = entry.get("setup_script")
        if setup_script is not None:
            setup_script = str(setup_script)
        trigger = _parse_update_trigger(entry.get("update_trigger"))
        expect_overrides = entry.get("expect")
        if expect_overrides is not None and not isinstance(expect_overrides, dict):
            raise ProfileError("initial_states[{}].expect: expected mapping".format(idx))
        parsed_pre_boot: Optional[List[PreBootWrite]] = None
        if "pre_boot_state" in entry:
            parsed_pre_boot = pre_boot
        states.append(InitialStateConfig(name=name, description=description,
            pre_boot_state=parsed_pre_boot, setup_script=setup_script,
            update_trigger=trigger, expect_overrides=expect_overrides or {}))
    return states


def _parse_component(
    raw: Dict[str, Any],
    idx: int,
    *,
    profile_path: Optional[Path] = None,
) -> ComponentConfig:
    """Parse a single component definition from the components list."""
    ctx = "components[{}]".format(idx)
    name = str(_require(raw, "name", ctx)).strip()
    if not name:
        raise ProfileError("{}.name: expected non-empty string".format(ctx))

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
    return dict(raw)


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

    fuzz_corpus_raw = data.get("fuzz_corpus")
    fuzz_corpus: Optional[str] = str(fuzz_corpus_raw) if fuzz_corpus_raw is not None else None
    expect = _parse_expect(data.get("expect"))
    semantic_assertions = _parse_semantic_assertions(data.get("semantic_assertions"))
    invariants = _parse_invariants(data.get("invariants"))
    invariant_providers = _parse_invariant_providers(data.get("invariant_providers"))
    invariant_config = _parse_invariant_config(data.get("invariant_config"))
    initial_states = _parse_initial_states(data.get("initial_states"))
    metadata_fault_regions = _parse_metadata_fault_regions(
        data.get("metadata_fault_regions"), slots=memory.slots
    )
    multi_component = _parse_components(
        data.get("multi_component"),
        profile_path=path,
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
        bootloader_region=bootloader_region,
        success_criteria_overrides=success_criteria_overrides,
        boot_register_pre_writes=boot_register_pre_writes,
        boot_registers=boot_registers,
        write_order_constraints=write_order_constraints,
        fuzz_corpus=fuzz_corpus,
    )

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

    return profile


def expand_initial_states(profile: ProfileConfig) -> List[ProfileConfig]:
    """Expand a profile into per-state profiles for sweep matrix."""
    if not profile.initial_states:
        return [profile]
    return [profile.resolve_initial_state(s) for s in profile.initial_states]


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
        "phase2_time_slice": profile.fault_sweep.phase2_time_slice,
        "boot_cycle_hook": profile.fault_sweep.boot_cycle_hook,
        "expected_rollback_at_cycle": profile.fault_sweep.expected_rollback_at_cycle,
        "phase2_fault_enabled": profile.fault_sweep.phase2_fault.enabled,
        "phase2_fault_max_points": profile.fault_sweep.phase2_fault.max_points,
        "phase2_fault_types": profile.fault_sweep.phase2_fault.fault_types,
        "sweep_hash_bypass_symbols": profile.fault_sweep.sweep_hash_bypass_symbols,
        "hook_fault_enabled": profile.fault_sweep.hook_fault.enabled,
        "hook_fault_max_points": profile.fault_sweep.hook_fault.max_points,
        "hook_fault_types": profile.fault_sweep.hook_fault.fault_types,
        "state_fuzzer_enabled": profile.state_fuzzer.enabled,
        "expect_should_find_issues": profile.expect.should_find_issues,
        "expect_control_outcome": profile.expect.control_outcome,
        "expect_allow_semantic_only_issues": profile.expect.allow_semantic_only_issues,
        "expect_required_issue_reasons": profile.expect.required_issue_reasons,
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
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
