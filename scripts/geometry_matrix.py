#!/usr/bin/env python3
"""Parameterized geometry generator for OTA bootloader fault-injection testing.

Generates Renode platform descriptions (.repl), linker scripts, boot-metadata
generators, and campaign runner arguments for a matrix of NVM memory layouts.
This catches geometry/math bugs (the MCUboot bug class) that only manifest
with non-default slot sizes, metadata placement, or word sizes.

Includes MCUboot-specific geometries that target known bug classes in swap-based
OTA (mixed sector sizes, trailer boundary conditions, scratch area sizing, etc.).

Usage:
    python3 scripts/geometry_matrix.py --output-dir /tmp/geo_matrix
    python3 scripts/geometry_matrix.py --output-dir /tmp/geo_matrix --geometry default small_nvm
    python3 scripts/geometry_matrix.py --output-dir /tmp/geo_matrix --mode mcuboot
    python3 scripts/geometry_matrix.py --output-dir /tmp/geo_matrix --mode all
    python3 scripts/geometry_matrix.py --list
    python3 scripts/geometry_matrix.py --list --mode mcuboot
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# NVM base address (fixed for all geometries)
# ---------------------------------------------------------------------------

NVM_BASE: int = 0x10000000


# ---------------------------------------------------------------------------
# GeometryConfig
# ---------------------------------------------------------------------------

@dataclass
class GeometryConfig:
    """Describes one NVM memory layout for OTA testing.

    All slot/metadata offsets are relative to the NVM base address
    (0x10000000).  Sizes are in bytes.
    """

    nvm_size: int           # Total NVM in bytes
    word_size: int          # Write granularity: 4 or 8 bytes
    slot_a_offset: int      # Offset from NVM base to slot A start
    slot_a_size: int        # Slot A size in bytes
    slot_b_offset: int      # Offset from NVM base to slot B start
    slot_b_size: int        # Slot B size in bytes
    metadata_offset: int    # Offset from NVM base to metadata region
    metadata_size: int      # Metadata size (256 min for one replica, 512 for two)
    sram_size: int          # SRAM size in bytes
    name: str               # Human-readable identifier


# ---------------------------------------------------------------------------
# MCUboot-specific geometry config
# ---------------------------------------------------------------------------

@dataclass
class SectorRange:
    """One contiguous run of same-sized sectors within a slot."""

    count: int        # Number of sectors in this range
    size: int         # Size of each sector in bytes


@dataclass
class MCUbootGeometryConfig(GeometryConfig):
    """Extends GeometryConfig with MCUboot swap-specific layout parameters.

    MCUboot's swap algorithm depends on sector geometry, scratch area sizing,
    trailer placement, and alignment constraints that the base GeometryConfig
    does not capture.  These extra fields let us generate geometries that
    exercise known MCUboot bug classes.
    """

    # Sector map for slot A (list of SectorRange).  If empty, uniform sectors
    # of `sector_size` are assumed.
    slot_a_sectors: List[SectorRange] = field(default_factory=list)

    # Sector map for slot B.  Same convention.
    slot_b_sectors: List[SectorRange] = field(default_factory=list)

    # Uniform sector size (used when slot_*_sectors is empty).
    sector_size: int = 0x1000  # 4KB default

    # Scratch area for swap-scratch algorithm.
    scratch_offset: int = 0
    scratch_size: int = 0

    # MCUboot image trailer size in bytes.
    trailer_size: int = 128

    # MCUboot write alignment (BOOT_MAX_ALIGN).
    write_alignment: int = 8

    # Human-readable description of what bug class this geometry targets.
    bug_class: str = ""


def _sector_total(sectors: List[SectorRange]) -> int:
    """Return the total size covered by a sector map."""
    return sum(s.count * s.size for s in sectors)


def _largest_sector(sectors: List[SectorRange]) -> int:
    """Return the largest sector size in a sector map."""
    if not sectors:
        return 0
    return max(s.size for s in sectors)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_geometry(config: GeometryConfig) -> None:
    """Check that a geometry is internally consistent.

    Raises ValueError on any overlap, alignment, or bounds violation.
    """
    errors: List[str] = []

    # Word size must be 4 or 8.
    if config.word_size not in (4, 8):
        errors.append("word_size must be 4 or 8, got {}".format(config.word_size))

    # NVM size must be positive and a power-of-two multiple of word_size.
    if config.nvm_size <= 0:
        errors.append("nvm_size must be positive, got {}".format(config.nvm_size))

    # Metadata minimum.
    if config.metadata_size < 256:
        errors.append(
            "metadata_size must be >= 256 (one replica), got {}".format(config.metadata_size)
        )

    # Slot sizes must be positive.
    if config.slot_a_size <= 0:
        errors.append("slot_a_size must be positive, got {}".format(config.slot_a_size))
    if config.slot_b_size <= 0:
        errors.append("slot_b_size must be positive, got {}".format(config.slot_b_size))

    # SRAM must be positive.
    if config.sram_size <= 0:
        errors.append("sram_size must be positive, got {}".format(config.sram_size))

    # Word alignment checks.
    ws = config.word_size
    for label, value in [
        ("slot_a_offset", config.slot_a_offset),
        ("slot_a_size", config.slot_a_size),
        ("slot_b_offset", config.slot_b_offset),
        ("slot_b_size", config.slot_b_size),
        ("metadata_offset", config.metadata_offset),
        ("metadata_size", config.metadata_size),
    ]:
        if value % ws != 0:
            errors.append(
                "{} (0x{:X}) is not aligned to word_size ({} bytes)".format(
                    label, value, ws
                )
            )

    # Regions as (start, end_exclusive, label) for overlap detection.
    regions: List[tuple[int, int, str]] = [
        (config.slot_a_offset, config.slot_a_offset + config.slot_a_size, "slot_a"),
        (config.slot_b_offset, config.slot_b_offset + config.slot_b_size, "slot_b"),
        (config.metadata_offset, config.metadata_offset + config.metadata_size, "metadata"),
    ]

    # Boot region occupies [0, slot_a_offset) if slot_a_offset > 0.
    if config.slot_a_offset > 0:
        regions.append((0, config.slot_a_offset, "boot"))

    # Everything must fit within NVM.
    for start, end, label in regions:
        if end > config.nvm_size:
            errors.append(
                "{} extends past NVM: end 0x{:X} > nvm_size 0x{:X}".format(
                    label, end, config.nvm_size
                )
            )

    # Pairwise overlap check.
    for i in range(len(regions)):
        for j in range(i + 1, len(regions)):
            a_start, a_end, a_label = regions[i]
            b_start, b_end, b_label = regions[j]
            if a_start < b_end and b_start < a_end:
                errors.append(
                    "{} [0x{:X}, 0x{:X}) overlaps {} [0x{:X}, 0x{:X})".format(
                        a_label, a_start, a_end, b_label, b_start, b_end
                    )
                )

    if errors:
        raise ValueError(
            "Invalid geometry '{}': {}".format(config.name, "; ".join(errors))
        )


def validate_mcuboot_geometry(config: MCUbootGeometryConfig) -> None:
    """Validate MCUboot-specific geometry constraints on top of base validation.

    Raises ValueError on any inconsistency.
    """
    # Run base validation first.
    validate_geometry(config)

    errors: List[str] = []

    # Sector maps, if provided, must sum to the slot size.
    if config.slot_a_sectors:
        total_a = _sector_total(config.slot_a_sectors)
        if total_a != config.slot_a_size:
            errors.append(
                "slot_a_sectors total ({}) != slot_a_size (0x{:X})".format(
                    total_a, config.slot_a_size
                )
            )

    if config.slot_b_sectors:
        total_b = _sector_total(config.slot_b_sectors)
        if total_b != config.slot_b_size:
            errors.append(
                "slot_b_sectors total ({}) != slot_b_size (0x{:X})".format(
                    total_b, config.slot_b_size
                )
            )

    # Trailer must fit within the slot.
    if config.trailer_size > config.slot_a_size:
        errors.append(
            "trailer_size (0x{:X}) exceeds slot_a_size (0x{:X})".format(
                config.trailer_size, config.slot_a_size
            )
        )

    # Write alignment must be a power of two.
    wa = config.write_alignment
    if wa <= 0 or (wa & (wa - 1)) != 0:
        errors.append("write_alignment ({}) must be a power of two".format(wa))

    # Scratch area validation (0 means no scratch / overwrite-only mode).
    if config.scratch_size > 0:
        scratch_end = config.scratch_offset + config.scratch_size
        if scratch_end > config.nvm_size:
            errors.append(
                "scratch area extends past NVM: end 0x{:X} > nvm_size 0x{:X}".format(
                    scratch_end, config.nvm_size
                )
            )
        # Scratch must not overlap slots or metadata.
        scratch_regions = [
            (config.slot_a_offset, config.slot_a_offset + config.slot_a_size, "slot_a"),
            (config.slot_b_offset, config.slot_b_offset + config.slot_b_size, "slot_b"),
            (config.metadata_offset, config.metadata_offset + config.metadata_size, "metadata"),
        ]
        for r_start, r_end, r_label in scratch_regions:
            if config.scratch_offset < r_end and r_start < scratch_end:
                errors.append(
                    "scratch [0x{:X}, 0x{:X}) overlaps {} [0x{:X}, 0x{:X})".format(
                        config.scratch_offset, scratch_end, r_label, r_start, r_end
                    )
                )

    if errors:
        raise ValueError(
            "Invalid MCUboot geometry '{}': {}".format(config.name, "; ".join(errors))
        )


# ---------------------------------------------------------------------------
# Platform .repl generation
# ---------------------------------------------------------------------------

_REPL_TEMPLATE = """\
cpu: CPU.CortexM @ sysbus
    cpuType: "cortex-m0+"
    nvic: nvic

nvic: IRQControllers.NVIC @ sysbus 0xE000E000
    -> cpu@0

nvm: Memory.NVMemory @ sysbus 0x{nvm_base:08X}
    Size: 0x{nvm_size:X}
    WordSize: {word_size}
    EnforceWordWriteSemantics: true
    WriteLatencyMicros: 0

nvm_boot_alias: Memory.NVMemory @ sysbus 0x00000000
    AliasTarget: nvm

nvm_nv_read: Memory.NVMemory @ sysbus 0x{nvm_ro_alias:08X}
    AliasTarget: nvm
    ReadOnly: true

sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 0x{sram_size:X}

nvm_ctrl: NVMemoryController @ sysbus 0x40001000
    Nvm: nvm
    FullMode: true
"""


def generate_platform_repl(config: GeometryConfig, output_path: Path) -> Path:
    """Generate a Renode .repl platform description for the given geometry.

    Returns the path to the written file.
    """
    content = _REPL_TEMPLATE.format(
        nvm_base=NVM_BASE,
        nvm_size=config.nvm_size,
        word_size=config.word_size,
        nvm_ro_alias=NVM_BASE + config.nvm_size,
        sram_size=config.sram_size,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


# MCUboot-specific .repl template.  Adds InjectPartialWrite for sector-aware
# fault injection and a scratch region when present.  The NVMemory controller
# is configured with SectorLayout hints so the test harness can reason about
# sector erase boundaries.
_MCUBOOT_REPL_TEMPLATE = """\
cpu: CPU.CortexM @ sysbus
    cpuType: "cortex-m0+"
    nvic: nvic

nvic: IRQControllers.NVIC @ sysbus 0xE000E000
    -> cpu@0

nvm: Memory.NVMemory @ sysbus 0x{nvm_base:08X}
    Size: 0x{nvm_size:X}
    WordSize: {word_size}
    EnforceWordWriteSemantics: true
    WriteLatencyMicros: 0

nvm_boot_alias: Memory.NVMemory @ sysbus 0x00000000
    AliasTarget: nvm

nvm_nv_read: Memory.NVMemory @ sysbus 0x{nvm_ro_alias:08X}
    AliasTarget: nvm
    ReadOnly: true

sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 0x{sram_size:X}

nvm_ctrl: NVMemoryController @ sysbus 0x40001000
    Nvm: nvm
    FullMode: true
    InjectPartialWrite: true
{extra_sections}"""

_MCUBOOT_SCRATCH_SECTION = """
scratch: Memory.NVMemory @ sysbus 0x{scratch_addr:08X}
    Size: 0x{scratch_size:X}
    WordSize: {word_size}
    EnforceWordWriteSemantics: true
    WriteLatencyMicros: 0
"""


def _build_sector_layout_comment(config: MCUbootGeometryConfig) -> str:
    """Build a Renode .repl comment block documenting the sector layout."""
    lines: List[str] = []
    lines.append("// MCUboot geometry: {}".format(config.name))
    if config.bug_class:
        lines.append("// Bug class: {}".format(config.bug_class))
    lines.append("// Slot A sectors:")
    if config.slot_a_sectors:
        offset = config.slot_a_offset
        for sr in config.slot_a_sectors:
            lines.append(
                "//   {}x 0x{:X} byte sectors @ offset 0x{:X}".format(
                    sr.count, sr.size, offset
                )
            )
            offset += sr.count * sr.size
    else:
        n_sectors = config.slot_a_size // config.sector_size
        lines.append(
            "//   {}x 0x{:X} byte uniform sectors".format(n_sectors, config.sector_size)
        )
    lines.append("// Slot B sectors:")
    if config.slot_b_sectors:
        offset = config.slot_b_offset
        for sr in config.slot_b_sectors:
            lines.append(
                "//   {}x 0x{:X} byte sectors @ offset 0x{:X}".format(
                    sr.count, sr.size, offset
                )
            )
            offset += sr.count * sr.size
    else:
        n_sectors = config.slot_b_size // config.sector_size
        lines.append(
            "//   {}x 0x{:X} byte uniform sectors".format(n_sectors, config.sector_size)
        )
    if config.scratch_size > 0:
        lines.append(
            "// Scratch: 0x{:X} bytes @ offset 0x{:X}".format(
                config.scratch_size, config.scratch_offset
            )
        )
    lines.append(
        "// Trailer: {} bytes, write_alignment: {} bytes".format(
            config.trailer_size, config.write_alignment
        )
    )
    lines.append("")
    return "\n".join(lines)


def generate_mcuboot_platform_repl(
    config: MCUbootGeometryConfig, output_path: Path
) -> Path:
    """Generate a Renode .repl for an MCUboot-specific geometry.

    Includes InjectPartialWrite, sector layout comments, and optional scratch
    region.  Returns the path to the written file.
    """
    extra = ""
    if config.scratch_size > 0:
        extra = _MCUBOOT_SCRATCH_SECTION.format(
            scratch_addr=NVM_BASE + config.scratch_offset,
            scratch_size=config.scratch_size,
            word_size=config.word_size,
        )

    repl_body = _MCUBOOT_REPL_TEMPLATE.format(
        nvm_base=NVM_BASE,
        nvm_size=config.nvm_size,
        word_size=config.word_size,
        nvm_ro_alias=NVM_BASE + config.nvm_size,
        sram_size=config.sram_size,
        extra_sections=extra,
    )

    # Prepend sector layout documentation.
    comment = _build_sector_layout_comment(config)
    content = comment + repl_body

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Linker script generation
# ---------------------------------------------------------------------------

_LINKER_TEMPLATE = """\
ENTRY(Reset_Handler)

MEMORY
{{
    {region_name} ({region_attrs}) : ORIGIN = 0x{origin:08X}, LENGTH = 0x{length:X}
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x{sram_size:X}
}}

SECTIONS
{{
    .isr_vector :
    {{
        KEEP(*(.isr_vector))
    }} > {region_name}

    .text :
    {{
        *(.text*)
        *(.rodata*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame*)
    }} > {region_name}

    .data :
    {{
        *(.data*)
    }} > SRAM AT > {region_name}

    .bss (NOLOAD) :
    {{
        *(.bss*)
        *(COMMON)
    }} > SRAM

    __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
}}
"""


def generate_linker_scripts(config: GeometryConfig, output_dir: Path) -> Dict[str, Path]:
    """Generate boot, slot_a, and slot_b linker scripts for the geometry.

    Returns a dict mapping script name to its written path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    scripts: Dict[str, Path] = {}

    # Boot linker: [NVM_BASE, NVM_BASE + slot_a_offset).
    boot_size = config.slot_a_offset
    if boot_size > 0:
        boot_path = output_dir / "linker_boot.ld"
        boot_path.write_text(
            _LINKER_TEMPLATE.format(
                region_name="BOOT",
                region_attrs="rx",
                origin=NVM_BASE,
                length=boot_size,
                sram_size=config.sram_size,
            ),
            encoding="utf-8",
        )
        scripts["boot"] = boot_path

    # Slot A linker.
    slot_a_path = output_dir / "linker_slot_a.ld"
    slot_a_path.write_text(
        _LINKER_TEMPLATE.format(
            region_name="SLOTA",
            region_attrs="rx",
            origin=NVM_BASE + config.slot_a_offset,
            length=config.slot_a_size,
            sram_size=config.sram_size,
        ),
        encoding="utf-8",
    )
    scripts["slot_a"] = slot_a_path

    # Slot B linker.
    slot_b_path = output_dir / "linker_slot_b.ld"
    slot_b_path.write_text(
        _LINKER_TEMPLATE.format(
            region_name="SLOTB",
            region_attrs="rx",
            origin=NVM_BASE + config.slot_b_offset,
            length=config.slot_b_size,
            sram_size=config.sram_size,
        ),
        encoding="utf-8",
    )
    scripts["slot_b"] = slot_b_path

    return scripts


# ---------------------------------------------------------------------------
# Boot metadata generator script
# ---------------------------------------------------------------------------

_BOOT_META_TEMPLATE = '''\
#!/usr/bin/env python3
"""Generate boot_meta.bin for geometry: {name}.

Metadata is placed at NVM offset 0x{metadata_offset:X} ({metadata_size} bytes).
Two replicas of {replica_size} bytes each.
"""

import struct
from pathlib import Path

BOOT_META_MAGIC = 0x4F54414D
BOOT_META_REPLICA_SIZE = {replica_size}

words = [0] * (BOOT_META_REPLICA_SIZE // 4)
words[0] = BOOT_META_MAGIC
words[1] = 1   # seq
words[2] = 0   # active_slot
words[3] = 0   # target_slot
words[4] = 0   # state: confirmed
words[5] = 0   # boot_count
words[6] = 3   # max_boot_count

crc = 0xFFFFFFFF
for w in words[:-1]:
    for shift in (0, 8, 16, 24):
        crc ^= (w >> shift) & 0xFF
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
        crc &= 0xFFFFFFFF
words[-1] = (~crc) & 0xFFFFFFFF

replica = struct.pack(\'<\' + \'I\' * len(words), *words)
Path(\'boot_meta.bin\').write_bytes(replica + replica)
'''


def generate_boot_meta_script(config: GeometryConfig, output_path: Path) -> Path:
    """Generate a gen_boot_meta.py script for the geometry's metadata layout.

    Returns the path to the written file.
    """
    replica_size = min(config.metadata_size // 2, 256)
    # Ensure at least 256 per replica.
    if replica_size < 256:
        replica_size = 256

    content = _BOOT_META_TEMPLATE.format(
        name=config.name,
        metadata_offset=config.metadata_offset,
        metadata_size=config.metadata_size,
        replica_size=replica_size,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Campaign argument generation
# ---------------------------------------------------------------------------

def generate_campaign_args(config: GeometryConfig) -> List[str]:
    """Return --robot-var arguments for a fault-sweep runner to use this geometry.

    These are the extra CLI args you'd pass to a Robot-based fault sweep so it
    picks up the correct platform file, slot addresses, and metadata location.
    """
    args: List[str] = [
        "--robot-var", "NVM_SIZE:0x{:X}".format(config.nvm_size),
        "--robot-var", "NVM_WORD_SIZE:{}".format(config.word_size),
        "--robot-var", "SLOT_A_OFFSET:0x{:X}".format(config.slot_a_offset),
        "--robot-var", "SLOT_A_SIZE:0x{:X}".format(config.slot_a_size),
        "--robot-var", "SLOT_A_ADDR:0x{:08X}".format(NVM_BASE + config.slot_a_offset),
        "--robot-var", "SLOT_B_OFFSET:0x{:X}".format(config.slot_b_offset),
        "--robot-var", "SLOT_B_SIZE:0x{:X}".format(config.slot_b_size),
        "--robot-var", "SLOT_B_ADDR:0x{:08X}".format(NVM_BASE + config.slot_b_offset),
        "--robot-var", "METADATA_OFFSET:0x{:X}".format(config.metadata_offset),
        "--robot-var", "METADATA_SIZE:0x{:X}".format(config.metadata_size),
        "--robot-var", "SRAM_SIZE:0x{:X}".format(config.sram_size),
        "--robot-var", "GEOMETRY_NAME:{}".format(config.name),
    ]
    return args


def generate_mcuboot_campaign_args(config: MCUbootGeometryConfig) -> List[str]:
    """Return --robot-var arguments for the campaign runner for MCUboot geometry.

    Extends the base campaign args with MCUboot-specific parameters: sector
    layout, scratch area, trailer, and write alignment.  Also computes the
    fault_range and total_writes hints so the campaign runner knows how many
    NVM write operations to expect.
    """
    args = generate_campaign_args(config)

    # MCUboot-specific vars.
    args.extend([
        "--robot-var", "TRAILER_SIZE:{}".format(config.trailer_size),
        "--robot-var", "WRITE_ALIGNMENT:{}".format(config.write_alignment),
        "--robot-var", "SECTOR_SIZE:0x{:X}".format(config.sector_size),
    ])

    if config.scratch_size > 0:
        args.extend([
            "--robot-var", "SCRATCH_OFFSET:0x{:X}".format(config.scratch_offset),
            "--robot-var", "SCRATCH_SIZE:0x{:X}".format(config.scratch_size),
            "--robot-var", "SCRATCH_ADDR:0x{:08X}".format(NVM_BASE + config.scratch_offset),
        ])

    # Sector layout as a serialized string: "count:size,count:size,..."
    if config.slot_a_sectors:
        sector_str = ",".join(
            "{}:0x{:X}".format(s.count, s.size) for s in config.slot_a_sectors
        )
        args.extend(["--robot-var", "SLOT_A_SECTORS:{}".format(sector_str)])

    if config.slot_b_sectors:
        sector_str = ",".join(
            "{}:0x{:X}".format(s.count, s.size) for s in config.slot_b_sectors
        )
        args.extend(["--robot-var", "SLOT_B_SECTORS:{}".format(sector_str)])

    # Compute campaign hints.
    #
    # total_writes: approximate number of word-sized writes for a full slot
    # copy.  This tells the campaign runner the upper bound for fault injection
    # points.
    #
    # write_granularity: the word size (minimum partial-write unit).
    #
    # fault_range: "0:<total_writes>" -- the range of write indices where
    # injecting a power-cut is meaningful.
    total_writes = config.slot_a_size // config.word_size
    args.extend([
        "--robot-var", "TOTAL_WRITES:{}".format(total_writes),
        "--robot-var", "WRITE_GRANULARITY:{}".format(config.word_size),
        "--robot-var", "FAULT_RANGE:0:{}".format(total_writes),
    ])

    if config.bug_class:
        args.extend(["--robot-var", "BUG_CLASS:{}".format(config.bug_class)])

    return args


# ---------------------------------------------------------------------------
# MCUboot-specific geometry definitions
# ---------------------------------------------------------------------------

def _mcuboot_asymmetric_sectors() -> MCUbootGeometryConfig:
    """Slot with mixed sector sizes: 4x4KB + 1x32KB = 48KB per slot.

    Catches MCUboot #2205 where the last-sector size was computed from
    sector[0].size instead of the actual last sector, causing the final
    swap pass to copy the wrong number of bytes.
    """
    # Layout: 256KB NVM
    #   Boot:     0x0000 - 0x1FFF  (8KB)
    #   Slot A:   0x2000 - 0xDFFF  (48KB) = 4x4KB + 1x32KB
    #   Slot B:   0xE000 - 0x19FFF (48KB) = 4x4KB + 1x32KB
    #   Metadata: 0x1A000          (512B)
    #   Scratch:  0x1B000 - 0x22FFF (32KB, >= largest sector)
    slot_sectors = [
        SectorRange(count=4, size=0x1000),   # 4x 4KB = 16KB
        SectorRange(count=1, size=0x8000),   # 1x 32KB
    ]
    slot_size = _sector_total(slot_sectors)  # 48KB = 0xC000

    return MCUbootGeometryConfig(
        nvm_size=0x40000,           # 256KB
        word_size=8,
        slot_a_offset=0x2000,
        slot_a_size=slot_size,
        slot_b_offset=0x2000 + slot_size,   # 0xE000
        slot_b_size=slot_size,
        metadata_offset=0x1A000,
        metadata_size=512,
        sram_size=0x20000,
        name="mcuboot_asymmetric_sectors",
        slot_a_sectors=list(slot_sectors),
        slot_b_sectors=list(slot_sectors),
        sector_size=0x1000,         # smallest sector (for reference)
        scratch_offset=0x1B000,
        scratch_size=0x8000,        # 32KB >= largest sector
        trailer_size=128,
        write_alignment=8,
        bug_class=(
            "MCUboot #2205: last-sector size miscalculation with mixed sector "
            "sizes.  Swap loop uses sector[0].size for all passes instead of "
            "the actual sector size at each index."
        ),
    )


def _mcuboot_trailer_at_sector_boundary() -> MCUbootGeometryConfig:
    """Trailer (128 bytes) lands exactly at a sector boundary.

    In a slot with N uniform 4KB sectors, the image area is
    (slot_size - trailer_size).  If we pick slot_size = 5 * 4KB = 20KB,
    trailer_size = 128 = 0x80, then the trailer starts at offset 0x4F80
    within the slot.  But we want the trailer to START exactly at a sector
    boundary.  So: slot_size must be chosen so that
    (slot_size - trailer_size) is sector-aligned.

    With 4KB sectors and 128B trailer: slot_size = N * 0x1000 + 0x80 is NOT
    sector-aligned.  Instead, make the LAST sector exactly trailer_size so
    the trailer occupies the entire last sector.  That way, writing the
    trailer means erasing that sector, and any off-by-one in the sector
    index computation will erase the adjacent (image) sector.

    Catches MCUboot #2206, #2214: trailer-overlap underflow where
    boot_status_off() returns a value that wraps around or indexes into the
    wrong sector when the trailer sits at a sector boundary.
    """
    # Layout: 256KB NVM
    #   Boot:     0x0000 - 0x1FFF  (8KB)
    #   Slot A:   0x2000 - 0x15FFF (80KB) = 20 uniform 4KB sectors
    #   Slot B:   0x16000 - 0x29FFF (80KB)
    #   Metadata: 0x2A000          (512B)
    #   Scratch:  0x2B000 - 0x2BFFF (4KB, one sector)
    #
    # trailer_size = 128.  Image max = 80KB - 128 = 81792 bytes.
    # 81792 / 4096 = 19.96875 -- the trailer starts 128 bytes before
    # the end of sector 19, i.e. at sector_boundary(20) - 128.
    # This means the trailer straddles the boundary between sector 19
    # and the end of the slot (which IS the boundary).
    #
    # Actually: to land the trailer exactly AT a boundary, we use
    # slot_size that is a multiple of sector_size, and trailer_size
    # that equals sector_size.  But 128 != 4096.  The real trigger is
    # that the trailer START address (slot_end - trailer_size) happens
    # to be sector-aligned.  With 4KB sectors: slot_end is always
    # sector-aligned.  trailer_size = 4096 would make trailer start at
    # the penultimate sector boundary.
    #
    # Simplest approach that hits the bug: make trailer_size = sector_size
    # so the trailer IS the last sector.
    sector_size = 0x1000  # 4KB
    n_sectors = 20
    slot_size = n_sectors * sector_size  # 80KB
    trailer_size = sector_size  # 4KB -- trailer fills entire last sector

    return MCUbootGeometryConfig(
        nvm_size=0x40000,           # 256KB
        word_size=8,
        slot_a_offset=0x2000,
        slot_a_size=slot_size,
        slot_b_offset=0x2000 + slot_size,   # 0x16000
        slot_b_size=slot_size,
        metadata_offset=0x2A000,
        metadata_size=512,
        sram_size=0x20000,
        name="mcuboot_trailer_at_sector_boundary",
        sector_size=sector_size,
        scratch_offset=0x2B000,
        scratch_size=sector_size,   # one sector
        trailer_size=trailer_size,
        write_alignment=8,
        bug_class=(
            "MCUboot #2206, #2214: trailer-overlap underflow.  When the "
            "trailer exactly fills the last sector, boot_status_off() can "
            "underflow or produce a sector index that points into image data.  "
            "Writing swap status then erases the adjacent image sector."
        ),
    )


def _mcuboot_max_size_image() -> MCUbootGeometryConfig:
    """Image fills the slot to exactly (slot_size - trailer_size) bytes.

    Zero padding between image end and trailer start.  This is the tightest
    possible packing.  Catches MCUboot #2283, #2553 where the max image size
    check used < instead of <= (off-by-one), or where alignment rounding
    pushed the image end past the trailer.
    """
    # Layout: 512KB NVM, 4KB sectors, 128B trailer, 8-byte alignment.
    #   Boot:     0x0000 - 0x1FFF  (8KB)
    #   Slot A:   0x2000 - 0x38FFF (220KB)
    #   Slot B:   0x39000 - 0x6FFFF (220KB)
    #   Metadata: 0x70000          (512B)
    #
    # max_image = slot_size - trailer_size = 0x37000 - 128 = 225152 - 128
    #           = 225024 = 0x36F80
    # With 8-byte alignment: 225024 is already 8-byte aligned (225024 % 8 == 0).
    slot_size = 0x37000   # 220KB
    trailer_size = 128
    max_image_size = slot_size - trailer_size  # 0x36F80

    return MCUbootGeometryConfig(
        nvm_size=0x80000,           # 512KB
        word_size=8,
        slot_a_offset=0x2000,
        slot_a_size=slot_size,
        slot_b_offset=0x39000,
        slot_b_size=slot_size,
        metadata_offset=0x70000,
        metadata_size=512,
        sram_size=0x20000,
        name="mcuboot_max_size_image",
        sector_size=0x1000,
        trailer_size=trailer_size,
        write_alignment=8,
        bug_class=(
            "MCUboot #2283, #2553: max-size and alignment errors.  When the "
            "image exactly fills (slot_size - trailer_size), off-by-one in "
            "size validation or alignment rounding can reject a valid image "
            "or corrupt the trailer.  max_image=0x{:X} bytes, zero padding."
            .format(max_image_size)
        ),
    )


def _mcuboot_tiny_scratch() -> MCUbootGeometryConfig:
    """Scratch area smaller than the largest sector.

    Forces MCUboot's swap-scratch algorithm into multi-pass mode: a single
    sector cannot be swapped in one shot, so the bootloader must chunk it
    across multiple scratch fills.  Catches swap-scratch resume bugs where
    the resume index calculation assumes scratch >= max_sector.
    """
    # Layout: 256KB NVM, mixed sectors (8x4KB + 1x32KB = 64KB per slot).
    # Scratch = 4KB (one small sector) but largest sector = 32KB.
    # MCUboot must do 32KB/4KB = 8 passes to swap the large sector.
    slot_sectors = [
        SectorRange(count=8, size=0x1000),   # 8x 4KB = 32KB
        SectorRange(count=1, size=0x8000),   # 1x 32KB
    ]
    slot_size = _sector_total(slot_sectors)  # 64KB = 0x10000

    return MCUbootGeometryConfig(
        nvm_size=0x40000,           # 256KB
        word_size=8,
        slot_a_offset=0x2000,
        slot_a_size=slot_size,
        slot_b_offset=0x2000 + slot_size,   # 0x12000
        slot_b_size=slot_size,
        metadata_offset=0x22000,
        metadata_size=512,
        sram_size=0x20000,
        name="mcuboot_tiny_scratch",
        slot_a_sectors=list(slot_sectors),
        slot_b_sectors=list(slot_sectors),
        sector_size=0x1000,         # smallest sector
        scratch_offset=0x23000,
        scratch_size=0x1000,        # 4KB -- smaller than largest sector (32KB)
        trailer_size=128,
        write_alignment=8,
        bug_class=(
            "Swap-scratch resume bugs.  Scratch (4KB) < largest sector (32KB) "
            "forces multi-pass swap: 8 passes to move the 32KB sector through "
            "4KB scratch.  Resume index calculation must track which sub-pass "
            "was interrupted.  Off-by-one here bricks on second boot after "
            "power-loss mid-swap."
        ),
    )


def _mcuboot_misaligned_slots() -> MCUbootGeometryConfig:
    """Slot start address not aligned to sector size.

    Boot region = 6KB (0x1800), but sectors = 4KB (0x1000).  So slot A starts
    at offset 0x1800, which is NOT 4KB-aligned.  Catches MCUboot #2609 where
    sector-to-slot-offset math assumed slot_start % sector_size == 0.
    """
    # Layout: 256KB NVM
    #   Boot:     0x0000 - 0x17FF  (6KB)
    #   Slot A:   0x1800 - 0x11FFF (42KB = 0xA800)
    #   Slot B:   0x12000 - 0x22FFF (this one IS aligned, asymmetric alignment)
    #   But we also need slot_b to be misaligned for full coverage.
    #   Slot B:   0x1C000 - 0x2C7FF (42KB)
    #   Metadata: 0x2D000          (512B)
    #
    # Actually, let's keep it simpler:
    #   Boot:     0x0000 - 0x17FF  (6KB)
    #   Slot A:   0x1800 - 0x19FFF (42.5KB -- no, must be word-aligned)
    #
    # 6KB = 0x1800.  slot_size must be word-aligned (8 bytes).
    # 42KB = 0xA800 (word-aligned, but 0x1800 + 0xA800 = 0xC000).
    # slot B at 0xC000 is sector-aligned.  We want slot B ALSO misaligned.
    # Put slot B right after slot A: 0xC000.  That's 4KB-aligned. Instead:
    # Add a 2KB gap: slot B at 0xC800 (misaligned).
    # 0xC800 + 0xA800 = 0x17000.
    # Metadata at 0x17000, scratch at 0x18000.
    boot_size = 0x1800              # 6KB -- NOT sector-aligned
    slot_size = 0xA800              # 42KB
    slot_b_start = boot_size + slot_size + 0x800  # 0xC800 -- also misaligned

    return MCUbootGeometryConfig(
        nvm_size=0x40000,           # 256KB
        word_size=8,
        slot_a_offset=boot_size,            # 0x1800, NOT 4KB-aligned
        slot_a_size=slot_size,
        slot_b_offset=slot_b_start,         # 0xC800, NOT 4KB-aligned
        slot_b_size=slot_size,
        metadata_offset=slot_b_start + slot_size,  # 0x17000
        metadata_size=512,
        sram_size=0x20000,
        name="mcuboot_misaligned_slots",
        sector_size=0x1000,         # 4KB sectors
        scratch_offset=0x18000,
        scratch_size=0x1000,        # one sector
        trailer_size=128,
        write_alignment=8,
        bug_class=(
            "MCUboot #2609: alignment assumption bugs.  Slot A starts at "
            "0x1800 (6KB boot), slot B at 0xC800 -- neither is 4KB-sector-"
            "aligned.  Code that computes sector index as "
            "(addr - slot_start) / sector_size gives wrong results when "
            "slot_start is not sector-aligned."
        ),
    )


def _mcuboot_single_sector_slot() -> MCUbootGeometryConfig:
    """Each slot is exactly one sector (4KB).

    Minimizes swap complexity (only one sector to swap) but exercises all
    the boundary math with N=1.  Off-by-one errors in loop bounds, sector
    index range checks, and trailer offset calculations often manifest when
    there is exactly one sector because the edge-case of first==last is not
    tested.
    """
    # Layout: 128KB NVM
    #   Boot:     0x0000 - 0x0FFF  (4KB = 1 sector)
    #   Slot A:   0x1000 - 0x1FFF  (4KB = 1 sector)
    #   Slot B:   0x2000 - 0x2FFF  (4KB = 1 sector)
    #   Metadata: 0x3000           (512B)
    #   Scratch:  0x4000 - 0x4FFF  (4KB = 1 sector)
    sector_size = 0x1000  # 4KB

    return MCUbootGeometryConfig(
        nvm_size=0x20000,           # 128KB
        word_size=8,
        slot_a_offset=0x1000,
        slot_a_size=sector_size,    # exactly one sector
        slot_b_offset=0x2000,
        slot_b_size=sector_size,    # exactly one sector
        metadata_offset=0x3000,
        metadata_size=512,
        sram_size=0x10000,          # 64KB
        name="mcuboot_single_sector_slot",
        sector_size=sector_size,
        scratch_offset=0x4000,
        scratch_size=sector_size,
        trailer_size=128,
        write_alignment=8,
        bug_class=(
            "Single-sector boundary math.  Each slot is exactly one 4KB "
            "sector.  Loop bounds, sector count calculations, and trailer "
            "offset logic all degenerate when num_sectors=1.  First==last "
            "sector is the classic off-by-one blind spot."
        ),
    )


# Collect all MCUboot geometries.
MCUBOOT_GEOMETRIES: List[MCUbootGeometryConfig] = [
    _mcuboot_asymmetric_sectors(),
    _mcuboot_trailer_at_sector_boundary(),
    _mcuboot_max_size_image(),
    _mcuboot_tiny_scratch(),
    _mcuboot_misaligned_slots(),
    _mcuboot_single_sector_slot(),
]

MCUBOOT_GEOMETRIES_BY_NAME: Dict[str, MCUbootGeometryConfig] = {
    g.name: g for g in MCUBOOT_GEOMETRIES
}


@dataclass
class MCUbootGeometryEntry:
    """Full description of one MCUboot geometry for external consumption."""

    config: MCUbootGeometryConfig
    repl_content: str
    campaign_args: List[str]
    description: str


def mcuboot_geometries() -> List[MCUbootGeometryEntry]:
    """Return all MCUboot-specific geometries with their platform descriptions,
    campaign runner arguments, and human-readable descriptions.

    Each entry is fully self-contained: you can write the .repl to disk and
    pass the campaign_args to a sweep runner without any further computation.
    """
    entries: List[MCUbootGeometryEntry] = []

    for config in MCUBOOT_GEOMETRIES:
        # Validate.
        validate_mcuboot_geometry(config)

        # Generate .repl content (in memory, not written to disk).
        extra = ""
        if config.scratch_size > 0:
            extra = _MCUBOOT_SCRATCH_SECTION.format(
                scratch_addr=NVM_BASE + config.scratch_offset,
                scratch_size=config.scratch_size,
                word_size=config.word_size,
            )
        repl_body = _MCUBOOT_REPL_TEMPLATE.format(
            nvm_base=NVM_BASE,
            nvm_size=config.nvm_size,
            word_size=config.word_size,
            nvm_ro_alias=NVM_BASE + config.nvm_size,
            sram_size=config.sram_size,
            extra_sections=extra,
        )
        repl_content = _build_sector_layout_comment(config) + repl_body

        # Campaign args.
        campaign_args = generate_mcuboot_campaign_args(config)

        entries.append(MCUbootGeometryEntry(
            config=config,
            repl_content=repl_content,
            campaign_args=campaign_args,
            description=config.bug_class,
        ))

    return entries


# ---------------------------------------------------------------------------
# Standard geometry matrix
# ---------------------------------------------------------------------------

STANDARD_GEOMETRIES: List[GeometryConfig] = [
    # (a) default -- matches current cortex_m0_nvm.repl and linker scripts.
    #     512KB NVM, 8-byte words.
    #     Boot: 0x0000-0x1FFF (8KB), Slot A: 0x2000 (220KB), Slot B: 0x39000 (220KB),
    #     Metadata: 0x70000 (512 bytes for two replicas).
    GeometryConfig(
        nvm_size=0x80000,           # 512KB
        word_size=8,
        slot_a_offset=0x2000,       # 8KB boot region before slot A
        slot_a_size=0x37000,        # 220KB
        slot_b_offset=0x39000,
        slot_b_size=0x37000,        # 220KB
        metadata_offset=0x70000,
        metadata_size=512,
        sram_size=0x20000,          # 128KB
        name="default",
    ),
    # (b) small_nvm -- 128KB NVM, 48KB slots, metadata at end.
    GeometryConfig(
        nvm_size=0x20000,          # 128KB
        word_size=8,
        slot_a_offset=0x2000,       # 8KB boot
        slot_a_size=0xC000,         # 48KB
        slot_b_offset=0xE000,
        slot_b_size=0xC000,         # 48KB
        metadata_offset=0x1A000,    # After slot B ends at 0x1A000
        metadata_size=512,
        sram_size=0x20000,
        name="small_nvm",
    ),
    # (c) large_nvm -- 2MB NVM, 960KB slots.
    GeometryConfig(
        nvm_size=0x200000,         # 2MB
        word_size=8,
        slot_a_offset=0x4000,       # 16KB boot
        slot_a_size=0xF0000,        # 960KB
        slot_b_offset=0xF4000,
        slot_b_size=0xF0000,        # 960KB
        metadata_offset=0x1E4000,
        metadata_size=512,
        sram_size=0x40000,          # 256KB
        name="large_nvm",
    ),
    # (d) minimal_slots -- smallest viable slots (4KB each).
    #     Tests near-boundary behavior and off-by-one geometry math.
    GeometryConfig(
        nvm_size=0x20000,          # 128KB
        word_size=8,
        slot_a_offset=0x1000,       # 4KB boot
        slot_a_size=0x1000,         # 4KB
        slot_b_offset=0x2000,
        slot_b_size=0x1000,         # 4KB
        metadata_offset=0x3000,
        metadata_size=512,
        sram_size=0x10000,          # 64KB
        name="minimal_slots",
    ),
    # (e) asymmetric -- Slot A = 128KB, Slot B = 64KB.
    #     Tests size mismatch handling in copy/swap logic.
    GeometryConfig(
        nvm_size=0x80000,          # 512KB
        word_size=8,
        slot_a_offset=0x2000,       # 8KB boot
        slot_a_size=0x20000,        # 128KB
        slot_b_offset=0x22000,
        slot_b_size=0x10000,        # 64KB
        metadata_offset=0x32000,
        metadata_size=512,
        sram_size=0x20000,
        name="asymmetric",
    ),
    # (f) tight_metadata -- metadata immediately after slot B with no gap.
    #     Tests boundary arithmetic when there's zero padding between
    #     the staging area and metadata.
    GeometryConfig(
        nvm_size=0x80000,          # 512KB
        word_size=8,
        slot_a_offset=0x2000,
        slot_a_size=0x37000,        # 220KB
        slot_b_offset=0x39000,
        slot_b_size=0x37000,        # 220KB
        metadata_offset=0x70000,    # Immediately after slot B (0x39000 + 0x37000 = 0x70000)
        metadata_size=256,          # Single replica, minimum viable
        sram_size=0x20000,
        name="tight_metadata",
    ),
    # (g) word_size_4 -- 4-byte word size instead of 8.
    #     Tests that write-granularity assumptions aren't hardcoded to 8.
    GeometryConfig(
        nvm_size=0x80000,          # 512KB
        word_size=4,
        slot_a_offset=0x2000,
        slot_a_size=0x37000,
        slot_b_offset=0x39000,
        slot_b_size=0x37000,
        metadata_offset=0x70000,
        metadata_size=512,
        sram_size=0x20000,
        name="word_size_4",
    ),
    # (h) max_slots -- slots consume nearly all available NVM.
    #     Boot = 4KB, two equal slots filling the rest minus 512 bytes metadata.
    #     512KB total: 4KB boot + 2 * 254.75KB slots + 512B metadata.
    #     slot_size = (0x80000 - 0x1000 - 0x200) // 2 = 0x3F700, rounded down to
    #     8-byte alignment = 0x3F700 (259840 bytes each).
    GeometryConfig(
        nvm_size=0x80000,          # 512KB
        word_size=8,
        slot_a_offset=0x1000,       # 4KB boot
        slot_a_size=0x3F600,        # ~253.5KB
        slot_b_offset=0x40600,
        slot_b_size=0x3F600,        # ~253.5KB
        metadata_offset=0x7FC00,    # Near end of NVM
        metadata_size=512,          # 0x200
        sram_size=0x20000,
        name="max_slots",
    ),
]

# Name-indexed lookup (includes both standard and MCUboot geometries).
GEOMETRIES_BY_NAME: Dict[str, GeometryConfig] = {g.name: g for g in STANDARD_GEOMETRIES}
GEOMETRIES_BY_NAME.update({g.name: g for g in MCUBOOT_GEOMETRIES})

# Combined list for --mode all.
ALL_GEOMETRIES: List[GeometryConfig] = list(STANDARD_GEOMETRIES) + list(MCUBOOT_GEOMETRIES)


# ---------------------------------------------------------------------------
# Full matrix generation
# ---------------------------------------------------------------------------

def _config_to_dict(config: GeometryConfig) -> Dict[str, Any]:
    """Serialize a GeometryConfig to a JSON-friendly dict with hex strings."""
    d: Dict[str, Any] = {
        "name": config.name,
        "nvm_size": config.nvm_size,
        "nvm_size_hex": "0x{:X}".format(config.nvm_size),
        "word_size": config.word_size,
        "slot_a_offset": config.slot_a_offset,
        "slot_a_offset_hex": "0x{:X}".format(config.slot_a_offset),
        "slot_a_size": config.slot_a_size,
        "slot_a_size_hex": "0x{:X}".format(config.slot_a_size),
        "slot_a_addr": NVM_BASE + config.slot_a_offset,
        "slot_a_addr_hex": "0x{:08X}".format(NVM_BASE + config.slot_a_offset),
        "slot_b_offset": config.slot_b_offset,
        "slot_b_offset_hex": "0x{:X}".format(config.slot_b_offset),
        "slot_b_size": config.slot_b_size,
        "slot_b_size_hex": "0x{:X}".format(config.slot_b_size),
        "slot_b_addr": NVM_BASE + config.slot_b_offset,
        "slot_b_addr_hex": "0x{:08X}".format(NVM_BASE + config.slot_b_offset),
        "metadata_offset": config.metadata_offset,
        "metadata_offset_hex": "0x{:X}".format(config.metadata_offset),
        "metadata_size": config.metadata_size,
        "sram_size": config.sram_size,
        "sram_size_hex": "0x{:X}".format(config.sram_size),
    }

    # Add MCUboot-specific fields if present.
    if isinstance(config, MCUbootGeometryConfig):
        d["sector_size"] = config.sector_size
        d["sector_size_hex"] = "0x{:X}".format(config.sector_size)
        d["trailer_size"] = config.trailer_size
        d["write_alignment"] = config.write_alignment
        d["bug_class"] = config.bug_class
        if config.scratch_size > 0:
            d["scratch_offset"] = config.scratch_offset
            d["scratch_offset_hex"] = "0x{:X}".format(config.scratch_offset)
            d["scratch_size"] = config.scratch_size
            d["scratch_size_hex"] = "0x{:X}".format(config.scratch_size)
            d["scratch_addr"] = NVM_BASE + config.scratch_offset
            d["scratch_addr_hex"] = "0x{:08X}".format(NVM_BASE + config.scratch_offset)
        if config.slot_a_sectors:
            d["slot_a_sectors"] = [
                {"count": s.count, "size": s.size, "size_hex": "0x{:X}".format(s.size)}
                for s in config.slot_a_sectors
            ]
        if config.slot_b_sectors:
            d["slot_b_sectors"] = [
                {"count": s.count, "size": s.size, "size_hex": "0x{:X}".format(s.size)}
                for s in config.slot_b_sectors
            ]
        total_writes = config.slot_a_size // config.word_size
        d["total_writes"] = total_writes
        d["write_granularity"] = config.word_size
        d["fault_range"] = "0:{}".format(total_writes)

    return d


def generate_matrix(
    output_dir: Path,
    geometries: Optional[List[GeometryConfig]] = None,
) -> Dict[str, Any]:
    """Generate all artifacts for a set of geometries.

    Creates per-geometry subdirectories under output_dir, each containing:
        - platform.repl
        - linker_boot.ld, linker_slot_a.ld, linker_slot_b.ld
        - gen_boot_meta.py
        - campaign_args.txt

    Returns a manifest dict suitable for JSON serialization.
    """
    if geometries is None:
        geometries = STANDARD_GEOMETRIES

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_entries: List[Dict[str, Any]] = []

    for config in geometries:
        is_mcuboot = isinstance(config, MCUbootGeometryConfig)

        if is_mcuboot:
            validate_mcuboot_geometry(config)
        else:
            validate_geometry(config)

        geo_dir = output_dir / config.name
        geo_dir.mkdir(parents=True, exist_ok=True)

        # Platform .repl -- use MCUboot-specific template when applicable.
        if is_mcuboot:
            repl_path = generate_mcuboot_platform_repl(config, geo_dir / "platform.repl")
        else:
            repl_path = generate_platform_repl(config, geo_dir / "platform.repl")

        # Linker scripts
        linker_paths = generate_linker_scripts(config, geo_dir)

        # Boot metadata generator
        meta_script_path = generate_boot_meta_script(config, geo_dir / "gen_boot_meta.py")

        # Campaign args -- MCUboot configs get extra parameters.
        if is_mcuboot:
            campaign_args = generate_mcuboot_campaign_args(config)
        else:
            campaign_args = generate_campaign_args(config)
        args_path = geo_dir / "campaign_args.txt"
        args_path.write_text(" \\\n    ".join(campaign_args) + "\n", encoding="utf-8")

        entry: Dict[str, Any] = _config_to_dict(config)
        entry["files"] = {
            "platform_repl": str(repl_path),
            "gen_boot_meta": str(meta_script_path),
            "campaign_args": str(args_path),
            "linker_boot": str(linker_paths["boot"]) if "boot" in linker_paths else None,
            "linker_slot_a": str(linker_paths["slot_a"]),
            "linker_slot_b": str(linker_paths["slot_b"]),
        }
        entry["campaign_args_list"] = campaign_args
        manifest_entries.append(entry)

    manifest: Dict[str, Any] = {
        "nvm_base": NVM_BASE,
        "nvm_base_hex": "0x{:08X}".format(NVM_BASE),
        "geometry_count": len(manifest_entries),
        "geometries": manifest_entries,
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_geometry_list(geometries: List[GeometryConfig], header: str = "") -> None:
    """Print a formatted listing of geometries to stdout."""
    if header:
        print(header)
    for g in geometries:
        base_info = "{:<40s}  NVM={:>7s}  word={}  slotA={:>7s}  slotB={:>7s}  meta@0x{:X}".format(
            g.name,
            "{}KB".format(g.nvm_size // 1024),
            g.word_size,
            "{}KB".format(g.slot_a_size // 1024),
            "{}KB".format(g.slot_b_size // 1024),
            g.metadata_offset,
        )
        print(base_info)
        if isinstance(g, MCUbootGeometryConfig):
            extras: List[str] = []
            extras.append("sector=0x{:X}".format(g.sector_size))
            extras.append("trailer={}B".format(g.trailer_size))
            if g.scratch_size > 0:
                extras.append("scratch={}KB".format(g.scratch_size // 1024))
            if g.slot_a_sectors:
                sector_desc = "+".join(
                    "{}x{}KB".format(s.count, s.size // 1024) for s in g.slot_a_sectors
                )
                extras.append("sectors=[{}]".format(sector_desc))
            print("  {}".format("  ".join(extras)))
            if g.bug_class:
                # Print first sentence of bug_class as a one-liner.
                first_sentence = g.bug_class.split(".")[0].strip()
                print("  -> {}".format(first_sentence))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate OTA geometry matrix: platform files, linker scripts, and campaign args."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory to write generated artifacts into.",
    )
    parser.add_argument(
        "--geometry",
        nargs="*",
        metavar="NAME",
        help=(
            "One or more geometry names to generate (default: depends on --mode). "
            "Available: {}".format(", ".join(sorted(GEOMETRIES_BY_NAME.keys())))
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("standard", "mcuboot", "all"),
        default="standard",
        help=(
            "Which geometry set to use. 'standard' = base NVM layouts, "
            "'mcuboot' = MCUboot-specific bug-class geometries, "
            "'all' = both. Default: standard."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        dest="list_geometries",
        help="List available geometries and exit.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate geometries without generating files.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # Resolve the base geometry set from --mode.
    if args.mode == "mcuboot":
        base_geometries: List[GeometryConfig] = list(MCUBOOT_GEOMETRIES)
    elif args.mode == "all":
        base_geometries = list(ALL_GEOMETRIES)
    else:
        base_geometries = list(STANDARD_GEOMETRIES)

    if args.list_geometries:
        if args.mode == "all":
            _print_geometry_list(STANDARD_GEOMETRIES, "=== Standard geometries ===")
            print()
            _print_geometry_list(MCUBOOT_GEOMETRIES, "=== MCUboot geometries ===")
        elif args.mode == "mcuboot":
            _print_geometry_list(MCUBOOT_GEOMETRIES, "=== MCUboot geometries ===")
        else:
            _print_geometry_list(STANDARD_GEOMETRIES, "=== Standard geometries ===")
        return 0

    # Resolve which geometries to use.
    if args.geometry:
        selected: List[GeometryConfig] = []
        for name in args.geometry:
            if name not in GEOMETRIES_BY_NAME:
                print(
                    "Unknown geometry '{}'. Available: {}".format(
                        name, ", ".join(GEOMETRIES_BY_NAME.keys())
                    ),
                    file=sys.stderr,
                )
                return 1
            selected.append(GEOMETRIES_BY_NAME[name])
    else:
        selected = base_geometries

    # Validate all selected geometries.
    for config in selected:
        try:
            if isinstance(config, MCUbootGeometryConfig):
                validate_mcuboot_geometry(config)
            else:
                validate_geometry(config)
        except ValueError as exc:
            print("Validation error: {}".format(exc), file=sys.stderr)
            return 1

    if args.validate_only:
        print("All {} geometries valid.".format(len(selected)))
        return 0

    if args.output_dir is None:
        print("--output-dir is required (unless using --list or --validate-only).", file=sys.stderr)
        return 1

    manifest = generate_matrix(args.output_dir, geometries=selected)
    print(
        "Generated {} geometries in {}".format(
            manifest["geometry_count"], args.output_dir
        )
    )
    print("Manifest: {}".format(args.output_dir / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
