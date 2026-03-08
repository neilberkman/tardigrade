#!/usr/bin/env python3
"""Partial staging image generator for OTA client crash-during-download simulation.

Generates truncated variants of a staging image to simulate interrupted
downloads at various points. The bootloader is expected to reject partial
images gracefully — either booting the safe exec slot or explicitly refusing
the staging image. Booting a partial image or bricking is a defect.

Usage as library::

    from partial_staging import (
        generate_truncation_points,
        generate_partial_image,
        PartialStagingConfig,
        classify_partial_staging_outcome,
    )

    points = generate_truncation_points(
        image_size=0x38000,
        strategy="heuristic",
        header_size=32,
        sector_size=4096,
    )
    for offset in points:
        truncated = generate_partial_image(original, offset, fill=0xFF)
        # ... load into staging slot, boot, check outcome
"""

from __future__ import annotations

import dataclasses
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclasses.dataclass
class TruncationPoint:
    """A single truncation point with metadata."""

    offset: int
    label: str
    description: str

    @property
    def as_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "label": self.label,
            "description": self.description,
        }


@dataclasses.dataclass
class PartialStagingConfig:
    """Configuration for partial staging sweep."""

    staging_image_path: str
    staging_slot_name: str
    truncation_points: str  # "heuristic", "exhaustive", or explicit list
    fill_pattern: int  # 0xFF (erased flash) or 0x00
    header_size: int
    sector_size: int
    trailer_size: int
    explicit_offsets: Optional[List[int]] = None
    max_points: Optional[int] = None

    def __post_init__(self) -> None:
        if self.fill_pattern not in (0x00, 0xFF):
            raise ValueError(
                "fill_pattern must be 0x00 or 0xFF, got 0x{:02X}".format(
                    self.fill_pattern
                )
            )
        if self.header_size < 0:
            raise ValueError(
                "header_size must be non-negative, got {}".format(self.header_size)
            )
        if self.sector_size < 1:
            raise ValueError(
                "sector_size must be positive, got {}".format(self.sector_size)
            )
        if self.trailer_size < 0:
            raise ValueError(
                "trailer_size must be non-negative, got {}".format(self.trailer_size)
            )
        if self.max_points is not None and self.max_points < 1:
            raise ValueError(
                "max_points must be positive or None, got {}".format(self.max_points)
            )


def generate_truncation_points(
    image_size: int,
    strategy: str = "heuristic",
    header_size: int = 32,
    sector_size: int = 4096,
    trailer_size: int = 0,
    explicit_offsets: Optional[List[int]] = None,
    max_points: Optional[int] = None,
) -> List[TruncationPoint]:
    """Generate truncation offsets for a given image size.

    Strategies:
        heuristic  - Key structural boundaries (header, sectors, trailer, midpoints).
        exhaustive - Every sector boundary plus heuristic points.
        explicit   - User-provided offsets only.

    Args:
        image_size: Total size of the complete staging image in bytes.
        strategy: Truncation point selection strategy.
        header_size: Size of the image header in bytes (0 if no header).
        sector_size: Flash sector/page size in bytes.
        trailer_size: Size of trailer/TLV area at end of image.
        explicit_offsets: User-provided truncation offsets (for explicit strategy).
        max_points: Maximum number of truncation points to return (exhaustive
            mode only). When set, points are evenly sampled from the full set
            to stay within this cap. Heuristic mode is unaffected.

    Returns:
        Sorted list of TruncationPoint objects.
    """
    if image_size < 1:
        return []

    if strategy == "explicit":
        if not explicit_offsets:
            return []
        points = []
        for offset in explicit_offsets:
            clamped = max(0, min(offset, image_size))
            points.append(
                TruncationPoint(
                    offset=clamped,
                    label="explicit_0x{:X}".format(clamped),
                    description="User-specified truncation at offset 0x{:X}".format(
                        clamped
                    ),
                )
            )
        return _deduplicate_and_sort(points)

    # --- Heuristic points (always included) ---
    points: List[TruncationPoint] = []

    # 1. Empty staging slot (0 bytes downloaded).
    points.append(
        TruncationPoint(
            offset=0,
            label="empty",
            description="Empty staging slot — zero bytes downloaded",
        )
    )

    # 2. Single byte (minimal corruption).
    if image_size > 1:
        points.append(
            TruncationPoint(
                offset=1,
                label="one_byte",
                description="Only first byte present",
            )
        )

    # 3. Mid-header (if header_size > 0).
    if header_size > 1:
        mid_hdr = header_size // 2
        if mid_hdr > 0 and mid_hdr < image_size:
            points.append(
                TruncationPoint(
                    offset=mid_hdr,
                    label="mid_header",
                    description="Truncated mid-header at offset 0x{:X}".format(mid_hdr),
                )
            )

    # 4. End of header.
    if header_size > 0 and header_size < image_size:
        points.append(
            TruncationPoint(
                offset=header_size,
                label="end_header",
                description="Header complete, body truncated at offset 0x{:X}".format(
                    header_size
                ),
            )
        )

    # 5. First sector boundary after header.
    if sector_size > 0:
        first_sector = sector_size
        while first_sector <= header_size and first_sector < image_size:
            first_sector += sector_size
        if first_sector < image_size and first_sector > header_size:
            points.append(
                TruncationPoint(
                    offset=first_sector,
                    label="first_sector",
                    description="First sector boundary at offset 0x{:X}".format(
                        first_sector
                    ),
                )
            )

    # 6. ~25% of image body.
    quarter = image_size // 4
    if quarter > 0 and quarter < image_size:
        points.append(
            TruncationPoint(
                offset=quarter,
                label="quarter",
                description="25% of image at offset 0x{:X}".format(quarter),
            )
        )

    # 7. ~50% of image body.
    half = image_size // 2
    if half > 0 and half < image_size:
        points.append(
            TruncationPoint(
                offset=half,
                label="half",
                description="50% of image at offset 0x{:X}".format(half),
            )
        )

    # 8. ~75% of image body.
    three_quarter = (image_size * 3) // 4
    if three_quarter > 0 and three_quarter < image_size:
        points.append(
            TruncationPoint(
                offset=three_quarter,
                label="three_quarter",
                description="75% of image at offset 0x{:X}".format(three_quarter),
            )
        )

    # 9. Trailer boundary (if trailer_size > 0).
    if trailer_size > 0:
        trailer_start = image_size - trailer_size
        if trailer_start > 0:
            points.append(
                TruncationPoint(
                    offset=trailer_start,
                    label="trailer_start",
                    description="Body complete, trailer truncated at offset 0x{:X}".format(
                        trailer_start
                    ),
                )
            )
        # Mid-trailer.
        mid_trailer = image_size - (trailer_size // 2)
        if mid_trailer > trailer_start and mid_trailer < image_size:
            points.append(
                TruncationPoint(
                    offset=mid_trailer,
                    label="mid_trailer",
                    description="Mid-trailer at offset 0x{:X}".format(mid_trailer),
                )
            )

    # 10. Last sector boundary before end.
    if sector_size > 0:
        last_sector = (image_size // sector_size) * sector_size
        if last_sector > 0 and last_sector < image_size:
            points.append(
                TruncationPoint(
                    offset=last_sector,
                    label="last_sector_boundary",
                    description="Last sector boundary at offset 0x{:X}".format(
                        last_sector
                    ),
                )
            )

    # 11. Last byte missing.
    if image_size > 1:
        points.append(
            TruncationPoint(
                offset=image_size - 1,
                label="last_byte_missing",
                description="All but last byte at offset 0x{:X}".format(
                    image_size - 1
                ),
            )
        )

    # 12. Complete image (control point).
    points.append(
        TruncationPoint(
            offset=image_size,
            label="complete",
            description="Complete image (control reference)",
        )
    )

    # --- Exhaustive: add every sector boundary ---
    if strategy == "exhaustive" and sector_size > 0:
        for boundary in range(sector_size, image_size, sector_size):
            points.append(
                TruncationPoint(
                    offset=boundary,
                    label="sector_0x{:X}".format(boundary),
                    description="Sector boundary at offset 0x{:X}".format(boundary),
                )
            )

    result = _deduplicate_and_sort(points)

    # Apply max_points cap for exhaustive mode only.
    if (
        max_points is not None
        and strategy == "exhaustive"
        and len(result) > max_points
    ):
        result = _evenly_sample(result, max_points)

    return result


def _evenly_sample(
    points: List[TruncationPoint], max_points: int
) -> List[TruncationPoint]:
    """Evenly sample from a sorted list of truncation points.

    Always preserves structurally important anchor points (heuristic
    points like header, trailer, midpoints).  Only sector boundary
    points are subject to sampling.  This prevents the cap from
    discarding the most semantically valuable truncation points.
    """
    if max_points < 1:
        return []
    if max_points >= len(points):
        return points

    # Separate anchors (heuristic structural points) from sector fills.
    anchors = []
    sector_pts = []
    for p in points:
        if p.label.startswith("sector_"):
            sector_pts.append(p)
        else:
            anchors.append(p)

    # If anchors alone exceed budget, keep first/last + evenly sample anchors.
    if len(anchors) >= max_points:
        if max_points == 1:
            return [anchors[0]]
        indices = {0, len(anchors) - 1}
        interior = max_points - 2
        if interior > 0:
            step = (len(anchors) - 1) / (interior + 1)
            for i in range(1, interior + 1):
                indices.add(round(i * step))
        return [anchors[i] for i in sorted(indices)]

    # All anchors kept; fill remaining budget from sector boundaries.
    remaining = max_points - len(anchors)
    if remaining <= 0 or not sector_pts:
        return sorted(anchors, key=lambda p: p.offset)

    if remaining >= len(sector_pts):
        sampled_sectors = sector_pts
    else:
        indices = set()
        step = (len(sector_pts) - 1) / (remaining - 1) if remaining > 1 else 0
        for i in range(remaining):
            indices.add(min(round(i * step), len(sector_pts) - 1))
        sampled_sectors = [sector_pts[i] for i in sorted(indices)]

    merged = anchors + sampled_sectors
    merged.sort(key=lambda p: p.offset)
    return merged


def _deduplicate_and_sort(points: List[TruncationPoint]) -> List[TruncationPoint]:
    """Remove duplicate offsets (keeping first label) and sort by offset."""
    seen: Dict[int, TruncationPoint] = {}
    for point in points:
        if point.offset not in seen:
            seen[point.offset] = point
    return sorted(seen.values(), key=lambda p: p.offset)


def generate_partial_image(
    original: bytes,
    truncation_offset: int,
    fill: int = 0xFF,
) -> bytes:
    """Generate a partial image: real data up to offset, fill byte after.

    Args:
        original: Complete image binary data.
        truncation_offset: Number of real bytes to keep (0 = fully erased).
        fill: Fill byte for the remainder (0xFF = erased flash, 0x00 = zeroed).

    Returns:
        A bytes object of the same length as original, with real data up to
        truncation_offset and fill bytes after.
    """
    if truncation_offset <= 0:
        return bytes([fill]) * len(original)
    if truncation_offset >= len(original):
        return original
    kept = original[:truncation_offset]
    remainder = bytes([fill]) * (len(original) - truncation_offset)
    return kept + remainder


def write_partial_image_to_temp(
    original: bytes,
    truncation_offset: int,
    fill: int = 0xFF,
    label: str = "",
) -> str:
    """Write a partial image to a temp file and return the path.

    Caller is responsible for cleanup.
    """
    data = generate_partial_image(original, truncation_offset, fill)
    suffix = "_{}.bin".format(label) if label else ".bin"
    tmp = tempfile.NamedTemporaryFile(
        prefix="partial_staging_", suffix=suffix, delete=False
    )
    tmp.write(data)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------

# Outcome classes for partial staging sweep.
PARTIAL_STAGING_OUTCOMES = {
    "safe_fallback",       # Correct: booted exec slot, rejected partial image.
    "partial_image_booted",  # BAD: bootloader booted the partial/corrupt image.
    "brick",               # VERY BAD: device did not boot at all.
    "complete_image_ok",   # Control: complete image booted successfully.
}


def classify_partial_staging_outcome(
    boot_outcome: str,
    boot_slot: Optional[str],
    truncation_offset: int,
    image_size: int,
    expected_exec_slot: str = "exec",
) -> str:
    """Classify a boot result from a partial staging test.

    Args:
        boot_outcome: Raw boot outcome from the harness (success, no_boot, etc.).
        boot_slot: Which slot the bootloader booted from.
        truncation_offset: How many bytes of the image were present.
        image_size: Total image size.
        expected_exec_slot: Name of the exec/safe slot.

    Returns:
        One of the PARTIAL_STAGING_OUTCOMES values.
    """
    outcome = str(boot_outcome or "unknown").strip().lower()
    slot = str(boot_slot or "").strip().lower()

    # Complete image is the control case.
    if truncation_offset >= image_size:
        if outcome == "success":
            return "complete_image_ok"
        # Even the complete image failed — this is a brick (or config error).
        if outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}:
            return "brick"
        return "safe_fallback"

    # Partial image cases:
    # If the device didn't boot at all, it's a brick.
    if outcome in {"no_boot", "hard_fault", "wrong_pc", "misaligned_vtor"}:
        return "brick"

    # If it booted and landed in the exec/safe slot, that's correct behavior.
    exec_names = {"exec", "primary", "slot_a", "slot0", "a"}
    staging_names = {"staging", "secondary", "slot_b", "slot1", "b"}

    if outcome == "success" and slot in exec_names:
        return "safe_fallback"

    # If it booted and landed in the staging slot with a partial image, BAD.
    if slot in staging_names:
        return "partial_image_booted"

    # Success but unclear slot — if we have a known exec slot match, safe.
    if outcome == "success":
        if slot == expected_exec_slot.lower():
            return "safe_fallback"
        # Booted *somewhere* but not the safe slot — likely partial image.
        return "partial_image_booted"

    # Anything else is a brick.
    return "brick"


# ---------------------------------------------------------------------------
# Sweep summary
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class PartialStagingResult:
    """Result from a single partial staging test point."""

    truncation_point: TruncationPoint
    boot_outcome: str
    boot_slot: Optional[str]
    classification: str
    temp_image_path: Optional[str] = None
    raw_result: Optional[Dict[str, Any]] = None


def summarize_partial_staging(
    results: List[PartialStagingResult],
) -> Dict[str, Any]:
    """Compute summary statistics from partial staging sweep results."""
    total = len(results)
    classification_counts: Dict[str, int] = {}
    issues: List[Dict[str, Any]] = []

    for r in results:
        classification_counts[r.classification] = (
            classification_counts.get(r.classification, 0) + 1
        )
        if r.classification in {"partial_image_booted", "brick"}:
            issues.append(
                {
                    "offset": r.truncation_point.offset,
                    "label": r.truncation_point.label,
                    "classification": r.classification,
                    "boot_outcome": r.boot_outcome,
                    "boot_slot": r.boot_slot,
                }
            )

    bricks = classification_counts.get("brick", 0)
    partial_booted = classification_counts.get("partial_image_booted", 0)
    safe = classification_counts.get("safe_fallback", 0)
    control_ok = classification_counts.get("complete_image_ok", 0)

    return {
        "total_points": total,
        "safe_fallback": safe,
        "partial_image_booted": partial_booted,
        "brick": bricks,
        "complete_image_ok": control_ok,
        "issue_count": partial_booted + bricks,
        "issue_rate": (
            float(partial_booted + bricks) / float(total) if total else 0.0
        ),
        "classifications": classification_counts,
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# Config parsing from profile YAML
# ---------------------------------------------------------------------------

def parse_partial_staging_config(
    raw: Optional[Dict[str, Any]],
    images: Dict[str, str],
    slots: Dict[str, Any],
    sector_size: int = 4096,
) -> Optional[PartialStagingConfig]:
    """Parse partial_staging config from a fault_sweep YAML block.

    Returns None if not configured.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("partial_staging: expected mapping")

    staging_slot = str(raw.get("staging_slot", "staging"))
    if staging_slot not in slots:
        raise ValueError(
            "partial_staging.staging_slot '{}' not found in memory.slots".format(
                staging_slot
            )
        )

    # Resolve staging image path.
    staging_image = raw.get("staging_image")
    if staging_image is None:
        # Default: use the "staging" image from the images dict.
        staging_image = images.get(staging_slot) or images.get("staging")
    if staging_image is None:
        raise ValueError(
            "partial_staging: no staging image found. Set staging_image or "
            "define a 'staging' image in images."
        )

    fill_raw = raw.get("fill_pattern", "0xFF")
    if isinstance(fill_raw, int):
        fill_pattern = fill_raw
    else:
        fill_pattern = int(str(fill_raw), 0)

    header_size = int(raw.get("header_size", 32))
    trailer_size = int(raw.get("trailer_size", 0))
    truncation_points = str(raw.get("truncation_points", "heuristic"))

    explicit_offsets = None
    if truncation_points == "explicit":
        offsets_raw = raw.get("offsets", [])
        if not isinstance(offsets_raw, list):
            raise ValueError("partial_staging.offsets: expected list of integers")
        explicit_offsets = [int(str(o), 0) for o in offsets_raw]

    max_points_raw = raw.get("max_points")
    max_points = int(max_points_raw) if max_points_raw is not None else None

    # Profile-level sector_size overrides the caller default.
    if "sector_size" in raw:
        sector_size = int(raw["sector_size"])

    return PartialStagingConfig(
        staging_image_path=str(staging_image),
        staging_slot_name=staging_slot,
        truncation_points=truncation_points,
        fill_pattern=fill_pattern,
        header_size=header_size,
        sector_size=sector_size,
        trailer_size=trailer_size,
        explicit_offsets=explicit_offsets,
        max_points=max_points,
    )
