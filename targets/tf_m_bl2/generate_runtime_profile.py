#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Tardigrade contributors
"""Generate a native AN521 TF-M BL2 runtime profile from build outputs."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEMPLATE_PATH = (
    REPO_ROOT / "profiles" / "tf_m_bl2_an521_native.template.yaml.in"
)
DEFAULT_HEADERS_DIR = (
    REPO_ROOT
    / "third_party"
    / "trusted-firmware-m"
    / "platform"
    / "ext"
    / "target"
    / "arm"
    / "mps2"
    / "an521"
    / "partition"
)
PROFILES_DIR = (REPO_ROOT / "profiles").resolve()


def _extract_mcuboot_image_2_lines(text: str) -> list[str]:
    """Return active preprocessor lines when MCUBOOT_IMAGE_NUMBER == 2."""
    out: list[str] = []
    joined = re.sub(r"\\\r?\n", " ", text)
    mode = "normal"
    for raw_line in joined.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("#if") and "MCUBOOT_IMAGE_NUMBER" in stripped:
            if "MCUBOOT_IMAGE_NUMBER == 2" in stripped:
                mode = "keep"
            else:
                mode = "skip"
            continue
        if stripped.startswith("#elif") and "MCUBOOT_IMAGE_NUMBER" in stripped:
            if "MCUBOOT_IMAGE_NUMBER == 2" in stripped:
                mode = "keep"
            else:
                mode = "skip"
            continue
        if stripped.startswith("#else") and mode in ("keep", "skip"):
            mode = "skip"
            continue
        if stripped.startswith("#endif") and mode in ("keep", "skip"):
            mode = "normal"
            continue
        if mode != "skip":
            out.append(raw_line)
    return out


def parse_c_defines(header_paths: list[Path]) -> dict[str, int]:
    """Evaluate integer #define macros from AN521 flash_layout.h / region_defs.h."""
    raw_defines: dict[str, str] = {"MCUBOOT_IMAGE_NUMBER": "2"}
    define_re = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$")
    for path in header_paths:
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"//[^\n]*", "", text)
        for line in _extract_mcuboot_image_2_lines(text):
            match = define_re.match(line)
            if not match:
                continue
            name, expr = match.group(1), match.group(2).strip()
            if "(" in name:
                continue
            raw_defines[name] = expr

    resolved: dict[str, int] = {}

    def _eval_expr(expr: str, depth: int = 0) -> int | None:
        if depth > 32:
            return None
        cleaned = expr.strip()
        cleaned = re.sub(
            r"\bS_ROM_ALIAS\s*\(([^()]+)\)",
            r"(S_ROM_ALIAS_BASE + (\1))",
            cleaned,
        )
        cleaned = re.sub(
            r"\bNS_ROM_ALIAS\s*\(([^()]+)\)",
            r"(NS_ROM_ALIAS_BASE + (\1))",
            cleaned,
        )
        cleaned = re.sub(r"\b(0x[0-9A-Fa-f]+|\d+)[uUlL]+\b", r"\1", cleaned)

        def _replace_ident(match: re.Match[str]) -> str:
            token = match.group(0)
            if token in resolved:
                return str(resolved[token])
            if token in raw_defines:
                val = _eval_expr(raw_defines[token], depth + 1)
                if val is not None:
                    resolved[token] = val
                    return str(val)
            return token

        substituted = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", _replace_ident, cleaned)
        if not re.fullmatch(r"[0-9xXa-fA-F+\-*/()<>\s]+", substituted):
            return None
        try:
            return int(eval(substituted, {"__builtins__": {}}, {}))
        except Exception:
            return None

    for name, expr in list(raw_defines.items()):
        val = _eval_expr(expr)
        if val is not None:
            resolved[name] = val

    return resolved


def parse_elf32_symbols_and_vectors(elf_path: Path) -> tuple[dict[str, int], int | None]:
    """Parse ELF32 symbol addresses and the lowest PT_LOAD p_vaddr."""
    data = elf_path.read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError(f"{elf_path} is not a valid 32-bit little-endian ELF")

    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)

    lowest_load_vaddr: int | None = None
    if e_phoff and e_phnum and e_phentsize >= 32:
        for idx in range(e_phnum):
            off = e_phoff + idx * e_phentsize
            if off + 32 > len(data):
                break
            p_type, _p_offset, p_vaddr, _p_paddr, _p_filesz, p_memsz, _p_flags, _p_align = (
                struct.unpack_from("<IIIIIIII", data, off)
            )
            if p_type == 1 and p_memsz > 0:
                if lowest_load_vaddr is None or p_vaddr < lowest_load_vaddr:
                    lowest_load_vaddr = p_vaddr

    symbols: dict[str, int] = {}
    if e_shoff and e_shnum and e_shentsize >= 40:
        sections = []
        for idx in range(e_shnum):
            off = e_shoff + idx * e_shentsize
            if off + 40 > len(data):
                break
            sections.append(struct.unpack_from("<IIIIIIIIII", data, off))

        SHT_SYMTAB = 2
        for sh in sections:
            sh_type = sh[1]
            sh_offset = sh[4]
            sh_size = sh[5]
            sh_link = sh[6]
            sh_entsize = sh[9] or 16
            if sh_type != SHT_SYMTAB or sh_link >= len(sections):
                continue
            strtab_sh = sections[sh_link]
            strtab_off = strtab_sh[4]
            strtab_size = strtab_sh[5]
            strtab = data[strtab_off : strtab_off + strtab_size]
            for pos in range(sh_offset, sh_offset + sh_size, sh_entsize):
                if pos + 16 > len(data):
                    break
                st_name, st_value, _st_size, _st_info, _st_other, _st_shndx = (
                    struct.unpack_from("<IIIBBH", data, pos)
                )
                if st_name == 0 or st_name >= len(strtab):
                    continue
                end = strtab.find(b"\x00", st_name)
                if end == -1:
                    continue
                name = strtab[st_name:end].decode("utf-8", errors="replace")
                if name:
                    symbols[name] = st_value

    return symbols, lowest_load_vaddr


def resolve_layout_from_headers(headers_dir: Path) -> dict[str, int]:
    """Compute AN521 slot bases, slot size, and BL2 vector base from headers."""
    flash_layout = headers_dir / "flash_layout.h"
    region_defs = headers_dir / "region_defs.h"
    missing = [p for p in (flash_layout, region_defs) if not p.exists()]
    if missing:
        raise FileNotFoundError(missing[0])

    defs = parse_c_defines([flash_layout, region_defs])
    s_rom_base = defs["S_ROM_ALIAS_BASE"]
    ns_rom_base = defs["NS_ROM_ALIAS_BASE"]
    slot_size = defs["FLASH_S_PARTITION_SIZE"]
    if defs.get("FLASH_NS_PARTITION_SIZE", slot_size) != slot_size:
        raise ValueError("S and NS partition sizes must match for common TFM_SLOT_SIZE")

    bl2_entry = defs.get("BL2_CODE_START", s_rom_base + defs["FLASH_AREA_BL2_OFFSET"])
    secure_primary = s_rom_base + defs["FLASH_AREA_0_OFFSET"]
    ns_primary = ns_rom_base + defs["FLASH_AREA_1_OFFSET"]
    secure_secondary = s_rom_base + defs["FLASH_AREA_2_OFFSET"]
    ns_secondary = ns_rom_base + defs["FLASH_AREA_3_OFFSET"]

    return {
        "bl2_entry": bl2_entry,
        "secure_primary_base": secure_primary,
        "secure_secondary_base": secure_secondary,
        "ns_primary_base": ns_primary,
        "ns_secondary_base": ns_secondary,
        "slot_size": slot_size,
    }


def _find_bl2_elf(build_dir: Path) -> Path:
    for candidate in (
        build_dir / "bl2.axf",
        build_dir / "bl2.elf",
        build_dir / "spe" / "bin" / "bl2.axf",
        build_dir / "spe" / "bin" / "bl2.elf",
    ):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(build_dir / "bl2.axf")


def render_runtime_profile(
    build_dir: Path,
    *,
    headers_dir: Path | None = None,
    template_path: Path = DEFAULT_TEMPLATE_PATH,
    run_duration_s: str = "3.0",
    vtor_settle_iters: int = 10,
    max_writes_cap: int = 200000,
    tracking_start_address: int | None = None,
    tracking_start_symbol: str = "fwu_bootloader_mark_image_accepted",
    max_heuristic_points: int | None = 64,
    preserve_critical_tiers: bool = False,
    should_find_issues: bool | None = None,
    confirmed_staging: bool = False,
    boot_cycles: int = 1,
) -> str:
    """Substitute all ${TFM_*} tokens in the AN521 native template."""
    build_dir = build_dir.resolve()
    cmake_cache = build_dir / "build_test" / "spe" / "CMakeCache.txt"
    is_overwrite_only = (
        cmake_cache.exists()
        and "MCUBOOT_UPGRADE_STRATEGY:STRING=OVERWRITE_ONLY"
        in cmake_cache.read_text(encoding="utf-8", errors="replace")
    )
    if is_overwrite_only and max_writes_cap == 200000:
        max_writes_cap = 700000
    if should_find_issues is None:
        should_find_issues = not (confirmed_staging or is_overwrite_only)
    if headers_dir is None:
        candidate_headers = build_dir / "partition"
        headers_dir = candidate_headers if candidate_headers.exists() else DEFAULT_HEADERS_DIR
    headers_dir = headers_dir.resolve()

    layout = resolve_layout_from_headers(headers_dir)
    slot_size = layout["slot_size"]

    bl2_elf = _find_bl2_elf(build_dir)
    s_primary_img = build_dir / "tfm_s_signed.bin"
    ns_primary_img = build_dir / "tfm_ns_signed.bin"
    if confirmed_staging:
        s_secondary_img = build_dir / "tfm_s_staging_confirmed.bin"
        if not s_secondary_img.exists() and (build_dir / "tfm_s_staging_signed_confirmed.bin").exists():
            s_secondary_img = build_dir / "tfm_s_staging_signed_confirmed.bin"
        ns_secondary_img = build_dir / "tfm_ns_staging_confirmed.bin"
        if not ns_secondary_img.exists() and (build_dir / "tfm_ns_staging_signed_confirmed.bin").exists():
            ns_secondary_img = build_dir / "tfm_ns_staging_signed_confirmed.bin"
    else:
        s_secondary_img = build_dir / "tfm_s_staging_signed.bin"
        ns_secondary_img = build_dir / "tfm_ns_staging_signed.bin"

    for img in (s_primary_img, s_secondary_img, ns_primary_img, ns_secondary_img):
        if not img.exists():
            raise FileNotFoundError(img)
        if img.stat().st_size > slot_size:
            raise ValueError(
                f"{img} ({img.stat().st_size} bytes) exceeds slot size 0x{slot_size:X}"
            )

    symbols, _lowest_vaddr = parse_elf32_symbols_and_vectors(bl2_elf)
    bl2_entry = symbols.get("__Vectors", layout["bl2_entry"])
    if bl2_entry != layout["bl2_entry"]:
        bl2_entry = layout["bl2_entry"]

    if tracking_start_address is None:
        sym_addr = symbols.get(tracking_start_symbol)
        tracking_start = (sym_addr & ~1) if sym_addr is not None else 0
    else:
        tracking_start = int(tracking_start_address)

    def _rel_or_abs(path: Path) -> str:
        try:
            return path.resolve().relative_to(REPO_ROOT).as_posix()
        except ValueError:
            return path.resolve().as_posix()

    substitutions = {
        "${TFM_BL2_ELF}": _rel_or_abs(bl2_elf),
        "${TFM_BL2_ENTRY}": f"0x{bl2_entry:08X}",
        "${TFM_SECURE_PRIMARY_BASE}": f"0x{layout['secure_primary_base']:08X}",
        "${TFM_SECURE_SECONDARY_BASE}": f"0x{layout['secure_secondary_base']:08X}",
        "${TFM_NS_PRIMARY_BASE}": f"0x{layout['ns_primary_base']:08X}",
        "${TFM_NS_SECONDARY_BASE}": f"0x{layout['ns_secondary_base']:08X}",
        "${TFM_SLOT_SIZE}": f"0x{slot_size:08X}",
        "${TFM_SECURE_PRIMARY_IMAGE}": _rel_or_abs(s_primary_img),
        "${TFM_SECURE_SECONDARY_IMAGE}": _rel_or_abs(s_secondary_img),
        "${TFM_NS_PRIMARY_IMAGE}": _rel_or_abs(ns_primary_img),
        "${TFM_NS_SECONDARY_IMAGE}": _rel_or_abs(ns_secondary_img),
        "${TFM_RUN_DURATION_S}": str(run_duration_s),
        "${TFM_VTOR_SETTLE_ITERS}": str(int(vtor_settle_iters)),
        "${TFM_TRACKING_START_ADDRESS}": (
            f"0x{tracking_start:08X}" if tracking_start else "0x0"
        ),
        "${TFM_MAX_WRITES_CAP}": str(int(max_writes_cap)),
    }

    rendered = template_path.read_text(encoding="utf-8")
    for token, value in substitutions.items():
        rendered = rendered.replace(token, value)

    remaining = re.findall(r"\$\{TFM_[^}]+\}", rendered)
    if remaining:
        raise ValueError(f"Unresolved template tokens: {remaining}")

    if is_overwrite_only and max_heuristic_points == 64:
        max_heuristic_points = 34
    extra_lines: list[str] = []
    if max_heuristic_points is not None:
        extra_lines.append(f"  max_heuristic_points: {int(max_heuristic_points)}")
    if not preserve_critical_tiers or is_overwrite_only:
        extra_lines.append("  heuristic:")
        if not preserve_critical_tiers:
            extra_lines.append("    preserve_critical_tiers: false")
        if is_overwrite_only:
            extra_lines.append("    critical_regions:")
            for primary_base in (
                layout["ns_primary_base"],
                layout["secure_primary_base"],
            ):
                primary_end = primary_base + slot_size
                extra_lines.append(
                    f"      - {{ start: 0x{primary_base:08X}, end: 0x{primary_base + 4:08X} }}"
                )
                extra_lines.append(
                    f"      - {{ start: 0x{primary_end - 16:08X}, end: 0x{primary_end:08X} }}"
                )
            for secondary_base in (
                layout["ns_secondary_base"],
                layout["secure_secondary_base"],
            ):
                secondary_end = secondary_base + slot_size
                trailer_sector_start = secondary_end - 0x1000
                extra_lines.append(
                    f"      - {{ start: 0x{secondary_base:08X}, end: 0x{secondary_base + 4:08X} }}"
                )
                extra_lines.append(
                    f"      - {{ start: 0x{trailer_sector_start:08X}, end: 0x{trailer_sector_start + 4:08X} }}"
                )
                extra_lines.append(
                    f"      - {{ start: 0x{secondary_end - 16:08X}, end: 0x{secondary_end:08X} }}"
                )
    boot_cycles_line = f"  boot_cycles: {int(boot_cycles)}\n"
    if "  boot_cycles: 1\n" in rendered:
        replacement = boot_cycles_line
        if extra_lines:
            replacement += "\n".join(extra_lines) + "\n"
        rendered = rendered.replace("  boot_cycles: 1\n", replacement, 1)
    if not tracking_start and "  semantic_state_stage: fault_snapshot\n" in rendered:
        rendered = rendered.replace(
            "  semantic_state_stage: fault_snapshot\n",
            "  semantic_state_stage: final\n",
            1,
        )
    if should_find_issues and "  should_find_issues: false\n" in rendered:
        rendered = rendered.replace(
            "  should_find_issues: false\n",
            "  should_find_issues: true\n",
            1,
        )
    elif not should_find_issues and "  should_find_issues: true\n" in rendered:
        rendered = rendered.replace(
            "  should_find_issues: true\n",
            "  should_find_issues: false\n",
            1,
        )

    return rendered


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
        default=REPO_ROOT / "results" / "tfm_an521",
        help="Directory containing bl2.axf and signed S/NS images",
    )
    parser.add_argument(
        "--headers-dir",
        type=Path,
        default=None,
        help="Directory containing AN521 flash_layout.h and region_defs.h",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=DEFAULT_TEMPLATE_PATH,
        help="Path to tf_m_bl2_an521_native.template.yaml.in",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output YAML path (defaults to <build-dir>/tf_m_bl2_an521_native.yaml)",
    )
    parser.add_argument(
        "--run-duration",
        default="3.0",
        help="Emulated seconds per boot slice (default: 3.0)",
    )
    parser.add_argument(
        "--vtor-settle-iters",
        type=int,
        default=10,
        help="Post-VTOR 5ms settle iterations for NS handoff (default: 10)",
    )
    parser.add_argument(
        "--max-writes-cap",
        type=int,
        default=200000,
        help="Upper bound on fault_sweep.max_writes_cap (default: 200000)",
    )
    parser.add_argument(
        "--tracking-start-address",
        type=lambda x: int(x, 0),
        default=None,
        help="Explicit tracking_start_address override",
    )
    parser.add_argument(
        "--max-heuristic-points",
        type=int,
        default=64,
        help="Maximum heuristic fault points (default: 64)",
    )
    parser.add_argument(
        "--preserve-critical-tiers",
        action="store_true",
        help="Preserve all Tier 0/1 writes even when exceeding max_heuristic_points",
    )
    parser.add_argument(
        "--confirmed-staging",
        "--confirmed",
        dest="confirmed_staging",
        action="store_true",
        help="Select confirmed staging images (*_confirmed.bin) instead of test staging images",
    )
    parser.add_argument(
        "--boot-cycles",
        type=int,
        default=1,
        help="Number of recovery boot cycles per fault point (default: 1)",
    )
    args = parser.parse_args(argv)

    output_path = args.output or (args.build_dir / "tf_m_bl2_an521_native.yaml")
    rendered = render_runtime_profile(
        args.build_dir,
        headers_dir=args.headers_dir,
        template_path=args.template,
        run_duration_s=args.run_duration,
        vtor_settle_iters=args.vtor_settle_iters,
        max_writes_cap=args.max_writes_cap,
        tracking_start_address=args.tracking_start_address,
        max_heuristic_points=args.max_heuristic_points,
        preserve_critical_tiers=args.preserve_critical_tiers,
        confirmed_staging=args.confirmed_staging,
        boot_cycles=args.boot_cycles,
    )
    written = write_runtime_profile(output_path, rendered)
    print(written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
