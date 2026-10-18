#!/usr/bin/env python3
"""Verify every tracked MCUboot ELF against its expected upstream boot_swap_tables."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import io
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, Sequence

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ASSETS_DIR = ROOT / "results" / "oss_validation" / "assets"

# Generation 1: pre-PR #2100 (or Zephyr v3.7.0 module build at fb2cf0ec3da3).
# 3 entries x 6 bytes = 18 bytes; entry 2 requires magic_secondary_slot = UNSET (0x03).
SWAP_TABLE_GEN1 = (
    b"\x04\x01\x04\x03\x04\x02"  # ANY, GOOD, ANY, UNSET, ANY -> TEST
    b"\x04\x01\x04\x01\x04\x03"  # ANY, GOOD, ANY, SET, ANY -> PERM
    b"\x01\x03\x03\x04\x01\x04"  # GOOD, UNSET, UNSET, ANY, SET -> REVERT
)

# Generation 2: post-PR #2100 fix (4f393563 / 664093d0) for move and scratch builds.
# 3 entries x 6 bytes = 18 bytes; entry 2 accepts magic_secondary_slot = ANY (0x04).
SWAP_TABLE_GEN2 = (
    b"\x04\x01\x04\x03\x04\x02"  # ANY, GOOD, ANY, UNSET, ANY -> TEST
    b"\x04\x01\x04\x01\x04\x03"  # ANY, GOOD, ANY, SET, ANY -> PERM
    b"\x01\x04\x03\x04\x01\x04"  # GOOD, ANY, UNSET, ANY, SET -> REVERT
)

# Generation 3: swap-using-offset builds (post-4af73169 with MCUBOOT_SWAP_USING_OFFSET).
# 4 entries x 7 bytes = 28 bytes; includes copy_done_secondary_slot and offset revert row.
SWAP_TABLE_GEN3 = (
    b"\x04\x01\x04\x03\x04\x01\x04"  # ANY, GOOD, ANY, UNSET, ANY, SET -> REVERT
    b"\x04\x01\x04\x03\x04\x04\x02"  # ANY, GOOD, ANY, UNSET, ANY, ANY -> TEST
    b"\x04\x01\x04\x01\x04\x04\x03"  # ANY, GOOD, ANY, SET, ANY, ANY -> PERM
    b"\x01\x04\x03\x04\x01\x04\x04"  # GOOD, ANY, UNSET, ANY, SET, ANY -> REVERT
)

KNOWN_UPSTREAM_TABLES: tuple[bytes, ...] = (
    SWAP_TABLE_GEN3,
    SWAP_TABLE_GEN2,
    SWAP_TABLE_GEN1,
)

# Commits whose Zephyr builds link bootutil_public.c with the Generation 1 table.
GEN1_COMMITS: frozenset[str] = frozenset(
    {
        "fb2cf0ec3da3687b93f28e556ab682bdd4b85223",  # Zephyr v3.7.0 mcuboot revision
        "172694eac08dd041576d0f56bafa6a594d02ba87",  # PR #2109 broken
        "c50b332ba794bd35c1915fdf5342fb5ce10e7ab6",  # PR #2109 fixed
        "2ac797677ef04aa416a07294ad8ced87e90e8e9f",  # PR #2100 broken
        "429e2fea24518f178cd4d33928cb66fcb0205803",  # PR #2214 broken (detached worktree on Zephyr v3.7.0)
        "90fd59d2f9e45c24d0833dd391dcdc932b3b1908",  # PR #2214 fixed (detached worktree on Zephyr v3.7.0)
    }
)

# Commits after PR #2100 fix (4f393563 / 664093d0) and before swap-offset (4af73169).
GEN2_ONLY_COMMITS: frozenset[str] = frozenset(
    {
        "4f3935638e3e4535246ff1372796f7a22880c4d9",  # PR #2100 fixed
        "664093d07023bb3051f00f3ad5585b3220ad2354",  # v2.1.0-76-g664093d07023
    }
)

# Commits after swap-offset introduction (4af73169) built with in-tree bootutil_public.c:
# move/scratch builds produce Generation 2; offset builds produce Generation 3.
POST_OFFSET_COMMITS: frozenset[str] = frozenset(
    {
        "25e2761c669035c991dff115f03e34f1505bd97a",  # PR #2199 broken
        "33094fc5a50096c8cbb3d2f443c4162a0ff08ea8",  # PR #2199 fixed
        "7253f01c06e19d2c5d7b146fedcf4473200b6b0d",  # scratch erase broken
        "f76fba706a66ce08d733468b47f89e26d59b3de5",  # scratch erase fixed
        "b893d34f564f454f454f3643b05b1e18fb457e5c",  # head_offset
        "f84b9d3fd019fb1945e532924bee7a9c03c77373",  # head matrix
    }
)

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HEAD_MATRIX_STEM_RE = re.compile(r"^oss_mcuboot_head_(?:move|scratch|offset)_(?:nrf52|stm32f4|small)$")


@dataclass(frozen=True)
class SwapTableCheckResult:
    elf_path: Path
    status: str  # "ok", "mismatch", "unverifiable"
    commit: str | None
    algorithm: str | None
    location: str | None  # ".symtab", ".rodata", or None
    found_bytes: bytes | None
    expected_bytes: bytes | None
    message: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def detect_algorithm(elf_path: Path, elf_bytes: bytes) -> str | None:
    stem = elf_path.stem.lower()
    if "offset" in stem:
        return "offset"
    if "scratch" in stem:
        return "scratch"
    if "move" in stem:
        return "move"
    for alg in ("offset", "scratch", "move"):
        if f"Starting swap using {alg} algorithm".encode("ascii") in elf_bytes:
            return alg
    if stem in {
        "oss_mcuboot_head",
        "oss_mcuboot_mcuboot_swap_current_guard",
        "oss_mcuboot_pr2100_broken",
        "oss_mcuboot_pr2100_fixed",
        "oss_mcuboot_stm32f4",
    }:
        return "move"
    return None


def read_recorded_commit(elf_path: Path) -> tuple[str | None, str | None]:
    commit_path = elf_path.with_name(f"{elf_path.stem}_commit.txt")
    if not commit_path.is_file():
        if HEAD_MATRIX_STEM_RE.match(elf_path.stem):
            fallback = elf_path.parent / "mcuboot_head_commit.txt"
            if fallback.is_file():
                commit_path = fallback
            else:
                return None, f"missing commit file {commit_path.name}"
        else:
            return None, f"missing commit file {commit_path.name}"

    raw = commit_path.read_text(encoding="utf-8").strip().lower()
    if not COMMIT_RE.match(raw):
        return None, f"invalid commit SHA in {commit_path.name}: {raw!r}"
    return raw, None


def expected_swap_table(commit_sha: str, algorithm: str) -> bytes | None:
    commit = commit_sha.lower()
    if commit in GEN1_COMMITS:
        return SWAP_TABLE_GEN1
    if commit in GEN2_ONLY_COMMITS:
        if algorithm in ("move", "scratch"):
            return SWAP_TABLE_GEN2
        return None
    if commit in POST_OFFSET_COMMITS:
        if algorithm == "offset":
            return SWAP_TABLE_GEN3
        if algorithm in ("move", "scratch"):
            return SWAP_TABLE_GEN2
        return None
    return None


def locate_swap_table(elf_bytes: bytes, expected_len: int) -> tuple[bytes | None, str | None]:
    elf = ELFFile(io.BytesIO(elf_bytes))
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        symbols = section.get_symbol_by_name("boot_swap_tables")
        if not symbols:
            continue
        sym = symbols[0]
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int):
            continue
        target_sec = elf.get_section(shndx)
        offset = int(sym["st_value"]) - int(target_sec["sh_addr"])
        size = int(sym["st_size"])
        data = target_sec.data()
        if 0 <= offset and offset + size <= len(data):
            return data[offset : offset + size], ".symtab"

    rodata = elf.get_section_by_name(".rodata") or elf.get_section_by_name("rodata")
    if rodata is None:
        return None, None
    ro_bytes = rodata.data()
    for table in KNOWN_UPSTREAM_TABLES:
        idx = ro_bytes.find(table)
        if idx != -1:
            return ro_bytes[idx : idx + len(table)], ".rodata"

    # If a stripped ELF has a modified entry after the standard TEST/PERM rows,
    # extract expected_len bytes from that prefix so the diagnostic prints the
    # exact modified bytes found.
    for prefix in (
        b"\x04\x01\x04\x03\x04\x01\x04\x04\x01\x04\x03\x04\x04\x02",
        b"\x04\x01\x04\x03\x04\x02\x04\x01\x04\x01\x04\x03",
    ):
        idx = ro_bytes.find(prefix)
        if idx != -1 and idx + expected_len <= len(ro_bytes):
            return ro_bytes[idx : idx + expected_len], ".rodata"

    return None, ".rodata"


def check_elf(elf_path: Path, *, repo_root: Path = ROOT) -> SwapTableCheckResult:
    try:
        rel_label = str(elf_path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        rel_label = str(elf_path)

    if not elf_path.is_file():
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="unverifiable",
            commit=None,
            algorithm=None,
            location=None,
            found_bytes=None,
            expected_bytes=None,
            message=f"{rel_label}: unverifiable (missing ELF file)",
        )

    commit_sha, err = read_recorded_commit(elf_path)
    if err is not None or commit_sha is None:
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="unverifiable",
            commit=None,
            algorithm=None,
            location=None,
            found_bytes=None,
            expected_bytes=None,
            message=f"{rel_label}: unverifiable ({err})",
        )

    elf_bytes = elf_path.read_bytes()
    algorithm = detect_algorithm(elf_path, elf_bytes)
    if algorithm is None:
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="unverifiable",
            commit=commit_sha,
            algorithm=None,
            location=None,
            found_bytes=None,
            expected_bytes=None,
            message=f"{rel_label}: unverifiable (cannot determine swap algorithm)",
        )

    expected = expected_swap_table(commit_sha, algorithm)
    if expected is None:
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="unverifiable",
            commit=commit_sha,
            algorithm=algorithm,
            location=None,
            found_bytes=None,
            expected_bytes=None,
            message=f"{rel_label}: unverifiable (unknown expected swap table for commit {commit_sha} and algorithm {algorithm})",
        )

    found, location = locate_swap_table(elf_bytes, len(expected))
    if found is None:
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="mismatch",
            commit=commit_sha,
            algorithm=algorithm,
            location=location,
            found_bytes=None,
            expected_bytes=expected,
            message=(
                f"{rel_label}: boot_swap_tables not found "
                f"(commit={commit_sha} algorithm={algorithm} found=none expected={expected.hex()})"
            ),
        )

    if found != expected:
        return SwapTableCheckResult(
            elf_path=elf_path,
            status="mismatch",
            commit=commit_sha,
            algorithm=algorithm,
            location=location,
            found_bytes=found,
            expected_bytes=expected,
            message=(
                f"{rel_label}: boot_swap_tables mismatch "
                f"(commit={commit_sha} algorithm={algorithm} via={location} "
                f"found={found.hex()} expected={expected.hex()})"
            ),
        )

    return SwapTableCheckResult(
        elf_path=elf_path,
        status="ok",
        commit=commit_sha,
        algorithm=algorithm,
        location=location,
        found_bytes=found,
        expected_bytes=expected,
        message=(
            f"{rel_label}: ok (commit={commit_sha[:12]} algorithm={algorithm} "
            f"via={location} bytes={found.hex()})"
        ),
    )


def discover_tracked_elfs(repo_root: Path = ROOT) -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "results/oss_validation/assets/oss_mcuboot_*.elf"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return [repo_root / line.strip() for line in sorted(proc.stdout.splitlines()) if line.strip()]
    assets_dir = repo_root / "results" / "oss_validation" / "assets"
    return sorted(assets_dir.glob("oss_mcuboot_*.elf"))


def check_assets(
    elf_paths: Iterable[Path] | None = None,
    *,
    repo_root: Path = ROOT,
) -> list[SwapTableCheckResult]:
    paths = list(elf_paths) if elf_paths is not None else discover_tracked_elfs(repo_root)
    return [check_elf(path, repo_root=repo_root) for path in paths]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify tracked MCUboot ELFs against their expected upstream boot_swap_tables."
    )
    parser.add_argument(
        "elfs",
        nargs="*",
        type=Path,
        help="Optional explicit ELF paths to check (defaults to all tracked oss_mcuboot_*.elf).",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help="Check all oss_mcuboot_*.elf files in this directory.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Repository root for relative path reporting and git ls-files discovery.",
    )
    args = parser.parse_args(argv)

    if args.elfs:
        target_elfs = list(args.elfs)
    elif args.assets_dir is not None:
        target_elfs = sorted(args.assets_dir.glob("oss_mcuboot_*.elf"))
    else:
        target_elfs = discover_tracked_elfs(args.repo_root)

    if not target_elfs:
        print("No oss_mcuboot_*.elf files found to check.", file=sys.stderr)
        return 1

    results = check_assets(target_elfs, repo_root=args.repo_root)
    failures = [res for res in results if not res.ok]
    if failures:
        for failure in failures:
            print(failure.message, file=sys.stderr)
        return 1

    for res in results:
        print(res.message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
