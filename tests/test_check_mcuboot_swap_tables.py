#!/usr/bin/env python3
"""Unit tests for scripts/check_mcuboot_swap_tables.py."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import check_mcuboot_swap_tables as swap_check  # noqa: E402


def _build_synthetic_elf(
    rodata_payload: bytes,
    *,
    include_symtab: bool = True,
    sym_offset: int = 0,
    sym_size: int | None = None,
) -> bytes:
    """Build a minimal 32-bit little-endian ARM ELF with .rodata and optional .symtab."""
    if sym_size is None:
        sym_size = len(rodata_payload) - sym_offset

    rodata_vaddr = 0x00005000
    if include_symtab:
        shstrtab = b"\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00"
        name_rodata = shstrtab.index(b".rodata\x00")
        name_symtab = shstrtab.index(b".symtab\x00")
        name_strtab = shstrtab.index(b".strtab\x00")
        name_shstrtab = shstrtab.index(b".shstrtab\x00")

        strtab = b"\x00boot_swap_tables\x00"
        sym_name_off = strtab.index(b"boot_swap_tables\x00")
        # Elf32_Sym: st_name, st_value, st_size, st_info, st_other, st_shndx
        null_sym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
        # STB_LOCAL (0) << 4 | STT_OBJECT (1) = 1; section index 1 is .rodata
        swap_sym = struct.pack(
            "<IIIBBH",
            sym_name_off,
            rodata_vaddr + sym_offset,
            sym_size,
            0x01,
            0,
            1,
        )
        symtab = null_sym + swap_sym
        sections = [
            # (sh_name, sh_type, sh_flags, sh_addr, data, sh_link, sh_info, sh_addralign, sh_entsize)
            (0, 0, 0, 0, b"", 0, 0, 0, 0),
            (name_rodata, 1, 0x02, rodata_vaddr, rodata_payload, 0, 0, 4, 0),
            (name_symtab, 2, 0, 0, symtab, 3, 2, 4, 16),
            (name_strtab, 3, 0, 0, strtab, 0, 0, 1, 0),
            (name_shstrtab, 3, 0, 0, shstrtab, 0, 0, 1, 0),
        ]
        shstrndx = 4
    else:
        shstrtab = b"\x00.rodata\x00.shstrtab\x00"
        name_rodata = shstrtab.index(b".rodata\x00")
        name_shstrtab = shstrtab.index(b".shstrtab\x00")
        sections = [
            (0, 0, 0, 0, b"", 0, 0, 0, 0),
            (name_rodata, 1, 0x02, rodata_vaddr, rodata_payload, 0, 0, 4, 0),
            (name_shstrtab, 3, 0, 0, shstrtab, 0, 0, 1, 0),
        ]
        shstrndx = 2

    ehdr_size = 52
    body = bytearray()
    shdrs = bytearray()
    for sh_name, sh_type, sh_flags, sh_addr, data, sh_link, sh_info, sh_align, sh_entsize in sections:
        if sh_type == 0:
            sh_offset = 0
            sh_size = 0
        else:
            while (ehdr_size + len(body)) % max(sh_align, 1) != 0:
                body.append(0)
            sh_offset = ehdr_size + len(body)
            sh_size = len(data)
            body.extend(data)
        shdrs.extend(
            struct.pack(
                "<10I",
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_align,
                sh_entsize,
            )
        )

    while (ehdr_size + len(body)) % 4 != 0:
        body.append(0)
    e_shoff = ehdr_size + len(body)

    e_ident = b"\x7fELF\x01\x01\x01" + (b"\x00" * 9)
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,  # ET_EXEC
        40,  # EM_ARM
        1,  # EV_CURRENT
        0,  # e_entry
        0,  # e_phoff
        e_shoff,
        0,  # e_flags
        ehdr_size,
        0,  # e_phentsize
        0,  # e_phnum
        40,  # e_shentsize
        len(sections),
        shstrndx,
    )
    return bytes(ehdr + body + shdrs)


class CheckMcubootSwapTablesTests(unittest.TestCase):
    def test_tracked_assets_pass_swap_table_check(self) -> None:
        tracked = set(
            subprocess.check_output(
                ["git", "ls-files", "results/oss_validation/assets"],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
        elf_paths = swap_check.discover_tracked_elfs(ROOT)
        self.assertGreaterEqual(len(elf_paths), 25)
        for elf_path in elf_paths:
            rel_elf = str(elf_path.relative_to(ROOT))
            commit_path = elf_path.with_name(f"{elf_path.stem}_commit.txt")
            rel_commit = str(commit_path.relative_to(ROOT))
            with self.subTest(elf=rel_elf):
                self.assertIn(rel_elf, tracked)
                self.assertTrue(commit_path.is_file(), f"missing {rel_commit}")
                self.assertIn(rel_commit, tracked)

        results = swap_check.check_assets(repo_root=ROOT)
        for res in results:
            with self.subTest(elf=res.elf_path.name):
                self.assertTrue(res.ok, res.message)
                self.assertEqual(res.location, ".symtab", res.message)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = swap_check.main([])
        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_synthetic_elf_with_modified_table_fails(self) -> None:
        patched_table = (
            b"\x04\x01\x04\x03\x04\x02"
            b"\x04\x01\x04\x01\x04\x03"
            b"\x01\x04\x03\x04\x04\x04"  # modified entry 2 from commit 4295e59
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            elf_path = tmp_dir / "oss_mcuboot_pr2214_offset_nrf52_fixed.elf"
            commit_path = tmp_dir / "oss_mcuboot_pr2214_offset_nrf52_fixed_commit.txt"
            elf_path.write_bytes(_build_synthetic_elf(patched_table, include_symtab=True))
            commit_path.write_text("90fd59d2f9e45c24d0833dd391dcdc932b3b1908\n", encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = swap_check.main([str(elf_path)])

            self.assertNotEqual(rc, 0)
            err_text = stderr.getvalue()
            self.assertIn("oss_mcuboot_pr2214_offset_nrf52_fixed.elf", err_text)
            self.assertIn(f"found={patched_table.hex()}", err_text)
            self.assertIn(f"expected={swap_check.SWAP_TABLE_GEN1.hex()}", err_text)

    def test_stripped_synthetic_elf_with_modified_table_fails(self) -> None:
        patched_table = (
            b"\x04\x01\x04\x03\x04\x02"
            b"\x04\x01\x04\x01\x04\x03"
            b"\x01\x04\x03\x04\x04\x04"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            elf_path = tmp_dir / "oss_mcuboot_pr2199_move_fixed.elf"
            commit_path = tmp_dir / "oss_mcuboot_pr2199_move_fixed_commit.txt"
            elf_path.write_bytes(
                _build_synthetic_elf(
                    b"banner\x00" + patched_table + b"\x00trailer",
                    include_symtab=False,
                )
            )
            commit_path.write_text("33094fc5a50096c8cbb3d2f443c4162a0ff08ea8\n", encoding="utf-8")

            res = swap_check.check_elf(elf_path, repo_root=tmp_dir)
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "mismatch")
            self.assertEqual(res.location, ".rodata")
            self.assertEqual(res.found_bytes, patched_table)
            self.assertEqual(res.expected_bytes, swap_check.SWAP_TABLE_GEN2)

    def test_missing_commit_file_reports_unverifiable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            elf_path = tmp_dir / "oss_mcuboot_custom_move.elf"
            elf_path.write_bytes(_build_synthetic_elf(swap_check.SWAP_TABLE_GEN2, include_symtab=True))

            res = swap_check.check_elf(elf_path, repo_root=tmp_dir)
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "unverifiable")
            self.assertIn("unverifiable", res.message)


if __name__ == "__main__":
    unittest.main()
