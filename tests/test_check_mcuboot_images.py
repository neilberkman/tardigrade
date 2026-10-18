#!/usr/bin/env python3
"""Unit tests for scripts/check_mcuboot_images.py."""

from __future__ import annotations

import contextlib
import hashlib
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

import check_mcuboot_images as img_check  # noqa: E402


def _parse_rsa_private_numbers(pem_bytes: bytes) -> tuple[int, int, int, bytes]:
    der = img_check._parse_pem_der(pem_bytes)
    _, seq_val, _ = img_check._read_der_tlv(der, 0)
    _, _, pos = img_check._read_der_tlv(seq_val, 0)  # version
    tag_n, n_bytes, pos = img_check._read_der_tlv(seq_val, pos)
    tag_e, e_bytes, pos = img_check._read_der_tlv(seq_val, pos)
    _, d_bytes, _ = img_check._read_der_tlv(seq_val, pos)
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    d = int.from_bytes(d_bytes, "big")
    pkcs1_pub_der = img_check._encode_der_tlv(
        0x30,
        img_check._encode_der_tlv(tag_n, n_bytes) + img_check._encode_der_tlv(tag_e, e_bytes),
    )
    keyhash = hashlib.sha256(pkcs1_pub_der).digest()
    return n, e, d, keyhash


def _sign_rsa_pss_stdlib(n: int, d: int, message: bytes, *, salt: bytes = b"\x42" * 32) -> bytes:
    mod_bits = n.bit_length()
    em_len = (mod_bits + 7) // 8
    h_len = 32
    masked_db_len = em_len - h_len - 1
    m_hash = hashlib.sha256(message).digest()
    h = hashlib.sha256((b"\x00" * 8) + m_hash + salt).digest()
    ps_len = masked_db_len - len(salt) - 1
    db = (b"\x00" * ps_len) + b"\x01" + salt
    db_mask = img_check._mgf1_sha256(h, masked_db_len)
    masked_db = bytearray(a ^ b for a, b in zip(db, db_mask))
    top_bits = 8 * em_len - (mod_bits - 1)
    masked_db[0] &= 0xFF >> top_bits
    em = bytes(masked_db) + h + b"\xbc"
    m_int = int.from_bytes(em, "big")
    s_int = pow(m_int, d, n)
    return s_int.to_bytes(em_len, "big")


def _build_synthetic_mcuboot_image(
    *,
    payload: bytes = b"\x00\x20\x00\x20\xe5\xd1\x00\x00" + (b"\xaa" * 120),
    hdr_size: int = 0x200,
    tamper_signature: bool = False,
    tamper_sha256: bool = False,
) -> bytes:
    img_size = len(payload)
    header = bytearray(hdr_size)
    img_check.IMAGE_HEADER_STRUCT.pack_into(
        header,
        0,
        img_check.IMAGE_MAGIC,
        0,
        hdr_size,
        0,
        img_size,
        0,
        1,
        0,
        0,
        0,
    )
    signed_bytes = bytes(header) + payload
    sha256_digest = hashlib.sha256(signed_bytes).digest()
    if tamper_sha256:
        sha256_digest = bytes([sha256_digest[0] ^ 0xFF]) + sha256_digest[1:]

    n, _, d, keyhash = _parse_rsa_private_numbers(img_check.DEFAULT_ROOT_RSA_2048_PEM)
    signature = bytearray(_sign_rsa_pss_stdlib(n, d, signed_bytes))
    if tamper_signature:
        signature[-1] ^= 0x01

    tlv_entries = bytearray()
    for tlv_type, val in (
        (img_check.TLV_SHA256, sha256_digest),
        (img_check.TLV_KEYHASH, keyhash),
        (img_check.TLV_RSA2048_PSS, bytes(signature)),
    ):
        tlv_entries.extend(img_check.TLV_ENTRY_STRUCT.pack(tlv_type, len(val)))
        tlv_entries.extend(val)

    tlv_info = img_check.TLV_INFO_STRUCT.pack(
        img_check.TLV_INFO_MAGIC,
        img_check.TLV_INFO_STRUCT.size + len(tlv_entries),
    )
    return signed_bytes + tlv_info + bytes(tlv_entries)


class CheckMcubootImagesTests(unittest.TestCase):
    def test_tracked_assets_pass_image_check(self) -> None:
        tracked = set(
            subprocess.check_output(
                ["git", "ls-files", "results/oss_validation/assets/*.bin"],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
        image_paths = img_check.discover_tracked_images(ROOT)
        self.assertEqual(len(image_paths), 34)
        for path in image_paths:
            rel = str(path.relative_to(ROOT))
            with self.subTest(image=rel):
                self.assertIn(rel, tracked)
                self.assertIn(path.name, img_check.PROVENANCE_SPECS)

        results = img_check.check_assets(repo_root=ROOT)
        self.assertEqual(len(results), 34)
        ok_count = 0
        allowlisted_count = 0
        for res in results:
            with self.subTest(image=res.image_path.name):
                self.assertTrue(res.ok, res.message)
                if res.status == "allowlisted":
                    allowlisted_count += 1
                    self.assertIn(res.image_path.name, img_check.ALLOWLIST)
                    self.assertIn("allowlisted (", res.message)
                    self.assertIsNotNone(res.allowlist_reason)
                    self.assertIn(res.allowlist_reason, res.message)
                else:
                    ok_count += 1
                    self.assertEqual(res.status, "ok")
                    self.assertEqual(res.magic, img_check.IMAGE_MAGIC)
                    self.assertEqual(res.header_size, 0x200)
                    self.assertTrue(res.hash_matches)
                    self.assertTrue(res.signature_verified)

        self.assertEqual(ok_count, 28)
        self.assertEqual(allowlisted_count, 6)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = img_check.main([])
        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_synthetic_image_with_valid_signature_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "synthetic_valid.bin"
            img_path.write_bytes(_build_synthetic_mcuboot_image(tamper_signature=False))

            res = img_check.check_image(img_path, repo_root=Path(tmp))
            self.assertTrue(res.ok, res.message)
            self.assertEqual(res.status, "ok")
            self.assertTrue(res.hash_matches)
            self.assertTrue(res.signature_verified)

    def test_synthetic_image_with_wrong_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "synthetic_bad_sig.bin"
            img_path.write_bytes(_build_synthetic_mcuboot_image(tamper_signature=True))

            res = img_check.check_image(img_path, repo_root=tmp_dir)
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "failed")
            self.assertTrue(res.hash_matches)
            self.assertFalse(res.signature_verified)
            self.assertIn("synthetic_bad_sig.bin", res.message)
            self.assertIn("signature verification failed", res.message)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = img_check.main([str(img_path), "--repo-root", str(tmp_dir)])
            self.assertNotEqual(rc, 0)
            self.assertIn("synthetic_bad_sig.bin", stderr.getvalue())
            self.assertIn("signature verification failed", stderr.getvalue())

    def test_synthetic_image_with_wrong_sha256_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "synthetic_bad_sha.bin"
            img_path.write_bytes(_build_synthetic_mcuboot_image(tamper_sha256=True))

            res = img_check.check_image(img_path, repo_root=tmp_dir)
            self.assertFalse(res.ok)
            self.assertEqual(res.status, "failed")
            self.assertFalse(res.hash_matches)
            self.assertIn("SHA-256 mismatch", res.message)

    def test_profile_vector_crosscheck_identifies_expected_mismatches(self) -> None:
        profiles = img_check.discover_mcuboot_profiles(ROOT)
        self.assertEqual(len(profiles), 94)

        results = img_check.check_all_profile_vectors(profiles, repo_root=ROOT)
        self.assertEqual(len(results), 94)

        ok_profiles = {r.profile_path.name: r for r in results if r.ok}
        mismatch_map = {r.profile_path.name: r for r in results if not r.ok}
        self.assertEqual(len(ok_profiles), 94)
        self.assertEqual(set(mismatch_map.keys()), set())

        for name in (
            "mcuboot_stm32f4_upgrade.yaml",
        ):
            self.assertIn(name, ok_profiles)
            self.assertIn("hdr=0x200,vec=0x200,reset=0x0802110d", ok_profiles[name].message)

        for name in (
            "mcuboot_pr2214_offset_geom_broken.yaml",
            "mcuboot_pr2214_offset_geom_fixed.yaml",
        ):
            self.assertIn(name, ok_profiles)
            self.assertIn("hdr=0x200,vec=0x200,reset=0x08009131", ok_profiles[name].message)

        self.assertIn("mcuboot_head_scratch_stm32f4_writeback.yaml", ok_profiles)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = img_check.main(["--check-profiles"])
        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")

        stdout_report = io.StringIO()
        stderr_report = io.StringIO()
        with contextlib.redirect_stdout(stdout_report), contextlib.redirect_stderr(stderr_report):
            rc_report = img_check.main(["--check-profiles", "--report-only"])
        self.assertEqual(rc_report, 0)
        self.assertEqual(stderr_report.getvalue(), "")
        self.assertEqual(len(stdout_report.getvalue().strip().splitlines()), 94)


if __name__ == "__main__":
    unittest.main()

