#!/usr/bin/env python3
"""Verify tracked MCUboot application images under results/oss_validation/assets/."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ASSETS_DIR = ROOT / "results" / "oss_validation" / "assets"

IMAGE_MAGIC = 0x96F3B83D
IMAGE_HEADER_STRUCT = struct.Struct("<IIHHIIBBHI")
TLV_INFO_STRUCT = struct.Struct("<HH")
TLV_ENTRY_STRUCT = struct.Struct("<HH")

TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908

TLV_KEYHASH = 0x01
TLV_PUBKEY = 0x02
TLV_SHA256 = 0x10
TLV_RSA2048_PSS = 0x20
TLV_ECDSA224 = 0x21
TLV_ECDSA_SIG = 0x22
TLV_RSA3072_PSS = 0x23
TLV_ED25519 = 0x24
TLV_SEC_CNT = 0x50

SIGNATURE_TLV_NAMES: dict[int, str] = {
    TLV_RSA2048_PSS: "RSA-2048-PSS",
    TLV_ECDSA224: "ECDSA-P224",
    TLV_ECDSA_SIG: "ECDSA-P256",
    TLV_RSA3072_PSS: "RSA-3072-PSS",
    TLV_ED25519: "ED25519",
}

# Upstream MCUboot default test keys (third_party/zephyr_ws/bootloader/mcuboot/root-*.pem).
# Kept here as a fallback when third_party/zephyr_ws is not checked out on disk.
DEFAULT_ROOT_RSA_2048_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0QYIGhhELBjo+/33DaNPH7vuXvmq0ksY01rpbRiAGfnwnDQb\n"
    "y/O8dNtC54x/EFN+Q14NVyxE0WcIDw27XO7ss5nf4E2EC6p3QWDtFShJpwG0PBDm\n"
    "aYwvX6xBTZ5cFN/y+M89Hm/nW7q0qciIfkc8lMN3Z1RLqo04NcpiYX634RXbd3PU\n"
    "vntyIYlpJPv4ZW5kPsgO14XVXErkUw0v/7f98xM5gz+jrtIPp2qd+f64zvoqvq+4\n"
    "4PqCN1T0PuEr0NMIWBj2XkzIiIExrV+wghfyimknI/Orhz6TGh3+6PgaJGZZ+Byr\n"
    "3M5oG2ZkNez6DRGdr1w6p9FnxkfvsUssYuHRyQIDAQABAoIBAEahFCHFK1v/OtLT\n"
    "eSSZl0Xw2dYr5QXULFpWsOOVUMv2QdB2ZyIehQKziEL3nYPlwpd+82EOa16awwVb\n"
    "LYF0lnUFvLltV/4dJtjnqJTqnSCamc1mJIVrwiJA8XwJ07GWDuL2G//p7jJ3v05T\n"
    "nZOV/KmD9xfqSvshZun+LgolqHqcrAa1f4cmuP9C9oqenZryljyfj7piaIZGI0JR\n"
    "PrJJ5kImYJqRcMgKTyHP4L8nwQ4moMJr6zbfbWxxb5TC7KVZSQ9UKZZ+ZLuy/pkU\n"
    "Qe4G8XSE0r+R9u4JCg87I1vgHhn8WJSxVX027OVUq5HfOzg2skQBTcExph5V9B2b\n"
    "onNxd8UCgYEA/32PW+ZwRcdKXMj+QVkxXUd6xkXy7mTXPEaQuOLWZQgrSqAFH1l4\n"
    "5/6d099KAJrjM6kR8pKXtz72IIyMHTPm332ghymjKvaEl2XP9sF+f6FmYURar4y6\n"
    "8Zh3eivP86+Q/YzOGKwtRSziBMzrAfoIXgtwH8pwIPYLP3zBV4449ZsCgYEA0XC/\n"
    "gu2ub5M6EXBnjq9K2d4LlTyAPsIbAcMSwkhOUH4YJFS22qXLYQUA9zM+DUyLCrl/\n"
    "PKN2G0HQVgMb4DIbeHv8kXB5oGm5zfbWorWqOomXB3AsI7X8YDMtf/PsZV2amBei\n"
    "qVskmPJQV21qFyeOcHlT+dHuRb0O0un3dK8RHmsCgYEApDCH4dJ80osZoflVVJ/C\n"
    "VqTqJOOtFEFgBQ+AUCEPEQyn7aRaxmPUjJsXyKJVx3/ChV+g9hf5Qj1HJXHNVbMW\n"
    "KwhsEpDSmHimizlV5clBxzntNpMcCHdTaJHILo5bbMqmThugE0ELMsp+UgFzAeky\n"
    "WWXWX8fUOYqFff5prh/rQQMCgYBQQ8FhT+113Rp37HgDerJY5HvT6afMZV8sQbJC\n"
    "uqsotepSohShnsBeoihIlF7HgfoXVhepCYwNzh8ll3NrbEiS2BFnO4+hJmOKx3pi\n"
    "SPTAElLLCvYfiXL6+yII01ZZUpIYj5ZLCR7xbovTtZ7e2M4B1L2WFBoYp+eydO/c\n"
    "y+rnmQKBgCh0gfyBT/OKPkfKv+Bbt8HcoxgEj+TyH+vYdeTbP9ZSJ6y5utMbPg7z\n"
    "iLLbJ+9IcSwPCwJSmI+I0Om4xEp4ZblCrzAG7hWvG2NNzxQjmoOOrAANyTvJR/ap\n"
    "N+UkQA4WrMSKEYyBlRS/hR9Unz31vMc2k9Re0ukWhWh/QksQGDfJ\n"
    "-----END RSA PRIVATE KEY-----\n"
).encode("ascii")

DEFAULT_ROOT_EC_P256_PEM = (
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEINeY1S+DASQ701QrflXtTHRhGQCw+VBagk/h6OwGO8/xoAoGCCqGSM49\n"
    "AwEHoUQDQgAEKstAPOj+7VukSZWhqR2u6Nu+GTfNFPsvJFc35ZU5iNmUudZa69fN\n"
    "1TCK1v5IskpqgQ7l8H2LaDTMOmr8U476wQ==\n"
    "-----END EC PRIVATE KEY-----\n"
).encode("ascii")


@dataclass(frozen=True)
class AllowlistSpec:
    category: str  # "unsigned", "padded", "corrupted"
    reason: str
    erased_size: int | None = None
    unsigned_only: bool = False
    prefix_ff_bytes: int = 0
    unpadded_img_size: int | None = None
    corrupt_offset: int | None = None
    corrupt_byte: int | None = None
    restored_byte: int | None = None


@dataclass(frozen=True)
class ImageProvenanceSpec:
    family: str
    expected_key: str | None
    expected_header_size: int | None
    align: int | None
    slot_size: int | None
    build_source: str


PROVENANCE_SPECS: dict[str, ImageProvenanceSpec] = {
    "erased_slot_0x76000.bin": ImageProvenanceSpec(
        family="erased_slot",
        expected_key=None,
        expected_header_size=None,
        align=None,
        slot_size=0x76000,
        build_source="profiles/mcuboot_pr2199_move_broken.yaml:24 (0x76000 bytes of 0xFF)",
    ),
    "zephyr_head_move_nrf52_seccounter_v1.bin": ImageProvenanceSpec(
        family="head_move_nrf52_seccounter",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:1172-1179",
    ),
    "zephyr_head_move_nrf52_seccounter_v2.bin": ImageProvenanceSpec(
        family="head_move_nrf52_seccounter",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:1182-1189",
    ),
    "zephyr_head_move_nrf52_slot0.bin": ImageProvenanceSpec(
        family="head_move_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/build_mcuboot_head_matrix.sh:584",
    ),
    "zephyr_head_move_nrf52_slot1.bin": ImageProvenanceSpec(
        family="head_move_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/build_mcuboot_head_matrix.sh:585",
    ),
    "zephyr_head_move_nrf52_slot1_verify_corrupt.bin": ImageProvenanceSpec(
        family="head_move_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/build_mcuboot_head_matrix.sh:585 + 1-byte corruption at 0x7c00",
    ),
    "zephyr_head_move_small_slot0.bin": ImageProvenanceSpec(
        family="head_move_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:628",
    ),
    "zephyr_head_move_small_slot1.bin": ImageProvenanceSpec(
        family="head_move_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:629",
    ),
    "zephyr_head_move_stm32f4_slot0.bin": ImageProvenanceSpec(
        family="head_move_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/build_mcuboot_head_matrix.sh:602",
    ),
    "zephyr_head_move_stm32f4_slot1.bin": ImageProvenanceSpec(
        family="head_move_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/build_mcuboot_head_matrix.sh:603",
    ),
    "zephyr_head_offset_nrf52_slot0.bin": ImageProvenanceSpec(
        family="head_offset_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/build_mcuboot_head_matrix.sh:646",
    ),
    "zephyr_head_offset_nrf52_slot1.bin": ImageProvenanceSpec(
        family="head_offset_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/build_mcuboot_head_matrix.sh:647",
    ),
    "zephyr_head_offset_small_slot0.bin": ImageProvenanceSpec(
        family="head_offset_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:667",
    ),
    "zephyr_head_offset_small_slot1.bin": ImageProvenanceSpec(
        family="head_offset_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:668",
    ),
    "zephyr_head_offset_stm32f4_slot0.bin": ImageProvenanceSpec(
        family="head_offset_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/build_mcuboot_head_matrix.sh:655",
    ),
    "zephyr_head_offset_stm32f4_slot1.bin": ImageProvenanceSpec(
        family="head_offset_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/build_mcuboot_head_matrix.sh:656",
    ),
    "zephyr_head_offset_stm32f4_slot1_offsetslot.bin": ImageProvenanceSpec(
        family="head_offset_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/build_mcuboot_head_matrix.sh:657-660",
    ),
    "zephyr_head_scratch_nrf52_slot0.bin": ImageProvenanceSpec(
        family="head_scratch_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x6E000,
        build_source="scripts/build_mcuboot_head_matrix.sh:593",
    ),
    "zephyr_head_scratch_nrf52_slot1.bin": ImageProvenanceSpec(
        family="head_scratch_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x6E000,
        build_source="scripts/build_mcuboot_head_matrix.sh:594",
    ),
    "zephyr_head_scratch_small_slot0.bin": ImageProvenanceSpec(
        family="head_scratch_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:637",
    ),
    "zephyr_head_scratch_small_slot1.bin": ImageProvenanceSpec(
        family="head_scratch_small",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x20000,
        build_source="scripts/build_mcuboot_head_matrix.sh:638",
    ),
    "zephyr_head_scratch_stm32f4_mirrored_slot0.bin": ImageProvenanceSpec(
        family="head_scratch_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x38000,
        build_source="scripts/build_mcuboot_head_matrix.sh:612",
    ),
    "zephyr_head_scratch_stm32f4_mirrored_slot1.bin": ImageProvenanceSpec(
        family="head_scratch_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x38000,
        build_source="scripts/build_mcuboot_head_matrix.sh:613",
    ),
    "zephyr_head_scratch_stm32f4_pr2206_slot0.bin": ImageProvenanceSpec(
        family="head_scratch_stm32f4_pr2206",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=32,
        slot_size=0x18000,
        build_source="scripts/build_mcuboot_head_matrix.sh:619; scripts/bootstrap_mcuboot_matrix_assets.sh:740-742",
    ),
    "zephyr_head_scratch_stm32f4_pr2206_slot1.bin": ImageProvenanceSpec(
        family="head_scratch_stm32f4_pr2206",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=32,
        slot_size=0x18000,
        build_source="scripts/build_mcuboot_head_matrix.sh:620; scripts/bootstrap_mcuboot_matrix_assets.sh:743-745",
    ),
    "zephyr_slot0_padded.bin": ImageProvenanceSpec(
        family="pr_differential_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x6E000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:734-736",
    ),
    "zephyr_slot1_large.bin": ImageProvenanceSpec(
        family="pr_differential_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x6E000,
        build_source="profiles/mcuboot_pr2109_scratch_broken.yaml:26 (commit 4295e59)",
    ),
    "zephyr_slot1_max.bin": ImageProvenanceSpec(
        family="pr_differential_geom",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x76000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:778,783-785",
    ),
    "zephyr_slot1_offset_geom_full.bin": ImageProvenanceSpec(
        family="pr_differential_geom",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=32,
        slot_size=0x18000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:918-925",
    ),
    "zephyr_slot1_offset_geom_full_offsetslot.bin": ImageProvenanceSpec(
        family="pr_differential_geom",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=32,
        slot_size=0x18000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:926-929",
    ),
    "zephyr_slot1_padded.bin": ImageProvenanceSpec(
        family="pr_differential_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x6E000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:737-739",
    ),
    "zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin": ImageProvenanceSpec(
        family="pr2214_offset_nrf52",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=4,
        slot_size=0x76000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:697-709",
    ),
    "zephyr_stm32f4_slot0.bin": ImageProvenanceSpec(
        family="legacy_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:743-745",
    ),
    "zephyr_stm32f4_slot1.bin": ImageProvenanceSpec(
        family="legacy_stm32f4",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=0x60000,
        build_source="scripts/bootstrap_mcuboot_matrix_assets.sh:746-748",
    ),
}

ALLOWLIST: dict[str, AllowlistSpec] = {
    "erased_slot_0x76000.bin": AllowlistSpec(
        category="unsigned",
        reason=(
            "0x76000 bytes of 0xFF representing an erased secondary slot for "
            "mcuboot_pr2199_move_broken and mcuboot_pr2199_move_fixed stuck-revert profiles"
        ),
        erased_size=0x76000,
    ),
    "zephyr_head_offset_stm32f4_slot1_offsetslot.bin": AllowlistSpec(
        category="padded",
        reason=(
            "Prepended with 0x20000 bytes of 0xFF (one STM32F4 erase sector) by make_offset_slot_image "
            "in scripts/build_mcuboot_head_matrix.sh:657-660 for MCUBOOT_SWAP_USING_OFFSET secondary-slot "
            "staging; embedded image at 0x20000 verifies against root-rsa-2048.pem"
        ),
        prefix_ff_bytes=0x20000,
    ),
    "zephyr_slot1_offset_geom_full_offsetslot.bin": AllowlistSpec(
        category="padded",
        reason=(
            "Prepended with 0x4000 bytes of 0xFF (one STM32F4 16 KiB erase sector) by make_offset_slot_image in "
            "scripts/bootstrap_mcuboot_matrix_assets.sh:926-929 for "
            "mcuboot_pr2214_offset_geom_{broken,fixed} secondary-slot staging; "
            "embedded image at 0x4000 verifies against root-rsa-2048.pem"
        ),
        prefix_ff_bytes=0x4000,
    ),
    "zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin": AllowlistSpec(
        category="padded",
        reason=(
            "Prepended with 0x1000 bytes of 0xFF (one nRF52840 erase sector) by make_offset_slot_image "
            "in scripts/bootstrap_mcuboot_matrix_assets.sh:706-709 for "
            "mcuboot_pr2214_offset_{broken,fixed} secondary-slot staging; "
            "embedded image at 0x1000 verifies against root-rsa-2048.pem"
        ),
        prefix_ff_bytes=0x1000,
    ),
    "zephyr_slot1_large.bin": AllowlistSpec(
        category="padded",
        reason=(
            "Payload zero-padded from 0x4a78 to 0x8a78 bytes (+0x4000 zeros) with SHA-256 TLV recomputed "
            "after signing with root-rsa-2048.pem so mcuboot_pr2109_scratch_{broken,fixed} have "
            "different-sized images (slot0=19KB, slot1=36KB) as required by the profile description; "
            "pre-pad 0x4a78 payload verifies against root-rsa-2048.pem"
        ),
        unpadded_img_size=0x4A78,
    ),
    "zephyr_head_move_nrf52_slot1_verify_corrupt.bin": AllowlistSpec(
        category="corrupted",
        reason=(
            "Payload byte at offset 0x7c00 flipped from 0x00 to 0x01 after signing with root-rsa-2048.pem "
            "to produce a deliberately corrupted staging image for "
            "mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_{candidates,critical,full}; "
            "restoring byte 0x7c00 to 0x00 matches the stored SHA-256 TLV and root-rsa-2048.pem signature"
        ),
        corrupt_offset=0x7C00,
        corrupt_byte=0x01,
        restored_byte=0x00,
    ),
}


@dataclass(frozen=True)
class TlvEntry:
    protected: bool
    tlv_type: int
    value: bytes


@dataclass(frozen=True)
class ParsedMcubootImage:
    slot_offset: int
    magic: int
    load_addr: int
    header_size: int
    protected_tlv_size: int
    image_size: int
    flags: int
    version: str
    security_counter: int | None
    tlvs: tuple[TlvEntry, ...]
    signed_bytes: bytes
    computed_sha256: bytes
    sha256_tlv: bytes | None
    keyhash_tlv: bytes | None
    signature_tlv_type: int | None
    signature_tlv: bytes | None
    trailing_bytes: int


@dataclass(frozen=True)
class ImageCheckResult:
    image_path: Path
    status: str  # "ok", "allowlisted", "failed"
    family: str
    expected_key: str | None
    build_source: str
    slot_offset: int
    magic: int | None
    load_addr: int | None
    header_size: int | None
    protected_tlv_size: int | None
    image_size: int | None
    flags: int | None
    version: str | None
    security_counter: int | None
    sha256_tlv: bytes | None
    computed_sha256: bytes | None
    hash_matches: bool | None
    keyhash_tlv: bytes | None
    signature_type: str | None
    signature_verified: bool | None
    verifier_backend: str | None
    allowlist_category: str | None
    allowlist_reason: str | None
    message: str

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "allowlisted")


def _read_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated ASN.1 DER header")
    tag = data[offset]
    first = data[offset + 1]
    offset += 2
    if first < 0x80:
        length = first
    else:
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("invalid ASN.1 DER length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    if offset + length > len(data):
        raise ValueError("truncated ASN.1 DER value")
    return tag, data[offset : offset + length], offset + length


def _encode_der_tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        len_bytes = bytes([length])
    else:
        raw_len = length.to_bytes((length.bit_length() + 7) // 8, "big")
        len_bytes = bytes([0x80 | len(raw_len)]) + raw_len
    return bytes([tag]) + len_bytes + value


def _parse_pem_der(pem_bytes: bytes) -> bytes:
    b64_lines = [
        line.strip()
        for line in pem_bytes.decode("ascii").splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    return base64.b64decode("".join(b64_lines))


def _parse_rsa_private_key_pem(pem_bytes: bytes) -> tuple[int, int, bytes]:
    der = _parse_pem_der(pem_bytes)
    tag, seq_val, _ = _read_der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected ASN.1 SEQUENCE in RSA private key")
    _, _, pos = _read_der_tlv(seq_val, 0)  # version
    tag_n, n_bytes, pos = _read_der_tlv(seq_val, pos)
    tag_e, e_bytes, _ = _read_der_tlv(seq_val, pos)
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    pkcs1_pub_der = _encode_der_tlv(
        0x30,
        _encode_der_tlv(tag_n, n_bytes) + _encode_der_tlv(tag_e, e_bytes),
    )
    keyhash = hashlib.sha256(pkcs1_pub_der).digest()
    return n, e, keyhash


def _parse_ec_p256_private_key_pem(pem_bytes: bytes) -> tuple[int, int, bytes]:
    der = _parse_pem_der(pem_bytes)
    tag, seq_val, _ = _read_der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected ASN.1 SEQUENCE in EC private key")
    pos = 0
    pub_bitstring: bytes | None = None
    while pos < len(seq_val):
        t, v, pos = _read_der_tlv(seq_val, pos)
        if t == 0xA1:
            _, pub_bitstring, _ = _read_der_tlv(v, 0)
            break
    if pub_bitstring is None or len(pub_bitstring) != 66 or pub_bitstring[:2] != b"\x00\x04":
        raise ValueError("missing or invalid uncompressed P-256 public point in EC key")
    x = int.from_bytes(pub_bitstring[2:34], "big")
    y = int.from_bytes(pub_bitstring[34:66], "big")
    alg_id = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    spki_der = _encode_der_tlv(0x30, alg_id + _encode_der_tlv(0x03, pub_bitstring))
    keyhash = hashlib.sha256(spki_der).digest()
    return x, y, keyhash


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def _verify_rsa_pss_stdlib(n: int, e: int, message: bytes, signature: bytes) -> bool:
    mod_bits = n.bit_length()
    em_len = (mod_bits + 7) // 8
    if len(signature) != em_len:
        return False
    s_int = int.from_bytes(signature, "big")
    if s_int <= 0 or s_int >= n:
        return False
    em = pow(s_int, e, n).to_bytes(em_len, "big")
    if em[-1] != 0xBC:
        return False
    h_len = 32
    masked_db_len = em_len - h_len - 1
    masked_db = em[:masked_db_len]
    h = em[masked_db_len : masked_db_len + h_len]
    top_bits = 8 * em_len - (mod_bits - 1)
    if masked_db[0] >> (8 - top_bits) != 0:
        return False
    db_mask = _mgf1_sha256(h, masked_db_len)
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))
    db[0] &= 0xFF >> top_bits
    zero_idx = 0
    while zero_idx < len(db) and db[zero_idx] == 0:
        zero_idx += 1
    if zero_idx >= len(db) or db[zero_idx] != 0x01:
        return False
    salt = bytes(db[zero_idx + 1 :])
    m_hash = hashlib.sha256(message).digest()
    h_prime = hashlib.sha256((b"\x00" * 8) + m_hash + salt).digest()
    return h == h_prime


# NIST P-256 curve parameters for stdlib ECDSA verification.
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p256_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return x3, y3


def _p256_mul(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k > 0:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return result


def _verify_ecdsa_p256_stdlib(qx: int, qy: int, message: bytes, signature: bytes) -> bool:
    try:
        tag, seq_val, end = _read_der_tlv(signature, 0)
        if tag != 0x30:
            return False
        tag_r, r_bytes, pos = _read_der_tlv(seq_val, 0)
        tag_s, s_bytes, pos = _read_der_tlv(seq_val, pos)
        if tag_r != 0x02 or tag_s != 0x02:
            return False
        r = int.from_bytes(r_bytes, "big")
        s = int.from_bytes(s_bytes, "big")
    except ValueError:
        return False
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _P256_N)
    u1 = (z * w) % _P256_N
    u2 = (r * w) % _P256_N
    pt = _p256_add(_p256_mul(u1, (_P256_GX, _P256_GY)), _p256_mul(u2, (qx, qy)))
    if pt is None:
        return False
    return (pt[0] % _P256_N) == r


def load_key_bytes(key_name: str, *, repo_root: Path = ROOT) -> bytes:
    mcuboot_key = repo_root / "third_party" / "zephyr_ws" / "bootloader" / "mcuboot" / key_name
    if mcuboot_key.is_file():
        return mcuboot_key.read_bytes()
    if key_name == "root-rsa-2048.pem":
        return DEFAULT_ROOT_RSA_2048_PEM
    if key_name == "root-ec-p256.pem":
        return DEFAULT_ROOT_EC_P256_PEM
    raise FileNotFoundError(f"unknown key {key_name}")


def expected_keyhash_for_key(key_name: str, *, repo_root: Path = ROOT) -> bytes:
    pem_bytes = load_key_bytes(key_name, repo_root=repo_root)
    if "RSA" in key_name.upper():
        _, _, kh = _parse_rsa_private_key_pem(pem_bytes)
        return kh
    if "EC" in key_name.upper():
        _, _, kh = _parse_ec_p256_private_key_pem(pem_bytes)
        return kh
    raise ValueError(f"unsupported key type for {key_name}")


def detect_verifier_backend(requested: str = "auto") -> str:
    if requested != "auto":
        return requested
    venv_bin = Path(sys.executable).resolve().parent
    imgtool_exe = venv_bin / "imgtool"
    if (imgtool_exe.is_file() and os.access(imgtool_exe, os.X_OK)) or (
        importlib.util.find_spec("imgtool") is not None
    ) or (shutil.which("imgtool") is not None):
        return "imgtool"
    if importlib.util.find_spec("cryptography") is not None:
        return "cryptography"
    return "stdlib"


def _verify_with_imgtool(image_bytes: bytes, key_bytes: bytes) -> bool:
    venv_bin = Path(sys.executable).resolve().parent
    imgtool_exe = venv_bin / "imgtool"
    if imgtool_exe.is_file() and os.access(imgtool_exe, os.X_OK):
        cmd_prefix = [str(imgtool_exe)]
    elif importlib.util.find_spec("imgtool") is not None:
        cmd_prefix = [sys.executable, "-m", "imgtool"]
    else:
        which_imgtool = shutil.which("imgtool")
        if which_imgtool is None:
            raise RuntimeError("imgtool is not available in the active environment")
        cmd_prefix = [which_imgtool]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        key_file = tmp_dir / "key.pem"
        img_file = tmp_dir / "image.bin"
        key_file.write_bytes(key_bytes)
        img_file.write_bytes(image_bytes)
        proc = subprocess.run(
            [*cmd_prefix, "verify", "--key", str(key_file), str(img_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0


def _verify_with_cryptography(
    key_bytes: bytes,
    signed_bytes: bytes,
    signature_tlv_type: int,
    signature: bytes,
) -> bool:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    priv = serialization.load_pem_private_key(key_bytes, password=None)
    pub = priv.public_key()
    try:
        if signature_tlv_type in (TLV_RSA2048_PSS, TLV_RSA3072_PSS):
            pub.verify(
                signature,
                signed_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        if signature_tlv_type == TLV_ECDSA_SIG:
            # imgtool sometimes pads DER ECDSA signatures with trailing zero bytes.
            _, seq_val, der_len = _read_der_tlv(signature, 0)
            der_sig = signature[:der_len]
            pub.verify(der_sig, signed_bytes, ec.ECDSA(hashes.SHA256()))
            return True
    except Exception:
        return False
    return False


def _verify_with_stdlib(
    key_bytes: bytes,
    signed_bytes: bytes,
    signature_tlv_type: int,
    signature: bytes,
) -> bool:
    if signature_tlv_type == TLV_RSA2048_PSS:
        n, e, _ = _parse_rsa_private_key_pem(key_bytes)
        return _verify_rsa_pss_stdlib(n, e, signed_bytes, signature)
    if signature_tlv_type == TLV_ECDSA_SIG:
        qx, qy, _ = _parse_ec_p256_private_key_pem(key_bytes)
        return _verify_ecdsa_p256_stdlib(qx, qy, signed_bytes, signature)
    return False


def verify_signature(
    *,
    full_image_bytes: bytes,
    signed_bytes: bytes,
    signature_tlv_type: int,
    signature: bytes,
    key_name: str,
    repo_root: Path = ROOT,
    verifier: str = "auto",
) -> tuple[bool, str]:
    backend = detect_verifier_backend(verifier)
    key_bytes = load_key_bytes(key_name, repo_root=repo_root)
    if backend == "imgtool":
        ok = _verify_with_imgtool(full_image_bytes, key_bytes)
        return ok, "imgtool"
    if backend == "cryptography":
        ok = _verify_with_cryptography(key_bytes, signed_bytes, signature_tlv_type, signature)
        return ok, "cryptography"
    if backend == "stdlib":
        ok = _verify_with_stdlib(key_bytes, signed_bytes, signature_tlv_type, signature)
        return ok, "stdlib"
    raise ValueError(f"unknown verifier backend: {verifier!r}")


def parse_mcuboot_image(raw: bytes, *, slot_offset: int = 0) -> ParsedMcubootImage:
    if slot_offset < 0 or slot_offset > len(raw):
        raise ValueError(f"invalid slot_offset 0x{slot_offset:x} for image of size 0x{len(raw):x}")
    body = raw[slot_offset:]
    if len(body) < IMAGE_HEADER_STRUCT.size:
        raise ValueError(f"image body too short ({len(body)} bytes) for MCUboot header")

    (
        magic,
        load_addr,
        hdr_size,
        prot_tlv_size,
        img_size,
        flags,
        ver_major,
        ver_minor,
        ver_rev,
        ver_build,
    ) = IMAGE_HEADER_STRUCT.unpack_from(body, 0)

    if magic != IMAGE_MAGIC:
        raise ValueError(f"invalid MCUboot header magic 0x{magic:08x} (expected 0x{IMAGE_MAGIC:08x})")

    version = f"{ver_major}.{ver_minor}.{ver_rev}+{ver_build}"
    signed_end = hdr_size + img_size + prot_tlv_size
    if signed_end > len(body):
        raise ValueError(
            f"header+image+prot_tlv (0x{signed_end:x}) exceeds image body length (0x{len(body):x})"
        )

    tlvs: list[TlvEntry] = []
    pos = hdr_size + img_size
    if prot_tlv_size > 0:
        if pos + TLV_INFO_STRUCT.size > len(body):
            raise ValueError("truncated protected TLV info header")
        prot_magic, prot_total = TLV_INFO_STRUCT.unpack_from(body, pos)
        if prot_magic != TLV_PROT_INFO_MAGIC:
            raise ValueError(
                f"invalid protected TLV magic 0x{prot_magic:04x} (expected 0x{TLV_PROT_INFO_MAGIC:04x})"
            )
        if prot_total != prot_tlv_size:
            raise ValueError(
                f"protected TLV total 0x{prot_total:x} != ih_protect_tlv_size 0x{prot_tlv_size:x}"
            )
        cur = pos + TLV_INFO_STRUCT.size
        prot_end = pos + prot_total
        while cur < prot_end:
            if cur + TLV_ENTRY_STRUCT.size > prot_end:
                raise ValueError("truncated protected TLV entry header")
            tlv_type, tlv_len = TLV_ENTRY_STRUCT.unpack_from(body, cur)
            cur += TLV_ENTRY_STRUCT.size
            if cur + tlv_len > prot_end:
                raise ValueError("truncated protected TLV entry value")
            tlvs.append(TlvEntry(protected=True, tlv_type=tlv_type, value=body[cur : cur + tlv_len]))
            cur += tlv_len
        pos = prot_end

    if pos + TLV_INFO_STRUCT.size > len(body):
        raise ValueError("missing unprotected TLV info header")
    unprot_magic, unprot_total = TLV_INFO_STRUCT.unpack_from(body, pos)
    if unprot_magic != TLV_INFO_MAGIC:
        raise ValueError(
            f"invalid unprotected TLV magic 0x{unprot_magic:04x} (expected 0x{TLV_INFO_MAGIC:04x})"
        )
    unprot_end = pos + unprot_total
    if unprot_end > len(body):
        raise ValueError(
            f"unprotected TLV area end 0x{unprot_end:x} exceeds image body length 0x{len(body):x}"
        )
    cur = pos + TLV_INFO_STRUCT.size
    while cur < unprot_end:
        if cur + TLV_ENTRY_STRUCT.size > unprot_end:
            raise ValueError("truncated unprotected TLV entry header")
        tlv_type, tlv_len = TLV_ENTRY_STRUCT.unpack_from(body, cur)
        cur += TLV_ENTRY_STRUCT.size
        if cur + tlv_len > unprot_end:
            raise ValueError("truncated unprotected TLV entry value")
        tlvs.append(TlvEntry(protected=False, tlv_type=tlv_type, value=body[cur : cur + tlv_len]))
        cur += tlv_len

    signed_bytes = body[:signed_end]
    computed_sha256 = hashlib.sha256(signed_bytes).digest()

    sha256_tlv: bytes | None = None
    keyhash_tlv: bytes | None = None
    sig_tlv_type: int | None = None
    sig_tlv: bytes | None = None
    sec_cnt: int | None = None

    for entry in tlvs:
        if entry.tlv_type == TLV_SHA256:
            sha256_tlv = entry.value
        elif entry.tlv_type == TLV_KEYHASH:
            keyhash_tlv = entry.value
        elif entry.tlv_type in SIGNATURE_TLV_NAMES:
            sig_tlv_type = entry.tlv_type
            sig_tlv = entry.value
        elif entry.tlv_type == TLV_SEC_CNT and len(entry.value) == 4:
            sec_cnt = int.from_bytes(entry.value, "little")

    return ParsedMcubootImage(
        slot_offset=slot_offset,
        magic=magic,
        load_addr=load_addr,
        header_size=hdr_size,
        protected_tlv_size=prot_tlv_size,
        image_size=img_size,
        flags=flags,
        version=version,
        security_counter=sec_cnt,
        tlvs=tuple(tlvs),
        signed_bytes=signed_bytes,
        computed_sha256=computed_sha256,
        sha256_tlv=sha256_tlv,
        keyhash_tlv=keyhash_tlv,
        signature_tlv_type=sig_tlv_type,
        signature_tlv=sig_tlv,
        trailing_bytes=len(body) - unprot_end,
    )


def infer_provenance_spec(image_path: Path) -> ImageProvenanceSpec:
    if image_path.name in PROVENANCE_SPECS:
        return PROVENANCE_SPECS[image_path.name]
    return ImageProvenanceSpec(
        family="custom",
        expected_key="root-rsa-2048.pem",
        expected_header_size=0x200,
        align=8,
        slot_size=None,
        build_source="custom",
    )


def check_image(
    image_path: Path,
    *,
    repo_root: Path = ROOT,
    verifier: str = "auto",
    allowlist: dict[str, AllowlistSpec] | None = None,
) -> ImageCheckResult:
    active_allowlist = ALLOWLIST if allowlist is None else allowlist
    try:
        rel_label = str(image_path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        rel_label = str(image_path)

    spec = infer_provenance_spec(image_path)
    allow = active_allowlist.get(image_path.name)

    if not image_path.is_file():
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=0,
            magic=None,
            load_addr=None,
            header_size=None,
            protected_tlv_size=None,
            image_size=None,
            flags=None,
            version=None,
            security_counter=None,
            sha256_tlv=None,
            computed_sha256=None,
            hash_matches=None,
            keyhash_tlv=None,
            signature_type=None,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=None,
            allowlist_reason=None,
            message=f"{rel_label}: failed (missing image file)",
        )

    raw = image_path.read_bytes()

    # Case 1: allowlisted erased slot image (all 0xFF).
    if allow is not None and allow.erased_size is not None:
        if len(raw) == allow.erased_size and raw == (b"\xff" * allow.erased_size):
            return ImageCheckResult(
                image_path=image_path,
                status="allowlisted",
                family=spec.family,
                expected_key=None,
                build_source=spec.build_source,
                slot_offset=0,
                magic=None,
                load_addr=None,
                header_size=None,
                protected_tlv_size=None,
                image_size=None,
                flags=None,
                version=None,
                security_counter=None,
                sha256_tlv=None,
                computed_sha256=None,
                hash_matches=None,
                keyhash_tlv=None,
                signature_type=None,
                signature_verified=None,
                verifier_backend=None,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=f"{rel_label}: allowlisted ({allow.category}: {allow.reason})",
            )
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=None,
            build_source=spec.build_source,
            slot_offset=0,
            magic=None,
            load_addr=None,
            header_size=None,
            protected_tlv_size=None,
            image_size=None,
            flags=None,
            version=None,
            security_counter=None,
            sha256_tlv=None,
            computed_sha256=None,
            hash_matches=None,
            keyhash_tlv=None,
            signature_type=None,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=allow.category,
            allowlist_reason=allow.reason,
            message=f"{rel_label}: failed (expected 0x{allow.erased_size:x} bytes of 0xFF)",
        )

    slot_offset = allow.prefix_ff_bytes if allow is not None else 0
    if slot_offset > 0:
        if len(raw) <= slot_offset or raw[:slot_offset] != (b"\xff" * slot_offset):
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=spec.expected_key,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=None,
                load_addr=None,
                header_size=None,
                protected_tlv_size=None,
                image_size=None,
                flags=None,
                version=None,
                security_counter=None,
                sha256_tlv=None,
                computed_sha256=None,
                hash_matches=None,
                keyhash_tlv=None,
                signature_type=None,
                signature_verified=None,
                verifier_backend=None,
                allowlist_category=allow.category if allow else None,
                allowlist_reason=allow.reason if allow else None,
                message=f"{rel_label}: failed (missing expected 0x{slot_offset:x} bytes of leading 0xFF padding)",
            )

    try:
        parsed = parse_mcuboot_image(raw, slot_offset=slot_offset)
    except ValueError as exc:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=None,
            load_addr=None,
            header_size=None,
            protected_tlv_size=None,
            image_size=None,
            flags=None,
            version=None,
            security_counter=None,
            sha256_tlv=None,
            computed_sha256=None,
            hash_matches=None,
            keyhash_tlv=None,
            signature_type=None,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=f"{rel_label}: failed ({exc})",
        )

    sig_type_name = (
        SIGNATURE_TLV_NAMES.get(parsed.signature_tlv_type)
        if parsed.signature_tlv_type is not None
        else None
    )

    if spec.expected_header_size is not None and parsed.header_size != spec.expected_header_size:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=None,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=(
                f"{rel_label}: failed (header size 0x{parsed.header_size:x} != "
                f"expected 0x{spec.expected_header_size:x})"
            ),
        )

    if parsed.sha256_tlv is None:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=None,
            computed_sha256=parsed.computed_sha256,
            hash_matches=False,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=f"{rel_label}: failed (missing SHA256 TLV 0x10)",
        )

    hash_matches = parsed.sha256_tlv == parsed.computed_sha256

    # Case 2: allowlisted unsigned image (SHA-256 TLV only, no signature TLV).
    if allow is not None and allow.unsigned_only:
        if not hash_matches:
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=None,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=False,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=None,
                verifier_backend=None,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=(
                    f"{rel_label}: failed (SHA-256 mismatch on unsigned image: "
                    f"tlv={parsed.sha256_tlv.hex()} computed={parsed.computed_sha256.hex()})"
                ),
            )
        if parsed.signature_tlv is not None:
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=None,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=True,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=None,
                verifier_backend=None,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=f"{rel_label}: failed (unexpected signature TLV on unsigned allowlist entry)",
            )
        return ImageCheckResult(
            image_path=image_path,
            status="allowlisted",
            family=spec.family,
            expected_key=None,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=True,
            keyhash_tlv=None,
            signature_type=None,
            signature_verified=None,
            verifier_backend=None,
            allowlist_category=allow.category,
            allowlist_reason=allow.reason,
            message=(
                f"{rel_label}: allowlisted ({allow.category}: {allow.reason}; "
                f"hdr=0x{parsed.header_size:x} img=0x{parsed.image_size:x} "
                f"ver={parsed.version} sha256={parsed.computed_sha256.hex()[:16]})"
            ),
        )

    # All remaining images require a signature TLV and an expected key.
    if spec.expected_key is None or parsed.signature_tlv is None or parsed.signature_tlv_type is None:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=hash_matches,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=False,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=f"{rel_label}: failed (missing signature TLV for key {spec.expected_key})",
        )

    expected_kh = expected_keyhash_for_key(spec.expected_key, repo_root=repo_root)
    if parsed.keyhash_tlv is not None and parsed.keyhash_tlv != expected_kh:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=hash_matches,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=False,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=(
                f"{rel_label}: failed (KEYHASH TLV {parsed.keyhash_tlv.hex()} != "
                f"expected {expected_kh.hex()} for {spec.expected_key})"
            ),
        )

    # Case 3: allowlisted post-sign zero-padded image (zephyr_slot1_large.bin).
    if allow is not None and allow.unpadded_img_size is not None:
        unpadded_sz = allow.unpadded_img_size
        pad_start = parsed.header_size + unpadded_sz
        pad_end = parsed.header_size + parsed.image_size
        body = raw[slot_offset:]
        pad_region = body[pad_start:pad_end]
        if not hash_matches or unpadded_sz >= parsed.image_size or any(pad_region):
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=spec.expected_key,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=hash_matches,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=False,
                verifier_backend=None,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=f"{rel_label}: failed (invalid post-sign zero pad or SHA-256 mismatch)",
            )
        reconstructed_hdr = bytearray(body[: parsed.header_size])
        struct.pack_into("<I", reconstructed_hdr, 12, unpadded_sz)
        reconstructed_signed = bytes(reconstructed_hdr) + body[parsed.header_size : pad_start]
        # Reconstruct unpadded image with original SHA-256 TLV for imgtool verify compatibility.
        unpadded_sha = hashlib.sha256(reconstructed_signed).digest()
        tlv_blob = bytearray(body[pad_end:])
        sha_idx = tlv_blob.find(parsed.sha256_tlv)
        if sha_idx != -1:
            tlv_blob[sha_idx : sha_idx + 32] = unpadded_sha
        reconstructed_full = reconstructed_signed + bytes(tlv_blob)
        sig_ok, backend = verify_signature(
            full_image_bytes=reconstructed_full,
            signed_bytes=reconstructed_signed,
            signature_tlv_type=parsed.signature_tlv_type,
            signature=parsed.signature_tlv,
            key_name=spec.expected_key,
            repo_root=repo_root,
            verifier=verifier,
        )
        if not sig_ok:
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=spec.expected_key,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=hash_matches,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=False,
                verifier_backend=backend,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=f"{rel_label}: failed (pre-pad 0x{unpadded_sz:x} signature verification failed)",
            )
        return ImageCheckResult(
            image_path=image_path,
            status="allowlisted",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=True,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=True,
            verifier_backend=backend,
            allowlist_category=allow.category,
            allowlist_reason=allow.reason,
            message=(
                f"{rel_label}: allowlisted ({allow.category}: {allow.reason}; "
                f"hdr=0x{parsed.header_size:x} img=0x{parsed.image_size:x} "
                f"ver={parsed.version} key={spec.expected_key} via={backend})"
            ),
        )

    # Case 4: allowlisted deliberately corrupted image (zephyr_head_move_nrf52_slot1_verify_corrupt.bin).
    if (
        allow is not None
        and allow.corrupt_offset is not None
        and allow.corrupt_byte is not None
        and allow.restored_byte is not None
    ):
        body = bytearray(raw[slot_offset:])
        if (
            hash_matches
            or allow.corrupt_offset >= len( parsed.signed_bytes )
            or body[allow.corrupt_offset] != allow.corrupt_byte
        ):
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=spec.expected_key,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=hash_matches,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=False,
                verifier_backend=None,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=(
                    f"{rel_label}: failed (expected deliberate corruption byte "
                    f"0x{allow.corrupt_byte:02x} at 0x{allow.corrupt_offset:x})"
                ),
            )
        body[allow.corrupt_offset] = allow.restored_byte
        restored_signed = bytes(body[: len(parsed.signed_bytes)])
        restored_sha = hashlib.sha256(restored_signed).digest()
        sig_ok, backend = verify_signature(
            full_image_bytes=bytes(body),
            signed_bytes=restored_signed,
            signature_tlv_type=parsed.signature_tlv_type,
            signature=parsed.signature_tlv,
            key_name=spec.expected_key,
            repo_root=repo_root,
            verifier=verifier,
        )
        if restored_sha != parsed.sha256_tlv or not sig_ok:
            return ImageCheckResult(
                image_path=image_path,
                status="failed",
                family=spec.family,
                expected_key=spec.expected_key,
                build_source=spec.build_source,
                slot_offset=slot_offset,
                magic=parsed.magic,
                load_addr=parsed.load_addr,
                header_size=parsed.header_size,
                protected_tlv_size=parsed.protected_tlv_size,
                image_size=parsed.image_size,
                flags=parsed.flags,
                version=parsed.version,
                security_counter=parsed.security_counter,
                sha256_tlv=parsed.sha256_tlv,
                computed_sha256=parsed.computed_sha256,
                hash_matches=False,
                keyhash_tlv=parsed.keyhash_tlv,
                signature_type=sig_type_name,
                signature_verified=False,
                verifier_backend=backend,
                allowlist_category=allow.category,
                allowlist_reason=allow.reason,
                message=(
                    f"{rel_label}: failed (restoring byte 0x{allow.corrupt_offset:x} did not "
                    f"reproduce SHA-256 TLV and valid {spec.expected_key} signature)"
                ),
            )
        return ImageCheckResult(
            image_path=image_path,
            status="allowlisted",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=False,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=True,
            verifier_backend=backend,
            allowlist_category=allow.category,
            allowlist_reason=allow.reason,
            message=(
                f"{rel_label}: allowlisted ({allow.category}: {allow.reason}; "
                f"hdr=0x{parsed.header_size:x} img=0x{parsed.image_size:x} "
                f"ver={parsed.version} key={spec.expected_key} via={backend})"
            ),
        )

    # Standard signed image (or offset-slot padded image with valid embedded signed image).
    if not hash_matches:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=False,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=False,
            verifier_backend=None,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=(
                f"{rel_label}: failed (SHA-256 mismatch: "
                f"tlv={parsed.sha256_tlv.hex()} computed={parsed.computed_sha256.hex()})"
            ),
        )

    sig_ok, backend = verify_signature(
        full_image_bytes=raw[slot_offset:],
        signed_bytes=parsed.signed_bytes,
        signature_tlv_type=parsed.signature_tlv_type,
        signature=parsed.signature_tlv,
        key_name=spec.expected_key,
        repo_root=repo_root,
        verifier=verifier,
    )
    if not sig_ok:
        return ImageCheckResult(
            image_path=image_path,
            status="failed",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=True,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=False,
            verifier_backend=backend,
            allowlist_category=allow.category if allow else None,
            allowlist_reason=allow.reason if allow else None,
            message=(
                f"{rel_label}: failed ({sig_type_name} signature verification failed "
                f"against {spec.expected_key} via {backend})"
            ),
        )

    if allow is not None:
        return ImageCheckResult(
            image_path=image_path,
            status="allowlisted",
            family=spec.family,
            expected_key=spec.expected_key,
            build_source=spec.build_source,
            slot_offset=slot_offset,
            magic=parsed.magic,
            load_addr=parsed.load_addr,
            header_size=parsed.header_size,
            protected_tlv_size=parsed.protected_tlv_size,
            image_size=parsed.image_size,
            flags=parsed.flags,
            version=parsed.version,
            security_counter=parsed.security_counter,
            sha256_tlv=parsed.sha256_tlv,
            computed_sha256=parsed.computed_sha256,
            hash_matches=True,
            keyhash_tlv=parsed.keyhash_tlv,
            signature_type=sig_type_name,
            signature_verified=True,
            verifier_backend=backend,
            allowlist_category=allow.category,
            allowlist_reason=allow.reason,
            message=(
                f"{rel_label}: allowlisted ({allow.category}: {allow.reason}; "
                f"offset=0x{slot_offset:x} hdr=0x{parsed.header_size:x} "
                f"img=0x{parsed.image_size:x} prot=0x{parsed.protected_tlv_size:x} "
                f"ver={parsed.version} key={spec.expected_key} via={backend})"
            ),
        )

    return ImageCheckResult(
        image_path=image_path,
        status="ok",
        family=spec.family,
        expected_key=spec.expected_key,
        build_source=spec.build_source,
        slot_offset=slot_offset,
        magic=parsed.magic,
        load_addr=parsed.load_addr,
        header_size=parsed.header_size,
        protected_tlv_size=parsed.protected_tlv_size,
        image_size=parsed.image_size,
        flags=parsed.flags,
        version=parsed.version,
        security_counter=parsed.security_counter,
        sha256_tlv=parsed.sha256_tlv,
        computed_sha256=parsed.computed_sha256,
        hash_matches=True,
        keyhash_tlv=parsed.keyhash_tlv,
        signature_type=sig_type_name,
        signature_verified=True,
        verifier_backend=backend,
        allowlist_category=None,
        allowlist_reason=None,
        message=(
            f"{rel_label}: ok (family={spec.family} magic=0x{parsed.magic:08x} "
            f"hdr=0x{parsed.header_size:x} img=0x{parsed.image_size:x} "
            f"prot=0x{parsed.protected_tlv_size:x} flags=0x{parsed.flags:x} "
            f"ver={parsed.version} sig={sig_type_name} key={spec.expected_key} via={backend})"
        ),
    )


def discover_tracked_images(repo_root: Path = ROOT) -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "results/oss_validation/assets/*.bin"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return [
            repo_root / line.strip()
            for line in sorted(proc.stdout.splitlines())
            if line.strip()
        ]
    assets_dir = repo_root / "results" / "oss_validation" / "assets"
    return sorted(assets_dir.glob("*.bin"))


def check_assets(
    image_paths: Iterable[Path] | None = None,
    *,
    repo_root: Path = ROOT,
    verifier: str = "auto",
    allowlist: dict[str, AllowlistSpec] | None = None,
) -> list[ImageCheckResult]:
    paths = list(image_paths) if image_paths is not None else discover_tracked_images(repo_root)
    return [
        check_image(path, repo_root=repo_root, verifier=verifier, allowlist=allowlist)
        for path in paths
    ]


@dataclass(frozen=True)
class ImageVectorInfo:
    image_path: Path
    erased: bool
    slot_offset: int
    header_size: int | None
    image_size: int | None
    vector_offset: int | None
    initial_sp_at_header: int | None
    reset_vector_at_header: int | None
    initial_sp: int | None
    reset_vector: int | None
    linked_slot0_base: int | None


@dataclass(frozen=True)
class ProfileVectorCheckResult:
    profile_path: Path
    elf_path: Path
    elf_slot0_base: int
    elf_slot0_size: int
    profile_exec_base: int
    profile_exec_size: int
    profile_vector_table_offset: int | None
    exec_image: ImageVectorInfo | None
    staging_image: ImageVectorInfo | None
    mismatches: tuple[str, ...]
    message: str

    @property
    def ok(self) -> bool:
        return len(self.mismatches) == 0


def inspect_image_vectors(image_path: Path) -> ImageVectorInfo:
    raw = image_path.read_bytes()
    non_ff = 0
    while non_ff < len(raw) and raw[non_ff] == 0xFF:
        non_ff += 1
    if non_ff == len(raw):
        return ImageVectorInfo(
            image_path=image_path,
            erased=True,
            slot_offset=0,
            header_size=None,
            image_size=None,
            vector_offset=None,
            initial_sp_at_header=None,
            reset_vector_at_header=None,
            initial_sp=None,
            reset_vector=None,
            linked_slot0_base=None,
        )
    parsed = parse_mcuboot_image(raw, slot_offset=non_ff)
    body = raw[non_ff:]
    hdr_sz = parsed.header_size
    sp_hdr, rst_hdr = struct.unpack_from("<II", body, hdr_sz)
    vec_off = hdr_sz
    if sp_hdr == 0 and rst_hdr == 0 and len(body) >= 0x440:
        sp_400, rst_400 = struct.unpack_from("<II", body, 0x400)
        if (sp_400 & 0xFF000000) == 0x20000000 and (rst_400 & 1) == 1:
            vec_off = 0x400
    vecs = struct.unpack_from("<16I", body, vec_off)
    non_zero_vecs = [v & ~1 for v in vecs[1:] if v != 0]
    linked_slot0 = (min(non_zero_vecs) & ~0x3FFF) if non_zero_vecs else None
    return ImageVectorInfo(
        image_path=image_path,
        erased=False,
        slot_offset=non_ff,
        header_size=hdr_sz,
        image_size=parsed.image_size,
        vector_offset=vec_off,
        initial_sp_at_header=sp_hdr,
        reset_vector_at_header=rst_hdr,
        initial_sp=vecs[0],
        reset_vector=vecs[1],
        linked_slot0_base=linked_slot0,
    )


def extract_elf_slot0_partition(elf_path: Path, boot_entry: int) -> tuple[int, int]:
    import io as _io
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(_io.BytesIO(elf_path.read_bytes()))
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        symbols = section.get_symbol_by_name("default_flash_map")
        if not symbols:
            continue
        sym = symbols[0]
        target_sec = elf.get_section(int(sym["st_shndx"]))
        offset = int(sym["st_value"]) - int(target_sec["sh_addr"])
        size = int(sym["st_size"])
        data = target_sec.data()[offset : offset + size]
        for idx in range(0, len(data), 16):
            if idx + 12 <= len(data):
                fa_id, _fa_dev, _pad, fa_off, fa_size = struct.unpack_from("<BBHII", data, idx)
                if fa_id == 1:
                    return boot_entry + fa_off, fa_size
    raise ValueError(f"default_flash_map slot0 entry (fa_id=1) not found in {elf_path}")


def _load_merged_profile_yaml(profile_path: Path) -> dict:
    import yaml

    raw = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
    base_name = raw.get("base_profile")
    if not base_name:
        return raw
    base_path = profile_path.parent / base_name if not Path(base_name).is_file() else Path(base_name)
    merged = _load_merged_profile_yaml(base_path)
    for key, val in raw.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            sub = dict(merged[key])
            sub.update(val)
            merged[key] = sub
        else:
            merged[key] = val
    return merged


def discover_mcuboot_profiles(repo_root: Path = ROOT) -> list[Path]:
    profiles_dir = repo_root / "profiles"
    out: list[Path] = []
    for path in sorted(profiles_dir.glob("*.yaml")):
        merged = _load_merged_profile_yaml(path)
        elf_rel = str((merged.get("bootloader") or {}).get("elf") or "")
        if "oss_mcuboot_" in elf_rel:
            out.append(path)
    return out


def check_profile_vectors(
    profile_path: Path,
    *,
    repo_root: Path = ROOT,
) -> ProfileVectorCheckResult:
    merged = _load_merged_profile_yaml(profile_path)
    boot = merged.get("bootloader") or {}
    elf_rel = str(boot.get("elf") or "")
    elf_path = Path(elf_rel) if Path(elf_rel).is_absolute() else (repo_root / elf_rel)
    boot_entry = int(boot.get("entry", 0))
    elf_slot0_base, elf_slot0_size = extract_elf_slot0_partition(elf_path, boot_entry)

    slots = (merged.get("memory") or {}).get("slots") or {}
    exec_slot = slots.get("exec") or {}
    prof_exec_base = int(exec_slot.get("base", 0))
    prof_exec_size = int(exec_slot.get("size", 0))

    sc = merged.get("success_criteria") or {}
    raw_vto = sc.get("vector_table_offset")
    prof_vto = int(raw_vto) if raw_vto is not None else None

    images = merged.get("images") or {}
    mismatches: list[str] = []

    if prof_exec_base != elf_slot0_base:
        mismatches.append(
            f"profile exec.base=0x{prof_exec_base:08x} != bootloader ELF slot0_base=0x{elf_slot0_base:08x}"
        )

    role_infos: dict[str, ImageVectorInfo | None] = {"exec": None, "staging": None}
    for role in ("exec", "staging"):
        img_rel = images.get(role)
        if not img_rel:
            continue
        img_path = Path(img_rel) if Path(img_rel).is_absolute() else (repo_root / img_rel)
        info = inspect_image_vectors(img_path)
        role_infos[role] = info
        if info.erased:
            continue
        assert info.header_size is not None
        assert info.vector_offset is not None
        assert info.reset_vector is not None
        assert info.initial_sp_at_header is not None
        if info.vector_offset != info.header_size:
            mismatches.append(
                f"{role} ({img_path.name}): ih_hdr_size=0x{info.header_size:x} != "
                f"vector_table_offset=0x{info.vector_offset:x} "
                f"(sp@0x{info.header_size:x}=0x{info.initial_sp_at_header:08x}, "
                f"reset@0x{info.vector_offset:x}=0x{info.reset_vector:08x})"
            )
        if info.linked_slot0_base is not None and info.linked_slot0_base != elf_slot0_base:
            mismatches.append(
                f"{role} ({img_path.name}): linked_slot0_base=0x{info.linked_slot0_base:08x} "
                f"(reset=0x{info.reset_vector:08x}) != bootloader ELF slot0_base=0x{elf_slot0_base:08x}"
            )
        if prof_vto is not None and prof_vto != info.vector_offset:
            mismatches.append(
                f"{role} ({img_path.name}): profile success_criteria.vector_table_offset=0x{prof_vto:x} != "
                f"image vector_table_offset=0x{info.vector_offset:x}"
            )

    try:
        rel_prof = str(profile_path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        rel_prof = str(profile_path)

    exec_info = role_infos["exec"]
    staging_info = role_infos["staging"]
    exec_desc = (
        f"{exec_info.image_path.name}(hdr=0x{exec_info.header_size:x},vec=0x{exec_info.vector_offset:x},reset=0x{exec_info.reset_vector:08x})"
        if exec_info and not exec_info.erased
        else (f"{exec_info.image_path.name}(erased)" if exec_info else "none")
    )
    staging_desc = (
        f"{staging_info.image_path.name}(hdr=0x{staging_info.header_size:x},vec=0x{staging_info.vector_offset:x},reset=0x{staging_info.reset_vector:08x})"
        if staging_info and not staging_info.erased
        else (f"{staging_info.image_path.name}(erased)" if staging_info else "none")
    )

    if mismatches:
        msg = (
            f"{rel_prof}: mismatch (elf={elf_path.name} elf_slot0=0x{elf_slot0_base:08x} "
            f"exec={exec_desc} staging={staging_desc}; " + "; ".join(mismatches) + ")"
        )
    else:
        msg = (
            f"{rel_prof}: ok (elf={elf_path.name} elf_slot0=0x{elf_slot0_base:08x} "
            f"exec={exec_desc} staging={staging_desc})"
        )

    return ProfileVectorCheckResult(
        profile_path=profile_path,
        elf_path=elf_path,
        elf_slot0_base=elf_slot0_base,
        elf_slot0_size=elf_slot0_size,
        profile_exec_base=prof_exec_base,
        profile_exec_size=prof_exec_size,
        profile_vector_table_offset=prof_vto,
        exec_image=exec_info,
        staging_image=staging_info,
        mismatches=tuple(mismatches),
        message=msg,
    )


def check_all_profile_vectors(
    profile_paths: Iterable[Path] | None = None,
    *,
    repo_root: Path = ROOT,
) -> list[ProfileVectorCheckResult]:
    paths = list(profile_paths) if profile_paths is not None else discover_mcuboot_profiles(repo_root)
    return [check_profile_vectors(path, repo_root=repo_root) for path in paths]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify tracked MCUboot application images under results/oss_validation/assets/."
    )
    parser.add_argument(
        "images",
        nargs="*",
        type=Path,
        help="Optional explicit .bin image paths to check (defaults to all tracked *.bin).",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help="Check all *.bin files in this directory.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Repository root for relative path reporting and git ls-files discovery.",
    )
    parser.add_argument(
        "--verifier",
        choices=("auto", "imgtool", "cryptography", "stdlib"),
        default="auto",
        help="Signature verification backend (default: auto).",
    )
    parser.add_argument(
        "--check-profiles",
        action="store_true",
        help="Cross-check each MCUboot profile's image header sizes and reset vectors against its bootloader ELF.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="With --check-profiles, print all profile results including mismatches and exit 0.",
    )
    args = parser.parse_args(argv)

    if args.check_profiles:
        prof_results = check_all_profile_vectors(repo_root=args.repo_root)
        prof_mismatches = [res for res in prof_results if not res.ok]
        for res in prof_results:
            stream = sys.stderr if (not res.ok and not args.report_only) else sys.stdout
            print(res.message, file=stream)
        if prof_mismatches and not args.report_only:
            return 1
        return 0

    if args.images:
        target_images = list(args.images)
    elif args.assets_dir is not None:
        target_images = sorted(args.assets_dir.glob("*.bin"))
    else:
        target_images = discover_tracked_images(args.repo_root)

    if not target_images:
        print("No *.bin files found to check.", file=sys.stderr)
        return 1

    results = check_assets(target_images, repo_root=args.repo_root, verifier=args.verifier)
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

