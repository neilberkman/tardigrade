#!/usr/bin/env bash
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
#
# Reproducibly build the pinned open-source Zephyr targets for Flash Circular
# Buffer (FCB, subsys/fs/fcb) and the settings subsystem's FCB backend
# (subsys/settings/src/settings_fcb.c) at both pinned Zephyr v3.7.0
# (36940db938a8f4a1e919496793ed439850a221c2) and upstream Zephyr head
# (06b50e7c66d27d519826a49e3c524ed762873cb6):
#   1. Raw FCB target (append, walk, rotate) on nRF52840 internal NVMC flash0
#      (0x0000C000, 12 KiB = 3 x 4096 B sectors) and external JEDEC SPI NOR
#      flash (jedec,spi-nor on spi2 @ 0x40023000, CS# P0.22).
#   2. Settings-on-FCB target (save, update, delete, load, compress) on
#      nRF52840 internal NVMC flash0 and external JEDEC SPI NOR flash.
#   3. Deterministic pre-cut 12 KiB seed images for both the ordinary
#      append/update/delete workload and the close-to-full sector rotation /
#      settings compaction workload.
#
# These targets reproduce known open upstream Zephyr issues:
#   - Zephyr issue #121749 (referencing #121748): power cut during
#     fcb_sector_hdr_init() after fd_magic is programmed leaves fd_ver and
#     fd_id erased (fd_id = 0xFFFF = -1), treated as f_oldest with zero free
#     sectors (permanent -ENOSPC in raw FCB, and active-sector erasure via
#     flash_area_flatten(f_active) in settings_fcb_src()).
#   - Zephyr issue #122446: uncommitted torn entry accepted by fcb_elem_crc8()
#     when crc8_ccitt(0xFF, length_header || partial_payload || erased_0xFF)
#     equals the erased flash byte 0xFF.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/build"
BUILD_ROOT="${BUILD_ROOT:-/tmp/zf-zephyr-fcb-settings-build}"

PINNED_ZEPHYR_COMMIT="36940db938a8f4a1e919496793ed439850a221c2"
HEAD_ZEPHYR_COMMIT="06b50e7c66d27d519826a49e3c524ed762873cb6"
ZEPHYR_REPOSITORY="https://github.com/zephyrproject-rtos/zephyr"

ZEPHYR_WS="${ZEPHYR_WS:-${BUILD_ROOT}/zephyrproject}"
HEAD_ZEPHYR_WS="${HEAD_ZEPHYR_WS:-${BUILD_ROOT}/zephyrproject-head}"
WEST="${WEST:-$(command -v west || true)}"
if [[ -z "${WEST}" || ! -x "${WEST}" ]]; then
    echo "ERROR: Set WEST to an executable west installation" >&2
    exit 1
fi
PYTHON_BIN="${PYTHON_BIN:-$(dirname "${WEST}")/python3}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "ERROR: Set PYTHON_BIN to the Python interpreter that provides west's dependencies" >&2
    exit 1
fi

prepare_zephyr_ws() {
    local ws_dir="$1"
    local commit="$2"
    local manifest_out="$3"

    if [[ ! -d "${ws_dir}/zephyr/.git" ]]; then
        mkdir -p "${ws_dir}/zephyr"
        git -C "${ws_dir}/zephyr" init
        git -C "${ws_dir}/zephyr" remote add origin "${ZEPHYR_REPOSITORY}"
    fi
    if [[ -n "$(git -C "${ws_dir}/zephyr" status --porcelain --untracked-files=no)" ]]; then
        echo "ERROR: ${ws_dir}/zephyr has tracked changes; refusing unverifiable source provenance" >&2
        exit 1
    fi
    if [[ "$(git -C "${ws_dir}/zephyr" rev-parse --verify HEAD^{commit} 2>/dev/null || true)" != "${commit}" ]]; then
        git -C "${ws_dir}/zephyr" fetch --depth 1 origin "${commit}"
        git -C "${ws_dir}/zephyr" checkout --detach FETCH_HEAD
    fi
    if [[ ! -d "${ws_dir}/.west" ]]; then
        "${WEST}" init -l "${ws_dir}/zephyr"
    fi
    (
        cd "${ws_dir}"
        "${WEST}" config manifest.project-filter -- "-.*,+^cmsis$,+^cmsis_6$,+^hal_nordic$"
        "${WEST}" update --narrow -o=--depth=1 cmsis cmsis_6 hal_nordic
        "${WEST}" manifest --freeze --active-only > "${manifest_out}"
    )
    local actual_commit
    actual_commit="$(git -C "${ws_dir}/zephyr" rev-parse --verify HEAD^{commit})"
    if [[ "${actual_commit}" != "${commit}" ]]; then
        echo "ERROR: Expected Zephyr commit ${commit}, got ${actual_commit}" >&2
        exit 1
    fi
}

detect_toolchain_path() {
    if [[ -n "${GNUARMEMB_TOOLCHAIN_PATH:-}" ]]; then
        echo "${GNUARMEMB_TOOLCHAIN_PATH}"
        return
    fi
    local candidate
    for candidate in \
        "${HOME}"/tools-xpack/xpack-arm-none-eabi-gcc-* \
        "${HOME}"/arm-gnu-toolchain-* \
        "${HOME}"/tools/gcc-arm-none-eabi-*; do
        if [[ -x "${candidate}/bin/arm-none-eabi-gcc" ]]; then
            echo "${candidate}"
            return
        fi
    done
    echo "ERROR: Set GNUARMEMB_TOOLCHAIN_PATH to an Arm GNU toolchain root" >&2
    exit 1
}

TOOLCHAIN_PATH="$(detect_toolchain_path)"
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"
GDB_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb"

mkdir -p "${OUT_DIR}" "${BUILD_ROOT}"

WEST_MANIFEST="${BUILD_ROOT}/west-manifest.freeze.yml"
HEAD_WEST_MANIFEST="${BUILD_ROOT}/west-manifest-head.freeze.yml"

prepare_zephyr_ws "${ZEPHYR_WS}" "${PINNED_ZEPHYR_COMMIT}" "${WEST_MANIFEST}"
prepare_zephyr_ws "${HEAD_ZEPHYR_WS}" "${HEAD_ZEPHYR_COMMIT}" "${HEAD_WEST_MANIFEST}"

build_four_targets() {
    local ws_dir="$1"
    local suffix="$2"

    echo "[build] Building raw FCB internal target (${suffix:-v3.7.0})..."
    (
        cd "${ws_dir}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
            -d "${BUILD_ROOT}/zephyr_fcb_raw_internal${suffix}" \
            -p auto \
            -b nrf52840dk/nrf52840 \
            "${SCRIPT_DIR}/fcb_raw" \
            -- \
            -DCONF_FILE="${SCRIPT_DIR}/fcb_raw/prj_internal.conf" \
            -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/fcb_raw/app_internal.overlay" \
            "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${BUILD_ROOT}/zephyr_fcb_raw_internal${suffix}/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_fcb_raw_internal${suffix}.elf"
    "${STRIP_BIN}" -g "${OUT_DIR}/zephyr_fcb_raw_internal${suffix}.elf"

    echo "[build] Building raw FCB SPI NOR target (${suffix:-v3.7.0})..."
    (
        cd "${ws_dir}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
            -d "${BUILD_ROOT}/zephyr_fcb_raw_spi_nor${suffix}" \
            -p auto \
            -b nrf52840dk/nrf52840 \
            "${SCRIPT_DIR}/fcb_raw" \
            -- \
            -DCONF_FILE="${SCRIPT_DIR}/fcb_raw/prj_spi_nor.conf" \
            -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/fcb_raw/app_spi_nor.overlay" \
            "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${BUILD_ROOT}/zephyr_fcb_raw_spi_nor${suffix}/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_fcb_raw_spi_nor${suffix}.elf"
    "${STRIP_BIN}" -g "${OUT_DIR}/zephyr_fcb_raw_spi_nor${suffix}.elf"

    echo "[build] Building settings-on-FCB internal target (${suffix:-v3.7.0})..."
    (
        cd "${ws_dir}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
            -d "${BUILD_ROOT}/zephyr_settings_fcb_internal${suffix}" \
            -p auto \
            -b nrf52840dk/nrf52840 \
            "${SCRIPT_DIR}/settings_fcb" \
            -- \
            -DCONF_FILE="${SCRIPT_DIR}/settings_fcb/prj_internal.conf" \
            -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/settings_fcb/app_internal.overlay" \
            "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${BUILD_ROOT}/zephyr_settings_fcb_internal${suffix}/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_settings_fcb_internal${suffix}.elf"
    "${STRIP_BIN}" -g "${OUT_DIR}/zephyr_settings_fcb_internal${suffix}.elf"

    echo "[build] Building settings-on-FCB SPI NOR target (${suffix:-v3.7.0})..."
    (
        cd "${ws_dir}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
            -d "${BUILD_ROOT}/zephyr_settings_fcb_spi_nor${suffix}" \
            -p auto \
            -b nrf52840dk/nrf52840 \
            "${SCRIPT_DIR}/settings_fcb" \
            -- \
            -DCONF_FILE="${SCRIPT_DIR}/settings_fcb/prj_spi_nor.conf" \
            -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/settings_fcb/app_spi_nor.overlay" \
            "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${BUILD_ROOT}/zephyr_settings_fcb_spi_nor${suffix}/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_settings_fcb_spi_nor${suffix}.elf"
    "${STRIP_BIN}" -g "${OUT_DIR}/zephyr_settings_fcb_spi_nor${suffix}.elf"
}

build_four_targets "${ZEPHYR_WS}" ""
build_four_targets "${HEAD_ZEPHYR_WS}" "_head"

echo "[build] Generating deterministic pre-cut seed images and provenance manifest..."
cp "${WEST_MANIFEST}" "${OUT_DIR}/west-manifest.freeze.yml"
cp "${HEAD_WEST_MANIFEST}" "${OUT_DIR}/west-manifest-head.freeze.yml"
"${PYTHON_BIN}" - "${OUT_DIR}" "${PINNED_ZEPHYR_COMMIT}" "${HEAD_ZEPHYR_COMMIT}" <<'PY'
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

out_dir = Path(sys.argv[1])
zephyr_commit = sys.argv[2]
head_zephyr_commit = sys.argv[3]

SECTOR_SIZE = 4096
FCB_RAW_MAGIC = 0x46434231
SETTINGS_FCB_MAGIC = 0xC0FFEEEE
FCB_VERSION = 1

REC_MAGIC_BASE = 0x46437000
REC_FLAG_LIVE = 0x00
REC_FLAG_DELETED = 0x01
REC_FLAG_FILLER = 0x02
KEY_FILLER = 0xFE

def crc8_ccitt(init: int, data: bytes) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc

def align_up(n: int, align: int) -> int:
    if align <= 1:
        return n
    return (n + align - 1) & ~(align - 1)

def encode_fcb_len(length: int) -> bytes:
    if not (0 < length <= 0x3FFF):
        raise ValueError(f"Invalid FCB element length {length}")
    if length < 0x80:
        return bytes([length])
    return bytes([(length & 0x7F) | 0x80, (length >> 7) & 0x7F])

def make_fcb_sector_hdr(magic: int, version: int, sector_id: int) -> bytes:
    return struct.pack("<IBBH", magic & 0xFFFFFFFF, version & 0xFF, 0xFF, sector_id & 0xFFFF)

def make_fcb_entry(payload: bytes, align: int) -> bytes:
    len_bytes = encode_fcb_len(len(payload))
    crc = crc8_ccitt(0xFF, len_bytes + payload)
    assert crc != 0xFF, "Seed entry CRC8 must not equal erased byte 0xFF"
    len_field = len_bytes + (b"\xFF" * (align_up(len(len_bytes), align) - len(len_bytes)))
    data_field = payload + (b"\xFF" * (align_up(len(payload), align) - len(payload)))
    crc_field = bytes([crc]) + (b"\xFF" * (align_up(1, align) - 1))
    return len_field + data_field + crc_field

def expected_val0(key_id: int, seq: int) -> int:
    return ((0xA5000000 | ((key_id & 0xFF) << 16) | (seq & 0xFFFF)) ^ (seq * 0x01010101)) & 0xFFFFFFFF

def expected_val1(key_id: int, seq: int) -> int:
    return ((0x5A000000 | ((key_id & 0xFF) << 16) | ((seq * 17) & 0xFFFF)) ^ 0xC0FFEE11) & 0xFFFFFFFF

def make_record_struct(key_id: int, seq: int, flags: int = REC_FLAG_LIVE) -> bytes:
    if flags & REC_FLAG_DELETED:
        v0, v1 = 0, 0
    else:
        v0 = expected_val0(key_id, seq)
        v1 = expected_val1(key_id, seq)
    body = struct.pack("<IIIII", REC_MAGIC_BASE | (flags & 0xFF), key_id, seq, v0, v1)
    crc32 = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc32)

def make_raw_filler_payload(seq: int, total_payload_len: int) -> bytes:
    hdr = make_record_struct(KEY_FILLER, seq, REC_FLAG_FILLER)
    assert total_payload_len >= len(hdr)
    pad = bytearray(b"\x5A" * (total_payload_len - len(hdr)))
    len_bytes = encode_fcb_len(total_payload_len)
    for tweak in range(256):
        if pad:
            pad[-1] = tweak
        candidate = hdr + bytes(pad)
        if crc8_ccitt(0xFF, len_bytes + candidate) != 0xFF:
            return candidate
    raise RuntimeError("Could not find filler payload with non-0xFF CRC8")

def make_settings_filler_payload(name: str, total_payload_len: int) -> bytes:
    prefix = f"{name}=".encode("ascii")
    assert total_payload_len > len(prefix)
    pad = bytearray(b"A" * (total_payload_len - len(prefix)))
    len_bytes = encode_fcb_len(total_payload_len)
    for tweak in range(26):
        pad[-1] = ord("A") + tweak
        candidate = prefix + bytes(pad)
        if crc8_ccitt(0xFF, len_bytes + candidate) != 0xFF:
            return candidate
    raise RuntimeError("Could not find settings filler payload with non-0xFF CRC8")

def build_raw_fcb_ordinary_seed(align: int) -> bytes:
    s0 = bytearray(b"\xFF" * SECTOR_SIZE)
    hdr = make_fcb_sector_hdr(FCB_RAW_MAGIC, FCB_VERSION, 1)
    s0[0:len(hdr)] = hdr
    off = align_up(len(hdr), align)
    records = [
        (0, 1, REC_FLAG_LIVE),
        (1, 2, REC_FLAG_LIVE),
        (2, 3, REC_FLAG_LIVE),
        (3, 4, REC_FLAG_LIVE),
        (1, 10, REC_FLAG_LIVE),
        (2, 11, REC_FLAG_DELETED),
        (4, 12, REC_FLAG_LIVE),
        (5, 13, REC_FLAG_LIVE),
    ]
    for key_id, seq, flags in records:
        ent = make_fcb_entry(make_record_struct(key_id, seq, flags), align)
        s0[off:off + len(ent)] = ent
        off += len(ent)
    return bytes(s0) + (b"\xFF" * (2 * SECTOR_SIZE))

def build_raw_fcb_rotation_seed(align: int) -> bytes:
    rec_entry_size = len(make_fcb_entry(make_record_struct(0, 1, REC_FLAG_LIVE), align))
    hdr_size = align_up(8, align)

    s0 = bytearray(b"\xFF" * SECTOR_SIZE)
    s0[0:8] = make_fcb_sector_hdr(FCB_RAW_MAGIC, FCB_VERSION, 1)
    off = hdr_size
    for key_id, seq, flags in (
        (0, 1, REC_FLAG_LIVE),
        (1, 2, REC_FLAG_LIVE),
        (2, 3, REC_FLAG_LIVE),
        (3, 4, REC_FLAG_LIVE),
    ):
        ent = make_fcb_entry(make_record_struct(key_id, seq, flags), align)
        s0[off:off + len(ent)] = ent
        off += len(ent)
    s0_rem = SECTOR_SIZE - off
    s0_overhead = align_up(2, align) + align_up(1, align)
    s0_filler_len = s0_rem - s0_overhead
    s0_filler = make_fcb_entry(make_raw_filler_payload(5, s0_filler_len), align)
    assert off + len(s0_filler) == SECTOR_SIZE
    s0[off:off + len(s0_filler)] = s0_filler

    s1 = bytearray(b"\xFF" * SECTOR_SIZE)
    s1[0:8] = make_fcb_sector_hdr(FCB_RAW_MAGIC, FCB_VERSION, 2)
    off = hdr_size
    for key_id, seq, flags in (
        (1, 10, REC_FLAG_LIVE),
        (2, 11, REC_FLAG_DELETED),
        (4, 12, REC_FLAG_LIVE),
        (5, 13, REC_FLAG_LIVE),
    ):
        ent = make_fcb_entry(make_record_struct(key_id, seq, flags), align)
        s1[off:off + len(ent)] = ent
        off += len(ent)
    s1_target_free = 2 * rec_entry_size
    s1_rem = SECTOR_SIZE - off - s1_target_free
    s1_overhead = align_up(2, align) + align_up(1, align)
    s1_filler_len = s1_rem - s1_overhead
    s1_filler = make_fcb_entry(make_raw_filler_payload(14, s1_filler_len), align)
    assert off + len(s1_filler) + s1_target_free == SECTOR_SIZE
    s1[off:off + len(s1_filler)] = s1_filler

    return bytes(s0) + bytes(s1) + (b"\xFF" * SECTOR_SIZE)

def make_settings_val_entry(key_id: int, seq: int, align: int) -> bytes:
    payload = f"nvm/k0{key_id}=".encode("ascii") + make_record_struct(key_id, seq, REC_FLAG_LIVE)
    return make_fcb_entry(payload, align)

def make_settings_del_entry(name: str, align: int) -> bytes:
    payload = f"{name}=".encode("ascii")
    return make_fcb_entry(payload, align)

def build_settings_fcb_ordinary_seed(align: int) -> bytes:
    s0 = bytearray(b"\xFF" * SECTOR_SIZE)
    s0[0:8] = make_fcb_sector_hdr(SETTINGS_FCB_MAGIC, FCB_VERSION, 1)
    off = align_up(8, align)
    entries = [
        make_settings_val_entry(0, 1, align),
        make_settings_val_entry(1, 2, align),
        make_settings_val_entry(2, 3, align),
        make_settings_val_entry(3, 4, align),
        make_settings_val_entry(1, 10, align),
        make_settings_del_entry("nvm/k02", align),
        make_settings_val_entry(4, 12, align),
        make_settings_val_entry(5, 13, align),
    ]
    for ent in entries:
        s0[off:off + len(ent)] = ent
        off += len(ent)
    return bytes(s0) + (b"\xFF" * (2 * SECTOR_SIZE))

def build_settings_fcb_compaction_seed(align: int) -> bytes:
    val_entry_size = len(make_settings_val_entry(0, 1, align))
    del_entry_size = len(make_settings_del_entry("nvm/k02", align))
    hdr_size = align_up(8, align)
    filler_overhead = align_up(2, align) + align_up(1, align)

    s0 = bytearray(b"\xFF" * SECTOR_SIZE)
    s0[0:8] = make_fcb_sector_hdr(SETTINGS_FCB_MAGIC, FCB_VERSION, 1)
    off = hdr_size
    for ent in (
        make_settings_val_entry(0, 1, align),
        make_settings_val_entry(1, 2, align),
        make_settings_val_entry(2, 3, align),
        make_settings_val_entry(3, 4, align),
    ):
        s0[off:off + len(ent)] = ent
        off += len(ent)
    s0_del = make_settings_del_entry("nvm/fil", align)
    s0_rem = SECTOR_SIZE - off - len(s0_del)
    s0_filler_len = s0_rem - filler_overhead
    s0_filler = make_fcb_entry(make_settings_filler_payload("nvm/fil", s0_filler_len), align)
    assert off + len(s0_filler) + len(s0_del) == SECTOR_SIZE
    s0[off:off + len(s0_filler)] = s0_filler
    off += len(s0_filler)
    s0[off:off + len(s0_del)] = s0_del

    s1 = bytearray(b"\xFF" * SECTOR_SIZE)
    s1[0:8] = make_fcb_sector_hdr(SETTINGS_FCB_MAGIC, FCB_VERSION, 2)
    off = hdr_size
    for ent in (
        make_settings_val_entry(1, 10, align),
        make_settings_del_entry("nvm/k02", align),
        make_settings_val_entry(4, 12, align),
        make_settings_val_entry(5, 13, align),
    ):
        s1[off:off + len(ent)] = ent
        off += len(ent)
    s1_target_free = val_entry_size + del_entry_size
    s1_del = make_settings_del_entry("nvm/fl2", align)
    s1_rem = SECTOR_SIZE - off - len(s1_del) - s1_target_free
    s1_filler_len = s1_rem - filler_overhead
    s1_filler = make_fcb_entry(make_settings_filler_payload("nvm/fl2", s1_filler_len), align)
    assert off + len(s1_filler) + len(s1_del) + s1_target_free == SECTOR_SIZE
    s1[off:off + len(s1_filler)] = s1_filler
    off += len(s1_filler)
    s1[off:off + len(s1_del)] = s1_del

    return bytes(s0) + bytes(s1) + (b"\xFF" * SECTOR_SIZE)

seed_files = {
    "fcb_raw_internal_ordinary_seed.bin": build_raw_fcb_ordinary_seed(4),
    "fcb_raw_internal_rotation_seed.bin": build_raw_fcb_rotation_seed(4),
    "fcb_raw_spi_nor_ordinary_seed.bin": build_raw_fcb_ordinary_seed(1),
    "fcb_raw_spi_nor_rotation_seed.bin": build_raw_fcb_rotation_seed(1),
    "settings_fcb_internal_ordinary_seed.bin": build_settings_fcb_ordinary_seed(4),
    "settings_fcb_internal_compaction_seed.bin": build_settings_fcb_compaction_seed(4),
    "settings_fcb_spi_nor_ordinary_seed.bin": build_settings_fcb_ordinary_seed(1),
    "settings_fcb_spi_nor_compaction_seed.bin": build_settings_fcb_compaction_seed(1),
}

for name, data in seed_files.items():
    assert len(data) == 3 * SECTOR_SIZE, (name, len(data))
    (out_dir / name).write_bytes(data)

elf_commits = {
    "zephyr_fcb_raw_internal.elf": zephyr_commit,
    "zephyr_fcb_raw_spi_nor.elf": zephyr_commit,
    "zephyr_settings_fcb_internal.elf": zephyr_commit,
    "zephyr_settings_fcb_spi_nor.elf": zephyr_commit,
    "zephyr_fcb_raw_internal_head.elf": head_zephyr_commit,
    "zephyr_fcb_raw_spi_nor_head.elf": head_zephyr_commit,
    "zephyr_settings_fcb_internal_head.elf": head_zephyr_commit,
    "zephyr_settings_fcb_spi_nor_head.elf": head_zephyr_commit,
}

elf_issues = {
    "zephyr_fcb_raw_internal.elf": ["#121749"],
    "zephyr_fcb_raw_spi_nor.elf": ["#121749"],
    "zephyr_settings_fcb_internal.elf": ["#121749"],
    "zephyr_settings_fcb_spi_nor.elf": ["#121749", "#122446"],
    "zephyr_fcb_raw_internal_head.elf": ["#121749"],
    "zephyr_fcb_raw_spi_nor_head.elf": ["#121749"],
    "zephyr_settings_fcb_internal_head.elf": ["#121749"],
    "zephyr_settings_fcb_spi_nor_head.elf": ["#121749", "#122446"],
}

artifacts = {}
for name in (*elf_commits.keys(), *seed_files.keys()):
    p = out_dir / name
    entry = {
        "size": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
    }
    if name in elf_commits:
        entry["zephyr_commit"] = elf_commits[name]
        entry["reproduces_upstream_issues"] = elf_issues[name]
    artifacts[name] = entry

provenance = {
    "board": "nrf52840dk/nrf52840",
    "sources": {
        "zephyr_base": {
            "repository": "https://github.com/zephyrproject-rtos/zephyr",
            "commit": zephyr_commit,
            "version": "v3.7.0",
        },
        "zephyr_head": {
            "repository": "https://github.com/zephyrproject-rtos/zephyr",
            "commit": head_zephyr_commit,
            "version": "v4.5.99",
        },
    },
    "upstream_issues": {
        "#121749": {
            "url": "https://github.com/zephyrproject-rtos/zephyr/issues/121749",
            "references": ["#121748"],
            "summary": (
                "Power cut during fcb_sector_hdr_init() after fd_magic is written "
                "leaves fd_ver and fd_id erased (fd_id = 0xFFFF); fcb_sector_hdr_read() "
                "validates only fd_magic, FCB_ID_GT treats 0xFFFF (-1) as f_oldest, "
                "fcb_free_sector_cnt() becomes 0 (-ENOSPC in raw FCB), and "
                "settings_fcb_src() erases f_active (the active data sector) instead "
                "of the scratch sector."
            ),
        },
        "#122446": {
            "url": "https://github.com/zephyrproject-rtos/zephyr/issues/122446",
            "summary": (
                "Power cut during entry payload write before fcb_append_finish() leaves "
                "the trailing CRC-8 byte erased (0xFF); when crc8_ccitt(0xFF, "
                "length_header || partial_payload || remaining_0xFF_bytes) == 0xFF, "
                "fcb_elem_crc8() accepts the torn uncommitted entry as valid."
            ),
        },
        "#121748": {
            "url": "https://github.com/zephyrproject-rtos/zephyr/issues/121748",
            "summary": (
                "Referenced by #121749: power cut after the first byte of a 2-byte "
                "entry length header (entries >= 128 bytes) causes fcb_get_len() to "
                "decode an oversized length and fcb_init() to fail permanently with "
                "-EIO. Not exercised by these 24-byte/32-byte record profiles."
            ),
        },
    },
    "api_differences_at_head": [
        "No application source changes were required between 36940db938a8 (v3.7.0) and 06b50e7c66d2 (v4.5.99 head); both fcb_raw/src/main.c and settings_fcb/src/main.c compile unchanged.",
        "In include/zephyr/fs/fcb.h, struct fcb field f_sector_cnt widened from uint8_t to uint16_t.",
        "In subsys/fs/fcb/fcb.c, commit f15889378791 (issue #111886) changed fcb_sector_hdr_init() to write a 16-byte WRITE_ALIGNMENT_BUFFER_SIZE union padded with f_erase_value (0xFF) instead of an 8-byte struct fcb_disk_area, adding two 4-byte 0xFFFFFFFF padding writes (+0x008 and +0x00C) per sector header initialization.",
    ],
    "west_manifest": {
        "file": "west-manifest.freeze.yml",
        "sha256": hashlib.sha256((out_dir / "west-manifest.freeze.yml").read_bytes()).hexdigest(),
    },
    "head_west_manifest": {
        "file": "west-manifest-head.freeze.yml",
        "sha256": hashlib.sha256((out_dir / "west-manifest-head.freeze.yml").read_bytes()).hexdigest(),
    },
    "artifacts": artifacts,
}
(out_dir / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
PY

echo "[build] All Zephyr FCB and settings-on-FCB targets (v3.7.0 and head) built successfully in ${OUT_DIR}"
