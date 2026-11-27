#!/usr/bin/env bash
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
#
# Reproducibly build the pinned open-source Zephyr targets for external NVM
# (JEDEC SPI NOR flash and 24-series I2C EEPROM):
#   1. MCUboot on Zephyr (nrf52840dk/nrf52840) with primary slot in internal
#      flash0 (0x0000C000, 64 KiB) and a 64 KiB
#      secondary slot on external SPI NOR flash (jedec,spi-nor on spi2 @
#      0x40023000, CS# P0.22), plus signed v1
#      and v2 slot images.
#   2. Zephyr NVS storage subsystem on external SPI NOR flash (jedec,spi-nor on
#      spi2 @ 0x40023000, CS# P0.22), built immediately before and at the
#      upstream power-loss recovery fix, plus its pre-cut NVS seed image.
#   3. Zephyr EEPROM storage target on external 24-series I2C EEPROM
#      (atmel,at24 on i2c0/twi0 @ 0x40003000, slave address 0x50) and its
#      pre-cut EEPROM seed image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/build"
BUILD_ROOT="${BUILD_ROOT:-/tmp/cx-zephyr-external-nvm-build}"

PINNED_ZEPHYR_COMMIT="36940db938a8f4a1e919496793ed439850a221c2"
PINNED_MCUBOOT_COMMIT="fb2cf0ec3da3687b93f28e556ab682bdd4b85223"
NVS_BROKEN_ZEPHYR_COMMIT="1c128d59b5e1561dafdc1c7b246b8eb1d9857a97"
NVS_FIXED_ZEPHYR_COMMIT="c200ff1eb4e30e06ae53e9cb9cb77515d1708509"
ZEPHYR_REPOSITORY="https://github.com/zephyrproject-rtos/zephyr"
MCUBOOT_REPOSITORY="https://github.com/mcu-tools/mcuboot"

ZEPHYR_WS="${ZEPHYR_WS:-${BUILD_ROOT}/zephyrproject}"
NVS_ZEPHYR_WS="${NVS_ZEPHYR_WS:-${BUILD_ROOT}/zephyrproject-nvs-differential}"
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

if [[ ! -d "${ZEPHYR_WS}/.west" ]]; then
    if [[ ! -d "${ZEPHYR_WS}/zephyr/.git" ]]; then
        mkdir -p "${ZEPHYR_WS}/zephyr"
        git -C "${ZEPHYR_WS}/zephyr" init
        git -C "${ZEPHYR_WS}/zephyr" remote add origin "${ZEPHYR_REPOSITORY}"
        git -C "${ZEPHYR_WS}/zephyr" fetch --depth 1 origin "${PINNED_ZEPHYR_COMMIT}"
        git -C "${ZEPHYR_WS}/zephyr" checkout --detach FETCH_HEAD
    fi
    "${WEST}" init -l "${ZEPHYR_WS}/zephyr"
    (
        cd "${ZEPHYR_WS}"
        "${WEST}" update --narrow
    )
fi

MCUBOOT_DIR="${ZEPHYR_WS}/bootloader/mcuboot"
IMGTOOL_PY="${MCUBOOT_DIR}/scripts/imgtool.py"
IMGTOOL_KEY="${MCUBOOT_DIR}/root-rsa-2048.pem"

# Zephyr's pinned manifest revision is not necessarily the MCUboot revision used
# by this target. Refuse to overwrite a modified checkout, then fetch and detach
# at the target's independently pinned public commit.
if [[ -n "$(git -C "${MCUBOOT_DIR}" status --porcelain --untracked-files=no)" ]]; then
    echo "ERROR: ${MCUBOOT_DIR} has tracked changes; refusing to replace them" >&2
    exit 1
fi
if [[ "$(git -C "${MCUBOOT_DIR}" rev-parse --verify HEAD^{commit})" != "${PINNED_MCUBOOT_COMMIT}" ]]; then
    git -C "${MCUBOOT_DIR}" fetch --depth 1 "${MCUBOOT_REPOSITORY}" "${PINNED_MCUBOOT_COMMIT}"
    git -C "${MCUBOOT_DIR}" checkout --detach FETCH_HEAD
fi

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

for source_dir in "${ZEPHYR_WS}/zephyr" "${MCUBOOT_DIR}"; do
    if [[ ! -d "${source_dir}/.git" && ! -f "${source_dir}/.git" ]]; then
        echo "ERROR: ${source_dir} is not a Git checkout; refusing unverifiable source provenance" >&2
        exit 1
    fi
    if [[ -n "$(git -C "${source_dir}" status --porcelain --untracked-files=no)" ]]; then
        echo "ERROR: ${source_dir} has tracked changes; refusing unverifiable source provenance" >&2
        exit 1
    fi
done

ACTUAL_ZEPHYR_COMMIT="$(git -C "${ZEPHYR_WS}/zephyr" rev-parse --verify HEAD^{commit})"
if [[ "${ACTUAL_ZEPHYR_COMMIT}" != "${PINNED_ZEPHYR_COMMIT}" ]]; then
    echo "ERROR: Expected Zephyr commit ${PINNED_ZEPHYR_COMMIT}, got ${ACTUAL_ZEPHYR_COMMIT}" >&2
    exit 1
fi

ACTUAL_MCUBOOT_COMMIT="$(git -C "${MCUBOOT_DIR}" rev-parse --verify HEAD^{commit})"
if [[ "${ACTUAL_MCUBOOT_COMMIT}" != "${PINNED_MCUBOOT_COMMIT}" ]]; then
    echo "ERROR: Expected MCUboot commit ${PINNED_MCUBOOT_COMMIT}, got ${ACTUAL_MCUBOOT_COMMIT}" >&2
    exit 1
fi

WEST_MANIFEST="${BUILD_ROOT}/west-manifest.freeze.yml"
mkdir -p "${OUT_DIR}" "${BUILD_ROOT}"
(
    cd "${ZEPHYR_WS}"
    "${WEST}" manifest --freeze --active-only > "${WEST_MANIFEST}"
)

echo "[build] 1/6 Building MCUboot bootloader with secondary slot on SPI NOR (spi2)..."
(
    cd "${ZEPHYR_WS}"
    ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
    GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
    "${WEST}" build \
        -d "${BUILD_ROOT}/mcuboot_spi_nor" \
        -p auto \
        -b nrf52840dk/nrf52840 \
        "${MCUBOOT_DIR}/boot/zephyr" \
        -- \
        -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/mcuboot_spi_nor/mcuboot.overlay" \
        -DCONFIG_MULTITHREADING=y \
        -DCONFIG_GPIO=y \
        -DCONFIG_SPI=y \
        -DCONFIG_SPI_NOR=y \
        -DCONFIG_SPI_NOR_FLASH_LAYOUT_PAGE_SIZE=4096 \
        -DCONFIG_SPI_NOR_SFDP_RUNTIME=y \
        -DCONFIG_BOOT_UPGRADE_ONLY=y \
        -DCONFIG_BOOT_MAX_IMG_SECTORS=16 \
        -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
        -DCONFIG_MINIMAL_LIBC=y \
        -DCONFIG_PICOLIBC=n \
        "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
        "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
)
cp "${BUILD_ROOT}/mcuboot_spi_nor/zephyr/zephyr.elf" "${OUT_DIR}/mcuboot_spi_nor.elf"
"${STRIP_BIN}" -g "${OUT_DIR}/mcuboot_spi_nor.elf"

echo "[build] 2/6 Building & signing Zephyr slot0 (v1) and slot1 (v2) images for MCUboot SPI NOR..."
(
    cd "${ZEPHYR_WS}"
    ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
    GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
    "${WEST}" build \
        -d "${BUILD_ROOT}/mcuboot_spi_nor_app" \
        -p auto \
        -b nrf52840dk/nrf52840 \
        "${ZEPHYR_WS}/zephyr/samples/basic/minimal" \
        -- \
        -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/mcuboot_spi_nor/app.overlay" \
        "-DCONF_FILE=prj.conf;common.conf;no-mt.conf;no-timers.conf;arm.conf" \
        -DCONFIG_BOOTLOADER_MCUBOOT=y \
        -DCONFIG_ROM_START_OFFSET=0x200 \
        -DCONFIG_MINIMAL_LIBC=y \
        -DCONFIG_PICOLIBC=n \
        "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
        "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
)

APP_BIN="${BUILD_ROOT}/mcuboot_spi_nor_app/zephyr/zephyr.bin"
APP_V2_INPUT="${BUILD_ROOT}/mcuboot_spi_nor_app_v2_input.bin"
"${PYTHON_BIN}" - "${APP_BIN}" "${APP_V2_INPUT}" <<'PY'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
# Append a deterministic 64-byte version tag so v1 and v2 have distinct digests.
Path(sys.argv[2]).write_bytes(raw + (b"TARDIGRADE_SPI_NOR_SLOT1_V2_PAYLOAD!" + b"\x5A" * 28))
PY

"${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
    --align 4 \
    --header-size 0x200 \
    --slot-size 0x10000 \
    --version 1.0.0+0 \
    "${APP_BIN}" \
    "${OUT_DIR}/mcuboot_spi_nor_slot0_v1.bin"

"${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
    --align 4 \
    --header-size 0x200 \
    --slot-size 0x10000 \
    --version 2.0.0+0 \
    "${APP_V2_INPUT}" \
    "${OUT_DIR}/mcuboot_spi_nor_slot1_v2.bin"

echo "[build] 3/6 Preparing exact Zephyr parent/fix revisions for the NVS differential..."
if [[ ! -d "${NVS_ZEPHYR_WS}/zephyr/.git" ]]; then
    mkdir -p "${NVS_ZEPHYR_WS}/zephyr"
    git -C "${NVS_ZEPHYR_WS}/zephyr" init
    git -C "${NVS_ZEPHYR_WS}/zephyr" remote add origin "${ZEPHYR_REPOSITORY}"
fi
if [[ -n "$(git -C "${NVS_ZEPHYR_WS}/zephyr" status --porcelain --untracked-files=no)" ]]; then
    echo "ERROR: ${NVS_ZEPHYR_WS}/zephyr has tracked changes; refusing to replace them" >&2
    exit 1
fi
git -C "${NVS_ZEPHYR_WS}/zephyr" fetch --depth 2 origin "${NVS_FIXED_ZEPHYR_COMMIT}"
git -C "${NVS_ZEPHYR_WS}/zephyr" checkout --detach "${NVS_BROKEN_ZEPHYR_COMMIT}"
if [[ ! -d "${NVS_ZEPHYR_WS}/.west" ]]; then
    "${WEST}" init -l "${NVS_ZEPHYR_WS}/zephyr"
fi
(
    cd "${NVS_ZEPHYR_WS}"
    "${WEST}" update --narrow
    "${WEST}" manifest --freeze --active-only > "${BUILD_ROOT}/west-manifest-nvs-broken.freeze.yml"
)
ACTUAL_NVS_BROKEN_ZEPHYR_COMMIT="$(git -C "${NVS_ZEPHYR_WS}/zephyr" rev-parse --verify HEAD^{commit})"
if [[ "${ACTUAL_NVS_BROKEN_ZEPHYR_COMMIT}" != "${NVS_BROKEN_ZEPHYR_COMMIT}" ]]; then
    echo "ERROR: Expected broken NVS Zephyr commit ${NVS_BROKEN_ZEPHYR_COMMIT}, got ${ACTUAL_NVS_BROKEN_ZEPHYR_COMMIT}" >&2
    exit 1
fi

echo "[build] 4/6 Building broken and fixed Zephyr NVS targets on SPI NOR (spi2)..."
(
    cd "${NVS_ZEPHYR_WS}"
    ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
    GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
    "${WEST}" build \
        -d "${BUILD_ROOT}/zephyr_spi_nor_nvs_broken" \
        -p auto \
        -b nrf52840dk/nrf52840 \
        "${SCRIPT_DIR}/spi_nor_nvs" \
        -- \
        -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/spi_nor_nvs/app.overlay" \
        "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
        "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
)
cp "${BUILD_ROOT}/zephyr_spi_nor_nvs_broken/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_spi_nor_nvs_broken.elf"
"${STRIP_BIN}" -g "${OUT_DIR}/zephyr_spi_nor_nvs_broken.elf"

git -C "${NVS_ZEPHYR_WS}/zephyr" checkout --detach "${NVS_FIXED_ZEPHYR_COMMIT}"
(
    cd "${NVS_ZEPHYR_WS}"
    "${WEST}" update --narrow
    "${WEST}" manifest --freeze --active-only > "${BUILD_ROOT}/west-manifest-nvs-fixed.freeze.yml"
    ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
    GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
    "${WEST}" build \
        -d "${BUILD_ROOT}/zephyr_spi_nor_nvs_fixed" \
        -p auto \
        -b nrf52840dk/nrf52840 \
        "${SCRIPT_DIR}/spi_nor_nvs" \
        -- \
        -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/spi_nor_nvs/app.overlay" \
        "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
        "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
)
ACTUAL_NVS_FIXED_ZEPHYR_COMMIT="$(git -C "${NVS_ZEPHYR_WS}/zephyr" rev-parse --verify HEAD^{commit})"
if [[ "${ACTUAL_NVS_FIXED_ZEPHYR_COMMIT}" != "${NVS_FIXED_ZEPHYR_COMMIT}" ]]; then
    echo "ERROR: Expected fixed NVS Zephyr commit ${NVS_FIXED_ZEPHYR_COMMIT}, got ${ACTUAL_NVS_FIXED_ZEPHYR_COMMIT}" >&2
    exit 1
fi
cp "${BUILD_ROOT}/zephyr_spi_nor_nvs_fixed/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_spi_nor_nvs_fixed.elf"
"${STRIP_BIN}" -g "${OUT_DIR}/zephyr_spi_nor_nvs_fixed.elf"

echo "[build] 5/6 Building Zephyr EEPROM storage target on I2C EEPROM (twi0 @ 0x50)..."
(
    cd "${ZEPHYR_WS}"
    ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
    GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
    "${WEST}" build \
        -d "${BUILD_ROOT}/zephyr_i2c_eeprom_storage" \
        -p auto \
        -b nrf52840dk/nrf52840 \
        "${SCRIPT_DIR}/i2c_eeprom_storage" \
        -- \
        -DDTC_OVERLAY_FILE="${SCRIPT_DIR}/i2c_eeprom_storage/app.overlay" \
        "-DCMAKE_GDB:FILEPATH=${GDB_BIN}" \
        "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
)
cp "${BUILD_ROOT}/zephyr_i2c_eeprom_storage/zephyr/zephyr.elf" "${OUT_DIR}/zephyr_i2c_eeprom_storage.elf"
"${STRIP_BIN}" -g "${OUT_DIR}/zephyr_i2c_eeprom_storage.elf"

echo "[build] 6/6 Generating deterministic pre-cut seed images and provenance manifest..."
cp "${WEST_MANIFEST}" "${OUT_DIR}/west-manifest.freeze.yml"
cp "${BUILD_ROOT}/west-manifest-nvs-broken.freeze.yml" "${OUT_DIR}/west-manifest-nvs-broken.freeze.yml"
cp "${BUILD_ROOT}/west-manifest-nvs-fixed.freeze.yml" "${OUT_DIR}/west-manifest-nvs-fixed.freeze.yml"
"${PYTHON_BIN}" - "${OUT_DIR}" "${ACTUAL_ZEPHYR_COMMIT}" "${ACTUAL_MCUBOOT_COMMIT}" "${ACTUAL_NVS_BROKEN_ZEPHYR_COMMIT}" "${ACTUAL_NVS_FIXED_ZEPHYR_COMMIT}" <<'PY'
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

out_dir = Path(sys.argv[1])
zephyr_commit = sys.argv[2]
mcuboot_commit = sys.argv[3]
nvs_broken_commit = sys.argv[4]
nvs_fixed_commit = sys.argv[5]

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

def make_nvs_ate(ate_id: int, offset: int, length: int, part: int = 0xFF) -> bytes:
    body = struct.pack("<HHHB", ate_id & 0xFFFF, offset & 0xFFFF, length & 0xFFFF, part & 0xFF)
    return body + bytes([crc8_ccitt(0xFF, body)])

# Build 12 KiB (3 x 4096 B) NVS seed image for SPI NOR flash:
# Sector 0 has:
#   - GC-done ATE at 4096 - 16 (4080): id=0xFFFF, offset=0, len=0
#   - Pre-cut anchor 1 (id=0x0001, value=0xC0FFEE11) at data offset 0, ATE at 4072
#   - Pre-cut anchor 2 (id=0x0002, value=0x5AFE2233) at data offset 4, ATE at 4064
#   - Pre-cut deleted filler record (id=0x0030, len=3984) at data offset 8, ATE at 4056,
#     plus its deletion ATE (id=0x0030, offset=0, len=0) at ATE 4048!
#     Because id=0x0030 is marked deleted (len=0), NVS sector 0 only has 48 bytes
#     of free space left (so main()'s runtime writes first program into sector 0 via
#     0x02 Page Program and then trigger NVS sector rotation and 0x20 4 KiB Sector
#     Erase), AND during GC NVS skips the deleted 3984-byte filler and only copies
#     the live anchor records!
sector0 = bytearray(b"\xFF" * 4096)
struct.pack_into("<I", sector0, 0, 0xC0FFEE11)
struct.pack_into("<I", sector0, 4, 0x5AFE2233)
filler_len = 3984
sector0[8 : 8 + filler_len] = b"\xA5" * filler_len

sector0[4080:4088] = make_nvs_ate(0xFFFF, 0, 0)
sector0[4072:4080] = make_nvs_ate(0x0001, 0, 4)
sector0[4064:4072] = make_nvs_ate(0x0002, 4, 4)
sector0[4056:4064] = make_nvs_ate(0x0030, 8, filler_len)
sector0[4048:4056] = make_nvs_ate(0x0030, 8 + filler_len, 0)

nvs_seed = bytes(sector0) + (b"\xFF" * (2 * 4096))
(out_dir / "spi_nor_nvs_seed.bin").write_bytes(nvs_seed)

# Build 32 KiB I2C EEPROM seed image:
#   - Page 0 (0x0000..0x003F): Pre-cut anchor record A (key=1, payload[0]=0xDEADBEEF)
#   - Page 1 (0x0040..0x007F): Pre-cut anchor record B (key=2, payload[0]=0x55667788)
#   - Remaining pages erased (0xFF).
def make_eeprom_record(key: int, seq: int, first_word: int) -> bytes:
    words = [first_word] + [((first_word ^ (0x11111111 * i)) & 0xFFFFFFFF) for i in range(1, 12)]
    body = struct.pack("<III12I", 0x45455052, key, seq, *words)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)

eeprom_seed = bytearray(b"\xFF" * 32768)
eeprom_seed[0:64] = make_eeprom_record(1, 1, 0xDEADBEEF)
eeprom_seed[64:128] = make_eeprom_record(2, 1, 0x55667788)
(out_dir / "i2c_eeprom_seed.bin").write_bytes(bytes(eeprom_seed))

artifacts = {}
for name in (
    "mcuboot_spi_nor.elf",
    "mcuboot_spi_nor_slot0_v1.bin",
    "mcuboot_spi_nor_slot1_v2.bin",
    "zephyr_spi_nor_nvs_broken.elf",
    "zephyr_spi_nor_nvs_fixed.elf",
    "spi_nor_nvs_seed.bin",
    "zephyr_i2c_eeprom_storage.elf",
    "i2c_eeprom_seed.bin",
):
    p = out_dir / name
    artifacts[name] = {
        "size": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
    }

provenance = {
    "board": "nrf52840dk/nrf52840",
    "sources": {
        "zephyr_base": {
            "repository": "https://github.com/zephyrproject-rtos/zephyr",
            "commit": zephyr_commit,
        },
        "zephyr_nvs_broken": {
            "repository": "https://github.com/zephyrproject-rtos/zephyr",
            "commit": nvs_broken_commit,
        },
        "zephyr_nvs_fixed": {
            "repository": "https://github.com/zephyrproject-rtos/zephyr",
            "commit": nvs_fixed_commit,
            "fix_commit": "c200ff1eb4e30e06ae53e9cb9cb77515d1708509",
        },
        "mcuboot": {
            "repository": "https://github.com/mcu-tools/mcuboot",
            "commit": mcuboot_commit,
        },
    },
    "west_manifest": {
        "file": "west-manifest.freeze.yml",
        "sha256": hashlib.sha256((out_dir / "west-manifest.freeze.yml").read_bytes()).hexdigest(),
    },
    "nvs_west_manifests": {
        name: {
            "file": name,
            "sha256": hashlib.sha256((out_dir / name).read_bytes()).hexdigest(),
        }
        for name in (
            "west-manifest-nvs-broken.freeze.yml",
            "west-manifest-nvs-fixed.freeze.yml",
        )
    },
    "artifacts": artifacts,
}
(out_dir / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
PY

echo "[build] All targets built successfully in ${OUT_DIR}"
