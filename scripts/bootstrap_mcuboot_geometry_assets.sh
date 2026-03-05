#!/usr/bin/env bash
# Build geometry-trigger MCUboot assets used by exploratory PR2206/PR2214 profiles.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ZEPHYR_WS="${REPO_ROOT}/third_party/zephyr_ws"
ZEPHYR_VENV="${REPO_ROOT}/third_party/zephyr-venv"
MCUBOOT_REPO="${ZEPHYR_WS}/bootloader/mcuboot"
ASSETS_DIR="${REPO_ROOT}/results/oss_validation/assets"
BUILD_DIR="${REPO_ROOT}/results/oss_validation/build"
TOOLCHAIN_PATH="${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major"
WEST="${ZEPHYR_VENV}/bin/west"
IMGTOOL_PY="${MCUBOOT_REPO}/scripts/imgtool.py"
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"

# PR2206 broken/fixed pair.
PR2206_BROKEN="e35461d29484f1e11c75c769b066ec2b79b4791c"
PR2206_FIXED="08985c9679f6877ab593a7ff62ab244ca6fbaae5"

msg() { echo ">> $*" >&2; }

require_file() {
    local p="$1"
    if [[ ! -e "${p}" ]]; then
        echo "ERROR: missing required path: ${p}" >&2
        exit 1
    fi
}

require_file "${WEST}"
require_file "${IMGTOOL_PY}"
require_file "${STRIP_BIN}"
require_file "${MCUBOOT_REPO}/root-rsa-2048.pem"
require_file "${BUILD_DIR}/scratch_with_code_partition.dts"

mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}"

WT_ROOT="$(mktemp -d /tmp/mcuboot_geom_wt.XXXXXX)"
cleanup() {
    for d in "${WT_ROOT}/pr2206_broken" "${WT_ROOT}/pr2206_fixed"; do
        if [[ -d "${d}" ]]; then
            git -C "${MCUBOOT_REPO}" worktree remove --force "${d}" >/dev/null 2>&1 || true
        fi
    done
    rm -rf "${WT_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

msg "Creating detached worktrees for PR2206 geometry pair"
git -C "${MCUBOOT_REPO}" worktree add --detach "${WT_ROOT}/pr2206_broken" "${PR2206_BROKEN}" >/dev/null
git -C "${MCUBOOT_REPO}" worktree add --detach "${WT_ROOT}/pr2206_fixed" "${PR2206_FIXED}" >/dev/null

build_pr2206_variant() {
    local name="$1"
    local src="$2"
    local out_build="${BUILD_DIR}/${name}"
    local out_elf="${ASSETS_DIR}/oss_mcuboot_${name}.elf"

    msg "Building ${name}"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
          -d "${out_build}" \
          -p always \
          -b nrf52840dk/nrf52840 \
          "${src}/boot/zephyr" \
          -- \
          -DDTC_OVERLAY_FILE="${BUILD_DIR}/scratch_with_code_partition.dts" \
          -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS=1024 \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          -DPython3_EXECUTABLE:FILEPATH="${IMGTOOL_PYTHON}"
    )

    cp "${out_build}/zephyr/zephyr.elf" "${out_elf}"
    "${STRIP_BIN}" -g "${out_elf}"
    msg "Wrote ${out_elf}"
}

build_pr2206_variant "pr2206_scratch_geom_broken" "${WT_ROOT}/pr2206_broken"
build_pr2206_variant "pr2206_scratch_geom_fixed" "${WT_ROOT}/pr2206_fixed"

msg "Generating geometry-trigger slot images"
REPO_ROOT="${REPO_ROOT}" python3 - <<'PY'
from pathlib import Path
import struct
import os

repo = Path(os.environ["REPO_ROOT"])
base = (repo / "results/oss_validation/assets/zephyr_slot1_padded.bin").read_bytes()
ih_size = struct.unpack_from("<I", base, 0x0C)[0]
payload = base[0x200:0x200 + ih_size]

def make_payload(path: Path, size: int, fill: int) -> None:
    if len(payload) >= size:
        out = payload[:size]
    else:
        out = payload + bytes([fill]) * (size - len(payload))
    path.write_bytes(out)

make_payload(Path("/tmp/zephyr_slot1_scratch_geom_payload.bin"), 0x69000, 0xA5)
make_payload(Path("/tmp/zephyr_slot1_offset_geom_payload.bin"), 0x75000, 0x5A)
PY

"${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
  --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
  --align 8 \
  --header-size 0x200 \
  --slot-size 0x6e000 \
  --pad-header \
  --pad \
  --confirm \
  --version 1.0.2+0 \
  /tmp/zephyr_slot1_scratch_geom_payload.bin \
  "${ASSETS_DIR}/zephyr_slot1_scratch_geom_max.bin"

"${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
  --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
  --align 8 \
  --header-size 0x200 \
  --slot-size 0x76000 \
  --pad-header \
  --pad \
  --confirm \
  --version 1.0.3+0 \
  /tmp/zephyr_slot1_offset_geom_payload.bin \
  "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin"

msg "Geometry assets complete"
