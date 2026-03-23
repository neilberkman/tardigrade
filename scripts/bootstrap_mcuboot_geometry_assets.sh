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
GENERATED_DIR="${BUILD_DIR}/bootstrap_mcuboot_geometry_assets"
WEST="${ZEPHYR_VENV}/bin/west"
IMGTOOL_PY="${MCUBOOT_REPO}/scripts/imgtool.py"
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"
GEOM_ALIGN="32"
GEOM_TRAILER_RESERVE="0x30a0"
GEOM_SIGN_OVERHEAD="0x400"
PR2206_BOUNDARY_PAYLOAD_SIZE="0x7C80"
# Zephyr's STM32F4 flash binding only permits write-block-size values up to 8.
# This is the minimal sector budget that still pushes boot_trailer_sz(write_sz=8)
# past a 64 KiB tail sector on the PR2206 geometry:
# (2725 * 3 * 8) + (5 * 32) = 0x10018.
PR2206_GEOM_WRITE_BLOCK_SIZE="8"
PR2206_BOOT_MAX_IMG_SECTORS="2725"
printf -v PR2206_GEOM_TRAILER_RESERVE '0x%x' \
    $(( (PR2206_BOOT_MAX_IMG_SECTORS * 3 * PR2206_GEOM_WRITE_BLOCK_SIZE) + (GEOM_ALIGN * 5) ))

# PR2206 broken/fixed pair.
PR2206_BROKEN="e35461d29484f1e11c75c769b066ec2b79b4791c"
PR2206_FIXED="08985c9679f6877ab593a7ff62ab244ca6fbaae5"

msg() { echo ">> $*" >&2; }

make_offset_slot_image() {
  local input_path="$1"
  local output_path="$2"
  local offset_bytes="$3"

  "${IMGTOOL_PYTHON}" - "$input_path" "$output_path" "$offset_bytes" <<'PY'
from pathlib import Path
import sys

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
offset_bytes = int(sys.argv[3], 0)

output_path.write_bytes((b"\xFF" * offset_bytes) + input_path.read_bytes())
PY
}

detect_toolchain_path() {
    if [[ -n "${GNUARMEMB_TOOLCHAIN_PATH:-}" ]]; then
        echo "${GNUARMEMB_TOOLCHAIN_PATH}"
        return
    fi
    if [[ -d "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major" ]]; then
        echo "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major"
        return
    fi
    local candidate
    for candidate in "${HOME}"/arm-gnu-toolchain-*; do
        if [[ -x "${candidate}/bin/arm-none-eabi-gcc" && -x "${candidate}/bin/arm-none-eabi-gdb" ]]; then
            echo "${candidate}"
            return
        fi
    done
    if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
        local compiler_bin toolchain_root
        compiler_bin="$(readlink -f "$(command -v arm-none-eabi-gcc)")"
        toolchain_root="$(cd "$(dirname "${compiler_bin}")/.." && pwd)"
        if [[ -x "${toolchain_root}/bin/arm-none-eabi-gcc" && -x "${toolchain_root}/bin/arm-none-eabi-gdb" ]]; then
            echo "${toolchain_root}"
            return
        fi
    fi
    echo "set GNUARMEMB_TOOLCHAIN_PATH to an ARM GCC toolchain root" >&2
    exit 1
}

TOOLCHAIN_PATH="$(detect_toolchain_path)"
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"

write_geometry_overlay() {
    mkdir -p "${GENERATED_DIR}"
    cat > "${GENERATED_DIR}/scratch_with_geom_partition.dts" <<'EOF'
&flash0 {
    write-block-size = <8>;
    /delete-node/ partitions;

    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0x08000>;
        };
        slot0_partition: partition@8000 {
            label = "image-0";
            reg = <0x08000 0x18000>;
        };
        slot1_partition: partition@108000 {
            label = "image-1";
            reg = <0x108000 0x18000>;
        };
        scratch_partition: partition@120000 {
            label = "image-scratch";
            reg = <0x120000 0x20000>;
        };
        storage_partition: partition@140000 {
            label = "storage";
            reg = <0x140000 0xC0000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
EOF
}

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
mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}" "${GENERATED_DIR}"
write_geometry_overlay
require_file "${GENERATED_DIR}/scratch_with_geom_partition.dts"

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
          -b nucleo_f429zi \
          "${src}/boot/zephyr" \
          -- \
          -DDTC_OVERLAY_FILE="${GENERATED_DIR}/scratch_with_geom_partition.dts" \
          -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
          "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${GEOM_ALIGN}" \
          -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}" \
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
REPO_ROOT="${REPO_ROOT}" \
PR2206_GEOM_TRAILER_RESERVE="${PR2206_GEOM_TRAILER_RESERVE}" \
python3 - <<'PY'
from pathlib import Path
import os
import struct

repo = Path(os.environ["REPO_ROOT"])

def load_payload(base_image: Path) -> bytes:
    base = base_image.read_bytes()
    ih_size = struct.unpack_from("<I", base, 0x0C)[0]
    return base[0x200:0x200 + ih_size]

def make_payload(path: Path, payload: bytes, size: int, fill: int) -> None:
    if len(payload) >= size:
        body = payload[:size]
    else:
        body = payload + bytes([fill]) * (size - len(payload))
    # imgtool expects the MCUboot header reservation at the start of the
    # input image when --pad-header is not used. Restore the 0x200-byte
    # gap so the signed output's vector table lands at 0x200, not 0x400.
    path.write_bytes((b"\x00" * 0x200) + body)

scratch_base = repo / "results/oss_validation/assets/zephyr_head_scratch_stm32f4_pr2206_slot1.bin"
offset_base = repo / "results/oss_validation/assets/zephyr_head_offset_stm32f4_slot1.bin"
scratch_payload = load_payload(scratch_base)
offset_payload = load_payload(offset_base)

scratch_geom_size = (0x18000 - 0x200 - int(os.environ["PR2206_GEOM_TRAILER_RESERVE"], 0) - int("0x400", 0)) & ~0x1F
make_payload(Path("/tmp/zephyr_slot1_scratch_geom_payload.bin"), scratch_payload, scratch_geom_size, 0xA5)
make_payload(
    Path("/tmp/zephyr_slot1_scratch_geom_pr2206_boundary_payload.bin"),
    scratch_payload,
    int(os.environ["PR2206_BOUNDARY_PAYLOAD_SIZE"], 0),
    0xA5,
)
make_payload(Path("/tmp/zephyr_slot1_offset_geom_payload.bin"), offset_payload, 0x40000, 0x5A)
PY

"${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
  --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
  --align "${GEOM_ALIGN}" \
  --header-size 0x200 \
  --slot-size 0x18000 \
  --version 1.0.2+0 \
  /tmp/zephyr_slot1_scratch_geom_payload.bin \
  "${ASSETS_DIR}/zephyr_slot1_scratch_geom_max.bin"

"${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
  --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
  --align "${GEOM_ALIGN}" \
  --header-size 0x200 \
  --slot-size 0x18000 \
  --version 1.0.4+0 \
  /tmp/zephyr_slot1_scratch_geom_pr2206_boundary_payload.bin \
  "${ASSETS_DIR}/zephyr_slot1_scratch_geom_pr2206_boundary.bin"

"${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
  --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
  --align "${GEOM_ALIGN}" \
  --header-size 0x200 \
  --slot-size 0x76000 \
  --version 1.0.3+0 \
  /tmp/zephyr_slot1_offset_geom_payload.bin \
  "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin"
make_offset_slot_image \
  "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin" \
  "${ASSETS_DIR}/zephyr_slot1_offset_geom_full_offsetslot.bin" \
  "0x1E000"

msg "Geometry assets complete"
