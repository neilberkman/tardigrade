#!/usr/bin/env bash
# Build broken/fixed MCUboot ELFs for PR #1597 (g_last_idx swap-move brick bug)
# on STM32F4 (stm32f4_disco).
#
# Strategy: worktrees from HEAD (compatible with Zephyr v3.7.0), then swap
# only boot/bootutil/src/swap_move.c from the broken/fixed commits.
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
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"
DTS_OVERLAY="${BUILD_DIR}/stm32f4_swap_move.dts"

# PR1597: g_last_idx static variable causes brick after power-cycle mid swap-move.
PR1597_BROKEN="bfdf934e3a9f6e39496f2434817df776ef35247d"
PR1597_FIXED="2acc3b6a1c5d4dff19b2e72faecdad2248b1388d"
SWAP_MOVE_SRC="boot/bootutil/src/swap_move.c"

msg() { echo ">> $*" >&2; }

require_file() {
    local p="$1"
    if [[ ! -e "${p}" ]]; then
        echo "ERROR: missing required path: ${p}" >&2
        exit 1
    fi
}

require_file "${WEST}"
require_file "${STRIP_BIN}"
require_file "${DTS_OVERLAY}"

mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}"

WT_ROOT="$(mktemp -d /tmp/mcuboot_pr1597_wt.XXXXXX)"
cleanup() {
    for d in "${WT_ROOT}/pr1597_broken" "${WT_ROOT}/pr1597_fixed"; do
        if [[ -d "${d}" ]]; then
            git -C "${MCUBOOT_REPO}" worktree remove --force "${d}" >/dev/null 2>&1 || true
        fi
    done
    rm -rf "${WT_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

msg "Creating detached worktrees from HEAD"
git -C "${MCUBOOT_REPO}" worktree add --detach "${WT_ROOT}/pr1597_broken" HEAD >/dev/null
git -C "${MCUBOOT_REPO}" worktree add --detach "${WT_ROOT}/pr1597_fixed" HEAD >/dev/null

msg "Injecting swap_move.c from broken commit ${PR1597_BROKEN:0:8}"
git -C "${MCUBOOT_REPO}" show "${PR1597_BROKEN}:${SWAP_MOVE_SRC}" \
    > "${WT_ROOT}/pr1597_broken/${SWAP_MOVE_SRC}"

msg "Injecting swap_move.c from fixed commit ${PR1597_FIXED:0:8}"
git -C "${MCUBOOT_REPO}" show "${PR1597_FIXED}:${SWAP_MOVE_SRC}" \
    > "${WT_ROOT}/pr1597_fixed/${SWAP_MOVE_SRC}"

build_variant() {
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
          -b stm32f4_disco \
          "${src}/boot/zephyr" \
          -- \
          -DDTC_OVERLAY_FILE="${DTS_OVERLAY}" \
          -DCONFIG_BOOT_SWAP_USING_MOVE=y \
          -DCONFIG_BOOT_PREFER_SWAP_MOVE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          -DPython3_EXECUTABLE:FILEPATH="${IMGTOOL_PYTHON}"
    )

    cp "${out_build}/zephyr/zephyr.elf" "${out_elf}"
    "${STRIP_BIN}" -g "${out_elf}"
    msg "Wrote ${out_elf}"
}

build_variant "pr1597_stm32f4_broken" "${WT_ROOT}/pr1597_broken"
build_variant "pr1597_stm32f4_fixed" "${WT_ROOT}/pr1597_fixed"

msg "PR1597 STM32F4 assets complete"
