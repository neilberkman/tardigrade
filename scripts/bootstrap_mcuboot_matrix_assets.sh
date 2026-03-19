#!/usr/bin/env bash
# Bootstrap Zephyr workspace + MCUboot for building from source in CI.
# Idempotent -- safe to run multiple times.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ZEPHYR_REF="${ZEPHYR_REF:-v3.7.0}"
ZEPHYR_WS="${REPO_ROOT}/third_party/zephyr_ws"
ZEPHYR_VENV="${REPO_ROOT}/third_party/zephyr-venv"
MCUBOOT_DIR="${ZEPHYR_WS}/bootloader/mcuboot"
ASSETS_DIR="${REPO_ROOT}/results/oss_validation/assets"
BUILD_ROOT="${REPO_ROOT}/results/oss_validation/build/bootstrap_mcuboot_matrix_assets"
GENERATED_DIR="${BUILD_ROOT}/generated"
WEST="${ZEPHYR_VENV}/bin/west"
PYTHON_BIN="${ZEPHYR_VENV}/bin/python3"
IMGTOOL_PY="${MCUBOOT_DIR}/scripts/imgtool.py"
IMGTOOL_KEY="${MCUBOOT_DIR}/root-rsa-2048.pem"

msg() { echo ">> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -e "$1" ]] || die "missing required path: $1"; }

detect_toolchain_path() {
    if [[ -n "${GNUARMEMB_TOOLCHAIN_PATH:-}" ]]; then
        echo "${GNUARMEMB_TOOLCHAIN_PATH}"
        return
    fi
    if [[ -d "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major" ]]; then
        echo "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major"
        return
    fi
    die "set GNUARMEMB_TOOLCHAIN_PATH to an ARM GCC toolchain root"
}

write_nrf52_default_overlays() {
    mkdir -p "${GENERATED_DIR}"
    cat > "${GENERATED_DIR}/nrf52_move_bootloader.overlay" <<'EOF'
/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
EOF
    cat > "${GENERATED_DIR}/nrf52_move_app.overlay" <<'EOF'
/ {
    chosen {
        zephyr,code-partition = &slot0_partition;
    };
};
EOF
}

build_seccounter_assets() {
    local toolchain_path strip_bin gdb_bin
    toolchain_path="$(detect_toolchain_path)"
    strip_bin="${toolchain_path}/bin/arm-none-eabi-strip"
    gdb_bin="${toolchain_path}/bin/arm-none-eabi-gdb"

    require_file "${WEST}"
    require_file "${PYTHON_BIN}"
    require_file "${IMGTOOL_PY}"
    require_file "${IMGTOOL_KEY}"
    require_file "${strip_bin}"
    require_file "${gdb_bin}"

    mkdir -p "${ASSETS_DIR}" "${BUILD_ROOT}"
    write_nrf52_default_overlays

    local mcuboot_build="${BUILD_ROOT}/mcuboot_seccounter"
    local app_build="${BUILD_ROOT}/hello_world_seccounter"
    local boot_overlay="${GENERATED_DIR}/nrf52_move_bootloader.overlay"
    local app_overlay="${GENERATED_DIR}/nrf52_move_app.overlay"
    local out_elf="${ASSETS_DIR}/oss_mcuboot_head_move_nrf52_seccounter.elf"
    local out_v1="${ASSETS_DIR}/zephyr_head_move_nrf52_seccounter_v1.bin"
    local out_v2="${ASSETS_DIR}/zephyr_head_move_nrf52_seccounter_v2.bin"
    local app_bin="${app_build}/zephyr/zephyr.bin"

    msg "Building MCUboot nrf52840 seccounter bootloader"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${toolchain_path}" \
        "${WEST}" build \
            -d "${mcuboot_build}" \
            -p always \
            -b nrf52840dk/nrf52840 \
            "${MCUBOOT_DIR}/boot/zephyr" \
            -- \
            -DDTC_OVERLAY_FILE="${boot_overlay}" \
            -DCONFIG_BOOT_SWAP_USING_MOVE=y \
            -DCONFIG_BOOT_PREFER_SWAP_MOVE=y \
            -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
            -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
            -DCONFIG_BOOT_MAX_IMG_SECTORS=1024 \
            -DCONFIG_MCUBOOT_HW_DOWNGRADE_PREVENTION=y \
            "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${mcuboot_build}/zephyr/zephyr.elf" "${out_elf}"
    "${strip_bin}" -g "${out_elf}"
    msg "Wrote ${out_elf}"

    msg "Building Zephyr hello_world app for seccounter images"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${toolchain_path}" \
        "${WEST}" build \
            -d "${app_build}" \
            -p always \
            -b nrf52840dk/nrf52840 \
            "${ZEPHYR_WS}/zephyr/samples/hello_world" \
            -- \
            -DDTC_OVERLAY_FILE="${app_overlay}" \
            -DCONFIG_BOOTLOADER_MCUBOOT=y \
            "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )

    require_file "${app_bin}"

    msg "Signing security-counter image v1"
    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align 8 \
        --header-size 0x200 \
        --slot-size 0x76000 \
        --version 1.0.0+0 \
        --security-counter 1 \
        "${app_bin}" "${out_v1}"

    msg "Signing security-counter image v2"
    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align 8 \
        --header-size 0x200 \
        --slot-size 0x76000 \
        --version 2.0.0+0 \
        --security-counter 2 \
        "${app_bin}" "${out_v2}"

    msg "Wrote ${out_v1}"
    msg "Wrote ${out_v2}"
}

# --- 1. Python venv with west and build-time deps ---
if [[ ! -x "${ZEPHYR_VENV}/bin/west" ]]; then
    msg "Creating Python venv at ${ZEPHYR_VENV}"
    python3 -m venv "${ZEPHYR_VENV}"
    "${ZEPHYR_VENV}/bin/pip" install --quiet --upgrade pip
    "${ZEPHYR_VENV}/bin/pip" install --quiet \
        west intelhex cbor2 cryptography pyyaml
else
    msg "Venv already exists, skipping creation"
fi

# --- 2. Initialize Zephyr workspace ---
if [[ ! -d "${ZEPHYR_WS}/.west" ]]; then
    msg "Initializing Zephyr workspace (${ZEPHYR_REF})"
    "${WEST}" init \
        -m https://github.com/zephyrproject-rtos/zephyr \
        --mr "${ZEPHYR_REF}" "${ZEPHYR_WS}"
else
    msg "Zephyr workspace already initialized"
fi

# --- 3. Fetch Zephyr + MCUboot via west update ---
msg "Running west update (narrow + shallow)"
( cd "${ZEPHYR_WS}" && \
  "${WEST}" update --narrow -o=--depth=1 )

# --- 4. Add upstream MCUboot remote for commit checkouts ---
if [[ ! -d "${MCUBOOT_DIR}" ]]; then
    msg "ERROR: MCUboot not found at ${MCUBOOT_DIR}"
    exit 1
fi
if ! git -C "${MCUBOOT_DIR}" remote | grep -q '^upstream$'; then
    msg "Adding upstream remote to MCUboot"
    git -C "${MCUBOOT_DIR}" remote add upstream \
        https://github.com/mcu-tools/mcuboot.git
fi
git -C "${MCUBOOT_DIR}" fetch --quiet upstream

# --- 5. Install Zephyr + MCUboot Python requirements ---
for req in \
    "${ZEPHYR_WS}/zephyr/scripts/requirements.txt" \
    "${MCUBOOT_DIR}/scripts/requirements.txt"; do
    if [[ -f "${req}" ]]; then
        msg "Installing requirements from ${req##*/}"
        "${ZEPHYR_VENV}/bin/pip" install --quiet -r "${req}"
    fi
done

# --- 6. Configure build generator ---
( cd "${ZEPHYR_WS}"
  if command -v ninja >/dev/null 2>&1; then
      "${WEST}" config build.generator "Ninja"
  else
      "${WEST}" config build.generator "Unix Makefiles"
  fi )

build_seccounter_assets

msg "Bootstrap complete. Workspace: ${ZEPHYR_WS}"
