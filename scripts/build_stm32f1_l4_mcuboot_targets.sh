#!/usr/bin/env bash
# Build MCUboot + Zephyr update targets for STM32F103RB (nucleo_f103rb) and
# STM32L476RG (nucleo_l476rg) using the shared read-only Zephyr workspace.
set -euo pipefail

msg() { echo ">> $*" >&2; }

require_file() {
    if [[ ! -e "$1" ]]; then
        echo "ERROR: missing required path: $1" >&2
        exit 1
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/examples/stm32_mcuboot"
BUILD_ROOT="${REPO_ROOT}/build/stm32_flash_targets"
OVERLAY_DIR="${BUILD_ROOT}/overlays"

usage() {
    cat >&2 <<'EOF'
Usage: build_stm32f1_l4_mcuboot_targets.sh [options]

Options (or set the corresponding environment variables):
  --zephyr-ws <dir>         Path to Zephyr workspace (env: ZEPHYR_WS)
  --zephyr-venv <dir>       Path to Python virtualenv with west/imgtool deps (env: ZEPHYR_VENV)
  --toolchain-path <dir>    Path to Arm GNU toolchain root (env: GNUARMEMB_TOOLCHAIN_PATH or TOOLCHAIN_PATH)
EOF
}

ZEPHYR_WS="${ZEPHYR_WS:-}"
ZEPHYR_VENV="${ZEPHYR_VENV:-}"
TOOLCHAIN_PATH="${GNUARMEMB_TOOLCHAIN_PATH:-${TOOLCHAIN_PATH:-}}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zephyr-ws)
            [[ $# -ge 2 ]] || { echo "ERROR: --zephyr-ws requires a value" >&2; usage; exit 1; }
            ZEPHYR_WS="$2"
            shift 2
            ;;
        --zephyr-venv)
            [[ $# -ge 2 ]] || { echo "ERROR: --zephyr-venv requires a value" >&2; usage; exit 1; }
            ZEPHYR_VENV="$2"
            shift 2
            ;;
        --toolchain-path|--gnuarmemb-toolchain-path)
            [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; usage; exit 1; }
            TOOLCHAIN_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${ZEPHYR_WS}" ]]; then
    echo "ERROR: ZEPHYR_WS is not set (pass --zephyr-ws <dir> or export ZEPHYR_WS)" >&2
    exit 1
fi
if [[ -z "${ZEPHYR_VENV}" ]]; then
    echo "ERROR: ZEPHYR_VENV is not set (pass --zephyr-venv <dir> or export ZEPHYR_VENV)" >&2
    exit 1
fi
if [[ -z "${TOOLCHAIN_PATH}" ]]; then
    echo "ERROR: GNUARMEMB_TOOLCHAIN_PATH / TOOLCHAIN_PATH is not set (pass --toolchain-path <dir> or export GNUARMEMB_TOOLCHAIN_PATH)" >&2
    exit 1
fi

MCUBOOT_SRC="${ZEPHYR_WS}/bootloader/mcuboot"
WEST="${ZEPHYR_VENV}/bin/west"
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"

require_file "${WEST}"
require_file "${STRIP_BIN}"
require_file "${MCUBOOT_SRC}/scripts/imgtool.py"

rm -rf "${BUILD_ROOT}"
mkdir -p "${ASSETS_DIR}" "${BUILD_ROOT}" "${OVERLAY_DIR}"

MCUBOOT_COMMIT="$(git -C "${MCUBOOT_SRC}" rev-parse HEAD)"
ZEPHYR_COMMIT="$(git -C "${ZEPHYR_WS}/zephyr" rev-parse HEAD)"
msg "MCUboot commit: ${MCUBOOT_COMMIT}"
msg "Zephyr commit:  ${ZEPHYR_COMMIT}"

echo "${MCUBOOT_COMMIT}" > "${ASSETS_DIR}/mcuboot_stm32f103_commit.txt"
echo "${MCUBOOT_COMMIT}" > "${ASSETS_DIR}/mcuboot_stm32l476_commit.txt"

# Copy MCUboot source into our own build directory so the shared workspace
# remains strictly read-only while applying Zephyr 3.7 module/Kconfig shims.
MCUBOOT_REPO="${BUILD_ROOT}/mcuboot"
rsync -a --exclude='.git' "${MCUBOOT_SRC}/" "${MCUBOOT_REPO}/"
IMGTOOL_PY="${MCUBOOT_REPO}/scripts/imgtool.py"

MODULE_YML="${MCUBOOT_REPO}/zephyr/module.yml"
if grep -q 'package-managers' "${MODULE_YML}" 2>/dev/null; then
    msg "Stripping unsupported 'package-managers' from local module.yml copy"
    sed -i.bak '/^package-managers:/,/^[^ ]/{ /^package-managers:/d; /^  /d; }' "${MODULE_YML}"
    rm -f "${MODULE_YML}.bak"
fi

MCUBOOT_KCONFIG="${MCUBOOT_REPO}/boot/zephyr/Kconfig"
if grep -q '^config MBEDTLS_CONFIG_FILE$' "${MCUBOOT_KCONFIG}" && \
   ! awk '
       /^config MBEDTLS_CONFIG_FILE$/ { in_symbol = 1; next }
       in_symbol && /^config / { exit }
       in_symbol && /^[[:space:]]*(bool|string|int|hex|tristate)([[:space:]]|$)/ {
           found = 1; exit
       }
       END { exit found ? 0 : 1 }
   ' "${MCUBOOT_KCONFIG}"; then
    msg "Adding Zephyr 3.7 type compatibility for MBEDTLS_CONFIG_FILE"
    sed -i.bak '/^config MBEDTLS_CONFIG_FILE$/a\
    string "Mbed TLS configuration header"' "${MCUBOOT_KCONFIG}"
    rm -f "${MCUBOOT_KCONFIG}.bak"
fi

if grep -q '^config USBD_DFU_NUMOF_IMAGES$' "${MCUBOOT_KCONFIG}" && \
   ! awk '
       /^config USBD_DFU_NUMOF_IMAGES$/ { in_symbol = 1; next }
       in_symbol && /^config / { exit }
       in_symbol && /^[[:space:]]*(bool|string|int|hex|tristate)([[:space:]]|$)/ {
           found = 1; exit
       }
       END { exit found ? 0 : 1 }
   ' "${MCUBOOT_KCONFIG}"; then
    msg "Adding Zephyr 3.7 types for current USB DFU defaults"
    sed -i.bak '/^config USBD_DFU_NUMOF_IMAGES$/a\
    int' "${MCUBOOT_KCONFIG}"
    sed -i.bak '/^config USBD_DFU_ENABLE_UPLOAD$/a\
    bool' "${MCUBOOT_KCONFIG}"
    sed -i.bak '/^config USBD_DFU_FLASH_SLOT0$/a\
    bool' "${MCUBOOT_KCONFIG}"
    rm -f "${MCUBOOT_KCONFIG}.bak"
fi

if grep -q '^choice MBEDTLS_PSA_CRYPTO_RNG_SOURCE$' "${MCUBOOT_KCONFIG}"; then
    msg "Removing inactive newer-Zephyr Mbed TLS PSA RNG choice"
    sed -i.bak \
        '/^choice MBEDTLS_PSA_CRYPTO_RNG_SOURCE$/,/^endchoice$/d' \
        "${MCUBOOT_KCONFIG}"
    rm -f "${MCUBOOT_KCONFIG}.bak"
fi

ZEPHYR_MODULES_LIST="${MCUBOOT_REPO};${ZEPHYR_WS}/modules/hal/cmsis;${ZEPHYR_WS}/modules/hal/stm32"

# 1. STM32F103RB (nucleo_f103rb): 128 KiB flash, 1 KiB pages, 2-byte half-word writes.
#    boot:    0x00000..0x07FFF (32 KiB)
#    slot0:   0x08000..0x0FFFF (32 KiB)
#    slot1:   0x10000..0x17FFF (32 KiB)
#    storage: 0x18000..0x1FFFF (32 KiB)
cat > "${OVERLAY_DIR}/stm32f103_move.dts" <<'DTS'
&iwdg {
    status = "disabled";
};

&flash0 {
    /delete-node/ partitions;

    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x00000000 0x00008000>;
        };
        slot0_partition: partition@8000 {
            label = "image-0";
            reg = <0x00008000 0x00008000>;
        };
        slot1_partition: partition@10000 {
            label = "image-1";
            reg = <0x00010000 0x00008000>;
        };
        storage_partition: partition@18000 {
            label = "storage";
            reg = <0x00018000 0x00008000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# 2. STM32L476RG (nucleo_l476rg): 1 MiB dual-bank flash, 2 KiB pages, 8-byte double-word writes.
#    boot:    0x00000..0x0FFFF (64 KiB, Bank 1)
#    slot0:   0x10000..0x1FFFF (64 KiB, Bank 1, BKER=0)
#    slot1:   0x80000..0x8FFFF (64 KiB, Bank 2, BKER=1)
#    storage: 0x90000..0x9FFFF (64 KiB, Bank 2)
cat > "${OVERLAY_DIR}/stm32l476_move.dts" <<'DTS'
&lptim1 {
    status = "disabled";
};

&flash0 {
    /delete-node/ partitions;

    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x00000000 0x00010000>;
        };
        slot0_partition: partition@10000 {
            label = "image-0";
            reg = <0x00010000 0x00010000>;
        };
        slot1_partition: partition@80000 {
            label = "image-1";
            reg = <0x00080000 0x00010000>;
        };
        storage_partition: partition@90000 {
            label = "storage";
            reg = <0x00090000 0x00010000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

build_mcuboot() {
    local name="$1"
    local board="$2"
    local overlay="$3"
    shift 3
    local extra_cmake=("$@")

    local out_build="${BUILD_ROOT}/mcuboot_${name}"
    local out_elf="${ASSETS_DIR}/mcuboot_${name}.elf"

    msg "Building MCUboot for ${name} (board=${board})"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
          -d "${out_build}" \
          -p always \
          -b "${board}" \
          "${MCUBOOT_REPO}/boot/zephyr" \
          -- \
          "-DZEPHYR_MODULES=${ZEPHYR_MODULES_LIST}" \
          -DDTC_OVERLAY_FILE="${overlay}" \
          -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
          -DCONFIG_BOOT_SWAP_USING_MOVE=y \
          -DCONFIG_BOOT_UPGRADE_ONLY=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS=128 \
          -DCONFIG_BOOT_WATCHDOG_FEED=n \
          -DCONFIG_IWDG_STM32=n \
          -DCONFIG_CORTEX_M_SYSTICK=y \
          -DCONFIG_MAIN_STACK_SIZE=4096 \
          -DCONFIG_BOOTLOADER_SRAM_SIZE=16 \
          -DCONFIG_LOG=n \
          -DCONFIG_SERIAL=n \
          -DCONFIG_CONSOLE=n \
          -DCONFIG_UART_CONSOLE=n \
          -DCONFIG_GPIO=n \
          -DCONFIG_SPI=n \
          -DCONFIG_I2C=n \
          -DCONFIG_PWM=n \
          -DCONFIG_ADC=n \
          -DCONFIG_RTC=n \
          -DCONFIG_DMA=n \
          -DCONFIG_PINCTRL=n \
          -DCONFIG_MULTITHREADING=n \
          -DCONFIG_WARN_DEPRECATED=n \
          -DCONFIG_USE_SEGGER_RTT=n \
          -DCONFIG_MINIMAL_LIBC=y \
          -DCONFIG_PICOLIBC=n \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          "-DPython3_EXECUTABLE:FILEPATH=${IMGTOOL_PYTHON}" \
          "${extra_cmake[@]}"
    )

    cp "${out_build}/zephyr/zephyr.elf" "${out_elf}"
    "${STRIP_BIN}" -g "${out_elf}"
    msg "Wrote ${out_elf}"
}

build_test_app() {
    local name="$1"
    local board="$2"
    local mcuboot_overlay="$3"
    shift 3
    local extra_cmake=("$@")

    local out_build="${BUILD_ROOT}/app_${name}"
    local app_overlay="${OVERLAY_DIR}/app_${name}.dts"
    sed 's/zephyr,code-partition = &boot_partition/zephyr,code-partition = \&slot0_partition/' \
        "${mcuboot_overlay}" > "${app_overlay}"

    msg "Building Zephyr hello_world app for ${name} (board=${board})"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${TOOLCHAIN_PATH}" \
        "${WEST}" build \
          -d "${out_build}" \
          -p always \
          -b "${board}" \
          "${ZEPHYR_WS}/zephyr/samples/hello_world" \
          -- \
          "-DZEPHYR_MODULES=${ZEPHYR_MODULES_LIST}" \
          -DDTC_OVERLAY_FILE="${app_overlay}" \
          -DCONFIG_BOOTLOADER_MCUBOOT=y \
          -DCONFIG_SYS_CLOCK_EXISTS=n \
          -DCONFIG_CORTEX_M_SYSTICK=n \
          -DCONFIG_IWDG_STM32=n \
          -DCONFIG_SERIAL=n \
          -DCONFIG_CONSOLE=n \
          -DCONFIG_UART_CONSOLE=n \
          -DCONFIG_PRINTK=n \
          -DCONFIG_BOOT_BANNER=n \
          -DCONFIG_GPIO=n \
          -DCONFIG_SPI=n \
          -DCONFIG_I2C=n \
          -DCONFIG_PWM=n \
          -DCONFIG_ADC=n \
          -DCONFIG_RTC=n \
          -DCONFIG_DMA=n \
          -DCONFIG_PINCTRL=n \
          -DCONFIG_MULTITHREADING=n \
          -DCONFIG_USE_SEGGER_RTT=n \
          -DCONFIG_MINIMAL_LIBC=y \
          -DCONFIG_PICOLIBC=n \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          "-DPython3_EXECUTABLE:FILEPATH=${IMGTOOL_PYTHON}" \
          "${extra_cmake[@]}"
    )
}

app_rom_start_offset() {
    local config="$1"
    local value
    require_file "${config}"
    value="$(sed -n 's/^CONFIG_ROM_START_OFFSET=//p' "${config}")"
    if [[ ! "${value}" =~ ^0x[0-9a-fA-F]+$ ]]; then
        echo "ERROR: ${config} has no hex CONFIG_ROM_START_OFFSET (got '${value}')" >&2
        exit 1
    fi
    echo "${value}"
}

sign_image() {
    local name="$1"
    local slot_size="$2"
    local version="$3"
    local out_name="$4"
    local pad_extra="${5:-0}"
    local align="${6:-8}"

    local bin="${BUILD_ROOT}/app_${name}/zephyr/zephyr.bin"
    local app_config="${BUILD_ROOT}/app_${name}/zephyr/.config"
    local out="${ASSETS_DIR}/${out_name}"
    local header_size
    header_size="$(app_rom_start_offset "${app_config}")"

    local sign_input="${bin}"
    if (( pad_extra > 0 )); then
        local tmp="${BUILD_ROOT}/app_${name}_${version}.bin"
        cp "${bin}" "${tmp}"
        dd if=/dev/zero bs=1 count="${pad_extra}" >> "${tmp}" 2>/dev/null
        sign_input="${tmp}"
    fi

    "${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
      --align "${align}" \
      --header-size "${header_size}" \
      --slot-size "${slot_size}" \
      --version "${version}" \
      "${sign_input}" "${out}"

    "${IMGTOOL_PYTHON}" "${SCRIPT_DIR}/check_mcuboot_image_vectors.py" \
      --image "${out}" --app-config "${app_config}"

    local sz
    sz="$(wc -c < "${out}" | tr -d ' ')"
    msg "Signed image: ${out} (${sz} bytes, slot=${slot_size}, align=${align}, header=${header_size})"
}

# Build STM32F103RB
build_mcuboot "stm32f103" "nucleo_f103rb" "${OVERLAY_DIR}/stm32f103_move.dts"
build_test_app "stm32f103" "nucleo_f103rb" "${OVERLAY_DIR}/stm32f103_move.dts"
sign_image "stm32f103" "0x8000" "1.0.0+0" "zephyr_stm32f103_slot0.bin" 0 8
sign_image "stm32f103" "0x8000" "1.1.0+0" "zephyr_stm32f103_slot1.bin" 1024 8

# Build STM32L476RG
build_mcuboot "stm32l476" "nucleo_l476rg" "${OVERLAY_DIR}/stm32l476_move.dts" \
    -DCONFIG_STM32_LPTIM_TIMER=n
build_test_app "stm32l476" "nucleo_l476rg" "${OVERLAY_DIR}/stm32l476_move.dts" \
    -DCONFIG_STM32_LPTIM_TIMER=n
sign_image "stm32l476" "0x10000" "1.0.0+0" "zephyr_stm32l476_slot0.bin" 0 8
sign_image "stm32l476" "0x10000" "1.1.0+0" "zephyr_stm32l476_slot1.bin" 2048 8

rm -rf "${BUILD_ROOT}"
msg "=== STM32F103 & STM32L476 MCUboot targets built successfully ==="
ls -lh "${ASSETS_DIR}"/mcuboot_stm32f103* "${ASSETS_DIR}"/mcuboot_stm32l476* \
       "${ASSETS_DIR}"/zephyr_stm32f103_* "${ASSETS_DIR}"/zephyr_stm32l476_*
