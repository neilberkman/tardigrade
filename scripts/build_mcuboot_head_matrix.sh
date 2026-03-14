#!/usr/bin/env bash
# Build MCUboot HEAD for zero-day hunt matrix.
# Produces ELFs and test images for 6 configurations:
#   1. head_move_nrf52      - swap-move, nrf52840dk, default geometry
#   2. head_scratch_nrf52   - swap-scratch, nrf52840dk, default geometry
#   3. head_move_stm32f4    - swap-move, nucleo_f429zi, non-uniform sectors
#   4. head_scratch_stm32f4 - swap-scratch, nucleo_f429zi, non-uniform sectors
#   5. head_move_small      - swap-move, nrf52840dk, 128KB slots
#   6. head_scratch_small   - swap-scratch, nrf52840dk, 128KB+4KB scratch
#
# Each config gets two DIFFERENT-SIZED test images to expose geometry bugs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ZEPHYR_WS="${REPO_ROOT}/third_party/zephyr_ws"
ZEPHYR_VENV="${REPO_ROOT}/third_party/zephyr-venv"
MCUBOOT_REPO="${ZEPHYR_WS}/bootloader/mcuboot"
ASSETS_DIR="${REPO_ROOT}/results/oss_validation/assets"
BUILD_DIR="${REPO_ROOT}/results/oss_validation/build"
WEST="${ZEPHYR_VENV}/bin/west"
IMGTOOL_PY="${MCUBOOT_REPO}/scripts/imgtool.py"
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"

# Auto-detect toolchain: prefer External SSD copy, fall back to ~/tools
if [[ -d "/Volumes/External SSD/tardigrade/tools/arm-gnu-toolchain" ]]; then
    TOOLCHAIN_PATH="/Volumes/External SSD/tardigrade/tools/arm-gnu-toolchain"
elif [[ -d "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major" ]]; then
    TOOLCHAIN_PATH="${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major"
else
    echo "ERROR: no ARM toolchain found" >&2; exit 1
fi
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"

msg() { echo ">> $*" >&2; }

require_file() {
    if [[ ! -e "$1" ]]; then
        echo "ERROR: missing required path: $1" >&2; exit 1
    fi
}

require_file "${WEST}"
require_file "${STRIP_BIN}"

mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}"

# Record MCUboot HEAD commit for reproducibility.
MCUBOOT_HEAD="$(git -C "${MCUBOOT_REPO}" rev-parse HEAD)"
msg "MCUboot HEAD: ${MCUBOOT_HEAD}"
echo "${MCUBOOT_HEAD}" > "${ASSETS_DIR}/mcuboot_head_commit.txt"

# Patch module.yml if it has 'package-managers' (unsupported by Zephyr < 4.0).
MODULE_YML="${MCUBOOT_REPO}/zephyr/module.yml"
if grep -q 'package-managers' "${MODULE_YML}" 2>/dev/null; then
    msg "Stripping unsupported 'package-managers' from module.yml"
    sed -i.bak '/^package-managers:/,/^[^ ]/{ /^package-managers:/d; /^  /d; }' "${MODULE_YML}"
fi

# --- DTS overlays ---

# nrf52840dk scratch overlay: redefine partitions with scratch + code-partition
cat > "${BUILD_DIR}/nrf52_scratch.dts" <<'DTS'
/ {
    /delete-node/ partitions;
};

&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0xc000>;
        };
        slot0_partition: partition@c000 {
            label = "image-0";
            reg = <0xc000 0x6e000>;
        };
        slot1_partition: partition@7a000 {
            label = "image-1";
            reg = <0x7a000 0x6e000>;
        };
        scratch_partition: partition@e8000 {
            label = "image-scratch";
            reg = <0xe8000 0x10000>;
        };
        storage_partition: partition@f8000 {
            label = "storage";
            reg = <0xf8000 0x8000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# nrf52840dk small-slot move overlay: 128KB slots
cat > "${BUILD_DIR}/nrf52_small_move.dts" <<'DTS'
/ {
    /delete-node/ partitions;
};

&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0xc000>;
        };
        slot0_partition: partition@c000 {
            label = "image-0";
            reg = <0xc000 0x20000>;
        };
        slot1_partition: partition@2c000 {
            label = "image-1";
            reg = <0x2c000 0x20000>;
        };
        storage_partition: partition@4c000 {
            label = "storage";
            reg = <0x4c000 0x8000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# nrf52840dk small-slot scratch overlay: 128KB slots + 4KB scratch
cat > "${BUILD_DIR}/nrf52_small_scratch.dts" <<'DTS'
/ {
    /delete-node/ partitions;
};

&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0xc000>;
        };
        slot0_partition: partition@c000 {
            label = "image-0";
            reg = <0xc000 0x20000>;
        };
        slot1_partition: partition@2c000 {
            label = "image-1";
            reg = <0x2c000 0x20000>;
        };
        scratch_partition: partition@4c000 {
            label = "image-scratch";
            reg = <0x4c000 0x1000>;
        };
        storage_partition: partition@4d000 {
            label = "storage";
            reg = <0x4d000 0x8000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# STM32F4 (nucleo_f429zi) swap-move overlay
cat > "${BUILD_DIR}/stm32f4_move.dts" <<'DTS'
/ {
    /delete-node/ partitions;
};

&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0x20000>;
        };
        slot0_partition: partition@20000 {
            label = "image-0";
            reg = <0x20000 0x60000>;
        };
        slot1_partition: partition@80000 {
            label = "image-1";
            reg = <0x80000 0x60000>;
        };
        storage_partition: partition@e0000 {
            label = "storage";
            reg = <0xe0000 0x20000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# STM32F4 (nucleo_f429zi) swap-scratch overlay
cat > "${BUILD_DIR}/stm32f4_scratch.dts" <<'DTS'
/ {
    /delete-node/ partitions;
};

&flash0 {
    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0x20000>;
        };
        slot0_partition: partition@20000 {
            label = "image-0";
            reg = <0x20000 0x58000>;
        };
        slot1_partition: partition@78000 {
            label = "image-1";
            reg = <0x78000 0x58000>;
        };
        scratch_partition: partition@d0000 {
            label = "image-scratch";
            reg = <0xd0000 0x10000>;
        };
        storage_partition: partition@e0000 {
            label = "storage";
            reg = <0xe0000 0x20000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# --- Build functions ---

build_mcuboot() {
    local name="$1"
    local board="$2"
    local overlay="$3"
    shift 3
    local extra_cmake=("$@")

    local out_build="${BUILD_DIR}/head_${name}"
    local out_elf="${ASSETS_DIR}/oss_mcuboot_head_${name}.elf"

    msg "Building head_${name} (board=${board})"
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
          -DDTC_OVERLAY_FILE="${overlay}" \
          -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
          -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
          -DCONFIG_BOOT_MAX_IMG_SECTORS=1024 \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          -DPython3_EXECUTABLE:FILEPATH="${IMGTOOL_PYTHON}" \
          "${extra_cmake[@]}"
    )

    cp "${out_build}/zephyr/zephyr.elf" "${out_elf}"
    "${STRIP_BIN}" -g "${out_elf}"
    msg "Wrote ${out_elf}"
}

build_test_app() {
    local name="$1"
    local board="$2"
    local overlay="$3"

    local out_build="${BUILD_DIR}/hello_${name}"

    msg "Building hello_world for ${name} (board=${board})"
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
          -DDTC_OVERLAY_FILE="${overlay}" \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          -DPython3_EXECUTABLE:FILEPATH="${IMGTOOL_PYTHON}"
    )
}

sign_image() {
    local name="$1"
    local slot_size="$2"
    local version="$3"
    local out_name="$4"
    local payload_size="${5:-}"

    local hex="${BUILD_DIR}/hello_${name}/zephyr/zephyr.hex"
    local bin="${BUILD_DIR}/hello_${name}/zephyr/zephyr.bin"
    local out="${ASSETS_DIR}/${out_name}"

    local sign_input="${bin}"
    if [[ -n "${payload_size}" ]]; then
        # Truncate or pad to exact size for different-sized image pair
        local tmp="/tmp/zephyr_head_${name}_${version}.bin"
        dd if="${bin}" of="${tmp}" bs=1 count="${payload_size}" 2>/dev/null
        local actual
        actual=$(wc -c < "${tmp}" | tr -d ' ')
        if (( actual < payload_size )); then
            dd if=/dev/zero bs=1 count=$((payload_size - actual)) >> "${tmp}" 2>/dev/null
        fi
        sign_input="${tmp}"
    fi

    "${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
      --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
      --align 8 \
      --header-size 0x200 \
      --slot-size "${slot_size}" \
      --pad-header \
      --pad \
      --confirm \
      --version "${version}" \
      "${sign_input}" "${out}"

    msg "Signed image: ${out} (slot=${slot_size})"
}

# --- 1. head_move_nrf52: swap-move, nrf52840dk, default geometry ---
# Default nrf52840dk: slot0 @ 0xC000 (0x76000), slot1 @ 0x82000 (0x76000)
cat > "${BUILD_DIR}/nrf52_move_default.dts" <<'DTS'
/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

build_mcuboot "move_nrf52" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_move_default.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y

build_test_app "move_nrf52" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_move_default.dts"
sign_image "move_nrf52" "0x76000" "1.0.0+0" "zephyr_head_move_nrf52_slot0.bin"
sign_image "move_nrf52" "0x76000" "1.1.0+0" "zephyr_head_move_nrf52_slot1.bin" "36864"

# --- 2. head_scratch_nrf52: swap-scratch, nrf52840dk ---
# Slots: 0x6E000 (440KB) each, scratch: 0x10000 (64KB)
build_mcuboot "scratch_nrf52" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_nrf52" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_scratch.dts"
sign_image "scratch_nrf52" "0x6e000" "1.0.0+0" "zephyr_head_scratch_nrf52_slot0.bin"
sign_image "scratch_nrf52" "0x6e000" "1.1.0+0" "zephyr_head_scratch_nrf52_slot1.bin" "36864"

# --- 3. head_move_stm32f4: swap-move, nucleo_f429zi, non-uniform sectors ---
# Slots: 0x60000 (384KB) each
build_mcuboot "move_stm32f4" "nucleo_f429zi" "${BUILD_DIR}/stm32f4_move.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y

build_test_app "move_stm32f4" "nucleo_f429zi" "${BUILD_DIR}/stm32f4_move.dts"
sign_image "move_stm32f4" "0x60000" "1.0.0+0" "zephyr_head_move_stm32f4_slot0.bin"
sign_image "move_stm32f4" "0x60000" "1.1.0+0" "zephyr_head_move_stm32f4_slot1.bin" "36864"

# --- 4. head_scratch_stm32f4: swap-scratch, nucleo_f429zi ---
# Slots: 0x58000 (352KB) each, scratch: 0x10000 (64KB)
build_mcuboot "scratch_stm32f4" "nucleo_f429zi" "${BUILD_DIR}/stm32f4_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_stm32f4" "nucleo_f429zi" "${BUILD_DIR}/stm32f4_scratch.dts"
sign_image "scratch_stm32f4" "0x58000" "1.0.0+0" "zephyr_head_scratch_stm32f4_slot0.bin"
sign_image "scratch_stm32f4" "0x58000" "1.1.0+0" "zephyr_head_scratch_stm32f4_slot1.bin" "36864"

# --- 5. head_move_small: swap-move, nrf52840dk, 128KB slots ---
# Slots: 0x20000 (128KB) each
build_mcuboot "move_small" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_small_move.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y

build_test_app "move_small" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_small_move.dts"
sign_image "move_small" "0x20000" "1.0.0+0" "zephyr_head_move_small_slot0.bin"
sign_image "move_small" "0x20000" "1.1.0+0" "zephyr_head_move_small_slot1.bin" "16384"

# --- 6. head_scratch_small: swap-scratch, nrf52840dk, 128KB + 4KB scratch ---
# Slots: 0x20000 (128KB) each, scratch: 0x1000 (4KB)
build_mcuboot "scratch_small" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_small_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_small" "nrf52840dk/nrf52840" "${BUILD_DIR}/nrf52_small_scratch.dts"
sign_image "scratch_small" "0x20000" "1.0.0+0" "zephyr_head_scratch_small_slot0.bin"
sign_image "scratch_small" "0x20000" "1.1.0+0" "zephyr_head_scratch_small_slot1.bin" "16384"

msg "=== MCUboot HEAD matrix build complete ==="
msg "MCUboot commit: ${MCUBOOT_HEAD}"
msg "Assets in: ${ASSETS_DIR}"
ls -la "${ASSETS_DIR}"/oss_mcuboot_head_*.elf
ls -la "${ASSETS_DIR}"/zephyr_head_*.bin
