#!/usr/bin/env bash
# Build MCUboot HEAD for zero-day hunt matrix.
# Produces ELFs and test images for 9 MCUboot configurations:
#   1. head_move_nrf52      - swap-move, nrf52840dk, default geometry
#   2. head_scratch_nrf52   - swap-scratch, nrf52840dk, default geometry
#   3. head_move_stm32f4    - swap-move, nucleo_f429zi, non-uniform sectors
#   4. head_scratch_stm32f4 - swap-scratch, nucleo_f429zi, non-uniform sectors
#   5. head_move_small      - swap-move, nrf52840dk, 128KB slots
#   6. head_scratch_small   - swap-scratch, nrf52840dk, 128KB+4KB scratch
#   7. head_offset_nrf52    - offset metadata, nrf52840dk
#   8. head_offset_stm32f4 - offset metadata, nucleo_f429zi
#   9. head_offset_small    - offset metadata, nrf52840dk, 128KB slots
#
# Auxiliary PR-2206 geometry images are generated between configurations 4
# and 5; they do not add a separate MCUboot build configuration.
#
# Each config gets two DIFFERENT-SIZED test images to expose geometry bugs.
set -euo pipefail

msg() { echo ">> $*" >&2; }

require_file() {
    if [[ ! -e "$1" ]]; then
        echo "ERROR: missing required path: $1" >&2; exit 1
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/results/oss_validation/assets"
BUILD_DIR="${REPO_ROOT}/results/oss_validation/build"

# CMake/DTC/GCC all choke on spaces in paths (e.g. "/Volumes/External SSD/").
# The Zephyr workspace MUST live on a space-free path. Check /tmp first
# (where we move it on External SSD setups), then fall back to repo-local.
if [[ -d "/tmp/mcuboot_build/zephyr_ws" ]]; then
    ZEPHYR_WS="/tmp/mcuboot_build/zephyr_ws"
    ZEPHYR_VENV="/tmp/mcuboot_build/zephyr-venv"
    msg "Using space-free workspace at ${ZEPHYR_WS}"
elif [[ -d "${REPO_ROOT}/third_party/zephyr_ws" ]]; then
    ZEPHYR_WS="${REPO_ROOT}/third_party/zephyr_ws"
    ZEPHYR_VENV="${REPO_ROOT}/third_party/zephyr-venv"
    if [[ "${ZEPHYR_WS}" == *" "* ]]; then
        echo "ERROR: Zephyr workspace is on a path with spaces: ${ZEPHYR_WS}" >&2
        echo "Move it to /tmp/mcuboot_build/zephyr_ws first." >&2
        exit 1
    fi
else
    echo "ERROR: no Zephyr workspace found. Run bootstrap_mcuboot_matrix_assets.sh first." >&2
    exit 1
fi

MCUBOOT_REPO="${ZEPHYR_WS}/bootloader/mcuboot"
IMGTOOL_PY="${MCUBOOT_REPO}/scripts/imgtool.py"
OVERLAY_DIR="$(mktemp -d /tmp/mcuboot_head_overlays.XXXXXX)"
BUILD_TMP="$(mktemp -d /tmp/mcuboot_head_builds.XXXXXX)"
WEST="${ZEPHYR_VENV}/bin/west"
IMGTOOL_PYTHON="${ZEPHYR_VENV}/bin/python3"
MCUBOOT_REMOTE="${MCUBOOT_REMOTE:-mcu-tools}"
# Public revision used by the checked-in HEAD corpus. Override MCUBOOT_REF to
# test another revision against the pinned Zephyr workspace.
MCUBOOT_REF="${MCUBOOT_REF:-f84b9d3fd019fb1945e532924bee7a9c03c77373}"
ORIGINAL_MCUBOOT_HEAD="$(git -C "${MCUBOOT_REPO}" rev-parse HEAD)"
MCUBOOT_CHECKED_OUT=false

cleanup() {
    if [[ "${MCUBOOT_CHECKED_OUT}" == "true" ]]; then
        git -C "${MCUBOOT_REPO}" restore --worktree -- \
            zephyr/module.yml boot/zephyr/Kconfig >/dev/null 2>&1 || true
        git -C "${MCUBOOT_REPO}" checkout --quiet --detach "${ORIGINAL_MCUBOOT_HEAD}" || true
    fi
    rm -f "${MCUBOOT_REPO}/zephyr/module.yml.bak"
    rm -rf "${OVERLAY_DIR}" "${BUILD_TMP}"
}
trap cleanup EXIT

# Auto-detect toolchain: honor explicit override first, then prefer External
# SSD copy, then fall back to common local install paths.
if [[ -n "${GNUARMEMB_TOOLCHAIN_PATH:-}" ]]; then
    TOOLCHAIN_PATH="${GNUARMEMB_TOOLCHAIN_PATH}"
elif [[ -d "/Volumes/External SSD/tardigrade/tools/arm-gnu-toolchain" ]]; then
    ln -sfn "/Volumes/External SSD/tardigrade/tools/arm-gnu-toolchain" /tmp/arm-toolchain
    TOOLCHAIN_PATH="/tmp/arm-toolchain"
elif [[ -d "${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major" ]]; then
    TOOLCHAIN_PATH="${HOME}/tools/gcc-arm-none-eabi-8-2018-q4-major"
else
    echo "ERROR: no ARM toolchain found" >&2; exit 1
fi
STRIP_BIN="${TOOLCHAIN_PATH}/bin/arm-none-eabi-strip"

require_file "${WEST}"
require_file "${STRIP_BIN}"

mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}"

# Resolve and check out the current public MCUboot head, then record the exact
# commit for reproducibility. The original west-managed revision is restored
# by the EXIT trap.
if ! git -C "${MCUBOOT_REPO}" diff --quiet || \
   ! git -C "${MCUBOOT_REPO}" diff --cached --quiet; then
    echo "ERROR: MCUboot workspace has local changes" >&2
    exit 1
fi
MCUBOOT_FETCH_REF="${MCUBOOT_REF}"
if [[ "${MCUBOOT_FETCH_REF}" == "${MCUBOOT_REMOTE}/"* ]]; then
    MCUBOOT_FETCH_REF="${MCUBOOT_FETCH_REF#${MCUBOOT_REMOTE}/}"
fi
git -C "${MCUBOOT_REPO}" fetch --quiet "${MCUBOOT_REMOTE}" "${MCUBOOT_FETCH_REF}"
git -C "${MCUBOOT_REPO}" checkout --quiet --detach "${MCUBOOT_REF}"
MCUBOOT_CHECKED_OUT=true

MCUBOOT_HEAD="$(git -C "${MCUBOOT_REPO}" rev-parse HEAD)"
msg "MCUboot HEAD: ${MCUBOOT_HEAD}"
echo "${MCUBOOT_HEAD}" > "${ASSETS_DIR}/mcuboot_head_commit.txt"

# Patch module.yml if it has 'package-managers' (unsupported by Zephyr < 4.0).
MODULE_YML="${MCUBOOT_REPO}/zephyr/module.yml"
if grep -q 'package-managers' "${MODULE_YML}" 2>/dev/null; then
    msg "Stripping unsupported 'package-managers' from module.yml"
    sed -i.bak '/^package-managers:/,/^[^ ]/{ /^package-managers:/d; /^  /d; }' "${MODULE_YML}"
fi

# MCUboot main extends this symbol from newer Zephyr releases. Zephyr 3.7,
# which this repository pins for reproducible builds, predates that symbol and
# therefore needs a local type declaration while configuring the dependency.
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

# --- DTS overlays ---

# nrf52840dk scratch overlay: redefine partitions with scratch + code-partition
cat > "${OVERLAY_DIR}/nrf52_scratch.dts" <<'DTS'
&flash0 {
    /delete-node/ partitions;

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
cat > "${OVERLAY_DIR}/nrf52_small_move.dts" <<'DTS'
&flash0 {
    /delete-node/ partitions;

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
cat > "${OVERLAY_DIR}/nrf52_small_scratch.dts" <<'DTS'
&flash0 {
    /delete-node/ partitions;

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
cat > "${OVERLAY_DIR}/stm32f4_move.dts" <<'DTS'
&flash0 {
    /delete-node/ partitions;

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

# STM32F4 (nucleo_f429zi) swap-scratch overlay.
# The two slots mirror the 16K/16K/64K/128K sector sequence across the
# STM32F429's two flash banks; scratch and storage each start on a sector.
cat > "${OVERLAY_DIR}/stm32f4_scratch.dts" <<'DTS'
&flash0 {
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
            reg = <0x08000 0x38000>;
        };
        slot1_partition: partition@108000 {
            label = "image-1";
            reg = <0x108000 0x38000>;
        };
        scratch_partition: partition@40000 {
            label = "image-scratch";
            reg = <0x40000 0x20000>;
        };
        storage_partition: partition@60000 {
            label = "storage";
            reg = <0x60000 0xA0000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

# STM32F4 (nucleo_f429zi) swap-offset overlay on the tracked 1 MiB layout.
cat > "${OVERLAY_DIR}/stm32f4_offset.dts" <<'DTS'
&flash0 {
    /delete-node/ partitions;

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

# STM32F4 (nucleo_f429zi) PR2206-specific swap-scratch overlay.
# Mirror the low-bank 16K/16K/64K sector pattern into bank 2 so scratch swap
# can match cumulative primary/secondary sizes while BOOT_MAX_IMG_SECTORS
# still pushes the trailer past the primary tail sector boundary.
cat > "${OVERLAY_DIR}/stm32f4_pr2206_scratch.dts" <<'DTS'
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
DTS

# --- Build functions ---

build_mcuboot() {
    local name="$1"
    local board="$2"
    local overlay="$3"
    shift 3
    local extra_cmake=("$@")

    local out_build="${BUILD_TMP}/head_${name}"
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
          -DCONFIG_BOOTLOADER_SRAM_SIZE=64 \
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

    local out_build="${BUILD_TMP}/hello_${name}"

    # Create app overlay: same partition layout as MCUboot but link at slot0.
    local app_overlay="${OVERLAY_DIR}/app_${name}.dts"
    sed 's/zephyr,code-partition = &boot_partition/zephyr,code-partition = \&slot0_partition/' \
        "${mcuboot_overlay}" > "${app_overlay}"

    msg "Building hello_world for ${name} (board=${board})"
    # CONFIG_BOOTLOADER_MCUBOOT=y reserves header space (0x200) in the binary
    # and links code at slot0_base + 0x200. Do NOT also use --pad-header in
    # imgtool or you get a double header.
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
          -DDTC_OVERLAY_FILE="${app_overlay}" \
          -DCONFIG_BOOTLOADER_MCUBOOT=y \
          -DCONFIG_USE_SEGGER_RTT=n \
          -DCONFIG_MINIMAL_LIBC=y \
          -DCONFIG_PICOLIBC=n \
          -DCMAKE_GDB:FILEPATH="${TOOLCHAIN_PATH}/bin/arm-none-eabi-gdb" \
          "-DPython3_EXECUTABLE:FILEPATH=${IMGTOOL_PYTHON}"
    )
}

sign_image() {
    local name="$1"
    local slot_size="$2"
    local version="$3"
    local out_name="$4"
    local payload_size="${5:-}"
    local align="${6:-8}"

    local hex="${BUILD_TMP}/hello_${name}/zephyr/zephyr.hex"
    local bin="${BUILD_TMP}/hello_${name}/zephyr/zephyr.bin"
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

    # App binary built with CONFIG_BOOTLOADER_MCUBOOT=y already reserves
    # 0x200 bytes for the header. Do NOT use --pad-header (double header).
    # Do NOT use --pad (fills to slot size, makes image huge and swap slow).
    # Profile system handles update_trigger (trailer magic) separately.
    "${IMGTOOL_PYTHON}" "${IMGTOOL_PY}" sign \
      --key "${MCUBOOT_REPO}/root-rsa-2048.pem" \
      --align "${align}" \
      --header-size 0x200 \
      --slot-size "${slot_size}" \
      --version "${version}" \
      "${sign_input}" "${out}"

    msg "Signed image: ${out} (slot=${slot_size}, align=${align})"
}

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

# --- 1. head_move_nrf52: swap-move, nrf52840dk, default geometry ---
# Default nrf52840dk: slot0 @ 0xC000 (0x76000), slot1 @ 0x82000 (0x76000)
cat > "${OVERLAY_DIR}/nrf52_move_default.dts" <<'DTS'
/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
DTS

build_mcuboot "move_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_move_default.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=n

build_test_app "move_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_move_default.dts"
sign_image "move_nrf52" "0x76000" "1.0.0+0" "zephyr_head_move_nrf52_slot0.bin"
sign_image "move_nrf52" "0x76000" "1.1.0+0" "zephyr_head_move_nrf52_slot1.bin" "36864"

# --- 2. head_scratch_nrf52: swap-scratch, nrf52840dk ---
# Slots: 0x6E000 (440KB) each, scratch: 0x10000 (64KB)
build_mcuboot "scratch_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_scratch.dts"
sign_image "scratch_nrf52" "0x6e000" "1.0.0+0" "zephyr_head_scratch_nrf52_slot0.bin"
sign_image "scratch_nrf52" "0x6e000" "1.1.0+0" "zephyr_head_scratch_nrf52_slot1.bin" "36864"

# --- 3. head_move_stm32f4: swap-move, nucleo_f429zi, non-uniform sectors ---
# Slots: 0x60000 (384KB) each
build_mcuboot "move_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_move.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=n

build_test_app "move_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_move.dts"
sign_image "move_stm32f4" "0x60000" "1.0.0+0" "zephyr_head_move_stm32f4_slot0.bin"
sign_image "move_stm32f4" "0x60000" "1.1.0+0" "zephyr_head_move_stm32f4_slot1.bin" "36864"

# --- 4. head_scratch_stm32f4: swap-scratch, nucleo_f429zi ---
# Slots: 0x38000 (224KB) each, mirrored across banks; scratch: 0x20000
# (128KB). Every partition boundary is an STM32F429 erase-sector boundary.
build_mcuboot "scratch_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_scratch.dts"
sign_image "scratch_stm32f4" "0x38000" "1.0.0+0" "zephyr_head_scratch_stm32f4_mirrored_slot0.bin"
sign_image "scratch_stm32f4" "0x38000" "1.1.0+0" "zephyr_head_scratch_stm32f4_mirrored_slot1.bin" "36864"

# --- 4b. head_scratch_stm32f4_pr2206: swap-scratch, PR2206 trigger geometry ---
# Mirror the 0x18000 low-bank sector pattern into bank 2 so scratch swap can
# terminate, while the primary tail still lands on a 64 KiB sector.
build_test_app "scratch_stm32f4_pr2206" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_pr2206_scratch.dts"
sign_image "scratch_stm32f4_pr2206" "0x18000" "1.0.0+0" "zephyr_head_scratch_stm32f4_pr2206_slot0.bin" "" "32"
sign_image "scratch_stm32f4_pr2206" "0x18000" "1.1.0+0" "zephyr_head_scratch_stm32f4_pr2206_slot1.bin" "36864" "32"

# --- 5. head_move_small: swap-move, nrf52840dk, 128KB slots ---
# Slots: 0x20000 (128KB) each
build_mcuboot "move_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_move.dts" \
    -DCONFIG_BOOT_SWAP_USING_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_MOVE=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=n

build_test_app "move_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_move.dts"
sign_image "move_small" "0x20000" "1.0.0+0" "zephyr_head_move_small_slot0.bin"
sign_image "move_small" "0x20000" "1.1.0+0" "zephyr_head_move_small_slot1.bin" "16384"

# --- 6. head_scratch_small: swap-scratch, nrf52840dk, 128KB + 4KB scratch ---
# Slots: 0x20000 (128KB) each, scratch: 0x1000 (4KB)
build_mcuboot "scratch_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_scratch.dts" \
    -DCONFIG_BOOT_SWAP_USING_SCRATCH=y

build_test_app "scratch_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_scratch.dts"
sign_image "scratch_small" "0x20000" "1.0.0+0" "zephyr_head_scratch_small_slot0.bin"
sign_image "scratch_small" "0x20000" "1.1.0+0" "zephyr_head_scratch_small_slot1.bin" "16384"

# --- 7. head_offset_nrf52: swap-offset (NEW algorithm), nrf52840dk, default geometry ---
# swap-offset is the new default in MCUboot HEAD — prime zero-day target.
build_mcuboot "offset_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_move_default.dts" \
    -DCONFIG_BOOT_SWAP_USING_OFFSET=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y

build_test_app "offset_nrf52" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_move_default.dts"
sign_image "offset_nrf52" "0x76000" "1.0.0+0" "zephyr_head_offset_nrf52_slot0.bin"
sign_image "offset_nrf52" "0x76000" "1.1.0+0" "zephyr_head_offset_nrf52_slot1.bin" "36864"

# --- 8. head_offset_stm32f4: swap-offset, nucleo_f429zi, non-uniform sectors ---
# Slots: 0x60000 (384KB) each on the tracked 1 MiB layout.
build_mcuboot "offset_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_offset.dts" \
    -DCONFIG_BOOT_SWAP_USING_OFFSET=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y

build_test_app "offset_stm32f4" "nucleo_f429zi" "${OVERLAY_DIR}/stm32f4_offset.dts"
sign_image "offset_stm32f4" "0x60000" "1.0.0+0" "zephyr_head_offset_stm32f4_slot0.bin"
sign_image "offset_stm32f4" "0x60000" "1.1.0+0" "zephyr_head_offset_stm32f4_slot1.bin" "36864"
make_offset_slot_image \
    "${ASSETS_DIR}/zephyr_head_offset_stm32f4_slot1.bin" \
    "${ASSETS_DIR}/zephyr_head_offset_stm32f4_slot1_offsetslot.bin" \
    "0x20000"

# --- 9. head_offset_small: swap-offset, nrf52840dk, 128KB slots ---
build_mcuboot "offset_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_move.dts" \
    -DCONFIG_BOOT_SWAP_USING_OFFSET=y -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y

build_test_app "offset_small" "nrf52840dk/nrf52840" "${OVERLAY_DIR}/nrf52_small_move.dts"
sign_image "offset_small" "0x20000" "1.0.0+0" "zephyr_head_offset_small_slot0.bin"
sign_image "offset_small" "0x20000" "1.1.0+0" "zephyr_head_offset_small_slot1.bin" "16384"

msg "=== MCUboot HEAD matrix build complete ==="
msg "MCUboot commit: ${MCUBOOT_HEAD}"
msg "Assets in: ${ASSETS_DIR}"
ls -la "${ASSETS_DIR}"/oss_mcuboot_head_*.elf
ls -la "${ASSETS_DIR}"/zephyr_head_*.bin
