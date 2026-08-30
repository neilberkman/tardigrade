#!/usr/bin/env bash
# Bootstrap Zephyr workspace + MCUboot for building from source in CI.
# Idempotent -- safe to run multiple times.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Public Zephyr v3.7.0 commit. Keep this immutable for reproducible assets.
ZEPHYR_REF="${ZEPHYR_REF:-36940db938a8f4a1e919496793ed439850a221c2}"
# west passes --mr to git clone --branch, so use the advertised release tag
# when resolving the immutable default commit. Non-SHA overrides can be used
# directly as the manifest ref (for example, a branch or another tag).
if [[ "${ZEPHYR_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    ZEPHYR_INIT_REF="v3.7.0"
else
    ZEPHYR_INIT_REF="${ZEPHYR_REF}"
fi
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
MODULE_YML="${MCUBOOT_DIR}/zephyr/module.yml"

PR2205_BROKEN="c21c3909eafff152a5527fb794ba7be7695d202e"
PR2205_FIXED="bbd0ee1ecce3d7e7be6baf606027710052dd4e13"
PR2206_BROKEN="e35461d29484f1e11c75c769b066ec2b79b4791c"
PR2206_FIXED="08985c9679f6877ab593a7ff62ab244ca6fbaae5"
PR2214_BROKEN="429e2fea24518f178cd4d33928cb66fcb0205803"
PR2214_FIXED="90fd59d2f9e45c24d0833dd391dcdc932b3b1908"
PR_DIFF_GEOM_ALIGN="32"
PR_DIFF_GEOM_TRAILER_RESERVE="0x30a0"
PR_DIFF_GEOM_SIGN_OVERHEAD="0x400"
# Zephyr's STM32F4 flash binding only permits write-block-size values up to 8.
# This is the minimal sector budget that still pushes boot_trailer_sz(write_sz=8)
# past a 64 KiB tail sector on the PR2206 geometry:
# (2725 * 3 * 8) + (5 * 32) = 0x10018.
PR2206_GEOM_WRITE_BLOCK_SIZE="8"
PR2206_BOOT_MAX_IMG_SECTORS="2725"
printf -v PR2206_GEOM_TRAILER_RESERVE '0x%x' \
    $(( (PR2206_BOOT_MAX_IMG_SECTORS * 3 * PR2206_GEOM_WRITE_BLOCK_SIZE) + (PR_DIFF_GEOM_ALIGN * 5) ))

msg() { echo ">> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -e "$1" ]] || die "missing required path: $1"; }

zephyr_ref_is_commit() {
    [[ "$1" =~ ^[0-9a-fA-F]{40}$ ]]
}

fetch_zephyr_ref() {
    local repo="$1"
    local ref="$2"

    if git -C "${repo}" fetch --quiet origin -- "${ref}"; then
        return
    fi
    if ! zephyr_ref_is_commit "${ref}"; then
        return 1
    fi

    # Some Git hosts reject wants addressed only by an object ID. Fetch all
    # branch refs as a fallback; this makes a full-SHA ZEPHYR_REF override
    # work when the commit is reachable from a non-default branch.
    msg "Direct Zephyr SHA fetch failed; fetching remote branch refs"
    git -C "${repo}" fetch --quiet origin \
        '+refs/heads/*:refs/remotes/origin/*'
}

checkout_zephyr_ref() {
    local repo="$1"
    local ref="$2"
    local resolved

    require_file "${repo}"

    # west init uses the manifest repository's ref as a git clone --branch
    # argument.  A commit ID is not an advertised branch, so initialize from
    # the v3.7.0 release tag and resolve the requested ref in the
    # already-cloned repository.
    # Keep the full commit check below so the default pin remains immutable.
    if zephyr_ref_is_commit "${ref}"; then
        if ! git -C "${repo}" cat-file -e "${ref}^{commit}" >/dev/null 2>&1; then
            fetch_zephyr_ref "${repo}" "${ref}"
        fi
        git -C "${repo}" checkout --detach --quiet "${ref}"
    else
        # FETCH_HEAD avoids accidentally using a stale local branch when an
        # operator supplies a branch or tag through ZEPHYR_REF.
        fetch_zephyr_ref "${repo}" "${ref}"
        git -C "${repo}" checkout --detach --quiet FETCH_HEAD
    fi

    resolved="$(git -C "${repo}" rev-parse --verify HEAD^{commit})"
    if zephyr_ref_is_commit "${ref}" && [[ "${resolved,,}" != "${ref,,}" ]]; then
        die "Zephyr checkout ${resolved} does not match pinned commit ${ref}"
    fi
    RESOLVED_ZEPHYR_COMMIT="${resolved}"
    msg "Using Zephyr commit ${resolved} (ref ${ref})"
}

verify_zephyr_checkout() {
    local repo="$1"
    local actual

    actual="$(git -C "${repo}" rev-parse --verify HEAD^{commit})"
    if [[ "${actual}" != "${RESOLVED_ZEPHYR_COMMIT}" ]]; then
        die "Zephyr checkout changed from ${RESOLVED_ZEPHYR_COMMIT} to ${actual}"
    fi
}

restore_mcuboot_module_yml() {
    if git -C "${MCUBOOT_DIR}" diff --quiet -- "zephyr/module.yml" >/dev/null 2>&1; then
        return
    fi
    msg "Restoring MCUboot zephyr/module.yml before west update"
    git -C "${MCUBOOT_DIR}" checkout -- "zephyr/module.yml"
}

patch_mcuboot_module_yml() {
    if [[ -f "${MODULE_YML}" ]] && grep -q 'package-managers' "${MODULE_YML}" 2>/dev/null; then
        msg "Stripping unsupported 'package-managers' from MCUboot zephyr/module.yml"
        sed -i.bak '/^package-managers:/,/^[^ ]/{ /^package-managers:/d; /^  /d; }' "${MODULE_YML}"
    fi
}

build_shared_nrf52_test_app() {
    local toolchain_path gdb_bin
    toolchain_path="$(detect_toolchain_path)"
    gdb_bin="${toolchain_path}/bin/arm-none-eabi-gdb"

    require_file "${WEST}"
    require_file "${PYTHON_BIN}"
    require_file "${gdb_bin}"

    mkdir -p "${BUILD_ROOT}" "${GENERATED_DIR}"
    write_nrf52_default_overlays

    local app_build="${BUILD_ROOT}/hello_world_mcuboot_common"
    local app_overlay="${GENERATED_DIR}/nrf52_move_app.overlay"
    local app_bin="${app_build}/zephyr/zephyr.bin"
    if [[ -f "${app_bin}" ]]; then
        echo "${app_bin}"
        return
    fi

    msg "Building shared Zephyr hello_world app for MCUboot assets"
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
            -DCONFIG_MINIMAL_LIBC=y \
            -DCONFIG_PICOLIBC=n \
            "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    ) >&2

    require_file "${app_bin}"
    echo "${app_bin}"
}

build_shared_stm32f4_pr2206_test_app() {
    local toolchain_path gdb_bin
    toolchain_path="$(detect_toolchain_path)"
    gdb_bin="${toolchain_path}/bin/arm-none-eabi-gdb"

    require_file "${WEST}"
    require_file "${PYTHON_BIN}"
    require_file "${gdb_bin}"

    mkdir -p "${BUILD_ROOT}" "${GENERATED_DIR}"
    write_stm32f4_pr2206_overlay

    local app_build="${BUILD_ROOT}/hello_scratch_stm32f4_pr2206"
    local mcuboot_overlay="${GENERATED_DIR}/stm32f4_pr2206_scratch.dts"
    local app_overlay="${GENERATED_DIR}/app_scratch_stm32f4_pr2206.dts"
    local app_bin="${app_build}/zephyr/zephyr.bin"
    if [[ -f "${app_bin}" ]]; then
        echo "${app_bin}"
        return
    fi

    sed 's/zephyr,code-partition = &boot_partition/zephyr,code-partition = \&slot0_partition/' \
        "${mcuboot_overlay}" > "${app_overlay}"

    msg "Building shared Zephyr hello_world app for STM32F4 PR2206 scratch assets"
    (
        cd "${ZEPHYR_WS}"
        ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
        GNUARMEMB_TOOLCHAIN_PATH="${toolchain_path}" \
        "${WEST}" build \
            -d "${app_build}" \
            -p always \
            -b nucleo_f429zi \
            "${ZEPHYR_WS}/zephyr/samples/hello_world" \
            -- \
            -DDTC_OVERLAY_FILE="${app_overlay}" \
            -DCONFIG_BOOTLOADER_MCUBOOT=y \
            -DCONFIG_MINIMAL_LIBC=y \
            -DCONFIG_PICOLIBC=n \
            "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    ) >&2

    require_file "${app_bin}"
    echo "${app_bin}"
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

write_nrf52_pr_differential_overlays() {
    mkdir -p "${GENERATED_DIR}"
    cat > "${GENERATED_DIR}/scratch_with_code_partition.dts" <<'EOF'
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
EOF
    cat > "${GENERATED_DIR}/scratch_with_geom_partition.dts" <<'EOF'
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
EOF
    cat > "${GENERATED_DIR}/offset_with_geom_partition.dts" <<'EOF'
&flash0 {
    /delete-node/ partitions;

    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0x0c000>;
        };
        slot0_partition: partition@c000 {
            label = "image-0";
            reg = <0x0c000 0x76000>;
        };
        slot1_partition: partition@82000 {
            label = "image-1";
            reg = <0x82000 0x76000>;
        };
        storage_partition: partition@f8000 {
            label = "storage";
            reg = <0xf8000 0x08000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
EOF
    cat > "${GENERATED_DIR}/scratch_app_with_code_partition.dts" <<'EOF'
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
        zephyr,code-partition = &slot0_partition;
    };
};
EOF
}

write_stm32f4_pr2205_overlay() {
    mkdir -p "${GENERATED_DIR}"
    cat > "${GENERATED_DIR}/stm32f4_pr2205_scratch.dts" <<'EOF'
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
            reg = <0x08000 0x18000>;
        };
        slot1_partition: partition@20000 {
            label = "image-1";
            reg = <0x20000 0x20000>;
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
EOF
}

write_stm32f4_pr2206_overlay() {
    mkdir -p "${GENERATED_DIR}"
    cat > "${GENERATED_DIR}/stm32f4_pr2206_scratch.dts" <<'EOF'
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

ensure_mcuboot_history() {
    local repo="$1"
    msg "Fetching MCUboot history for differential commit builds"
    # Unshallow if needed — prefer the real MCUboot remote first.
    if [[ "$(git -C "${repo}" rev-parse --is-shallow-repository)" == "true" ]]; then
        git -C "${repo}" fetch --quiet --unshallow mcu-tools 2>/dev/null || \
            git -C "${repo}" fetch --quiet --unshallow fork 2>/dev/null || \
            git -C "${repo}" fetch --quiet --unshallow origin 2>/dev/null || \
            git -C "${repo}" fetch --quiet --unshallow upstream 2>/dev/null || \
            git -C "${repo}" fetch --quiet --depth=10000 mcu-tools 2>/dev/null || true
    fi
    # Always refresh the real MCUboot remotes; "upstream" may point at Zephyr's mirror.
    git -C "${repo}" fetch --quiet mcu-tools 2>/dev/null || true
    git -C "${repo}" fetch --quiet fork 2>/dev/null || true
    git -C "${repo}" fetch --quiet upstream 2>/dev/null || true
    # Fetch PR branches — topic branch commits aren't on main and live on mcu-tools.
    for pr in 2205 2206 2214; do
        git -C "${repo}" fetch --quiet mcu-tools "+refs/pull/${pr}/head:refs/pull/${pr}" 2>/dev/null || \
            git -C "${repo}" fetch --quiet fork "+refs/pull/${pr}/head:refs/pull/${pr}" 2>/dev/null || true
    done
}

require_mcuboot_commit() {
    local repo="$1"
    local sha="$2"
    if ! git -C "${repo}" rev-parse --verify "${sha}^{commit}" >/dev/null 2>&1; then
        msg "WARNING: MCUboot commit ${sha} not available — PR differential builds will be skipped"
        return 1
    fi
}

sign_pr_differential_image() {
    local app_bin="$1"
    local slot_size="$2"
    local version="$3"
    local out_path="$4"
    local payload_size="${5:-}"
    local align="${6:-8}"

    local sign_input="${app_bin}"
    if [[ -n "${payload_size}" ]]; then
        local tmp="${BUILD_ROOT}/$(basename "${out_path}" .bin)_payload.bin"
        dd if="${app_bin}" of="${tmp}" bs=1 count="${payload_size}" 2>/dev/null
        local actual
        actual=$(wc -c < "${tmp}" | tr -d ' ')
        if (( actual < payload_size )); then
            dd if=/dev/zero bs=1 count=$((payload_size - actual)) >> "${tmp}" 2>/dev/null
        fi
        sign_input="${tmp}"
    fi

    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align "${align}" \
        --header-size 0x200 \
        --slot-size "${slot_size}" \
        --version "${version}" \
        "${sign_input}" "${out_path}"
}

sign_pr_differential_geom_image() {
    local payload_bin="$1"
    local slot_size="$2"
    local version="$3"
    local out_path="$4"
    local align="${5:-${PR_DIFF_GEOM_ALIGN}}"

    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align "${align}" \
        --header-size 0x200 \
        --slot-size "${slot_size}" \
        --version "${version}" \
        "${payload_bin}" "${out_path}"
}

make_offset_slot_image() {
    local input_path="$1"
    local output_path="$2"
    local offset_bytes="$3"

    "${PYTHON_BIN}" - "$input_path" "$output_path" "$offset_bytes" <<'PY'
from pathlib import Path
import sys

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
offset_bytes = int(sys.argv[3], 0)

output_path.write_bytes((b"\xFF" * offset_bytes) + input_path.read_bytes())
PY
}

build_pr_differential_images() {
    local toolchain_path strip_bin gdb_bin
    local app_bin stm32f4_pr2206_app_bin
    toolchain_path="$(detect_toolchain_path)"
    strip_bin="${toolchain_path}/bin/arm-none-eabi-strip"
    gdb_bin="${toolchain_path}/bin/arm-none-eabi-gdb"

    require_file "${WEST}"
    require_file "${PYTHON_BIN}"
    require_file "${IMGTOOL_PY}"
    require_file "${IMGTOOL_KEY}"
    require_file "${strip_bin}"
    require_file "${gdb_bin}"

    mkdir -p "${ASSETS_DIR}" "${BUILD_ROOT}" "${GENERATED_DIR}"
    write_nrf52_default_overlays
    write_nrf52_pr_differential_overlays

    app_bin="$(build_shared_nrf52_test_app)"
    stm32f4_pr2206_app_bin="$(build_shared_stm32f4_pr2206_test_app)"

    msg "Signing base PR differential slot images"
    sign_pr_differential_image \
        "${app_bin}" "0x6e000" "1.0.0+0" \
        "${ASSETS_DIR}/zephyr_slot0_padded.bin"
    sign_pr_differential_image \
        "${app_bin}" "0x6e000" "1.0.1+0" \
        "${ASSETS_DIR}/zephyr_slot1_padded.bin"
    sign_pr_differential_image \
        "${stm32f4_pr2206_app_bin}" "0x18000" "1.0.0+0" \
        "${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot0.bin" "" "32"
    sign_pr_differential_image \
        "${stm32f4_pr2206_app_bin}" "0x18000" "1.1.0+0" \
        "${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot1.bin" "36864" "32"

    msg "Generating geometry/max payload variants (CONFIG_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN})"
    PR_DIFF_BASE_IMAGE="${ASSETS_DIR}/zephyr_slot1_padded.bin" \
    PR_DIFF_TMP="${BUILD_ROOT}" \
    PR_DIFF_GEOM_TRAILER_RESERVE="${PR_DIFF_GEOM_TRAILER_RESERVE}" \
    PR_DIFF_GEOM_SIGN_OVERHEAD="${PR_DIFF_GEOM_SIGN_OVERHEAD}" \
    python3 - <<'PY'
from pathlib import Path
import os
import struct

base_image = Path(os.environ["PR_DIFF_BASE_IMAGE"])
tmp_root = Path(os.environ["PR_DIFF_TMP"])
geom_trailer_reserve = int(os.environ["PR_DIFF_GEOM_TRAILER_RESERVE"], 0)
geom_sign_overhead = int(os.environ["PR_DIFF_GEOM_SIGN_OVERHEAD"], 0)
base = base_image.read_bytes()
ih_size = struct.unpack_from("<I", base, 0x0C)[0]
payload = base[0x200:0x200 + ih_size]

def max_payload(slot_size: int) -> int:
    return (slot_size - 0x200 - geom_trailer_reserve - geom_sign_overhead) & ~0x1F

def make_payload(path: Path, size: int, fill: int) -> None:
    if len(payload) >= size:
        body = payload[:size]
    else:
        body = payload + bytes([fill]) * (size - len(payload))
    # imgtool expects the MCUboot header reservation at the start of the
    # input image when --pad-header is not used. Restore the 0x200-byte
    # gap so the signed output's vector table lands at 0x200, not 0x400.
    path.write_bytes((b"\x00" * 0x200) + body)

make_payload(tmp_root / "zephyr_slot1_max_payload.bin", 0x74000, 0x3C)
make_payload(tmp_root / "zephyr_slot1_scratch_geom_payload.bin", max_payload(0x6E000), 0xA5)
make_payload(tmp_root / "zephyr_slot1_offset_geom_payload.bin", max_payload(0x76000), 0x5A)
PY

    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_max_payload.bin" "0x76000" "1.0.1+0" \
        "${ASSETS_DIR}/zephyr_slot1_max.bin" "8"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_scratch_geom_payload.bin" "0x6e000" "1.0.2+0" \
        "${ASSETS_DIR}/zephyr_slot1_scratch_geom_max.bin"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_offset_geom_payload.bin" "0x76000" "1.0.3+0" \
        "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin"

    msg "Generating STM32F4 geometry boundary payload variants (CONFIG_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN})"
    PR_DIFF_STM32F4_OFFSET_BASE="${ASSETS_DIR}/zephyr_head_offset_stm32f4_slot1.bin" \
    PR_DIFF_STM32F4_SCRATCH_BASE="${ASSETS_DIR}/zephyr_head_scratch_stm32f4_pr2206_slot1.bin" \
    PR_DIFF_STM32F4_PR2206_PRIMARY_SLOT_SIZE="0x18000" \
    PR_DIFF_STM32F4_PR2206_STAGING_SLOT_SIZE="0x18000" \
    PR2206_GEOM_TRAILER_RESERVE="${PR2206_GEOM_TRAILER_RESERVE}" \
    PR_DIFF_TMP="${BUILD_ROOT}" \
    python3 - <<'PY'
from pathlib import Path
import os
import struct

tmp_root = Path(os.environ["PR_DIFF_TMP"])

geom_trailer_reserve = int(os.environ["PR2206_GEOM_TRAILER_RESERVE"], 0)
geom_sign_overhead = int("0x400", 0)


def max_payload(slot_size: int) -> int:
    return (slot_size - 0x200 - geom_trailer_reserve - geom_sign_overhead) & ~0x1F

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

scratch_payload = load_payload(Path(os.environ["PR_DIFF_STM32F4_SCRATCH_BASE"]))
offset_payload = load_payload(Path(os.environ["PR_DIFF_STM32F4_OFFSET_BASE"]))
scratch_primary_slot_size = int(os.environ["PR_DIFF_STM32F4_PR2206_PRIMARY_SLOT_SIZE"], 0)

make_payload(
    tmp_root / "zephyr_slot1_scratch_geom_stm32f4_payload.bin",
    scratch_payload,
    max_payload(scratch_primary_slot_size),
    0xA5,
)
make_payload(
    tmp_root / "zephyr_slot1_scratch_geom_pr2206_boundary_payload.bin",
    scratch_payload,
    0x7C80,
    0xA5,
)
make_payload(tmp_root / "zephyr_slot1_offset_geom_stm32f4_payload.bin", offset_payload, 0x40000, 0x5A)
PY

    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_scratch_geom_stm32f4_payload.bin" "0x18000" "2.0.0+0" \
        "${ASSETS_DIR}/zephyr_slot1_scratch_geom_max.bin"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_scratch_geom_pr2206_boundary_payload.bin" "0x18000" "2.0.1+0" \
        "${ASSETS_DIR}/zephyr_slot1_scratch_geom_pr2206_boundary.bin"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_offset_geom_stm32f4_payload.bin" "0x76000" "2.1.0+0" \
        "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin"
    make_offset_slot_image \
        "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin" \
        "${ASSETS_DIR}/zephyr_slot1_offset_geom_full_offsetslot.bin" \
        "0x1E000"
}

build_pr_differential_elfs() {
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

    mkdir -p "${ASSETS_DIR}" "${BUILD_ROOT}" "${GENERATED_DIR}"
    write_nrf52_default_overlays
    write_nrf52_pr_differential_overlays
    write_stm32f4_pr2205_overlay
    write_stm32f4_pr2206_overlay
    ensure_mcuboot_history "${MCUBOOT_DIR}"
    local missing=false
    for sha in \
        "${PR2205_BROKEN}" "${PR2205_FIXED}" \
        "${PR2206_BROKEN}" "${PR2206_FIXED}" \
        "${PR2214_BROKEN}" "${PR2214_FIXED}"; do
        require_mcuboot_commit "${MCUBOOT_DIR}" "${sha}" || missing=true
    done
    if [[ "${missing}" == "true" ]]; then
        msg "Skipping PR differential ELF builds (missing commits — shallow CI clone)"
        return 0
    fi

    local wt_root
    wt_root="$(mktemp -d /tmp/mcuboot_pr_diff_wt.XXXXXX)"
    cleanup_pr_worktrees() {
        local cleanup_root="$1"
        for d in \
            "${cleanup_root}/pr2205_broken" "${cleanup_root}/pr2205_fixed" \
            "${cleanup_root}/pr2206_broken" "${cleanup_root}/pr2206_fixed" \
            "${cleanup_root}/pr2214_broken" "${cleanup_root}/pr2214_fixed"; do
            if [[ -d "${d}" ]]; then
                git -C "${MCUBOOT_DIR}" worktree remove --force "${d}" >/dev/null 2>&1 || true
            fi
        done
        rm -rf "${cleanup_root}" >/dev/null 2>&1 || true
    }
    trap "cleanup_pr_worktrees '${wt_root}'" EXIT

    msg "Creating detached worktrees for PR differential builds"
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2205_broken" "${PR2205_BROKEN}" >/dev/null
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2205_fixed" "${PR2205_FIXED}" >/dev/null
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2206_broken" "${PR2206_BROKEN}" >/dev/null
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2206_fixed" "${PR2206_FIXED}" >/dev/null
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2214_broken" "${PR2214_BROKEN}" >/dev/null
    git -C "${MCUBOOT_DIR}" worktree add --detach "${wt_root}/pr2214_fixed" "${PR2214_FIXED}" >/dev/null

    build_pr_bootloader_variant() {
        local name="$1"
        local src="$2"
        local board="$3"
        local overlay="$4"
        shift 4
        local extra_cmake=("$@")
        local out_build="${BUILD_ROOT}/${name}"
        local out_elf="${ASSETS_DIR}/oss_mcuboot_${name}.elf"

        msg "Building ${name}"
        (
            cd "${ZEPHYR_WS}"
            ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb \
            GNUARMEMB_TOOLCHAIN_PATH="${toolchain_path}" \
            "${WEST}" build \
                -d "${out_build}" \
                -p always \
                -b "${board}" \
                "${src}/boot/zephyr" \
                -- \
                -DDTC_OVERLAY_FILE="${overlay}" \
                -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
                -DCONFIG_BOOT_SIGNATURE_TYPE_RSA=n \
                "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
                "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}" \
                "${extra_cmake[@]}"
        )

        cp "${out_build}/zephyr/zephyr.elf" "${out_elf}"
        "${strip_bin}" -g "${out_elf}"
        msg "Wrote ${out_elf}"
    }

    local scratch_overlay="${GENERATED_DIR}/scratch_with_code_partition.dts"
    local scratch_geom_overlay="${GENERATED_DIR}/scratch_with_geom_partition.dts"
    local offset_geom_overlay="${GENERATED_DIR}/offset_with_geom_partition.dts"
    local offset_overlay="${GENERATED_DIR}/nrf52_move_bootloader.overlay"
    local stm32f4_pr2205_overlay="${GENERATED_DIR}/stm32f4_pr2205_scratch.dts"
    local stm32f4_pr2206_overlay="${GENERATED_DIR}/stm32f4_pr2206_scratch.dts"
    build_pr_bootloader_variant "pr2205_scratch_broken" "${wt_root}/pr2205_broken" "nucleo_f429zi" "${stm32f4_pr2205_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2205_scratch_fixed" "${wt_root}/pr2205_fixed" "nucleo_f429zi" "${stm32f4_pr2205_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2206_scratch_broken" "${wt_root}/pr2206_broken" "nucleo_f429zi" "${stm32f4_pr2206_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}" \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}"
    build_pr_bootloader_variant "pr2206_scratch_fixed" "${wt_root}/pr2206_fixed" "nucleo_f429zi" "${stm32f4_pr2206_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}" \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}"
    build_pr_bootloader_variant "pr2206_scratch_geom_broken" "${wt_root}/pr2206_broken" "nucleo_f429zi" "${stm32f4_pr2206_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}" \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}"
    build_pr_bootloader_variant "pr2206_scratch_geom_fixed" "${wt_root}/pr2206_fixed" "nucleo_f429zi" "${stm32f4_pr2206_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}" \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS="${PR2206_BOOT_MAX_IMG_SECTORS}"
    build_pr_bootloader_variant "pr2214_offset_broken" "${wt_root}/pr2214_broken" "nucleo_f429zi" "${offset_geom_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}"
    build_pr_bootloader_variant "pr2214_offset_fixed" "${wt_root}/pr2214_fixed" "nucleo_f429zi" "${offset_geom_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}"
    build_pr_bootloader_variant "pr2214_offset_geom_broken" "${wt_root}/pr2214_broken" "nucleo_f429zi" "${offset_geom_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}"
    build_pr_bootloader_variant "pr2214_offset_geom_fixed" "${wt_root}/pr2214_fixed" "nucleo_f429zi" "${offset_geom_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y \
        "-DCMAKE_C_FLAGS=-DMCUBOOT_BOOT_MAX_ALIGN=${PR_DIFF_GEOM_ALIGN}"
}

build_pr_differential_assets() {
    build_pr_differential_images
    build_pr_differential_elfs
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
    local boot_overlay="${GENERATED_DIR}/nrf52_move_bootloader.overlay"
    local out_elf="${ASSETS_DIR}/oss_mcuboot_head_move_nrf52_seccounter.elf"
    local out_v1="${ASSETS_DIR}/zephyr_head_move_nrf52_seccounter_v1.bin"
    local out_v2="${ASSETS_DIR}/zephyr_head_move_nrf52_seccounter_v2.bin"
    local app_bin

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
            -DCONFIG_MCUBOOT_DOWNGRADE_PREVENTION=y \
            -DCONFIG_MCUBOOT_DOWNGRADE_PREVENTION_SECURITY_COUNTER=y \
            "-DCMAKE_GDB:FILEPATH=${gdb_bin}" \
            "-DPython3_EXECUTABLE:FILEPATH=${PYTHON_BIN}"
    )
    cp "${mcuboot_build}/zephyr/zephyr.elf" "${out_elf}"
    "${strip_bin}" -g "${out_elf}"
    msg "Wrote ${out_elf}"

    app_bin="$(build_shared_nrf52_test_app)"

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
else
    msg "Venv already exists, reconciling exact public dependencies"
fi
"${ZEPHYR_VENV}/bin/pip" install --quiet \
    -r "${REPO_ROOT}/requirements-oss-build.txt"

# --- 2. Initialize Zephyr workspace ---
if [[ ! -d "${ZEPHYR_WS}/.west" ]]; then
    msg "Initializing Zephyr workspace (manifest ref ${ZEPHYR_INIT_REF}; Zephyr ref ${ZEPHYR_REF})"
    "${WEST}" init \
        -m https://github.com/zephyrproject-rtos/zephyr \
        --mr "${ZEPHYR_INIT_REF}" "${ZEPHYR_WS}"
else
    msg "Zephyr workspace already initialized"
fi
checkout_zephyr_ref "${ZEPHYR_WS}/zephyr" "${ZEPHYR_REF}"

# --- 3. Fetch only the Zephyr/MCUboot projects needed for the differential corpus ---
if [[ -d "${MCUBOOT_DIR}/.git" ]]; then
    restore_mcuboot_module_yml
fi
msg "Running targeted west update (zephyr + mcuboot + nrf/stm32 deps)"
( cd "${ZEPHYR_WS}" && \
  "${WEST}" update --narrow -o=--depth=1 zephyr mcuboot hal_nordic hal_stm32 cmsis )
verify_zephyr_checkout "${ZEPHYR_WS}/zephyr"

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
patch_mcuboot_module_yml

# --- 5. Verify the pinned build environment ---
"${ZEPHYR_VENV}/bin/pip" check

# --- 6. Configure build generator ---
( cd "${ZEPHYR_WS}"
  if command -v ninja >/dev/null 2>&1; then
      "${WEST}" config build.generator "Ninja"
  else
      "${WEST}" config build.generator "Unix Makefiles"
  fi )

build_seccounter_assets

build_pr_differential_assets

msg "Bootstrap complete. Workspace: ${ZEPHYR_WS}"
