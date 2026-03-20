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
MODULE_YML="${MCUBOOT_DIR}/zephyr/module.yml"

PR2205_BROKEN="c21c3909"
PR2205_FIXED="bbd0ee1e"
PR2206_BROKEN="e35461d2"
PR2206_FIXED="08985c96"
PR2214_BROKEN="429e2fea"
PR2214_FIXED="90fd59d2"

msg() { echo ">> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -e "$1" ]] || die "missing required path: $1"; }

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

ensure_mcuboot_history() {
    local repo="$1"
    msg "Fetching MCUboot history for differential commit builds"
    # Unshallow if needed — try origin first (west's remote), then upstream.
    if [[ "$(git -C "${repo}" rev-parse --is-shallow-repository)" == "true" ]]; then
        git -C "${repo}" fetch --quiet --unshallow origin 2>/dev/null || \
            git -C "${repo}" fetch --quiet --unshallow upstream 2>/dev/null || \
            git -C "${repo}" fetch --quiet --depth=10000 upstream 2>/dev/null || true
    fi
    # Always fetch upstream to ensure PR commits are reachable.
    git -C "${repo}" fetch --quiet upstream 2>/dev/null || true
    # Last resort: fetch each required SHA individually.
    for sha in \
        "${PR2205_BROKEN}" "${PR2205_FIXED}" \
        "${PR2206_BROKEN}" "${PR2206_FIXED}" \
        "${PR2214_BROKEN}" "${PR2214_FIXED}"; do
        if ! git -C "${repo}" rev-parse --verify "${sha}^{commit}" >/dev/null 2>&1; then
            git -C "${repo}" fetch --quiet upstream "${sha}" 2>/dev/null || true
        fi
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

    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align 8 \
        --header-size 0x200 \
        --slot-size "${slot_size}" \
        --version "${version}" \
        "${app_bin}" "${out_path}"
}

sign_pr_differential_geom_image() {
    local payload_bin="$1"
    local slot_size="$2"
    local version="$3"
    local out_path="$4"

    "${PYTHON_BIN}" "${IMGTOOL_PY}" sign \
        --key "${IMGTOOL_KEY}" \
        --align 8 \
        --header-size 0x200 \
        --slot-size "${slot_size}" \
        --pad-header \
        --pad \
        --confirm \
        --version "${version}" \
        "${payload_bin}" "${out_path}"
}

build_pr_differential_images() {
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

    local app_bin
    app_bin="$(build_shared_nrf52_test_app)"

    msg "Signing base PR differential slot images"
    sign_pr_differential_image \
        "${app_bin}" "0x6e000" "1.0.0+0" \
        "${ASSETS_DIR}/zephyr_slot0_padded.bin"
    sign_pr_differential_image \
        "${app_bin}" "0x6e000" "1.0.1+0" \
        "${ASSETS_DIR}/zephyr_slot1_padded.bin"

    msg "Generating geometry/max payload variants"
    PR_DIFF_APP_BIN="${app_bin}" PR_DIFF_TMP="${BUILD_ROOT}" python3 - <<'PY'
from pathlib import Path
import os

app_bin = Path(os.environ["PR_DIFF_APP_BIN"])
tmp_root = Path(os.environ["PR_DIFF_TMP"])
payload = app_bin.read_bytes()

def make_payload(path: Path, size: int, fill: int) -> None:
    if len(payload) >= size:
        out = payload[:size]
    else:
        out = payload + bytes([fill]) * (size - len(payload))
    path.write_bytes(out)

make_payload(tmp_root / "zephyr_slot1_max_payload.bin", 0x74000, 0x3C)
make_payload(tmp_root / "zephyr_slot1_scratch_geom_payload.bin", 0x69000, 0xA5)
make_payload(tmp_root / "zephyr_slot1_offset_geom_payload.bin", 0x75000, 0x5A)
PY

    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_max_payload.bin" "0x76000" "1.0.1+0" \
        "${ASSETS_DIR}/zephyr_slot1_max.bin"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_scratch_geom_payload.bin" "0x6e000" "1.0.2+0" \
        "${ASSETS_DIR}/zephyr_slot1_scratch_geom_max.bin"
    sign_pr_differential_geom_image \
        "${BUILD_ROOT}/zephyr_slot1_offset_geom_payload.bin" "0x76000" "1.0.3+0" \
        "${ASSETS_DIR}/zephyr_slot1_offset_geom_full.bin"
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
        for d in \
            "${wt_root}/pr2205_broken" "${wt_root}/pr2205_fixed" \
            "${wt_root}/pr2206_broken" "${wt_root}/pr2206_fixed" \
            "${wt_root}/pr2214_broken" "${wt_root}/pr2214_fixed"; do
            if [[ -d "${d}" ]]; then
                git -C "${MCUBOOT_DIR}" worktree remove --force "${d}" >/dev/null 2>&1 || true
            fi
        done
        rm -rf "${wt_root}" >/dev/null 2>&1 || true
    }
    trap cleanup_pr_worktrees EXIT

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
        local overlay="$3"
        shift 3
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
                -b nrf52840dk/nrf52840 \
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
    local offset_overlay="${GENERATED_DIR}/nrf52_move_bootloader.overlay"
    build_pr_bootloader_variant "pr2205_scratch_broken" "${wt_root}/pr2205_broken" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2205_scratch_fixed" "${wt_root}/pr2205_fixed" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2206_scratch_broken" "${wt_root}/pr2206_broken" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2206_scratch_fixed" "${wt_root}/pr2206_fixed" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y
    build_pr_bootloader_variant "pr2206_scratch_geom_broken" "${wt_root}/pr2206_broken" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS=1024
    build_pr_bootloader_variant "pr2206_scratch_geom_fixed" "${wt_root}/pr2206_fixed" "${scratch_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_SCRATCH=y \
        -DCONFIG_BOOT_MAX_IMG_SECTORS_AUTO=n \
        -DCONFIG_BOOT_MAX_IMG_SECTORS=1024
    build_pr_bootloader_variant "pr2214_offset_broken" "${wt_root}/pr2214_broken" "${offset_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y
    build_pr_bootloader_variant "pr2214_offset_fixed" "${wt_root}/pr2214_fixed" "${offset_overlay}" \
        -DCONFIG_BOOT_SWAP_USING_OFFSET=y \
        -DCONFIG_BOOT_PREFER_SWAP_OFFSET=y
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

# --- 3. Fetch only the Zephyr/MCUboot projects needed for nRF52 builds ---
if [[ -d "${MCUBOOT_DIR}/.git" ]]; then
    restore_mcuboot_module_yml
fi
msg "Running targeted west update (zephyr + mcuboot + nrf deps)"
( cd "${ZEPHYR_WS}" && \
  "${WEST}" update --narrow -o=--depth=1 zephyr mcuboot hal_nordic cmsis )

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

build_pr_differential_assets

msg "Bootstrap complete. Workspace: ${ZEPHYR_WS}"
