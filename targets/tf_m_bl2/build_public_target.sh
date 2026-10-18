#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Tardigrade contributors
#
# Build the AN521 TF-M BL2 target (SPE, BL2, NSPE, and signed primary/staging
# images for MCUBOOT_IMAGE_NUMBER=2 with SWAP_USING_MOVE) from pinned upstream
# revisions inside tardigrade-oss-validation:latest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OUTPUT_DIR="$REPO_ROOT/results/tfm_an521"
THIRD_PARTY_DIR="$REPO_ROOT/third_party"
DOCKER_IMAGE="tardigrade-oss-validation:latest"
PRIMARY_VERSION="2.3.1"
STAGING_VERSION="2.4.0"
UPGRADE_STRATEGY="SWAP_USING_MOVE"
JOBS=4
PREPARE_ONLY=0
PACKAGE_ONLY=0

# Pinned upstream revisions
TFM_REPO_URL="https://github.com/TrustedFirmware-M/trusted-firmware-m.git"
TFM_TAG="TF-Mv2.3.1"
TFM_COMMIT="0b40d7806136baadf489febf8e2f91bf87aca63d"

TFM_TESTS_REPO_URL="https://github.com/TrustedFirmware-M/tf-m-tests.git"
TFM_TESTS_TAG="TF-Mv2.3.1"
TFM_TESTS_COMMIT="465acb8405fb35b12a624a27062e361afe0025e4"

MCUBOOT_REPO_URL="https://github.com/mcu-tools/mcuboot.git"
MCUBOOT_TAG="v2.4.0"
MCUBOOT_COMMIT="6d3b3d2c38ab20c242e5b9abb04d050086383eb2"

TF_PSA_CRYPTO_REPO_URL="https://github.com/Mbed-TLS/TF-PSA-Crypto.git"
TF_PSA_CRYPTO_TAG="tf-psa-crypto-1.1.1"
TF_PSA_CRYPTO_COMMIT="a0632be94d883daa0295ac1eabf70359ad94f91b"

CMSIS_REPO_URL="https://github.com/ARM-software/CMSIS_6.git"
CMSIS_TAG="v6.2.0"
CMSIS_COMMIT="6f0a58d01aa9bd2feba212097f9afe7acd991d52"

QCBOR_REPO_URL="https://github.com/laurencelundblade/QCBOR.git"
QCBOR_TAG="v1.2"
QCBOR_COMMIT="92d3f89030baff4af7be8396c563e6c8ef263622"

T_COSE_REPO_URL="https://github.com/laurencelundblade/t_cose.git"
T_COSE_TAG="v2.0-alpha-2"
T_COSE_COMMIT="3076010eeb6383f0827bd992c75b68af9311cf1d"

TFM_EXTRAS_REPO_URL="https://git.trustedfirmware.org/TF-M/tf-m-extras.git"
TFM_EXTRAS_TAG="2ac90aff6da35cde4a67f2d34076b1adf6ca9161"
TFM_EXTRAS_COMMIT="2ac90aff6da35cde4a67f2d34076b1adf6ca9161"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --output-dir DIR        Output directory (default: results/tfm_an521)
  --third-party-dir DIR   Third-party checkout directory (default: third_party)
  --docker-image IMAGE    Docker build image (default: tardigrade-oss-validation:latest)
  --primary-version VER   Primary image version (default: 2.3.1)
  --staging-version VER   Staging image version (default: 2.4.0)
  --upgrade-strategy STR  MCUboot upgrade strategy (default: SWAP_USING_MOVE)
  --strategy STR          Alias for --upgrade-strategy
  --jobs N                Parallel build jobs (default: 4)
  --prepare-only          Clone/verify and patch third_party repositories only
  --package-only          Sign and package existing build outputs without rebuilding
  -h, --help              Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --third-party-dir)
      THIRD_PARTY_DIR="$2"
      shift 2
      ;;
    --docker-image)
      DOCKER_IMAGE="$2"
      shift 2
      ;;
    --primary-version)
      PRIMARY_VERSION="$2"
      shift 2
      ;;
    --staging-version)
      STAGING_VERSION="$2"
      shift 2
      ;;
    --upgrade-strategy|--strategy)
      UPGRADE_STRATEGY="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    --prepare-only)
      PREPARE_ONLY=1
      shift
      ;;
    --package-only)
      PACKAGE_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$THIRD_PARTY_DIR"
THIRD_PARTY_DIR="$(cd "$THIRD_PARTY_DIR" && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

case "$OUTPUT_DIR" in
  "$REPO_ROOT"/*)
    REL_OUTPUT_DIR="${OUTPUT_DIR#"$REPO_ROOT"/}"
    ;;
  *)
    echo "Error: --output-dir ($OUTPUT_DIR) must reside inside $REPO_ROOT for container mount." >&2
    exit 1
    ;;
esac

case "$THIRD_PARTY_DIR" in
  "$REPO_ROOT"/*)
    REL_THIRD_PARTY_DIR="${THIRD_PARTY_DIR#"$REPO_ROOT"/}"
    ;;
  *)
    echo "Error: --third-party-dir ($THIRD_PARTY_DIR) must reside inside $REPO_ROOT for container mount." >&2
    exit 1
    ;;
esac

ensure_pinned_repo() {
  local name="$1"
  local url="$2"
  local ref="$3"
  local expected_commit="$4"
  local repo_dir="$THIRD_PARTY_DIR/$name"

  if [[ ! -d "$repo_dir/.git" && ! -f "$repo_dir/.git" ]]; then
    echo "Cloning $name ($ref) from $url..."
    if [[ "$ref" == "$expected_commit" ]]; then
      git clone "$url" "$repo_dir"
      git -C "$repo_dir" checkout "$expected_commit"
    else
      git clone --depth 1 --branch "$ref" "$url" "$repo_dir"
    fi
  fi

  local head_commit
  head_commit="$(git -C "$repo_dir" rev-parse HEAD)"
  if [[ "$head_commit" != "$expected_commit" ]]; then
    echo "Error: $name HEAD is $head_commit, expected $expected_commit" >&2
    exit 1
  fi
  echo "Verified $name at $head_commit ($(git -C "$repo_dir" describe --tags --always))"
}

apply_tfm_ext_patches() {
  local tfm_ext="$THIRD_PARTY_DIR/trusted-firmware-m/lib/ext"
  local pair repo patch_dir p
  for pair in "cmsis:cmsis" "mcuboot:mcuboot" "qcbor:qcbor" "t_cose:t_cose" "tf-psa-crypto:tf-psa-crypto"; do
    repo="${pair%%:*}"
    patch_dir="${pair##*:}"
    for p in "$tfm_ext/$patch_dir"/*.patch; do
      [[ -e "$p" ]] || continue
      if git -C "$THIRD_PARTY_DIR/$repo" apply --check "$p" 2>/dev/null; then
        git -C "$THIRD_PARTY_DIR/$repo" apply "$p"
        echo "Applied $(basename "$p") to $repo"
      elif git -C "$THIRD_PARTY_DIR/$repo" apply --reverse --check "$p" 2>/dev/null; then
        :
      else
        echo "Patch $(basename "$p") already applied or handled in $repo"
      fi
    done
  done

  python3 - "$THIRD_PARTY_DIR/trusted-firmware-m" <<'PY'
import sys
from pathlib import Path

tfm_root = Path(sys.argv[1])
needle = '"   bne      ns_agent_nspe_jump_panic       \\n"\n'
insert = (
    needle
    + '        "   mrs      r2, control                    \\n"\n'
    + '        "   bic      r2, r2, #2                     \\n"\n'
    + '        "   msr      control, r2                    \\n"\n'
    + '        "   isb                                     \\n"\n'
)
for rel in (
    "secure_fw/partitions/ns_agent_tz/ns_agent_tz_v80m.c",
    "secure_fw/partitions/ns_agent_tz/ns_agent_tz.c",
):
    path = tfm_root / rel
    text = path.read_text(encoding="utf-8")
    if "bic      r2, r2, #2" not in text:
        if needle not in text:
            raise RuntimeError(f"Expected handoff needle not found in {path}")
        path.write_text(text.replace(needle, insert, 1), encoding="utf-8")
        print(f"Patched {rel} for Non-Secure MSP_NS handoff")
PY
}

ensure_pinned_repo "trusted-firmware-m" "$TFM_REPO_URL" "$TFM_TAG" "$TFM_COMMIT"
ensure_pinned_repo "tf-m-tests" "$TFM_TESTS_REPO_URL" "$TFM_TESTS_TAG" "$TFM_TESTS_COMMIT"
ensure_pinned_repo "mcuboot" "$MCUBOOT_REPO_URL" "$MCUBOOT_TAG" "$MCUBOOT_COMMIT"
ensure_pinned_repo "tf-psa-crypto" "$TF_PSA_CRYPTO_REPO_URL" "$TF_PSA_CRYPTO_TAG" "$TF_PSA_CRYPTO_COMMIT"
ensure_pinned_repo "cmsis" "$CMSIS_REPO_URL" "$CMSIS_TAG" "$CMSIS_COMMIT"
ensure_pinned_repo "qcbor" "$QCBOR_REPO_URL" "$QCBOR_TAG" "$QCBOR_COMMIT"
ensure_pinned_repo "t_cose" "$T_COSE_REPO_URL" "$T_COSE_TAG" "$T_COSE_COMMIT"
ensure_pinned_repo "tf-m-extras" "$TFM_EXTRAS_REPO_URL" "$TFM_EXTRAS_TAG" "$TFM_EXTRAS_COMMIT"

apply_tfm_ext_patches

if [[ "$PREPARE_ONLY" -eq 1 ]]; then
  exit 0
fi

docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT:/workspace" \
  -w /workspace \
  -e REL_OUTPUT_DIR="$REL_OUTPUT_DIR" \
  -e REL_THIRD_PARTY_DIR="$REL_THIRD_PARTY_DIR" \
  -e PRIMARY_VERSION="$PRIMARY_VERSION" \
  -e STAGING_VERSION="$STAGING_VERSION" \
  -e UPGRADE_STRATEGY="$UPGRADE_STRATEGY" \
  -e JOBS="$JOBS" \
  -e PACKAGE_ONLY="$PACKAGE_ONLY" \
  "$DOCKER_IMAGE" bash -lc '
set -euo pipefail
WORKSPACE="/workspace"
OUT_DIR="$WORKSPACE/$REL_OUTPUT_DIR"
TP_DIR="$WORKSPACE/$REL_THIRD_PARTY_DIR"
BUILD_ROOT="$OUT_DIR/build_test"

mkdir -p "$BUILD_ROOT/pypkgs" "$BUILD_ROOT/host-bin"
ln -sfn "$TP_DIR/trusted-firmware-m/bl2/ext/mcuboot/scripts" "$BUILD_ROOT/pypkgs/bl2"
ln -sfn "$TP_DIR/trusted-firmware-m/tools/modules" "$BUILD_ROOT/pypkgs/tfm_tools"
ln -sfn "$TP_DIR/mcuboot/scripts/imgtool" "$BUILD_ROOT/pypkgs/imgtool"

for entry in \
  "mcuboot_imagesign_wrapper:bl2.wrapper:main" \
  "mcuboot_imagesign_assemble:bl2.assemble:main" \
  "c_include:tfm_tools.c_include:main" \
  "c_macro:tfm_tools.c_macro:main" \
  "c_struct:tfm_tools.c_struct:main"; do
  name="${entry%%:*}"
  rest="${entry#*:}"
  mod="${rest%%:*}"
  fn="${rest##*:}"
  cat > "$BUILD_ROOT/host-bin/$name" <<EOF
#!/usr/bin/env python3
import sys
from $mod import $fn
sys.exit($fn())
EOF
  chmod +x "$BUILD_ROOT/host-bin/$name"
done

cat > "$BUILD_ROOT/host-bin/hex_generation" <<'\''EOF'\''
#!/usr/bin/env python3
import argparse, subprocess
p = argparse.ArgumentParser(allow_abbrev=False)
p.add_argument("--image_layout_h_file")
p.add_argument("--file_to_mirror")
p.add_argument("--compile_commands_file")
p.add_argument("--macro_name")
p.add_argument("--input_binary_file", required=True)
p.add_argument("--output_hex_file", required=True)
p.add_argument("--bl2_header_excluded", default=False, action=argparse.BooleanOptionalAction)
args = p.parse_args()
subprocess.run(["arm-none-eabi-objcopy", "-I", "binary", "-O", "ihex", args.input_binary_file, args.output_hex_file], check=True)
EOF
chmod +x "$BUILD_ROOT/host-bin/hex_generation"

export PATH="$BUILD_ROOT/host-bin:/opt/tardigrade-venv/bin:/opt/xpack-arm-none-eabi-gcc-13.2.1-1.1/bin:$PATH"
export PYTHONPATH="$BUILD_ROOT/pypkgs:$TP_DIR/mcuboot/scripts:${PYTHONPATH:-}"

if [[ "$PACKAGE_ONLY" -eq 0 ]]; then
  cmake -S "$TP_DIR/trusted-firmware-m" -B "$BUILD_ROOT/spe" -G Ninja \
    -DTFM_PLATFORM=arm/mps2/an521 \
    -DTFM_TOOLCHAIN_FILE="$TP_DIR/trusted-firmware-m/toolchain_GNUARM.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBL2=ON \
    -DMCUBOOT_IMAGE_NUMBER=2 \
    -DMCUBOOT_UPGRADE_STRATEGY="$UPGRADE_STRATEGY" \
    -DMCUBOOT_IMAGE_VERSION_S="$PRIMARY_VERSION" \
    -DMCUBOOT_IMAGE_VERSION_NS="$PRIMARY_VERSION" \
    -DTFM_MERGE_HEX_FILES=OFF \
    -DTFM_TEST_REPO_PATH="$TP_DIR/tf-m-tests" \
    -DMCUBOOT_PATH="$TP_DIR/mcuboot" \
    -DTF_PSA_CRYPTO_PATH="$TP_DIR/tf-psa-crypto" \
    -DCMSIS_PATH="$TP_DIR/cmsis" \
    -DQCBOR_PATH="$TP_DIR/qcbor" \
    -DT_COSE_PATH="$TP_DIR/t_cose" \
    -DTFM_EXTRAS_REPO_PATH="$TP_DIR/tf-m-extras"
  cmake --build "$BUILD_ROOT/spe" -- install -j"$JOBS"

  cmake -S "$TP_DIR/tf-m-tests/tests_reg" -B "$BUILD_ROOT/nspe" -G Ninja \
    -DCONFIG_SPE_PATH="$BUILD_ROOT/spe/api_ns" \
    -DTFM_TOOLCHAIN_FILE="$BUILD_ROOT/spe/api_ns/cmake/toolchain_ns_GNUARM.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DQCBOR_PATH="$TP_DIR/qcbor" \
    -DT_COSE_PATH="$TP_DIR/t_cose"
  cmake --build "$BUILD_ROOT/nspe" -j"$JOBS"
fi

cp "$BUILD_ROOT/spe/api_ns/bin/bl2.axf" "$OUT_DIR/bl2.axf"

STRATEGY_SIGN_ARGS=()
if [[ "$UPGRADE_STRATEGY" == "OVERWRITE_ONLY" ]]; then
  STRATEGY_SIGN_ARGS+=(--overwrite-only)
fi

mcuboot_imagesign_wrapper \
  --version "$PRIMARY_VERSION" \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_s.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_s_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(1, 0.0.0+0)" \
  "${STRATEGY_SIGN_ARGS[@]}" \
  --measured-boot-record \
  --psa-key-ids 2147451243 \
  "$BUILD_ROOT/spe/api_ns/bin/tfm_s.bin" \
  "$OUT_DIR/tfm_s_signed.bin"

mcuboot_imagesign_wrapper \
  --version "$PRIMARY_VERSION" \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_ns.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_ns_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(0, 0.0.0+0)" \
  "${STRATEGY_SIGN_ARGS[@]}" \
  --measured-boot-record \
  --psa-key-ids 2147451244 \
  "$BUILD_ROOT/nspe/bin/tfm_ns.bin" \
  "$OUT_DIR/tfm_ns_signed.bin"

mcuboot_imagesign_wrapper \
  --version "$STAGING_VERSION" \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_s.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_s_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(1, 0.0.0+0)" \
  "${STRATEGY_SIGN_ARGS[@]}" \
  --measured-boot-record \
  --psa-key-ids 2147451243 \
  "$BUILD_ROOT/spe/api_ns/bin/tfm_s.bin" \
  "$OUT_DIR/tfm_s_staging_signed.bin"

mcuboot_imagesign_wrapper \
  --version "$STAGING_VERSION" \
  --layout "$BUILD_ROOT/spe/api_ns/image_signing/layout_files/signing_layout_ns.o" \
  --key "$BUILD_ROOT/spe/api_ns/image_signing/keys/image_ns_signing_private_key.pem" \
  --public-key-format hash \
  --align 1 \
  --pad \
  --pad-header \
  -H 0x400 \
  -s 1 \
  -L 128 \
  -d "(0, 0.0.0+0)" \
  "${STRATEGY_SIGN_ARGS[@]}" \
  --measured-boot-record \
  --psa-key-ids 2147451244 \
  "$BUILD_ROOT/nspe/bin/tfm_ns.bin" \
  "$OUT_DIR/tfm_ns_staging_signed.bin"
'

python3 "$REPO_ROOT/targets/tf_m_bl2/generate_runtime_profile.py" --build-dir "$OUTPUT_DIR"
