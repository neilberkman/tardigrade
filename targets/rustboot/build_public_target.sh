#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Tardigrade contributors
#
# Build the nRF52840 rustBoot target (bootloader ELF and signed v1/v2 firmware
# images) from upstream nihalpasham/rustBoot without shipping prebuilt binaries
# in the repository.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OUTPUT_DIR="$REPO_ROOT/results/rustboot_nrf52840"
THIRD_PARTY_DIR="$REPO_ROOT/third_party"
RUSTBOOT_REPO_URL="https://github.com/nihalpasham/rustBoot.git"
RUSTBOOT_REF="d4394d383ba3758574159c6630e4c3261a6b47f1"
RUST_TOOLCHAIN="nightly-2024-12-01"
BOOT_VERSION="1"
UPDATE_VERSION="2"
ALLOW_UNPINNED=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --output-dir DIR        Output directory (default: results/rustboot_nrf52840)
  --third-party-dir DIR   Third-party checkout directory (default: third_party)
  --rustboot-ref REF      Git commit or branch to build (default: $RUSTBOOT_REF)
  --toolchain TOOLCHAIN   Rust toolchain for Cortex-M4 build (default: $RUST_TOOLCHAIN)
  --allow-unpinned        Allow building a non-default upstream ref
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
    --rustboot-ref)
      RUSTBOOT_REF="$2"
      ALLOW_UNPINNED=1
      shift 2
      ;;
    --toolchain)
      RUST_TOOLCHAIN="$2"
      shift 2
      ;;
    --allow-unpinned)
      ALLOW_UNPINNED=1
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

mkdir -p "$THIRD_PARTY_DIR" "$OUTPUT_DIR"
THIRD_PARTY_DIR="$(cd "$THIRD_PARTY_DIR" && pwd)"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

RUSTBOOT_DIR="$THIRD_PARTY_DIR/rustBoot"
if [[ ! -d "$RUSTBOOT_DIR/.git" ]]; then
  echo "Cloning rustBoot from $RUSTBOOT_REPO_URL..."
  git clone "$RUSTBOOT_REPO_URL" "$RUSTBOOT_DIR"
fi

git -C "$RUSTBOOT_DIR" checkout -f --detach "$RUSTBOOT_REF"
HEAD_COMMIT="$(git -C "$RUSTBOOT_DIR" rev-parse HEAD)"
echo "$HEAD_COMMIT" > "$OUTPUT_DIR/rustboot_commit.txt"
echo "Building rustBoot nRF52840 at $HEAD_COMMIT..."

python3 - "$RUSTBOOT_DIR" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
boards_toml = root / "boards" / "Cargo.toml"
boards_toml.write_text(
    """[workspace]
resolver = "2"
members = [
    "update",
    "hal",
    "firmware/nrf52840/*",
    "bootloaders/nrf52840",
]

[profile.dev]
incremental = false
codegen-units = 1
debug = true
lto = false

[profile.release]
debug = true
lto = true
opt-level = 2
""",
    encoding="utf-8",
)
updt_toml = root / "boards" / "firmware" / "nrf52840" / "updt_fw_blinky_red" / "Cargo.toml"
text = updt_toml.read_text(encoding="utf-8")
text = text.replace('panic-probe = { version = "0.2.0" }', 'panic-probe = { version = "0.3.0" }')
if "critical-section-single-core" not in text:
    text = text.replace(
        'cortex-m-rt = "0.7"',
        'cortex-m = { version = "0.7", features = ["critical-section-single-core"] }\ncortex-m-rt = "0.7"',
    )
updt_toml.write_text(text, encoding="utf-8")
for cfg in root.glob("boards/**/.cargo/config.toml"):
    cfg_text = cfg.read_text(encoding="utf-8")
    cfg_text = cfg_text.replace('"-C", "linker=flip-link",', "")
    if "firmware" in cfg.as_posix():
        cfg_text = cfg_text.replace('"-C", "link-arg=-Tdefmt.x",', "")
    cfg.write_text(cfg_text, encoding="utf-8")
PY

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
rustup target add --toolchain "$RUST_TOOLCHAIN" thumbv7em-none-eabihf >/dev/null 2>&1 || true

(
  cd "$RUSTBOOT_DIR/boards"
  cargo +"$RUST_TOOLCHAIN" generate-lockfile
  cargo +"$RUST_TOOLCHAIN" update -p embedded-storage@0.3.2 --precise 0.3.1 || true
  cargo +"$RUST_TOOLCHAIN" update -p fixed@1.31.0 --precise 1.27.0 || true
  cargo +"$RUST_TOOLCHAIN" update -p time@0.3.55 --precise 0.3.36 || true
)
(
  cd "$RUSTBOOT_DIR/boards/firmware/nrf52840/boot_fw_blinky_green"
  cargo +"$RUST_TOOLCHAIN" build --release
)
(
  cd "$RUSTBOOT_DIR/boards/firmware/nrf52840/updt_fw_blinky_red"
  cargo +"$RUST_TOOLCHAIN" build --release
)
(
  cd "$RUSTBOOT_DIR/boards/bootloaders/nrf52840"
  cargo +"$RUST_TOOLCHAIN" build --release
)

OBJCOPY_BIN="$(command -v arm-none-eabi-objcopy || command -v rust-objcopy)"
if [[ -z "$OBJCOPY_BIN" ]]; then
  echo "Error: neither arm-none-eabi-objcopy nor rust-objcopy found on PATH" >&2
  exit 1
fi

SIGNED_DIR="$RUSTBOOT_DIR/boards/sign_images/signed_images"
mkdir -p "$SIGNED_DIR"
"$OBJCOPY_BIN" -I elf32-littlearm "$RUSTBOOT_DIR/boards/target/thumbv7em-none-eabihf/release/nrf52840_bootfw" -O binary "$SIGNED_DIR/nrf52840_bootfw.bin"
"$OBJCOPY_BIN" -I elf32-littlearm "$RUSTBOOT_DIR/boards/target/thumbv7em-none-eabihf/release/nrf52840_updtfw" -O binary "$SIGNED_DIR/nrf52840_updtfw.bin"

# Pad boot (4096B -> 4352B signed) and update (8192B -> 8448B signed) payloads
# to 256-byte flash-buffer boundaries with distinct sector counts, and ensure
# mtime < atime as asserted by rbsigner.
python3 - "$SIGNED_DIR/nrf52840_bootfw.bin" "$SIGNED_DIR/nrf52840_updtfw.bin" <<'PY'
import os
import sys
import time
from pathlib import Path

for arg, target_len in ((sys.argv[1], 4096), (sys.argv[2], 8192)):
    p = Path(arg)
    raw = p.read_bytes()
    if len(raw) < target_len:
        raw = raw + b"\x00" * (target_len - len(raw))
    p.write_bytes(raw)
    now = time.time()
    os.utime(p, (now + 10.0, now - 10.0))
PY

(
  cd "$RUSTBOOT_DIR/rbsigner"
  cargo +"$RUST_TOOLCHAIN" run --release -- mcu-image ../boards/sign_images/signed_images/nrf52840_bootfw.bin nistp256 ../boards/sign_images/keygen/ecc256.der "$BOOT_VERSION"
  cargo +"$RUST_TOOLCHAIN" run --release -- mcu-image ../boards/sign_images/signed_images/nrf52840_updtfw.bin nistp256 ../boards/sign_images/keygen/ecc256.der "$UPDATE_VERSION"
)

cp "$RUSTBOOT_DIR/boards/target/thumbv7em-none-eabihf/release/nrf52840" "$OUTPUT_DIR/rustboot_nrf52840.elf"
cp "$SIGNED_DIR/nrf52840_bootfw_v${BOOT_VERSION}_signed.bin" "$OUTPUT_DIR/rustboot_boot_v1.bin"
cp "$SIGNED_DIR/nrf52840_updtfw_v${UPDATE_VERSION}_signed.bin" "$OUTPUT_DIR/rustboot_update_v2.bin"

python3 "$REPO_ROOT/targets/rustboot/generate_runtime_profile.py" \
  --build-dir "$OUTPUT_DIR" \
  --output "$OUTPUT_DIR/rustboot_nrf52840_update.yaml"
python3 "$REPO_ROOT/targets/rustboot/generate_runtime_profile.py" \
  --build-dir "$OUTPUT_DIR" \
  --state-search \
  --name "rustboot_nrf52840_state_search" \
  --output "$OUTPUT_DIR/rustboot_nrf52840_state_search.yaml"
