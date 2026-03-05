#!/usr/bin/env bash
# Bootstrap Zephyr workspace + MCUboot for building from source in CI.
# Idempotent -- safe to run multiple times.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ZEPHYR_REF="${ZEPHYR_REF:-v3.6.0}"
ZEPHYR_WS="${REPO_ROOT}/third_party/zephyr_ws"
ZEPHYR_VENV="${REPO_ROOT}/third_party/zephyr-venv"
MCUBOOT_DIR="${ZEPHYR_WS}/bootloader/mcuboot"

msg() { echo ">> $*" >&2; }

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
    "${ZEPHYR_VENV}/bin/west" init \
        -m https://github.com/zephyrproject-rtos/zephyr \
        --mr "${ZEPHYR_REF}" "${ZEPHYR_WS}"
else
    msg "Zephyr workspace already initialized"
fi

# --- 3. Fetch Zephyr + MCUboot via west update ---
msg "Running west update (narrow + shallow)"
( cd "${ZEPHYR_WS}" && \
  "${ZEPHYR_VENV}/bin/west" update --narrow -o=--depth=1 )

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
      "${ZEPHYR_VENV}/bin/west" config build.generator "Ninja"
  else
      "${ZEPHYR_VENV}/bin/west" config build.generator "Unix Makefiles"
  fi )

msg "Bootstrap complete. Workspace: ${ZEPHYR_WS}"
