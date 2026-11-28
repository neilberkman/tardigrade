#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Export a failing audit point or state as a standalone reproducer bundle."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any
import zlib

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from debug_point import (  # noqa: E402
    CODE_TO_FAULT_NAME,
    DEFAULT_RENODE_TEST,
    DEFAULT_ROBOT_SUITE,
    DebugError,
    DebugTarget,
    _cleanup_generated_robot_vars,
    _kill_process_group,
    _load_json_or_yaml_input,
    build_debug_robot_vars,
    resolve_debug_target,
)
from license_certify import _detect_gpl_license_marker  # noqa: E402
from profile_loader import load_profile_raw  # noqa: E402
from recovery_checkpoint import restore_snapshots  # noqa: E402
from recovery_search import first_persistent_difference  # noqa: E402
from recovery_state import PersistentState  # noqa: E402
from renode_runner import (  # noqa: E402
    DOCKER_RENODE_PREFIX,
    ensure_tool,
    prepare_renode_command,
    prepare_run_environment,
)


RENODE_RELEASE_ARCHIVES: dict[str, dict[str, str]] = {
    "1.17.0": {
        "url": "https://github.com/renode/renode/releases/download/v1.17.0/renode-1.17.0.linux-portable.tar.gz",
        "sha256": "4ba7c68b59e2447f188ef4b4b112fcccd2802582c460beedceb63b84e5605a5f",
    },
    "1.16.1": {
        "url": "https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-portable-dotnet.tar.gz",
        "sha256": "00e113cdbd0f5354cf2f64bbe3f5a070d8958409542fca66e45ac97d982938c0",
    },
}

DEFAULT_LICENSE_DECISIONS: dict[str, str] = {
    "Apache-2.0": "allow",
    "BSD-2-Clause": "allow",
    "BSD-3-Clause": "allow",
    "ISC": "allow",
    "MIT": "allow",
    "PSF-2.0": "allow",
    "MPL-2.0": "prohibit",
    "LGPL-3.0-only": "prohibit",
    "GPL-3.0-only": "prohibit",
    "GPL-3.0-only WITH GCC-exception-3.1": "prohibit",
}

PROHIBITED_LICENSE_TOKEN_RE = re.compile(
    r"\b(?:A|L)?GPL(?:-[0-9.]+(?:-(?:only|or-later)|\+)?)?\b"
    r"|\bMPL(?:-[0-9.]+)?\b"
    r"|\bCDDL(?:-[0-9.]+)?\b"
    r"|\bEPL(?:-[0-9.]+)?\b"
    r"|\bSLA0044\b"
    r"|\bProprietary\b"
    r"|\bNon-?Commercial\b"
    r"|\bForbid(?:den)?\b",
    re.IGNORECASE,
)

KNOWN_NON_REDISTRIBUTABLE_TARGETS: dict[str, dict[str, str]] = {
    "wolfboot": {
        "license_spdx": "GPL-3.0-or-later",
        "repository": "https://github.com/wolfSSL/wolfBoot.git",
        "commit": "ad8dc62131fc0067a3ab25edc1b7e731397712d4",
        "submodule_url": "https://github.com/wolfSSL/wolfssl.git",
        "submodule_commit": "f8a805dd64321bb4b396b99fa99b170b5b9cd3d7",
        "shipped_config": "config/examples/stm32f407-discovery.config",
        "recipe": "wolfboot",
    },
    "openblt": {
        "license_spdx": "GPL-3.0-or-later",
        "repository": "https://github.com/feaser/openblt.git",
        "commit": "64beeee6f24490f7ca3373185bfcd3188a6d3b15",
        "recipe": "openblt",
    },
    "uboot": {
        "license_spdx": "GPL-2.0-or-later",
        "recipe": "none",
    },
    "u-boot": {
        "license_spdx": "GPL-2.0-or-later",
        "recipe": "none",
    },
    "barebox": {
        "license_spdx": "GPL-2.0-only",
        "recipe": "none",
    },
}

# Canonical peripheral compilation order matching tests/ota_fault_point.robot
PERIPHERAL_LOAD_ORDER: tuple[str, ...] = (
    "ITardigradeFaultInjectable.cs",
    "NVMemoryController.cs",
    "GenericNvmController.cs",
    "FaultTracker.cs",
    "CFIFlash.cs",
    "MappedMRAMTracker.cs",
    "An521NvmInterceptor.cs",
    "NRF52NVMC.cs",
    "NRF52UARTE.cs",
    "SimpleCacheController.cs",
    "TraceReplayEngine.cs",
    "Sse200MpcStub.cs",
    "CMSDKAPBWatchdog.cs",
    "STM32F1FlashController.cs",
    "STM32F4FlashController.cs",
    "STM32F4FlashInterceptor.cs",
    "STM32F4FastFlash.cs",
    "STM32F4RCCStub.cs",
    "STM32H7FlashController.cs",
    "STM32H7FastFlash.cs",
    "STM32H7RCCStub.cs",
    "STM32H7PWRStub.cs",
    "STM32L4FlashController.cs",
    "STM32DummyUSART.cs",
    "OTPMemory.cs",
    "I2CFaultProxy.cs",
    "SPINORFlash.cs",
    "I2CEEPROM.cs",
    "PowerResetDomain.cs",
    "ARM_SP804PrimeCellTimer.cs",
    "PL061Stub.cs",
    "QEMUFwCfg.cs",
    "QEMUVirtARMv7A.cs",
)

PERIPHERAL_CLASS_TO_FILE: dict[str, str] = {
    "ITardigradeFaultInjectable": "ITardigradeFaultInjectable.cs",
    "NVMemory": "NVMemoryController.cs",
    "NVMemoryController": "NVMemoryController.cs",
    "GenericNvmController": "GenericNvmController.cs",
    "FaultTracker": "FaultTracker.cs",
    "CFIFlash": "CFIFlash.cs",
    "MappedMRAMTracker": "MappedMRAMTracker.cs",
    "An521NvmInterceptor": "An521NvmInterceptor.cs",
    "NRF52NVMC": "NRF52NVMC.cs",
    "NRF52UARTE": "NRF52UARTE.cs",
    "SimpleCacheController": "SimpleCacheController.cs",
    "TraceReplayEngine": "TraceReplayEngine.cs",
    "Sse200MpcStub": "Sse200MpcStub.cs",
    "CMSDKAPBWatchdog": "CMSDKAPBWatchdog.cs",
    "STM32F1FlashController": "STM32F1FlashController.cs",
    "STM32F1RCCStub": "STM32F1FlashController.cs",
    "STM32F1DeviceInfoStub": "STM32F1FlashController.cs",
    "STM32F4FlashController": "STM32F4FlashController.cs",
    "STM32F4FlashInterceptor": "STM32F4FlashInterceptor.cs",
    "STM32F4FastFlash": "STM32F4FastFlash.cs",
    "STM32F4RCCStub": "STM32F4RCCStub.cs",
    "STM32H7FlashController": "STM32H7FlashController.cs",
    "STM32H7FastFlash": "STM32H7FastFlash.cs",
    "STM32H7RCCStub": "STM32H7RCCStub.cs",
    "STM32H7PWRStub": "STM32H7PWRStub.cs",
    "STM32L4FlashController": "STM32L4FlashController.cs",
    "STM32L4RCCStub": "STM32L4FlashController.cs",
    "STM32L4DeviceInfoStub": "STM32L4FlashController.cs",
    "STM32DummyUSART": "STM32DummyUSART.cs",
    "OTPMemory": "OTPMemory.cs",
    "I2CFaultProxy": "I2CFaultProxy.cs",
    "SPINORFlash": "SPINORFlash.cs",
    "I2CEEPROM": "I2CEEPROM.cs",
    "PowerResetDomain": "PowerResetDomain.cs",
    "ARM_SP804PrimeCellTimer": "ARM_SP804PrimeCellTimer.cs",
    "PL061Stub": "PL061Stub.cs",
    "QEMUFwCfg": "QEMUFwCfg.cs",
    "QEMUVirtARMv7A": "QEMUVirtARMv7A.cs",
}

PERIPHERAL_FILE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "NVMemoryController.cs": ("ITardigradeFaultInjectable.cs",),
    "GenericNvmController.cs": ("ITardigradeFaultInjectable.cs", "NVMemoryController.cs"),
    "FaultTracker.cs": ("ITardigradeFaultInjectable.cs",),
    "CFIFlash.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "MappedMRAMTracker.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "NVMemoryController.cs",
    ),
    "An521NvmInterceptor.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "NRF52NVMC.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "NVMemoryController.cs",
    ),
    "TraceReplayEngine.cs": ("ITardigradeFaultInjectable.cs",),
    "STM32F1FlashController.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "STM32F4FlashController.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "STM32F4FlashInterceptor.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "STM32F4FlashController.cs",
    ),
    "STM32F4FastFlash.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "STM32H7FlashController.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "STM32H7FastFlash.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "STM32H7FlashController.cs",
    ),
    "STM32L4FlashController.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "OTPMemory.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "I2CFaultProxy.cs": ("ITardigradeFaultInjectable.cs", "FaultTracker.cs"),
    "SPINORFlash.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "NRF52NVMC.cs",
        "TraceReplayEngine.cs",
    ),
    "I2CEEPROM.cs": (
        "ITardigradeFaultInjectable.cs",
        "FaultTracker.cs",
        "TraceReplayEngine.cs",
    ),
}


class ExportReproError(DebugError):
    """Raised when a finding cannot be exported as a standalone reproducer."""


@dataclass(frozen=True)
class LicenseDecision:
    redistributable: bool
    license_spdx: str
    reason: str
    fetch_and_build_script: str | None = None
    target_source: dict[str, Any] | None = None


@dataclass(frozen=True)
class ReconstructedState:
    nvm_bytes: bytes
    base_address: int
    size: int
    sha256: str
    state_identity: str
    backend_kind: str
    flash_backend: str
    uncorrectable_offsets: tuple[int, ...]
    uncorrectable_words: tuple[str, ...]
    mram_torn_word: str
    torn_word: str
    persistent_values: dict[str, str]
    renode_version: str | None = None
    state_source: str = "emulator_capture"
    fully_specified: bool = True
    specified_regions: tuple[dict[str, Any], ...] = ()
    unspecified_regions: tuple[dict[str, Any], ...] = ()


def _reword_debug_error(message: str) -> str:
    text = re.sub(r"\bcannot debug\b", "cannot export", str(message))
    text = re.sub(r"\bwhen debugging\b", "when exporting", text)
    text = re.sub(r"\bto debug\b", "to export", text)
    return text


def resolve_export_target(
    *,
    report: Path | None = None,
    point: str | None = None,
    state: str | None = None,
    reproduction: str | Path | None = None,
    profile: Path | None = None,
    elf: Path | None = None,
    repo_root: Path = REPO_ROOT,
) -> DebugTarget:
    import debug_point as _dp

    orig_loader = _dp._load_profile_and_elf

    def _export_load_profile_and_elf(
        profile_path: Path,
        *,
        explicit_elf: Path | None,
        component: str | None,
        repo_root: Path,
    ):
        try:
            return orig_loader(
                profile_path,
                explicit_elf=explicit_elf,
                component=component,
                repo_root=repo_root,
            )
        except DebugError as exc:
            msg = str(exc)
            if explicit_elf is None and msg.startswith("bootloader ELF not found: "):
                missing_elf = Path(msg[len("bootloader ELF not found: ") :].strip())
                prof_obj = _dp.load_profile(profile_path, repo_root=repo_root)
                low_name = prof_obj.name.lower()
                if any(
                    low_name.startswith(k) or elf_path_matches_known(missing_elf, k)
                    for k in KNOWN_NON_REDISTRIBUTABLE_TARGETS
                ):
                    return prof_obj, missing_elf
            raise

    _dp._load_profile_and_elf = _export_load_profile_and_elf
    try:
        target = resolve_debug_target(
            report=report,
            point=point,
            state=state,
            reproduction=reproduction,
            profile=profile,
            elf=elf,
            stop_at="recovery-reset",
            repo_root=repo_root,
        )
    except DebugError as exc:
        raise ExportReproError(_reword_debug_error(str(exc))) from exc
    finally:
        _dp._load_profile_and_elf = orig_loader

    if report is not None:
        try:
            object.__setattr__(target, "_report_path", Path(report).expanduser().resolve())
        except Exception:
            pass

    if target.is_control:
        raise ExportReproError(
            f"cannot export clean control point {target.point_name!r}: "
            "export-repro requires a faulted point or recovery state"
        )

    row = target.row or {}
    raw_outcome = str(row.get("boot_outcome") or target.expected_outcome or "").strip()
    if raw_outcome in ("pending_shard_merge", "checkpoint_pending"):
        if target.pre_recovery_state is None and target.checkpoint_snapshot is None:
            raise ExportReproError(
                f"cannot export unbooted point {target.point_name!r} ({raw_outcome}): "
                "state has not been evaluated and has no persistent snapshot"
            )

    if not target.cuts and target.pre_recovery_state is None and target.checkpoint_snapshot is None:
        raise ExportReproError(
            f"cannot export point {target.point_name!r}: "
            "point has neither a cut sequence nor a pre-recovery persistent state snapshot"
        )

    for cut_idx, (_cut_at, cut_code) in enumerate(target.cuts, start=1):
        base_code = str(cut_code or "w").split(":", 1)[0]
        if base_code not in ("w", "e", "a", "t", "op", "m"):
            fault_label = CODE_TO_FAULT_NAME.get(base_code, cut_code)
            raise ExportReproError(
                f"cannot export point {target.point_name!r}: cut {cut_idx} fault type "
                f"{fault_label!r} ({cut_code}) does not produce a reconstructible "
                "power-loss recovery state"
            )

    return target


def _load_license_policy(repo_root: Path) -> dict[str, str]:
    decisions = dict(DEFAULT_LICENSE_DECISIONS)
    policy_path = repo_root / "docs" / "license-certification-policy.json"
    if policy_path.is_file():
        try:
            data = json.loads(policy_path.read_text(encoding="utf-8"))
            for spdx, rule in (data.get("licenses") or {}).items():
                if isinstance(rule, dict) and isinstance(rule.get("decision"), str):
                    decisions[str(spdx)] = str(rule["decision"]).strip().lower()
        except Exception:
            pass
    return decisions


def _is_license_allowed(spdx_expr: str, policy_decisions: dict[str, str]) -> bool:
    expr = str(spdx_expr or "").strip()
    if not expr:
        return True
    if expr in policy_decisions:
        return policy_decisions[expr] == "allow"
    if PROHIBITED_LICENSE_TOKEN_RE.search(expr):
        return False
    tokens = [
        tok.strip()
        for tok in re.split(r"\s+(?:AND|OR|WITH)\s+|[()/]", expr, flags=re.I)
        if tok.strip()
    ]
    if not tokens:
        return False
    for tok in tokens:
        if tok in policy_decisions:
            if policy_decisions[tok] != "allow":
                return False
        elif PROHIBITED_LICENSE_TOKEN_RE.search(tok):
            return False
        else:
            return False
    return True


def _detect_file_gpl_or_prohibited(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    text = data.decode("utf-8", errors="ignore")
    for match in re.finditer(
        r"SPDX-License-Identifier\s*:\s*([^\r\n*/]+)",
        text,
        re.IGNORECASE,
    ):
        spdx_expr = match.group(1).strip()
        if PROHIBITED_LICENSE_TOKEN_RE.search(spdx_expr):
            return f"SPDX-License-Identifier: {spdx_expr}"
    if re.search(
        r"redistribute(?:\s|\*)+it(?:\s|\*)+and/or(?:\s|\*)+modify(?:\s|\*)+it"
        r"(?:\s|\*)+under(?:\s|\*)+the(?:\s|\*)+terms(?:\s|\*)+of(?:\s|\*)+the"
        r"(?:\s|\*)+GNU(?:\s|\*)+(?:(?:Affero|Lesser|Library)(?:\s|\*)+)?"
        r"General(?:\s|\*)+Public(?:\s|\*)+License",
        text,
        re.IGNORECASE,
    ):
        return "GNU General Public License grant notice"
    return None


def _render_wolfboot_fetch_and_build_script(
    *,
    elf_rel_name: str,
    exec_img_rel_name: str | None,
    staging_img_rel_name: str | None,
    repository: str,
    commit: str,
    submodule_url: str,
    submodule_commit: str,
    shipped_config: str,
) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "# Fetch and build wolfBoot from pinned upstream sources.",
        "# wolfBoot is licensed under GPL-3.0-or-later; Tardigrade does not bundle",
        "# its source or binary artifacts in exported reproducer bundles.",
        "set -euo pipefail",
        "",
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'FIRMWARE_DIR="${SCRIPT_DIR}/firmware"',
        'WORK_DIR="${WOLFBOOT_BUILD_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/repro-wolfboot-build.XXXXXX")}"',
        f'REPO_URL={shlex.quote(repository)}',
        f'PINNED_COMMIT={shlex.quote(commit)}',
        f'SUBMODULE_URL={shlex.quote(submodule_url)}',
        f'SUBMODULE_COMMIT={shlex.quote(submodule_commit)}',
        f'SHIPPED_CONFIG={shlex.quote(shipped_config)}',
        "",
        'if [[ "${1:-}" != "--force" && -f "${FIRMWARE_DIR}/' + elf_rel_name + '" ]]; then',
        "    exit 0",
        "fi",
        "",
        "for tool in git make arm-none-eabi-gcc arm-none-eabi-objcopy; do",
        '    if ! command -v "${tool}" >/dev/null 2>&1; then',
        '        echo "ERROR: ${tool} is required to fetch and build wolfBoot from pinned sources" >&2',
        "        exit 1",
        "    fi",
        "done",
        "",
        'mkdir -p "${FIRMWARE_DIR}" "${WORK_DIR}"',
        'SRC_DIR="${WORK_DIR}/wolfBoot"',
        'git clone --no-checkout "${REPO_URL}" "${SRC_DIR}"',
        'git -C "${SRC_DIR}" fetch --depth 1 origin "${PINNED_COMMIT}"',
        'git -C "${SRC_DIR}" checkout --force --detach "${PINNED_COMMIT}"',
        'ACTUAL_COMMIT="$(git -C "${SRC_DIR}" rev-parse HEAD)"',
        'if [[ "${ACTUAL_COMMIT}" != "${PINNED_COMMIT}" ]]; then',
        '    echo "ERROR: wolfBoot HEAD ${ACTUAL_COMMIT} != pinned ${PINNED_COMMIT}" >&2',
        "    exit 1",
        "fi",
        'git -C "${SRC_DIR}" submodule update --init --depth 1 lib/wolfssl',
        'ACTUAL_SUB="$(git -C "${SRC_DIR}/lib/wolfssl" rev-parse HEAD)"',
        'if [[ "${ACTUAL_SUB}" != "${SUBMODULE_COMMIT}" ]]; then',
        '    echo "ERROR: wolfssl submodule ${ACTUAL_SUB} != pinned ${SUBMODULE_COMMIT}" >&2',
        "    exit 1",
        "fi",
        'cp "${SRC_DIR}/${SHIPPED_CONFIG}" "${SRC_DIR}/.config"',
        'make -C "${SRC_DIR}" keytools',
        '(cd "${SRC_DIR}" && ./tools/keytools/keygen --ed25519 -g wolfboot_signing_private_key.der)',
        'make -C "${SRC_DIR}" wolfboot.bin test-app/image.bin',
        '(cd "${SRC_DIR}" && ./tools/keytools/sign --ed25519 --sha256 test-app/image.bin wolfboot_signing_private_key.der 1)',
        '(cd "${SRC_DIR}" && ./tools/keytools/sign --ed25519 --sha256 test-app/image.bin wolfboot_signing_private_key.der 2)',
        f'cp "${{SRC_DIR}}/wolfboot.elf" "${{FIRMWARE_DIR}}/{elf_rel_name}"',
    ]
    if exec_img_rel_name:
        lines.append(
            f'cp "${{SRC_DIR}}/test-app/image_v1_signed.bin" "${{FIRMWARE_DIR}}/{exec_img_rel_name}"'
        )
    if staging_img_rel_name:
        lines.append(
            f'cp "${{SRC_DIR}}/test-app/image_v2_signed.bin" "${{FIRMWARE_DIR}}/{staging_img_rel_name}"'
        )
    lines.append('echo "[fetch_and_build] Built wolfBoot ${PINNED_COMMIT} into ${FIRMWARE_DIR}"')
    return "\n".join(lines) + "\n"


def _render_generic_pinned_fetch_and_build_script(
    *,
    target_name: str,
    repository: str,
    commit: str,
    elf_rel_name: str,
    build_command: str | None = None,
) -> str:
    build_cmd_line = (
        build_command
        if build_command
        else f'make -C "${{SRC_DIR}}" && cp "${{SRC_DIR}}"/*.elf "${{FIRMWARE_DIR}}/{elf_rel_name}"'
    )
    return (
        "#!/usr/bin/env bash\n"
        f"# Fetch and build {target_name} from pinned upstream source {repository} @ {commit}.\n"
        "set -euo pipefail\n\n"
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        'FIRMWARE_DIR="${SCRIPT_DIR}/firmware"\n'
        f'if [[ "${{1:-}}" != "--force" && -f "${{FIRMWARE_DIR}}/{elf_rel_name}" ]]; then\n'
        "    exit 0\n"
        "fi\n"
        f'REPO_URL={shlex.quote(repository)}\n'
        f'PINNED_COMMIT={shlex.quote(commit)}\n'
        'WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/repro-build.XXXXXX")"\n'
        'SRC_DIR="${WORK_DIR}/src"\n'
        'mkdir -p "${FIRMWARE_DIR}" "${SRC_DIR}"\n'
        'git clone --no-checkout "${REPO_URL}" "${SRC_DIR}"\n'
        'git -C "${SRC_DIR}" fetch --depth 1 origin "${PINNED_COMMIT}"\n'
        'git -C "${SRC_DIR}" checkout --force --detach "${PINNED_COMMIT}"\n'
        'ACTUAL_COMMIT="$(git -C "${SRC_DIR}" rev-parse HEAD)"\n'
        'if [[ "${ACTUAL_COMMIT}" != "${PINNED_COMMIT}" ]]; then\n'
        '    echo "ERROR: HEAD ${ACTUAL_COMMIT} != pinned ${PINNED_COMMIT}" >&2\n'
        "    exit 1\n"
        "fi\n"
        f"{build_cmd_line}\n"
    )


def resolve_upstream_provenance(
    target: DebugTarget,
    report_data: dict[str, Any] | None,
    raw_profile: dict[str, Any] | None,
    repo_root: Path,
) -> dict[str, str]:
    """Return upstream commit, repository, and target name for the finding."""
    sources = []
    if isinstance(report_data, dict) and isinstance(report_data.get("target_source"), dict):
        sources.append(report_data["target_source"])
    if isinstance(raw_profile, dict) and isinstance(raw_profile.get("target_source"), dict):
        sources.append(raw_profile["target_source"])
    prof_ts = getattr(target.profile, "target_source", None)
    if prof_ts is not None:
        if hasattr(prof_ts, "to_dict"):
            sources.append(prof_ts.to_dict())
        elif isinstance(prof_ts, dict):
            sources.append(prof_ts)

    for src in sources:
        rev = str(src.get("revision") or src.get("commit") or "").strip()
        repo = str(src.get("repository") or "").strip()
        name = str(src.get("name") or target.profile.name).strip()
        if rev:
            out = {"commit": rev, "name": name}
            if repo:
                out["repository"] = repo
            return out

    # Check adjacent <elf_stem>_commit.txt or mcuboot_head_commit.txt
    elf_path = target.elf_path
    commit_candidates = [
        elf_path.with_name(f"{elf_path.stem}_commit.txt"),
        elf_path.parent / "mcuboot_head_commit.txt",
    ]
    for cand in commit_candidates:
        if cand.is_file():
            try:
                commit_txt = cand.read_text(encoding="utf-8").strip().splitlines()[0].strip()
                if re.fullmatch(r"[0-9a-fA-F]{40}", commit_txt):
                    return {
                        "name": "mcuboot",
                        "repository": "https://github.com/mcu-tools/mcuboot",
                        "commit": commit_txt.lower(),
                    }
            except Exception:
                pass

    # Check adjacent provenance.json (e.g. targets/zephyr_external_nvm/build/provenance.json)
    prov_file = elf_path.parent / "provenance.json"
    if prov_file.is_file():
        try:
            prov_data = json.loads(prov_file.read_text(encoding="utf-8"))
            srcs = prov_data.get("sources") or {}
            if "nvs_broken" in elf_path.name and isinstance(srcs.get("zephyr_nvs_broken"), dict):
                s = srcs["zephyr_nvs_broken"]
                return {
                    "name": "zephyr-nvs-before-fix-c200ff1",
                    "repository": str(s.get("repository", "https://github.com/zephyrproject-rtos/zephyr")),
                    "commit": str(s.get("commit", "")),
                }
            if "nvs_fixed" in elf_path.name and isinstance(srcs.get("zephyr_nvs_fixed"), dict):
                s = srcs["zephyr_nvs_fixed"]
                return {
                    "name": "zephyr-nvs-fix-c200ff1",
                    "repository": str(s.get("repository", "https://github.com/zephyrproject-rtos/zephyr")),
                    "commit": str(s.get("commit", "")),
                }
        except Exception:
            pass

    if isinstance(report_data, dict):
        git_meta = report_data.get("git")
        if isinstance(git_meta, dict) and git_meta.get("commit") and git_meta["commit"] != "unavailable":
            return {
                "name": target.profile.name,
                "commit": str(git_meta["commit"]).strip(),
            }
        inputs_meta = report_data.get("inputs")
        if isinstance(inputs_meta, dict) and inputs_meta.get("tardigrade_revision"):
            return {
                "name": target.profile.name,
                "commit": str(inputs_meta["tardigrade_revision"]).strip(),
            }

    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return {
                "name": target.profile.name,
                "commit": proc.stdout.strip(),
            }
    except Exception:
        pass

    return {
        "name": target.profile.name,
        "commit": "unknown",
    }


def classify_target_license(
    target: DebugTarget,
    report_data: dict[str, Any] | None,
    raw_profile: dict[str, Any] | None,
    repo_root: Path,
) -> LicenseDecision:
    policy_decisions = _load_license_policy(repo_root)
    provenance = resolve_upstream_provenance(target, report_data, raw_profile, repo_root)

    declared_licenses: list[str] = []
    for obj in (report_data, raw_profile):
        if not isinstance(obj, dict):
            continue
        for key in ("license", "license_spdx"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                declared_licenses.append(val.strip())
        ts = obj.get("target_source")
        if isinstance(ts, dict):
            for key in ("license", "license_spdx"):
                val = ts.get(key)
                if isinstance(val, str) and val.strip():
                    declared_licenses.append(val.strip())
        bl = obj.get("bootloader")
        if isinstance(bl, dict):
            for key in ("license", "license_spdx"):
                val = bl.get(key)
                if isinstance(val, str) and val.strip():
                    declared_licenses.append(val.strip())

    target_name_low = str(provenance.get("name") or target.profile.name).strip().lower()
    profile_name_low = target.profile.name.strip().lower()
    elf_str_low = str(target.elf_path).lower()

    known_entry = None
    for known_key, entry in KNOWN_NON_REDISTRIBUTABLE_TARGETS.items():
        if (
            target_name_low == known_key
            or profile_name_low.startswith(known_key)
            or f"/{known_key}/" in elf_str_low
            or elf_path_matches_known(target.elf_path, known_key)
        ):
            known_entry = entry
            break

    if known_entry is not None and not declared_licenses:
        declared_licenses.append(known_entry["license_spdx"])

    # Also scan ELF/image files and any adjacent LICENSE/COPYING file for GPL/prohibited markers
    file_markers: list[str] = []
    files_to_check = [target.elf_path]
    for img_path_str in target.profile.images.values():
        try:
            resolved_img = Path(target.profile.resolve_path(repo_root, img_path_str))
            files_to_check.append(resolved_img)
        except Exception:
            pass
    for check_path in files_to_check:
        marker = _detect_file_gpl_or_prohibited(check_path)
        if marker:
            file_markers.append(f"{check_path.name} ({marker})")
        for lic_name in ("LICENSE", "COPYING", "COPYING.GPL", "LICENSE.txt"):
            adj_lic = check_path.parent / lic_name
            if adj_lic.is_file() and adj_lic != (repo_root / "LICENSE"):
                adj_marker = _detect_file_gpl_or_prohibited(adj_lic)
                if adj_marker:
                    file_markers.append(f"{adj_lic.name} ({adj_marker})")

    license_spdx = declared_licenses[0] if declared_licenses else "Apache-2.0"
    is_allowed = all(_is_license_allowed(lic, policy_decisions) for lic in declared_licenses)
    if file_markers:
        is_allowed = False
        if license_spdx == "Apache-2.0":
            license_spdx = file_markers[0]

    exec_img_name = (
        Path(target.profile.images["exec"]).name if "exec" in target.profile.images else None
    )
    staging_img_name = (
        Path(target.profile.images["staging"]).name if "staging" in target.profile.images else None
    )

    if not is_allowed:
        if known_entry and known_entry.get("recipe") == "wolfboot":
            script_text = _render_wolfboot_fetch_and_build_script(
                elf_rel_name=target.elf_path.name,
                exec_img_rel_name=exec_img_name,
                staging_img_rel_name=staging_img_name,
                repository=provenance.get("repository") or known_entry["repository"],
                commit=provenance.get("commit") if provenance.get("commit") != "unknown" else known_entry["commit"],
                submodule_url=known_entry["submodule_url"],
                submodule_commit=known_entry["submodule_commit"],
                shipped_config=known_entry["shipped_config"],
            )
            return LicenseDecision(
                redistributable=False,
                license_spdx=license_spdx,
                reason=f"license {license_spdx} forbids binary redistribution; generated fetch_and_build.sh from pinned sources",
                fetch_and_build_script=script_text,
                target_source=provenance,
            )

        repo_url = provenance.get("repository") or (known_entry or {}).get("repository") or ""
        commit_sha = provenance.get("commit") or (known_entry or {}).get("commit") or ""
        raw_ts = (
            (raw_profile or {}).get("target_source")
            if isinstance((raw_profile or {}).get("target_source"), dict)
            else {}
        )
        build_cmd = raw_ts.get("build_command") if isinstance(raw_ts, dict) else None
        if repo_url and commit_sha and commit_sha != "unknown" and (not known_entry or known_entry.get("recipe") != "none"):
            script_text = _render_generic_pinned_fetch_and_build_script(
                target_name=provenance.get("name", target.profile.name),
                repository=repo_url,
                commit=commit_sha,
                elf_rel_name=target.elf_path.name,
                build_command=str(build_cmd) if build_cmd else None,
            )
            return LicenseDecision(
                redistributable=False,
                license_spdx=license_spdx,
                reason=f"license {license_spdx} forbids binary redistribution; generated fetch_and_build.sh from pinned sources",
                fetch_and_build_script=script_text,
                target_source=provenance,
            )

        raise ExportReproError(
            f"cannot export target {target.profile.name!r}: third-party license {license_spdx!r} "
            "forbids redistribution and no pinned upstream source repository/commit build script is available"
        )

    # Permissive target: check if it also has a pinned target_source / build script (e.g. zephyr_external_nvm)
    fetch_script = None
    if provenance.get("repository") and provenance.get("commit") and provenance["commit"] != "unknown":
        fetch_script = _render_generic_pinned_fetch_and_build_script(
            target_name=provenance.get("name", target.profile.name),
            repository=provenance["repository"],
            commit=provenance["commit"],
            elf_rel_name=target.elf_path.name,
        )

    return LicenseDecision(
        redistributable=True,
        license_spdx=license_spdx,
        reason=f"permissive license ({license_spdx}) permits bundling artifacts",
        fetch_and_build_script=fetch_script,
        target_source=provenance,
    )


def elf_path_matches_known(elf_path: Path, known_key: str) -> bool:
    name = elf_path.name.lower()
    return name.startswith(known_key)


def resolve_platform_and_peripherals(
    target: DebugTarget,
    repo_root: Path,
) -> tuple[list[Path], list[Path]]:
    """Return (repl_files, peripheral_cs_files) required by target.profile."""
    main_repl = Path(target.profile.resolve_path(repo_root, target.profile.platform)).resolve()
    if not main_repl.is_file():
        raise ExportReproError(f"platform description not found: {main_repl}")

    repl_files: list[Path] = []
    seen_repls: set[Path] = set()
    combined_repl_text: list[str] = []

    def _visit_repl(repl_path: Path) -> None:
        resolved = repl_path.resolve()
        if resolved in seen_repls or not resolved.is_file():
            return
        seen_repls.add(resolved)
        marker = _detect_gpl_license_marker(repo_root, resolved.relative_to(repo_root)) if _is_under(resolved, repo_root) else _detect_file_gpl_or_prohibited(resolved)
        if marker:
            raise ExportReproError(
                f"cannot bundle platform description {resolved.name}: prohibited license ({marker})"
            )
        repl_files.append(resolved)
        text = resolved.read_text(encoding="utf-8", errors="ignore")
        combined_repl_text.append(text)
        for match in re.finditer(r'using\s+"([^"]+)"', text):
            inc_rel = match.group(1)
            for cand in (resolved.parent / inc_rel, repo_root / inc_rel):
                if cand.is_file():
                    _visit_repl(cand)
                    break

    _visit_repl(main_repl)
    full_repl_text = "\n".join(
        re.sub(r"//[^\r\n]*", "", chunk) for chunk in combined_repl_text
    )

    needed_cs_names: set[str] = set()
    for class_name, cs_filename in PERIPHERAL_CLASS_TO_FILE.items():
        if re.search(r"\b" + re.escape(class_name) + r"\b", full_repl_text):
            needed_cs_names.add(cs_filename)

    if "@../peripherals/STM32H7Constructors.cs" in full_repl_text or "STM32H7" in full_repl_text:
        for h7_helper in ("STM32H7Constructors.cs", "STM32H7LegacyConstructors.cs"):
            if (repo_root / "peripherals" / h7_helper).is_file():
                needed_cs_names.add(h7_helper)

    if getattr(target.profile, "otp_peripheral", None):
        needed_cs_names.add("OTPMemory.cs")
    if getattr(target.profile, "nvm_controller", None):
        needed_cs_names.add("GenericNvmController.cs")
        needed_cs_names.add("NVMemoryController.cs")

    # Add transitive dependencies
    added = True
    while added:
        added = False
        for cs_name in list(needed_cs_names):
            for dep in PERIPHERAL_FILE_DEPENDENCIES.get(cs_name, ()):
                if dep not in needed_cs_names:
                    needed_cs_names.add(dep)
                    added = True

    if not needed_cs_names:
        needed_cs_names.update(("ITardigradeFaultInjectable.cs", "FaultTracker.cs"))

    ordered_cs_paths: list[Path] = []
    peripherals_dir = repo_root / "peripherals"
    for cs_name in PERIPHERAL_LOAD_ORDER:
        if cs_name in needed_cs_names:
            cs_path = (peripherals_dir / cs_name).resolve()
            if cs_path.is_file():
                ordered_cs_paths.append(cs_path)
    for cs_name in sorted(needed_cs_names):
        if cs_name not in PERIPHERAL_LOAD_ORDER:
            cs_path = (peripherals_dir / cs_name).resolve()
            if cs_path.is_file():
                ordered_cs_paths.append(cs_path)

    for extra in getattr(target.profile, "extra_peripherals", None) or ():
        extra_path = Path(target.profile.resolve_path(repo_root, extra)).resolve()
        if not extra_path.is_file():
            raise ExportReproError(f"extra peripheral not found: {extra_path}")
        if extra_path not in ordered_cs_paths:
            ordered_cs_paths.append(extra_path)

    for cs_path in ordered_cs_paths:
        marker = (
            _detect_gpl_license_marker(repo_root, cs_path.relative_to(repo_root))
            if _is_under(cs_path, repo_root)
            else _detect_file_gpl_or_prohibited(cs_path)
        )
        if marker:
            raise ExportReproError(
                f"cannot bundle peripheral source {cs_path.name}: prohibited license ({marker})"
            )

    return repl_files, ordered_cs_paths


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def detect_renode_version(
    *,
    explicit_version: str | None,
    report_data: dict[str, Any] | None,
    reconstructed_version: str | None,
    renode_test: str | None,
) -> str:
    if explicit_version and str(explicit_version).strip():
        return _normalize_renode_version_str(str(explicit_version).strip())

    candidates: list[str] = []
    if isinstance(report_data, dict):
        for val in (
            report_data.get("renode_version"),
            (report_data.get("execution") or {}).get("renode_version")
            if isinstance(report_data.get("execution"), dict)
            else None,
            (report_data.get("inputs") or {}).get("renode_version")
            if isinstance(report_data.get("inputs"), dict)
            else None,
            (
                ((report_data.get("summary") or {}).get("recovery_state_search") or {}).get("partition")
                or {}
            ).get("renode_version")
            if isinstance(report_data.get("summary"), dict)
            else None,
            (report_data.get("tool_versions") or {}).get("renode")
            if isinstance(report_data.get("tool_versions"), dict)
            else None,
        ):
            if isinstance(val, str) and val.strip():
                candidates.append(val.strip())

    if reconstructed_version and reconstructed_version.strip():
        candidates.append(reconstructed_version.strip())

    if renode_test and not str(renode_test).startswith(DOCKER_RENODE_PREFIX):
        runner_path = shutil.which(str(renode_test)) or (
            str(renode_test) if Path(str(renode_test)).is_file() else None
        )
        if runner_path:
            renode_bin = Path(runner_path).resolve().with_name("renode")
            for probe_bin in (renode_bin, Path(runner_path).resolve()):
                if probe_bin.is_file():
                    try:
                        proc = subprocess.run(
                            [str(probe_bin), "--version"],
                            capture_output=True,
                            text=True,
                            timeout=8,
                            check=False,
                        )
                        out = (proc.stdout or proc.stderr or "").strip()
                        if out:
                            candidates.append(out)
                            break
                    except Exception:
                        pass

    for raw in candidates:
        norm = _normalize_renode_version_str(raw)
        if norm:
            return norm

    return "1.17.0"


def _normalize_renode_version_str(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj.get("version"):
                text = str(obj["version"])
        except Exception:
            pass
    m = re.search(r"(?:^|[^\d.])(1\.\d+\.\d+)(?:$|[^\d])", text)
    if m:
        return m.group(1)
    return text.splitlines()[0].strip()


def _infer_platform_nvm_geometry(target: DebugTarget, repo_root: Path) -> tuple[int, int, str, int]:
    """Return (base_address, size, backend_kind, erase_fill) from platform .repl and profile."""
    repl_path = Path(target.profile.resolve_path(repo_root, target.profile.platform)).resolve()
    repl_text = repl_path.read_text(encoding="utf-8", errors="ignore") if repl_path.is_file() else ""
    fb = str(target.profile.flash_backend or "").strip()
    if fb.startswith("sysbus."):
        fb = fb[len("sysbus."):]

    erase_fill = (
        int(target.profile.memory.erase_fill)
        if target.profile.memory.erase_fill is not None
        else 0xFF
    )

    if fb == "mramTracker" or "MappedMRAMTracker" in repl_text:
        m_base = re.search(r"FlashBaseAddress:\s*(0x[0-9A-Fa-f]+|\d+)", repl_text)
        m_size = re.search(r"FlashSize:\s*(0x[0-9A-Fa-f]+|\d+)", repl_text)
        m_fill = re.search(r"EraseFill:\s*(0x[0-9A-Fa-f]+|\d+)", repl_text)
        base = int(m_base.group(1), 0) if m_base else int(target.profile.slots.exec_base)
        size = int(m_size.group(1), 0) if m_size else 0x4000
        if target.profile.memory.erase_fill is None and m_fill:
            erase_fill = int(m_fill.group(1), 0)
        elif target.profile.memory.erase_fill is None:
            erase_fill = 0x00
        return base, size, "mram", erase_fill

    if fb == "spiNor":
        m_block = re.search(
            r"spiNor:\s*SPI\.SPINORFlash[^\n]*\n((?:[ \t]+[^\n]+\n?)*)",
            repl_text,
        )
        block = m_block.group(1) if m_block else repl_text
        m_base = re.search(r"flashBaseAddress:\s*(0x[0-9A-Fa-f]+|\d+)", block)
        m_size = re.search(r"size:\s*(0x[0-9A-Fa-f]+|\d+)", block)
        base = int(m_base.group(1), 0) if m_base else 0x60000000
        size = int(m_size.group(1), 0) if m_size else 0x200000
        return base, size, "fast", erase_fill

    if fb == "i2cEeprom":
        m_block = re.search(
            r"i2cEeprom:\s*I2C\.I2CEEPROM[^\n]*\n((?:[ \t]+[^\n]+\n?)*)",
            repl_text,
        )
        block = m_block.group(1) if m_block else repl_text
        m_base = re.search(r"flashBaseAddress:\s*(0x[0-9A-Fa-f]+|\d+)", block)
        m_size = re.search(r"size:\s*(0x[0-9A-Fa-f]+|\d+)", block)
        base = int(m_base.group(1), 0) if m_base else 0x61000000
        size = int(m_size.group(1), 0) if m_size else 0x8000
        return base, size, "fast", erase_fill

    m_base = re.search(r"FlashBaseAddress:\s*(0x[0-9A-Fa-f]+|\d+)", repl_text)
    m_size = re.search(r"FlashSize:\s*(0x[0-9A-Fa-f]+|\d+)", repl_text)
    if m_base and m_size:
        return int(m_base.group(1), 0), int(m_size.group(1), 0), "fast", erase_fill

    slot_bases = [s.base for s in target.profile.memory.slots.values()]
    slot_ends = [s.base + s.size for s in target.profile.memory.slots.values()]
    min_base = min(slot_bases)
    max_end = max(slot_ends)
    return min_base, max_end - min_base, "fast", erase_fill


def _verify_rebuilt_state_python(
    rebuilt_state: PersistentState,
    *,
    expected_state_id: str | None = None,
    expected_explanation: dict[str, Any] | None = None,
    preloaded_state: PersistentState | None = None,
) -> str:
    actual_state_id = rebuilt_state.identity_hex().lower()
    exp_id = str(expected_state_id or "").strip().lower()
    if exp_id and not actual_state_id.startswith(exp_id):
        raise ExportReproError(
            f"rebuilt persistent state {actual_state_id} does not match expected state {exp_id}"
        )

    nvm_region = rebuilt_state.region("nvm")
    base_addr = int(nvm_region.base_address)
    rebuilt_bytes = bytearray(rebuilt_state.materialize()["nvm"])
    rebuilt_mark_addrs = {
        base_addr + int(off)
        for rname, off in rebuilt_state.uncorrectable_words
        if rname == "nvm"
    }
    rebuilt_pv_map = dict(rebuilt_state.persistent_values)

    if preloaded_state is not None:
        observed_values = {name: bytearray(val) for name, val in rebuilt_pv_map.items()}
        diff = first_persistent_difference(
            preloaded_state,
            {"nvm": rebuilt_bytes},
            rebuilt_state.uncorrectable_words,
            observed_values,
        )
        if diff is not None:
            raise ExportReproError(
                f"rebuilt persistent state differs from expected snapshot at "
                f"{diff.get('address', diff.get('name', 'unknown'))} "
                f"({diff.get('kind', 'mismatch')}; expected={diff.get('expected', 'n/a')} "
                f"observed={diff.get('observed', 'n/a')})"
            )

    if not isinstance(expected_explanation, dict):
        return actual_state_id

    fault_snap = expected_explanation.get("fault_snapshot")
    if isinstance(fault_snap, dict):
        exp_sha = str(fault_snap.get("sha256") or "").strip().lower()
        if exp_sha:
            actual_sha = hashlib.sha256(bytes(rebuilt_bytes)).hexdigest().lower()
            if actual_sha != exp_sha:
                raise ExportReproError(
                    f"rebuilt fault snapshot sha256 {actual_sha} does not match report fault_snapshot {exp_sha}"
                )
        if "uncorrectable_words" in fault_snap and fault_snap["uncorrectable_words"] is not None:
            exp_marks = {
                int(str(item), 0)
                for item in (fault_snap.get("uncorrectable_words") or ())
            }
            if rebuilt_mark_addrs != exp_marks:
                raise ExportReproError(
                    f"rebuilt uncorrectable words {sorted(rebuilt_mark_addrs)} do not match "
                    f"report fault_snapshot {sorted(exp_marks)}"
                )
        closest = fault_snap.get("closest_declared_image")
        if isinstance(closest, dict) and closest.get("ranges_truncated") is False:
            for span in closest.get("differing_ranges") or ():
                if not isinstance(span, dict) or span.get("bytes_truncated"):
                    continue
                addr = int(str(span["address"]), 0)
                exp_hex = str(span.get("actual_hex") or "").strip().lower()
                if not exp_hex:
                    continue
                span_len = len(exp_hex) // 2
                rel = addr - base_addr
                if 0 <= rel and rel + span_len <= len(rebuilt_bytes):
                    obs_hex = binascii.hexlify(bytes(rebuilt_bytes[rel : rel + span_len])).decode("ascii").lower()
                    if obs_hex != exp_hex:
                        raise ExportReproError(
                            f"rebuilt bytes at 0x{addr:08X} ({obs_hex}) do not match "
                            f"fault_snapshot differing_ranges ({exp_hex})"
                        )

    comparison = expected_explanation.get("state_comparison")
    if isinstance(comparison, dict):
        for span in comparison.get("ranges") or ():
            if not isinstance(span, dict) or not span.get("address"):
                continue
            exp_hex = str(span.get("failing_hex") or "").strip().lower()
            if not exp_hex:
                continue
            addr = int(str(span["address"]), 0)
            span_len = len(exp_hex) // 2
            rel = addr - base_addr
            if 0 <= rel and rel + span_len <= len(rebuilt_bytes):
                obs_hex = binascii.hexlify(bytes(rebuilt_bytes[rel : rel + span_len])).decode("ascii").lower()
                if obs_hex != exp_hex:
                    raise ExportReproError(
                        f"rebuilt bytes at 0x{addr:08X} ({obs_hex}) do not match "
                        f"failure_explanation state_comparison ({exp_hex})"
                    )
        for item in comparison.get("uncorrectable_only_in_failing") or ():
            addr = int(str(item), 0)
            if addr not in rebuilt_mark_addrs:
                raise ExportReproError(
                    f"rebuilt state is missing uncorrectable ECC mark at 0x{addr:08X} "
                    "required by failure_explanation"
                )
        for item in comparison.get("uncorrectable_only_in_passing") or ():
            addr = int(str(item), 0)
            if addr in rebuilt_mark_addrs:
                raise ExportReproError(
                    f"rebuilt state unexpectedly has uncorrectable ECC mark at 0x{addr:08X} "
                    "prohibited by failure_explanation"
                )
        for pv in comparison.get("persistent_values") or ():
            if not isinstance(pv, dict):
                continue
            pv_name = str(pv.get("name") or "").strip()
            exp_pv_hex = str(pv.get("failing_hex") or "").strip().lower()
            if pv_name and exp_pv_hex:
                obs_pv = rebuilt_pv_map.get(pv_name)
                obs_pv_hex = (
                    binascii.hexlify(bytes(bytearray(obs_pv))).decode("ascii").lower()
                    if obs_pv is not None
                    else ""
                )
                if obs_pv_hex != exp_pv_hex:
                    raise ExportReproError(
                        f"rebuilt persistent value {pv_name!r} ({obs_pv_hex}) does not match "
                        f"failure_explanation ({exp_pv_hex})"
                    )

    return actual_state_id


def _decode_preloaded_state_from_target(
    target: DebugTarget,
    report_data: dict[str, Any] | None = None,
) -> PersistentState | None:
    for ckpt_source in (target.checkpoint_snapshot, report_data):
        if isinstance(ckpt_source, dict) and ckpt_source.get("snapshots") and ckpt_source.get("chunks") is not None:
            restored = restore_snapshots(ckpt_source)
            if restored:
                if target.state_identity and target.state_identity in restored:
                    return restored[target.state_identity]
                return next(iter(restored.values()))
    if isinstance(target.pre_recovery_state, dict) and target.pre_recovery_state.get("zlib_b64"):
        encoded = target.pre_recovery_state
        raw = zlib.decompress(base64.b64decode(encoded["zlib_b64"]))
        base = int(str(encoded.get("base_address", "0")), 0)
        marks = []
        for item in encoded.get("uncorrectable_words") or ():
            addr = int(str(item), 0)
            if addr >= base:
                marks.append(("nvm", addr - base))
        persistent_values = {}
        for name, val_b64 in (encoded.get("persistent_values") or {}).items():
            if isinstance(val_b64, str) and val_b64:
                persistent_values[str(name)] = bytearray(base64.b64decode(val_b64))
        return PersistentState.from_bytes(
            bytearray(raw),
            name="nvm",
            base_address=base,
            uncorrectable_words=tuple(marks),
            persistent_values=persistent_values,
        )
    return None


def _reconstruct_state_via_renode(
    target: DebugTarget,
    *,
    renode_test: str,
    timeout: int,
    repo_root: Path,
) -> ReconstructedState:
    runner = ensure_tool(renode_test)
    robot_suite = str((repo_root / DEFAULT_ROBOT_SUITE).resolve())

    with tempfile.TemporaryDirectory(prefix="tardigrade_export_") as tmp_dir_raw:
        work_dir = Path(tmp_dir_raw).resolve()
        ready_file = work_dir / "debug_ready.json"
        export_state_file = work_dir / "exported_state.json"
        result_file = work_dir / "result.json"
        rf_results = work_dir / "robot"
        temp_root = work_dir / ".tmp"
        bundle_dir = work_dir / ".dotnet_bundle"
        renode_config = work_dir / "renode.config"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        timeout_s = max(1, int(timeout))
        robot_timeout_m = max(5, (timeout_s + 180 + 59) // 60)
        robot_vars, base_vars_for_cleanup = build_debug_robot_vars(
            target,
            stop_at="recovery-reset",
            port=3333,
            ready_file=ready_file,
            timeout_s=timeout_s,
            repo_root=repo_root,
        )
        try:
            expected_state_file = ready_file.parent / "debug_expected_state.json"
            if expected_state_file.is_file():
                expected_payload = json.loads(expected_state_file.read_text(encoding="utf-8"))
            else:
                expected_payload = {"state_identity": target.state_identity}
                robot_vars.append(f"DEBUG_EXPECTED_STATE_FILE:{expected_state_file}")
            expected_payload["export_state_file"] = str(export_state_file)
            expected_payload["no_gdb"] = True
            expected_state_file.write_text(
                json.dumps(expected_payload, sort_keys=True),
                encoding="utf-8",
            )

            env = prepare_run_environment(os.environ.copy(), bundle_dir, temp_root)
            cmd = [
                runner,
                "--renode-config",
                str(renode_config),
                robot_suite,
                "--results-dir",
                str(rf_results),
                "--variable",
                f"RESULT_FILE:{result_file}",
                "--variable",
                "CALIBRATION_MODE:false",
                "--variable",
                f"TEST_TIMEOUT:{robot_timeout_m} minutes",
            ]
            for rv in robot_vars:
                cmd.extend(["--variable", rv])
            cmd = prepare_renode_command(runner, cmd, repo_root, env)

            process = subprocess.Popen(
                cmd,
                cwd=str(repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=float(timeout_s) + 30.0)
            except subprocess.TimeoutExpired as exc:
                _kill_process_group(process)
                process.communicate()
                raise ExportReproError(
                    f"state reconstruction exceeded {timeout_s}s timeout"
                ) from exc

            if ready_file.is_file():
                try:
                    ready_payload = json.loads(ready_file.read_text(encoding="utf-8"))
                except Exception:
                    ready_payload = {}
                if ready_payload.get("error"):
                    raise ExportReproError(str(ready_payload["error"]))

            if process.returncode != 0:
                raise ExportReproError(
                    f"Renode state reconstruction failed (exit {process.returncode})\n"
                    f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
                )

            if not export_state_file.is_file():
                raise ExportReproError(
                    "Renode state reconstruction did not produce an exported state file"
                )
            meta = json.loads(export_state_file.read_text(encoding="utf-8"))
            bin_path = Path(str(meta.get("binary_file") or (str(export_state_file) + ".bin")))
            if not bin_path.is_file():
                raise ExportReproError(
                    f"Renode state reconstruction binary file missing: {bin_path}"
                )
            nvm_bytes = bin_path.read_bytes()
            base_addr = int(str(meta.get("base_address", "0")), 0)
            uncorr_offsets = tuple(int(x) for x in (meta.get("uncorrectable_offsets") or ()))
            uncorr_words = tuple(str(x) for x in (meta.get("uncorrectable_words") or ()))
            pv_map_b64 = {
                str(k): str(v)
                for k, v in (meta.get("persistent_values") or {}).items()
            }
            pv_bytes = {
                k: bytearray(base64.b64decode(v))
                for k, v in pv_map_b64.items()
            }
            rebuilt_state = PersistentState.from_bytes(
                bytearray(nvm_bytes),
                name="nvm",
                base_address=base_addr,
                uncorrectable_words=tuple(("nvm", off) for off in uncorr_offsets),
                persistent_values=pv_bytes,
            )
            verified_id = _verify_rebuilt_state_python(
                rebuilt_state,
                expected_state_id=target.state_identity,
                expected_explanation=target.expected_explanation,
                preloaded_state=_decode_preloaded_state_from_target(target),
            )
            return ReconstructedState(
                nvm_bytes=nvm_bytes,
                base_address=base_addr,
                size=len(nvm_bytes),
                sha256=hashlib.sha256(nvm_bytes).hexdigest().lower(),
                state_identity=verified_id,
                backend_kind=str(meta.get("backend_kind") or "fast"),
                flash_backend=str(meta.get("flash_backend") or target.profile.flash_backend or "faultFlash"),
                uncorrectable_offsets=uncorr_offsets,
                uncorrectable_words=uncorr_words,
                mram_torn_word=str(meta.get("mram_torn_word") or target.profile.fault_sweep.mram_torn_word or "half"),
                torn_word=str(meta.get("torn_word") or target.profile.fault_sweep.torn_word or "fixed"),
                persistent_values=pv_map_b64,
                renode_version=str(meta.get("renode_version") or "") or None,
                state_source="emulator_capture",
                fully_specified=True,
                specified_regions=(
                    {
                        "address": f"0x{base_addr:08X}",
                        "offset": 0,
                        "size": len(nvm_bytes),
                        "reason": "captured directly from Renode emulator at recovery-reset",
                    },
                ),
                unspecified_regions=(),
            )
        finally:
            _cleanup_generated_robot_vars(base_vars_for_cleanup)


def _merge_byte_intervals(
    total_size: int,
    intervals: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    clipped: list[tuple[int, int]] = []
    for start, end in intervals:
        s = max(0, min(int(total_size), int(start)))
        e = max(0, min(int(total_size), int(end)))
        if e > s:
            clipped.append((s, e))
    if not clipped:
        return []
    clipped.sort()
    merged: list[tuple[int, int]] = [clipped[0]]
    for s, e in clipped[1:]:
        prev_s, prev_e = merged[-1]
        if s <= prev_e:
            merged[-1] = (prev_s, max(prev_e, e))
        else:
            merged.append((s, e))
    return merged


def _complement_byte_intervals(
    total_size: int,
    intervals: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    merged = _merge_byte_intervals(total_size, intervals)
    if not merged:
        return [(0, int(total_size))] if total_size > 0 else []
    comp: list[tuple[int, int]] = []
    cursor = 0
    for s, e in merged:
        if s > cursor:
            comp.append((cursor, s))
        cursor = max(cursor, e)
    if cursor < total_size:
        comp.append((cursor, int(total_size)))
    return comp


def _resolve_op_offset(
    op: dict[str, Any],
    *,
    base_addr: int,
    nvm_size: int,
) -> int | None:
    for key in ("flash_offset", "offset"):
        if op.get(key) is not None:
            try:
                off = int(str(op[key]), 0)
                if 0 <= off < nvm_size:
                    return off
                rel = off - base_addr
                if 0 <= rel < nvm_size:
                    return rel
            except Exception:
                pass
    if op.get("address") not in (None, ""):
        try:
            addr = int(str(op["address"]), 0)
            rel = addr - base_addr
            if 0 <= rel < nvm_size:
                return rel
        except Exception:
            pass
    return None


def _resolve_erase_size(
    op: dict[str, Any],
    *,
    rel_offset: int,
    base_addr: int,
    target: DebugTarget,
) -> int:
    for key in ("erase_size", "size"):
        if op.get(key) is not None:
            try:
                sz = int(str(op[key]), 0)
                if sz > 0:
                    return sz
            except Exception:
                pass
    abs_addr = base_addr + rel_offset
    for region in getattr(target.profile.memory, "erase_regions", None) or ():
        r_base = int(region.base)
        r_size = int(region.size)
        if r_base <= abs_addr < r_base + r_size and int(region.sector_size) > 0:
            return int(region.sector_size)
    return int(getattr(target.profile.memory, "page_size", 4096) or 4096)


def _replay_report_trace_operations(
    buf: bytearray,
    *,
    target: DebugTarget,
    report_data: dict[str, Any] | None,
    base_addr: int,
    nvm_size: int,
    erase_fill: int,
) -> tuple[bool, list[tuple[int, int]]]:
    """Replay completed Phase 1 and Phase 2 trace operations from report_data into buf."""
    if not target.cuts or not isinstance(report_data, dict):
        return False, []

    default_width = int(getattr(target.profile.memory, "write_granularity", 4) or 4)
    touched_spans: list[tuple[int, int]] = []
    rows = [
        r
        for r in (report_data.get("runtime_sweep_results") or ())
        if isinstance(r, dict)
    ]

    p1_writes_by_idx: dict[int, dict[str, Any]] = {}
    p1_erases_by_idx: dict[int, dict[str, Any]] = {}
    p1_ops_by_seq: dict[int, dict[str, Any]] = {}

    for r in rows:
        fw = r.get("fault_window")
        if not isinstance(fw, dict):
            continue
        for slot in ("before", "at", "after"):
            op = fw.get(slot)
            if not isinstance(op, dict):
                continue
            kind = str(op.get("kind") or "").strip().lower()
            if kind == "write" and op.get("write_index") is not None:
                wi = int(op["write_index"])
                p1_writes_by_idx.setdefault(wi, op)
            elif kind == "erase" and op.get("erase_index") is not None:
                ei = int(op["erase_index"])
                p1_erases_by_idx.setdefault(ei, op)
            if op.get("sequence") is not None:
                p1_ops_by_seq.setdefault(int(op["sequence"]), op)

    # Backfill earlier Phase 1 writes/erases when a Phase 2 restart re-executes the same prefix
    if p1_writes_by_idx and min(p1_writes_by_idx) > 1:
        min_known_wi = min(p1_writes_by_idx)
        for r in rows:
            p2 = r.get("phase2_fault")
            if not isinstance(p2, dict):
                continue
            p2_w_list = [w for w in (p2.get("p2_write_trace") or ()) if isinstance(w, dict) and w.get("write_index") is not None]
            p2_by_wi = {int(w["write_index"]): w for w in p2_w_list}
            overlap = [wi for wi in p1_writes_by_idx if wi in p2_by_wi]
            if not overlap:
                continue
            matches_overlap = True
            for wi in overlap:
                off1 = _resolve_op_offset(p1_writes_by_idx[wi], base_addr=base_addr, nvm_size=nvm_size)
                off2 = _resolve_op_offset(p2_by_wi[wi], base_addr=base_addr, nvm_size=nvm_size)
                val1 = int(str(p1_writes_by_idx[wi].get("value", 0)), 0)
                val2 = int(str(p2_by_wi[wi].get("value", 0)), 0)
                if off1 != off2 or val1 != val2:
                    matches_overlap = False
                    break
            if matches_overlap:
                for wi in range(1, min_known_wi):
                    if wi in p2_by_wi:
                        p1_writes_by_idx.setdefault(wi, p2_by_wi[wi])
                if not p1_erases_by_idx:
                    for e in p2.get("p2_erase_trace") or ():
                        if isinstance(e, dict) and int(e.get("writes_at_this_point", 0)) == 0 and e.get("erase_index") is not None:
                            p1_erases_by_idx.setdefault(int(e["erase_index"]), e)
                if all(wi in p1_writes_by_idx for wi in range(1, min_known_wi)):
                    break

    def _apply_write_op(op: dict[str, Any]) -> None:
        rel = _resolve_op_offset(op, base_addr=base_addr, nvm_size=nvm_size)
        if rel is None:
            return
        width = int(op.get("width") or op.get("write_width") or default_width)
        if width <= 0 or rel + width > nvm_size:
            return
        val_raw = op.get("completed_value", op.get("value", 0))
        val = int(str(val_raw), 0) if isinstance(val_raw, str) else int(val_raw)
        mask = (1 << (8 * width)) - 1
        buf[rel : rel + width] = (val & mask).to_bytes(width, "little")
        touched_spans.append((rel, rel + width))

    def _apply_erase_op(op: dict[str, Any]) -> None:
        rel = _resolve_op_offset(op, base_addr=base_addr, nvm_size=nvm_size)
        if rel is None:
            return
        sz = _resolve_erase_size(op, rel_offset=rel, base_addr=base_addr, target=target)
        end = min(nvm_size, rel + sz)
        if end > rel:
            buf[rel:end] = bytes([erase_fill & 0xFF]) * (end - rel)
            touched_spans.append((rel, end))

    cut1_at, cut1_code = target.cuts[0]
    cut1_base = str(cut1_code or "w").split(":", 1)[0]
    p1_complete = False

    if cut1_base == "w":
        target_wi = int(cut1_at) + 1
        cut_op = p1_writes_by_idx.get(target_wi)
        cut_seq = int(cut_op["sequence"]) if isinstance(cut_op, dict) and cut_op.get("sequence") is not None else None
        applied_erases: set[int] = set()
        for wi in range(1, target_wi):
            w_op = p1_writes_by_idx.get(wi)
            w_seq = int(w_op["sequence"]) if isinstance(w_op, dict) and w_op.get("sequence") is not None else None
            for ei in sorted(p1_erases_by_idx):
                if ei in applied_erases:
                    continue
                e_op = p1_erases_by_idx[ei]
                e_wat = e_op.get("writes_at_this_point")
                e_seq = e_op.get("sequence")
                if (e_wat is not None and int(e_wat) < wi) or (
                    e_seq is not None and w_seq is not None and int(e_seq) < w_seq
                ):
                    _apply_erase_op(e_op)
                    applied_erases.add(ei)
            if w_op is not None:
                _apply_write_op(w_op)
        for ei in sorted(p1_erases_by_idx):
            if ei in applied_erases:
                continue
            e_op = p1_erases_by_idx[ei]
            e_wat = e_op.get("writes_at_this_point")
            e_seq = e_op.get("sequence")
            if (e_wat is not None and int(e_wat) < target_wi) or (
                e_seq is not None and cut_seq is not None and int(e_seq) < cut_seq
            ):
                _apply_erase_op(e_op)
                applied_erases.add(ei)
        p1_complete = all(wi in p1_writes_by_idx for wi in range(1, target_wi))
        if isinstance(cut_op, dict):
            cut_rel = _resolve_op_offset(cut_op, base_addr=base_addr, nvm_size=nvm_size)
            cut_w = int(cut_op.get("width") or default_width)
            if cut_rel is not None and cut_rel + cut_w <= nvm_size:
                touched_spans.append((cut_rel, cut_rel + cut_w))
    elif cut1_base in ("e", "a"):
        target_ei = int(cut1_at) + 1
        cut_op = p1_erases_by_idx.get(target_ei)
        cut_seq = int(cut_op["sequence"]) if isinstance(cut_op, dict) and cut_op.get("sequence") is not None else None
        if cut_seq is not None:
            for seq in sorted(k for k in p1_ops_by_seq if k < cut_seq):
                op = p1_ops_by_seq[seq]
                if str(op.get("kind") or "").lower() == "erase":
                    _apply_erase_op(op)
                else:
                    _apply_write_op(op)
            p1_complete = all(s in p1_ops_by_seq for s in range(1, cut_seq))

    if len(target.cuts) == 1:
        return p1_complete, touched_spans

    # Phase 2 cut replay
    row = target.row or {}
    p2 = row.get("phase2_fault")
    if len(target.cuts) == 2 and isinstance(p2, dict):
        cut2_at, cut2_code = target.cuts[1]
        cut2_base = str(cut2_code or "w").split(":", 1)[0]
        p2_writes = [
            w
            for w in (p2.get("p2_write_trace") or ())
            if isinstance(w, dict) and w.get("write_index") is not None
        ]
        p2_erases = [
            e
            for e in (p2.get("p2_erase_trace") or ())
            if isinstance(e, dict)
        ]
        p2_by_wi = {int(w["write_index"]): w for w in p2_writes}
        if cut2_base == "w":
            target_p2_wi = int(cut2_at) + 1
            applied_p2_erases: set[int] = set()
            for wi in range(1, target_p2_wi):
                for idx_e, e_op in enumerate(p2_erases):
                    if idx_e in applied_p2_erases:
                        continue
                    if int(e_op.get("writes_at_this_point", 0)) < wi:
                        _apply_erase_op(e_op)
                        applied_p2_erases.add(idx_e)
                if wi in p2_by_wi:
                    _apply_write_op(p2_by_wi[wi])
            for idx_e, e_op in enumerate(p2_erases):
                if idx_e in applied_p2_erases:
                    continue
                if int(e_op.get("writes_at_this_point", 0)) < target_p2_wi:
                    _apply_erase_op(e_op)
                    applied_p2_erases.add(idx_e)
            if target_p2_wi in p2_by_wi:
                cut2_op = p2_by_wi[target_p2_wi]
                cut2_rel = _resolve_op_offset(cut2_op, base_addr=base_addr, nvm_size=nvm_size)
                cut2_w = int(cut2_op.get("width") or default_width)
                if cut2_rel is not None and cut2_rel + cut2_w <= nvm_size:
                    touched_spans.append((cut2_rel, cut2_rel + cut2_w))
            p2_complete = (
                (p2.get("p2_write_trace") is not None or p2.get("p2_erase_trace") is not None)
                and all(wi in p2_by_wi for wi in range(1, target_p2_wi))
            )
            return (p1_complete and p2_complete), touched_spans

    return False, touched_spans


def _synthesize_offline_state(
    target: DebugTarget,
    repo_root: Path,
    report_data: dict[str, Any] | None = None,
) -> ReconstructedState:
    """Reconstruct persistent state offline from profile images, pre_boot_state, trace operations, and report ranges."""
    if report_data is None:
        rep_path = getattr(target, "_report_path", None)
        if isinstance(rep_path, Path) and rep_path.is_file():
            try:
                loaded_rep, _ = _load_json_or_yaml_input(rep_path)
                if isinstance(loaded_rep, dict):
                    report_data = loaded_rep
            except Exception:
                pass

    base_addr, nvm_size, backend_kind, erase_fill = _infer_platform_nvm_geometry(target, repo_root)
    buf = bytearray([erase_fill & 0xFF]) * nvm_size
    explicit_spans: list[tuple[int, int]] = []

    load_addrs = target.profile.effective_image_load_addresses()
    for slot_name, img_rel in target.profile.images.items():
        try:
            img_path = Path(target.profile.resolve_path(repo_root, img_rel)).resolve()
        except Exception:
            continue
        if not img_path.is_file():
            continue
        img_bytes = img_path.read_bytes()
        load_addr = int(load_addrs.get(slot_name, base_addr))
        rel = load_addr - base_addr
        if 0 <= rel < nvm_size:
            end = min(nvm_size, rel + len(img_bytes))
            buf[rel:end] = img_bytes[: end - rel]

    # tests/ota_fault_point.robot defaults ${IMAGE_STAGING} to ${ROOT}/examples/vulnerable_ota/firmware.bin
    # whenever a profile declares a staging slot without overriding images.staging.
    default_staging_applied: tuple[int, int, bytes] | None = None
    if "staging" not in target.profile.images and "staging" in load_addrs:
        default_staging_path = (repo_root / "examples/vulnerable_ota/firmware.bin").resolve()
        if default_staging_path.is_file():
            staging_load_addr = int(load_addrs["staging"])
            rel = staging_load_addr - base_addr
            if 0 <= rel < nvm_size:
                stg_bytes = default_staging_path.read_bytes()
                end = min(nvm_size, rel + len(stg_bytes))
                prev_slice = bytes(buf[rel:end])
                buf[rel:end] = stg_bytes[: end - rel]
                default_staging_applied = (rel, end, prev_slice)

    for entry in getattr(target.profile, "pre_boot_state", None) or ():
        addr = int(entry.address)
        rel = addr - base_addr
        if entry.u32 is not None and 0 <= rel <= nvm_size - 4:
            val = int(entry.u32) & 0xFFFFFFFF
            buf[rel : rel + 4] = val.to_bytes(4, "little")
            explicit_spans.append((rel, rel + 4))
        elif getattr(entry, "bytes_data", None) is not None and 0 <= rel < nvm_size:
            raw_b = bytes(entry.bytes_data)
            end = min(nvm_size, rel + len(raw_b))
            buf[rel:end] = raw_b[: end - rel]
            explicit_spans.append((rel, end))

    trace_complete, trace_spans = _replay_report_trace_operations(
        buf,
        target=target,
        report_data=report_data,
        base_addr=base_addr,
        nvm_size=nvm_size,
        erase_fill=erase_fill,
    )
    explicit_spans.extend(trace_spans)

    uncorr_addrs: set[int] = set()
    row = target.row or {}
    has_full_snapshot_file = False
    if isinstance(row.get("fault_snapshot_file"), str) and row["fault_snapshot_file"]:
        snap_file = Path(row["fault_snapshot_file"])
        if snap_file.is_file():
            file_bytes = snap_file.read_bytes()
            if len(file_bytes) == nvm_size:
                buf[:] = file_bytes
                has_full_snapshot_file = True

    explanation = target.expected_explanation or {}
    fault_snap = explanation.get("fault_snapshot")
    if isinstance(fault_snap, dict):
        for item in fault_snap.get("uncorrectable_words") or ():
            uncorr_addrs.add(int(str(item), 0))
        closest = fault_snap.get("closest_declared_image")
        if isinstance(closest, dict):
            if closest.get("ranges_truncated") is False and fault_snap.get("identity_slot_base") and fault_snap.get("identity_slot_extent"):
                try:
                    id_base = int(str(fault_snap["identity_slot_base"]), 0)
                    id_ext = int(fault_snap["identity_slot_extent"])
                    id_rel = id_base - base_addr
                    if 0 <= id_rel and id_rel + id_ext <= nvm_size:
                        explicit_spans.append((id_rel, id_rel + id_ext))
                except Exception:
                    pass
            for span in closest.get("differing_ranges") or ():
                if not isinstance(span, dict) or not span.get("address") or not span.get("actual_hex"):
                    continue
                addr = int(str(span["address"]), 0)
                raw_span = bytes.fromhex(str(span["actual_hex"]))
                rel = addr - base_addr
                if 0 <= rel and rel + len(raw_span) <= nvm_size:
                    buf[rel : rel + len(raw_span)] = raw_span
                    explicit_spans.append((rel, rel + len(raw_span)))

    comparison = explanation.get("state_comparison")
    if isinstance(comparison, dict):
        for span in comparison.get("ranges") or ():
            if not isinstance(span, dict) or not span.get("address") or not span.get("failing_hex"):
                continue
            addr = int(str(span["address"]), 0)
            raw_span = bytes.fromhex(str(span["failing_hex"]))
            rel = addr - base_addr
            if 0 <= rel and rel + len(raw_span) <= nvm_size:
                buf[rel : rel + len(raw_span)] = raw_span
                explicit_spans.append((rel, rel + len(raw_span)))
        for item in comparison.get("uncorrectable_only_in_failing") or ():
            uncorr_addrs.add(int(str(item), 0))

    if (
        not uncorr_addrs
        and backend_kind == "mram"
        and str(target.profile.fault_sweep.mram_torn_word or "").lower() == "uncorrectable"
    ):
        search = row.get("recovery_state_search") or {}
        for cut in search.get("cuts") or ((search.get("chain") or {}).get("cuts") or ()):
            if isinstance(cut, dict) and cut.get("address"):
                uncorr_addrs.add(int(str(cut["address"]), 0))
        if not uncorr_addrs and row.get("fault_address"):
            addr_val = int(str(row["fault_address"]), 0)
            if base_addr <= addr_val < base_addr + nvm_size:
                uncorr_addrs.add(addr_val)

    uncorr_offsets = tuple(
        sorted(addr - base_addr for addr in uncorr_addrs if base_addr <= addr < base_addr + nvm_size)
    )
    uncorr_words = tuple(f"0x{base_addr + off:08X}" for off in uncorr_offsets)

    pv_map_b64: dict[str, str] = {}
    pv_bytes: dict[str, bytearray] = {}
    if isinstance(comparison, dict):
        for pv in comparison.get("persistent_values") or ():
            if isinstance(pv, dict) and pv.get("name") and pv.get("failing_hex"):
                raw_pv = bytes.fromhex(str(pv["failing_hex"]))
                pv_map_b64[str(pv["name"])] = base64.b64encode(raw_pv).decode("ascii")
                pv_bytes[str(pv["name"])] = bytearray(raw_pv)

    state_obj = PersistentState.from_bytes(
        buf,
        name="nvm",
        base_address=base_addr,
        uncorrectable_words=tuple(("nvm", off) for off in uncorr_offsets),
        persistent_values=pv_bytes,
    )

    # If a synthetic fixture omitted the Robot suite default staging image, check whether reverting it matches
    if default_staging_applied is not None:
        exp_sha = (
            str(fault_snap.get("sha256") or "").strip().lower()
            if isinstance(fault_snap, dict)
            else ""
        )
        exp_id = str(target.state_identity or "").strip().lower()
        cur_sha = hashlib.sha256(bytes(buf)).hexdigest().lower()
        cur_id = state_obj.identity_hex().lower()
        if (exp_sha and cur_sha != exp_sha) or (exp_id and not cur_id.startswith(exp_id)):
            s_rel, s_end, prev_slice = default_staging_applied
            alt_buf = bytearray(buf)
            alt_buf[s_rel:s_end] = prev_slice
            alt_obj = PersistentState.from_bytes(
                alt_buf,
                name="nvm",
                base_address=base_addr,
                uncorrectable_words=tuple(("nvm", off) for off in uncorr_offsets),
                persistent_values=pv_bytes,
            )
            alt_sha = hashlib.sha256(bytes(alt_buf)).hexdigest().lower()
            alt_id = alt_obj.identity_hex().lower()
            if (not exp_sha or alt_sha == exp_sha) and (not exp_id or alt_id.startswith(exp_id)):
                buf = alt_buf
                state_obj = alt_obj

    verified_id = _verify_rebuilt_state_python(
        state_obj,
        expected_state_id=target.state_identity,
        expected_explanation=target.expected_explanation,
        preloaded_state=None,
    )
    raw_bytes = bytes(buf)
    has_verified_sha256 = isinstance(fault_snap, dict) and bool(str(fault_snap.get("sha256") or "").strip())
    has_verified_state_id = bool(str(target.state_identity or "").strip())
    is_fully_specified = bool(
        has_full_snapshot_file
        or has_verified_sha256
        or has_verified_state_id
        or trace_complete
    )

    if is_fully_specified:
        if has_verified_sha256 and has_verified_state_id:
            spec_reason = "offline reconstruction verified against report fault_snapshot SHA-256 and PersistentState identity"
        elif has_verified_sha256:
            spec_reason = "offline reconstruction verified against report fault_snapshot SHA-256"
        elif has_verified_state_id:
            spec_reason = "offline reconstruction verified against report PersistentState identity"
        elif trace_complete:
            spec_reason = "offline reconstruction from profile seed images, pre_boot_state, and complete pre-cut operation trace"
        else:
            spec_reason = "offline reconstruction from fault_snapshot_file"
        specified_regions: tuple[dict[str, Any], ...] = (
            {
                "address": f"0x{base_addr:08X}",
                "offset": 0,
                "size": len(raw_bytes),
                "reason": spec_reason,
            },
        )
        unspecified_regions: tuple[dict[str, Any], ...] = ()
    else:
        merged_spec = _merge_byte_intervals(len(raw_bytes), explicit_spans)
        unspec_spans = _complement_byte_intervals(len(raw_bytes), merged_spec)
        specified_regions = tuple(
            {
                "address": f"0x{base_addr + s:08X}",
                "offset": s,
                "size": e - s,
                "reason": "explicitly specified by report state_comparison / fault_snapshot ranges or pre_boot_state",
            }
            for s, e in merged_spec
        )
        unspecified_regions = tuple(
            {
                "address": f"0x{base_addr + s:08X}",
                "offset": s,
                "size": e - s,
                "reason": "report omits pre-recovery snapshot, full state digest, and complete pre-cut write trace for this region",
            }
            for s, e in unspec_spans
        )

    return ReconstructedState(
        nvm_bytes=raw_bytes,
        base_address=base_addr,
        size=len(raw_bytes),
        sha256=hashlib.sha256(raw_bytes).hexdigest().lower(),
        state_identity=verified_id,
        backend_kind=backend_kind,
        flash_backend=str(target.profile.flash_backend or ("mramTracker" if backend_kind == "mram" else "faultFlash")),
        uncorrectable_offsets=uncorr_offsets,
        uncorrectable_words=uncorr_words,
        mram_torn_word=str(target.profile.fault_sweep.mram_torn_word or "half"),
        torn_word=str(target.profile.fault_sweep.torn_word or "fixed"),
        persistent_values=pv_map_b64,
        renode_version=None,
        state_source="offline_reconstruction",
        fully_specified=is_fully_specified,
        specified_regions=specified_regions,
        unspecified_regions=unspecified_regions,
    )


def reconstruct_persistent_state(
    target: DebugTarget,
    *,
    report_data: dict[str, Any] | None = None,
    renode_test: str = DEFAULT_RENODE_TEST,
    timeout: int = 300,
    repo_root: Path = REPO_ROOT,
) -> ReconstructedState:
    if report_data is None:
        rep_path = getattr(target, "_report_path", None)
        if isinstance(rep_path, Path) and rep_path.is_file():
            try:
                loaded_rep, _ = _load_json_or_yaml_input(rep_path)
                if isinstance(loaded_rep, dict):
                    report_data = loaded_rep
            except Exception:
                pass

    preloaded = _decode_preloaded_state_from_target(target, report_data=report_data)
    if preloaded is not None:
        verified_id = _verify_rebuilt_state_python(
            preloaded,
            expected_state_id=target.state_identity,
            expected_explanation=target.expected_explanation,
            preloaded_state=preloaded,
        )
        nvm_reg = preloaded.region("nvm")
        base_addr = int(nvm_reg.base_address)
        raw_bytes = bytes(preloaded.materialize()["nvm"])
        _, _, backend_kind, _ = _infer_platform_nvm_geometry(target, repo_root)
        uncorr_offsets = tuple(
            sorted(int(off) for rname, off in preloaded.uncorrectable_words if rname == "nvm")
        )
        uncorr_words = tuple(f"0x{base_addr + off:08X}" for off in uncorr_offsets)
        pv_b64 = {
            str(k): base64.b64encode(bytes(bytearray(v))).decode("ascii")
            for k, v in dict(preloaded.persistent_values).items()
        }
        is_ckpt = any(
            isinstance(s, dict) and s.get("snapshots") and s.get("chunks") is not None
            for s in (target.checkpoint_snapshot, report_data)
        )
        src_kind = "checkpoint_snapshot" if is_ckpt else "embedded_snapshot"
        return ReconstructedState(
            nvm_bytes=raw_bytes,
            base_address=base_addr,
            size=len(raw_bytes),
            sha256=hashlib.sha256(raw_bytes).hexdigest().lower(),
            state_identity=verified_id,
            backend_kind=backend_kind,
            flash_backend=str(target.profile.flash_backend or ("mramTracker" if backend_kind == "mram" else "faultFlash")),
            uncorrectable_offsets=uncorr_offsets,
            uncorrectable_words=uncorr_words,
            mram_torn_word=str(target.profile.fault_sweep.mram_torn_word or "half"),
            torn_word=str(target.profile.fault_sweep.torn_word or "fixed"),
            persistent_values=pv_b64,
            renode_version=None,
            state_source=src_kind,
            fully_specified=True,
            specified_regions=(
                {
                    "address": f"0x{base_addr:08X}",
                    "offset": 0,
                    "size": len(raw_bytes),
                    "reason": f"restored full pre-recovery persistent state from {src_kind}",
                },
            ),
            unspecified_regions=(),
        )

    runner_available = False
    if renode_test:
        if str(renode_test).startswith(DOCKER_RENODE_PREFIX):
            runner_available = shutil.which("docker") is not None
        elif os.path.isabs(str(renode_test)):
            runner_available = Path(str(renode_test)).is_file()
        else:
            runner_available = shutil.which(str(renode_test)) is not None

    if runner_available:
        return _reconstruct_state_via_renode(
            target,
            renode_test=renode_test,
            timeout=timeout,
            repo_root=repo_root,
        )

    if renode_test and renode_test != "renode-test" and not runner_available:
        raise ExportReproError(f"renode-test executable not found: {renode_test}")

    return _synthesize_offline_state(target, repo_root, report_data=report_data)


def verify_exported_state_against_emulator(
    exported: Path | ReconstructedState | dict[str, Any],
    emulator_bytes: bytes,
    *,
    emulator_uncorrectable_words: tuple[str | int, ...] | list[str | int] | None = None,
) -> dict[str, Any]:
    """Verify that an exported reproducer state matches the emulator state in every specified byte."""
    if isinstance(exported, ReconstructedState):
        exported_bytes = bytes(exported.nvm_bytes)
        base_addr = int(exported.base_address)
        spec_regs = list(exported.specified_regions)
        unspec_regs = list(exported.unspecified_regions)
        fully_spec = bool(exported.fully_specified)
        exp_uncorr_addrs = {int(str(w), 0) for w in exported.uncorrectable_words} | {
            base_addr + int(off) for off in exported.uncorrectable_offsets
        }
    elif isinstance(exported, Path):
        p = exported.resolve()
        if p.is_dir():
            meta_file = p / "state" / "persistent_state.json"
        else:
            meta_file = p
        if not meta_file.is_file():
            raise ExportReproError(f"exported persistent_state.json not found: {meta_file}")
        payload = json.loads(meta_file.read_text(encoding="utf-8"))
        ps = payload.get("persistent_state") or payload
        bundle_root = meta_file.parent.parent if meta_file.parent.name == "state" else meta_file.parent
        bin_rel = str(ps.get("binary_file") or "state/persistent_state.bin")
        bin_file = (bundle_root / bin_rel).resolve()
        if not bin_file.is_file():
            raise ExportReproError(f"exported persistent_state.bin not found: {bin_file}")
        exported_bytes = bin_file.read_bytes()
        base_addr = int(str(ps.get("base_address", "0")), 0)
        spec_regs = list(ps.get("specified_regions") or ())
        unspec_regs = list(ps.get("unspecified_regions") or ())
        fully_spec = bool(ps.get("fully_specified", not unspec_regs))
        exp_uncorr_addrs = {int(str(w), 0) for w in (ps.get("uncorrectable_words") or ())} | {
            base_addr + int(off) for off in (ps.get("uncorrectable_offsets") or ())
        }
    elif isinstance(exported, dict):
        ps = exported.get("persistent_state") if isinstance(exported.get("persistent_state"), dict) else exported
        raw_b = ps.get("nvm_bytes")
        if not isinstance(raw_b, (bytes, bytearray)):
            raise ExportReproError("dict passed to verify_exported_state_against_emulator must include nvm_bytes")
        exported_bytes = bytes(raw_b)
        base_addr = int(str(ps.get("base_address", "0")), 0)
        spec_regs = list(ps.get("specified_regions") or ())
        unspec_regs = list(ps.get("unspecified_regions") or ())
        fully_spec = bool(ps.get("fully_specified", not unspec_regs))
        exp_uncorr_addrs = {int(str(w), 0) for w in (ps.get("uncorrectable_words") or ())} | {
            base_addr + int(off) for off in (ps.get("uncorrectable_offsets") or ())
        }
    else:
        raise ExportReproError(f"unsupported exported state object: {type(exported)!r}")

    emu_bytes = bytes(emulator_bytes)
    if len(exported_bytes) != len(emu_bytes):
        raise ExportReproError(
            f"exported state image size ({len(exported_bytes)} bytes) differs from "
            f"emulator state size ({len(emu_bytes)} bytes)"
        )

    total_size = len(emu_bytes)
    unspec_intervals = _merge_byte_intervals(
        total_size,
        [
            (int(r["offset"]), int(r["offset"]) + int(r["size"]))
            for r in unspec_regs
            if isinstance(r, dict) and r.get("offset") is not None and r.get("size") is not None
        ],
    )
    if spec_regs:
        spec_intervals = _merge_byte_intervals(
            total_size,
            [
                (int(r["offset"]), int(r["offset"]) + int(r["size"]))
                for r in spec_regs
                if isinstance(r, dict) and r.get("offset") is not None and r.get("size") is not None
            ],
        )
    else:
        spec_intervals = _complement_byte_intervals(total_size, unspec_intervals)

    if fully_spec and (unspec_intervals or spec_intervals != ([(0, total_size)] if total_size > 0 else [])):
        raise ExportReproError(
            "exported state marks fully_specified=true but does not specify all bytes"
        )

    verified_byte_count = 0
    for s, e in spec_intervals:
        verified_byte_count += e - s
        if exported_bytes[s:e] != emu_bytes[s:e]:
            # Find exact first differing span inside [s, e)
            diff_start = s
            while diff_start < e and exported_bytes[diff_start] == emu_bytes[diff_start]:
                diff_start += 1
            diff_end = diff_start + 1
            while diff_end < e and exported_bytes[diff_end] != emu_bytes[diff_end]:
                diff_end += 1
            preview_end = min(diff_end, diff_start + 32)
            exp_hex = exported_bytes[diff_start:preview_end].hex()
            emu_hex = emu_bytes[diff_start:preview_end].hex()
            raise ExportReproError(
                f"exported state image differs from emulator state at specified offset "
                f"0x{diff_start:06X} (address 0x{base_addr + diff_start:08X}, length {diff_end - diff_start}): "
                f"exported={exp_hex} vs emulator={emu_hex}"
            )

    if emulator_uncorrectable_words is not None:
        emu_uncorr_addrs: set[int] = set()
        for item in emulator_uncorrectable_words:
            val = int(str(item), 0) if isinstance(item, str) else int(item)
            emu_uncorr_addrs.add(val if val >= base_addr else base_addr + val)
        if exp_uncorr_addrs != emu_uncorr_addrs:
            raise ExportReproError(
                f"exported uncorrectable words {[f'0x{a:08X}' for a in sorted(exp_uncorr_addrs)]} "
                f"differ from emulator uncorrectable words {[f'0x{a:08X}' for a in sorted(emu_uncorr_addrs)]}"
            )

    unspec_byte_count = sum(e - s for s, e in unspec_intervals)
    return {
        "total_bytes": total_size,
        "verified_bytes": verified_byte_count,
        "unspecified_bytes": unspec_byte_count,
        "fully_specified": fully_spec and unspec_byte_count == 0,
        "byte_identical": exported_bytes == emu_bytes,
    }


def _resolve_elf_symbol_addrs(elf_path: Path, symbols: list[str]) -> dict[str, str]:
    if not symbols or not elf_path.is_file():
        return {}
    resolved: dict[str, str] = {}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with elf_path.open("rb") as stream:
            elffile = ELFFile(stream)
            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for sym in section.iter_symbols():
                    if sym.name in symbols:
                        val = int(sym["st_value"]) & ~1
                        if val > 0:
                            resolved[sym.name] = f"0x{val:08X}"
    except Exception:
        pass
    if len(resolved) < len(symbols):
        nm_bin = shutil.which("arm-none-eabi-nm") or shutil.which("nm")
        if nm_bin:
            try:
                proc = subprocess.run(
                    [nm_bin, str(elf_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[2] in symbols:
                            addr = int(parts[0], 16) & ~1
                            if addr > 0:
                                resolved.setdefault(parts[2], f"0x{addr:08X}")
            except Exception:
                pass
    return resolved


def _build_recovery_config_dict(
    target: DebugTarget,
    state: ReconstructedState,
    license_decision: LicenseDecision,
    repo_root: Path,
) -> tuple[dict[str, Any], bytes, list[dict[str, Any]]]:
    """Return (recovery_config_dict, final_state_bytes, scrubbed_code_regions)."""
    prof = target.profile
    mem = prof.memory
    sc = prof.success_criteria
    fs = prof.fault_sweep

    elf_rel = f"firmware/{target.elf_path.name}"
    load_addrs = prof.effective_image_load_addresses()
    images_meta: dict[str, dict[str, Any]] = {}
    for slot_name, img_rel_raw in prof.images.items():
        img_path = Path(prof.resolve_path(repo_root, img_rel_raw)).resolve()
        img_sha = hashlib.sha256(img_path.read_bytes()).hexdigest().lower() if img_path.is_file() else ""
        images_meta[slot_name] = {
            "file": f"firmware/{img_path.name}",
            "load_address": f"0x{int(load_addrs.get(slot_name, 0)):08X}",
            "sha256": img_sha,
        }

    # Pre-compute slot image digests matching ProfileConfig._compute_image_digests / approved_image_running
    slot_image_digests: dict[str, str] = {}
    try:
        slot_image_digests = prof._compute_image_digests(repo_root, prof.images)
    except Exception:
        pass

    approved_running_dict = None
    try:
        approved_running_dict = prof._approved_image_running_runtime_dict(
            repo_root, sc, prof.images
        )
    except Exception:
        approved_running_dict = None

    success_checks = prof._success_checks_runtime_dict(sc)

    no_hash_bypass = target.fault_type_code.startswith("i:")
    bypass_syms = (
        []
        if no_hash_bypass
        else list(getattr(fs, "sweep_hash_bypass_symbols", None) or [])
    )
    bypass_addrs = _resolve_elf_symbol_addrs(target.elf_path, bypass_syms)

    rec_tracking_start = (
        int(fs.recovery_tracking_start_address)
        if fs.recovery_tracking_start_address is not None
        else (int(fs.tracking_start_address or 0) if target.state_search_gated else 0)
    )

    scrubbed_regions: list[dict[str, Any]] = []
    final_bytes = bytearray(state.nvm_bytes)
    if not license_decision.redistributable:
        # Scrub bootloader code region and application slot regions from persistent_state.bin
        # so zero bytes of non-redistributable object code are stored in the bundle.
        erase_fill = int(mem.erase_fill) if mem.erase_fill is not None else 0xFF
        page_size = int(getattr(mem, "page_size", 4096) or 4096)
        code_spans: list[tuple[str, int, int]] = []
        if prof.bootloader_region is not None:
            code_spans.append(("bootloader", int(prof.bootloader_region.base), int(prof.bootloader_region.size)))
        else:
            min_slot = min(s.base for s in mem.slots.values())
            if min_slot > state.base_address:
                # Preserve trailer sectors (e.g. 0x08004000..0x0800BFFF in wolfBoot); scrub only sector 0 boot code
                boot_code_size = min(0x4000, min_slot - state.base_address)
                code_spans.append(("bootloader_sector0", state.base_address, boot_code_size))
        for s_name, s_cfg in mem.slots.items():
            data_len = max(0, int(s_cfg.size) - page_size)
            if data_len > 0:
                code_spans.append((f"slot_{s_name}", int(s_cfg.base), data_len))
        for label, span_base, span_size in code_spans:
            rel_start = max(0, span_base - state.base_address)
            rel_end = min(len(final_bytes), span_base + span_size - state.base_address)
            if rel_end > rel_start:
                final_bytes[rel_start:rel_end] = bytes([erase_fill & 0xFF]) * (rel_end - rel_start)
                scrubbed_regions.append({
                    "name": label,
                    "address": f"0x{state.base_address + rel_start:08X}",
                    "offset": rel_start,
                    "size": rel_end - rel_start,
                    "fill": f"0x{erase_fill & 0xFF:02X}",
                })

    expected_exec_sha = ""
    if sc.image_hash:
        exp_img_key = sc.expected_image or "staging"
        expected_exec_sha = slot_image_digests.get(exp_img_key, "")

    allowed_hashes = [
        {"name": name, "sha256": slot_image_digests[name]}
        for name in (sc.allowed_images or ())
        if name in slot_image_digests
    ]

    recovery_cfg: dict[str, Any] = {
        "bootloader_elf": elf_rel,
        "bootloader_entry": f"0x{int(prof.bootloader_entry):08X}",
        "sram_start": f"0x{int(mem.sram_start):08X}",
        "sram_end": f"0x{int(mem.sram_end):08X}",
        "write_granularity": int(mem.write_granularity),
        "page_size": int(getattr(mem, "page_size", 4096) or 4096),
        "erase_fill": int(mem.erase_fill) if mem.erase_fill is not None else 0xFF,
        "erase_regions": [
            {
                "base": int(r.base),
                "size": int(r.size),
                "sector_size": int(r.sector_size),
            }
            for r in (mem.erase_regions or ())
        ],
        "volatile_regions": [
            {
                "name": r.name or f"volatile_{idx}",
                "base": f"0x{int(r.base):08X}",
                "size": int(r.size),
            }
            for idx, r in enumerate(mem.volatile_regions or ())
        ],
        "boot_register_pre_writes": [
            {
                "address": f"0x{int(pw.address):08X}",
                "value": f"0x{int(pw.value):08X}",
            }
            for pw in (prof.boot_register_pre_writes or ())
        ],
        "hash_bypass_addrs": bypass_addrs,
        "tracking_start_address": f"0x{int(fs.tracking_start_address or 0):08X}",
        "recovery_tracking_start_address": f"0x{rec_tracking_start:08X}",
        "run_duration_s": float(fs.run_duration or 1.0),
        "phase2_time_slice_s": float(fs.phase2_time_slice or 0.02),
        "phase2_wall_timeout_s": float(fs.phase2_wall_timeout_s or 30.0),
        "progress_stall_timeout_s": float(getattr(fs, "progress_stall_timeout_s", 5.0) or 5.0),
        "vtor_settle_iters": int(fs.vtor_settle_iters or 0),
        "watchdog_frequency": getattr(prof, "watchdog_frequency", None),
        "otp_peripheral": getattr(prof, "otp_peripheral", None) or "",
        "nvm_controller": getattr(prof, "nvm_controller", None) or "",
        "slots": {
            s_name: {
                "base": f"0x{int(s_cfg.base):08X}",
                "size": f"0x{int(s_cfg.size):08X}",
            }
            for s_name, s_cfg in mem.slots.items()
        },
        "images": images_meta,
        "success_criteria": {
            "vtor_in_slot": sc.vtor_in_slot or "",
            "vector_table_offset": f"0x{int(sc.vector_table_offset or 0):08X}",
            "pc_in_slot": sc.pc_in_slot or "",
            "terminal_after_reset": bool(sc.terminal_after_reset),
            "allow_fault_after_success": bool(sc.allow_fault_after_success),
            "marker_address": f"0x{int(sc.marker_address):08X}" if sc.marker_address is not None else "0x00000000",
            "marker_value": f"0x{int(sc.marker_value):08X}" if sc.marker_value is not None else "0x00000000",
            "image_hash": bool(sc.image_hash),
            "image_hash_slot": sc.image_hash_slot or "",
            "image_digests": slot_image_digests,
            "expected_exec_sha256": expected_exec_sha,
            "allowed_image_hashes": allowed_hashes,
            "approved_image_running": approved_running_dict,
            "memory_checks": success_checks.get("memory_checks") or [],
            "config_checks": success_checks.get("config_checks") or [],
            "bootloader_integrity": bool(success_checks.get("bootloader_integrity")),
        },
    }
    return recovery_cfg, bytes(final_bytes), scrubbed_regions


def _render_reproduce_resc(
    *,
    target: DebugTarget,
    state: ReconstructedState,
    repl_files: list[Path],
    peripheral_files: list[Path],
    expected_control_outcome: str,
    report_outcome: str,
) -> str:
    main_repl_name = repl_files[0].name
    elf_name = target.elf_path.name
    lines = [
        "# Standalone Renode reproducer script generated by tardigrade export-repro",
        f"# Profile: {target.profile.name}",
        f"# Point: {target.point_name}",
        f"# Expected outcome: {expected_control_outcome}",
        f"# Observed outcome in report: {report_outcome}",
        "",
    ]
    for cs_path in peripheral_files:
        if cs_path.name in ("STM32H7Constructors.cs", "STM32H7LegacyConstructors.cs"):
            continue
        lines.append(f'include @peripherals/{cs_path.name}')
    lines.extend([
        "",
        'mach create "repro"',
        f"machine LoadPlatformDescription @platforms/{main_repl_name}",
    ])
    wf = getattr(target.profile, "watchdog_frequency", None)
    if wf:
        lines.append(f"watchdogNs ClockFrequency {wf}")
    lines.extend([
        f"sysbus LoadELF @firmware/{elf_name}",
        f"# Persistent state image: state/persistent_state.bin @ {f'0x{state.base_address:08X}'} ({state.size} bytes)",
    ])
    if state.uncorrectable_words:
        lines.append(
            "# Uncorrectable / torn marks: " + ", ".join(state.uncorrectable_words)
        )
    lines.extend([
        "",
        'python """',
        "import os as _os",
        "_bundle_dir = _os.environ.get('REPRO_BUNDLE_DIR') or ''",
        "if not _bundle_dir or not _os.path.isfile(_os.path.join(_bundle_dir, 'reproduce_recovery.py')):",
        "    for _p in list(getattr(monitor, 'CurrentPathPrefixes', ()) or ()) + [_os.getcwd()]:",
        "        _cand = str(_p)",
        "        if _os.path.isfile(_os.path.join(_cand, 'reproduce_recovery.py')):",
        "            _bundle_dir = _cand",
        "            break",
        "if not _bundle_dir:",
        "    _bundle_dir = _os.getcwd()",
        "_os.environ['REPRO_BUNDLE_DIR'] = _bundle_dir",
        "_script = _os.path.join(_bundle_dir, 'reproduce_recovery.py')",
        "with open(_script, 'rb') as _f:",
        "    _src = _f.read()",
        "exec(compile(_src, _script, 'exec'), globals(), globals())",
        '"""',
        "quit",
    ])
    return "\n".join(lines) + "\n"


def _render_reproduce_recovery_py() -> str:
    """Return IronPython 2.7 / Renode 1.16.1 & 1.17.0 compatible recovery boot & outcome script."""
    return '''# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
# Standalone Renode recovery boot and outcome evaluator (IronPython 2.7 compatible).

import base64
import binascii
import hashlib
import json
import os
import struct
import time as _time

from Antmicro.Renode.Peripherals.CPU import RegisterValue
from System import Array, Byte, Convert
from System.IO import File as NetFile


def _as_int(val):
    if hasattr(val, 'RawValue'):
        return int(val.RawValue) & 0xFFFFFFFF
    try:
        return int(val) & 0xFFFFFFFF
    except Exception:
        return int(str(val), 0) & 0xFFFFFFFF


def _fmt_u32(val):
    return '0x{:08X}'.format(_as_int(val))


def _resolve_peripheral(m_ref, name):
    if not name:
        return None
    for cand in (name, 'sysbus.' + name):
        try:
            dev = m_ref[cand]
            if dev is not None:
                return dev
        except Exception:
            pass
    return None


def _read_machine_virtual_s(m_ref):
    try:
        evt = getattr(m_ref, 'ElapsedVirtualTime', None)
        if evt is None:
            return 0.0
        te = getattr(evt, 'TimeElapsed', evt)
        us = getattr(te, 'TotalMicroseconds', None)
        if us is not None:
            return float(us) / 1000000.0
        sec = getattr(te, 'TotalSeconds', None)
        if sec is not None:
            return float(sec)
    except Exception:
        pass
    return 0.0


def _is_terminal_halt_pc(bus, pc_value):
    pc_addr = _as_int(pc_value) & ~1
    try:
        insn = _as_int(bus.ReadWord(pc_addr)) & 0xFFFF
    except Exception:
        return False
    if insn in (0xE7FE, 0xBF30, 0xBE00):
        return True
    if insn == 0xE7FD and pc_addr >= 2:
        try:
            prev_insn = _as_int(bus.ReadWord(pc_addr - 2)) & 0xFFFF
            if prev_insn == 0xBF30:
                return True
        except Exception:
            pass
    # Check 16-bit unconditional self-branch B . (0xE000..0xE7FF with imm11 == -2 -> 0xE7FE)
    # or 32-bit B.W . (0xF7FF 0xBFFE)
    if insn == 0xF7FF:
        try:
            insn2 = _as_int(bus.ReadWord(pc_addr + 2)) & 0xFFFF
            if insn2 == 0xBFFE:
                return True
        except Exception:
            pass
    return False


def _read_nvm_bytes(bus, backend_dev, backend_kind, nvm_base, start_addr, count):
    count = int(count)
    if count <= 0:
        return b''
    rel = int(start_addr) - int(nvm_base)
    try:
        if backend_kind == 'mram' and backend_dev is not None and rel >= 0:
            clr_arr = backend_dev.ReadBytes(rel, count)
            return bytes(bytearray(int(b) & 0xFF for b in clr_arr))
        if backend_kind == 'slow' and backend_dev is not None and hasattr(backend_dev, 'Nvm') and rel >= 0:
            clr_arr = backend_dev.Nvm.ReadBytes(rel, count)
            return bytes(bytearray(int(b) & 0xFF for b in clr_arr))
        if backend_dev is not None and hasattr(backend_dev, 'Flash') and rel >= 0:
            clr_arr = backend_dev.Flash.ReadBytes(rel, count)
            return bytes(bytearray(int(b) & 0xFF for b in clr_arr))
    except Exception:
        pass
    clr_arr = bus.ReadBytes(int(start_addr), count)
    return bytes(bytearray(int(b) & 0xFF for b in clr_arr))


def _resolve_slot_hash_extent(bus, backend_dev, backend_kind, nvm_base, slot_base, slot_size, erase_regions, page_size):
    slot_base = int(slot_base)
    slot_size = int(slot_size)
    if slot_size >= 32:
        hdr = _read_nvm_bytes(bus, backend_dev, backend_kind, nvm_base, slot_base, 32)
        if len(hdr) >= 32:
            ih_magic = struct.unpack_from('<I', hdr, 0)[0]
            if ih_magic == 0x96F3B83D:
                ih_hdr_size, ih_protect_tlv_size, ih_img_size = struct.unpack_from('<HHI', hdr, 8)
                unprot_off = int(ih_hdr_size) + int(ih_img_size) + int(ih_protect_tlv_size)
                if ih_hdr_size >= 32 and unprot_off + 4 <= slot_size:
                    tlv_hdr = _read_nvm_bytes(bus, backend_dev, backend_kind, nvm_base, slot_base + unprot_off, 4)
                    if len(tlv_hdr) == 4:
                        tlv_magic, tlv_tot = struct.unpack_from('<HH', tlv_hdr, 0)
                        if tlv_magic == 0x6907 and tlv_tot >= 4:
                            ext = unprot_off + int(tlv_tot)
                            if 0 < ext <= slot_size:
                                return ext
    if slot_size > 0:
        slot_end = slot_base + slot_size
        last_addr = slot_end - 1
        for entry in erase_regions or ():
            r_base = int(entry['base'])
            r_size = int(entry['size'])
            sec_size = int(entry['sector_size'])
            r_end = r_base + r_size
            if r_base <= last_addr < r_end and sec_size > 0:
                sec_start = r_base + ((last_addr - r_base) // sec_size) * sec_size
                last_sec = min(sec_size, slot_end - max(slot_base, sec_start))
                if 0 < last_sec < slot_size:
                    return slot_size - last_sec
        if page_size and 0 < int(page_size) < slot_size:
            return slot_size - int(page_size)
    return slot_size - 4096 if slot_size > 4096 else slot_size


def _evaluate_memory_checks(bus, checks):
    all_ok = True
    failed = []
    for chk in checks or ():
        addr = int(str(chk.get('address', '0')), 0)
        width = int(chk.get('width', 4) or 4)
        op = str(chk.get('op') or 'eq').strip().lower()
        mask = chk.get('mask')
        exp = chk.get('expected')
        if width == 1:
            actual = _as_int(bus.ReadByte(addr)) & 0xFF
        elif width == 2:
            actual = _as_int(bus.ReadWord(addr)) & 0xFFFF
        else:
            actual = _as_int(bus.ReadDoubleWord(addr)) & 0xFFFFFFFF
        eff_val = (actual & int(str(mask), 0)) if mask is not None else actual
        exp_val = int(str(exp), 0) if exp is not None else 0
        if op in ('eq', '=='):
            ok = (eff_val == exp_val)
        elif op in ('ne', '!='):
            ok = (eff_val != exp_val)
        elif op == 'nonzero':
            ok = (eff_val != 0)
        elif op in ('gt', '>'):
            ok = (eff_val > exp_val)
        elif op in ('ge', '>='):
            ok = (eff_val >= exp_val)
        elif op in ('lt', '<'):
            ok = (eff_val < exp_val)
        elif op in ('le', '<='):
            ok = (eff_val <= exp_val)
        else:
            ok = (eff_val == exp_val)
        if not ok:
            all_ok = False
            failed.append({
                'address': _fmt_u32(addr),
                'op': op,
                'actual': _fmt_u32(actual),
                'expected': _fmt_u32(exp_val) if exp is not None else 'nonzero',
            })
    return all_ok, failed


def run_standalone_reproducer():
    cwd = os.environ.get('REPRO_BUNDLE_DIR') or os.getcwd()
    meta_path = os.path.join(cwd, 'state', 'persistent_state.json')
    with open(meta_path, 'r') as f:
        meta = json.loads(f.read())

    pstate = meta['persistent_state']
    rcfg = meta['recovery_config']
    sc = rcfg['success_criteria']

    bin_rel = pstate.get('binary_file', 'state/persistent_state.bin')
    bin_path = os.path.join(cwd, bin_rel)
    if not os.path.isfile(bin_path):
        raise RuntimeError('Persistent state binary not found: ' + bin_path)

    clr_bytes = NetFile.ReadAllBytes(bin_path)
    py_raw = bytes(bytearray(int(b) & 0xFF for b in clr_bytes))
    actual_sha = hashlib.sha256(py_raw).hexdigest().lower()
    expected_sha = str(pstate.get('sha256') or '').strip().lower()
    if expected_sha and actual_sha != expected_sha:
        raise RuntimeError(
            'Persistent state binary SHA-256 mismatch: expected {}, got {}'.format(
                expected_sha, actual_sha
            )
        )

    m_ref = monitor.Machine
    bus = m_ref.SystemBus
    cpu_ref = m_ref['sysbus.cpu']
    monitor.Parse('machine Pause')

    # Clear volatile memory regions
    for vreg in rcfg.get('volatile_regions') or ():
        v_base = int(str(vreg['base']), 0)
        v_size = int(vreg['size'])
        if v_size > 0:
            bus.WriteBytes(Array.CreateInstance(Byte, v_size), v_base)

    sram_start = int(str(rcfg.get('sram_start', '0x20000000')), 0)
    sram_end = int(str(rcfg.get('sram_end', '0x20040000')), 0)
    marker_addr = int(str(sc.get('marker_address', '0')), 0)
    marker_value = int(str(sc.get('marker_value', '0')), 0)
    if marker_addr != 0 and sram_start <= marker_addr < sram_end:
        bus.WriteDoubleWord(marker_addr, 0)

    nvm_base = int(str(pstate.get('base_address', '0')), 0)
    nvm_size = int(pstate.get('size', len(py_raw)))
    backend_kind = str(pstate.get('backend_kind') or 'fast')
    flash_backend = str(pstate.get('flash_backend') or 'faultFlash')
    backend_dev = _resolve_peripheral(m_ref, flash_backend)

    # Reload ELF and any base images for slow/scrubbed backends before applying persistent state
    if backend_kind == 'slow' or pstate.get('scrubbed_code_regions'):
        elf_path = os.path.join(cwd, rcfg['bootloader_elf'])
        if os.path.isfile(elf_path):
            monitor.Parse('sysbus LoadELF @{}'.format(elf_path))
        for _sname, img_info in (rcfg.get('images') or {}).items():
            img_p = os.path.join(cwd, img_info['file'])
            load_a = int(str(img_info['load_address']), 0)
            if os.path.isfile(img_p):
                monitor.Parse('sysbus LoadBinary @{} 0x{:08X}'.format(img_p, load_a))

    if pstate.get('scrubbed_code_regions'):
        # Splice locally built code regions from bus into clr_bytes before restoring backend
        scrub_set = []
        for sreg in pstate.get('scrubbed_code_regions') or ():
            s_off = int(sreg['offset'])
            s_len = int(sreg['size'])
            s_addr = nvm_base + s_off
            live_code = bus.ReadBytes(s_addr, s_len)
            Array.Copy(live_code, 0, clr_bytes, s_off, s_len)

    if backend_kind == 'mram' and backend_dev is not None:
        restore_raw = getattr(backend_dev, 'RestoreSnapshotRaw', None)
        if restore_raw is not None:
            restore_raw(clr_bytes)
        else:
            backend_dev.WriteBytes(0, clr_bytes, 0, clr_bytes.Length)
    elif backend_kind == 'slow' and backend_dev is not None and hasattr(backend_dev, 'Nvm'):
        restore_raw = getattr(backend_dev.Nvm, 'RestoreSnapshotRaw', None)
        if restore_raw is not None:
            restore_raw(clr_bytes)
        else:
            backend_dev.Nvm.WriteBytes(0, clr_bytes, 0, clr_bytes.Length)
    elif backend_kind == 'otp' and backend_dev is not None:
        test_restore = getattr(backend_dev, 'TestRestore', None)
        if test_restore is not None:
            test_restore(clr_bytes)
        else:
            backend_dev.WriteBytes(0, clr_bytes, 0, clr_bytes.Length)
    elif backend_dev is not None and hasattr(backend_dev, 'Flash'):
        backend_dev.Flash.WriteBytes(0, clr_bytes)
    else:
        bus.WriteBytes(clr_bytes, nvm_base)

    # Verify that the emulator's restored NVM state matches persistent_state.bin in every specified byte
    spec_regions = pstate.get('specified_regions')
    unspec_regions = pstate.get('unspecified_regions') or []
    if not spec_regions and not unspec_regions:
        spec_regions = [{'offset': 0, 'size': len(py_raw)}]
    specified_bytes_verified = 0
    for sreg in spec_regions or ():
        s_off = int(sreg.get('offset', 0))
        s_len = int(sreg.get('size', 0))
        if s_len <= 0:
            continue
        emu_span = _read_nvm_bytes(bus, backend_dev, backend_kind, nvm_base, nvm_base + s_off, s_len)
        exp_span = py_raw[s_off : s_off + s_len]
        if emu_span != exp_span:
            raise RuntimeError(
                'Emulator NVM state mismatch in specified region at offset 0x{:06X} (len {})'.format(
                    s_off, s_len
                )
            )
        specified_bytes_verified += s_len
    unspecified_bytes_count = sum(int(ureg.get('size', 0)) for ureg in unspec_regions)

    # Restore OTP or auxiliary persistent values
    pv_map = pstate.get('persistent_values') or {}
    otp_name = str(rcfg.get('otp_peripheral') or '')
    if otp_name and 'otp' in pv_map:
        otp_dev = _resolve_peripheral(m_ref, otp_name)
        if otp_dev is not None and hasattr(otp_dev, 'TestRestore'):
            otp_dev.TestRestore(Convert.FromBase64String(str(pv_map['otp'])))

    # Reset controller tracking & disarm faults
    rec_track_start = int(str(rcfg.get('recovery_tracking_start_address', '0')), 0)
    if backend_dev is not None:
        try:
            backend_dev.Reset()
        except Exception:
            pass
        for attr, val in (
            ('FaultAtWordWrite', 0),
            ('FaultAtPageErase', 0),
            ('TrackingStartAddress', rec_track_start),
        ):
            if hasattr(backend_dev, attr):
                try:
                    setattr(backend_dev, attr, val)
                except Exception:
                    pass
        if backend_kind == 'slow' and hasattr(backend_dev, 'Nvm'):
            for attr, val in (
                ('FaultAtWordWrite', 0),
                ('FaultAtPageErase', 0),
                ('TrackingStartAddress', rec_track_start),
            ):
                if hasattr(backend_dev.Nvm, attr):
                    try:
                        setattr(backend_dev.Nvm, attr, val)
                    except Exception:
                        pass

    # Restore MRAM uncorrectable / torn word marks AFTER controller Reset()
    mram_target = None
    if backend_dev is not None and hasattr(backend_dev, 'MarkWordUncorrectable'):
        mram_target = backend_dev
    elif backend_dev is not None and hasattr(getattr(backend_dev, 'Nvm', None), 'MarkWordUncorrectable'):
        mram_target = backend_dev.Nvm
    if mram_target is not None:
        if hasattr(mram_target, 'ClearUncorrectableWords'):
            mram_target.ClearUncorrectableWords()
        if hasattr(mram_target, 'TornWordMode') and pstate.get('mram_torn_word'):
            try:
                mram_target.TornWordMode = str(pstate['mram_torn_word'])
            except Exception:
                pass
        for off in pstate.get('uncorrectable_offsets') or ():
            mram_target.MarkWordUncorrectable(int(off))
        if hasattr(mram_target, 'ClearUncorrectableReadLog'):
            mram_target.ClearUncorrectableReadLog()

    # Apply register pre-writes and hash bypass patches
    for pw in rcfg.get('boot_register_pre_writes') or ():
        bus.WriteDoubleWord(int(str(pw['address']), 0), int(str(pw['value']), 0))

    for _sym, addr_str in (rcfg.get('hash_bypass_addrs') or {}).items():
        b_addr = int(str(addr_str), 0) & ~1
        if b_addr > 0:
            bus.WriteWord(b_addr, 0x2000)
            bus.WriteWord(b_addr + 2, 0x4770)

    # Prime bootloader entry vector (SP, PC, VTOR)
    boot_entry = int(str(rcfg.get('bootloader_entry', '0')), 0)
    init_sp = _as_int(bus.ReadDoubleWord(boot_entry))
    init_pc = _as_int(bus.ReadDoubleWord(boot_entry + 4))
    cpu_ref.SetRegisterUnsafe(13, RegisterValue.Create(init_sp, 32))
    cpu_ref.PC = RegisterValue.Create(init_pc, 32)
    bus.WriteDoubleWord(0xE000ED08, boot_entry)
    cpu_ref.IsHalted = False

    slot_ranges = {}
    for s_name, s_info in (rcfg.get('slots') or {}).items():
        s_base = int(str(s_info['base']), 0)
        s_size = int(str(s_info['size']), 0)
        slot_ranges[str(s_name)] = (s_base, s_base + s_size)

    sticky_vtor = {'captured': False, 'value': 0, 'slot': None}
    sticky_pc = {'captured': False, 'value': 0, 'slot': None}

    def _check_vtor(vtor_val):
        v = _as_int(vtor_val)
        if v != 0:
            for sn, (s_lo, s_hi) in slot_ranges.items():
                if s_lo <= v < s_hi:
                    sticky_vtor['captured'] = True
                    sticky_vtor['value'] = v
                    sticky_vtor['slot'] = sn
                    break

    def _check_pc(pc_val):
        p = _as_int(pc_val) & ~1
        for sn, (s_lo, s_hi) in slot_ranges.items():
            if s_lo <= p < s_hi:
                sticky_pc['captured'] = True
                sticky_pc['value'] = p
                sticky_pc['slot'] = sn
                break

    # Run recovery boot loop
    time_slice_s = max(0.002, min(0.05, float(rcfg.get('phase2_time_slice_s', 0.02) or 0.02)))
    slice_str = '{:.3f}'.format(time_slice_s)
    run_duration_s = max(0.1, float(rcfg.get('run_duration_s', 2.0) or 2.0))
    wall_timeout_s = max(10.0, float(rcfg.get('phase2_wall_timeout_s', 30.0) or 30.0))
    stall_timeout_s = float(rcfg.get('progress_stall_timeout_s', 5.0) or 5.0)
    settle_iters = int(rcfg.get('vtor_settle_iters', 0) or 0)
    max_iters = max(20, int(run_duration_s / time_slice_s) + 10)

    eff_vtor_slot = str(sc.get('vtor_in_slot') or '').strip()
    eff_pc_slot = str(sc.get('pc_in_slot') or '').strip()
    vec_offset = int(str(sc.get('vector_table_offset', '0')), 0)

    started_wall = _time.time()
    start_virt = _read_machine_virtual_s(m_ref)
    last_progress_virt = start_virt
    last_progress_wall = started_wall
    last_key = None
    last_pc_norm = None
    halt_hits = 0
    vtor_settle_remaining = settle_iters
    stop_reason = 'budget'
    exception_active = 0
    lockup_observed = False

    for _it in range(1, max_iters + 1):
        monitor.Parse('emulation RunFor "{}"'.format(slice_str))
        now_wall = _time.time()
        now_virt = _read_machine_virtual_s(m_ref)
        pc_now = _as_int(cpu_ref.GetRegisterUnsafe(15))
        vtor_now = _as_int(bus.ReadDoubleWord(0xE000ED08))
        _check_vtor(vtor_now)
        _check_pc(pc_now)

        try:
            xpsr = _as_int(getattr(cpu_ref, 'XProgramStatusRegister', 0))
            ipsr = xpsr & 0x1FF
            if ipsr in (3, 4, 5, 6):
                exception_active = ipsr
        except Exception:
            pass

        try:
            if bool(getattr(cpu_ref, 'IsLockedUp', False)) or (pc_now & ~1) == 0xEFFFFFFE:
                lockup_observed = True
        except Exception:
            pass

        if sticky_vtor['captured']:
            if vtor_settle_remaining > 0:
                vtor_settle_remaining -= 1
            else:
                stop_reason = 'vtor_captured'
                break

        if eff_pc_slot and sticky_pc['captured'] and sticky_pc['slot'] == eff_pc_slot:
            stop_reason = 'pc_captured'
            break

        if lockup_observed or exception_active in (3, 4, 5, 6):
            stop_reason = 'fault_exception'
            break

        pc_norm = pc_now & ~1
        if last_pc_norm == pc_norm and _is_terminal_halt_pc(bus, pc_now):
            halt_hits += 1
            if halt_hits >= 2:
                stop_reason = 'no_boot_terminal_loop'
                break
        else:
            halt_hits = 0
        last_pc_norm = pc_norm

        try:
            insns = int(cpu_ref.ExecutedInstructions)
        except Exception:
            insns = 0
        w_cnt = int(getattr(backend_dev, 'TotalWordWrites', 0) or 0) if backend_dev is not None else 0
        e_cnt = int(getattr(backend_dev, 'TotalPageErases', 0) or 0) if backend_dev is not None else 0
        cur_key = (w_cnt, e_cnt, sticky_vtor['captured'], sticky_pc['captured'], pc_norm)
        if last_key is None or cur_key != last_key:
            last_key = cur_key
            last_progress_virt = now_virt
            last_progress_wall = now_wall
        elif stall_timeout_s > 0 and (now_virt - last_progress_virt) >= max(0.05, stall_timeout_s):
            stop_reason = 'no_boot_stall'
            break

        if (now_wall - started_wall) >= wall_timeout_s:
            stop_reason = 'wall_timeout'
            break

    # Evaluate outcome
    final_vtor = _as_int(bus.ReadDoubleWord(0xE000ED08))
    final_pc = _as_int(cpu_ref.GetRegisterUnsafe(15))
    actual_vtor = sticky_vtor['value'] if sticky_vtor['captured'] else final_vtor
    vtor_aligned = (actual_vtor % 128 == 0)
    no_boot_without_vtor = stop_reason.startswith('no_boot') and not sticky_vtor['captured']

    boot_slot = None
    for sn, (s_lo, s_hi) in slot_ranges.items():
        if s_lo <= actual_vtor < s_hi:
            boot_slot = sn
            break
    if boot_slot is None and sticky_pc['captured'] and not no_boot_without_vtor:
        boot_slot = sticky_pc['slot']
    if boot_slot is None and eff_pc_slot in slot_ranges and not no_boot_without_vtor:
        s_lo, s_hi = slot_ranges[eff_pc_slot]
        if s_lo <= (final_pc & ~1) < s_hi:
            boot_slot = eff_pc_slot
    execution_observed = boot_slot is not None

    vtor_ok = not bool(eff_vtor_slot)
    if eff_vtor_slot == 'any':
        if vec_offset > 0:
            if boot_slot in slot_ranges:
                vtor_ok = (actual_vtor == slot_ranges[boot_slot][0] + vec_offset)
            else:
                vtor_ok = False
        else:
            vtor_ok = (boot_slot is not None)
    elif eff_vtor_slot in slot_ranges:
        s_lo, s_hi = slot_ranges[eff_vtor_slot]
        if vec_offset > 0:
            vtor_ok = (s_lo <= actual_vtor < s_hi) and (actual_vtor == s_lo + vec_offset)
        else:
            vtor_ok = (s_lo <= actual_vtor < s_hi)

    pc_ok = True
    if eff_pc_slot in slot_ranges:
        s_lo, s_hi = slot_ranges[eff_pc_slot]
        pc_lo = s_lo + vec_offset
        pc_norm = final_pc & ~1
        pc_ok = (pc_lo <= pc_norm < s_hi) or (
            sticky_pc['captured'] and sticky_pc['slot'] == eff_pc_slot and not no_boot_without_vtor
        )

    marker_ok = True
    actual_marker = 0
    if marker_addr != 0:
        actual_marker = _as_int(bus.ReadDoubleWord(marker_addr))
        marker_ok = (actual_marker == marker_value)

    page_size = int(rcfg.get('page_size', 4096) or 4096)
    erase_regions = rcfg.get('erase_regions') or []
    if sc.get('image_hash'):
        hash_slot = str(sc.get('image_hash_slot') or '').strip()
        if not hash_slot or hash_slot == 'any':
            hash_slot = boot_slot or 'exec'
        if hash_slot in slot_ranges:
            hs_lo, hs_hi = slot_ranges[hash_slot]
            ext = _resolve_slot_hash_extent(
                bus, backend_dev, backend_kind, nvm_base, hs_lo, hs_hi - hs_lo, erase_regions, page_size
            )
            slot_data = _read_nvm_bytes(bus, backend_dev, backend_kind, nvm_base, hs_lo, ext)
            actual_hash = hashlib.sha256(slot_data).hexdigest().lower()
            allowed_list = sc.get('allowed_image_hashes') or []
            exp_sha = str(sc.get('expected_exec_sha256') or '').strip().lower()
            if allowed_list:
                marker_ok = marker_ok and any(
                    actual_hash == str(item.get('sha256') or '').strip().lower()
                    for item in allowed_list
                )
            elif exp_sha:
                marker_ok = marker_ok and (actual_hash == exp_sha)

    approved_cfg = sc.get('approved_image_running')
    approved_failed_part = None
    if isinstance(approved_cfg, dict):
        app_slot = str(approved_cfg.get('slot') or 'exec').strip()
        if app_slot in slot_ranges:
            as_lo, as_hi = slot_ranges[app_slot]
            ext = _resolve_slot_hash_extent(
                bus, backend_dev, backend_kind, nvm_base, as_lo, as_hi - as_lo, erase_regions, page_size
            )
            slot_data = _read_nvm_bytes(bus, backend_dev, nvm_base if False else backend_kind, nvm_base, as_lo, ext)
            actual_hash = hashlib.sha256(slot_data).hexdigest().lower()
            app_images = approved_cfg.get('images') or []
            digest_ok = False
            for entry in app_images:
                if isinstance(entry, dict) and str(entry.get('sha256') or '').strip().lower() == actual_hash:
                    digest_ok = True
                    break
            if not digest_ok:
                approved_failed_part = 'digest'
                marker_ok = False

    mem_checks_ok, failed_mem_checks = _evaluate_memory_checks(bus, sc.get('memory_checks'))

    if approved_failed_part == 'digest':
        observed_outcome = 'wrong_image'
    elif exception_active == 5:
        observed_outcome = 'bus_fault'
    elif exception_active in (3, 4, 6) or lockup_observed:
        observed_outcome = 'hard_fault'
    elif stop_reason == 'wall_timeout':
        observed_outcome = 'timeout'
    elif not execution_observed:
        observed_outcome = 'no_boot'
    elif not vtor_aligned:
        observed_outcome = 'misaligned_vtor'
    elif not pc_ok:
        observed_outcome = 'wrong_pc'
    elif not vtor_ok or not marker_ok:
        observed_outcome = 'wrong_image'
    elif not mem_checks_ok:
        observed_outcome = 'memory_checks_unmet'
    else:
        observed_outcome = 'success'

    expected_outcome = str(meta.get('expected_outcome') or 'success')
    report_outcome = str(meta.get('report_outcome') or observed_outcome)

    result_payload = {
        'profile': meta.get('profile'),
        'point_name': meta.get('point_name'),
        'observed_outcome': observed_outcome,
        'expected_outcome': expected_outcome,
        'report_outcome': report_outcome,
        'matches_report': (observed_outcome == report_outcome),
        'boot_slot': boot_slot,
        'stop_reason': stop_reason,
        'vtor': _fmt_u32(actual_vtor),
        'pc': _fmt_u32(final_pc),
        'marker_actual': _fmt_u32(actual_marker) if marker_addr != 0 else None,
        'state_identity': pstate.get('state_identity'),
        'state_sha256': actual_sha,
        'specified_bytes_verified': specified_bytes_verified,
        'unspecified_bytes': unspecified_bytes_count,
        'uncorrectable_words': pstate.get('uncorrectable_words') or [],
        'failed_memory_checks': failed_mem_checks,
    }
    res_path = os.path.join(cwd, 'result.json')
    with open(res_path, 'w') as rf:
        rf.write(json.dumps(result_payload, indent=2, sort_keys=True) + '\\n')

    print('Observed outcome: {}'.format(observed_outcome))
    print('Expected outcome: {}'.format(expected_outcome))


run_standalone_reproducer()
'''


def _render_dockerfile(renode_version: str) -> str:
    ver_key = "1.16.1" if renode_version.startswith("1.16.1") else "1.17.0"
    archive = RENODE_RELEASE_ARCHIVES[ver_key]
    return (
        "FROM ubuntu:24.04\n\n"
        "ARG DEBIAN_FRONTEND=noninteractive\n"
        f"ARG RENODE_VERSION={ver_key}\n"
        f"ARG RENODE_URL={archive['url']}\n"
        f"ARG RENODE_SHA256={archive['sha256']}\n\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "    ca-certificates \\\n"
        "    curl \\\n"
        "    libicu-dev \\\n"
        "    python3 && \\\n"
        "    rm -rf /var/lib/apt/lists/*\n\n"
        "RUN curl --fail --location --proto '=https' --tlsv1.2 \"${RENODE_URL}\" \\\n"
        "      --output /tmp/renode.tar.gz && \\\n"
        "    echo \"${RENODE_SHA256}  /tmp/renode.tar.gz\" | sha256sum -c - && \\\n"
        "    mkdir -p /opt/renode && \\\n"
        "    tar -xzf /tmp/renode.tar.gz -C /opt/renode --strip-components=1 && \\\n"
        "    rm /tmp/renode.tar.gz && \\\n"
        "    /opt/renode/renode --version\n\n"
        "ENV PATH=/opt/renode:${PATH}\n"
        "ENV REPRO_BUNDLE_DIR=/repro\n"
        "WORKDIR /repro\n"
        'ENTRYPOINT ["/opt/renode/renode", "--disable-xwt", "--console", "/repro/reproduce.resc"]\n'
    )


def _render_run_sh(
    *,
    renode_version: str,
    has_fetch_script: bool,
    redistributable: bool,
    elf_rel_path: str,
) -> str:
    ver_key = "1.16.1" if renode_version.startswith("1.16.1") else "1.17.0"
    lines = [
        "#!/usr/bin/env bash",
        "# Standalone reproducer runner (Docker-based by default, native Renode optional).",
        "set -euo pipefail",
        "",
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'cd "${SCRIPT_DIR}"',
        'export REPRO_BUNDLE_DIR="${SCRIPT_DIR}"',
        "",
        f'RECORDED_RENODE_VERSION={shlex.quote(ver_key)}',
        'MODE="auto"',
        'RENODE_BIN="${RENODE:-}"',
        'DOCKER_IMAGE="${REPRO_DOCKER_IMAGE:-rpx-repro-renode:${RECORDED_RENODE_VERSION}}"',
        'CONTAINER_PREFIX="${REPRO_CONTAINER_PREFIX:-rpx-repro}"',
        'ALLOW_VERSION_MISMATCH=0',
        'VERBOSE=0',
        "",
        "while [[ $# -gt 0 ]]; do",
        '    case "$1" in',
        "        --docker)",
        '            MODE="docker"',
        "            shift",
        "            ;;",
        "        --native)",
        '            MODE="native"',
        "            shift",
        "            ;;",
        "        --renode)",
        '            MODE="native"',
        '            RENODE_BIN="$2"',
        "            ALLOW_VERSION_MISMATCH=1",
        "            shift 2",
        "            ;;",
        "        --docker-image)",
        '            MODE="docker"',
        '            DOCKER_IMAGE="$2"',
        "            shift 2",
        "            ;;",
        "        --allow-version-mismatch)",
        "            ALLOW_VERSION_MISMATCH=1",
        "            shift",
        "            ;;",
        "        --verbose|-v)",
        "            VERBOSE=1",
        "            shift",
        "            ;;",
        "        --help|-h)",
        '            echo "Usage: ./run.sh [--docker | --native | --renode PATH] [--docker-image IMAGE] [--allow-version-mismatch] [--verbose]"',
        "            exit 0",
        "            ;;",
        "        *)",
        '            echo "Unknown option: $1" >&2',
        "            exit 2",
        "            ;;",
        "    esac",
        "done",
        "",
    ]
    if has_fetch_script:
        lines.extend([
            f'if [[ ! -f "${{SCRIPT_DIR}}/{elf_rel_path}" ]]; then',
            '    if [[ -x "${SCRIPT_DIR}/fetch_and_build.sh" ]]; then',
            '        "${SCRIPT_DIR}/fetch_and_build.sh"',
            "    fi",
            "fi",
            "",
        ])
    lines.extend([
        'if [[ "${MODE}" == "auto" ]]; then',
        '    if [[ -n "${RENODE_BIN}" ]]; then',
        '        MODE="native"',
        '    elif command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then',
        '        MODE="docker"',
        '    elif command -v renode >/dev/null 2>&1; then',
        '        MODE="native"',
        "    else",
        '        echo "ERROR: Neither Docker nor native Renode (${RECORDED_RENODE_VERSION}) is available." >&2',
        "        exit 1",
        "    fi",
        "fi",
        "",
        'rm -f "${SCRIPT_DIR}/result.json" "${SCRIPT_DIR}/renode.log"',
        "",
        'if [[ "${MODE}" == "native" ]]; then',
        '    if [[ -z "${RENODE_BIN}" ]]; then',
        '        RENODE_BIN="$(command -v renode || true)"',
        "    fi",
        '    if [[ -z "${RENODE_BIN}" || ! -x "${RENODE_BIN}" ]]; then',
        '        echo "ERROR: Native Renode executable not found. Pass --renode /path/to/renode or run with Docker." >&2',
        "        exit 1",
        "    fi",
        '    ACTUAL_VER="$("${RENODE_BIN}" --version 2>&1 | head -n 1 || true)"',
        '    if [[ "${ALLOW_VERSION_MISMATCH}" -eq 0 && "${ACTUAL_VER}" != *"${RECORDED_RENODE_VERSION}"* ]]; then',
        '        echo "ERROR: Recorded Renode version is ${RECORDED_RENODE_VERSION}, but ${RENODE_BIN} reported: ${ACTUAL_VER}" >&2',
        '        echo "Pass --allow-version-mismatch to run with a different Renode version." >&2',
        "        exit 1",
        "    fi",
        '    DOTNET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rpx-dotnet.XXXXXX")"',
        '    trap \'rm -rf "${DOTNET_DIR}"\' EXIT',
        '    export DOTNET_BUNDLE_EXTRACT_BASE_DIR="${DOTNET_DIR}"',
        '    if [[ "${VERBOSE}" -eq 1 ]]; then',
        '        "${RENODE_BIN}" --disable-xwt --console "${SCRIPT_DIR}/reproduce.resc" 2>&1 | tee "${SCRIPT_DIR}/renode.log"',
        "    else",
        '        if ! "${RENODE_BIN}" --disable-xwt --console "${SCRIPT_DIR}/reproduce.resc" >"${SCRIPT_DIR}/renode.log" 2>&1; then',
        '            cat "${SCRIPT_DIR}/renode.log" >&2',
        "            exit 1",
        "        fi",
        "    fi",
        "else",
        '    if ! docker image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1; then',
        '        docker build -t "${DOCKER_IMAGE}" "${SCRIPT_DIR}" >/dev/null',
        "    fi",
        '    CONTAINER_NAME="${CONTAINER_PREFIX}-$$-${RANDOM}"',
        '    if [[ "${VERBOSE}" -eq 1 ]]; then',
        '        docker run --rm --name "${CONTAINER_NAME}" -e REPRO_BUNDLE_DIR=/repro -v "${SCRIPT_DIR}:/repro" -w /repro "${DOCKER_IMAGE}" 2>&1 | tee "${SCRIPT_DIR}/renode.log"',
        "    else",
        '        if ! docker run --rm --name "${CONTAINER_NAME}" -e REPRO_BUNDLE_DIR=/repro -v "${SCRIPT_DIR}:/repro" -w /repro "${DOCKER_IMAGE}" >"${SCRIPT_DIR}/renode.log" 2>&1; then',
        '            cat "${SCRIPT_DIR}/renode.log" >&2',
        "            exit 1",
        "        fi",
        "    fi",
        "fi",
        "",
        'if [[ ! -f "${SCRIPT_DIR}/result.json" ]]; then',
        '    echo "ERROR: Reproducer did not write result.json" >&2',
        '    [[ -f "${SCRIPT_DIR}/renode.log" ]] && cat "${SCRIPT_DIR}/renode.log" >&2',
        "    exit 1",
        "fi",
        "",
        'OBS="$(sed -n \'s/.*"observed_outcome"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p\' "${SCRIPT_DIR}/result.json" | head -n 1)"',
        'EXP="$(sed -n \'s/.*"expected_outcome"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p\' "${SCRIPT_DIR}/result.json" | head -n 1)"',
        'REP="$(sed -n \'s/.*"report_outcome"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p\' "${SCRIPT_DIR}/result.json" | head -n 1)"',
        'echo "Observed outcome: ${OBS}"',
        'echo "Expected outcome: ${EXP}"',
        'if [[ -n "${REP}" && "${OBS}" != "${REP}" ]]; then',
        '    echo "ERROR: Observed outcome (${OBS}) does not match report outcome (${REP})" >&2',
        "    exit 1",
        "fi",
    ])
    return "\n".join(lines) + "\n"


def _format_cut_chain_text(target: DebugTarget) -> str:
    row = target.row or {}
    search = row.get("recovery_state_search") or {}
    chain = search.get("chain") if isinstance(search.get("chain"), dict) else {}
    if chain.get("text"):
        return str(chain["text"])
    if target.cuts:
        return " -> ".join(
            f"{CODE_TO_FAULT_NAME.get(code, code)}[{idx}]"
            for idx, code in target.cuts
        )
    return target.point_name


def _render_readme_md(
    *,
    target: DebugTarget,
    state: ReconstructedState,
    provenance: dict[str, str],
    renode_version: str,
    license_decision: LicenseDecision,
    expected_control_outcome: str,
    report_outcome: str,
    repl_files: list[Path],
    peripheral_files: list[Path],
    final_state_sha256: str | None = None,
    fully_specified: bool | None = None,
    specified_regions: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    unspecified_regions: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> str:
    row = target.row or {}
    explanation = row.get("failure_explanation") if isinstance(row.get("failure_explanation"), dict) else None
    cut_chain_text = _format_cut_chain_text(target)
    upstream_commit = provenance.get("commit", "unknown")
    upstream_repo = provenance.get("repository", "")
    upstream_name = provenance.get("name", target.profile.name)

    lines = [
        f"# Standalone Power-Loss Reproducer: `{target.profile.name}`",
        "",
        "## Overview",
        "",
        f"- **Profile**: `{target.profile.name}`",
        f"- **Point / State**: `{target.point_name}`",
        f"- **Cut Chain**: `{cut_chain_text}`",
        f"- **Observed Outcome**: `{report_outcome}`",
        f"- **Expected Outcome**: `{expected_control_outcome}`",
    ]
    if target.expected_fault_class:
        lines.append(f"- **Fault Class**: `{target.expected_fault_class}`")
    if state.state_identity:
        lines.append(f"- **State Identity**: `{state.state_identity}`")
    if upstream_repo:
        lines.append(f"- **Upstream Target**: `{upstream_name}` ({upstream_repo})")
    else:
        lines.append(f"- **Upstream Target**: `{upstream_name}`")
    lines.extend([
        f"- **Upstream Commit**: `{upstream_commit}`",
        f"- **Renode Version**: `{renode_version}`",
        f"- **Target License**: `{license_decision.license_spdx}` ({'bundled' if license_decision.redistributable else 'fetched & built from pinned sources; binaries not bundled'})",
        "",
        "## Quick Start",
        "",
        "Run with Docker (default, requires only Docker and no Tardigrade checkout):",
        "",
        "```sh",
        "./run.sh",
        "```",
        "",
        f"Run with a local installation of Renode `{renode_version}`:",
        "",
        "```sh",
        "./run.sh --native",
        "# or specify an explicit Renode executable:",
        "./run.sh --renode /path/to/renode",
        "```",
        "",
        "`./run.sh` boots the recovery from the reconstructed persistent state in `state/persistent_state.bin` and prints:",
        "",
        "```text",
        f"Observed outcome: {report_outcome}",
        f"Expected outcome: {expected_control_outcome}",
        "```",
        "",
        "## Cut Chain",
        "",
        f"Cut sequence: `{cut_chain_text}`",
        "",
    ])

    exp_cuts = explanation.get("cuts") if isinstance(explanation, dict) and isinstance(explanation.get("cuts"), list) else None
    if exp_cuts:
        for idx, cut_info in enumerate(exp_cuts, start=1):
            if not isinstance(cut_info, dict):
                continue
            op = cut_info.get("operation", "write")
            op_idx = cut_info.get("operation_index", 0)
            ft = cut_info.get("fault_type", "power_loss")
            addr = cut_info.get("address", "")
            pc = cut_info.get("pc", "")
            src = cut_info.get("source") if isinstance(cut_info.get("source"), dict) else {}
            src_desc = ""
            if src.get("function"):
                src_desc = f" in `{src['function']}`"
                if src.get("file") and src.get("line"):
                    src_desc += f" (`{src['file']}:{src['line']}`)"
            line = f"{idx}. `{op}[{op_idx}]` (`{ft}`)"
            if addr:
                line += f" at `{addr}`"
            if pc:
                line += f", PC `{pc}`"
            line += src_desc
            lines.append(line)
            chain = cut_info.get("call_chain")
            if isinstance(chain, list) and chain:
                chain_str = " <- ".join(
                    f"{frame.get('function', '?')} ({frame.get('pc', '?')})"
                    for frame in chain
                    if isinstance(frame, dict)
                )
                if chain_str:
                    lines.append(f"   - Call chain: `{chain_str}`")
        lines.append("")
    elif target.cuts:
        for idx, (c_at, c_code) in enumerate(target.cuts, start=1):
            ft_name = CODE_TO_FAULT_NAME.get(c_code, c_code)
            lines.append(f"{idx}. `{ft_name}[{c_at}]` (wire code `{c_code}`)")
        lines.append("")

    lines.extend([
        "## Failure Explanation (`failure_explanation`)",
        "",
    ])
    if isinstance(explanation, dict):
        msg = explanation.get("message")
        if msg:
            lines.extend([
                f"> {msg}",
                "",
            ])
        comparison = explanation.get("state_comparison")
        if isinstance(comparison, dict):
            lines.append(f"- **State Comparison Status**: `{comparison.get('status', 'n/a')}`")
            for span in comparison.get("ranges") or ():
                if isinstance(span, dict):
                    field_note = f" ({span['field']})" if span.get("field") else ""
                    lines.append(
                        f"  - Address `{span.get('address')}`{field_note}: "
                        f"failing `{span.get('failing_hex')}` vs passing `{span.get('passing_hex')}`"
                    )
            for u_addr in comparison.get("uncorrectable_only_in_failing") or ():
                lines.append(f"  - Uncorrectable ECC mark only in failing state: `{u_addr}`")
            lines.append("")
        sibling = explanation.get("passing_sibling")
        if isinstance(sibling, dict):
            lines.append(
                f"- **Passing Sibling**: `{sibling.get('fault_type', 'power_loss')}[{sibling.get('operation_index', '?')}]`"
                + (f" (state `{sibling['state_identity']}`)" if sibling.get("state_identity") else "")
            )
            lines.append("")
        lines.extend([
            "```json",
            json.dumps(explanation, indent=2, sort_keys=True),
            "```",
            "",
        ])
    else:
        lines.extend([
            f"Point `{target.point_name}` (cuts `{cut_chain_text}`) observed `{report_outcome}` "
            f"(expected `{expected_control_outcome}`).",
            "",
        ])

    eff_sha = final_state_sha256 or state.sha256
    eff_spec = list(specified_regions if specified_regions is not None else state.specified_regions)
    eff_unspec = list(unspecified_regions if unspecified_regions is not None else state.unspecified_regions)
    eff_fully_spec = (
        bool(fully_specified)
        if fully_specified is not None
        else (bool(state.fully_specified) and not eff_unspec)
    )
    spec_bytes_total = sum(int(r.get("size", 0)) for r in eff_spec if isinstance(r, dict))
    unspec_bytes_total = sum(int(r.get("size", 0)) for r in eff_unspec if isinstance(r, dict))

    lines.extend([
        "## Reconstructed Persistent State",
        "",
        "- **Binary Image**: `state/persistent_state.bin`",
        "- **Metadata**: `state/persistent_state.json`",
        f"- **State Source**: `{state.state_source}`",
        f"- **Base Address**: `0x{state.base_address:08X}`",
        f"- **Size**: `{state.size}` bytes",
        f"- **SHA-256**: `{eff_sha}`",
        f"- **State Identity**: `{state.state_identity}`",
        f"- **Flash Backend**: `{state.flash_backend}` (`{state.backend_kind}`)",
        f"- **Uncorrectable / Torn Word Marks**: `{list(state.uncorrectable_words)}` (offsets `{list(state.uncorrectable_offsets)}`)",
        f"- **Torn-Word Mode**: MRAM `{state.mram_torn_word}`, Flash `{state.torn_word}`",
    ])
    if eff_fully_spec and unspec_bytes_total == 0:
        lines.append(
            f"- **Specification Status**: `fully_specified` (`{state.size}` / `{state.size}` bytes specified; `0` unspecified bytes)"
        )
    else:
        lines.append(
            f"- **Specification Status**: `partially_specified` (`{spec_bytes_total}` / `{state.size}` bytes specified; `{unspec_bytes_total}` bytes unspecified)"
        )
        for ureg in eff_unspec:
            if not isinstance(ureg, dict):
                continue
            u_addr = ureg.get("address", f"0x{state.base_address + int(ureg.get('offset', 0)):08X}")
            u_off = int(ureg.get("offset", 0))
            u_sz = int(ureg.get("size", 0))
            u_reason = ureg.get("reason", "unspecified")
            lines.append(
                f"  - Unspecified region `{u_addr}` (offset `0x{u_off:06X}`, `{u_sz}` bytes): {u_reason}"
            )
    lines.extend([
        "",
        "## Bundle Contents",
        "",
        "- `run.sh`: One-command reproducer runner (Docker by default, `--native` / `--renode` optional)",
        f"- `Dockerfile`: Container definition pinning Renode `{renode_version}`",
        "- `reproduce.resc`: Renode script that compiles the peripherals, loads the platform, ELF, and reconstructed persistent state, and boots recovery",
        "- `reproduce_recovery.py`: Self-contained Renode recovery boot and outcome check script",
        "- `platforms/`: " + ", ".join(f"`{p.name}`" for p in repl_files),
        "- `peripherals/`: " + ", ".join(f"`{p.name}`" for p in peripheral_files),
        "- `state/persistent_state.bin` & `state/persistent_state.json`: Reconstructed persistent memory image and uncorrectable/torn word marks",
    ])
    if not license_decision.redistributable:
        lines.append("- `fetch_and_build.sh`: Fetches and builds the target from pinned upstream sources before running")
    elif license_decision.fetch_and_build_script:
        lines.append("- `firmware/` & `fetch_and_build.sh`: Bundled firmware artifacts plus optional rebuild script from pinned upstream sources")
    else:
        lines.append("- `firmware/`: Bundled bootloader ELF and slot images")
    return "\n".join(lines) + "\n"


def _slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(text or "").strip()).strip("_")
    return slug[:64] if slug else "point"


def export_reproducer(
    *,
    report: Path | None = None,
    point: str | None = None,
    state: str | None = None,
    reproduction: str | Path | None = None,
    profile: Path | None = None,
    elf: Path | None = None,
    output: Path | None = None,
    archive: bool = False,
    renode_test: str = DEFAULT_RENODE_TEST,
    renode_version: str | None = None,
    timeout: int = 300,
    repo_root: Path = REPO_ROOT,
) -> Path:
    if timeout is None or isinstance(timeout, bool) or int(timeout) <= 0:
        raise ExportReproError("--timeout must be a positive integer")
    repo_root = Path(repo_root).resolve()

    target = resolve_export_target(
        report=report,
        point=point,
        state=state,
        reproduction=reproduction,
        profile=profile,
        elf=elf,
        repo_root=repo_root,
    )

    report_data: dict[str, Any] | None = None
    if report is not None:
        loaded_rep, _ = _load_json_or_yaml_input(report)
        if isinstance(loaded_rep, dict):
            report_data = loaded_rep

    raw_profile: dict[str, Any] = {}
    if target.profile_path.is_file():
        try:
            raw_profile = load_profile_raw(target.profile_path)
        except Exception:
            raw_profile = {}

    license_decision = classify_target_license(target, report_data, raw_profile, repo_root)
    provenance = license_decision.target_source or resolve_upstream_provenance(
        target, report_data, raw_profile, repo_root
    )
    repl_files, peripheral_files = resolve_platform_and_peripherals(target, repo_root)
    reconstructed = reconstruct_persistent_state(
        target,
        report_data=report_data,
        renode_test=renode_test,
        timeout=timeout,
        repo_root=repo_root,
    )

    recorded_renode_version = detect_renode_version(
        explicit_version=renode_version,
        report_data=report_data,
        reconstructed_version=reconstructed.renode_version,
        renode_test=renode_test,
    )

    expected_control_outcome = str(
        ((report_data or {}).get("expect") or {}).get("control_outcome")
        or getattr(getattr(target.profile, "expect", None), "control_outcome", None)
        or "success"
    )
    report_outcome = str(
        target.expected_outcome
        or (target.row or {}).get("boot_outcome")
        or "unknown"
    )

    default_name = f"repro-{_slugify(target.profile.name)}-{_slugify(target. state_identity[:12] if target.state_identity else target.point_name)}"
    if output is None:
        out_path = (Path.cwd() / (default_name + (".tar.gz" if archive else ""))).resolve()
    else:
        out_path = Path(output).expanduser().resolve()

    is_archive = archive or out_path.name.endswith((".tar.gz", ".tgz", ".tar"))

    with tempfile.TemporaryDirectory(prefix="tardigrade_repro_stage_") as stage_raw:
        if is_archive:
            bundle_stem = re.sub(r"\.(?:tar\.gz|tgz|tar)$", "", out_path.name) or default_name
            bundle_dir = Path(stage_raw) / bundle_stem
        else:
            if out_path.exists():
                if out_path.is_dir():
                    shutil.rmtree(out_path)
                else:
                    out_path.unlink()
            bundle_dir = out_path

        platforms_dir = bundle_dir / "platforms"
        peripherals_dir = bundle_dir / "peripherals"
        firmware_dir = bundle_dir / "firmware"
        state_dir = bundle_dir / "state"
        for d in (platforms_dir, peripherals_dir, firmware_dir, state_dir):
            d.mkdir(parents=True, exist_ok=True)

        for repl_file in repl_files:
            shutil.copy2(repl_file, platforms_dir / repl_file.name)

        for cs_file in peripheral_files:
            shutil.copy2(cs_file, peripherals_dir / cs_file.name)

        if license_decision.redistributable:
            shutil.copy2(target.elf_path, firmware_dir / target.elf_path.name)
            for _slot_name, img_rel in target.profile.images.items():
                img_src = Path(target.profile.resolve_path(repo_root, img_rel)).resolve()
                if img_src.is_file():
                    marker = _detect_file_gpl_or_prohibited(img_src)
                    if marker:
                        raise ExportReproError(
                            f"cannot bundle image {img_src.name}: prohibited license ({marker})"
                        )
                    shutil.copy2(img_src, firmware_dir / img_src.name)

        if license_decision.fetch_and_build_script:
            fetch_sh = bundle_dir / "fetch_and_build.sh"
            fetch_sh.write_text(license_decision.fetch_and_build_script, encoding="utf-8")
            fetch_sh.chmod(0o755)

        recovery_cfg, final_state_bytes, scrubbed_regions = _build_recovery_config_dict(
            target,
            reconstructed,
            license_decision,
            repo_root,
        )
        final_state_sha256 = hashlib.sha256(final_state_bytes).hexdigest().lower()

        total_len = len(final_state_bytes)
        if scrubbed_regions:
            base_unspec_spans = [
                (int(r["offset"]), int(r["offset"]) + int(r["size"]))
                for r in reconstructed.unspecified_regions
                if isinstance(r, dict)
            ]
            scrub_spans = [
                (int(r["offset"]), int(r["offset"]) + int(r["size"]))
                for r in scrubbed_regions
                if isinstance(r, dict)
            ]
            all_unspec_spans = _merge_byte_intervals(total_len, base_unspec_spans + scrub_spans)
            final_spec_spans = _complement_byte_intervals(total_len, all_unspec_spans)
            final_specified_regions = [
                {
                    "address": f"0x{reconstructed.base_address + s:08X}",
                    "offset": s,
                    "size": e - s,
                    "reason": "preserved persistent metadata/trailer bytes outside license-scrubbed code regions",
                }
                for s, e in final_spec_spans
            ]
            final_unspecified_regions = [
                {
                    "name": sreg.get("name", "scrubbed_code"),
                    "address": sreg["address"],
                    "offset": int(sreg["offset"]),
                    "size": int(sreg["size"]),
                    "fill": sreg.get("fill", "0xFF"),
                    "reason": (
                        f"scrubbed to {sreg.get('fill', '0xFF')} because target license "
                        f"({license_decision.license_spdx}) forbids binary redistribution; "
                        "populated at runtime from fetch_and_build.sh"
                    ),
                }
                for sreg in scrubbed_regions
            ] + [
                dict(ureg)
                for ureg in reconstructed.unspecified_regions
                if isinstance(ureg, dict)
            ]
            final_fully_specified = False
        else:
            final_specified_regions = [dict(r) for r in reconstructed.specified_regions] or [
                {
                    "address": f"0x{reconstructed.base_address:08X}",
                    "offset": 0,
                    "size": total_len,
                    "reason": f"full persistent state from {reconstructed.state_source}",
                }
            ]
            final_unspecified_regions = [dict(r) for r in reconstructed.unspecified_regions]
            final_fully_specified = bool(reconstructed.fully_specified and not final_unspecified_regions)

        state_bin_path = state_dir / "persistent_state.bin"
        state_bin_path.write_bytes(final_state_bytes)

        cuts_list = []
        for idx, (c_at, c_code) in enumerate(target.cuts, start=1):
            cuts_list.append({
                "cut": idx,
                "operation_index": int(c_at),
                "fault_type": CODE_TO_FAULT_NAME.get(c_code, c_code),
                "code": str(c_code),
            })

        state_json_payload: dict[str, Any] = {
            "schema_version": 1,
            "profile": target.profile.name,
            "point_name": target.point_name,
            "point_kind": target.point_kind,
            "fault_at": int(target.fault_at),
            "fault_type_code": target.fault_type_code,
            "cuts": cuts_list,
            "cut_chain": _format_cut_chain_text(target),
            "expected_outcome": expected_control_outcome,
            "report_outcome": report_outcome,
            "report_fault_class": target.expected_fault_class,
            "report_boot_slot": (target.row or {}).get("boot_slot"),
            "renode_version": recorded_renode_version,
            "upstream_commit": provenance.get("commit", "unknown"),
            "target_source": provenance,
            "license": {
                "spdx": license_decision.license_spdx,
                "redistributable": license_decision.redistributable,
                "reason": license_decision.reason,
            },
            "persistent_state": {
                "binary_file": "state/persistent_state.bin",
                "base_address": f"0x{reconstructed.base_address:08X}",
                "size": len(final_state_bytes),
                "sha256": final_state_sha256,
                "unscrubbed_sha256": reconstructed.sha256,
                "state_identity": reconstructed.state_identity,
                "state_source": reconstructed.state_source,
                "fully_specified": final_fully_specified,
                "specified_regions": final_specified_regions,
                "unspecified_regions": final_unspecified_regions,
                "backend_kind": reconstructed.backend_kind,
                "flash_backend": reconstructed.flash_backend,
                "uncorrectable_offsets": list(reconstructed.uncorrectable_offsets),
                "uncorrectable_words": list(reconstructed.uncorrectable_words),
                "mram_torn_word": reconstructed.mram_torn_word,
                "torn_word": reconstructed.torn_word,
                "persistent_values": reconstructed.persistent_values,
                "scrubbed_code_regions": scrubbed_regions,
            },
            "recovery_config": recovery_cfg,
            "failure_explanation": (target.row or {}).get("failure_explanation"),
        }
        state_json_path = state_dir / "persistent_state.json"
        state_json_path.write_text(
            json.dumps(state_json_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        resc_text = _render_reproduce_resc(
            target=target,
            state=reconstructed,
            repl_files=repl_files,
            peripheral_files=peripheral_files,
            expected_control_outcome=expected_control_outcome,
            report_outcome=report_outcome,
        )
        (bundle_dir / "reproduce.resc").write_text(resc_text, encoding="utf-8")
        (bundle_dir / "reproduce_recovery.py").write_text(
            _render_reproduce_recovery_py(),
            encoding="utf-8",
        )
        (bundle_dir / "Dockerfile").write_text(
            _render_dockerfile(recorded_renode_version),
            encoding="utf-8",
        )

        run_sh_path = bundle_dir / "run.sh"
        run_sh_path.write_text(
            _render_run_sh(
                renode_version=recorded_renode_version,
                has_fetch_script=bool(license_decision.fetch_and_build_script),
                redistributable=license_decision.redistributable,
                elf_rel_path=f"firmware/{target.elf_path.name}",
            ),
            encoding="utf-8",
        )
        run_sh_path.chmod(0o755)

        readme_text = _render_readme_md(
            target=target,
            state=reconstructed,
            provenance=provenance,
            renode_version=recorded_renode_version,
            license_decision=license_decision,
            expected_control_outcome=expected_control_outcome,
            report_outcome=report_outcome,
            repl_files=repl_files,
            peripheral_files=peripheral_files,
            final_state_sha256=final_state_sha256,
            fully_specified=final_fully_specified,
            specified_regions=final_specified_regions,
            unspecified_regions=final_unspecified_regions,
        )
        (bundle_dir / "README.md").write_text(readme_text, encoding="utf-8")

        repo_license = repo_root / "LICENSE"
        if repo_license.is_file():
            shutil.copy2(repo_license, bundle_dir / "LICENSE")
        notices = repo_root / "THIRD_PARTY_NOTICES.md"
        if license_decision.redistributable and notices.is_file():
            shutil.copy2(notices, bundle_dir / "THIRD_PARTY_NOTICES.md")

        if is_archive:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "w:gz" if out_path.name.endswith((".tar.gz", ".tgz")) or archive else "w"
            if archive and not out_path.name.endswith((".tar.gz", ".tgz", ".tar")):
                out_path = out_path.with_name(out_path.name + ".tar.gz")
            with tarfile.open(out_path, mode) as tf:
                tf.add(bundle_dir, arcname=bundle_dir.name)

    return out_path


def build_arg_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Export a failing audit point or state as a standalone reproducer bundle.",
    )
    parser.add_argument(
        "positional",
        nargs="*",
        help="Positional arguments: <report> <point or state id> [output].",
    )
    parser.add_argument(
        "--report",
        "--input",
        "--sarif",
        dest="report",
        type=Path,
        help="Audit JSON report, state-search checkpoint, or SARIF 2.1.0 report file.",
    )
    parser.add_argument(
        "--point",
        help="Point or state selector within --report (e.g. '3,0', 'w[11]', '#1', or state identity).",
    )
    parser.add_argument(
        "--state",
        help="State identity (full 64-character hex or unique prefix) from recovery_state_search.",
    )
    parser.add_argument(
        "--reproduction",
        help="SARIF reproduction block (or SARIF point/result JSON) as inline JSON or file path.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        help="Profile YAML path (optional when --report records profile_path).",
    )
    parser.add_argument(
        "--elf",
        type=Path,
        help="Override bootloader ELF path.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output directory or .tar.gz archive path.",
    )
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Write a .tar.gz archive instead of a plain directory.",
    )
    parser.add_argument(
        "--renode-test",
        default=DEFAULT_RENODE_TEST,
        help="Path to renode-test executable used to rebuild state if needed.",
    )
    parser.add_argument(
        "--renode-version",
        help="Explicit Renode version to record in the bundle (auto-detected by default).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Wall-clock timeout in seconds for state reconstruction (default: 300).",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository or runtime root directory.",
    )
    return parser


def _parse_export_args(
    parser: argparse.ArgumentParser,
    argv: list[str] | None,
) -> argparse.Namespace:
    args = parser.parse_args(argv)
    pos = list(args.positional or ())
    if pos:
        if args.report is None and args.reproduction is None:
            args.report = Path(pos.pop(0))
        if pos and args.point is None and args.state is None:
            args.point = str(pos.pop(0))
        if pos and args.output is None:
            args.output = Path(pos.pop(0))
        if pos:
            raise ExportReproError(f"unexpected positional arguments: {' '.join(pos)}")
    return args


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    parser = build_arg_parser(prog=prog)
    try:
        args = _parse_export_args(parser, argv)
        out_path = export_reproducer(
            report=args.report,
            point=args.point,
            state=args.state,
            reproduction=args.reproduction,
            profile=args.profile,
            elf=args.elf,
            output=args.output,
            archive=args.archive,
            renode_test=args.renode_test,
            renode_version=args.renode_version,
            timeout=args.timeout,
            repo_root=args.repo_root,
        )
        print(str(out_path), flush=True)
        return 0
    except (ExportReproError, DebugError, OSError, ValueError, RuntimeError) as exc:
        prefix = prog or parser.prog
        parser.exit(2, f"{prefix}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
