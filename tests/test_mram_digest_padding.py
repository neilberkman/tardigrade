#!/usr/bin/env python3
"""Tests for short-image digest padding, memory.erase_fill, and runtime EraseFill checks."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RUNTIME_SCRIPT = SCRIPTS / "run_runtime_fault_sweep.py"
SELF_UPDATE_DIR = ROOT / "examples" / "runtime_self_update"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import ProfileError, load_profile  # noqa: E402
from sweep import _build_mcuboot_state_slot_config  # noqa: E402
from trigger_discovery import _image_digest_for_evidence  # noqa: E402
from writeback_reconstruction import (  # noqa: E402
    reconstruct_committed_snapshot,
    validate_erase_trace_data,
    validate_write_trace_width,
)


def _runtime_functions(*names: str, globals_dict=None) -> dict:
    tree = ast.parse(
        RUNTIME_SCRIPT.read_text(encoding="utf-8"), filename=str(RUNTIME_SCRIPT)
    )
    wanted = set(names)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    missing = wanted - {node.name for node in selected}
    assert not missing, f"missing runtime functions: {sorted(missing)}"
    namespace = dict(globals_dict or {})
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(RUNTIME_SCRIPT), "exec"),
        namespace,
        namespace,
    )
    return namespace


def _write_mram_repl(
    directory: Path,
    *,
    backend_name: str = "mram",
    erase_fill: int = 0xFF,
) -> Path:
    repl_path = directory / "platform.repl"
    repl_path.write_text(
        textwrap.dedent(
            f"""\
            cpu: CPU.CortexM @ sysbus
                cpuType: "cortex-m0+"
                nvic: nvic

            nvic: IRQControllers.NVIC @ sysbus 0xE000E000
                -> cpu@0

            boot: Memory.MappedMemory @ sysbus 0x00000000
                size: 0x1000

            mramStorage: Memory.MappedMemory @ sysbus 0x10100000
                size: 0x3000

            {backend_name}: Miscellaneous.MappedMRAMTracker @ sysbus 0x40000000
                BackingMemory: mramStorage
                FlashBaseAddress: 0x10100000
                FlashSize: 0x3000
                ProgramUnitSize: 16
                EraseFill: 0x{erase_fill:02X}

            sram: Memory.MappedMemory @ sysbus 0x20000000
                size: 0x2000
            """
        ),
        encoding="utf-8",
    )
    return repl_path


def _write_profile(
    directory: Path,
    *,
    platform_ref: str,
    flash_backend: str,
    exec_image: Path,
    staging_image: Path,
    slot_size: int = 0x2000,
    page_size: int | None = None,
    erase_fill_yaml: str | None = None,
    evaluation_mode: str = "execute",
    filename: str = "profile.yaml",
) -> Path:
    lines = [
        "schema_version: 1",
        f"name: digest_pad_{flash_backend}",
        f"platform: {platform_ref}",
        f"flash_backend: {flash_backend}",
        "bootloader:",
        "  elf: examples/vulnerable_ota/firmware.elf",
        "  entry: 0x00000000",
        "memory:",
        "  sram: { start: 0x20000000, end: 0x20002000 }",
        "  write_granularity: 16",
    ]
    if page_size is not None:
        lines.append(f"  page_size: 0x{page_size:X}")
    if erase_fill_yaml is not None:
        lines.append(f"  erase_fill: {erase_fill_yaml}")
    lines.extend(
        [
            "  slots:",
            f"    exec: {{ base: 0x10100000, size: 0x{slot_size:X} }}",
            f"    staging: {{ base: 0x{0x10100000 + slot_size:X}, size: 0x{slot_size:X} }}",
            "images:",
            f"  exec: {exec_image.name}",
            f"  staging: {staging_image.name}",
            "success_criteria:",
            "  pc_in_slot: exec",
            "  image_hash: true",
            "  image_hash_slot: exec",
            "  allowed_images: [exec, staging]",
            "fault_sweep:",
            "  mode: runtime",
            f"  evaluation_mode: {evaluation_mode}",
            "  max_writes: auto",
            "",
        ]
    )
    profile_path = directory / filename
    profile_path.write_text("\n".join(lines), encoding="utf-8")
    return profile_path


@pytest.mark.parametrize("backend_name", ["mram", "mramTracker", "faultFlash"])
@pytest.mark.parametrize("erase_fill", [0xFF, 0x00, 0x5A])
def test_memory_erase_fill_sets_pad_byte_in_loader_sweep_and_discovery(
    tmp_path: Path, backend_name: str, erase_fill: int
) -> None:
    """Explicit memory.erase_fill controls digest padding across loader, sweep, and discovery."""
    exec_img = tmp_path / "old.bin"
    staging_img = tmp_path / "update.bin"
    exec_img.write_bytes(b"\x11" * 512)
    staging_img.write_bytes(b"\x22" * 512)

    platform_ref = (
        "platforms/cortex_m4_flash_fast.repl"
        if backend_name == "faultFlash"
        else "platforms/cortex_m0_self_update.repl"
    )
    profile_path = _write_profile(
        tmp_path,
        platform_ref=platform_ref,
        flash_backend=backend_name,
        exec_image=exec_img,
        staging_image=staging_img,
        slot_size=0x2000,
        page_size=0x1000,
        erase_fill_yaml=f"0x{erase_fill:02X}",
    )
    profile = load_profile(profile_path, strict=True, repo_root=ROOT)

    assert profile.memory.erase_fill == erase_fill
    assert profile.image_pad_byte(ROOT) == erase_fill

    expected = hashlib.sha256(
        staging_img.read_bytes() + bytes([erase_fill]) * (0x1000 - 512)
    ).hexdigest()
    assert profile._compute_image_digests(ROOT, profile.images)["staging"] == expected
    assert _build_mcuboot_state_slot_config(profile, ROOT)["pad_byte"] == erase_fill
    assert _image_digest_for_evidence(profile, ROOT, "staging") == expected

    rv = profile.robot_vars(ROOT)
    assert f"IMAGE_PAD_BYTE:0x{erase_fill:02X}" in rv
    assert f"MEMORY_ERASE_FILL:0x{erase_fill:02X}" in rv


def test_naive_bare_copy_pad_byte_matches_nvm_backend_erase_fill() -> None:
    """The generic NVMemory backend erases to zero, so digest padding must too."""
    profile = load_profile(
        ROOT / "profiles/naive_bare_copy.yaml",
        strict=True,
        repo_root=ROOT,
    )

    assert profile.flash_backend == "nvm_ctrl"
    assert profile.memory.erase_fill == 0x00
    assert profile.image_pad_byte(ROOT) == profile.memory.erase_fill
    assert "MEMORY_ERASE_FILL:0x00" in profile.robot_vars(ROOT)


@pytest.mark.parametrize(
    "platform_ref,backend_name",
    [
        ("platforms/cortex_m0_mram.repl", "mram"),
        ("platforms/cortex_m0_self_update.repl", "mramTracker"),
    ],
)
def test_mram_backends_default_pad_byte_is_zero(
    tmp_path: Path, platform_ref: str, backend_name: str
) -> None:
    """Without memory.erase_fill, MRAM backends (including mramTracker) pad with 0x00."""
    exec_img = tmp_path / "old.bin"
    staging_img = tmp_path / "update.bin"
    exec_img.write_bytes(b"\x33" * 512)
    staging_img.write_bytes(b"\x44" * 512)

    profile_path = _write_profile(
        tmp_path,
        platform_ref=platform_ref,
        flash_backend=backend_name,
        exec_image=exec_img,
        staging_image=staging_img,
        slot_size=0x2000,
        page_size=None,
    )
    profile = load_profile(profile_path, strict=True, repo_root=ROOT)

    assert profile.memory.erase_fill is None
    assert profile.image_pad_byte(ROOT) == 0x00

    expected = hashlib.sha256(
        staging_img.read_bytes() + b"\x00" * (0x1000 - 512)
    ).hexdigest()
    assert profile._compute_image_digests(ROOT, profile.images)["staging"] == expected
    assert _build_mcuboot_state_slot_config(profile, ROOT)["pad_byte"] == 0x00
    assert _image_digest_for_evidence(profile, ROOT, "staging") == expected

    rv = profile.robot_vars(ROOT)
    assert "IMAGE_PAD_BYTE:0x00" in rv
    assert not any(v.startswith("MEMORY_ERASE_FILL:") for v in rv)


def test_non_mram_backends_default_pad_byte_is_ff(tmp_path: Path) -> None:
    """Without memory.erase_fill, non-MRAM backends still pad with 0xFF."""
    exec_img = tmp_path / "old.bin"
    staging_img = tmp_path / "update.bin"
    exec_img.write_bytes(b"\x12" * 512)
    staging_img.write_bytes(b"\x34" * 512)

    # Also verify a directory path containing "mram" does not misclassify a non-MRAM platform.
    mram_named_dir = tmp_path / "mram-checkout"
    mram_named_dir.mkdir()
    plain_repl = mram_named_dir / "flash_only.repl"
    plain_repl.write_text("faultFlash: Miscellaneous.NRF52NVMC @ sysbus 0x4001E000\n", encoding="utf-8")

    cases = (
        ("platforms/cortex_m4_flash_fast.repl", "faultFlash", "execute"),
        ("platforms/cortex_m0_nvm.repl", "nvm_ctrl", "state"),
        (str(plain_repl), "customFlash", "execute"),
    )
    expected = hashlib.sha256(
        staging_img.read_bytes() + b"\xFF" * (0x1000 - 512)
    ).hexdigest()

    for idx, (platform_ref, backend_name, eval_mode) in enumerate(cases):
        profile_path = _write_profile(
            tmp_path,
            platform_ref=platform_ref,
            flash_backend=backend_name,
            exec_image=exec_img,
            staging_image=staging_img,
            slot_size=0x2000,
            page_size=None,
            evaluation_mode=eval_mode,
            filename=f"non_mram_{idx}.yaml",
        )
        profile = load_profile(profile_path, repo_root=ROOT)
        assert profile.image_pad_byte(ROOT) == 0xFF
        assert profile._compute_image_digests(ROOT, profile.images)["staging"] == expected
        assert _build_mcuboot_state_slot_config(profile, ROOT)["pad_byte"] == 0xFF
        assert _image_digest_for_evidence(profile, ROOT, "staging") == expected


@pytest.mark.parametrize("bad_value", ["0x100", "-1", "true", '"bad"'])
def test_memory_erase_fill_rejects_invalid_values(tmp_path: Path, bad_value: str) -> None:
    exec_img = tmp_path / "old.bin"
    staging_img = tmp_path / "update.bin"
    exec_img.write_bytes(b"\x10" * 64)
    staging_img.write_bytes(b"\x20" * 64)

    profile_path = _write_profile(
        tmp_path,
        platform_ref="platforms/cortex_m0_mram.repl",
        flash_backend="mram",
        exec_image=exec_img,
        staging_image=staging_img,
        erase_fill_yaml=bad_value,
    )
    with pytest.raises(ProfileError, match=r"memory\.erase_fill"):
        load_profile(profile_path, repo_root=ROOT)


@pytest.mark.parametrize("erase_fill", [0xFF, 0x00, 0x5A])
def test_writeback_reconstruction_uses_memory_erase_fill(erase_fill: int) -> None:
    """Writeback snapshot reconstruction pads erases with memory.erase_fill when set."""
    ns = _runtime_functions(
        "_runtime_erase_fill_byte",
        "_writeback_trace_width_is_safe",
        "writeback_strip_uncommitted_from_snapshot",
        globals_dict={
            "backend": {"kind": "mram", "data": SimpleNamespace(EraseFill=erase_fill)},
            "memory_erase_fill": erase_fill,
            "image_pad_byte": erase_fill,
            "writeback_capacity": lambda: 1,
            "_writeback_barriers": (),
            "writeback_erase_flushes": False,
            "_writeback_snapshot_reconstruction_status": None,
            "_validated_writeback_trace": lambda td: validate_write_trace_width(
                td, legacy_width=None, baseline_size=16, snapshot_size=16
            ),
            "_validated_erase_trace": lambda et, require_replay_metadata=False: validate_erase_trace_data(
                et, flash_size=16, page_size=4, require_monotonic=True
            ),
            "reconstruct_committed_snapshot": reconstruct_committed_snapshot,
            "log": lambda _msg: None,
        },
    )
    baseline = bytes([0xAA] * 16)
    trace = [(1, 0, 0x11223344, 4)]
    erases = [(0, 0, 4)]
    committed, discarded = ns["writeback_strip_uncommitted_from_snapshot"](
        baseline, trace, erases, 1, 0x10100000, 4, initial_snapshot=baseline
    )
    assert discarded == 1
    assert committed[:4] == bytes([erase_fill] * 4)
    assert committed[4:] == bytes([0xAA] * 12)


def test_runtime_validate_image_pad_byte_checks_live_erase_fill() -> None:
    """Runtime validation stops with a clear error naming memory.erase_fill and both values."""

    def _run_check(
        *,
        pad: int | None,
        explicit: int | None,
        live_fill: int,
        kind: str = "mram",
        backend_name: str = "sysbus.mram",
        eval_mode: str = "execute",
        img_hash: bool = True,
        wb_active: bool = False,
    ) -> list[str]:
        logs: list[str] = []
        ns = _runtime_functions(
            "_validate_image_pad_byte",
            globals_dict={
                "image_pad_byte": pad,
                "memory_erase_fill": explicit,
                "backend": {
                    "kind": kind,
                    "backend_sysbus_name": backend_name,
                    "data": SimpleNamespace(EraseFill=live_fill),
                },
                "evaluation_mode": eval_mode,
                "success_image_hash": img_hash,
                "update_sequence_phases": [],
                "writeback_active": lambda: wb_active,
                "log": logs.append,
            },
        )
        ns["_validate_image_pad_byte"]()
        return logs

    # Matching values pass.
    _run_check(pad=0x00, explicit=None, live_fill=0x00)
    _run_check(pad=0xFF, explicit=0xFF, live_fill=0xFF)
    _run_check(pad=0xFF, explicit=None, live_fill=0xFF, kind="fast", backend_name="sysbus.faultFlash")

    # MRAM default 0x00 vs live EraseFill 0xFF raises naming memory.erase_fill and both values.
    with pytest.raises(RuntimeError) as exc_info:
        _run_check(pad=0x00, explicit=None, live_fill=0xFF, backend_name="sysbus.mram")
    msg = str(exc_info.value)
    assert "memory.erase_fill" in msg
    assert "0x00" in msg
    assert "0xFF" in msg

    # Explicit memory.erase_fill conflicting with live EraseFill raises naming memory.erase_fill and both values.
    with pytest.raises(RuntimeError) as exc_info:
        _run_check(pad=0xFF, explicit=0xFF, live_fill=0x00, backend_name="sysbus.mramTracker")
    msg = str(exc_info.value)
    assert "memory.erase_fill" in msg
    assert "0xFF" in msg
    assert "0x00" in msg

    # Legacy slow backend in state mode without explicit memory.erase_fill stays allowed;
    # execute mode with image_hash enabled (or explicit memory.erase_fill) stops loudly.
    _run_check(
        pad=0xFF, explicit=None, live_fill=0x00,
        kind="slow", backend_name="sysbus.nvm_ctrl", eval_mode="state", img_hash=True,
    )
    with pytest.raises(RuntimeError, match=r"memory\.erase_fill"):
        _run_check(
            pad=0xFF, explicit=None, live_fill=0x00,
            kind="slow", backend_name="sysbus.nvm_ctrl", eval_mode="execute", img_hash=True,
        )
    with pytest.raises(RuntimeError, match=r"memory\.erase_fill"):
        _run_check(
            pad=0xFF, explicit=0xFF, live_fill=0x00,
            kind="slow", backend_name="sysbus.nvm_ctrl", eval_mode="state", img_hash=False,
        )


def _find_renode_test() -> str | None:
    env_path = os.environ.get("RENODE_TEST")
    if env_path and Path(env_path).is_file():
        return env_path
    found = shutil.which("renode-test")
    if found:
        return found
    app_path = Path("/Applications/Renode.app/Contents/MacOS/renode-test")
    if app_path.is_file():
        return str(app_path)
    return None


def _build_short_self_update_fixture(
    td_path: Path,
    *,
    backend_name: str,
    erase_fill: int,
    profile_erase_fill: int | None,
) -> Path:
    subprocess.run(["make", "-C", str(SELF_UPDATE_DIR), "all"], cwd=ROOT, check=True)
    rel_dir = td_path.relative_to(ROOT)

    old_short = td_path / "old_short.bin"
    update_short = td_path / "update_short.bin"
    for elf_name, out_bin in (("old.elf", old_short), ("update.elf", update_short)):
        subprocess.run(
            ["arm-none-eabi-objcopy", "-O", "binary", str(SELF_UPDATE_DIR / elf_name), str(out_bin)],
            check=True,
        )
        assert len(out_bin.read_bytes()) < 0x1000

    _write_mram_repl(td_path, backend_name=backend_name, erase_fill=erase_fill)
    profile_text = textwrap.dedent(
        f"""\
        schema_version: 1
        name: mram_short_image_{backend_name}_{erase_fill:02x}
        platform: {rel_dir}/platform.repl
        bootloader:
          elf: examples/runtime_self_update/boot.elf
          entry: 0x00000000
        bootloader_region: {{ base: 0x00000000, size: 0x1000 }}
        memory:
          sram: {{ start: 0x20000000, end: 0x20002000 }}
          volatile_regions:
            - {{ name: runtime_sram, base: 0x20000000, size: 0x2000 }}
          write_granularity: 16
          page_size: 0x1000
          trace_address_map:
            - {{ offset_start: 0x0, offset_end: 0x3000, address_addend: 0x10100000 }}
          slots:
            exec: {{ base: 0x10100000, size: 0x1000 }}
            staging: {{ base: 0x10101000, size: 0x1000 }}
        images:
          exec: {rel_dir}/old_short.bin
          staging: {rel_dir}/update_short.bin
        pre_boot_state:
          - {{ address: 0x10102000, u32: 1 }}
        flash_backend: {backend_name}
        success_criteria:
          pc_in_slot: exec
          image_hash: true
          image_hash_slot: exec
          allowed_images: [exec, staging]
          terminal_after_reset: true
          memory_checks:
            - {{ address: 0x20000200, expected_value: 1, op: eq }}
            - {{ address: 0x20000204, expected_value: 1, op: ge }}
        fault_sweep:
          mode: runtime
          evaluation_mode: execute
          fault_types: [power_loss]
          max_writes: auto
          max_writes_cap: 4096
          sweep_strategy: exhaustive
          run_duration: "0.2"
          calibration_time_slice: "0.01"
          progress_stall_timeout_s: 0.2
          tracking_start_address: 0x20000400
          calibration_stop:
            address: 0x20000480
            success_criteria: true
        expect:
          should_find_issues: true
        """
    )
    if profile_erase_fill is not None:
        profile_text = profile_text.replace(
            "  page_size: 0x1000\n",
            f"  page_size: 0x1000\n  erase_fill: 0x{profile_erase_fill:02X}\n",
            1,
        )
    profile_path = td_path / "profile.yaml"
    profile_path.write_text(profile_text, encoding="utf-8")
    return rel_dir / "profile.yaml"


@pytest.mark.parametrize(
    "backend_name,erase_fill,profile_erase_fill",
    [
        ("mram", 0xFF, 0xFF),
        ("mram", 0x00, None),
        ("mramTracker", 0x00, None),
        ("mramTracker", 0xFF, 0xFF),
    ],
)
def test_renode_e2e_short_mram_self_update_clean_control(
    backend_name: str, erase_fill: int, profile_erase_fill: int | None
) -> None:
    """Real Renode clean control with a short image (< slot size) and MRAM EraseFill 0xFF/0x00."""
    renode_test = _find_renode_test()
    if renode_test is None:
        pytest.skip("renode-test is not installed")
    if shutil.which("arm-none-eabi-gcc") is None or shutil.which("arm-none-eabi-objcopy") is None:
        pytest.skip("arm-none-eabi toolchain is not installed")

    results_root = ROOT / "results"
    results_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=results_root, prefix=f"mram_pad_{backend_name}_{erase_fill:02x}_"
    ) as td:
        td_path = Path(td)
        rel_profile = _build_short_self_update_fixture(
            td_path,
            backend_name=backend_name,
            erase_fill=erase_fill,
            profile_erase_fill=profile_erase_fill,
        )
        output_path = td_path / "control.json"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests" / "run_runtime_self_update_control.py"),
                "--profile",
                str(rel_profile),
                "--renode-test",
                renode_test,
                "--output",
                str(output_path),
            ],
            cwd=ROOT,
            check=True,
        )
        result = json.loads(output_path.read_text(encoding="utf-8"))
        signals = result.get("signals") or {}
        assert result.get("boot_outcome") == "success", result
        assert signals.get("matched_image") == "staging", signals
        assert signals.get("phase1_stop_reason") == "success_terminal_after_reset", signals


def test_renode_e2e_runtime_erase_fill_mismatch_stops_with_error() -> None:
    """Real Renode run stops before loading images when pad byte disagrees with live EraseFill."""
    renode_test = _find_renode_test()
    if renode_test is None:
        pytest.skip("renode-test is not installed")
    if shutil.which("arm-none-eabi-gcc") is None or shutil.which("arm-none-eabi-objcopy") is None:
        pytest.skip("arm-none-eabi toolchain is not installed")

    results_root = ROOT / "results"
    results_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=results_root, prefix="mram_pad_mismatch_") as td:
        td_path = Path(td)
        rel_profile = _build_short_self_update_fixture(
            td_path,
            backend_name="mram",
            erase_fill=0xFF,
            profile_erase_fill=None,
        )
        output_path = td_path / "control.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests" / "run_runtime_self_update_control.py"),
                "--profile",
                str(rel_profile),
                "--renode-test",
                renode_test,
                "--output",
                str(output_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0, "expected runtime mismatch to abort before loading images"
        assert not output_path.exists()
        combined = proc.stdout + "\n" + proc.stderr
        assert "memory.erase_fill" in combined, combined
        assert "0x00" in combined, combined
        assert "0xFF" in combined, combined
