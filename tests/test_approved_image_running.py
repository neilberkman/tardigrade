#!/usr/bin/env python3
"""Tests for success_criteria.approved_image_running and failure-shape audit."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "scripts" / "run_runtime_fault_sweep.py"
sys.path.insert(0, str(ROOT / "scripts"))

from audit_report import summarize_runtime_sweep  # noqa: E402
from boundary_reserved import BOUNDARY_RESERVED_VARIABLES  # noqa: E402
from fault_classification import (  # noqa: E402
    _expected_boot_slot,
    classify_failure_class,
    result_issue_reasons,
)
from profile_loader import (  # noqa: E402
    DEFAULT_APPROVED_IMAGE_DWELL_S,
    MCUBOOT_IMAGE_MAGIC,
    MCUBOOT_TLV_INFO_MAGIC,
    MCUBOOT_TLV_PROT_INFO_MAGIC,
    ProfileError,
    image_executable_extent,
    load_profile,
)
from result_checks import annotate_result_checks  # noqa: E402
from sweep import (  # noqa: E402
    _select_mcuboot_state_evaluator_points,
    _validate_runtime_control_result,
    validate_runtime_fault_mode_compat,
)


class _Event:
    def __init__(self) -> None:
        self._handlers = []

    def __iadd__(self, handler):
        self._handlers.append(handler)
        return self

    def __isub__(self, handler):
        if handler in self._handlers:
            self._handlers.remove(handler)
        return self

    def fire(self, *args) -> None:
        for handler in list(self._handlers):
            handler(*args)


class _VirtualTime:
    def __init__(self, seconds: float = 0.0) -> None:
        self.seconds = float(seconds)

    @property
    def TimeElapsed(self):
        return SimpleNamespace(
            TotalMicroseconds=int(round(self.seconds * 1_000_000)),
            TotalSeconds=self.seconds,
        )


def _build_mcuboot_image(
    *,
    hdr_size: int = 0x200,
    img_size: int = 0x1000,
    protect_tlv_size: int = 0x40,
    unprot_tlv_size: int = 0x140,
    sp: int = 0x20004000,
    reset_vector: int = 0x0000C221,
    body_fill: int = 0xA5,
) -> bytes:
    assert hdr_size >= 32
    assert img_size >= 16
    hdr = bytearray(b"\x00" * hdr_size)
    struct.pack_into(
        "<IIHHI",
        hdr,
        0,
        MCUBOOT_IMAGE_MAGIC,
        0,
        hdr_size,
        protect_tlv_size,
        img_size,
    )
    body = bytearray([body_fill & 0xFF]) * img_size
    struct.pack_into("<II", body, 0, sp, reset_vector)
    # Put valid HardFault and BusFault vectors at +12 and +20 inside the body.
    struct.pack_into("<I", body, 12, (reset_vector & ~0xFF) | 0x81)
    struct.pack_into("<I", body, 20, (reset_vector & ~0xFF) | 0x91)
    tlvs = bytearray()
    if protect_tlv_size:
        assert protect_tlv_size >= 4
        prot = bytearray(b"\x11" * protect_tlv_size)
        struct.pack_into("<HH", prot, 0, MCUBOOT_TLV_PROT_INFO_MAGIC, protect_tlv_size)
        tlvs.extend(prot)
    assert unprot_tlv_size >= 4
    unprot = bytearray(b"\x22" * unprot_tlv_size)
    struct.pack_into("<HH", unprot, 0, MCUBOOT_TLV_INFO_MAGIC, unprot_tlv_size)
    tlvs.extend(unprot)
    return bytes(hdr + body + tlvs)


def _load_runtime_functions(*names: str, extra_namespace: dict | None = None) -> dict:
    tree = ast.parse(RUNTIME.read_text(encoding="utf-8"), filename=str(RUNTIME))
    wanted = set(names)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    found = {node.name for node in selected}
    missing = wanted - found
    assert not missing, f"missing runtime functions: {sorted(missing)}"
    namespace = dict(extra_namespace or {})
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(RUNTIME), "exec"),
        namespace,
        namespace,
    )
    return namespace


def _build_runtime_harness(
    *,
    step_fn=None,
    slot_base: int = 0x0000C000,
    slot_size: int = 0x4000,
    initial_vtor: int = 0x0000C200,
    initial_pc: int = 0x0000C221,
    success_vtor_slot: str = "exec",
    success_vector_offset: int = 0,
    success_pc_slot: str | None = None,
    success_image_hash: bool = False,
    expected_exec_sha256: str = "",
    image_exec_sha256: str = "",
    image_staging_sha256: str = "",
    allowed_image_hashes: list[dict] | None = None,
    approved_image_running_config: dict | None = None,
    max_reset_vector_offset: int | None = None,
    slot_hash_fn=None,
    uncorrectable_words: list[str] | None = None,
    terminal_after_reset: bool = False,
    vector_sp: int = 0x20004000,
    vector_reset: int = 0x0000C221,
    vector_hardfault: int = 0x0000C281,
    vector_busfault: int = 0x0000C291,
):
    sticky_vtor = {"captured": False, "value": 0, "slot": None}
    sticky_pc = {"captured": False, "value": 0, "slot": None}
    slot_ranges = {
        "exec": (slot_base, slot_base + slot_size),
        "staging": (slot_base + slot_size, slot_base + 2 * slot_size),
    }
    state = {
        "run_calls": 0,
        "run_durations": [],
        "instructions": 0,
        "pc": initial_pc,
        "vtor": initial_vtor,
        "ipsr": 0,
        "cfsr": 0,
        "hfsr": 0,
        "pending_irq": 528,
        "writes": 0,
        "erases": 0,
        "locked_up": False,
        "hooks": {},
        "irq_hooks": [],
        "virtual_time": _VirtualTime(0.0),
        "vector_sp": vector_sp,
        "vector_reset": vector_reset,
        "vector_hardfault": vector_hardfault,
        "vector_busfault": vector_busfault,
        "mem": {},
    }

    class FakeNvic:
        @staticmethod
        def FindPendingInterrupt():
            return state["pending_irq"]

    class FakeCpu:
        IsHalted = False
        Model = "cortex-m4"

        @property
        def IsLockedUp(self):
            return bool(state["locked_up"])

        @property
        def ExecutedInstructions(self):
            return state["instructions"]

        @property
        def PC(self):
            return state["pc"]

        @property
        def XProgramStatusRegister(self):
            return state["ipsr"]

        @staticmethod
        def GetRegisterUnsafe(_index):
            return state["pc"]

        @staticmethod
        def AddHook(address, callback):
            state["hooks"][address] = callback

        @staticmethod
        def RemoveHook(address, callback):
            if state["hooks"].get(address) is callback:
                del state["hooks"][address]

        def AddHookAtInterruptBegin(self, callback):
            state["irq_hooks"].append(callback)

    cpu = FakeCpu()
    nvic = FakeNvic()

    class FakeMachine:
        def __init__(self) -> None:
            self.MachineReset = _Event()
            self.PeripheralReset = _Event()

        def __getitem__(self, name: str):
            if name in ("sysbus.cpu", "cpu"):
                return cpu
            if name in ("sysbus.nvic", "nvic"):
                return nvic
            raise KeyError(name)

        @property
        def ElapsedVirtualTime(self):
            return state["virtual_time"]

    machine = FakeMachine()

    class FakeBus:
        @staticmethod
        def ReadDoubleWord(address):
            addr = int(address)
            if addr == 0xE000ED08:
                return state["vtor"]
            if addr == 0xE000ED28:
                return state["cfsr"]
            if addr == 0xE000ED2C:
                return state["hfsr"]
            if addr == 0x00000004:
                return 0x00000021
            for vbase in (slot_base, slot_base + 0x200, state["vtor"]):
                if addr == vbase:
                    return state["vector_sp"]
                if addr == vbase + 4:
                    return state["vector_reset"]
                if addr == vbase + 12:
                    return state["vector_hardfault"]
                if addr == vbase + 20:
                    return state["vector_busfault"]
            return state["mem"].get(addr, 0)

        @staticmethod
        def WriteDoubleWord(address, value):
            state["mem"][int(address)] = int(value) & 0xFFFFFFFF

        @staticmethod
        def ReadWord(_address):
            return 0

    def fire_fault(exc_num: int, *, set_cfsr: int = 0, set_hfsr: int = 0) -> None:
        state["pending_irq"] = exc_num
        for cb in list(state["irq_hooks"]):
            cb(5)
        state["ipsr"] = exc_num
        if set_cfsr:
            state["cfsr"] |= set_cfsr
        if set_hfsr:
            state["hfsr"] |= set_hfsr

    class FakeMonitor:
        Machine = machine

        @staticmethod
        def Parse(command):
            state["run_calls"] += 1
            parts = str(command).split('"')
            dur = float(parts[1]) if len(parts) >= 2 else 0.05
            state["run_durations"].append(dur)
            state["virtual_time"].seconds += dur
            state["instructions"] += 100
            if step_fn is not None:
                step_fn(state, machine, cpu, fire_fault, dur)

    def capture_sticky_pc(value):
        pc = int(value) & ~1
        for s_name, (s_lo, s_hi) in slot_ranges.items():
            if s_lo <= pc < s_hi:
                sticky_pc.update(captured=True, value=pc, slot=s_name)
                break

    ns = _load_runtime_functions(
        "_normalize_approved_image_running_config",
        "_resolve_effective_approved_image_running",
        "_classify_pc_in_approved_slot",
        "_evaluate_approved_image_digest",
        "_evaluate_approved_image_extent",
        "_evaluate_approved_image_running",
        "_match_configured_image_hash",
        "evaluate_structured_success_checks",
        "collect_recovery_execution_evidence",
        "recovery_failure_outcome",
        "evaluate_boot_outcome",
        "_calibration_success_stop_observation",
        "_reset_gated_success_stop_observation",
        "_dispatch_interrupt_begin",
        "_ensure_interrupt_begin_hook",
        "run_until_done",
        "run_state_fault",
        extra_namespace={
            "DEFAULT_APPROVED_IMAGE_DWELL_S": DEFAULT_APPROVED_IMAGE_DWELL_S,
            "os": __import__("os"),
            "re": __import__("re"),
            "_interrupt_begin_hook_cpus": [],
            "_active_interrupt_begin_observer": [None],
            "_time": SimpleNamespace(time=lambda: 0.0),
            "phase1_time_slice": "0.05",
            "success_vtor_slot": success_vtor_slot,
            "success_vector_offset": success_vector_offset,
            "success_pc_slot": success_pc_slot,
            "success_image_hash": success_image_hash,
            "success_image_hash_slot": "exec",
            "success_terminal_after_reset": terminal_after_reset,
            "success_allow_fault_after_success": False,
            "success_marker_addr": 0,
            "success_marker_value": 0,
            "success_checks_config": {},
            "success_checks_parse_error": None,
            "success_otadata_expect": {},
            "success_otadata_expect_scope": "always",
            "security_anti_rollback": False,
            "max_reset_vector_offset": max_reset_vector_offset,
            "allowed_image_hashes": list(allowed_image_hashes or []),
            "approved_image_running_config": approved_image_running_config,
            "expected_exec_sha256": expected_exec_sha256,
            "expected_image_name": "staging",
            "image_exec_sha256": image_exec_sha256,
            "image_staging_sha256": image_staging_sha256,
            "slot_ranges": slot_ranges,
            "slot_exec_base": slot_base,
            "slot_exec_size": slot_size,
            "slot_staging_base": slot_base + slot_size,
            "total_copy_writes": 4,
            "write_granularity": 4,
            "backend": {"kind": "fast"},
            "boundary_setup_env": False,
            "boundary_durable_state_file": "",
            "boundary_phase": "",
            " sticky_vtor": sticky_vtor,
            "sticky_vtor": sticky_vtor,
            "sticky_pc": sticky_pc,
            "sram_start": 0x20000000,
            "sram_end": 0x20020000,
            "bootloader_entry": 0x00000000,
            "calibration_mode": False,
            "calibration_stop_on_success": False,
            "calibration_stop_address": 0,
            "_calibration_stop_state": {},
            "_recovery_zero_vector_guard": False,
            "progress_stall_timeout_s": 0.0,
            "expect_control_outcome": "success",
            "no_boot_zero_write_slices": 100,
            "no_boot_min_emulated_s": 10.0,
            "max_step_limit": 10_000_000,
            "wall_timeout": 300.0,
            "cpu": cpu,
            "bus": FakeBus(),
            "monitor": FakeMonitor(),
            "as_int": lambda value: int(value),
            "fmt_u32": lambda value: f"0x{int(value) & 0xFFFFFFFF:08X}",
            "log": lambda _msg: None,
            "get_total_writes": lambda: state["writes"],
            "get_total_erases": lambda: state["erases"],
            "check_console_fatal": lambda: None,
            "fault_requires_immediate_stop": lambda: False,
            "was_otp_fault_injected": lambda: False,
            "capture_sticky_pc": capture_sticky_pc,
            "capture_console_state": lambda include_recent=False: {
                "attached_names": [],
                "attached_count": 0,
                "last_line": None,
                "last_lines": [],
                "recent_logs": [],
            },
            "compute_slot_hash": slot_hash_fn or (lambda _slot: expected_exec_sha256),
            "resolve_slot_hash_extent": lambda _base, _size: (0x1380, "mcuboot_header"),
            "_mram_uncorrectable_words_in_range": (
                (lambda _lo, _hi: list(uncorrectable_words))
                if uncorrectable_words
                else None
            ),
            "collect_otadata_signals": lambda: {},
            "capture_boot_registers": lambda: None,
            "normalize_signal_token": lambda value: str(value or "").strip().lower(),
            "boot_outcome_after_stop": (
                lambda fallback, stop_reason: "timeout"
                if str(stop_reason).startswith(("wall_timeout", "instruction_limit"))
                or stop_reason == "budget"
                else fallback
            ),
            "add_boundary_contract_signals": lambda _s: None,
            "collect_semantic_state": lambda _d: None,
            "get_effective_criteria": lambda _ft: {},
            "classify_fault_result": lambda outcome, _slot, _sig, effective_criteria=None: outcome,
        },
    )
    return ns, state, machine, cpu, sticky_vtor, sticky_pc


def _write_test_profile(
    tmp_path: Path,
    *,
    exec_blob: bytes,
    staging_blob: bytes,
    evaluation_mode: str | None = "execute",
    success_criteria: dict,
    extra: dict | None = None,
) -> Path:
    repl = tmp_path / "platform.repl"
    repl.write_text(
        'cpu: CPU.CortexM @ sysbus\n    cpuType: "cortex-m4"\n'
        "flash: Memory.MappedMemory @ sysbus 0x00000000\n    size: 0x20000\n",
        encoding="utf-8",
    )
    boot_elf = tmp_path / "boot.elf"
    boot_elf.write_bytes(b"\x7fELFboot")
    exec_path = tmp_path / "app_v1.bin"
    staging_path = tmp_path / "app_v2.bin"
    exec_path.write_bytes(exec_blob)
    staging_path.write_bytes(staging_blob)

    raw_profile: dict = {
        "schema_version": 1,
        "name": "test_approved_image_running",
        "platform": {"repl": str(repl)},
        "bootloader": {"elf": str(boot_elf), "entry": 0x00000000},
        "images": {"exec": str(exec_path), "staging": str(staging_path)},
        "memory": {
            "sram": {"start": 0x20000000, "end": 0x20020000},
            "slots": {
                "exec": {"base": 0x0000C000, "size": 0x4000},
                "staging": {"base": 0x00010000, "size": 0x4000},
            },
        },
        "pre_boot_state": [{"address": 0x00013FF0, "u32": 0x12345678}],
        "fault_sweep": {},
        "success_criteria": success_criteria,
    }
    if evaluation_mode is not None:
        raw_profile["fault_sweep"]["evaluation_mode"] = evaluation_mode
    if extra:
        raw_profile.update(extra)
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(yaml.safe_dump(raw_profile), encoding="utf-8")
    return profile_path


# ---------------------------------------------------------------------------
# Step 1: Audit of existing criteria vs the 4 failure shapes
# ---------------------------------------------------------------------------


def test_audit_failure_shape_1_corrupted_mixed_image_with_intact_vector_table():
    """A mixed/corrupted slot image with an intact vector table passes vtor_in_slot
    and pc_in_slot in execute mode and passes state mode, is caught by image_hash in
    execute mode (not state mode), and is caught by approved_image_running (digest)."""
    good_sha = "11" * 32
    corrupted_sha = "99" * 32
    approved_cfg = {
        "slot": "exec",
        "slot_base": 0x0000C000,
        "slot_size": 0x4000,
        "dwell_s": 0.25,
        "images": [
            {
                "name": "staging",
                "sha256": good_sha,
                "code_offset": 0x200,
                "code_size": 0x1000,
                "code_start": 0x0000C200,
                "code_end": 0x0000D200,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1380,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1380,
            }
        ],
    }

    # 1a. Legacy vtor_in_slot + pc_in_slot without image_hash MISSES corrupted slot body.
    ns_legacy, _, _, _, sticky_vtor, sticky_pc = _build_runtime_harness(
        success_vtor_slot="exec",
        success_pc_slot="exec",
        success_image_hash=False,
        slot_hash_fn=lambda _slot: corrupted_sha,
    )
    sticky_vtor.update(captured=True, value=0x0000C200, slot="exec")
    sticky_pc.update(captured=True, value=0x0000C220, slot="exec")
    outcome, slot, _ = ns_legacy["evaluate_boot_outcome"](
        0x0000C200, 0x0000C221, p2_status={"reason": "vtor_captured"}
    )
    assert outcome == "success"
    assert slot == "exec"

    # 1b. Legacy state mode ALSO MISSES corrupted slot body (judges vector table only)
    # even when image_hash=True is configured.
    ns_state, _, _, _, _, _ = _build_runtime_harness(
        success_vtor_slot="exec",
        success_image_hash=True,
        expected_exec_sha256=good_sha,
        slot_hash_fn=lambda _slot: corrupted_sha,
    )
    state_res = ns_state["run_state_fault"](-1)
    assert state_res["boot_outcome"] == "success"

    # 1c. approved_image_running CATCHES it with failed_part == "digest".
    ns_app, _, _, _, sticky_vtor_app, _ = _build_runtime_harness(
        success_vtor_slot="exec",
        approved_image_running_config=approved_cfg,
        slot_hash_fn=lambda _slot: corrupted_sha,
    )
    sticky_vtor_app.update(captured=True, value=0x0000C200, slot="exec")
    outcome_app, _, sig_app = ns_app["evaluate_boot_outcome"](
        0x0000C200,
        0x0000C221,
        p2_status={"reason": "vtor_captured", "emulated_s": 0.30},
    )
    assert outcome_app == "wrong_image"
    assert sig_app["approved_image_running"]["ok"] is False
    assert sig_app["approved_image_running"]["failed_part"] == "digest"
    assert sig_app["approved_image_running"]["digest"]["observed_sha256"] == corrupted_sha


def test_audit_failure_shape_2_pc_in_leading_image_header():
    """PC executing in the leading MCUboot header [slot_base, slot_base + ih_hdr_size)
    is missed by vtor_in_slot + image_hash + pc_in_slot (without vector_table_offset),
    and caught by approved_image_running with failed_part == 'extent' (pc_location='header')."""
    good_sha = "22" * 32
    approved_cfg = {
        "slot": "exec",
        "slot_base": 0x0000C000,
        "slot_size": 0x4000,
        "dwell_s": 0.25,
        "images": [
            {
                "name": "staging",
                "sha256": good_sha,
                "code_offset": 0x200,
                "code_size": 0x1000,
                "code_start": 0x0000C200,
                "code_end": 0x0000D200,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1380,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1380,
            }
        ],
    }
    header_pc = 0x0000C041  # offset 0x40 inside the 0x200-byte MCUboot header

    # 2a. Legacy vtor_in_slot + pc_in_slot (no vector_table_offset) + image_hash MISSES header PC.
    ns_legacy, _, _, _, sticky_vtor, sticky_pc = _build_runtime_harness(
        success_vtor_slot="exec",
        success_pc_slot="exec",
        success_vector_offset=0,
        success_image_hash=True,
        expected_exec_sha256=good_sha,
        slot_hash_fn=lambda _slot: good_sha,
    )
    sticky_vtor.update(captured=True, value=0x0000C200, slot="exec")
    sticky_pc.update(captured=True, value=header_pc & ~1, slot="exec")
    outcome, _, _ = ns_legacy["evaluate_boot_outcome"](
        0x0000C200, header_pc, p2_status={"reason": "vtor_captured"}
    )
    assert outcome == "success"

    # 2b. approved_image_running CATCHES header PC automatically from ih_hdr_size.
    ns_app, _, _, _, sticky_vtor_app, _ = _build_runtime_harness(
        success_vtor_slot="exec",
        approved_image_running_config=approved_cfg,
        slot_hash_fn=lambda _slot: good_sha,
    )
    sticky_vtor_app.update(captured=True, value=0x0000C200, slot="exec")
    outcome_app, _, sig_app = ns_app["evaluate_boot_outcome"](
        0x0000C200, header_pc, p2_status={"reason": "vtor_captured", "emulated_s": 0.30}
    )
    assert outcome_app == "wrong_pc"
    verdict = sig_app["approved_image_running"]
    assert verdict["ok"] is False
    assert verdict["failed_part"] == "extent"
    assert verdict["extent"]["pc_location"] == "header"
    assert verdict["extent"]["expected_extent"] == ["0x0000C200", "0x0000D200"]


def test_audit_failure_shape_3_pc_past_executable_code_in_tlv_or_slot_tail():
    """PC executing past ih_hdr_size + ih_img_size in the TLV area or erased/stale
    slot tail is missed by vtor_in_slot, pc_in_slot (even with vector_table_offset),
    image_hash, and max_reset_vector_offset (when the reset vector itself is in bounds),
    and caught by approved_image_running with failed_part == 'extent'."""
    good_sha = "33" * 32
    approved_cfg = {
        "slot": "exec",
        "slot_base": 0x0000C000,
        "slot_size": 0x4000,
        "dwell_s": 0.25,
        "images": [
            {
                "name": "staging",
                "sha256": good_sha,
                "code_offset": 0x200,
                "code_size": 0x1000,
                "code_start": 0x0000C200,
                "code_end": 0x0000D200,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1380,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1380,
            }
        ],
    }

    for bad_pc, expected_loc in (
        (0x0000D241, "tlv"),        # inside TLV region [0xC000+0x1200, 0xC000+0x1380)
        (0x0000E101, "slot_tail"),  # inside stale/erased tail [0xC000+0x1380, 0x10000)
    ):
        # 3a. Legacy criteria (even with vector_table_offset=0x200, image_hash=True,
        # and max_reset_vector_offset=0x1200 when reset vector at VTOR+4 is 0x0000C221)
        # all MISS execution that lands in the TLV or slot tail!
        ns_legacy, _, _, _, sticky_vtor, sticky_pc = _build_runtime_harness(
            success_vtor_slot="exec",
            success_pc_slot="exec",
            success_vector_offset=0x200,
            success_image_hash=True,
            expected_exec_sha256=good_sha,
            max_reset_vector_offset=0x1200,
            slot_hash_fn=lambda _slot: good_sha,
        )
        sticky_vtor.update(captured=True, value=0x0000C200, slot="exec")
        sticky_pc.update(captured=True, value=bad_pc & ~1, slot="exec")
        outcome, _, _ = ns_legacy["evaluate_boot_outcome"](
            0x0000C200, bad_pc, p2_status={"reason": "vtor_captured"}
        )
        assert outcome == "success"

        # 3b. approved_image_running CATCHES both TLV and slot_tail PCs.
        ns_app, _, _, _, sticky_vtor_app, _ = _build_runtime_harness(
            success_vtor_slot="exec",
            approved_image_running_config=approved_cfg,
            slot_hash_fn=lambda _slot: good_sha,
        )
        sticky_vtor_app.update(captured=True, value=0x0000C200, slot="exec")
        outcome_app, _, sig_app = ns_app["evaluate_boot_outcome"](
            0x0000C200, bad_pc, p2_status={"reason": "vtor_captured", "emulated_s": 0.30}
        )
        assert outcome_app == "wrong_pc"
        verdict = sig_app["approved_image_running"]
        assert verdict["ok"] is False
        assert verdict["failed_part"] == "extent"
        assert verdict["extent"]["pc_location"] == expected_loc


def test_audit_failure_shape_4_post_handoff_crash_missed_by_legacy_5ms_settle():
    """When the CPU jumps into the image's code and faults after the legacy 5ms
    vtor_in_slot settle window (or after the 0ms pc_in_slot hook hit), legacy
    criteria stop early and report 'success', whereas approved_image_running
    continues for dwell_s (0.25s) and catches the fault with failed_part == 'dwell'."""
    good_sha = "44" * 32
    approved_cfg = {
        "slot": "exec",
        "slot_base": 0x0000C000,
        "slot_size": 0x4000,
        "dwell_s": 0.25,
        "images": [
            {
                "name": "staging",
                "sha256": good_sha,
                "code_offset": 0x200,
                "code_size": 0x1000,
                "code_start": 0x0000C200,
                "code_end": 0x0000D200,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1380,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1380,
            }
        ],
    }

    # Firmware faults at 0.10s of emulated execution (after the 50ms slice + 5ms settle).
    def step_fault_at_100ms(state, _machine, _cpu, fire_fault, _dur):
        if state["virtual_time"].seconds >= 0.10:
            fire_fault(3, set_cfsr=0x00020000, set_hfsr=0x40000000)

    # 4a. Legacy vtor_in_slot + image_hash stops after 1st slice (0.05s) + 0.005s settle (0.055s)
    # BEFORE the fault at 0.10s and falsely reports 'success'.
    ns_legacy, _, _, cpu_legacy, _, _ = _build_runtime_harness(
        step_fn=step_fault_at_100ms,
        success_vtor_slot="exec",
        success_image_hash=True,
        expected_exec_sha256=good_sha,
        slot_hash_fn=lambda _slot: good_sha,
    )
    p2_legacy = ns_legacy["run_until_done"](
        cpu_legacy,
        max_iters=20,
        expect_writes=False,
        zero_writes_is_brick=False,
        label="p2_legacy",
        time_slice="0.05",
    )
    assert p2_legacy["reason"] == "vtor_captured"
    outcome_legacy, _, _ = ns_legacy["evaluate_boot_outcome"](
        0x0000C200, cpu_legacy.PC, p2_status=p2_legacy
    )
    assert outcome_legacy == "success"

    # 4b. approved_image_running keeps running across the 0.25s dwell window,
    # observes the fault at 0.10s, and fails with failed_part == 'dwell'.
    ns_app, _, _, cpu_app, _, _ = _build_runtime_harness(
        step_fn=step_fault_at_100ms,
        success_vtor_slot="exec",
        approved_image_running_config=approved_cfg,
        slot_hash_fn=lambda _slot: good_sha,
    )
    p2_app = ns_app["run_until_done"](
        cpu_app,
        max_iters=20,
        expect_writes=False,
        zero_writes_is_brick=False,
        label="p2_approved",
        time_slice="0.05",
    )
    assert p2_app["reason"] == "approved_image_dwell_fault"
    outcome_app, _, sig_app = ns_app["evaluate_boot_outcome"](
        0x0000C200, cpu_app.PC, p2_status=p2_app
    )
    assert outcome_app == "hard_fault"
    verdict = sig_app["approved_image_running"]
    assert verdict["ok"] is False
    assert verdict["failed_part"] == "dwell"
    assert verdict["dwell"]["failure_reason"] == "fault_exception"
    assert verdict["dwell"]["observed_dwell_s"] == pytest.approx(0.05)


# ---------------------------------------------------------------------------
# Step 2: Executable extent computation & profile schema validation
# ---------------------------------------------------------------------------


def test_image_executable_extent_mcuboot_and_raw():
    mcuboot_blob = _build_mcuboot_image(
        hdr_size=0x200,
        img_size=0x1400,
        protect_tlv_size=0x40,
        unprot_tlv_size=0x140,
    )
    code_offset, code_size, source = image_executable_extent(mcuboot_blob, 0x4000)
    assert (code_offset, code_size, source) == (0x200, 0x1400, "mcuboot_header")

    raw_blob = b"\x00\x40\x00\x20\x21\xc0\x00\x00" + (b"\x90" * 300)
    raw_offset, raw_size, raw_source = image_executable_extent(raw_blob, 0x4000)
    assert (raw_offset, raw_size, raw_source) == (0, len(raw_blob), "artifact_size")

    with pytest.raises((ProfileError, ValueError), match="empty"):
        image_executable_extent(b"", 0x4000)

    with pytest.raises((ProfileError, ValueError), match="larger than its"):
        image_executable_extent(b"\x01" * 0x5000, 0x4000)

    # Corrupt MCUboot header (valid magic, truncated TLV) fails closed.
    bad_mcuboot = bytearray(mcuboot_blob[:0x200 + 0x100])
    with pytest.raises((ProfileError, ValueError), match="invalid executable payload extent"):
        image_executable_extent(bytes(bad_mcuboot), 0x4000)


def test_profile_loader_approved_image_running_mcuboot_and_offset_padded(tmp_path: Path):
    assert "APPROVED_IMAGE_RUNNING_B64" in BOUNDARY_RESERVED_VARIABLES
    exec_blob = _build_mcuboot_image(hdr_size=0x200, img_size=0x1000, body_fill=0x11)
    staging_inner = _build_mcuboot_image(hdr_size=0x200, img_size=0x1200, body_fill=0x22)
    # Offset-slot staging image prefixed with one 4KB erased sector of 0xFF.
    staging_padded = (b"\xff" * 0x1000) + staging_inner

    profile_path = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_padded,
        evaluation_mode="execute",
        success_criteria={
            "vtor_in_slot": "exec",
            "approved_image_running": {
                "slot": "exec",
                "images": ["exec", "staging"],
            },
        },
    )
    cfg = load_profile(profile_path)
    app = cfg.success_criteria.approved_image_running
    assert app is not None
    assert app.slot == "exec"
    assert app.images == ["exec", "staging"]
    assert app.dwell_s == pytest.approx(DEFAULT_APPROVED_IMAGE_DWELL_S)

    rv = cfg.robot_vars(tmp_path)
    encoded = next(
        item.split(":", 1)[1]
        for item in rv
        if item.startswith("APPROVED_IMAGE_RUNNING_B64:")
    )
    decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
    assert decoded["slot"] == "exec"
    assert decoded["slot_base"] == 0x0000C000
    assert decoded["slot_size"] == 0x4000
    assert decoded["dwell_s"] == pytest.approx(0.25)
    by_name = {entry["name"]: entry for entry in decoded["images"]}
    assert by_name["exec"]["code_offset"] == 0x200
    assert by_name["exec"]["code_size"] == 0x1000
    assert by_name["exec"]["code_start"] == 0x0000C200
    assert by_name["exec"]["code_end"] == 0x0000D200
    assert by_name["staging"]["code_offset"] == 0x200
    assert by_name["staging"]["code_size"] == 0x1200
    assert by_name["staging"]["code_start"] == 0x0000C200
    assert by_name["staging"]["code_end"] == 0x0000D400
    assert by_name["staging"]["sha256"] == hashlib.sha256(staging_inner).hexdigest()


def test_profile_loader_approved_image_running_validation_errors(tmp_path: Path):
    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)

    # Unknown image name (even when allowed_images is omitted)
    p_unknown_img = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["nonexistent"]}
        },
    )
    with pytest.raises((ProfileError, ValueError), match="approved_image_running.images='nonexistent'"):
        load_profile(p_unknown_img)

    # Unknown slot name
    p_unknown_slot = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "bogus_slot", "images": ["staging"]}
        },
    )
    with pytest.raises((ProfileError, ValueError), match="is not present in memory.slots"):
        load_profile(p_unknown_slot)

    # Indistinguishable digests in images list
    p_dup_digest = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=exec_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["exec", "staging"]}
        },
    )
    with pytest.raises((ProfileError, ValueError), match="indistinguishable approved content"):
        load_profile(p_dup_digest).robot_vars(tmp_path)

    # Invalid dwell_s <= 0
    p_bad_dwell = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {
                "slot": "exec",
                "images": ["staging"],
                "dwell_s": 0,
            }
        },
    )
    with pytest.raises((ProfileError, ValueError), match="expected positive number"):
        load_profile(p_bad_dwell)


# ---------------------------------------------------------------------------
# Step 3: State-mode rejection and no-evidence fail-closed checks
# ---------------------------------------------------------------------------


def test_state_mode_rejects_approved_image_running_everywhere(tmp_path: Path):
    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)

    # 1. Explicit evaluation_mode: state at profile load
    p_state = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="state",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    with pytest.raises((ProfileError, ValueError), match="evaluation_mode 'execute'"):
        load_profile(p_state)

    # 2. Omitted evaluation_mode (defaults to state) at profile load
    p_default_state = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode=None,
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    with pytest.raises((ProfileError, ValueError), match="evaluation_mode 'execute'"):
        load_profile(p_default_state)

    # 3. Execute profile overridden with --evaluation-mode state in sweep.py
    p_exec = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    cfg = load_profile(p_exec)
    with pytest.raises((ProfileError, RuntimeError, ValueError), match="evaluation_mode 'execute'"):
        validate_runtime_fault_mode_compat(cfg, "state")

    # 4. MCUboot fast state evaluator is disabled when approved_image_running is set
    assert (
        _select_mcuboot_state_evaluator_points(
            repo_root=tmp_path,
            profile=cfg,
            evaluation_mode="execute",
            fault_points=[1],
            fault_types_list=["w"],
            trace_file=None,
        )
        is None
    )

    # 5. Control validator rejects state-mode or missing-evidence control results
    cfg_state = SimpleNamespace(
        fault_sweep=SimpleNamespace(evaluation_mode="state"),
        success_criteria=cfg.success_criteria,
        expect=cfg.expect,
    )
    with pytest.raises(RuntimeError, match="requires evaluation_mode 'execute'"):
        _validate_runtime_control_result(
            cfg_state,
            {"fault_injected": False, "boot_outcome": "success", "boot_slot": "exec", "signals": {}},
        )
    with pytest.raises(RuntimeError, match="was not confirmed"):
        _validate_runtime_control_result(
            cfg,
            {"fault_injected": False, "boot_outcome": "success", "boot_slot": "exec", "signals": {}},
        )

    # 6. Runtime run_state_fault raises RuntimeError if invoked with approved_image_running
    ns, _, _, _, _, _ = _build_runtime_harness(
        approved_image_running_config={
            "slot": "exec",
            "slot_base": 0x0000C000,
            "slot_size": 0x4000,
            "dwell_s": 0.25,
            "images": [
                {
                    "name": "staging",
                    "sha256": "22" * 32,
                    "code_offset": 0x200,
                    "code_size": 0x1000,
                    "code_start": 0x0000C200,
                    "code_end": 0x0000D200,
                }
            ],
        }
    )
    with pytest.raises(RuntimeError, match="cannot run in evaluation_mode: state"):
        ns["run_state_fault"](-1)


# ---------------------------------------------------------------------------
# Step 4: Dwell timing and per-part failure records (digest, extent, dwell)
# ---------------------------------------------------------------------------


def _sample_approved_config(dwell_s: float = 0.25) -> dict:
    return {
        "slot": "exec",
        "slot_base": 0x0000C000,
        "slot_size": 0x4000,
        "dwell_s": dwell_s,
        "images": [
            {
                "name": "exec",
                "sha256": "aa" * 32,
                "code_offset": 0x200,
                "code_size": 0x1000,
                "code_start": 0x0000C200,
                "code_end": 0x0000D200,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1380,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1380,
            },
            {
                "name": "staging",
                "sha256": "bb" * 32,
                "code_offset": 0x200,
                "code_size": 0x1200,
                "code_start": 0x0000C200,
                "code_end": 0x0000D400,
                "extent_source": "mcuboot_header",
                "digest_extent": 0x1580,
                "digest_extent_source": "mcuboot_header",
                "artifact_size": 0x1580,
            },
        ],
    }


def test_approved_image_running_passes_after_full_dwell(tmp_path: Path):
    cfg_dict = _sample_approved_config(dwell_s=0.25)
    ns, state, _, cpu, _, _ = _build_runtime_harness(
        approved_image_running_config=cfg_dict,
        slot_hash_fn=lambda _slot: "bb" * 32,
    )
    p2_status = ns["run_until_done"](
        cpu,
        max_iters=20,
        expect_writes=False,
        zero_writes_is_brick=True,
        label="p2_pass",
        time_slice="0.05",
    )
    assert p2_status["reason"] == "vtor_captured"
    # Entry on slice 1 (0.05s) + 5 dwell slices of 0.05s = 6 slices (0.30s total, 0.25s dwell).
    assert state["run_calls"] == 6
    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x0000C200, cpu.PC, p2_status=p2_status
    )
    assert outcome == "success"
    assert slot == "exec"
    verdict = signals["approved_image_running"]
    assert verdict["ok"] is True
    assert verdict["failed_part"] is None
    assert verdict["matched_image"] == "staging"
    assert verdict["digest"]["ok"] is True
    assert verdict["extent"]["ok"] is True
    assert verdict["dwell"]["ok"] is True
    assert verdict["dwell"]["observed_dwell_s"] >= 0.25

    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)
    p_exec = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    cfg = load_profile(p_exec)
    point_res = {
        "fault_at": -1,
        "fault_injected": False,
        "boot_outcome": outcome,
        "boot_slot": slot,
        "signals": signals,
    }
    annotate_result_checks([point_res], cfg, repo_root=tmp_path)
    assert point_res["approved_image_running"]["ok"] is True
    assert point_res["approved_image_running"]["failed_part"] is None
    assert result_issue_reasons(point_res, "success") == []


@pytest.mark.parametrize(
    "failure_mode,expected_outcome,expected_dwell_reason",
    [
        ("lockup", "hard_fault", "lockup"),
        ("reset", "no_boot", "reset"),
        ("pc_exited_extent", "wrong_pc", "pc_exited_extent"),
        ("insufficient_dwell", "no_boot", "insufficient_dwell"),
    ],
)
def test_approved_image_running_dwell_failure_modes(
    tmp_path: Path, failure_mode: str, expected_outcome: str, expected_dwell_reason: str
):
    cfg_dict = _sample_approved_config(dwell_s=0.25)

    def step_fn(state, machine, cpu, _fire_fault, _dur):
        # After entry on slice 1, trigger the requested failure on slice 3 (0.10s into dwell).
        if state["run_calls"] == 3:
            if failure_mode == "lockup":
                state["locked_up"] = True
            elif failure_mode == "reset":
                machine.PeripheralReset.fire(machine, cpu)
            elif failure_mode == "pc_exited_extent":
                state["pc"] = 0x0000D501  # inside TLV region outside [0xC200, 0xD400)

    max_iters = 3 if failure_mode == "insufficient_dwell" else 20
    ns, _, _, cpu, _, _ = _build_runtime_harness(
        step_fn=step_fn,
        approved_image_running_config=cfg_dict,
        slot_hash_fn=lambda _slot: "bb" * 32,
    )
    p2_status = ns["run_until_done"](
        cpu,
        max_iters=max_iters,
        expect_writes=False,
        zero_writes_is_brick=False,
        label=f"p2_{failure_mode}",
        time_slice="0.05",
    )
    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x0000C200, cpu.PC, p2_status=p2_status
    )
    assert outcome == expected_outcome
    verdict = signals["approved_image_running"]
    assert verdict["ok"] is False
    assert verdict["failed_part"] == "dwell"
    assert verdict["dwell"]["started"] is True
    assert verdict["dwell"]["completed"] is False
    assert verdict["dwell"]["failure_reason"] == expected_dwell_reason
    assert "approved_image_running(dwell)" in signals["failure_reason"]

    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)
    p_exec = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    cfg = load_profile(p_exec)
    point_res = {
        "fault_at": 1,
        "fault_injected": True,
        "boot_outcome": outcome,
        "boot_slot": slot,
        "signals": signals,
    }
    annotate_result_checks([point_res], cfg, repo_root=tmp_path)
    assert point_res["approved_image_running"]["failed_part"] == "dwell"
    reasons = result_issue_reasons(point_res, "success")
    assert "pc_expectation" in reasons


def test_fault_classification_and_audit_report_integration(tmp_path: Path):
    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)
    p_exec = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "approved_image_running": {"slot": "exec", "images": ["staging"]}
        },
    )
    cfg = load_profile(p_exec)

    digest_fail_point = {
        "fault_at": 1,
        "fault_injected": True,
        "boot_outcome": "wrong_image",
        "boot_slot": "exec",
        "signals": {
            "content_criteria_ok": False,
            "approved_image_running": {
                "ok": False,
                "slot": "exec",
                "failed_part": "digest",
                "digest": {"ok": False},
                "extent": {"ok": False},
                "dwell": {"ok": False},
            },
        },
    }
    assert _expected_boot_slot(digest_fail_point) == "exec"
    assert "content_criteria" in result_issue_reasons(digest_fail_point, "success")

    control_point = {
        "fault_at": -1,
        "fault_type": "control",
        "is_control": True,
        "fault_injected": False,
        "boot_outcome": "success",
        "boot_slot": "exec",
        "fault_class": "clean_boot",
        "matched_image": "staging",
        "approved_image_running": {
            "ok": True,
            "failed_part": None,
            "slot": "exec",
            "matched_image": "staging",
            "required_dwell_s": 0.25,
            "observed_dwell_s": 0.25,
        },
        "signals": {
            "approved_image_running": {
                "ok": True,
                "failed_part": None,
                "slot": "exec",
                "matched_image": "staging",
                "required_dwell_s": 0.25,
                "observed_dwell_s": 0.25,
            }
        },
    }
    _validate_runtime_control_result(cfg, control_point)
    summary = summarize_runtime_sweep([control_point], profile=cfg)
    assert summary["control"]["signals"]["approved_image_running"]["ok"] is True


def test_enabled_mcuboot_profiles_load_approved_image_running():
    expected_profiles = {
        "mcuboot_head_move_nrf52_revert.yaml": ("exec", ["staging"]),
        "mcuboot_head_move_stm32f4_upgrade.yaml": ("exec", ["staging"]),
        "mcuboot_head_move_stm32f4_revert.yaml": ("exec", ["staging"]),
        "mcuboot_pr3011_move_broken.yaml": ("exec", ["staging"]),
        "mcuboot_pr3011_move_fixed.yaml": ("exec", ["staging"]),
        "mcuboot_pr3011_offset_broken.yaml": ("exec", ["staging"]),
        "mcuboot_pr3011_offset_fixed.yaml": ("exec", ["staging"]),
        "mcuboot_pr2199_move_broken.yaml": ("exec", ["exec"]),
        "mcuboot_pr2199_move_fixed.yaml": ("exec", ["exec"]),
        "mcuboot_pr2109_scratch_broken.yaml": ("exec", ["staging"]),
        "mcuboot_pr2109_scratch_fixed.yaml": ("exec", ["staging"]),
    }
    for filename, (expected_slot, expected_images) in expected_profiles.items():
        path = ROOT / "profiles" / filename
        cfg = load_profile(path)
        app = cfg.success_criteria.approved_image_running
        assert app is not None, filename
        assert app.slot == expected_slot, filename
        assert app.images == expected_images, filename
        assert app.dwell_s == pytest.approx(DEFAULT_APPROVED_IMAGE_DWELL_S), filename
        rv = cfg.robot_vars(ROOT)
        encoded = next(
            item.split(":", 1)[1]
            for item in rv
            if item.startswith("APPROVED_IMAGE_RUNNING_B64:")
        )
        decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
        assert decoded["slot"] == expected_slot, filename
        assert [img["name"] for img in decoded["images"]] == expected_images, filename
        for img in decoded["images"]:
            assert img["code_offset"] > 0, (filename, img)
            assert img["code_size"] > 0, (filename, img)
            assert img["extent_source"] == "mcuboot_header", (filename, img)


def test_approved_image_running_unapproved_known_image_and_early_handoff_stop(tmp_path: Path):
    exec_blob = _build_mcuboot_image(body_fill=0x11)
    staging_blob = _build_mcuboot_image(body_fill=0x22)
    p_exec = _write_test_profile(
        tmp_path,
        exec_blob=exec_blob,
        staging_blob=staging_blob,
        evaluation_mode="execute",
        success_criteria={
            "vtor_in_slot": "exec",
            "approved_image_running": {"slot": "exec", "images": ["staging"]},
        },
    )
    cfg = load_profile(p_exec)
    rv = cfg.robot_vars(tmp_path)
    encoded = next(
        item.split(":", 1)[1]
        for item in rv
        if item.startswith("APPROVED_IMAGE_RUNNING_B64:")
    )
    decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
    assert "exec" in decoded["known_images"]
    assert "staging" in decoded["known_images"]
    exec_digest = decoded["known_images"]["exec"]
    staging_digest = decoded["known_images"]["staging"]
    assert exec_digest != staging_digest

    # Boot into the unapproved-but-known exec image: run_until_done must stop on
    # vtor_captured (1 slice + 1 post-VTOR settle = 2 RunFor calls) instead of
    # spinning through all 20 max_iters slices to budget, and must classify the
    # result as wrong_image (observed_image="exec", image_hash_match="exec_image")
    # rather than silent_corruption.
    ns, state, _, cpu, _, _ = _build_runtime_harness(
        approved_image_running_config=decoded,
        slot_hash_fn=lambda _slot: exec_digest,
    )
    p2_status = ns["run_until_done"](
        cpu,
        max_iters=20,
        expect_writes=False,
        zero_writes_is_brick=True,
        label="p2_unapproved_known",
        time_slice="0.05",
    )
    assert p2_status["reason"] == "vtor_captured"
    assert state["run_calls"] == 2
    outcome, slot, signals = ns["evaluate_boot_outcome"](
        0x0000C200, cpu.PC, p2_status=p2_status
    )
    assert outcome == "wrong_image"
    assert slot == "exec"
    verdict = signals["approved_image_running"]
    assert verdict["ok"] is False
    assert verdict["failed_part"] == "digest"
    assert verdict["matched_image"] is None
    assert verdict["digest"]["observed_image"] == "exec"
    assert signals["image_hash_match"] == "exec_image"
    assert (
        classify_failure_class(
            {
                "fault_injected": True,
                "boot_outcome": outcome,
                "boot_slot": slot,
                "signals": signals,
            }
        )
        == "wrong_image"
    )

    # By contrast, an unknown corrupted slot digest is classified as silent_corruption.
    ns_corrupt, state_corrupt, _, cpu_corrupt, _, _ = _build_runtime_harness(
        approved_image_running_config=decoded,
        slot_hash_fn=lambda _slot: "ff" * 32,
    )
    p2_corrupt = ns_corrupt["run_until_done"](
        cpu_corrupt,
        max_iters=20,
        expect_writes=False,
        zero_writes_is_brick=True,
        label="p2_corrupt",
        time_slice="0.05",
    )
    assert p2_corrupt["reason"] == "vtor_captured"
    assert state_corrupt["run_calls"] == 2
    outcome_c, slot_c, signals_c = ns_corrupt["evaluate_boot_outcome"](
        0x0000C200, cpu_corrupt.PC, p2_status=p2_corrupt
    )
    assert outcome_c == "wrong_image"
    assert signals_c["approved_image_running"]["digest"]["observed_image"] is None
    assert signals_c["image_hash_match"] == "unknown"
    assert (
        classify_failure_class(
            {
                "fault_injected": True,
                "boot_outcome": outcome_c,
                "boot_slot": slot_c,
                "signals": signals_c,
            }
        )
        == "silent_corruption"
    )


