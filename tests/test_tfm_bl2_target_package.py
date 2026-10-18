#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the TF-M BL2 target-side invariants."""

from __future__ import annotations

import ast
import unittest
from types import SimpleNamespace

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from targets.tf_m_bl2.invariants import (  # noqa: E402
    INVARIANTS,
    check_tfm_multi_image_acceptance_consistency,
    check_tfm_multi_image_consistency,
    check_tfm_no_partial_magic,
)
from targets.tf_m_bl2.probe import (  # noqa: E402
    MCUBOOT_GOOD_MAGIC,
    _get_monitor_var,
    _parse_image_version,
    _slot_probe,
    boot_magic_decode,
    collect_state,
    mcuboot_expected_magic,
    mcuboot_trailer_magic,
)
from profile_loader import (  # noqa: E402
    ProfileError,
    ProfileConfig,
    SuccessCriteria,
    FaultSweepConfig,
    StateFuzzerConfig,
    ExpectConfig,
    _parse_fault_sweep,
    _parse_invariant_config,
    _parse_memory,
)


def _result(secure_state: str, ns_state: str):
    secure_version = {
        "state": "valid",
        "major": 2,
        "minor": 3,
        "revision": 0,
        "build": 1,
        "canonical": "2.3.0+1",
    }
    ns_version = {
        "state": "valid",
        "major": 4,
        "minor": 5,
        "revision": 6,
        "build": 7,
        "canonical": "4.5.6+7",
    }
    return SimpleNamespace(
        nvm_state={
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": {
                    "image_ok": {"state": secure_state},
                    "version": secure_version,
                },
                "ns_exec": {
                    "image_ok": {"state": ns_state},
                    "version": ns_version,
                },
            },
        }
    )


JOINT_ACCEPTANCE = {"invariant_config": {"tfm_joint_acceptance": True}}


class TfmBl2AcceptanceInvariantTest(unittest.TestCase):
    def test_missing_required_slot_evidence_is_inconclusive(self) -> None:
        result = _result("set", "set")
        del result.nvm_state["slots"]["ns_exec"]
        with self.assertRaisesRegex(ValueError, "requires secure and non-secure"):
            check_tfm_multi_image_acceptance_consistency(
                result, **JOINT_ACCEPTANCE
            )

    def test_rejects_malformed_image_ok_even_when_both_match(self) -> None:
        with self.assertRaises(InvariantViolation):
            check_tfm_multi_image_acceptance_consistency(
                _result("other", "other"), **JOINT_ACCEPTANCE
            )

    def test_rejects_interrupted_acceptance_split(self) -> None:
        for secure_state, ns_state in (("set", "unset"), ("unset", "set")):
            with self.subTest(secure_state=secure_state, ns_state=ns_state):
                with self.assertRaises(InvariantViolation) as ctx:
                    check_tfm_multi_image_acceptance_consistency(
                        _result(secure_state, ns_state), **JOINT_ACCEPTANCE
                    )

                self.assertEqual(
                    ctx.exception.invariant_name,
                    "tfm_multi_image_acceptance_consistency",
                )
                self.assertEqual(
                    ctx.exception.details["secure_exec_image_ok"], secure_state
                )
                self.assertEqual(
                    ctx.exception.details["ns_exec_image_ok"], ns_state
                )
                self.assertEqual(
                    ctx.exception.details["secure_exec_version"]["canonical"],
                    "2.3.0+1",
                )
                self.assertEqual(
                    ctx.exception.details["ns_exec_version"]["canonical"],
                    "4.5.6+7",
                )

    def test_accepts_matching_primary_states(self) -> None:
        for state in ("set", "unset"):
            with self.subTest(state=state):
                check_tfm_multi_image_acceptance_consistency(
                    _result(state, state), **JOINT_ACCEPTANCE
                )

    def test_skips_when_joint_acceptance_is_not_declared(self) -> None:
        check_tfm_multi_image_acceptance_consistency(_result("set", "unset"))

    def test_is_registered(self) -> None:
        self.assertIs(
            INVARIANTS["tfm_multi_image_acceptance_consistency"],
            check_tfm_multi_image_acceptance_consistency,
        )


class TfmBl2JointVersionInvariantTest(unittest.TestCase):
    def test_multi_image_consistency_rejects_missing_slot_evidence(self):
        result = _result("set", "set")
        del result.nvm_state["slots"]["secure_exec"]
        with self.assertRaisesRegex(ValueError, "requires secure and non-secure"):
            check_tfm_multi_image_consistency(result)

    def test_equal_trailer_state_rejects_incompatible_declared_versions(self):
        result = _result("set", "set")
        with self.assertRaises(InvariantViolation) as ctx:
            check_tfm_multi_image_consistency(
                result,
                invariant_config={
                    "tfm_joint_version_policy": {"mode": "compatible"}
                },
            )
        self.assertEqual(ctx.exception.invariant_name, "tfm_multi_image_consistency")
        self.assertEqual(ctx.exception.details["secure_exec_version"]["major"], 2)

    def test_compatible_policy_accepts_equal_major_versions(self):
        result = _result("set", "set")
        result.nvm_state["slots"]["ns_exec"]["version"]["major"] = 2
        check_tfm_multi_image_consistency(
            result,
            invariant_config={
                "tfm_joint_version_policy": {"mode": "compatible"}
            },
        )

    def test_declared_policy_requires_version_evidence(self):
        result = _result("unset", "unset")
        result.nvm_state["slots"]["secure_exec"]["version"] = {
            "state": "erased"
        }
        with self.assertRaises(ValueError):
            check_tfm_multi_image_consistency(
                result,
                invariant_config={"tfm_joint_version_policy": "equal"},
            )

    def test_trailer_magic_rejects_unknown_state_after_recovery(self):
        result = _result("set", "set")
        result.nvm_state["slots"]["secure_exec"]["magic_state"] = "other"
        with self.assertRaises(InvariantViolation):
            check_tfm_no_partial_magic(result)

    def test_trailer_invariant_rejects_absent_or_malformed_slot_evidence(self):
        result = _result("set", "set")
        del result.nvm_state["slots"]
        with self.assertRaises(ValueError):
            check_tfm_no_partial_magic(result)
        result = _result("set", "set")
        result.nvm_state["slots"]["secure_exec"] = None
        with self.assertRaises(ValueError):
            check_tfm_no_partial_magic(result)

    def test_secure_slot_invariant_rejects_missing_evidence_on_non_success(self):
        result = _result("set", "set")
        result.boot_outcome = "crash"
        del result.nvm_state["slots"]["secure_exec"]
        from targets.tf_m_bl2.invariants import check_tfm_secure_slot_not_empty

        with self.assertRaises(ValueError):
            check_tfm_secure_slot_not_empty(result)


class _ProbeMonitor:
    def __init__(self, variables):
        self.variables = variables

    def GetVariable(self, name):
        if name not in self.variables:
            raise KeyError(name)
        return self.variables[name]


class _ProbeBus:
    def ReadBytes(self, _address, size):
        return bytes([0] * int(size))


class _HeaderProbeBus:
    def __init__(self, base, header):
        self.base = int(base)
        self.header = bytes(header)

    def ReadBytes(self, address, size):
        if int(address) == self.base and int(size) == len(self.header):
            return self.header
        return bytes([0xFF] * int(size))


class TfmBl2ProbeImageVersionTest(unittest.TestCase):
    def test_parses_mcu_boot_version_and_canonical_string(self):
        header = bytearray(32)
        header[0:4] = (0x96F3B83D).to_bytes(4, "little")
        header[20:28] = bytes((2, 5)) + (0x1234).to_bytes(2, "little") + (7).to_bytes(4, "little")

        self.assertEqual(
            _parse_image_version(header),
            {
                "state": "valid",
                "major": 2,
                "minor": 5,
                "revision": 0x1234,
                "build": 7,
                "canonical": "2.5.4660+7",
            },
        )

        slot = _slot_probe(_HeaderProbeBus(0x1000, header), 0x1000, 0x1000, 8)
        self.assertEqual(slot["version"]["canonical"], "2.5.4660+7")

    def test_erased_invalid_and_short_headers_are_safe(self):
        for header, state in (
            (b"\xFF" * 32, "erased"),
            (b"\x00" * 32, "invalid"),
            (b"\x01", "invalid"),
        ):
            with self.subTest(state=state):
                version = _parse_image_version(header)
                self.assertEqual(version["state"], state)
                self.assertIsNone(version["canonical"])
                self.assertIsNone(version["major"])

        short_slot = _slot_probe(_HeaderProbeBus(0x1000, b"\x00" * 16), 0x1000, 16, 8)
        self.assertEqual(short_slot["version"]["state"], "invalid")


class TfmBl2ProbeSlotCompatibilityTest(unittest.TestCase):
    def test_generic_runtime_slots_map_to_four_tf_m_slots(self):
        variables = {
            "mcuboot_trailer_align": "8",
            "slot_exec_base": "0x80000",
            "slot_exec_size": "0x80000",
            "slot_staging_base": "0x180000",
            "slot_staging_size": "0x80000",
            "slot_tertiary_base": "0x100000",
            "slot_tertiary_size": "0x80000",
            "slot_recovery_base": "0x200000",
            "slot_recovery_size": "0x80000",
        }
        state = collect_state(_ProbeBus(), _ProbeMonitor(variables))

        self.assertTrue(state["flags"]["multi_image"])
        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x00080000")
        self.assertEqual(state["slots"]["secure_staging"]["base"], "0x00180000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x00100000")
        self.assertEqual(state["slots"]["ns_staging"]["base"], "0x00200000")
        self.assertEqual(state["security_boundary"]["status"], "unavailable")
        self.assertEqual(state["security_boundary"]["mpc"], "not_evaluated")

    def test_dedicated_slot_names_override_generic_aliases(self):
        variables = {
            "slot_exec_base": "0x1000",
            "slot_exec_size": "0x2000",
            "slot_staging_base": "0x3000",
            "slot_staging_size": "0x2000",
            "slot_tertiary_base": "0x5000",
            "slot_tertiary_size": "0x2000",
            "slot_recovery_base": "0x7000",
            "slot_recovery_size": "0x2000",
            "slot_s_exec_base": "0xA000",
            "slot_s_exec_size": "0x1000",
            "slot_s_staging_base": "0xB000",
            "slot_s_staging_size": "0x1000",
            "slot_ns_exec_base": "0xC000",
            "slot_ns_exec_size": "0x1000",
            "slot_ns_staging_base": "0xD000",
            "slot_ns_staging_size": "0x1000",
        }
        state = collect_state(_ProbeBus(), _ProbeMonitor(variables))

        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x0000A000")
        self.assertEqual(state["slots"]["secure_staging"]["base"], "0x0000B000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x0000C000")
        self.assertEqual(state["slots"]["ns_staging"]["base"], "0x0000D000")

    def test_context_slot_geometry_survives_reset_scoped_monitor_vars(self):
        context = {
            "slot_geometry": {
                "exec": {"base": 0x80000, "size": 0x80000},
                "staging": {"base": 0x180000, "size": 0x80000},
                "tertiary": {"base": 0x100000, "size": 0x80000},
                "recovery": {"base": 0x200000, "size": 0x80000},
            }
        }
        state = collect_state(
            _ProbeBus(),
            _ProbeMonitor({"mcuboot_trailer_align": "8"}),
            context=context,
        )
        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x00080000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x00100000")
        self.assertEqual(state["slots"]["ns_staging"]["size"], "0x00080000")

    def test_missing_monitor_values_remain_missing(self):
        self.assertIsNone(_get_monitor_var(_ProbeMonitor({"empty": None}), "empty"))

    def test_profile_parser_exposes_opt_in_vtor_settle_budget(self):
        parsed = _parse_fault_sweep(
            {
                "vtor_settle_iters": 37,
                "fault_types": ["power_loss"],
                "max_writes_cap": 10,
            }
        )
        self.assertEqual(parsed.vtor_settle_iters, 37)

    def test_tracking_start_address_is_parsed_and_emitted(self):
        parsed = _parse_fault_sweep(
            {
                "tracking_start_address": "0x0010072C",
                "fault_types": ["power_loss"],
                "max_writes_cap": 10,
            }
        )
        self.assertEqual(parsed.tracking_start_address, 0x10072C)

    def test_tracking_start_address_defaults_and_validates(self):
        self.assertEqual(_parse_fault_sweep({}).tracking_start_address, 0)
        with self.assertRaises(ProfileError):
            _parse_fault_sweep({"tracking_start_address": "0x100000000"})

    def test_invariant_semantic_state_stage_is_validated(self):
        self.assertEqual(
            _parse_invariant_config({"semantic_state_stage": "fault_snapshot"})[
                "semantic_state_stage"
            ],
            "fault_snapshot",
        )
        with self.assertRaises(ProfileError):
            _parse_invariant_config({"semantic_state_stage": "unknown"})

    def test_trace_address_map_rejects_overlap_and_bad_32_bit_bound(self):
        base = {
            "sram": {"start": 0x38000000, "end": 0x38040000},
            "slots": {"exec": {"base": 0x80000, "size": 0x80000}},
        }
        parsed = _parse_memory({
            **base,
            "trace_address_map": [{
                "offset_start": 0x80000,
                "offset_end": 0x100000,
                "address_addend": 0x10000000,
            }],
        })
        self.assertEqual(parsed.trace_address_map[0]["address_addend"], 0x10000000)
        with self.assertRaises(ProfileError):
            _parse_memory({
                **base,
                "trace_address_map": [
                    {"offset_start": 0, "offset_end": 4, "address_addend": 0},
                    {"offset_start": 3, "offset_end": 8, "address_addend": 0},
                ],
            })
        with self.assertRaises(ProfileError):
            _parse_memory({
                **base,
                "trace_address_map": [{
                    "offset_start": 0xFFFFFFF0,
                    "offset_end": 0x100000000,
                    "address_addend": 1,
                }],
            })

    def test_postmortem_geometry_and_partitions_parse_and_emit(self):
        parsed = _parse_memory({
            "sram": {"start": 0x20000000, "end": 0x20010000},
            "slots": {"exec": {"base": 0x08010000, "size": 0x4000}},
            "erase_regions": [
                {"base": 0x08000000, "size": 0x4000, "sector_size": 0x4000},
                {"base": 0x08004000, "size": 0x10000, "sector_size": 0x10000},
                {"base": 0x08014000, "size": 0x4000, "sector_size": 0x4000},
            ],
            "postmortem_partitions": [
                {"name": "scratch", "base": 0x08014000, "size": 0x4000}
            ],
        })
        self.assertEqual(parsed.erase_regions[1].sector_size, 0x10000)
        self.assertEqual(parsed.postmortem_partitions[0].name, "scratch")
        profile = ProfileConfig(
            schema_version=1, name="postmortem", description="",
            platform="platforms/cortex_m0_nvm.repl",
            bootloader_elf="test.elf", bootloader_entry=0,
            memory=parsed, images={}, pre_boot_state=[], setup_script=None,
            extra_peripherals=None, success_criteria=SuccessCriteria(),
            fault_sweep=FaultSweepConfig(), state_fuzzer=StateFuzzerConfig(),
            expect=ExpectConfig(),
        )
        vars_list = profile.robot_vars(ROOT)
        layout = next(v for v in vars_list if v.startswith("POSTMORTEM_LAYOUT_B64:"))
        self.assertTrue(layout.split(":", 1)[1])

    def test_postmortem_regions_require_valid_geometry_and_names(self):
        base = {
            "sram": {"start": 0x20000000, "end": 0x20010000},
            "slots": {"exec": {"base": 0x08000000, "size": 0x10000}},
        }
        with self.assertRaises(ProfileError):
            _parse_memory({**base, "erase_regions": [{"base": 0, "size": 4}]})
        with self.assertRaises(ProfileError):
            _parse_memory({**base, "postmortem_partitions": [{"base": 0, "size": 4}]})
        with self.assertRaises(ProfileError):
            _parse_memory({
                **base,
                "postmortem_partitions": [
                    {"name": "scratch", "base": 0, "size": 4},
                    {"name": "scratch", "base": 8, "size": 4},
                ],
            })

    def test_runtime_tracking_gate_fails_closed_on_unsupported_backend(self):
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_apply_tracking_start_address"
        )
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<runtime_gate>", "exec"), namespace)
        apply_gate = namespace["_apply_tracking_start_address"]
        with self.assertRaisesRegex(Exception, "requires backend"):
            apply_gate(SimpleNamespace(), "unsupported", 0x10072C)
        capable = SimpleNamespace(TrackingStartAddress=0)
        apply_gate(capable, "supported", 0x10072C)
        self.assertEqual(capable.TrackingStartAddress, 0x10072C)

    def test_native_template_is_path_neutral_and_not_discovered_as_profile(self):
        template = ROOT / "profiles" / "tf_m_bl2_an521_native.template.yaml.in"
        text = template.read_text(encoding="utf-8")
        self.assertIn("${TFM_BL2_ELF}", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("/tmp/", text)
        self.assertFalse(template.name.endswith(".yaml"))
        self.assertIn("pc_in_slot: tertiary", text)
        self.assertIn("tracking_start_address: ${TFM_TRACKING_START_ADDRESS}", text)
        self.assertIn("semantic_state_stage: fault_snapshot", text)
        self.assertIn("trace_address_map:", text)
        self.assertIn("address_addend: 0x10000000", text)
        self.assertIn("should_find_issues: false", text)

    def test_vtor_settle_budget_is_wired_through_runtime_boundary(self):
        robot = (ROOT / "tests" / "ota_fault_point.robot").read_text(encoding="utf-8")
        resc = (ROOT / "scripts" / "run_runtime_fault_sweep.resc").read_text(
            encoding="utf-8"
        )
        runtime = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("${VTOR_SETTLE_ITERS}", robot)
        self.assertIn("$vtor_settle_iters", resc)
        self.assertIn("vtor_settle_iters_config", runtime)
        self.assertIn("return vtor_settle_iters_config", runtime)
        self.assertIn("${TRACKING_START_ADDRESS}", robot)
        self.assertIn("$tracking_start_address", resc)
        self.assertIn("tracking_start_address_config", runtime)
        self.assertIn("TrackingStartAddress", runtime)
        self.assertIn("_apply_tracking_start_address", runtime)
        self.assertIn("requires backend", runtime)
        self.assertIn("def _configure_python_tracking_gate(force=False)", runtime)
        self.assertIn("_configure_python_tracking_gate(force=True)", runtime)
        self.assertIn("cpu_ref.AddHook(address, _python_tracking_gate_hook)", runtime)
        self.assertIn("_runtime_slot_geometry", runtime)
        self.assertIn("slot_geometry", runtime)
        self.assertIn("reset_sticky_handoff_state()", runtime)


def _build_synthetic_elf32(symbols: dict[str, int], load_vaddr: int = 0x10000000) -> bytes:
    strtab = bytearray(b"\x00")
    sym_entries = [b"\x00" * 16]
    for name, value in symbols.items():
        st_name = len(strtab)
        strtab.extend(name.encode("utf-8") + b"\x00")
        sym_entries.append(
            struct.pack("<IIIBBH", st_name, value, 4, 0x12, 0, 1)
        )
    symtab = b"".join(sym_entries)

    ehdr_size = 52
    phdr_off = ehdr_size
    phdr_size = 32
    symtab_off = phdr_off + phdr_size
    strtab_off = symtab_off + len(symtab)
    shdr_off = strtab_off + len(strtab)

    ehdr = (
        b"\x7fELF"
        + bytes([1, 1, 1, 0])
        + (b"\x00" * 8)
        + struct.pack(
            "<HHIIIIIHHHHHH",
            2,
            40,
            1,
            load_vaddr | 1,
            phdr_off,
            shdr_off,
            0,
            ehdr_size,
            phdr_size,
            1,
            40,
            3,
            2,
        )
    )
    phdr = struct.pack(
        "<IIIIIIII", 1, 0, load_vaddr, load_vaddr, 64, 64, 5, 0x1000
    )
    sh_null = b"\x00" * 40
    sh_symtab = struct.pack(
        "<IIIIIIIIII", 0, 2, 0, 0, symtab_off, len(symtab), 2, 1, 4, 16
    )
    sh_strtab = struct.pack(
        "<IIIIIIIIII", 0, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0
    )
    return ehdr + phdr + symtab + bytes(strtab) + sh_null + sh_symtab + sh_strtab


def _write_synthetic_an521_headers(headers_dir: Path) -> None:
    headers_dir.mkdir(parents=True, exist_ok=True)
    (headers_dir / "flash_layout.h").write_text(
        """\
#define FLASH_S_PARTITION_SIZE          (0x80000)
#define FLASH_NS_PARTITION_SIZE         (0x80000)
#define FLASH_AREA_BL2_OFFSET           (0x0)
#define FLASH_AREA_BL2_SIZE             (0x80000)
#if (MCUBOOT_IMAGE_NUMBER == 1)
#define FLASH_AREA_0_OFFSET             (0x80000)
#elif (MCUBOOT_IMAGE_NUMBER == 2)
#define FLASH_AREA_0_OFFSET             (FLASH_AREA_BL2_OFFSET + FLASH_AREA_BL2_SIZE)
#define FLASH_AREA_1_OFFSET             (FLASH_AREA_0_OFFSET + FLASH_S_PARTITION_SIZE)
#define FLASH_AREA_2_OFFSET             (FLASH_AREA_1_OFFSET + FLASH_NS_PARTITION_SIZE)
#define FLASH_AREA_3_OFFSET             (FLASH_AREA_2_OFFSET + FLASH_S_PARTITION_SIZE)
#endif
""",
        encoding="utf-8",
    )
    (headers_dir / "region_defs.h").write_text(
        """\
#define S_ROM_ALIAS_BASE                (0x10000000)
#define NS_ROM_ALIAS_BASE               (0x00000000)
#define S_ROM_ALIAS(x)                  (S_ROM_ALIAS_BASE + (x))
#define NS_ROM_ALIAS(x)                 (NS_ROM_ALIAS_BASE + (x))
#define BL2_CODE_START                  (S_ROM_ALIAS(FLASH_AREA_BL2_OFFSET))
""",
        encoding="utf-8",
    )


class TfmBl2GenerateRuntimeProfileTest(unittest.TestCase):
    def test_synthetic_build_dir_renders_valid_profile(self) -> None:
        import struct as _struct
        import tempfile
        import shutil
        from targets.tf_m_bl2.generate_runtime_profile import (
            main as gen_main,
            render_runtime_profile,
            write_runtime_profile,
        )
        from profile_loader import load_profile

        globals()["struct"] = _struct
        temp_dir = Path(tempfile.mkdtemp(prefix="tfm_bl2_synth_"))
        try:
            build_dir = temp_dir / "build"
            headers_dir = build_dir / "partition"
            _write_synthetic_an521_headers(headers_dir)

            elf_bytes = _build_synthetic_elf32(
                {
                    "__Vectors": 0x10000000,
                    "fwu_bootloader_mark_image_accepted": 0x10004561,
                }
            )
            (build_dir / "bl2.axf").write_bytes(elf_bytes)
            for img_name in (
                "tfm_s_signed.bin",
                "tfm_s_staging_signed.bin",
                "tfm_ns_signed.bin",
                "tfm_ns_staging_signed.bin",
            ):
                (build_dir / img_name).write_bytes(b"\xAA" * 1024)

            rendered = render_runtime_profile(build_dir)
            self.assertNotIn("${TFM_", rendered)

            out_yaml = build_dir / "tf_m_bl2_an521_native.yaml"
            written = write_runtime_profile(out_yaml, rendered)
            self.assertEqual(written, out_yaml.resolve())

            loaded = load_profile(written)
            self.assertEqual(loaded.bootloader_entry, 0x10000000)
            self.assertEqual(loaded.memory.slots["exec"].base, 0x10080000)
            self.assertEqual(loaded.memory.slots["staging"].base, 0x10180000)
            self.assertEqual(loaded.memory.slots["tertiary"].base, 0x00100000)
            self.assertEqual(loaded.memory.slots["recovery"].base, 0x00200000)
            self.assertEqual(loaded.memory.slots["exec"].size, 0x00080000)
            self.assertEqual(loaded.fault_sweep.tracking_start_address, 0x10004560)
            self.assertEqual(loaded.fault_sweep.max_writes_cap, 200000)
            self.assertEqual(loaded.fault_sweep.max_heuristic_points, 64)
            self.assertFalse(loaded.fault_sweep.heuristic_config.preserve_critical_tiers)

            self.assertEqual(
                loaded.invariant_config.get("semantic_state_stage"),
                "fault_snapshot",
            )
            self.assertTrue(loaded.expect.should_find_issues)

            # Without fwu_bootloader_mark_image_accepted, tracking_start_address
            # resolves to 0x0 and semantic_state_stage defaults to final.
            (build_dir / "bl2.axf").write_bytes(
                _build_synthetic_elf32({"__Vectors": 0x10000000})
            )
            rendered_swap = render_runtime_profile(build_dir)
            written_swap = write_runtime_profile(out_yaml, rendered_swap)
            loaded_swap = load_profile(written_swap)
            self.assertEqual(loaded_swap.fault_sweep.tracking_start_address, 0)
            self.assertEqual(
                loaded_swap.invariant_config.get("semantic_state_stage"),
                "final",
            )
            self.assertTrue(loaded_swap.expect.should_find_issues)

            with self.assertRaisesRegex(ValueError, "Refusing to write"):
                write_runtime_profile(ROOT / "profiles" / "forbidden.yaml", rendered)

            # Verify confirmed staging image selection via API and CLI flag
            for img_name in (
                "tfm_s_staging_confirmed.bin",
                "tfm_ns_staging_confirmed.bin",
            ):
                (build_dir / img_name).write_bytes(b"\xBB" * 1024)

            rendered_confirmed = render_runtime_profile(
                build_dir, confirmed_staging=True, boot_cycles=3
            )
            written_confirmed = write_runtime_profile(out_yaml, rendered_confirmed)
            loaded_confirmed = load_profile(written_confirmed)
            self.assertTrue(
                loaded_confirmed.images["staging"].endswith(
                    "tfm_s_staging_confirmed.bin"
                )
            )
            self.assertTrue(
                loaded_confirmed.images["recovery"].endswith(
                    "tfm_ns_staging_confirmed.bin"
                )
            )
            self.assertEqual(loaded_confirmed.fault_sweep.boot_cycles, 3)
            self.assertFalse(loaded_confirmed.expect.should_find_issues)

            rc_confirmed = gen_main(
                ["--build-dir", str(build_dir), "--confirmed-staging"]
            )
            self.assertEqual(rc_confirmed, 0)
            loaded_cli_confirmed = load_profile(out_yaml)
            self.assertTrue(
                loaded_cli_confirmed.images["staging"].endswith(
                    "tfm_s_staging_confirmed.bin"
                )
            )
            self.assertTrue(
                loaded_cli_confirmed.images["recovery"].endswith(
                    "tfm_ns_staging_confirmed.bin"
                )
            )
            self.assertFalse(loaded_cli_confirmed.expect.should_find_issues)

            # Verify CLI entry point regenerates unconfirmed staging images by default
            rc = gen_main(["--build-dir", str(build_dir)])
            self.assertEqual(rc, 0)
            loaded_cli_default = load_profile(out_yaml)
            self.assertTrue(
                loaded_cli_default.images["staging"].endswith(
                    "tfm_s_staging_signed.bin"
                )
            )
            self.assertTrue(
                loaded_cli_default.images["recovery"].endswith(
                    "tfm_ns_staging_signed.bin"
                )
            )
            self.assertTrue(loaded_cli_default.expect.should_find_issues)

            # Verify OVERWRITE_ONLY build directory defaults max_writes_cap=700000 and should_find_issues=False
            cmake_cache = build_dir / "build_test" / "spe" / "CMakeCache.txt"
            cmake_cache.parent.mkdir(parents=True, exist_ok=True)
            cmake_cache.write_text(
                "MCUBOOT_UPGRADE_STRATEGY:STRING=OVERWRITE_ONLY\n",
                encoding="utf-8",
            )
            rendered_ow = render_runtime_profile(build_dir)
            written_ow = write_runtime_profile(out_yaml, rendered_ow)
            loaded_ow = load_profile(written_ow)
            self.assertEqual(loaded_ow.fault_sweep.max_writes_cap, 700000)
            self.assertEqual(loaded_ow.fault_sweep.max_heuristic_points, 34)
            self.assertIsNotNone(loaded_ow.fault_sweep.heuristic_config)
            self.assertEqual(
                len(loaded_ow.fault_sweep.heuristic_config.critical_regions), 10
            )
            self.assertFalse(loaded_ow.expect.should_find_issues)

            (build_dir / "tfm_s_signed.bin").write_bytes(b"\xAA" * (0x80000 + 4))
            with self.assertRaisesRegex(ValueError, "exceeds slot size"):
                render_runtime_profile(build_dir)
        finally:
            shutil.rmtree(temp_dir)

    def test_multi_image_consistency_gating_on_synthetic_trace(self) -> None:
        v231 = {
            "state": "valid",
            "major": 2,
            "minor": 3,
            "revision": 1,
            "build": 0,
            "canonical": "2.3.1+0",
        }
        v240 = {
            "state": "valid",
            "major": 2,
            "minor": 4,
            "revision": 0,
            "build": 0,
            "canonical": "2.4.0+0",
        }
        synthetic_write_spans = [
            (0x0017F000, 4),
            (0x0017FFE0, 4),
            (0x100FF000, 4),
            (0x10080E28, 4),
        ]
        fault_snapshot_state = {
            "stage": "fault_snapshot",
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": {
                    "base": "0x10080000",
                    "size": "0x00080000",
                    "magic_state": "unset",
                    "copy_done": {"state": "unset"},
                    "image_ok": {"state": "unset"},
                    "version": v231,
                },
                "ns_exec": {
                    "base": "0x00100000",
                    "size": "0x00080000",
                    "magic_state": "good",
                    "copy_done": {"state": "set"},
                    "image_ok": {"state": "unset"},
                    "version": v240,
                },
            },
        }
        # Before the Secure primary trailer is touched in the trace (fault_at=1),
        # a fault_snapshot state is gated out.
        pre_secure_result = SimpleNamespace(
            fault_at=1,
            boot_outcome="success",
            nvm_state=fault_snapshot_state,
        )
        check_tfm_multi_image_consistency(
            pre_secure_result,
            write_spans=synthetic_write_spans,
            invariant_config={"tfm_joint_version_policy": "compatible"},
        )

        # When result_dict provides a converged post-recovery semantic_state,
        # check_tfm_multi_image_consistency evaluates the post-recovery state.
        converged_recovery = {
            "stage": "post_boot",
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": {
                    "base": "0x10080000",
                    "size": "0x00080000",
                    "magic_state": "good",
                    "copy_done": {"state": "set"},
                    "image_ok": {"state": "unset"},
                    "version": v240,
                },
                "ns_exec": {
                    "base": "0x00100000",
                    "size": "0x00080000",
                    "magic_state": "good",
                    "copy_done": {"state": "set"},
                    "image_ok": {"state": "unset"},
                    "version": v240,
                },
            },
        }
        mid_swap_result = SimpleNamespace(
            fault_at=3,
            boot_outcome="success",
            nvm_state=fault_snapshot_state,
        )
        check_tfm_multi_image_consistency(
            mid_swap_result,
            write_spans=synthetic_write_spans,
            result_dict={"semantic_state": converged_recovery},
            invariant_config={"tfm_joint_version_policy": "compatible"},
        )

        # When recovery leaves secure_exec at a forward test swap (image_ok=unset)
        # and ns_exec reverted (image_ok=set), tfm_multi_image_consistency fails.
        split_recovery = {
            "stage": "post_boot",
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": {
                    "base": "0x10080000",
                    "size": "0x00080000",
                    "magic_state": "good",
                    "copy_done": {"state": "set"},
                    "image_ok": {"state": "unset"},
                    "version": v240,
                },
                "ns_exec": {
                    "base": "0x00100000",
                    "size": "0x00080000",
                    "magic_state": "good",
                    "copy_done": {"state": "set"},
                    "image_ok": {"state": "set"},
                    "version": v231,
                },
            },
        }
        with self.assertRaises(InvariantViolation) as ctx:
            check_tfm_multi_image_consistency(
                SimpleNamespace(
                    fault_at=3,
                    boot_outcome="success",
                    nvm_state=split_recovery,
                ),
                write_spans=synthetic_write_spans,
                invariant_config={"tfm_joint_version_policy": "compatible"},
            )
        self.assertEqual(
            ctx.exception.invariant_name, "tfm_multi_image_consistency"
        )
        self.assertEqual(
            ctx.exception.details["secure_exec_image_ok"], "unset"
        )
        self.assertEqual(ctx.exception.details["ns_exec_image_ok"], "set")


class _SyntheticSlotBus:
    def __init__(
        self,
        slot_base: int,
        slot_size: int,
        *,
        version: tuple[int, int, int, int] | None = (2, 4, 0, 0),
        magic: bytes = MCUBOOT_GOOD_MAGIC,
        magic_pad: bytes = b"",
        image_ok: int = 0x01,
        copy_done: int = 0x01,
        align: int = 8,
    ) -> None:
        self.base = int(slot_base)
        self.image = bytearray(b"\xFF" * int(slot_size))
        if version is not None:
            major, minor, rev, build = version
            self.image[0:4] = (0x96F3B83D).to_bytes(4, "little")
            self.image[20:28] = (
                bytes((major, minor))
                + int(rev).to_bytes(2, "little")
                + int(build).to_bytes(4, "little")
            )
        magic_align_size = (
            ((16 + align - 1) // align) * align if align > 16 else 16
        )
        if magic_pad:
            pad_start = int(slot_size) - magic_align_size
            self.image[pad_start:pad_start + len(magic_pad)] = magic_pad
        self.image[int(slot_size) - 16:int(slot_size)] = magic
        image_ok_off = int(slot_size) - magic_align_size - align
        copy_done_off = int(slot_size) - magic_align_size - (2 * align)
        self.image[image_ok_off] = int(image_ok) & 0xFF
        self.image[copy_done_off] = int(copy_done) & 0xFF

    def ReadBytes(self, address: int, size: int) -> bytes:
        offset = int(address) - self.base
        return bytes(self.image[offset:offset + int(size)])


class TfmBl2PartialMagicSyntheticTrailerTest(unittest.TestCase):
    def _build_multi_image_state(
        self,
        *,
        staging_magic: bytes,
        staging_pad: bytes = b"",
        align: int = 8,
        ns_exec_version: tuple[int, int, int, int] | None = (2, 4, 0, 0),
    ) -> dict:
        s_exec = _slot_probe(
            _SyntheticSlotBus(
                0x10080000,
                0x1000,
                magic=mcuboot_expected_magic(align),
                align=align,
            ),
            0x10080000,
            0x1000,
            align,
        )
        s_staging = _slot_probe(
            _SyntheticSlotBus(
                0x10180000,
                0x1000,
                version=None,
                magic=b"\xFF" * 16,
                image_ok=0xFF,
                copy_done=0xFF,
                align=align,
            ),
            0x10180000,
            0x1000,
            align,
        )
        ns_exec = _slot_probe(
            _SyntheticSlotBus(
                0x00100000,
                0x1000,
                version=ns_exec_version,
                magic=mcuboot_expected_magic(align),
                align=align,
            ),
            0x00100000,
            0x1000,
            align,
        )
        ns_staging = _slot_probe(
            _SyntheticSlotBus(
                0x00200000,
                0x1000,
                version=None,
                magic=staging_magic,
                magic_pad=staging_pad,
                image_ok=0xFF,
                copy_done=0xFF,
                align=align,
            ),
            0x00200000,
            0x1000,
            align,
        )
        return {
            "target": "tf_m_bl2",
            "stage": "post_boot",
            "trailer_align": align,
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": s_exec,
                "secure_staging": s_staging,
                "ns_exec": ns_exec,
                "ns_staging": ns_staging,
            },
        }

    def test_partial_magic_decoded_as_bad_passes_when_recovery_boots_valid_pair(
        self,
    ) -> None:
        for partial_magic in (
            MCUBOOT_GOOD_MAGIC[:8] + (b"\xFF" * 8),
            (b"\xFF" * 8) + MCUBOOT_GOOD_MAGIC[8:],
        ):
            with self.subTest(partial_magic=partial_magic.hex()):
                self.assertEqual(boot_magic_decode(partial_magic), "bad")
                self.assertEqual(mcuboot_trailer_magic(partial_magic), "bad")
                state = self._build_multi_image_state(
                    staging_magic=partial_magic
                )
                result = SimpleNamespace(
                    fault_at=284790,
                    boot_outcome="success",
                    nvm_state=state,
                )
                check_tfm_no_partial_magic(
                    result,
                    boot_cycles=[
                        {"cycle": 1, "outcome": "success"},
                        {"cycle": 2, "outcome": "success"},
                        {"cycle": 3, "outcome": "success"},
                    ],
                )

    def test_partial_magic_decoded_as_bad_fails_when_recovery_fails_valid_pair(
        self,
    ) -> None:
        partial_magic = MCUBOOT_GOOD_MAGIC[:8] + (b"\xFF" * 8)
        self.assertEqual(boot_magic_decode(partial_magic), "bad")

        failed_boot_state = self._build_multi_image_state(
            staging_magic=partial_magic
        )
        with self.assertRaises(InvariantViolation) as boot_ctx:
            check_tfm_no_partial_magic(
                SimpleNamespace(
                    fault_at=284790,
                    boot_outcome="brick",
                    nvm_state=failed_boot_state,
                )
            )
        self.assertEqual(
            boot_ctx.exception.invariant_name, "tfm_no_partial_magic"
        )
        self.assertIn("ns_staging", boot_ctx.exception.details["invalid_slots"])
        self.assertFalse(
            boot_ctx.exception.details["recovery_booted_valid_pair"]
        )

        erased_primary_state = self._build_multi_image_state(
            staging_magic=partial_magic,
            ns_exec_version=None,
        )
        with self.assertRaises(InvariantViolation) as pair_ctx:
            check_tfm_no_partial_magic(
                SimpleNamespace(
                    fault_at=284790,
                    boot_outcome="success",
                    nvm_state=erased_primary_state,
                )
            )
        self.assertIn("ns_staging", pair_ctx.exception.details["invalid_slots"])
        self.assertFalse(
            pair_ctx.exception.details["recovery_booted_valid_pair"]
        )

    def test_partial_magic_decoded_as_good_fails_even_when_recovery_boots(
        self,
    ) -> None:
        good_aligned_magic = mcuboot_expected_magic(32)
        self.assertEqual(boot_magic_decode(good_aligned_magic, align=32), "good")
        state = self._build_multi_image_state(
            staging_magic=good_aligned_magic,
            staging_pad=b"\xAA" * 8 + b"\xFF" * 8,
            align=32,
        )
        self.assertEqual(
            state["slots"]["ns_staging"]["magic_state"], "partial"
        )
        self.assertEqual(
            state["slots"]["ns_staging"]["mcuboot_magic"], "good"
        )
        with self.assertRaises(InvariantViolation) as ctx:
            check_tfm_no_partial_magic(
                SimpleNamespace(
                    fault_at=100,
                    boot_outcome="success",
                    nvm_state=state,
                )
            )
        self.assertEqual(ctx.exception.invariant_name, "tfm_no_partial_magic")
        self.assertEqual(ctx.exception.details["invalid_slots"], ["ns_staging"])
        self.assertEqual(
            ctx.exception.details["slot_magic"]["ns_staging"]["mcuboot_magic"],
            "good",
        )


if __name__ == "__main__":
    unittest.main()
