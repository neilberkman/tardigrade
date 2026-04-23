#!/usr/bin/env python3
"""Unit tests for instruction_skip fault type support."""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import textwrap
import unittest
import warnings
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RESC = ROOT / "scripts" / "run_runtime_fault_sweep.py"
sys.path.insert(0, str(SCRIPTS))

from fault_types import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES,
    FAULT_TYPE_NAME_TO_CODE,
    _fault_type_label,
)
from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from profile_loader import (  # noqa: E402
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    FaultSweepConfig,
    InstructionSkipConfig,
    ProfileError,
    VerificationProbeConfig,
    _find_clone_siblings,
    _is_glob_pattern,
    _match_symbol_query,
    _parse_verification_bypass_probe,
    _parse_instruction_skip_config,
    _parse_verification_probes,
    _strip_gcc_clone_suffixes,
    load_profile,
)
from thumb_instructions import (  # noqa: E402
    build_instruction_skip_patch_plan,
    enumerate_instruction_skip_addresses,
    is_thumb_32bit_first_halfword,
)


class InstructionSkipRegistrationTest(unittest.TestCase):
    """Verify instruction_skip is wired into the type registries."""

    def test_in_known_types(self) -> None:
        self.assertIn("instruction_skip", KNOWN_FAULT_TYPES)

    def test_in_implemented_types(self) -> None:
        self.assertIn("instruction_skip", IMPLEMENTED_FAULT_TYPES)

    def test_is_execute_only(self) -> None:
        self.assertIn("instruction_skip", EXECUTE_ONLY_FAULT_TYPES)

    def test_fault_type_code(self) -> None:
        self.assertEqual(FAULT_TYPE_NAME_TO_CODE["instruction_skip"], "i")

    def test_fault_type_label(self) -> None:
        self.assertEqual(_fault_type_label("i"), "instruction_skip")


class SymbolGlobMatchingTest(unittest.TestCase):
    """Unit tests for _is_glob_pattern and _match_symbol_query helpers."""

    def test_is_glob_detects_star(self) -> None:
        self.assertTrue(_is_glob_pattern("foo*"))

    def test_is_glob_detects_question(self) -> None:
        self.assertTrue(_is_glob_pattern("foo?bar"))

    def test_is_glob_detects_bracket(self) -> None:
        self.assertTrue(_is_glob_pattern("foo[ab]"))

    def test_is_glob_plain_string(self) -> None:
        self.assertFalse(_is_glob_pattern("foo_bar"))

    def test_is_glob_empty(self) -> None:
        self.assertFalse(_is_glob_pattern(""))

    def test_match_substring_without_glob(self) -> None:
        self.assertTrue(_match_symbol_query("Validate", "BOOT_META_ValidateSlotImage"))
        self.assertTrue(_match_symbol_query("Validate", "ValidateHash"))

    def test_match_substring_no_match(self) -> None:
        self.assertFalse(_match_symbol_query("Zzz", "BOOT_META_ValidateSlotImage"))

    def test_match_glob_star(self) -> None:
        self.assertTrue(_match_symbol_query("BOOT_META_Validate*", "BOOT_META_ValidateSlotImage"))
        self.assertTrue(
            _match_symbol_query(
                "BOOT_META_Validate*",
                "BOOT_META_ValidateSlotImage.part.3.constprop.8",
            )
        )

    def test_match_glob_star_no_match(self) -> None:
        self.assertFalse(_match_symbol_query("BOOT_META_Validate*", "Reset_Handler"))

    def test_match_glob_question(self) -> None:
        self.assertTrue(_match_symbol_query("Reset_Handle?", "Reset_Handler"))
        self.assertFalse(_match_symbol_query("Reset_Handle?", "Reset_Handler2"))

    def test_match_glob_is_case_sensitive(self) -> None:
        self.assertFalse(_match_symbol_query("reset*", "Reset_Handler"))

    def test_match_glob_full_wildcard(self) -> None:
        self.assertTrue(_match_symbol_query("*", "anything"))

    def test_match_glob_anchored(self) -> None:
        # fnmatch globs are anchored: "Validate*" does NOT match
        # "BOOT_META_ValidateSlotImage" because the prefix doesn't match.
        self.assertFalse(
            _match_symbol_query("Validate*", "BOOT_META_ValidateSlotImage")
        )
        # But substring match without glob does:
        self.assertTrue(
            _match_symbol_query("Validate", "BOOT_META_ValidateSlotImage")
        )


class GccCloneSuffixTest(unittest.TestCase):
    """Unit tests for compiler-clone-sibling symbol handling."""

    def test_strip_passthrough_for_plain_name(self) -> None:
        self.assertEqual(_strip_gcc_clone_suffixes("bootloader_main"), "bootloader_main")

    def test_strip_constprop(self) -> None:
        self.assertEqual(
            _strip_gcc_clone_suffixes("bootloader_main.constprop.0"),
            "bootloader_main",
        )

    def test_strip_part(self) -> None:
        self.assertEqual(_strip_gcc_clone_suffixes("helper.part.1"), "helper")

    def test_strip_isra(self) -> None:
        self.assertEqual(_strip_gcc_clone_suffixes("helper.isra.0"), "helper")

    def test_strip_cold(self) -> None:
        self.assertEqual(_strip_gcc_clone_suffixes("helper.cold.0"), "helper")

    def test_strip_cold_without_counter(self) -> None:
        # Some GCC versions emit bare ``.cold`` with no numeric suffix.
        self.assertEqual(_strip_gcc_clone_suffixes("helper.cold"), "helper")

    def test_strip_localalias(self) -> None:
        self.assertEqual(
            _strip_gcc_clone_suffixes("helper.localalias.0"),
            "helper",
        )

    def test_strip_lto_priv(self) -> None:
        self.assertEqual(_strip_gcc_clone_suffixes("helper.lto_priv.2"), "helper")

    def test_strip_chained_suffixes(self) -> None:
        self.assertEqual(
            _strip_gcc_clone_suffixes("helper.constprop.0.isra.1"),
            "helper",
        )

    def test_strip_does_not_eat_unrelated_dot_name(self) -> None:
        # ".data" style suffixes or user-defined dotted names must not be
        # stripped.  Only recognised GCC clone tags are removed.
        self.assertEqual(_strip_gcc_clone_suffixes("foo.bar.0"), "foo.bar.0")
        self.assertEqual(_strip_gcc_clone_suffixes("foo.section.0"), "foo.section.0")

    def test_strip_requires_trailing_digits(self) -> None:
        self.assertEqual(
            _strip_gcc_clone_suffixes("foo.constprop"),
            "foo.constprop",
        )

    def test_find_siblings_returns_clones_of_same_base(self) -> None:
        functions = [
            ("bootloader_main", 0x1000, 0x1200),
            ("bootloader_main.constprop.0", 0x1200, 0x1300),
            ("bootloader_main.part.1", 0x1300, 0x1380),
            ("unrelated_fn", 0x2000, 0x2100),
        ]
        siblings = _find_clone_siblings(
            "bootloader_main", functions, {"bootloader_main"}
        )
        sibling_names = [s[0] for s in siblings]
        self.assertEqual(
            sibling_names,
            ["bootloader_main.constprop.0", "bootloader_main.part.1"],
        )

    def test_find_siblings_skips_already_matched(self) -> None:
        functions = [
            ("helper", 0x1000, 0x1100),
            ("helper.constprop.0", 0x1100, 0x1180),
        ]
        siblings = _find_clone_siblings(
            "helper", functions, {"helper", "helper.constprop.0"}
        )
        self.assertEqual(siblings, [])

    def test_find_siblings_ignores_other_bases(self) -> None:
        functions = [
            ("helper", 0x1000, 0x1100),
            ("other_helper.constprop.0", 0x1100, 0x1180),
        ]
        siblings = _find_clone_siblings("helper", functions, {"helper"})
        self.assertEqual(siblings, [])


class InstructionSkipConfigTest(unittest.TestCase):
    """Validate InstructionSkipConfig construction and validation."""

    def test_defaults(self) -> None:
        cfg = InstructionSkipConfig()
        self.assertEqual(cfg.target_addresses, [])
        self.assertEqual(cfg.skip_count, 1)

    def test_valid_config(self) -> None:
        cfg = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x2000), (0x3000, 0x4000)],
            skip_count=2,
        )
        self.assertEqual(len(cfg.target_addresses), 2)
        self.assertEqual(cfg.target_addresses[0], (0x1000, 0x2000))
        self.assertEqual(cfg.skip_count, 2)

    def test_end_must_exceed_start(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            InstructionSkipConfig(target_addresses=[(0x2000, 0x1000)])
        self.assertIn("end", str(ctx.exception))
        self.assertIn("must be > start", str(ctx.exception))

    def test_equal_start_end_rejected(self) -> None:
        with self.assertRaises(ProfileError):
            InstructionSkipConfig(target_addresses=[(0x1000, 0x1000)])

    def test_start_must_be_halfword_aligned(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            InstructionSkipConfig(target_addresses=[(0x1001, 0x2000)])
        self.assertIn("halfword-aligned", str(ctx.exception))

    def test_skip_count_minimum_is_one(self) -> None:
        cfg = InstructionSkipConfig(skip_count=0)
        self.assertEqual(cfg.skip_count, 1)

    def test_skip_count_negative_clamped(self) -> None:
        cfg = InstructionSkipConfig(skip_count=-5)
        self.assertEqual(cfg.skip_count, 1)


class ParseInstructionSkipConfigTest(unittest.TestCase):
    """Test YAML parsing of instruction_skip_config."""

    def test_none_returns_none(self) -> None:
        self.assertIsNone(_parse_instruction_skip_config(None))

    def test_valid_yaml(self) -> None:
        raw = {
            "target_addresses": [
                {"start": "0x1000", "end": "0x2000"},
                {"start": "0x3000", "end": "0x3100"},
            ],
            "skip_count": 2,
        }
        cfg = _parse_instruction_skip_config(raw)
        self.assertIsNotNone(cfg)
        self.assertEqual(len(cfg.target_addresses), 2)
        self.assertEqual(cfg.target_addresses[0], (0x1000, 0x2000))
        self.assertEqual(cfg.target_addresses[1], (0x3000, 0x3100))
        self.assertEqual(cfg.skip_count, 2)

    def test_default_skip_count(self) -> None:
        raw = {"target_addresses": [{"start": "0x1000", "end": "0x2000"}]}
        cfg = _parse_instruction_skip_config(raw)
        self.assertEqual(cfg.skip_count, 1)

    def test_non_dict_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config("not a dict")

    def test_non_list_target_addresses_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config({"target_addresses": "not a list"})

    def test_invalid_region_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": ["not a dict"]}
            )

    def test_missing_start_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": [{"end": "0x2000"}]}
            )

    def test_missing_end_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config(
                {"target_addresses": [{"start": "0x1000"}]}
            )

    def test_invalid_skip_count_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_instruction_skip_config({"skip_count": -1})


class VerificationProbeConfigTest(unittest.TestCase):
    def test_parse_verification_probes(self) -> None:
        probes = _parse_verification_probes(
            [
                {
                    "symbol": "bootutil_img_validate",
                    "return_register": "r0",
                    "success_value": 0,
                    "label": "hash_validation",
                },
                {
                    "symbol": "boot_validate_slot.isra.3",
                    "return_register": "w0",
                    "success_value": 0,
                    "label": "slot_validation",
                },
            ]
        )
        self.assertEqual([p.label for p in probes], ["hash_validation", "slot_validation"])
        self.assertEqual(probes[0].return_register, "r0")
        self.assertEqual(probes[1].return_register, "r0")
        self.assertEqual(probes[1].return_register_index, 0)

    def test_duplicate_labels_raise(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_verification_probes(
                [
                    {"symbol": "a", "label": "dup"},
                    {"symbol": "b", "label": "dup"},
                ]
            )

    def test_invalid_register_raises(self) -> None:
        with self.assertRaises(ProfileError):
            _parse_verification_probes(
                [{"symbol": "bootutil_img_validate", "return_register": "pc"}]
            )

    def test_parse_verification_bypass_probe_alias(self) -> None:
        probes = _parse_verification_bypass_probe(
            {
                "enabled": True,
                "probe_functions": [
                    {
                        "symbol": "bootutil_img_validate",
                        "expected_success_value": 0,
                        "layer": "hash_validation",
                    },
                    {
                        "symbol": "boot_validate_slot.isra.3",
                        "return_register": "w0",
                        "expected_success_value": 0,
                        "layer": "slot_validation",
                    },
                ],
            }
        )
        self.assertEqual([p.label for p in probes], ["hash_validation", "slot_validation"])
        self.assertEqual(probes[0].success_value, 0)
        self.assertEqual(probes[1].return_register, "r0")

    def test_disabled_verification_bypass_probe_alias_returns_empty(self) -> None:
        probes = _parse_verification_bypass_probe(
            {
                "enabled": False,
                "probe_functions": [
                    {"symbol": "bootutil_img_validate", "layer": "hash_validation"}
                ],
            }
        )
        self.assertEqual(probes, [])

    def test_probe_summary_tracks_first_return_for_classification(self) -> None:
        resc_text = RESC.read_text(encoding="utf-8")
        self.assertIn("first_return_value", resc_text)
        self.assertIn("first_bypassed", resc_text)
        self.assertIn("'bypassed': bool(capture.get('first_bypassed'))", resc_text)


class InstructionSkipSymbolResolutionTest(unittest.TestCase):
    EXAMPLE_ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"
    ZERO_SIZE_ELF = (
        ROOT / "results" / "oss_validation" / "assets" / "oss_mcuboot_mcuboot_swap_current_guard.elf"
    )

    def _write_profile(self, tempdir: Path, target_block: str) -> Path:
        profile_path = tempdir / "profile.yaml"
        profile_path.write_text(
            textwrap.dedent(
                f"""
                schema_version: 1
                name: instruction_skip_symbol_profile
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: {self.EXAMPLE_ELF}
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    primary: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                fault_sweep:
                  fault_types: [instruction_skip]
                  evaluation_mode: execute
                  instruction_skip_config:
                    target_addresses:
                {target_block}
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return profile_path

    def test_load_profile_resolves_single_symbol_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                "      - { symbol: Reset }",
            )
            stderr = StringIO()
            with redirect_stderr(stderr):
                profile = load_profile(profile_path)
        self.assertEqual(
            profile.fault_sweep.instruction_skip_config.target_addresses,
            [(0x10000044, 0x100000F8)],
        )
        self.assertIn("Resolved 'Reset' -> Reset_Handler", stderr.getvalue())
        self.assertIn("89 fault points", stderr.getvalue())

    def test_symbol_target_resolves_multiple_matches(self) -> None:
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "Handler"}]},
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000040, 0x10000042), (0x10000044, 0x100000F8)],
        )

    def test_symbol_target_no_match_lists_available_symbols(self) -> None:
        with self.assertRaises(ProfileError) as ctx:
            _parse_instruction_skip_config(
                {"target_addresses": [{"symbol": "NoSuchFunction"}]},
                bootloader_elf=str(self.EXAMPLE_ELF),
            )
        message = str(ctx.exception)
        self.assertIn("Available function symbols:", message)
        self.assertIn("Default_Handler", message)
        self.assertIn("Reset_Handler", message)

    def test_mixed_symbol_and_explicit_ranges_are_allowed(self) -> None:
        cfg = _parse_instruction_skip_config(
            {
                "target_addresses": [
                    {"symbol": "Default"},
                    {"start": "0x2000", "end": "0x2008"},
                ]
            },
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000040, 0x10000042), (0x2000, 0x2008)],
        )

    def test_zero_size_function_uses_next_function_start(self) -> None:
        if not self.ZERO_SIZE_ELF.exists():
            self.skipTest("zero-size ELF fixture not present")
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "arch_cpu_idle"}]},
            bootloader_elf=str(self.ZERO_SIZE_ELF),
        )
        self.assertEqual(cfg.target_addresses, [(0x1F38, 0x1F54)])

    def test_glob_star_matches_multiple_symbols(self) -> None:
        """A trailing glob ``*_Handler`` should match both Default_Handler and Reset_Handler."""
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "*_Handler"}]},
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000040, 0x10000042), (0x10000044, 0x100000F8)],
        )

    def test_glob_prefix_star_matches(self) -> None:
        """``Reset*`` should match Reset_Handler."""
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "Reset*"}]},
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000044, 0x100000F8)],
        )

    def test_glob_question_mark_matches(self) -> None:
        """``Reset_Handle?`` should match Reset_Handler."""
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "Reset_Handle?"}]},
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000044, 0x100000F8)],
        )

    def test_glob_no_match_raises(self) -> None:
        """A glob that matches nothing should raise with available symbols."""
        with self.assertRaises(ProfileError) as ctx:
            _parse_instruction_skip_config(
                {"target_addresses": [{"symbol": "Zzz*"}]},
                bootloader_elf=str(self.EXAMPLE_ELF),
            )
        self.assertIn("Available function symbols:", str(ctx.exception))

    def test_exact_match_still_works_with_no_glob(self) -> None:
        """An exact symbol name without glob chars uses substring matching."""
        cfg = _parse_instruction_skip_config(
            {"target_addresses": [{"symbol": "Reset_Handler"}]},
            bootloader_elf=str(self.EXAMPLE_ELF),
        )
        self.assertEqual(
            cfg.target_addresses,
            [(0x10000044, 0x100000F8)],
        )


class FaultSweepConfigIntegrationTest(unittest.TestCase):
    """Verify instruction_skip_config integrates into FaultSweepConfig."""

    def test_default_is_none(self) -> None:
        fs = FaultSweepConfig()
        self.assertIsNone(fs.instruction_skip_config)

    def test_can_set_config(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x2000)], skip_count=1
        )
        probe = VerificationProbeConfig(
            symbol="bootutil_img_validate",
            return_register="r0",
            return_register_index=0,
            success_value=0,
            label="hash_validation",
        )
        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=isc,
            verification_probes=[probe],
        )
        self.assertIsNotNone(fs.instruction_skip_config)
        self.assertEqual(fs.instruction_skip_config.target_addresses, [(0x1000, 0x2000)])
        self.assertEqual(fs.verification_probes[0].label, "hash_validation")


class InstructionSkipPlannerRangeFilterTest(unittest.TestCase):
    """Instruction-skip addresses must honor fault_start/fault_end."""

    EXAMPLE_ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"

    def test_fault_start_end_narrow_symbol_range(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_range_filter_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        primary: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ symbol: Reset }}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=0),
            fault_start=0x10000048,
            fault_end=0x1000004C,
        )

        self.assertEqual(plan.fault_points, [0x10000048, 0x1000004A])
        self.assertEqual(plan.fault_types_list, ["i:0x10000048", "i:0x1000004A"])


class InstructionSkipQuickSamplingTest(unittest.TestCase):
    EXAMPLE_ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"

    def test_quick_samples_each_target_range(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_quick_sampling_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ start: 0x1000, end: 0x1014 }}
                          - {{ start: 0x2000, end: 0x2014 }}
                          - {{ start: 0x3000, end: 0x3006 }}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

        with mock.patch("fault_plan.make_elf_halfword_reader", return_value=None):
            plan = build_fault_plan(
                profile,
                CalibrationInputs(max_writes=0),
                quick=True,
            )

        self.assertEqual(
            plan.fault_points,
            [
                0x1000,
                0x1004,
                0x1008,
                0x100C,
                0x1012,
                0x2000,
                0x2004,
                0x2008,
                0x200C,
                0x2012,
                0x3000,
                0x3002,
                0x3004,
            ],
        )
        self.assertEqual(
            plan.fault_types_list,
            [
                "i:0x1000",
                "i:0x1004",
                "i:0x1008",
                "i:0x100C",
                "i:0x1012",
                "i:0x2000",
                "i:0x2004",
                "i:0x2008",
                "i:0x200C",
                "i:0x2012",
                "i:0x3000",
                "i:0x3002",
                "i:0x3004",
            ],
        )

    def test_quick_prioritizes_branch_and_compare_sites(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_quick_priority_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ start: 0x1000, end: 0x1014 }}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

        mapping = {
            0x1000: 0x6800,
            0x1002: 0x6801,
            0x1004: 0x6802,
            0x1006: 0xE001,
            0x1008: 0x6804,
            0x100A: 0x2C01,
            0x100C: 0x6806,
            0x100E: 0x6807,
            0x1010: 0x6808,
            0x1012: 0x6809,
        }

        def read_halfword(addr: int) -> int:
            return mapping[int(addr)]

        with mock.patch("fault_plan.make_elf_halfword_reader", return_value=read_halfword):
            plan = build_fault_plan(
                profile,
                CalibrationInputs(max_writes=0),
                quick=True,
            )

        self.assertEqual(len(plan.fault_points), 5)
        self.assertIn(0x1006, plan.fault_points)
        self.assertIn(0x100A, plan.fault_points)

    def test_quick_keeps_tail_branch_and_compare_sites(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_quick_tail_priority_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    flash_backend: faultFlash
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ start: 0x1000, end: 0x1016 }}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)

        mapping = {
            0x1000: 0x6800,
            0x1002: 0xE001,
            0x1004: 0x6802,
            0x1006: 0x2801,
            0x1008: 0x6804,
            0x100A: 0x6805,
            0x100C: 0xB108,
            0x100E: 0x6807,
            0x1010: 0x4283,
            0x1012: 0x6809,
            0x1014: 0x680A,
        }

        def read_halfword(addr: int) -> int:
            return mapping[int(addr)]

        with mock.patch("fault_plan.make_elf_halfword_reader", return_value=read_halfword):
            plan = build_fault_plan(
                profile,
                CalibrationInputs(max_writes=0),
                quick=True,
            )

        self.assertIn(0x100C, plan.fault_points)
        self.assertIn(0x1010, plan.fault_points)


class VerificationProbeRobotVarsTest(unittest.TestCase):
    EXAMPLE_ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"

    def test_robot_vars_emit_verification_probe_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_verification_probe_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ symbol: Reset }}
                      verification_probes:
                        - symbol: bootutil_img_validate
                          return_register: r0
                          success_value: 0
                          label: hash_validation
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
        payload = next(
            rv.split(":", 1)[1]
            for rv in robot_vars
            if rv.startswith("VERIFICATION_PROBES:")
        )
        decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
        self.assertEqual(decoded[0]["label"], "hash_validation")
        self.assertEqual(decoded[0]["return_register"], "r0")

    def test_verification_bypass_probe_alias_emits_same_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_verification_bypass_probe_alias_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ symbol: Reset }}
                      verification_bypass_probe:
                        enabled: true
                        probe_functions:
                          - symbol: bootutil_img_validate
                            expected_success_value: 0
                            layer: hash_validation
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)
            robot_vars = profile.robot_vars(ROOT)
        payload = next(
            rv.split(":", 1)[1]
            for rv in robot_vars
            if rv.startswith("VERIFICATION_PROBES:")
        )
        decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
        self.assertEqual(decoded[0]["label"], "hash_validation")
        self.assertEqual(decoded[0]["success_value"], 0)

    def test_new_and_old_verification_probe_configs_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(
                textwrap.dedent(
                    f"""
                    schema_version: 1
                    name: instruction_skip_verification_probe_conflict_profile
                    platform: platforms/cortex_m4_flash_fast.repl
                    bootloader:
                      elf: {self.EXAMPLE_ELF}
                      entry: 0x10000000
                    memory:
                      sram: {{ start: 0x20000000, end: 0x20020000 }}
                      write_granularity: 4
                      slots:
                        exec: {{ base: 0x10000000, size: 0x1000 }}
                        staging: {{ base: 0x10001000, size: 0x1000 }}
                    fault_sweep:
                      fault_types: [instruction_skip]
                      evaluation_mode: execute
                      instruction_skip_config:
                        target_addresses:
                          - {{ symbol: Reset }}
                      verification_probes:
                        - symbol: bootutil_img_validate
                          label: hash_validation
                      verification_bypass_probe:
                        enabled: true
                        probe_functions:
                          - symbol: boot_validate_slot
                            layer: slot_validation
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ProfileError):
                load_profile(profile_path)


class VerificationProbeProfileFixtureTest(unittest.TestCase):
    def test_nxboot_probe_profile_loads(self) -> None:
        profile = load_profile(ROOT / "profiles" / "nxboot_style_instruction_skip_probe.yaml")
        self.assertEqual(profile.fault_sweep.verification_probes[0].label, "image_validation")
        self.assertEqual(profile.fault_sweep.verification_probes[0].success_value, 0)

    def test_mcuboot_probe_profile_loads(self) -> None:
        profile = load_profile(
            ROOT / "profiles" / "mcuboot_head_move_nrf52_verify_instruction_skip_probe.yaml"
        )
        labels = [p.label for p in profile.fault_sweep.verification_probes]
        self.assertEqual(labels, ["hash_validation", "slot_validation"])
        self.assertEqual(profile.fault_sweep.verification_probes[0].success_value, 0)
        self.assertEqual(profile.fault_sweep.verification_probes[1].success_value, 0)


class BackendCompatWarningTest(unittest.TestCase):
    """Verify warnings for instruction_skip config mismatches."""

    def test_warn_config_without_fault_type(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        isc = InstructionSkipConfig(target_addresses=[(0x1000, 0x2000)])
        fs = FaultSweepConfig(
            fault_types=["power_loss"],
            instruction_skip_config=isc,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [x for x in w if "instruction_skip_config" in str(x.message)]
            self.assertTrue(
                len(skip_warnings) > 0,
                "Expected warning about instruction_skip_config without fault type",
            )

    def test_warn_fault_type_without_config(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=None,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [x for x in w if "instruction_skip" in str(x.message)]
            self.assertTrue(
                len(skip_warnings) > 0,
                "Expected warning about instruction_skip without config",
            )

    def test_no_warn_when_both_present(self) -> None:
        from profile_loader import _warn_fault_backend_compat

        isc = InstructionSkipConfig(target_addresses=[(0x1000, 0x2000)])
        fs = FaultSweepConfig(
            fault_types=["instruction_skip"],
            instruction_skip_config=isc,
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _warn_fault_backend_compat(fs, "cortex_m4_flash_fast", "faultFlash")
            skip_warnings = [
                x for x in w
                if "instruction_skip" in str(x.message)
            ]
            self.assertEqual(
                len(skip_warnings), 0,
                "No instruction_skip warnings expected when both type and config are set",
            )


class FaultPointGenerationTest(unittest.TestCase):
    """Verify instruction_skip fault points are generated from address ranges."""

    @staticmethod
    def _reader(mapping):
        def read_halfword(addr):
            if addr not in mapping:
                raise KeyError(addr)
            return mapping[addr]

        return read_halfword

    @classmethod
    def _enumerate(cls, isc: InstructionSkipConfig, mapping):
        sc = isc.skip_count if isc.skip_count > 0 else 1
        read_halfword = cls._reader(mapping)
        addrs = []
        for start, end in isc.target_addresses:
            addrs.extend(
                enumerate_instruction_skip_addresses(
                    read_halfword,
                    start,
                    end,
                    skip_count=sc,
                )
            )
        return addrs

    def test_is_thumb_32bit_first_halfword(self) -> None:
        self.assertTrue(is_thumb_32bit_first_halfword(0xF000))
        self.assertTrue(is_thumb_32bit_first_halfword(0xF800))
        self.assertTrue(is_thumb_32bit_first_halfword(0xE800))
        self.assertFalse(is_thumb_32bit_first_halfword(0x4770))
        self.assertFalse(is_thumb_32bit_first_halfword(0xBF00))
        self.assertFalse(is_thumb_32bit_first_halfword(0xB500))

    def test_address_enumeration(self) -> None:
        """Mixed-width instruction ranges should skip second halfwords."""
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1010)],
            skip_count=1,
        )
        mapping = {
            0x1000: 0xB500,
            0x1002: 0xF000,
            0x1004: 0xF800,
            0x1006: 0x4770,
            0x1008: 0xF000,
            0x100A: 0xF800,
            0x100C: 0xBF00,
            0x100E: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(addrs, [0x1000, 0x1002, 0x1006, 0x1008, 0x100C, 0x100E])

    def test_multiple_ranges(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1004), (0x2000, 0x2006)],
        )
        mapping = {
            0x1000: 0xB500,
            0x1002: 0x4770,
            0x2000: 0xF000,
            0x2002: 0xF800,
            0x2004: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(addrs, [0x1000, 0x1002, 0x2000, 0x2004])

    def test_fault_type_code_format(self) -> None:
        """Fault type codes should be 'i:0xADDR' format."""
        addr = 0x1234
        code = "i:0x{:X}".format(addr)
        self.assertEqual(code, "i:0x1234")
        # Parse it back
        parts = code.split(":")
        self.assertEqual(parts[0], "i")
        self.assertEqual(int(parts[1], 0), 0x1234)

    def test_skip_count_boundary_no_overflow(self) -> None:
        """With skip_count=3, addresses within 4 bytes of region_end must be excluded.

        Patching 3 consecutive halfwords (6 bytes) from start address must
        not extend past region_end.  So the last valid start is
        region_end - skip_count * 2 (exclusive upper bound of range).
        """
        # Region: 0x1000..0x100C (12 bytes = 6 halfwords)
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x100C)],
            skip_count=3,
        )
        mapping = {
            0x1000: 0xB500,
            0x1002: 0xF000,
            0x1004: 0xF800,
            0x1006: 0x4770,
            0x1008: 0xBF00,
            0x100A: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        # Instructions are [16-bit, 32-bit, 16-bit, 16-bit, 16-bit].
        # A 3-instruction skip fits at 0x1000, 0x1002, and 0x1006 only.
        self.assertEqual(len(addrs), 3)
        self.assertEqual(addrs[0], 0x1000)
        self.assertEqual(addrs[-1], 0x1006)

    def test_skip_count_1_unchanged(self) -> None:
        """skip_count=1 should still hit every real instruction boundary."""
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1008)],
            skip_count=1,
        )
        mapping = {
            0x1000: 0xB500,
            0x1002: 0x4770,
            0x1004: 0xBF00,
            0x1006: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(len(addrs), 4)
        self.assertEqual(addrs[-1], 0x1006)

    def test_skip_count_equals_region_size(self) -> None:
        """When skip_count covers the entire region, only one address is valid."""
        # Two 16-bit instructions, skip_count=2.
        isc = InstructionSkipConfig(
            target_addresses=[(0x2000, 0x2004)],
            skip_count=2,
        )
        mapping = {
            0x2000: 0xB500,
            0x2002: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(addrs, [0x2000])

    def test_skip_count_exceeds_region(self) -> None:
        """When skip_count > region halfwords, no addresses should be enumerated."""
        # Two 16-bit instructions, skip_count=3.
        isc = InstructionSkipConfig(
            target_addresses=[(0x3000, 0x3004)],
            skip_count=3,
        )
        mapping = {
            0x3000: 0xB500,
            0x3002: 0x4770,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(addrs, [])

    def test_skip_count_treats_32bit_instruction_as_single_instruction(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x4000, 0x4008)],
            skip_count=2,
        )
        mapping = {
            0x4000: 0xF000,
            0x4002: 0xF800,
            0x4004: 0x4770,
            0x4006: 0xBF00,
        }
        addrs = self._enumerate(isc, mapping)
        self.assertEqual(addrs, [0x4000, 0x4004])

    def test_patch_plan_nops_both_halfwords_of_32bit_instruction(self) -> None:
        mapping = {
            0x5000: 0xF000,
            0x5002: 0xF800,
        }
        patch = build_instruction_skip_patch_plan(
            self._reader(mapping),
            0x5000,
            1,
            patch_model="nop",
        )
        self.assertTrue(patch["supported"])
        self.assertEqual(patch["patched_addresses"], [0x5000, 0x5002])
        self.assertEqual(patch["original_halfwords"], [0xF000, 0xF800])
        self.assertEqual(patch["patched_halfwords"], [0xBF00, 0xBF00])

    def test_patch_plan_skip_count_two_nops_two_instructions(self) -> None:
        mapping = {
            0x6000: 0xF000,
            0x6002: 0xF800,
            0x6004: 0x4770,
        }
        patch = build_instruction_skip_patch_plan(
            self._reader(mapping),
            0x6000,
            2,
            patch_model="nop",
        )
        self.assertTrue(patch["supported"])
        self.assertEqual(patch["patched_addresses"], [0x6000, 0x6002, 0x6004])
        self.assertEqual(patch["patched_halfwords"], [0xBF00, 0xBF00, 0xBF00])


if __name__ == "__main__":
    unittest.main()
