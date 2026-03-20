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

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RESC = ROOT / "scripts" / "run_runtime_fault_sweep.resc"
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
    _parse_verification_bypass_probe,
    _parse_instruction_skip_config,
    _parse_verification_probes,
    load_profile,
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
        self.assertIn("90 fault points", stderr.getvalue())

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
    def _enumerate(isc: InstructionSkipConfig):
        """Replicate the enumeration logic from audit_bootloader.py."""
        sc = isc.skip_count if isc.skip_count > 0 else 1
        addrs = []
        for start, end in isc.target_addresses:
            stop = end - (sc - 1) * 2
            for addr in range(start, max(stop, start), 2):
                addrs.append(addr)
        return addrs

    def test_address_enumeration(self) -> None:
        """Each halfword in target ranges should produce one fault point."""
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1010)],
            skip_count=1,
        )
        # 0x1010 - 0x1000 = 16 bytes = 8 halfwords
        addrs = self._enumerate(isc)
        self.assertEqual(len(addrs), 8)
        self.assertEqual(addrs[0], 0x1000)
        self.assertEqual(addrs[-1], 0x100E)

    def test_multiple_ranges(self) -> None:
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1004), (0x2000, 0x2006)],
        )
        addrs = []
        for start, end in isc.target_addresses:
            for addr in range(start, end, 2):
                addrs.append(addr)
        # 2 halfwords + 3 halfwords = 5
        self.assertEqual(len(addrs), 5)

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
        addrs = self._enumerate(isc)
        # skip_count=3 means each fault patches 3 halfwords (6 bytes).
        # Last safe start: 0x100C - 3*2 = 0x1006.
        # Valid starts: 0x1000, 0x1002, 0x1004, 0x1006 = 4 addresses.
        self.assertEqual(len(addrs), 4)
        self.assertEqual(addrs[0], 0x1000)
        self.assertEqual(addrs[-1], 0x1006)
        # Verify that the last address + skip_count*2 does NOT exceed region_end
        for a in addrs:
            self.assertLessEqual(a + 3 * 2, 0x100C)

    def test_skip_count_1_unchanged(self) -> None:
        """skip_count=1 should behave identically to the original logic."""
        isc = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x1008)],
            skip_count=1,
        )
        addrs = self._enumerate(isc)
        self.assertEqual(len(addrs), 4)
        self.assertEqual(addrs[-1], 0x1006)

    def test_skip_count_equals_region_size(self) -> None:
        """When skip_count covers the entire region, only one address is valid."""
        # 4 bytes = 2 halfwords, skip_count=2
        isc = InstructionSkipConfig(
            target_addresses=[(0x2000, 0x2004)],
            skip_count=2,
        )
        addrs = self._enumerate(isc)
        self.assertEqual(addrs, [0x2000])

    def test_skip_count_exceeds_region(self) -> None:
        """When skip_count > region halfwords, no addresses should be enumerated."""
        # 4 bytes = 2 halfwords, skip_count=3
        isc = InstructionSkipConfig(
            target_addresses=[(0x3000, 0x3004)],
            skip_count=3,
        )
        addrs = self._enumerate(isc)
        self.assertEqual(addrs, [])


if __name__ == "__main__":
    unittest.main()
