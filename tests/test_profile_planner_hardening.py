#!/usr/bin/env python3
"""Regression coverage for profile, planner, and runtime registry contracts."""

from __future__ import annotations

import base64
import ast
import contextlib
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fault_inject import BootloaderRegionConfig  # noqa: E402
from fault_plan import CalibrationInputs, build_fault_plan  # noqa: E402
from profile_loader import (  # noqa: E402
    InitialStateConfig,
    ProfileError,
    load_profile,
)


BASE_PROFILE = """
schema_version: 1
name: hardening_test
description: public regression fixture
platform: platforms/cortex_m4_flash_fast.repl
bootloader:
  elf: examples/vulnerable_ota/firmware.elf
  entry: 0x10000000
memory:
  sram: { start: 0x20000000, end: 0x20020000 }
  write_granularity: 4
  slots:
    exec: { base: 0x10000000, size: 0x1000 }
    staging: { base: 0x10001000, size: 0x1000 }
images:
  staging: examples/vulnerable_ota/firmware.bin
success_criteria:
  vtor_in_slot: exec
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
expect:
  should_find_issues: false
"""


class ProfilePlannerHardeningTest(unittest.TestCase):
    def _load(self, suffix: str = "", *, strict: bool = False):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(
                textwrap.dedent(BASE_PROFILE + "\n" + suffix),
                encoding="utf-8",
            )
            return load_profile(path, strict=strict)

    def test_unknown_main_fault_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "unknown_fault"):
            self._load(
                """
fault_sweep:
  fault_types: [unknown_fault]
"""
            )

    def test_explicit_empty_main_fault_types_disable_write_faults(self) -> None:
        profile = self._load(
            """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: []
  boot_cycles: 3
  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py
  hook_fault:
    enabled: true
    fault_types: [power_loss]
    max_points: 2
"""
        )
        self.assertEqual(profile.fault_sweep.fault_types, [])
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=8),
            quick=False,
        )
        self.assertEqual(plan.fault_types_list, ["h:0:w", "h:1:w"])

    def test_profile_name_accepts_safe_identifier_punctuation(self) -> None:
        profile = self._load('name: "Release-1.2_alpha"')
        self.assertEqual(profile.name, "Release-1.2_alpha")

    def test_initial_state_names_cannot_escape_work_directories(self) -> None:
        for strict in (False, True):
            with self.subTest(strict=strict), self.assertRaisesRegex(
                ProfileError,
                "initial_states.*safe identifier",
            ):
                self._load(
                    """
initial_states:
  - name: ../../outside
""",
                    strict=strict,
                )

    def test_profile_name_rejects_path_tokens(self) -> None:
        for value in ("../escape", "nested/escape", "nested\\escape"):
            with self.subTest(value=value), self.assertRaisesRegex(
                ProfileError,
                "name: expected safe identifier",
            ):
                self._load('name: "{}"'.format(value.replace("\\", "\\\\")))

    def test_quoted_false_boolean_is_rejected_even_in_strict_mode(self) -> None:
        with self.assertRaisesRegex(ProfileError, "expected boolean"):
            self._load(
                """
success_criteria:
  vtor_in_slot: exec
  image_hash: "false"
""",
                strict=True,
            )

    def test_quoted_false_campaign_enable_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "multi_fault.enabled.*boolean"):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  multi_fault:
    enabled: "false"
"""
            )

    def test_strict_partial_staging_explicit_true_remains_enabled(self) -> None:
        profile = self._load(
            """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  partial_staging:
    enabled: true
""",
            strict=True,
        )
        self.assertEqual(profile.fault_sweep.partial_staging, {"enabled": True})

    def test_strict_partial_staging_explicit_false_is_disabled(self) -> None:
        profile = self._load(
            """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  partial_staging:
    enabled: false
""",
            strict=True,
        )
        self.assertIsNone(profile.fault_sweep.partial_staging)

    def test_strict_partial_staging_enabled_requires_boolean(self) -> None:
        with self.assertRaisesRegex(
            ProfileError,
            "partial_staging.enabled: expected boolean",
        ):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  partial_staging:
    enabled: "false"
""",
                strict=True,
            )

    def test_multi_faults_per_run_has_resource_ceiling(self) -> None:
        with self.assertRaisesRegex(ProfileError, "max_faults_per_run exceeds"):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  multi_fault:
    enabled: true
    max_faults_per_run: 65
"""
            )

    def test_explicit_multi_fault_sequences_cannot_exceed_max_pairs(self) -> None:
        with self.assertRaisesRegex(ProfileError, "exceeding max_pairs=1"):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  multi_fault:
    enabled: true
    strategy: explicit
    max_pairs: 1
    sequences:
      - [0, 1]
      - [2, 3]
"""
            )

    def test_classification_only_fault_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "classification label"):
            self._load(
                """
fault_sweep:
  fault_types: [bootloader_region_write]
"""
            )

    def test_duplicate_fault_types_are_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "duplicate fault type"):
            self._load(
                """
fault_sweep:
  max_writes: 2
  fault_types: [power_loss, power_loss]
"""
            )

    def test_known_but_unsupported_phase2_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "unsupported recovery-phase"):
            self._load(
                """
fault_sweep:
  fault_types: [power_loss]
  phase2_fault:
    enabled: true
    fault_types: [command_drop]
"""
            )

    def test_top_level_bootloader_region_is_canonical(self) -> None:
        profile = self._load(
            """
bootloader_region: { base: 0x10000000, size: 0x800 }
"""
        )
        self.assertIs(profile.bootloader_region, profile.memory.bootloader_region)
        self.assertEqual(profile.bootloader_region.base, 0x10000000)
        variables = profile.robot_vars(ROOT)
        self.assertIn("BOOTLOADER_REGION_BASE:0x10000000", variables)
        self.assertIn("BOOTLOADER_REGION_SIZE:0x00000800", variables)

    def test_memory_bootloader_region_remains_compatible(self) -> None:
        profile = self._load(
            """
memory:
  sram: { start: 0x20000000, end: 0x20020000 }
  write_granularity: 4
  bootloader_region: { base: 0x10000000, size: 0x800 }
  slots:
    exec: { base: 0x10000000, size: 0x1000 }
    staging: { base: 0x10001000, size: 0x1000 }
"""
        )
        self.assertIs(profile.bootloader_region, profile.memory.bootloader_region)

    def test_conflicting_bootloader_regions_are_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "conflicts"):
            self._load(
                """
bootloader_region: { base: 0x10000000, size: 0x800 }
memory:
  sram: { start: 0x20000000, end: 0x20020000 }
  write_granularity: 4
  bootloader_region: { base: 0x10000000, size: 0x400 }
  slots:
    exec: { base: 0x10000000, size: 0x1000 }
    staging: { base: 0x10001000, size: 0x1000 }
"""
            )

    def test_nvs_example_generates_variants_without_attribute_error(self) -> None:
        profile = load_profile(ROOT / "examples/nvs_config_migration/profile.yaml")
        plan = build_fault_plan(profile, CalibrationInputs(max_writes=2))
        nvs_codes = [code for code in plan.fault_types_list or [] if code.startswith("nv:")]
        self.assertEqual(nvs_codes, ["nv:{}".format(i) for i in range(8)])

    def test_nvs_tuning_values_drive_plan_and_runtime_transport(self) -> None:
        profile = self._load(
            """
nvs_region: { address: 0x10002000, size: 0x1000 }
fault_sweep:
  max_writes: 1
  fault_types: [nvs_corruption]
  nvs_corruption:
    enabled: true
    modes: [bit_flip, partial_erase, truncate, scramble]
    bit_flip_counts: [2, 7]
    erase_fractions: [0.25, 0.75]
    truncate_offsets: [8, null]
    seed: 19
"""
        )
        expected = [
            {"mode": "bit_flip", "bit_flip_count": 2},
            {"mode": "bit_flip", "bit_flip_count": 7},
            {"mode": "partial_erase", "erase_fraction": 0.25},
            {"mode": "partial_erase", "erase_fraction": 0.75},
            {"mode": "truncate", "truncate_offset": 8},
            {"mode": "truncate", "truncate_offset": None},
            {"mode": "scramble"},
        ]
        self.assertEqual(profile.fault_sweep.nvs_corruption.variant_specs(), expected)
        plan = build_fault_plan(profile, CalibrationInputs(max_writes=1))
        self.assertEqual(
            [code for code in plan.fault_types_list or [] if code.startswith("nv:")],
            ["nv:{}".format(i) for i in range(len(expected))],
        )
        encoded = next(
            value.split(":", 1)[1]
            for value in profile.robot_vars(ROOT)
            if value.startswith("NVS_CORRUPTION_VARIANTS_B64:")
        )
        self.assertEqual(json.loads(base64.b64decode(encoded)), expected)

    def test_timed_bit_corruption_is_encoded_as_declared(self) -> None:
        profile = self._load(
            """
fault_sweep:
  max_writes: 3
  fault_types: [timed_bit_corruption]
  timed_bit_corruption_config:
    pairs:
      - trigger: { address: 0x10000100 }
        corrupt_address: 0x10001000
        bit_flips: 2
"""
        )
        plan = build_fault_plan(profile, CalibrationInputs(max_writes=3))
        self.assertEqual(plan.fault_points, [0x10000100])
        self.assertEqual(
            plan.fault_types_list,
            ["tb:0x10000100:0x10001000:2"],
        )

    def test_timed_bit_corruption_symbol_trigger_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "symbol is not supported"):
            self._load(
                """
fault_sweep:
  max_writes: 1
  fault_types: [timed_bit_corruption]
  timed_bit_corruption_config:
    pairs:
      - trigger: { symbol: verify_image }
        corrupt_address: 0x10001000
"""
            )

    def test_fault_end_cannot_expand_calibrated_write_domain(self) -> None:
        profile = self._load()
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=3),
            fault_end=100000,
        )
        self.assertEqual(plan.fault_points, [0, 1, 2])

    def test_combined_fault_plan_has_one_total_allocation_ceiling(self) -> None:
        profile = self._load(
            """
fault_sweep:
  max_writes: 3
  fault_types: [power_loss, bit_corruption]
"""
        )
        with mock.patch("fault_plan.MAX_PROFILE_FAULT_POINTS", 3):
            with self.assertRaisesRegex(ProfileError, "total points"):
                build_fault_plan(profile, CalibrationInputs(max_writes=3))

    def test_fixed_bound_otp_profile_generates_blow_nop_points(self) -> None:
        profile = load_profile(ROOT / "profiles/firmware_otp_blow_nop_harness.yaml")
        plan = build_fault_plan(
            profile,
            CalibrationInputs(max_writes=100, total_otp_blows=0),
        )
        self.assertEqual(plan.fault_points, [0, 1, 2, 3, 4])
        self.assertEqual(plan.fault_types_list, ["on"] * 5)

    def test_initial_state_resolution_preserves_all_execution_fields(self) -> None:
        profile = self._load(
            """
nvm_controller: nvmController
otp_peripheral: otp
bootloader_region: { base: 0x10000000, size: 0x800 }
boot_register_pre_writes:
  - { address: 0x40000000, value: 1 }
boot_registers:
  - { address: 0x40000000, name: status }
write_order_constraints:
  - first: { start: 0x10000000, size: 4 }
    then: { start: 0x10000004, size: 4 }
"""
        )
        multi_component_marker = object()
        profile.multi_component = multi_component_marker
        resolved = profile.resolve_initial_state(InitialStateConfig(name="seeded"))
        self.assertEqual(resolved.nvm_controller, "nvmController")
        self.assertEqual(resolved.otp_peripheral, "otp")
        self.assertIs(resolved.multi_component, multi_component_marker)
        self.assertIs(resolved.bootloader_region, profile.bootloader_region)
        self.assertEqual(resolved.boot_register_pre_writes, profile.boot_register_pre_writes)
        self.assertEqual(resolved.boot_registers, profile.boot_registers)
        self.assertEqual(resolved.write_order_constraints, profile.write_order_constraints)

    def test_strict_mode_rejects_unknown_fields(self) -> None:
        with self.assertRaisesRegex(ProfileError, "unknown field"):
            self._load("ignored_typo: true", strict=True)
        with self.assertRaisesRegex(ProfileError, "max_writse"):
            self._load(
                """
fault_sweep:
  max_writes: 8
  max_writse: 9
  fault_types: [power_loss]
""",
                strict=True,
            )
        with self.assertRaisesRegex(ProfileError, "expect.*unknown field"):
            self._load(
                """
expect:
  should_find_issues: false
  typo: true
""",
                strict=True,
            )

    def test_expect_booleans_are_typed_fail_closed(self) -> None:
        with self.assertRaisesRegex(ProfileError, "expected boolean"):
            self._load(
                """
expect:
  should_find_issues: "false"
"""
            )

    def test_expect_control_outcome_uses_canonical_vocabulary(self) -> None:
        for strict in (False, True):
            for value in (
                "protocol_typo",
                " success",
                "SUCCESS",
                "infra_error",
                "timeout",
                "skipped",
            ):
                with self.subTest(strict=strict, value=value), self.assertRaisesRegex(
                    ProfileError,
                    "control_outcome.*expected one of",
                ):
                    self._load(
                        """
expect:
  control_outcome: {!r}
""".format(value),
                        strict=strict,
                    )

    def test_initial_state_control_outcome_uses_same_vocabulary(self) -> None:
        with self.assertRaisesRegex(ProfileError, "control_outcome.*expected one of"):
            self._load(
                """
initial_states:
  - name: seeded
    expect:
      control_outcome: protocol_typo
"""
            )

    def test_campaign_resource_limits_are_bounded(self) -> None:
        with self.assertRaisesRegex(ProfileError, "max_writes.*between"):
            self._load(
                """
fault_sweep:
  max_writes: 1000001
  fault_types: [power_loss]
"""
            )
        with self.assertRaisesRegex(ProfileError, "iterations exceeds"):
            self._load(
                """
state_fuzzer:
  enabled: true
  iterations: 100001
"""
            )
        with self.assertRaisesRegex(ProfileError, "expected boolean"):
            self._load(
                """
initial_states:
  - name: quoted
    expect:
      allow_control_only_issues: "false"
"""
            )

        auxiliary_configs = {
            "phase2_fault": """
fault_sweep:
  max_writes: 1
  fault_types: [power_loss]
  phase2_fault: { enabled: true, max_points: 1000001 }
""",
            "hook_fault": """
fault_sweep:
  max_writes: 1
  fault_types: [power_loss]
  boot_cycles: 2
  boot_cycle_hook: hooks/mcuboot_mark_image_ok.py
  hook_fault: { enabled: true, max_points: 1000001 }
""",
            "confirm_cycle": """
fault_sweep:
  max_writes: 1
  fault_types: [power_loss]
  boot_cycle_hook: hooks/mcuboot_mark_image_ok.py
  confirm_cycle:
    enabled: true
    confirm_function: 0x10000100
    max_points: 1000001
""",
        }
        for config_name, profile_suffix in auxiliary_configs.items():
            with self.subTest(config_name=config_name):
                with self.assertRaisesRegex(ProfileError, "exceeds safety limit"):
                    self._load(profile_suffix)

    def test_strict_base_profile_symlink_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            inside = temp_root / "inside"
            outside = temp_root / "outside"
            inside.mkdir()
            outside.mkdir()
            (outside / "base.yaml").write_text(
                textwrap.dedent(BASE_PROFILE), encoding="utf-8"
            )
            (inside / "base.yaml").symlink_to(outside / "base.yaml")
            child = inside / "child.yaml"
            child.write_text(
                "base_profile: base.yaml\nstrict_validation: true\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ProfileError, "escapes strict"):
                load_profile(child)

    def test_strict_mode_requires_observable_success_check(self) -> None:
        with self.assertRaisesRegex(ProfileError, "observable success check"):
            self._load("success_criteria: {}", strict=True)

    def test_strict_mode_rejects_absolute_and_parent_paths(self) -> None:
        with self.assertRaisesRegex(ProfileError, "relative path"):
            self._load("platform: /tmp/platform.repl", strict=True)
        with self.assertRaisesRegex(ProfileError, "relative path"):
            self._load("images: { staging: ../private/image.bin }", strict=True)
        with self.assertRaisesRegex(ProfileError, "relative path"):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  partial_staging: { staging_image: /etc/hosts }
""",
                strict=True,
            )
        with self.assertRaisesRegex(ProfileError, "relative path"):
            self._load(
                """
fault_sweep:
  mode: runtime
  max_writes: 8
  fault_types: [power_loss]
  partial_staging: { staging_image: ../private/image.bin }
""",
                strict=True,
            )
        # Compatibility mode still accepts absolute paths for local development.
        profile = self._load("platform: /tmp/platform.repl")
        self.assertEqual(profile.platform, "/tmp/platform.repl")

    def test_structured_success_checks_are_encoded_for_runtime(self) -> None:
        profile = self._load(
            """
bootloader_region: { base: 0x10000000, size: 0x800 }
success_criteria:
  vtor_in_slot: exec
  bootloader_integrity: true
  memory_checks:
    - { address: 0x20001000, expected_value: 5, op: ge, mask: 0xFF }
  config_checks:
    - { address: 0x20001004, nonzero: true }
"""
        )
        encoded = next(
            value.split(":", 1)[1]
            for value in profile.robot_vars(ROOT)
            if value.startswith("SUCCESS_CHECKS_B64:")
        )
        payload = json.loads(base64.b64decode(encoded).decode("utf-8"))
        self.assertEqual(payload["contract_version"], 1)
        self.assertEqual(payload["memory_checks"][0]["op"], "ge")
        self.assertTrue(payload["config_checks"][0]["nonzero"])
        self.assertTrue(payload["bootloader_integrity"])
        self.assertEqual(payload["bootloader_region"]["size"], 0x800)

    def test_runtime_registry_and_observation_contract_are_present(self) -> None:
        runtime = (SCRIPTS / "run_runtime_fault_sweep.py").read_text(encoding="utf-8")
        self.assertIn("frozenset(('op', 'os', 'od', 'oo', 'on'))", runtime)
        self.assertIn("'op', 'os', 'od', 'oo', 'on'", runtime)
        self.assertIn("def evaluate_structured_success_checks():", runtime)
        self.assertIn("result['criteria_observations']", runtime)
        robot = (ROOT / "tests/ota_fault_point.robot").read_text(encoding="utf-8")
        self.assertIn("${SUCCESS_CHECKS_B64}", robot)
        self.assertIn('$success_checks_b64="${SUCCESS_CHECKS_B64}"', robot)

    def test_runtime_nvs_variants_apply_transported_tuning(self) -> None:
        runtime_path = SCRIPTS / "run_runtime_fault_sweep.py"
        runtime = runtime_path.read_text(encoding="utf-8")
        tree = ast.parse(runtime, filename=str(runtime_path))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_generate_nvs_corruption"
        )
        namespace = {}
        exec(
            compile(ast.Module(body=[function], type_ignores=[]), str(runtime_path), "exec"),
            namespace,
        )
        generate = namespace["_generate_nvs_corruption"]

        bit_flipped = generate(
            b"\x00" * 8,
            {"mode": "bit_flip", "bit_flip_count": 2},
            seed=7,
        )
        self.assertEqual(sum(byte.bit_count() for byte in bit_flipped), 2)
        self.assertEqual(
            generate(
                b"\x00" * 8,
                {"mode": "partial_erase", "erase_fraction": 0.25},
            ),
            b"\x00" * 6 + b"\xFF" * 2,
        )
        self.assertEqual(
            generate(
                b"\xAA" * 8,
                {"mode": "truncate", "truncate_offset": None},
            ),
            b"\xAA" * 4 + b"\x00" * 4,
        )
        robot = (ROOT / "tests" / "ota_fault_point.robot").read_text(
            encoding="utf-8"
        )
        self.assertIn("${NVS_CORRUPTION_VARIANTS_B64}", robot)
        self.assertIn("$nvs_corruption_variants_b64=", robot)

    def test_every_committed_profile_loads(self) -> None:
        failures = []
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for path in sorted((ROOT / "profiles").glob("*.yaml")):
                try:
                    load_profile(path)
                except Exception as exc:  # pragma: no cover - diagnostic payload
                    failures.append("{}: {}".format(path.name, exc))
        self.assertEqual(failures, [])

    def test_every_committed_profile_passes_strict_validation(self) -> None:
        failures = []
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for path in sorted((ROOT / "profiles").glob("*.yaml")):
                try:
                    load_profile(path, strict=True)
                except Exception as exc:  # pragma: no cover - diagnostic payload
                    failures.append("{}: {}".format(path.name, exc))
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
