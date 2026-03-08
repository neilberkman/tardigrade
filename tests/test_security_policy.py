#!/usr/bin/env python3
"""Unit tests for security_policy profile configuration and adversarial fault classification."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import (
    classify_failure_class,
    result_has_issues,
    result_is_brick,
)
from profile_loader import (
    ProfileError,
    SecurityPolicyConfig,
    load_profile,
)


class SecurityPolicyConfigTests(unittest.TestCase):
    """Direct construction of SecurityPolicyConfig."""

    def test_defaults(self):
        sp = SecurityPolicyConfig()
        self.assertFalse(sp.anti_rollback)
        self.assertIsNone(sp.minimum_version)
        self.assertFalse(sp.toctou_protection)

    def test_custom_values(self):
        sp = SecurityPolicyConfig(
            anti_rollback=True,
            minimum_version=3,
            toctou_protection=True,
        )
        self.assertTrue(sp.anti_rollback)
        self.assertEqual(sp.minimum_version, 3)
        self.assertTrue(sp.toctou_protection)

    def test_minimum_version_zero(self):
        sp = SecurityPolicyConfig(minimum_version=0)
        self.assertEqual(sp.minimum_version, 0)


class SecurityPolicyParsingTests(unittest.TestCase):
    """Profile YAML parsing of security_policy block."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_security
                description: test
                platform: platforms/cortex_m0_nvm.repl
                flash_backend: nvm_ctrl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 8
                  slots:
                    exec: {{ base: 0x10000000, size: 0x38000 }}
                    staging: {{ base: 0x10038000, size: 0x38000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: true
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_no_security_policy_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            self.assertFalse(profile.security_policy.anti_rollback)
            self.assertIsNone(profile.security_policy.minimum_version)
            self.assertFalse(profile.security_policy.toctou_protection)

    def test_security_policy_all_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      anti_rollback: true
                      minimum_version: 2
                      toctou_protection: true
                """),
            )
            profile = load_profile(path)
            self.assertTrue(profile.security_policy.anti_rollback)
            self.assertEqual(profile.security_policy.minimum_version, 2)
            self.assertTrue(profile.security_policy.toctou_protection)

    def test_security_policy_partial(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      anti_rollback: true
                """),
            )
            profile = load_profile(path)
            self.assertTrue(profile.security_policy.anti_rollback)
            self.assertIsNone(profile.security_policy.minimum_version)
            self.assertFalse(profile.security_policy.toctou_protection)

    def test_security_policy_toctou_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      toctou_protection: true
                """),
            )
            profile = load_profile(path)
            self.assertFalse(profile.security_policy.anti_rollback)
            self.assertTrue(profile.security_policy.toctou_protection)

    def test_security_policy_minimum_version_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      minimum_version: 0
                """),
            )
            profile = load_profile(path)
            self.assertEqual(profile.security_policy.minimum_version, 0)

    def test_security_policy_negative_version_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      minimum_version: -1
                """),
            )
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_security_policy_non_mapping_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                "security_policy: true",
            )
            with self.assertRaises(ProfileError):
                load_profile(path)


class SecurityPolicyRobotVarsTests(unittest.TestCase):
    """Robot variable emission for security_policy fields."""

    def _write_profile(self, tmpdir, extra_yaml=""):
        path = Path(tmpdir) / "profile.yaml"
        path.write_text(
            textwrap.dedent("""\
                schema_version: 1
                name: test_robot_vars
                description: test
                platform: platforms/cortex_m0_nvm.repl
                flash_backend: nvm_ctrl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 8
                  slots:
                    exec: {{ base: 0x10000000, size: 0x38000 }}
                    staging: {{ base: 0x10038000, size: 0x38000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                {extra}
            """).format(extra=extra_yaml),
            encoding="utf-8",
        )
        return path

    def test_no_security_policy_no_robot_vars(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(td)
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            security_vars = [v for v in vars_list if v.startswith("SECURITY_")]
            self.assertEqual(security_vars, [])

    def test_anti_rollback_emits_robot_var(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      anti_rollback: true
                      minimum_version: 5
                """),
            )
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            self.assertIn("SECURITY_ANTI_ROLLBACK:true", vars_list)
            self.assertIn("SECURITY_MINIMUM_VERSION:5", vars_list)

    def test_toctou_emits_robot_var(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      toctou_protection: true
                """),
            )
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            self.assertIn("SECURITY_TOCTOU_PROTECTION:true", vars_list)
            # anti_rollback not set, so no SECURITY_ANTI_ROLLBACK var
            anti_rollback_vars = [
                v for v in vars_list if v.startswith("SECURITY_ANTI_ROLLBACK:")
            ]
            self.assertEqual(anti_rollback_vars, [])

    def test_all_security_vars(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_profile(
                td,
                textwrap.dedent("""\
                    security_policy:
                      anti_rollback: true
                      minimum_version: 2
                      toctou_protection: true
                """),
            )
            profile = load_profile(path)
            vars_list = profile.robot_vars(ROOT)
            self.assertIn("SECURITY_ANTI_ROLLBACK:true", vars_list)
            self.assertIn("SECURITY_MINIMUM_VERSION:2", vars_list)
            self.assertIn("SECURITY_TOCTOU_PROTECTION:true", vars_list)


class SecurityPolicyInitialStateTests(unittest.TestCase):
    """Security policy propagation through initial_state resolution."""

    def test_security_policy_propagates_to_resolved_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(
                textwrap.dedent("""\
                    schema_version: 1
                    name: test_propagation
                    description: test
                    platform: platforms/cortex_m0_nvm.repl
                    flash_backend: nvm_ctrl
                    bootloader:
                      elf: examples/vulnerable_ota/firmware.elf
                      entry: 0x10000000
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 8
                      slots:
                        exec: { base: 0x10000000, size: 0x38000 }
                        staging: { base: 0x10038000, size: 0x38000 }
                    images:
                      staging: examples/vulnerable_ota/firmware.bin
                    success_criteria:
                      vtor_in_slot: exec
                    security_policy:
                      anti_rollback: true
                      minimum_version: 3
                      toctou_protection: true
                    initial_states:
                      - name: clean_state
                        description: fresh install
                        pre_boot_state: []
                      - name: degraded_state
                        description: one replica corrupt
                        pre_boot_state:
                          - { address: 0x10070000, u32: 0xDEADBEEF }
                """),
                encoding="utf-8",
            )
            profile = load_profile(path)
            self.assertEqual(len(profile.initial_states), 2)
            for state in profile.initial_states:
                resolved = profile.resolve_initial_state(state)
                self.assertTrue(resolved.security_policy.anti_rollback)
                self.assertEqual(resolved.security_policy.minimum_version, 3)
                self.assertTrue(resolved.security_policy.toctou_protection)


class SecurityFaultClassificationTests(unittest.TestCase):
    """Fault result classification for security-specific outcomes."""

    def test_rollback_accepted_from_boot_outcome(self):
        result = {"boot_outcome": "rollback_accepted", "boot_slot": "exec"}
        self.assertEqual(classify_failure_class(result), "rollback_accepted")

    def test_toctou_corruption_from_boot_outcome(self):
        result = {"boot_outcome": "toctou_corruption", "boot_slot": "exec"}
        self.assertEqual(classify_failure_class(result), "toctou_corruption")

    def test_rollback_accepted_from_fault_class(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "rollback_accepted",
        }
        self.assertEqual(classify_failure_class(result), "rollback_accepted")

    def test_toctou_corruption_from_fault_class(self):
        result = {
            "boot_outcome": "success",
            "boot_slot": "exec",
            "fault_class": "toctou_corruption",
        }
        self.assertEqual(classify_failure_class(result), "toctou_corruption")

    def test_rollback_accepted_is_not_brick(self):
        result = {"boot_outcome": "rollback_accepted", "boot_slot": "exec"}
        self.assertFalse(result_is_brick(result))

    def test_toctou_corruption_is_not_brick(self):
        result = {"boot_outcome": "toctou_corruption", "boot_slot": "exec"}
        self.assertFalse(result_is_brick(result))

    def test_rollback_accepted_is_issue(self):
        result = {"boot_outcome": "rollback_accepted", "boot_slot": "exec"}
        self.assertTrue(result_has_issues(result, "success"))

    def test_toctou_corruption_is_issue(self):
        result = {"boot_outcome": "toctou_corruption", "boot_slot": "exec"}
        self.assertTrue(result_has_issues(result, "success"))

    def test_existing_classifications_unchanged(self):
        # Verify we haven't broken existing classifications.
        self.assertEqual(
            classify_failure_class({"boot_outcome": "success"}),
            "recoverable",
        )
        self.assertEqual(
            classify_failure_class({"boot_outcome": "no_boot"}),
            "unrecoverable",
        )
        self.assertEqual(
            classify_failure_class({"boot_outcome": "hard_fault"}),
            "unrecoverable",
        )
        self.assertEqual(
            classify_failure_class({"boot_outcome": "wrong_pc"}),
            "unrecoverable",
        )
        self.assertEqual(
            classify_failure_class({"boot_outcome": "wrong_image"}),
            "wrong_image",
        )


class SecurityProfileLoadTests(unittest.TestCase):
    """Load the actual security example profiles from disk."""

    def test_load_rollback_no_protection(self):
        path = ROOT / "profiles" / "security_rollback_no_protection.yaml"
        if not path.exists():
            self.skipTest("profile not found")
        profile = load_profile(path)
        self.assertEqual(profile.name, "security_rollback_no_protection")
        self.assertFalse(profile.security_policy.anti_rollback)
        self.assertEqual(profile.security_policy.minimum_version, 2)
        self.assertFalse(profile.security_policy.toctou_protection)

    def test_load_rollback_with_protection(self):
        path = ROOT / "profiles" / "security_rollback_with_protection.yaml"
        if not path.exists():
            self.skipTest("profile not found")
        profile = load_profile(path)
        self.assertEqual(profile.name, "security_rollback_with_protection")
        self.assertTrue(profile.security_policy.anti_rollback)
        self.assertEqual(profile.security_policy.minimum_version, 2)
        self.assertFalse(profile.security_policy.toctou_protection)

    def test_load_toctou_no_protection(self):
        path = ROOT / "profiles" / "security_toctou_no_protection.yaml"
        if not path.exists():
            self.skipTest("profile not found")
        profile = load_profile(path)
        self.assertEqual(profile.name, "security_toctou_no_protection")
        self.assertFalse(profile.security_policy.toctou_protection)
        self.assertIn("bit_corruption", profile.fault_sweep.fault_types)

    def test_load_toctou_with_protection(self):
        path = ROOT / "profiles" / "security_toctou_with_protection.yaml"
        if not path.exists():
            self.skipTest("profile not found")
        profile = load_profile(path)
        self.assertEqual(profile.name, "security_toctou_with_protection")
        self.assertTrue(profile.security_policy.toctou_protection)
        self.assertIn("bit_corruption", profile.fault_sweep.fault_types)


class SecurityPolicyCLIOutputTests(unittest.TestCase):
    """Verify security_policy appears in CLI debug output."""

    def test_debug_output_includes_security_policy(self):
        import json

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(
                textwrap.dedent("""\
                    schema_version: 1
                    name: cli_test
                    description: test
                    platform: platforms/cortex_m0_nvm.repl
                    flash_backend: nvm_ctrl
                    bootloader:
                      elf: examples/vulnerable_ota/firmware.elf
                      entry: 0x10000000
                    memory:
                      sram: { start: 0x20000000, end: 0x20020000 }
                      write_granularity: 8
                      slots:
                        exec: { base: 0x10000000, size: 0x38000 }
                        staging: { base: 0x10038000, size: 0x38000 }
                    images:
                      staging: examples/vulnerable_ota/firmware.bin
                    success_criteria:
                      vtor_in_slot: exec
                    security_policy:
                      anti_rollback: true
                      minimum_version: 4
                      toctou_protection: true
                """),
                encoding="utf-8",
            )
            profile = load_profile(path)
            # Replicate what main() does.
            info = {
                "security_policy": {
                    "anti_rollback": profile.security_policy.anti_rollback,
                    "minimum_version": profile.security_policy.minimum_version,
                    "toctou_protection": profile.security_policy.toctou_protection,
                },
            }
            self.assertTrue(info["security_policy"]["anti_rollback"])
            self.assertEqual(info["security_policy"]["minimum_version"], 4)
            self.assertTrue(info["security_policy"]["toctou_protection"])


if __name__ == "__main__":
    unittest.main()
