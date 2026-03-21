#!/usr/bin/env python3
"""Unit tests for seeded initial-state support in fault sweeps."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from profile_loader import (  # noqa: E402
    InitialStateConfig,
    PreBootWrite,
    ProfileError,
    UpdateTrigger,
    load_profile,
)


class InitialStatesSchemaTest(unittest.TestCase):
    """Test YAML parsing of the initial_states profile field."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_empty_initial_states_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_empty
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
                initial_states: []
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.initial_states, [])

    def test_no_initial_states_defaults_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_default
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
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(profile.initial_states, [])

    def test_initial_states_with_pre_boot_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_seeded
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
                initial_states:
                  - name: only_replica_0
                    description: "Only metadata replica 0 valid"
                    pre_boot_state:
                      - { address: 0x10070000, u32: 0x4F54414D }
                      - { address: 0x10070004, u32: 1 }
                  - name: both_invalid
                    description: "Both replicas invalid"
                    pre_boot_state: []
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.initial_states), 2)
            self.assertEqual(profile.initial_states[0].name, "only_replica_0")
            self.assertEqual(
                profile.initial_states[0].description,
                "Only metadata replica 0 valid",
            )
            self.assertEqual(len(profile.initial_states[0].pre_boot_state), 2)
            self.assertEqual(
                profile.initial_states[0].pre_boot_state[0].address, 0x10070000
            )
            self.assertEqual(
                profile.initial_states[0].pre_boot_state[0].u32, 0x4F54414D
            )
            # "both_invalid" has explicit empty pre_boot_state
            self.assertEqual(profile.initial_states[1].name, "both_invalid")
            self.assertIsNotNone(profile.initial_states[1].pre_boot_state)
            self.assertEqual(len(profile.initial_states[1].pre_boot_state), 0)

    def test_initial_states_with_expect_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_expect_override
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
                initial_states:
                  - name: degraded
                    description: "Degraded state expects issues"
                    expect:
                      should_find_issues: true
                      control_outcome: no_boot
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.initial_states), 1)
            state = profile.initial_states[0]
            self.assertEqual(state.expect_overrides["should_find_issues"], True)
            self.assertEqual(state.expect_overrides["control_outcome"], "no_boot")

    def test_initial_states_with_update_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_trigger_state
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
                initial_states:
                  - name: revert_pending
                    description: "MCUboot revert pending"
                    update_trigger:
                      type: mcuboot_trailer_magic
                      slot: staging
                      copy_done: 0x01
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.initial_states), 1)
            state = profile.initial_states[0]
            self.assertIsNotNone(state.update_trigger)
            self.assertEqual(state.update_trigger.type, "mcuboot_trailer_magic")
            self.assertEqual(state.update_trigger.slot, "staging")

    def test_initial_states_with_setup_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            script = tempdir / "seed.resc"
            script.write_text("# noop\n", encoding="utf-8")
            profile_path = self._write_profile(
                tempdir,
                f"""
                schema_version: 1
                name: test_setup_script
                platform: platforms/cortex_m4_flash_fast.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: {{ start: 0x20000000, end: 0x20020000 }}
                  write_granularity: 4
                  slots:
                    exec: {{ base: 0x10000000, size: 0x1000 }}
                    staging: {{ base: 0x10001000, size: 0x1000 }}
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                initial_states:
                  - name: custom_setup
                    setup_script: {script.as_posix()}
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.initial_states), 1)
            self.assertEqual(
                profile.initial_states[0].setup_script, str(script)
            )

    def test_duplicate_names_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_dup
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
                initial_states:
                  - name: state_a
                  - name: state_a
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError) as ctx:
                load_profile(profile_path)
            self.assertIn("duplicate name", str(ctx.exception))

    def test_missing_name_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_no_name
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
                initial_states:
                  - description: "no name"
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError) as ctx:
                load_profile(profile_path)
            self.assertIn("name", str(ctx.exception))

    def test_invalid_expect_type_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: test_bad_expect
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
                initial_states:
                  - name: bad
                    expect: "not a dict"
                expect:
                  should_find_issues: false
                """,
            )
            with self.assertRaises(ProfileError) as ctx:
                load_profile(profile_path)
            self.assertIn("expect", str(ctx.exception))


class ResolveInitialStateTest(unittest.TestCase):
    """Test the resolve_initial_state method on ProfileConfig."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def _base_profile(self, tempdir: Path) -> "ProfileConfig":
        profile_path = self._write_profile(
            tempdir,
            """
            schema_version: 1
            name: base_profile
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
            pre_boot_state:
              - { address: 0xAAAA0000, u32: 0xDEADBEEF }
            success_criteria:
              vtor_in_slot: exec
            expect:
              should_find_issues: false
            """,
        )
        return load_profile(profile_path)

    def test_resolve_replaces_pre_boot_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="custom",
                pre_boot_state=[
                    PreBootWrite(address=0xBBBB0000, u32=0x11111111),
                    PreBootWrite(address=0xBBBB0004, u32=0x22222222),
                ],
            )
            resolved = profile.resolve_initial_state(state)
            self.assertEqual(resolved.name, "base_profile/custom")
            self.assertEqual(len(resolved.pre_boot_state), 2)
            self.assertEqual(resolved.pre_boot_state[0].address, 0xBBBB0000)
            self.assertEqual(resolved.pre_boot_state[1].u32, 0x22222222)
            # Original profile unchanged.
            self.assertEqual(len(profile.pre_boot_state), 1)

    def test_resolve_inherits_pre_boot_when_state_omits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="inherit",
                description="inherits parent pre_boot_state",
            )
            resolved = profile.resolve_initial_state(state)
            self.assertEqual(len(resolved.pre_boot_state), 1)
            self.assertEqual(resolved.pre_boot_state[0].address, 0xAAAA0000)

    def test_resolve_clears_pre_boot_when_state_has_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="cleared",
                pre_boot_state=[],  # explicit empty = override
            )
            resolved = profile.resolve_initial_state(state)
            self.assertEqual(len(resolved.pre_boot_state), 0)

    def test_resolve_merges_expect_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="degraded",
                expect_overrides={
                    "should_find_issues": True,
                    "control_outcome": "no_boot",
                },
            )
            resolved = profile.resolve_initial_state(state)
            self.assertTrue(resolved.expect.should_find_issues)
            self.assertEqual(resolved.expect.control_outcome, "no_boot")
            # Fields NOT in overrides are inherited.
            self.assertFalse(resolved.expect.allow_semantic_only_issues)

    def test_resolve_replaces_setup_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="with_script",
                setup_script="/path/to/seed.resc",
            )
            resolved = profile.resolve_initial_state(state)
            self.assertEqual(resolved.setup_script, "/path/to/seed.resc")

    def test_resolve_prevents_recursive_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            # Manually add initial_states to verify they're cleared.
            profile.initial_states = [
                InitialStateConfig(name="a"),
                InitialStateConfig(name="b"),
            ]
            state = InitialStateConfig(name="c")
            resolved = profile.resolve_initial_state(state)
            self.assertEqual(resolved.initial_states, [])

    def test_resolve_expands_update_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="revert",
                update_trigger=UpdateTrigger(
                    type="mcuboot_trailer_magic",
                    slot="staging",
                    fields={"copy_done": 0x01},
                ),
            )
            resolved = profile.resolve_initial_state(state)
            # update_trigger should have been expanded into pre_boot_state.
            self.assertGreater(len(resolved.pre_boot_state), 0)
            # Verify MCUboot magic words are in the writes.
            addresses = [w.address for w in resolved.pre_boot_state]
            staging_end = 0x10001000 + 0x1000
            magic_base = staging_end - 16
            self.assertIn(magic_base, addresses)

    def test_resolve_expands_update_trigger_with_align32_magic(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile = self._base_profile(tempdir)
            state = InitialStateConfig(
                name="geom_pending",
                update_trigger=UpdateTrigger(
                    type="mcuboot_trailer_magic",
                    slot="staging",
                    fields={"max_align": 32},
                ),
            )
            resolved = profile.resolve_initial_state(state)
            writes = {w.address: w.u32 for w in resolved.pre_boot_state}
            staging_end = 0x10001000 + 0x1000
            self.assertEqual(writes[staging_end - 16], 0xE12D0020)
            self.assertEqual(writes[staging_end - 12], 0x0B41295D)
            self.assertEqual(writes[staging_end - 8], 0x9C67778D)
            self.assertEqual(writes[staging_end - 4], 0x8A1F0F11)


class ScenarioExpansionTest(unittest.TestCase):
    """Test that initial_states compose with scenario overrides."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_scenario_profile_overrides_compose_with_initial_states(self) -> None:
        """Verify that scenario-level profile_overrides can inject initial_states."""
        from run_scenario import _deep_merge

        base = {
            "schema_version": 1,
            "name": "base",
            "expect": {"should_find_issues": False},
        }
        overrides = {
            "initial_states": [
                {"name": "state_a", "pre_boot_state": [{"address": 0x1000, "u32": 0xFF}]},
                {"name": "state_b"},
            ],
        }
        merged = _deep_merge(base, overrides)
        self.assertEqual(len(merged["initial_states"]), 2)
        self.assertEqual(merged["initial_states"][0]["name"], "state_a")
        # Base fields preserved.
        self.assertFalse(merged["expect"]["should_find_issues"])

    def test_full_round_trip_with_initial_states(self) -> None:
        """Load a profile with initial_states and resolve each one."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: matrix_test
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
                pre_boot_state:
                  - { address: 0x10070000, u32: 0x4F54414D }
                initial_states:
                  - name: only_replica_0
                    description: "Only replica 0 valid"
                    pre_boot_state:
                      - { address: 0x10070000, u32: 0x4F54414D }
                      - { address: 0x10070004, u32: 1 }
                  - name: both_invalid
                    description: "No valid metadata"
                    pre_boot_state: []
                    expect:
                      should_find_issues: true
                      control_outcome: no_boot
                  - name: default_inherited
                    description: "Inherits parent pre_boot_state"
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            self.assertEqual(len(profile.initial_states), 3)

            resolved_profiles = [
                profile.resolve_initial_state(s) for s in profile.initial_states
            ]

            # only_replica_0: custom pre_boot_state.
            r0 = resolved_profiles[0]
            self.assertEqual(r0.name, "matrix_test/only_replica_0")
            self.assertEqual(len(r0.pre_boot_state), 2)
            self.assertFalse(r0.expect.should_find_issues)

            # both_invalid: empty pre_boot_state, expects issues.
            r1 = resolved_profiles[1]
            self.assertEqual(r1.name, "matrix_test/both_invalid")
            self.assertEqual(len(r1.pre_boot_state), 0)
            self.assertTrue(r1.expect.should_find_issues)
            self.assertEqual(r1.expect.control_outcome, "no_boot")

            # default_inherited: inherits parent pre_boot_state.
            r2 = resolved_profiles[2]
            self.assertEqual(r2.name, "matrix_test/default_inherited")
            self.assertEqual(len(r2.pre_boot_state), 1)
            self.assertEqual(r2.pre_boot_state[0].address, 0x10070000)

    def test_robot_vars_differ_per_resolved_state(self) -> None:
        """Each resolved profile should produce different robot vars."""
        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: robot_var_test
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
                initial_states:
                  - name: state_a
                    pre_boot_state:
                      - { address: 0xAAAA, u32: 0x1111 }
                  - name: state_b
                    pre_boot_state:
                      - { address: 0xBBBB, u32: 0x2222 }
                      - { address: 0xCCCC, u32: 0x3333 }
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            resolved_a = profile.resolve_initial_state(profile.initial_states[0])
            resolved_b = profile.resolve_initial_state(profile.initial_states[1])

            vars_a = resolved_a.robot_vars(ROOT)
            vars_b = resolved_b.robot_vars(ROOT)

            # Both should have PRE_BOOT_STATE_BIN but with different files.
            bin_a = [v for v in vars_a if v.startswith("PRE_BOOT_STATE_BIN:")]
            bin_b = [v for v in vars_b if v.startswith("PRE_BOOT_STATE_BIN:")]
            self.assertEqual(len(bin_a), 1)
            self.assertEqual(len(bin_b), 1)
            self.assertNotEqual(bin_a[0], bin_b[0])


class ExpandInitialStatesHelperTest(unittest.TestCase):
    """Test the expand_initial_states helper for audit orchestration."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_expand_empty_returns_parent(self) -> None:
        """When no initial_states are declared, expand returns just the parent."""
        from profile_loader import load_profile

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: no_states
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
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            # No initial_states -> sweep uses the profile as-is.
            expanded = expand_profiles(profile)
            self.assertEqual(len(expanded), 1)
            self.assertEqual(expanded[0].name, "no_states")

    def test_expand_returns_one_per_state(self) -> None:
        from profile_loader import load_profile

        with tempfile.TemporaryDirectory() as td:
            tempdir = Path(td)
            profile_path = self._write_profile(
                tempdir,
                """
                schema_version: 1
                name: multi_state
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
                initial_states:
                  - name: alpha
                  - name: beta
                  - name: gamma
                expect:
                  should_find_issues: false
                """,
            )
            profile = load_profile(profile_path)
            expanded = expand_profiles(profile)
            self.assertEqual(len(expanded), 3)
            self.assertEqual(expanded[0].name, "multi_state/alpha")
            self.assertEqual(expanded[1].name, "multi_state/beta")
            self.assertEqual(expanded[2].name, "multi_state/gamma")
            # Each should have no initial_states (prevents recursion).
            for p in expanded:
                self.assertEqual(p.initial_states, [])


def expand_profiles(profile):
    """Utility: expand a profile into a list of per-state profiles.

    If no initial_states, returns [profile].  Otherwise returns one resolved
    profile per initial state.
    """
    if not profile.initial_states:
        return [profile]
    return [profile.resolve_initial_state(s) for s in profile.initial_states]


if __name__ == "__main__":
    unittest.main()
