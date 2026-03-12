#!/usr/bin/env python3
"""Tests for multi-component fault injection feature."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from renode_runner import merge_robot_vars
from fault_inject import (
    MultiComponentFaultResult,
    classify_multi_component_outcome,
)
from profile_loader import (
    ComponentConfig,
    MultiComponentConfig,
    ProfileConfig,
    ProfileError,
    load_profile,
)


class TestClassifyMultiComponentOutcome(unittest.TestCase):
    """Test the classify_multi_component_outcome function."""

    def test_all_success(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "success"},
            "radio": {"boot_outcome": "success"},
        })
        self.assertEqual(result, "success")

    def test_split_brain(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "success"},
            "radio": {"boot_outcome": "no_boot"},
        })
        self.assertEqual(result, "split_brain")

    def test_split_brain_wrong_image(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "success"},
            "radio": {"boot_outcome": "wrong_image"},
        })
        self.assertEqual(result, "split_brain")

    def test_all_failed(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "no_boot"},
            "radio": {"boot_outcome": "hard_fault"},
        })
        self.assertEqual(result, "all_failed")

    def test_all_failed_wrong_image(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "wrong_image"},
            "radio": {"boot_outcome": "no_boot"},
        })
        self.assertEqual(result, "all_failed")

    def test_empty_dict(self) -> None:
        result = classify_multi_component_outcome({})
        self.assertEqual(result, "unknown")

    def test_three_components_split_brain(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "success"},
            "radio": {"boot_outcome": "no_boot"},
            "sensor": {"boot_outcome": "success"},
        })
        self.assertEqual(result, "split_brain")

    def test_three_components_all_success(self) -> None:
        result = classify_multi_component_outcome({
            "app": {"boot_outcome": "success"},
            "radio": {"boot_outcome": "success"},
            "sensor": {"boot_outcome": "success"},
        })
        self.assertEqual(result, "success")


class TestMultiComponentFaultResult(unittest.TestCase):
    """Test MultiComponentFaultResult data class."""

    def test_construction(self) -> None:
        r = MultiComponentFaultResult(
            faulted_component="app",
            fault_at=42,
            per_component={
                "app": {"boot_outcome": "no_boot"},
                "radio": {"boot_outcome": "success"},
            },
            combined_outcome="split_brain",
        )
        self.assertEqual(r.faulted_component, "app")
        self.assertEqual(r.fault_at, 42)
        self.assertEqual(r.combined_outcome, "split_brain")
        self.assertFalse(r.is_control)


class TestComponentConfigParsing(unittest.TestCase):
    """Test parsing multi-component profiles from YAML."""

    def _write_profile(self, yaml_content: str) -> str:
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        f.write(textwrap.dedent(yaml_content))
        f.close()
        return f.name

    def test_multi_component_profile_loads(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_multi_comp
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              fault_matrix: cross_product
              components:
                - name: mcu_a
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
                - name: mcu_b
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
        """)
        profile = load_profile(path)
        self.assertTrue(profile.is_multi_component)
        self.assertEqual(len(profile.multi_component.components), 2)
        self.assertEqual(profile.multi_component.components[0].name, "mcu_a")
        self.assertEqual(profile.multi_component.components[1].name, "mcu_b")
        self.assertEqual(profile.multi_component.fault_matrix, "cross_product")

    def test_component_profiles_generated(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_comp_profiles
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              components:
                - name: comp_x
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
                - name: comp_y
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
        """)
        profile = load_profile(path)
        comp_profiles = profile.component_profiles()
        self.assertEqual(len(comp_profiles), 2)
        self.assertEqual(comp_profiles[0].name, "test_comp_profiles/comp_x")
        self.assertEqual(comp_profiles[1].name, "test_comp_profiles/comp_y")
        # Components inherit parent fault_sweep when they don't define one.
        self.assertEqual(comp_profiles[0].fault_sweep.max_writes, 100)

    def test_single_component_profile_not_multi(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_single
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
            fault_sweep:
              mode: runtime
              max_writes: 100
        """)
        profile = load_profile(path)
        self.assertFalse(profile.is_multi_component)
        self.assertEqual(profile.component_profiles(), [])

    def test_rejects_single_component(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_single_comp
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              components:
                - name: only_one
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
        """)
        with self.assertRaises(ProfileError):
            load_profile(path)

    def test_rejects_duplicate_component_names(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_dup_names
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              components:
                - name: same_name
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
                - name: same_name
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
        """)
        with self.assertRaises(ProfileError):
            load_profile(path)

    def test_rejects_invalid_fault_matrix(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_bad_matrix
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              fault_matrix: invalid_strategy
              components:
                - name: a
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
                - name: b
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
        """)
        with self.assertRaises(ProfileError):
            load_profile(path)

    def test_component_with_own_fault_sweep(self) -> None:
        path = self._write_profile("""\
            schema_version: 1
            name: test_comp_sweep
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
            fault_sweep:
              mode: runtime
              max_writes: 100
            multi_component:
              components:
                - name: fast_comp
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
                  fault_sweep:
                    mode: runtime
                    max_writes: 50
                - name: slow_comp
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
                  fault_sweep:
                    mode: runtime
                    max_writes: 200
        """)
        profile = load_profile(path)
        comp_profiles = profile.component_profiles()
        # Each component uses its own fault_sweep.
        self.assertEqual(comp_profiles[0].fault_sweep.max_writes, 50)
        self.assertEqual(comp_profiles[1].fault_sweep.max_writes, 200)

    def test_example_profile_loads(self) -> None:
        """Verify example profiles parse without errors."""
        examples_dir = ROOT / "profiles" / "examples"
        for yaml_file in sorted(examples_dir.glob("multi_component_*.yaml")):
            profile = load_profile(str(yaml_file))
            self.assertTrue(
                profile.is_multi_component,
                "{} should be multi-component".format(yaml_file.name),
            )
            self.assertGreaterEqual(
                len(profile.multi_component.components), 2,
                "{} should have >= 2 components".format(yaml_file.name),
            )


class TestMergeRobotVars(unittest.TestCase):
    """Test merge_robot_vars helper used by multi-component sweep."""

    def test_base_vars_survive_when_no_conflict(self) -> None:
        """PHASE2_TIME_SLICE from base vars must propagate into merged output."""
        base = [
            "PHASE2_TIME_SLICE:0.050",
            "PROGRESS_STALL_TIMEOUT_S:30.000000",
            "EVALUATION_MODE:state",
        ]
        overlay = [
            "PLATFORM_REPL:platforms/cortex_m0_nvm.repl",
            "BOOTLOADER_ELF:firmware.elf",
        ]
        merged = merge_robot_vars(base, overlay)
        merged_dict = dict(v.split(":", 1) for v in merged)
        self.assertEqual(merged_dict["PHASE2_TIME_SLICE"], "0.050")
        self.assertEqual(merged_dict["PROGRESS_STALL_TIMEOUT_S"], "30.000000")
        self.assertEqual(merged_dict["EVALUATION_MODE"], "state")
        self.assertIn("PLATFORM_REPL", merged_dict)
        self.assertIn("BOOTLOADER_ELF", merged_dict)

    def test_stall_timeout_survives(self) -> None:
        """PROGRESS_STALL_TIMEOUT_S from base must survive component merge."""
        base = ["PROGRESS_STALL_TIMEOUT_S:25.000000"]
        overlay = ["BOOTLOADER_ELF:fw.elf"]
        merged = merge_robot_vars(base, overlay)
        merged_dict = dict(v.split(":", 1) for v in merged)
        self.assertEqual(merged_dict["PROGRESS_STALL_TIMEOUT_S"], "25.000000")

    def test_component_local_vars_override_base(self) -> None:
        """Component-specific vars must win over base when same key exists."""
        base = [
            "PLATFORM_REPL:parent_platform.repl",
            "BOOTLOADER_ELF:parent_firmware.elf",
            "PHASE2_TIME_SLICE:0.050",
        ]
        overlay = [
            "PLATFORM_REPL:component_platform.repl",
            "BOOTLOADER_ELF:component_firmware.elf",
        ]
        merged = merge_robot_vars(base, overlay)
        merged_dict = dict(v.split(":", 1) for v in merged)
        # Component-local values win on conflict.
        self.assertEqual(merged_dict["PLATFORM_REPL"], "component_platform.repl")
        self.assertEqual(merged_dict["BOOTLOADER_ELF"], "component_firmware.elf")
        # Non-conflicting base var survives.
        self.assertEqual(merged_dict["PHASE2_TIME_SLICE"], "0.050")

    def test_component_vars_win_same_key(self) -> None:
        """Explicit test: when both set the same key, overlay (component) wins."""
        base = ["TEST_TIMEOUT:120", "WRITE_GRANULARITY:4"]
        overlay = ["TEST_TIMEOUT:60", "WRITE_GRANULARITY:8"]
        merged = merge_robot_vars(base, overlay)
        merged_dict = dict(v.split(":", 1) for v in merged)
        self.assertEqual(merged_dict["TEST_TIMEOUT"], "60")
        self.assertEqual(merged_dict["WRITE_GRANULARITY"], "8")

    def test_empty_base(self) -> None:
        overlay = ["FOO:bar", "BAZ:qux"]
        merged = merge_robot_vars([], overlay)
        self.assertEqual(len(merged), 2)

    def test_empty_overlay(self) -> None:
        base = ["FOO:bar", "BAZ:qux"]
        merged = merge_robot_vars(base, [])
        self.assertEqual(len(merged), 2)

    def test_both_empty(self) -> None:
        self.assertEqual(merge_robot_vars([], []), [])

    def test_values_with_colons_preserved(self) -> None:
        """Values that contain colons (e.g. paths) must not be truncated."""
        base = ["IMAGE_STAGING:C:\\firmware\\image.bin"]
        overlay: List[str] = []
        merged = merge_robot_vars(base, overlay)
        merged_dict = dict(v.split(":", 1) for v in merged)
        self.assertEqual(merged_dict["IMAGE_STAGING"], "C:\\firmware\\image.bin")


if __name__ == "__main__":
    unittest.main()
