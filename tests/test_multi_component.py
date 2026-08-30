#!/usr/bin/env python3
"""Tests for multi-component fault injection feature."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import yaml

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
    InitialStateConfig,
    MultiComponentConfig,
    PreBootWrite,
    ProfileConfig,
    ProfileError,
    load_profile,
)
from sweep import (
    _bounded_component_write_count,
    _multi_component_issue_annotation,
    _multi_component_security_counts,
    _run_batch_worker,
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


class TestMultiComponentSecurityAccounting(unittest.TestCase):
    def test_overlapping_sources_count_one_fault_point(self) -> None:
        annotation = _multi_component_issue_annotation(
            {
                "fault_injected": True,
                "boot_outcome": "no_boot",
                "semantic_assertion_failures": [{"name": "version"}],
            },
            expected_outcome="success",
            combined_outcome="split_brain",
            relation_violations=[{"name": "state_relations"}],
            require_fault=True,
        )
        self.assertTrue(annotation["component_issue"])
        self.assertTrue(annotation["security_issue"])
        self.assertEqual(
            annotation["issue_sources"],
            ["component", "combined_outcome", "state_relation"],
        )
        counts = _multi_component_security_counts(
            [annotation],
            {"reliable": True, "security_issue": False},
        )
        self.assertEqual(counts["security_issue_points"], 1)

    def test_semantic_only_component_finding_is_preserved(self) -> None:
        annotation = _multi_component_issue_annotation(
            {
                "fault_injected": True,
                "boot_outcome": "success",
                "semantic_assertion_failures": [{"name": "version"}],
            },
            expected_outcome="success",
            combined_outcome="success",
            relation_violations=[],
            require_fault=True,
        )
        self.assertTrue(annotation["security_issue"])
        self.assertEqual(annotation["issue_sources"], ["component"])

    def test_infrastructure_result_is_not_a_security_issue(self) -> None:
        annotation = _multi_component_issue_annotation(
            {
                "fault_injected": True,
                "boot_outcome": "infra_error",
                "infrastructure_error": True,
            },
            expected_outcome="success",
            combined_outcome="degraded",
            relation_violations=[],
            require_fault=True,
        )
        self.assertFalse(annotation["reliable"])
        self.assertFalse(annotation["security_issue"])
        counts = _multi_component_security_counts(
            [annotation],
            {"reliable": True, "security_issue": False},
        )
        self.assertEqual(counts["security_issue_points"], 0)
        self.assertEqual(counts["unreliable_fault_points"], 1)

    def test_bad_supporting_control_cannot_create_combined_finding(self) -> None:
        annotation = _multi_component_issue_annotation(
            {
                "fault_injected": True,
                "boot_outcome": "success",
            },
            expected_outcome="success",
            combined_outcome="split_brain",
            relation_violations=[{"name": "state_relations"}],
            require_fault=True,
            supporting_controls_reliable=False,
        )
        self.assertTrue(annotation["component_reliable"])
        self.assertFalse(annotation["reliable"])
        self.assertFalse(annotation["component_issue"])
        self.assertFalse(annotation["security_issue"])
        self.assertEqual(annotation["issue_sources"], [])

    def test_local_finding_survives_bad_supporting_control(self) -> None:
        annotation = _multi_component_issue_annotation(
            {
                "fault_injected": True,
                "boot_outcome": "success",
                "semantic_assertion_failures": [{"name": "version"}],
            },
            expected_outcome="success",
            combined_outcome="split_brain",
            relation_violations=[{"name": "state_relations"}],
            require_fault=True,
            supporting_controls_reliable=False,
        )
        self.assertTrue(annotation["component_reliable"])
        self.assertFalse(annotation["reliable"])
        self.assertTrue(annotation["component_issue"])
        self.assertTrue(annotation["security_issue"])
        self.assertEqual(annotation["issue_sources"], ["component"])
        counts = _multi_component_security_counts(
            [annotation],
            {"reliable": True, "security_issue": False},
        )
        self.assertEqual(counts["component_reliable_fault_points"], 1)
        self.assertEqual(counts["reliable_fault_points"], 0)
        self.assertEqual(counts["security_issue_points"], 1)

    def test_control_findings_have_a_separate_binary_count(self) -> None:
        control = _multi_component_issue_annotation(
            {
                "fault_injected": False,
                "boot_outcome": "success",
                "semantic_assertion_failures": [
                    {"name": "one"},
                    {"name": "two"},
                ],
            },
            expected_outcome="success",
            combined_outcome="success",
            relation_violations=[{"name": "state_relations"}],
            require_fault=False,
        )
        counts = _multi_component_security_counts([], control)
        self.assertEqual(counts["security_issue_points"], 0)
        self.assertEqual(counts["control_security_issue_points"], 1)


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

    def test_component_names_reject_path_tokens(self) -> None:
        source = (
            ROOT / "profiles" / "examples" / "multi_component_dual_mcu.yaml"
        )
        baseline = yaml.safe_load(source.read_text(encoding="utf-8"))
        for value in ("../radio", "nested/radio", "nested\\radio"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as td:
                data = yaml.safe_load(yaml.safe_dump(baseline))
                data["multi_component"]["components"][0]["name"] = value
                profile_path = Path(td) / "profile.yaml"
                profile_path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaisesRegex(
                    ProfileError,
                    r"multi_component\.components\[0\]\.name: expected safe identifier",
                ):
                    load_profile(profile_path)

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

    def test_resolved_parent_contract_reaches_each_component(self) -> None:
        profile = load_profile(
            ROOT / "profiles" / "examples" / "multi_component_dual_mcu.yaml"
        )
        profile.invariants = ["at_least_one_bootable"]
        profile.semantic_assertions = {"always": {"boot.version": 2}}
        profile.invariant_config = {"allowed": ["exec"]}
        profile.nvm_controller = "nvmController"
        profile.otp_peripheral = "otp"
        persistent_layout = object()
        terminal_declarations = [object()]
        profile.persistent_state_layout = persistent_layout
        profile.terminal_error_paths = terminal_declarations
        profile.multi_component.components[0].pre_boot_state = [
            PreBootWrite(address=0x20000004, u32=0xDEAD)
        ]
        profile.multi_component.components[0].setup_script = "component_setup.py"
        state = InitialStateConfig(
            name="seeded",
            pre_boot_state=[PreBootWrite(address=0x20000000, u32=0xA5)],
            setup_script="hooks/mcuboot_mark_image_ok.py",
        )

        resolved_parent = profile.resolve_initial_state(state)
        self.assertIs(resolved_parent.persistent_state_layout, persistent_layout)
        self.assertIs(resolved_parent.terminal_error_paths, terminal_declarations)
        component_profiles = resolved_parent.component_profiles()
        self.assertEqual(len(component_profiles), 2)
        for component in component_profiles:
            with self.subTest(component=component.name):
                self.assertEqual(
                    [(write.address, write.u32) for write in component.pre_boot_state],
                    [(0x20000000, 0xA5)],
                )
                self.assertEqual(
                    component.setup_script,
                    "hooks/mcuboot_mark_image_ok.py",
                )
                self.assertEqual(component.invariants, ["at_least_one_bootable"])
                self.assertEqual(component.semantic_assertions, profile.semantic_assertions)
                self.assertEqual(component.invariant_config, profile.invariant_config)
                self.assertEqual(component.nvm_controller, "nvmController")
                self.assertEqual(component.otp_peripheral, "otp")
                self.assertIs(component.persistent_state_layout, persistent_layout)
                self.assertIs(component.terminal_error_paths, terminal_declarations)

    def test_component_auto_write_count_uses_profile_cap(self) -> None:
        profile = load_profile(
            ROOT / "profiles" / "examples" / "multi_component_dual_mcu.yaml"
        ).component_profiles()[0]
        profile.fault_sweep.max_writes_cap = 17
        self.assertEqual(_bounded_component_write_count(profile, 1000000), 17)

    def test_strict_component_fault_config_rejects_nested_typo(self) -> None:
        source = (
            ROOT / "profiles" / "examples" / "multi_component_dual_mcu.yaml"
        )
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
        data["multi_component"]["components"][0]["fault_sweep"][
            "phase2_fault"
        ] = {"enabled": False, "max_pionts": 99}
        with tempfile.TemporaryDirectory() as td:
            profile_path = Path(td) / "profile.yaml"
            profile_path.write_text(yaml.safe_dump(data), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "max_pionts"):
                load_profile(profile_path, strict=True)

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


class TestParallelComponentWorker(unittest.TestCase):
    def test_worker_reloads_selected_component_not_parent(self) -> None:
        profile_path = ROOT / "profiles" / "examples" / "multi_component_dual_mcu.yaml"
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("sweep._run_batches_chunked", return_value=[]) as run_batches:
                _run_batch_worker(
                    repo_root_str=str(ROOT),
                    renode_test="renode-test",
                    robot_suite="tests/ota_fault_point.robot",
                    profile_path=str(profile_path),
                    fault_points=[],
                    robot_vars=[],
                    work_dir_str=td,
                    renode_remote_server_dir="",
                    worker_id=0,
                    profile_component_name="secondary_mcu",
                )
        selected = run_batches.call_args.kwargs["profile"]
        self.assertEqual(selected.name, "multi_component_dual_mcu/secondary_mcu")
        self.assertFalse(selected.is_multi_component)


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
