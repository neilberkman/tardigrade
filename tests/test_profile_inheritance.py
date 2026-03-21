#!/usr/bin/env python3
"""Tests for profile base_profile inheritance (deep merge, chaining, cycles)."""

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

from profile_loader import (
    ProfileError,
    _deep_merge_profile_data,
    _resolve_base_profile,
    load_profile,
    load_profile_raw,
)


class DeepMergeTests(unittest.TestCase):
    """Unit tests for _deep_merge_profile_data."""

    def test_scalar_override(self):
        self.assertEqual(_deep_merge_profile_data({"a": 1}, {"a": 2}), {"a": 2})

    def test_new_key_added(self):
        self.assertEqual(
            _deep_merge_profile_data({"a": 1}, {"b": 2}),
            {"a": 1, "b": 2},
        )

    def test_nested_dict_merge(self):
        base = {"outer": {"a": 1, "b": 2}}
        override = {"outer": {"b": 3, "c": 4}}
        result = _deep_merge_profile_data(base, override)
        self.assertEqual(result, {"outer": {"a": 1, "b": 3, "c": 4}})

    def test_list_replaces(self):
        base = {"items": [1, 2, 3]}
        override = {"items": [4, 5]}
        result = _deep_merge_profile_data(base, override)
        self.assertEqual(result, {"items": [4, 5]})

    def test_override_none_replaces(self):
        result = _deep_merge_profile_data({"a": 1}, {"a": None})
        self.assertEqual(result, {"a": None})

    def test_non_dict_base_returns_override(self):
        self.assertEqual(_deep_merge_profile_data("old", "new"), "new")

    def test_deeply_nested(self):
        base = {"l1": {"l2": {"l3": {"val": "base", "keep": True}}}}
        override = {"l1": {"l2": {"l3": {"val": "child"}}}}
        result = _deep_merge_profile_data(base, override)
        self.assertEqual(result["l1"]["l2"]["l3"]["val"], "child")
        self.assertTrue(result["l1"]["l2"]["l3"]["keep"])


# ---------------------------------------------------------------------------
# Minimal profile YAML used as base for inheritance tests
# ---------------------------------------------------------------------------

_BASE_YAML = textwrap.dedent("""\
    schema_version: 1
    name: base_test
    description: "base profile"
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
      image_hash: true
      expected_image: staging
    fault_sweep:
      mode: runtime
      max_writes: 28672
      max_writes_cap: 100000
      run_duration: "0.01"
    expect:
      should_find_issues: true
""")


class SimpleInheritanceTests(unittest.TestCase):
    """Child overrides a single field from base."""

    def test_child_overrides_name_and_description(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            child_path = Path(tmpdir) / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: base.yaml
                name: child_test
                description: "child profile"
            """), encoding="utf-8")

            profile = load_profile(child_path)
            self.assertEqual(profile.name, "child_test")
            self.assertEqual(profile.description, "child profile")
            # Inherited from base
            self.assertEqual(profile.platform, "platforms/cortex_m0_nvm.repl")
            self.assertEqual(profile.bootloader_entry, 0x10000000)

    def test_child_overrides_fault_sweep_field(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            child_path = Path(tmpdir) / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: base.yaml
                name: child_override_sweep
                fault_sweep:
                  max_writes: 50000
            """), encoding="utf-8")

            profile = load_profile(child_path)
            self.assertEqual(profile.fault_sweep.max_writes, 50000)
            # mode inherited from base via deep merge
            self.assertEqual(profile.fault_sweep.mode, "runtime")


class DeepMergeInheritanceTests(unittest.TestCase):
    """Child adds to a nested dict without clobbering sibling keys."""

    def test_child_adds_to_memory_slots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            child_path = Path(tmpdir) / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: base.yaml
                name: child_extra_slot
                memory:
                  slots:
                    scratch: { base: 0x10070000, size: 0x10000 }
            """), encoding="utf-8")

            profile = load_profile(child_path)
            # All three slots should exist: exec, staging from base + scratch from child
            self.assertIn("exec", profile.memory.slots)
            self.assertIn("staging", profile.memory.slots)
            self.assertIn("scratch", profile.memory.slots)
            self.assertEqual(profile.memory.slots["scratch"].base, 0x10070000)

    def test_child_overrides_nested_value(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            child_path = Path(tmpdir) / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: base.yaml
                name: child_override_nested
                success_criteria:
                  image_hash: false
            """), encoding="utf-8")

            profile = load_profile(child_path)
            # Overridden
            self.assertFalse(profile.success_criteria.image_hash)
            # Inherited
            self.assertEqual(profile.success_criteria.vtor_in_slot, "exec")


class ChainInheritanceTests(unittest.TestCase):
    """A -> B -> C chain: grandchild inherits from child which inherits from base."""

    def test_three_level_chain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            grandparent = Path(tmpdir) / "grandparent.yaml"
            grandparent.write_text(_BASE_YAML, encoding="utf-8")

            parent = Path(tmpdir) / "parent.yaml"
            parent.write_text(textwrap.dedent("""\
                base_profile: grandparent.yaml
                name: parent_profile
                description: "middle layer"
                fault_sweep:
                  max_writes: 40000
            """), encoding="utf-8")

            child = Path(tmpdir) / "child.yaml"
            child.write_text(textwrap.dedent("""\
                base_profile: parent.yaml
                name: child_profile
                expect:
                  should_find_issues: false
            """), encoding="utf-8")

            profile = load_profile(child)
            # From child
            self.assertEqual(profile.name, "child_profile")
            self.assertFalse(profile.expect.should_find_issues)
            # From parent
            self.assertEqual(profile.fault_sweep.max_writes, 40000)
            # From grandparent
            self.assertEqual(profile.platform, "platforms/cortex_m0_nvm.repl")
            self.assertEqual(profile.bootloader_entry, 0x10000000)


class CycleDetectionTests(unittest.TestCase):
    """Inheritance cycles must raise ProfileError."""

    def test_direct_self_reference(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self_ref.yaml"
            path.write_text(textwrap.dedent("""\
                base_profile: self_ref.yaml
                schema_version: 1
                name: self_ref
            """), encoding="utf-8")

            with self.assertRaises(ProfileError) as ctx:
                load_profile(path)
            self.assertIn("cycle", str(ctx.exception).lower())

    def test_mutual_cycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a_path = Path(tmpdir) / "a.yaml"
            b_path = Path(tmpdir) / "b.yaml"

            a_path.write_text(textwrap.dedent("""\
                base_profile: b.yaml
                schema_version: 1
                name: a
            """), encoding="utf-8")

            b_path.write_text(textwrap.dedent("""\
                base_profile: a.yaml
                schema_version: 1
                name: b
            """), encoding="utf-8")

            with self.assertRaises(ProfileError) as ctx:
                load_profile(a_path)
            self.assertIn("cycle", str(ctx.exception).lower())


class BaseProfileNotFoundTests(unittest.TestCase):
    """Missing base_profile must raise ProfileError."""

    def test_missing_base(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "orphan.yaml"
            path.write_text(textwrap.dedent("""\
                base_profile: nonexistent.yaml
                schema_version: 1
                name: orphan
            """), encoding="utf-8")

            with self.assertRaises(ProfileError) as ctx:
                load_profile(path)
            self.assertIn("not found", str(ctx.exception).lower())


class NoBaseProfileTests(unittest.TestCase):
    """Profiles without base_profile must work unchanged."""

    def test_standalone_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "standalone.yaml"
            path.write_text(_BASE_YAML, encoding="utf-8")

            profile = load_profile(path)
            self.assertEqual(profile.name, "base_test")
            self.assertEqual(profile.platform, "platforms/cortex_m0_nvm.repl")


class LoadProfileRawInheritanceTests(unittest.TestCase):
    """load_profile_raw also resolves base_profile."""

    def test_raw_inherits_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            child_path = Path(tmpdir) / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: base.yaml
                name: raw_child
            """), encoding="utf-8")

            raw = load_profile_raw(child_path)
            self.assertEqual(raw["name"], "raw_child")
            self.assertEqual(raw["platform"], "platforms/cortex_m0_nvm.repl")
            # base_profile key should be consumed (popped)
            self.assertNotIn("base_profile", raw)


class SubdirectoryBaseProfileTests(unittest.TestCase):
    """base_profile paths resolve relative to the child profile's directory."""

    def test_relative_path_to_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir) / "base.yaml"
            base_path.write_text(_BASE_YAML, encoding="utf-8")

            subdir = Path(tmpdir) / "sub"
            subdir.mkdir()
            child_path = subdir / "child.yaml"
            child_path.write_text(textwrap.dedent("""\
                base_profile: ../base.yaml
                name: subdir_child
            """), encoding="utf-8")

            profile = load_profile(child_path)
            self.assertEqual(profile.name, "subdir_child")
            self.assertEqual(profile.platform, "platforms/cortex_m0_nvm.repl")


if __name__ == "__main__":
    unittest.main()
