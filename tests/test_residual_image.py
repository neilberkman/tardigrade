#!/usr/bin/env python3
"""Unit tests for the residual_image profile config and max_reset_vector_offset
success criterion."""

from __future__ import annotations

import os
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from profile_loader import (  # noqa: E402
    InitialStateConfig,
    ProfileError,
    ResidualImageConfig,
    SuccessCriteria,
    _parse_residual_image,
    _parse_success_criteria,
    expand_initial_states,
    load_profile,
    SlotConfig,
)


# ---------------------------------------------------------------------------
# ResidualImageConfig unit tests
# ---------------------------------------------------------------------------


class TestResidualImageConfig(unittest.TestCase):
    """Test the ResidualImageConfig data model."""

    def test_basic_construction(self):
        cfg = ResidualImageConfig(slot="staging", prior_image="large.bin")
        self.assertEqual(cfg.slot, "staging")
        self.assertEqual(cfg.prior_image, "large.bin")
        self.assertIsNone(cfg.fill_pattern)

    def test_with_fill_pattern(self):
        cfg = ResidualImageConfig(
            slot="exec", prior_image="old.bin", fill_pattern=0xFF
        )
        self.assertEqual(cfg.fill_pattern, 0xFF)

    def test_fill_pattern_zero(self):
        cfg = ResidualImageConfig(
            slot="exec", prior_image="old.bin", fill_pattern=0x00
        )
        self.assertEqual(cfg.fill_pattern, 0x00)

    def test_fill_pattern_out_of_range_raises(self):
        with self.assertRaises(ProfileError):
            ResidualImageConfig(
                slot="exec", prior_image="old.bin", fill_pattern=0x100
            )

    def test_fill_pattern_negative_raises(self):
        with self.assertRaises(ProfileError):
            ResidualImageConfig(
                slot="exec", prior_image="old.bin", fill_pattern=-1
            )

    def test_fill_only_no_prior_image(self):
        cfg = ResidualImageConfig(slot="staging", fill_pattern=0xFF)
        self.assertEqual(cfg.slot, "staging")
        self.assertIsNone(cfg.prior_image)
        self.assertEqual(cfg.fill_pattern, 0xFF)


# ---------------------------------------------------------------------------
# _parse_residual_image tests
# ---------------------------------------------------------------------------


class TestParseResidualImage(unittest.TestCase):
    """Test YAML parsing of the residual_image section."""

    def _slots(self):
        return {
            "exec": SlotConfig(base=0x10000000, size=0x38000),
            "staging": SlotConfig(base=0x10038000, size=0x38000),
        }

    def test_none_returns_none(self):
        result = _parse_residual_image(None, self._slots())
        self.assertIsNone(result)

    def test_valid_minimal(self):
        raw = {"slot": "staging", "prior_image": "old_firmware.bin"}
        result = _parse_residual_image(raw, self._slots())
        self.assertIsNotNone(result)
        self.assertEqual(result.slot, "staging")
        self.assertEqual(result.prior_image, "old_firmware.bin")
        self.assertIsNone(result.fill_pattern)

    def test_valid_with_fill(self):
        raw = {
            "slot": "exec",
            "prior_image": "old.bin",
            "fill_pattern": "0xFF",
        }
        result = _parse_residual_image(raw, self._slots())
        self.assertEqual(result.fill_pattern, 0xFF)

    def test_missing_slot_raises(self):
        raw = {"prior_image": "old.bin"}
        with self.assertRaises(ProfileError):
            _parse_residual_image(raw, self._slots())

    def test_empty_slot_raises(self):
        raw = {"slot": "", "prior_image": "old.bin"}
        with self.assertRaises(ProfileError):
            _parse_residual_image(raw, self._slots())

    def test_unknown_slot_raises(self):
        raw = {"slot": "tertiary", "prior_image": "old.bin"}
        with self.assertRaises(ProfileError):
            _parse_residual_image(raw, self._slots())

    def test_missing_both_prior_and_fill_raises(self):
        raw = {"slot": "staging"}
        with self.assertRaises(ProfileError):
            _parse_residual_image(raw, self._slots())

    def test_fill_only_no_prior_image(self):
        raw = {"slot": "staging", "fill_pattern": "0xFF"}
        result = _parse_residual_image(raw, self._slots())
        self.assertIsNotNone(result)
        self.assertEqual(result.slot, "staging")
        self.assertIsNone(result.prior_image)
        self.assertEqual(result.fill_pattern, 0xFF)

    def test_slot_with_no_image_raises(self):
        """residual_image.slot must have an image configured in images section."""
        raw = {"slot": "staging", "prior_image": "old.bin"}
        images = {"exec": "firmware.bin"}  # staging has no image
        with self.assertRaises(ProfileError):
            _parse_residual_image(raw, self._slots(), images=images)

    def test_fill_only_slot_with_no_image_is_allowed(self):
        raw = {"slot": "staging", "fill_pattern": "0xFF"}
        images = {"exec": "firmware.bin"}  # staging has no image
        result = _parse_residual_image(raw, self._slots(), images=images)
        self.assertIsNotNone(result)
        self.assertEqual(result.slot, "staging")
        self.assertIsNone(result.prior_image)
        self.assertEqual(result.fill_pattern, 0xFF)

    def test_slot_with_image_ok(self):
        raw = {"slot": "staging", "prior_image": "old.bin"}
        images = {"staging": "firmware.bin"}
        result = _parse_residual_image(raw, self._slots(), images=images)
        self.assertIsNotNone(result)

    def test_no_images_dict_skips_validation(self):
        """When images dict is not provided, skip the slot-image validation."""
        raw = {"slot": "staging", "prior_image": "old.bin"}
        result = _parse_residual_image(raw, self._slots())
        self.assertIsNotNone(result)

    def test_non_mapping_raises(self):
        with self.assertRaises(ProfileError):
            _parse_residual_image("not_a_dict", self._slots())


# ---------------------------------------------------------------------------
# max_reset_vector_offset on SuccessCriteria
# ---------------------------------------------------------------------------


class TestMaxResetVectorOffset(unittest.TestCase):
    """Test the max_reset_vector_offset success criterion."""

    def test_default_is_none(self):
        sc = SuccessCriteria()
        self.assertIsNone(sc.max_reset_vector_offset)

    def test_set_value(self):
        sc = SuccessCriteria(max_reset_vector_offset=1024)
        self.assertEqual(sc.max_reset_vector_offset, 1024)

    def test_zero_is_valid(self):
        sc = SuccessCriteria(max_reset_vector_offset=0)
        self.assertEqual(sc.max_reset_vector_offset, 0)

    def test_negative_raises(self):
        with self.assertRaises(ProfileError):
            SuccessCriteria(max_reset_vector_offset=-1)

    def test_parsed_from_yaml(self):
        raw = {
            "vtor_in_slot": "exec",
            "max_reset_vector_offset": 0x1000,
        }
        sc = _parse_success_criteria(raw)
        self.assertEqual(sc.max_reset_vector_offset, 0x1000)

    def test_parsed_hex_string(self):
        raw = {
            "vtor_in_slot": "exec",
            "max_reset_vector_offset": "0x200",
        }
        sc = _parse_success_criteria(raw)
        self.assertEqual(sc.max_reset_vector_offset, 0x200)

    def test_not_present_parses_as_none(self):
        raw = {"vtor_in_slot": "exec"}
        sc = _parse_success_criteria(raw)
        self.assertIsNone(sc.max_reset_vector_offset)


# ---------------------------------------------------------------------------
# Profile loading integration
# ---------------------------------------------------------------------------


class TestResidualImageProfileLoading(unittest.TestCase):
    """Test that profiles with residual_image load correctly."""

    def test_load_naive_profile(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_naive.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        self.assertIsNotNone(profile.residual_image)
        self.assertEqual(profile.residual_image.slot, "staging")
        self.assertIn("test_image.bin", profile.residual_image.prior_image)
        self.assertIsNone(profile.residual_image.fill_pattern)
        self.assertEqual(profile.success_criteria.max_reset_vector_offset, 248)

    def test_load_erased_profile(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_erased.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        self.assertIsNotNone(profile.residual_image)
        self.assertEqual(profile.residual_image.slot, "staging")
        self.assertEqual(profile.residual_image.fill_pattern, 0x00)
        self.assertEqual(profile.success_criteria.max_reset_vector_offset, 248)

    def test_load_pr2199_profile_uses_explicit_erased_staging_asset(self):
        profile_path = ROOT / "profiles" / "mcuboot_pr2199_move_broken.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        self.assertIsNone(profile.residual_image)
        self.assertTrue(profile.images["staging"].endswith("erased_slot_0x76000.bin"))


# ---------------------------------------------------------------------------
# robot_vars emission
# ---------------------------------------------------------------------------


class TestResidualImageRobotVars(unittest.TestCase):
    """Test that residual_image config produces correct robot variables."""

    def test_residual_vars_emitted(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_naive.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        vars_list = profile.robot_vars(ROOT)
        var_dict = {}
        for v in vars_list:
            k, _, val = v.partition(":")
            var_dict[k] = val

        self.assertEqual(var_dict.get("RESIDUAL_IMAGE_SLOT"), "staging")
        self.assertIn("test_image.bin", var_dict.get("RESIDUAL_IMAGE_PRIOR", ""))
        self.assertNotIn("RESIDUAL_IMAGE_FILL", var_dict)

    def test_residual_vars_with_fill(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_erased.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        vars_list = profile.robot_vars(ROOT)
        var_dict = {}
        for v in vars_list:
            k, _, val = v.partition(":")
            var_dict[k] = val

        self.assertEqual(var_dict.get("RESIDUAL_IMAGE_SLOT"), "staging")
        self.assertEqual(var_dict.get("RESIDUAL_IMAGE_FILL"), "0x00")

    def test_max_reset_vector_offset_emitted(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_naive.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        vars_list = profile.robot_vars(ROOT)
        var_dict = {}
        for v in vars_list:
            k, _, val = v.partition(":")
            var_dict[k] = val

        self.assertEqual(var_dict.get("MAX_RESET_VECTOR_OFFSET"), "0x000000F8")

    def test_no_residual_no_vars(self):
        """A profile without residual_image should not emit RESIDUAL_IMAGE vars."""
        profile_path = ROOT / "profiles" / "naive_bare_copy.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        vars_list = profile.robot_vars(ROOT)
        var_keys = [v.partition(":")[0] for v in vars_list]
        self.assertNotIn("RESIDUAL_IMAGE_SLOT", var_keys)
        self.assertNotIn("RESIDUAL_IMAGE_PRIOR", var_keys)
        self.assertNotIn("MAX_RESET_VECTOR_OFFSET", var_keys)


# ---------------------------------------------------------------------------
# initial_states expansion preserves residual_image
# ---------------------------------------------------------------------------


class TestInitialStatesPreservesResidualImage(unittest.TestCase):
    """expand_initial_states must carry residual_image through."""

    def test_residual_image_survives_expansion(self):
        profile_path = ROOT / "profiles" / "fault_residual_image_naive.yaml"
        if not profile_path.exists():
            self.skipTest("Profile not found")
        profile = load_profile(profile_path)
        self.assertIsNotNone(profile.residual_image)

        # Simulate having an initial_state and expanding it.
        state = InitialStateConfig(name="test_state", description="test")
        resolved = profile.resolve_initial_state(state)
        self.assertIsNotNone(resolved.residual_image)
        self.assertEqual(resolved.residual_image.slot, profile.residual_image.slot)
        self.assertEqual(resolved.residual_image.prior_image, profile.residual_image.prior_image)
        self.assertEqual(resolved.residual_image.fill_pattern, profile.residual_image.fill_pattern)


if __name__ == "__main__":
    unittest.main()
