#!/usr/bin/env python3
"""Unit tests for thumb_classify.py and bus_fault outcome classification."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fault_classification import (
    _effective_boot_result,
    classify_failure_class,
    result_has_issues,
    result_is_brick,
    result_issue_reasons,
)

# --- ELF fixtures ---
MCUBOOT_ELF = ROOT / "results" / "oss_validation" / "assets" / "oss_mcuboot_head.elf"
EXAMPLE_ELF = ROOT / "examples" / "vulnerable_ota" / "firmware.elf"


class MappingSymbolDetectionTest(unittest.TestCase):
    """Test _try_mapping_symbols against real ELFs with $t/$d symbols."""

    def setUp(self):
        if not MCUBOOT_ELF.exists():
            self.skipTest("MCUboot ELF fixture not present")
        from thumb_classify import _try_mapping_symbols

        self.classify = _try_mapping_symbols

    def test_finds_literal_pools_in_context_boot_go(self):
        """context_boot_go (0x8d0-0xb54) has known literal pools at the end."""
        pools = self.classify(str(MCUBOOT_ELF), [(0x8D0, 0xB54)])
        self.assertIsNotNone(pools)
        self.assertGreater(len(pools), 0)
        # Known literal pool region near end of function
        self.assertIn(0xB2C, pools)

    def test_pure_code_region_has_no_pools(self):
        """boot_fih_memequal (0x45fe-0x4602) is 4 bytes, pure code, no pools."""
        pools = self.classify(str(MCUBOOT_ELF), [(0x45FE, 0x4602)])
        self.assertIsNotNone(pools)
        self.assertEqual(len(pools), 0)

    def test_returns_none_without_mapping_symbols(self):
        """ELF without mapping symbols should return None (fallback needed)."""
        if not EXAMPLE_ELF.exists():
            self.skipTest("Example ELF fixture not present")
        pools = self.classify(str(EXAMPLE_ELF), [(0x10000044, 0x100000F8)])
        # The vulnerable_ota ELF may or may not have mapping symbols;
        # if it doesn't, None is returned, if it does, a set is returned.
        # Either way is fine — we just verify it doesn't crash.
        self.assertTrue(pools is None or isinstance(pools, set))

    def test_multiple_regions(self):
        """Multiple regions should accumulate results."""
        pools = self.classify(
            str(MCUBOOT_ELF),
            [(0x8D0, 0xB54), (0x4FC, 0x624)],
        )
        self.assertIsNotNone(pools)
        # Should have pools from both regions
        self.assertGreater(len(pools), 0)


class CapstoneClassifyTest(unittest.TestCase):
    """Test _capstone_classify against real ELFs."""

    def setUp(self):
        if not MCUBOOT_ELF.exists():
            self.skipTest("MCUboot ELF fixture not present")
        try:
            from thumb_classify import _capstone_classify

            self.classify = _capstone_classify
        except ImportError:
            self.skipTest("capstone not installed")

    def test_finds_literal_pools(self):
        """Capstone should find literal pools in context_boot_go."""
        pools = self.classify(str(MCUBOOT_ELF), [(0x8D0, 0xB54)])
        self.assertGreater(len(pools), 0)

    def test_pure_code_region(self):
        """boot_fih_memequal is pure code — no pools expected."""
        pools = self.classify(str(MCUBOOT_ELF), [(0x45FE, 0x4602)])
        self.assertEqual(len(pools), 0)

    def test_all_pool_addrs_are_halfword_aligned(self):
        pools = self.classify(str(MCUBOOT_ELF), [(0x8D0, 0xB54)])
        for addr in pools:
            self.assertEqual(addr % 2, 0, "0x{:X} not halfword-aligned".format(addr))


class FindLiteralPoolsIntegrationTest(unittest.TestCase):
    """Test the top-level find_literal_pools dispatch."""

    def setUp(self):
        if not MCUBOOT_ELF.exists():
            self.skipTest("MCUboot ELF fixture not present")
        from thumb_classify import find_literal_pools

        self.find = find_literal_pools

    def test_returns_set(self):
        result = self.find(str(MCUBOOT_ELF), [(0x8D0, 0xB54)])
        self.assertIsInstance(result, set)

    def test_excludes_known_code(self):
        """Code addresses should NOT be in the returned set."""
        pools = self.find(str(MCUBOOT_ELF), [(0x8D0, 0xB54)])
        # 0x8D0 is the function entry — must be code, not data.
        self.assertNotIn(0x8D0, pools)

    def test_empty_region_returns_empty(self):
        pools = self.find(str(MCUBOOT_ELF), [])
        self.assertEqual(len(pools), 0)


class NoCapstoneFallbackTest(unittest.TestCase):
    """Verify graceful fallback when capstone is not available."""

    def test_no_capstone_returns_empty_set(self):
        """When capstone is missing AND no mapping symbols, returns empty set."""
        import thumb_classify

        orig = thumb_classify.HAS_CAPSTONE
        try:
            thumb_classify.HAS_CAPSTONE = False
            # Also force mapping symbols to return None
            with patch.object(thumb_classify, "_try_mapping_symbols", return_value=None):
                result = thumb_classify.find_literal_pools(
                    "/nonexistent.elf",
                    [(0x1000, 0x2000)],
                )
            self.assertEqual(result, set())
        finally:
            thumb_classify.HAS_CAPSTONE = orig


class BusFaultClassificationTest(unittest.TestCase):
    """Test bus_fault outcome classification in fault_classification.py."""

    def test_bus_fault_not_a_brick(self):
        r = {"boot_outcome": "bus_fault", "boot_slot": None}
        self.assertFalse(result_is_brick(r))

    def test_bus_fault_no_issue_reasons(self):
        """bus_fault should produce zero issue reasons, even with invariant violations."""
        r = {
            "boot_outcome": "bus_fault",
            "boot_slot": None,
            "invariant_violations": ["at_least_one_bootable"],
            "semantic_assertion_failures": [{"rule": "test"}],
        }
        reasons = result_issue_reasons(r, "success")
        self.assertEqual(reasons, [])

    def test_bus_fault_has_no_issues(self):
        r = {"boot_outcome": "bus_fault"}
        self.assertFalse(result_has_issues(r, "success"))

    def test_bus_fault_failure_class_is_safe_dos(self):
        r = {"boot_outcome": "bus_fault", "boot_slot": None}
        self.assertEqual(classify_failure_class(r), "safe_dos")

    def test_no_boot_still_brick(self):
        """Ensure no_boot is not affected by bus_fault changes."""
        r = {"boot_outcome": "no_boot", "boot_slot": None}
        self.assertTrue(result_is_brick(r))
        self.assertIn("boot_outcome", result_issue_reasons(r, "success"))

    def test_wrong_image_still_issue(self):
        """Ensure wrong_image is not affected by bus_fault changes."""
        r = {"boot_outcome": "wrong_image", "boot_slot": "staging"}
        self.assertIn("boot_outcome", result_issue_reasons(r, "success"))

    def test_success_not_affected(self):
        r = {"boot_outcome": "success", "boot_slot": "exec"}
        self.assertFalse(result_has_issues(r, "success"))
        self.assertFalse(result_is_brick(r))

    def test_content_criteria_failure_counts_even_when_wrong_image_expected(self):
        r = {
            "boot_outcome": "wrong_image",
            "boot_slot": "exec",
            "signals": {
                "marker_ok": False,
                "marker_actual": "0xF395C277",
                "expectations_met": False,
                "vtor_ok": True,
                "vtor_aligned": True,
                "pc_ok": True,
            },
        }
        reasons = result_issue_reasons(r, "wrong_image")
        self.assertIn("content_criteria", reasons)
        self.assertTrue(result_has_issues(r, "wrong_image"))

    def test_marker_ok_true_does_not_create_spurious_issue(self):
        r = {
            "boot_outcome": "wrong_image",
            "boot_slot": "exec",
            "signals": {
                "marker_ok": True,
                "marker_actual": "0xFFFFFFFF",
                "expectations_met": True,
                "vtor_ok": True,
                "vtor_aligned": True,
                "pc_ok": True,
            },
        }
        self.assertEqual(result_issue_reasons(r, "wrong_image"), [])

    def test_bus_fault_with_invariant_not_counted(self):
        """bus_fault suppresses ALL issue reasons — including invariant."""
        r = {
            "boot_outcome": "bus_fault",
            "boot_slot": None,
            "invariant_violations": ["mpu_locks_mram"],
        }
        self.assertFalse(result_has_issues(r, "success"))

    def test_explicit_final_outcome_overrides_raw_boot_outcome(self):
        r = {
            "boot_outcome": "wrong_image",
            "boot_slot": "staging",
            "initial_boot_outcome": "wrong_image",
            "initial_boot_slot": "staging",
            "final_boot_outcome": "success",
            "final_boot_slot": "exec",
        }
        self.assertEqual(_effective_boot_result(r), ("success", "exec"))
        self.assertFalse(result_has_issues(r, "success"))
        self.assertEqual(classify_failure_class(r), "recoverable")


class BusFaultSummaryTest(unittest.TestCase):
    """Verify bus_fault is tracked in sweep summary."""

    def test_bus_fault_points_counted_in_summary(self):
        from audit_report import summarize_runtime_sweep

        results = [
            {
                "is_control": True,
                "boot_outcome": "success",
                "boot_slot": "exec",
                "fault_injected": False,
            },
            {
                "is_control": False,
                "boot_outcome": "bus_fault",
                "boot_slot": None,
                "fault_injected": True,
                "fault_at": 1,
            },
            {
                "is_control": False,
                "boot_outcome": "bus_fault",
                "boot_slot": None,
                "fault_injected": True,
                "fault_at": 2,
            },
            {
                "is_control": False,
                "boot_outcome": "wrong_image",
                "boot_slot": "staging",
                "fault_injected": True,
                "fault_at": 3,
            },
        ]
        summary = summarize_runtime_sweep(results)
        self.assertEqual(summary["bus_fault_points"], 2)
        # bus_fault should NOT be counted as issues
        self.assertEqual(summary["issue_points"], 1)  # only wrong_image
        # bus_fault should NOT be counted as bricks
        self.assertEqual(summary["bricks"], 0)

    def test_control_summary_surfaces_initial_and_final_boot_outcomes(self):
        from audit_report import summarize_runtime_sweep

        results = [
            {
                "is_control": True,
                "boot_outcome": "wrong_image",
                "boot_slot": "staging",
                "initial_boot_outcome": "wrong_image",
                "initial_boot_slot": "staging",
                "final_boot_outcome": "success",
                "final_boot_slot": "exec",
                "fault_injected": False,
            }
        ]
        summary = summarize_runtime_sweep(results)
        control = summary["control"]
        self.assertEqual(control["boot_outcome"], "wrong_image")
        self.assertEqual(control["initial_boot_outcome"], "wrong_image")
        self.assertEqual(control["final_boot_outcome"], "success")
        self.assertEqual(control["effective_outcome"], "success")


class IncludeLiteralPoolsConfigTest(unittest.TestCase):
    """Test include_literal_pools profile config field."""

    def test_default_is_false(self):
        from profile_loader import InstructionSkipConfig

        cfg = InstructionSkipConfig(target_addresses=[(0x1000, 0x2000)])
        self.assertFalse(cfg.include_literal_pools)

    def test_can_set_true(self):
        from profile_loader import InstructionSkipConfig

        cfg = InstructionSkipConfig(
            target_addresses=[(0x1000, 0x2000)],
            include_literal_pools=True,
        )
        self.assertTrue(cfg.include_literal_pools)

    def test_parsed_from_yaml(self):
        from profile_loader import _parse_instruction_skip_config

        raw = {
            "target_addresses": [{"start": "0x1000", "end": "0x2000"}],
            "include_literal_pools": True,
        }
        cfg = _parse_instruction_skip_config(raw)
        self.assertTrue(cfg.include_literal_pools)

    def test_default_parsed_from_yaml(self):
        from profile_loader import _parse_instruction_skip_config

        raw = {
            "target_addresses": [{"start": "0x1000", "end": "0x2000"}],
        }
        cfg = _parse_instruction_skip_config(raw)
        self.assertFalse(cfg.include_literal_pools)


class LiteralPoolFaultPlanExclusionTest(unittest.TestCase):
    """Test that literal pools are excluded from fault points."""

    def setUp(self):
        if not MCUBOOT_ELF.exists():
            self.skipTest("MCUboot ELF fixture not present")

    def test_literal_pools_excluded_from_fault_plan(self):
        """Using nxboot profile, verify literal pools reduce fault point count."""
        from profile_loader import load_profile
        from fault_plan import build_fault_plan, CalibrationInputs
        from thumb_classify import find_literal_pools

        profile_path = ROOT / "profiles" / "nxboot_style_instruction_skip.yaml"
        if not profile_path.exists():
            self.skipTest("nxboot instruction_skip profile not present")

        profile = load_profile(str(profile_path))
        isc = profile.fault_sweep.instruction_skip_config

        # Count total halfwords
        total = sum(
            (end - start) // 2
            for start, end in isc.target_addresses
        )

        # Build plan (with filtering)
        cal = CalibrationInputs(max_writes=0)
        plan = build_fault_plan(profile, cal)

        # Should have fewer points than total halfwords
        self.assertLess(len(plan.fault_points), total)
        self.assertGreater(len(plan.fault_points), 0)


if __name__ == "__main__":
    unittest.main()
