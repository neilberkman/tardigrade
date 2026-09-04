#!/usr/bin/env python3
"""Regression tests for generic self-test profile discovery."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from self_test import (
    build_detailed_result,
    check_verdict,
    discover_profiles,
    load_self_test_profile_names,
    load_runtime_manifest,
    partition_profiles_by_estimated_cost,
    partition_profiles_round_robin,
    run_audit,
    shard_costs_s,
    write_summary,
)


class SelfTestProfileDiscoveryTests(unittest.TestCase):
    def test_runtime_manifest_matches_discovered_profiles(self):
        discovered = {path.name for path in discover_profiles(ROOT)}
        _default_cost_s, profile_costs = load_runtime_manifest(ROOT)
        allowlist = load_self_test_profile_names(ROOT)
        self.assertIsNotNone(allowlist)
        self.assertEqual(allowlist, discovered)
        self.assertTrue(discovered.issubset(set(profile_costs)))

    def test_runtime_manifest_assigns_known_outlier_costs(self):
        default_cost_s, profile_costs = load_runtime_manifest(ROOT)

        self.assertGreater(default_cost_s, 0)
        self.assertIn("fault_no_crc_selftest.yaml", profile_costs)
        self.assertIn("mcuboot_head_scratch_nrf52_revert_extended.yaml", profile_costs)
        self.assertGreater(
            profile_costs["mcuboot_head_scratch_nrf52_revert_extended.yaml"],
            profile_costs["fault_no_crc_selftest.yaml"],
        )

    def test_weighted_sharding_reduces_ci_peak_cost(self):
        profiles = discover_profiles(ROOT)
        default_cost_s, profile_costs = load_runtime_manifest(ROOT)

        round_robin = partition_profiles_round_robin(profiles, 5)
        weighted = partition_profiles_by_estimated_cost(
            profiles,
            5,
            profile_costs,
            default_cost_s,
        )

        round_robin_costs = shard_costs_s(round_robin, profile_costs, default_cost_s)
        weighted_costs = shard_costs_s(weighted, profile_costs, default_cost_s)

        self.assertLess(max(weighted_costs), max(round_robin_costs))
        self.assertLessEqual(
            max(weighted_costs) - min(weighted_costs),
            max(round_robin_costs) - min(round_robin_costs),
        )

    def test_weighted_ci_shards_leave_headroom_for_timeout(self):
        profiles = discover_profiles(ROOT)
        default_cost_s, profile_costs = load_runtime_manifest(ROOT)
        weighted = partition_profiles_by_estimated_cost(
            profiles,
            5,
            profile_costs,
            default_cost_s,
        )

        # CI allows 45 minutes per shard; keep at least five minutes for
        # setup, teardown, and runtime variance beyond profile estimates.
        ci_timeout_s = 45 * 60
        required_headroom_s = 5 * 60
        self.assertLessEqual(
            max(shard_costs_s(weighted, profile_costs, default_cost_s)),
            ci_timeout_s - required_headroom_s,
        )

    def test_runtime_manifest_keeps_measured_otp_harness_cost(self):
        _default_cost_s, profile_costs = load_runtime_manifest(ROOT)
        self.assertGreaterEqual(
            profile_costs["firmware_otp_blow_nop_harness.yaml"],
            1700,
            "the long-running OTP harness must not fall back to a generic estimate",
        )

    def test_benchmark_and_execute_only_profiles_are_skipped(self):
        repo_root = ROOT
        discovered = {p.name for p in discover_profiles(repo_root)}

        self.assertNotIn("nuttx_nxboot_128.yaml", discovered)
        self.assertNotIn("security_toctou_no_protection.yaml", discovered)
        self.assertNotIn("security_toctou_with_protection.yaml", discovered)
        self.assertNotIn("fault_copy_before_validate.yaml", discovered)
        self.assertNotIn("fault_staging_overlap.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_extended.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults_long.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_rc_injection.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_nohashbypass.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_upgrade_extended_selftest.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_verify_instruction_skip.yaml", discovered)
        self.assertNotIn("mcuboot_pr2199_move_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2199_move_fixed.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2214_offset_geom_fixed.yaml", discovered)
        self.assertNotIn("mcuboot_pr2206_scratch_geom_broken.yaml", discovered)
        self.assertNotIn("mcuboot_pr2206_scratch_geom_fixed.yaml", discovered)
        self.assertNotIn("fault_no_crc.yaml", discovered)
        self.assertNotIn("fault_single_replica.yaml", discovered)
        self.assertNotIn("fault_wrong_slot_order.yaml", discovered)
        self.assertNotIn("fault_no_fallback.yaml", discovered)
        self.assertNotIn("fault_no_meta_replication.yaml", discovered)
        self.assertNotIn("fault_no_vector_check.yaml", discovered)
        self.assertNotIn("security_otp_blow_nop.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_stm32f4_fast_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_offset_stm32f4_fast_upgrade.yaml", discovered)
        self.assertNotIn("mcuboot_head_scratch_stm32f4_fast_upgrade.yaml", discovered)
        self.assertIn("fault_copy_before_validate_selftest.yaml", discovered)
        self.assertIn("fault_staging_overlap_selftest.yaml", discovered)
        self.assertNotIn("mcuboot_head_move_nrf52_revert_extended_selftest.yaml", discovered)
        self.assertIn("mcuboot_head_move_nrf52_revert_rc_injection_selftest.yaml", discovered)
        self.assertIn("mcuboot_head_move_nrf52_revert_write_faults_selftest.yaml", discovered)
        self.assertIn("fault_no_crc_selftest.yaml", discovered)
        self.assertIn("fault_single_replica_selftest.yaml", discovered)
        self.assertIn("fault_wrong_slot_order_selftest.yaml", discovered)
        self.assertIn("fault_no_fallback_selftest.yaml", discovered)
        self.assertIn("fault_no_meta_replication_selftest.yaml", discovered)
        self.assertIn("fault_no_vector_check_selftest.yaml", discovered)

    def test_retroactive_negative_controls_expect_no_issues(self):
        negative_controls = [
            "mcuboot_head_move_nrf52_revert_rc_injection.yaml",
            "mcuboot_head_move_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_head_move_nrf52_revert_write_faults.yaml",
            "mcuboot_head_move_nrf52_revert_write_faults_nohashbypass.yaml",
            "mcuboot_head_move_nrf52_seccounter_downgrade_rc_injection.yaml",
            "mcuboot_head_move_stm32f4_revert_driver_error.yaml",
            "mcuboot_head_offset_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_head_scratch_nrf52_revert_rc_injection_multiboot.yaml",
            "mcuboot_pr2109_scratch_fixed_silent.yaml",
        ]
        for relpath in negative_controls:
            with self.subTest(profile=relpath):
                raw = yaml.safe_load((ROOT / "profiles" / relpath).read_text(encoding="utf-8"))
                expect = raw.get("expect", {}) or {}
                self.assertFalse(expect.get("should_find_issues", False), relpath)

    def test_generic_stm32f4_offset_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_offset_stm32f4_upgrade.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(
            raw.get("fault_sweep", {}).get("fault_types"),
            ["power_loss", "swap_progress"],
        )
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x08020014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertNotIn("page_size", raw.get("memory", {}))

    def test_generic_nrf52_move_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(
            raw.get("fault_sweep", {}).get("fault_types"),
            ["power_loss", "swap_progress"],
        )
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertTrue(raw.get("expect", {}).get("should_find_issues"))
        self.assertNotIn("page_size", raw.get("memory", {}))

    def test_extended_nrf52_move_profile_stays_discovery_driven(self):
        raw = yaml.safe_load(
            (
                ROOT / "profiles" / "mcuboot_head_move_nrf52_upgrade_extended.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(raw.get("update_trigger"), "auto")
        self.assertNotIn("pre_boot_state", raw)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
        self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
        self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_move_upgrade_followon_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_move_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_move_nrf52_upgrade_multifault.yaml",
            "mcuboot_head_move_nrf52_upgrade_multifault_selftest.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_offset_upgrade_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_offset_nrf52_upgrade.yaml",
            "mcuboot_head_offset_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_offset_nrf52_upgrade_multifault.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_scratch_upgrade_profiles_use_marker_based_discovery(self):
        for name in [
            "mcuboot_head_scratch_nrf52_upgrade.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_extended.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_phase2fault.yaml",
            "mcuboot_head_scratch_nrf52_upgrade_multifault.yaml",
        ]:
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), 0x0000C014)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), 0x00000101)
                self.assertIn("swap_progress", raw.get("fault_sweep", {}).get("fault_types", []))

    def test_remaining_generic_mcuboot_upgrades_use_discovery(self):
        expected = {
            "mcuboot_head_upgrade.yaml": (0x0000C014, 0x00010001),
            "mcuboot_offset_upgrade.yaml": (0x0000C014, 0x00010001),
            "mcuboot_head_move_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_offset_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_scratch_small_upgrade.yaml": (0x0000C014, 0x00000101),
            "mcuboot_head_move_stm32f4_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_offset_stm32f4_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_move_stm32f4_fast_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_offset_stm32f4_fast_upgrade.yaml": (0x08020014, 0x00000101),
            "mcuboot_head_scratch_stm32f4_upgrade.yaml": (0x08008014, 0x00000101),
            "mcuboot_head_scratch_stm32f4_fast_upgrade.yaml": (0x08008014, 0x00000101),
        }
        for name, (marker_address, marker_value) in expected.items():
            with self.subTest(profile=name):
                raw = yaml.safe_load((ROOT / "profiles" / name).read_text(encoding="utf-8"))
                self.assertEqual(raw.get("update_trigger"), "auto")
                self.assertEqual(raw.get("success_criteria", {}).get("marker_address"), marker_address)
                self.assertEqual(raw.get("success_criteria", {}).get("marker_value"), marker_value)
                self.assertNotIn("image_hash", raw.get("success_criteria", {}))
                self.assertNotIn("expected_image", raw.get("success_criteria", {}))
                fault_types = raw.get("fault_sweep", {}).get("fault_types", [])
                self.assertIn("power_loss", fault_types)
                self.assertIn("swap_progress", fault_types)

    def test_pr2100_discovery_profiles_use_stable_revert_marker(self):
        for name in (
            "mcuboot_pr2100_broken_discovery.yaml",
            "mcuboot_pr2100_fixed_discovery.yaml",
        ):
            with self.subTest(profile=name):
                raw = yaml.safe_load(
                    (ROOT / "profiles" / name).read_text(encoding="utf-8")
                )
                self.assertNotIn("pre_boot_state", raw)
                self.assertEqual(
                    raw.get("update_trigger", {}).get("type"),
                    "mcuboot_trailer_magic",
                )
                success = raw.get("success_criteria", {})
                self.assertEqual(success.get("vtor_in_slot"), "exec")
                self.assertEqual(success.get("marker_address"), 0x0000C014)
                self.assertEqual(success.get("marker_value"), 0x00000001)
                self.assertNotIn("image_hash", success)
                self.assertNotIn("expected_image", success)

    def test_run_audit_forwards_extra_args(self):
        repo_root = ROOT
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        output_path = ROOT / "tmp_self_test_result.json"

        with mock.patch("self_test.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            run_audit(
                repo_root=repo_root,
                profile_path=profile_path,
                output_path=output_path,
                quick=False,
                renode_test="renode-test",
                extra_args=["--workers", "8"],
            )

        cmd = mock_run.call_args.kwargs["args"] if "args" in mock_run.call_args.kwargs else mock_run.call_args.args[0]
        self.assertIn("--workers", cmd)
        self.assertIn("8", cmd)

    def test_run_audit_retries_missing_report_for_clean_control_timeout(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            calls = []

            def fake_run(*args, **kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    return mock.Mock(
                        returncode=2,
                        stderr=(
                            "INFRASTRUCTURE FAILURE: renode-test failed for "
                            "control fault_at=1000000\n"
                            "Test timeout 2 minutes exceeded"
                        ),
                    )
                output_path.write_text('{"verdict":"PASS"}', encoding="utf-8")
                return mock.Mock(returncode=0, stderr="")

            with mock.patch("self_test.subprocess.run", side_effect=fake_run):
                exit_code, report, stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual((exit_code, report, stderr), (0, {"verdict": "PASS"}, ""))
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[1]["env"]["OTA_RENODE_ROBOT_TIMEOUT_MINUTES"],
            "5.0",
        )

    def test_run_audit_timeout_retry_preserves_larger_robot_budget(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            calls = []

            def fake_run(*args, **kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    return mock.Mock(
                        returncode=2,
                        stderr=(
                            "INFRASTRUCTURE FAILURE: renode-test failed for "
                            "control fault_at=1000000\n"
                            "Test timeout 2 minutes exceeded"
                        ),
                    )
                output_path.write_text('{"verdict":"PASS"}', encoding="utf-8")
                return mock.Mock(returncode=0, stderr="")

            with mock.patch.dict(
                "os.environ",
                {"OTA_RENODE_ROBOT_TIMEOUT_MINUTES": "10"},
                clear=False,
            ):
                with mock.patch("self_test.subprocess.run", side_effect=fake_run):
                    exit_code, report, stderr = run_audit(
                        repo_root=ROOT,
                        profile_path=profile_path,
                        output_path=output_path,
                        quick=False,
                        renode_test="renode-test",
                        extra_args=[],
                    )

        self.assertEqual((exit_code, report, stderr), (0, {"verdict": "PASS"}, ""))
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[1]["env"]["OTA_RENODE_ROBOT_TIMEOUT_MINUTES"],
            "10.0",
        )

    def test_run_audit_does_not_retry_non_timeout_control_failure(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            with mock.patch(
                "self_test.subprocess.run",
                return_value=mock.Mock(
                    returncode=2,
                    stderr=(
                        "INFRASTRUCTURE FAILURE: Clean control failed: "
                        "expected outcome 'success', observed 'wrong_image'"
                    ),
                ),
            ) as mock_run:
                exit_code, report, _stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(report, {})
        self.assertEqual(mock_run.call_count, 1)

    def test_run_audit_does_not_retry_fault_point_timeout(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            with mock.patch(
                "self_test.subprocess.run",
                return_value=mock.Mock(
                    returncode=2,
                    stderr=(
                        "INFRASTRUCTURE FAILURE: RenodeTimeoutError: "
                        "renode-test timed out for fault_17 fault_at=17"
                    ),
                ),
            ) as mock_run:
                exit_code, report, _stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(report, {})
        self.assertEqual(mock_run.call_count, 1)

    def test_run_audit_does_not_retry_exit_one_timeout(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            with mock.patch(
                "self_test.subprocess.run",
                return_value=mock.Mock(
                    returncode=1,
                    stderr=(
                        "INFRASTRUCTURE FAILURE: renode-test failed for "
                        "control fault_at=1000000\n"
                        "Test timeout 2 minutes exceeded"
                    ),
                ),
            ) as mock_run:
                exit_code, report, _stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(report, {})
        self.assertEqual(mock_run.call_count, 1)

    def test_run_audit_does_not_retry_when_timeout_report_exists(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            output_path.write_text('{"verdict":"INCONCLUSIVE"}', encoding="utf-8")
            with mock.patch(
                "self_test.subprocess.run",
                return_value=mock.Mock(
                    returncode=2,
                    stderr=(
                        "INFRASTRUCTURE FAILURE: Clean control timed out "
                        "after 120s"
                    ),
                ),
            ) as mock_run:
                exit_code, report, _stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(report, {"verdict": "INCONCLUSIVE"})
        self.assertEqual(mock_run.call_count, 1)

    def test_run_audit_timeout_retry_is_bounded(self):
        profile_path = ROOT / "profiles" / "fault_no_crc.yaml"
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            with mock.patch(
                "self_test.subprocess.run",
                return_value=mock.Mock(
                    returncode=2,
                    stderr=(
                        "INFRASTRUCTURE FAILURE: RenodeTimeoutError: "
                        "renode-test timed out for control fault_at=-1"
                    ),
                ),
            ) as mock_run:
                exit_code, report, _stderr = run_audit(
                    repo_root=ROOT,
                    profile_path=profile_path,
                    output_path=output_path,
                    quick=False,
                    renode_test="renode-test",
                    extra_args=[],
                )

        self.assertEqual(exit_code, 2)
        self.assertEqual(report, {})
        self.assertEqual(mock_run.call_count, 2)

    def test_write_summary_records_partial_progress(self):
        output_path = ROOT / "tmp_self_test_summary.json"
        try:
            write_summary(
                str(output_path),
                total=5,
                detailed_results=[
                    {"profile": "one", "passed": True},
                    {"profile": "two", "passed": False},
                ],
            )
            payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_profiles"], 5)
            self.assertEqual(payload["completed_profiles"], 2)
            self.assertEqual(payload["passed"], 1)
            self.assertEqual(payload["failed"], 1)
        finally:
            output_path.unlink(missing_ok=True)

    def test_build_detailed_result_keeps_raw_audit_verdict_separate(self):
        result = build_detailed_result(
            profile="mcuboot_head_move_nrf52_revert_phase2fault_selftest",
            passed=True,
            reason="No issues found, as expected",
            exit_code=1,
            report={
                "verdict": "FAIL — found 1042 issue points",
                "target_source": {
                    "revision": "4f8c0d3e2a1b9876543210fedcba0123456789ab",
                },
                "summary": {"runtime_sweep": {"bricks": 1042, "brick_rate": 0.97}},
            },
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["audit_verdict"], "FAIL — found 1042 issue points")
        self.assertEqual(result["bricks"], 1042)
        self.assertEqual(result["brick_rate"], 0.97)
        self.assertEqual(
            result["target_source"]["revision"],
            "4f8c0d3e2a1b9876543210fedcba0123456789ab",
        )

    def test_check_verdict_defaults_missing_expect_to_no_issues(self):
        passed, reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={},
            report={
                "verdict": "PASS",
                "summary": {
                    "runtime_sweep": {
                        "issue_points": 0,
                        "bricks": 0,
                        "brick_rate": 0.0,
                        "control": {"effective_outcome": "success"},
                    }
                },
            },
            exit_code=0,
        )

        self.assertTrue(passed)
        self.assertEqual(reason, "No issues found, as expected")

    def test_check_verdict_rejects_infrastructure_exit_even_with_matching_report(self):
        report = {
            "verdict": "PASS",
            "summary": {
                "runtime_sweep": {
                    "issue_points": 0,
                    "bricks": 0,
                    "brick_rate": 0.0,
                    "control": {"effective_outcome": "success"},
                }
            },
        }
        for exit_code in (-9, 2, 3, 127):
            with self.subTest(exit_code=exit_code):
                passed, reason = check_verdict(
                    profile_path=ROOT / "profiles" / "dummy.yaml",
                    profile_raw={},
                    report=report,
                    exit_code=exit_code,
                )
                self.assertFalse(passed)
                self.assertIn("infrastructure failure", reason.lower())

    def test_check_verdict_rejects_incomplete_campaign_before_expectation(self):
        report = {
            "verdict": "PASS",
            "summary": {
                "runtime_sweep": {
                    "issue_points": 0,
                    "bricks": 0,
                    "brick_rate": 0.0,
                    "control": {"effective_outcome": "success"},
                    "campaign_integrity": {
                        "complete": False,
                        "requested": 3,
                        "returned": 2,
                        "incomplete": 1,
                    },
                }
            },
        }
        for profile_raw in (
            {},
            {"expect": {"mode": "exploratory"}},
            {"expect": {"mode": "hunt"}},
        ):
            with self.subTest(profile_raw=profile_raw):
                passed, reason = check_verdict(
                    profile_path=ROOT / "profiles" / "dummy.yaml",
                    profile_raw=profile_raw,
                    report=report,
                    exit_code=1,
                )
                self.assertFalse(passed)
                self.assertIn("campaign integrity is incomplete", reason.lower())

    def test_check_verdict_rejects_infrastructure_invalid_campaign_report(self):
        report = {
            "verdict": "PASS",
            "summary": {
                "runtime_sweep": {
                    "issue_points": 3,
                    "bricks": 3,
                    "brick_rate": 1.0,
                    "control": {"effective_outcome": "success"},
                    "campaign_integrity": {
                        "complete": True,
                        "requested": 3,
                        "returned": 3,
                        "infrastructure_errors": 1,
                    },
                }
            },
        }
        passed, reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={"expect": {"mode": "exploratory"}},
            report=report,
            exit_code=0,
        )
        self.assertFalse(passed)
        self.assertIn("infrastructure_errors", reason)

    def test_check_verdict_rejects_legacy_runtime_failure_counters_without_integrity(self):
        for field in (
            "infrastructure_error_points",
            "timeout_points",
            "missing_result_points",
            "extra_result_points",
            "malformed_result_points",
            "control_timeout_points",
            "skipped_fault_points",
            "incomplete_fault_points",
        ):
            with self.subTest(field=field):
                passed, reason = check_verdict(
                    profile_path=ROOT / "profiles" / "dummy.yaml",
                    profile_raw={"expect": {"mode": "exploratory"}},
                    report={
                        "verdict": "PASS",
                        "summary": {
                            "runtime_sweep": {
                                "issue_points": 0,
                                "bricks": 0,
                                "brick_rate": 0.0,
                                "control": {"effective_outcome": "success"},
                                field: 1,
                            }
                        },
                    },
                    exit_code=0,
                )
                self.assertFalse(passed)
                self.assertIn(field, reason)

    def test_check_verdict_rejects_malformed_runtime_failure_counters(self):
        for value in (-1, True, "0"):
            with self.subTest(value=value):
                passed, reason = check_verdict(
                    profile_path=ROOT / "profiles" / "dummy.yaml",
                    profile_raw={"expect": {"mode": "exploratory"}},
                    report={
                        "verdict": "PASS",
                        "summary": {
                            "runtime_sweep": {
                                "issue_points": 0,
                                "bricks": 0,
                                "brick_rate": 0.0,
                                "control": {"effective_outcome": "success"},
                                "timeout_points": value,
                            }
                        },
                    },
                    exit_code=0,
                )
                self.assertFalse(passed)
                self.assertIn("invalid timeout_points", reason)

    def test_check_verdict_rejects_inconclusive_top_level_verdict(self):
        passed, reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={"expect": {"mode": "exploratory"}},
            report={"verdict": "INCONCLUSIVE -- campaign result coverage is incomplete"},
            exit_code=1,
        )
        self.assertFalse(passed)
        self.assertIn("incomplete or infrastructure-invalid", reason)

    def test_check_verdict_still_allows_assertion_exit_for_expected_fixture(self):
        passed, _reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={},
            report={
                "verdict": "PASS",
                "summary": {
                    "runtime_sweep": {
                        "issue_points": 0,
                        "bricks": 0,
                        "brick_rate": 0.0,
                        "control": {"effective_outcome": "success"},
                    }
                },
            },
            exit_code=1,
        )
        self.assertTrue(passed)

    def test_check_verdict_rejects_faults_when_control_outcome_mismatches(self):
        passed, reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={"expect": {"should_find_issues": True}},
            report={
                "summary": {
                    "runtime_sweep": {
                        "issue_points": 3,
                        "bricks": 3,
                        "control": {"effective_outcome": "wrong_image"},
                    }
                }
            },
            exit_code=0,
        )
        self.assertFalse(passed)
        self.assertEqual(reason, "Control outcome 'wrong_image' != expected 'success'")

    def test_check_verdict_rejects_faults_when_control_is_missing(self):
        passed, reason = check_verdict(
            profile_path=ROOT / "profiles" / "dummy.yaml",
            profile_raw={"expect": {"should_find_issues": True}},
            report={
                "summary": {
                    "runtime_sweep": {
                        "issue_points": 3,
                        "bricks": 3,
                    }
                }
            },
            exit_code=0,
        )
        self.assertFalse(passed)
        self.assertEqual(reason, "Clean control result is missing")

    def test_corrupted_staging_skip_profile_control_expectations(self):
        candidate = yaml.safe_load(
            (
                ROOT
                / "profiles"
                / "mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_candidates.yaml"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(candidate["success_criteria"]["expected_image"], "exec")
        self.assertEqual(candidate["expect"]["control_outcome"], "success")
        self.assertNotIn("allow_control_only_issues", candidate["expect"])

        for name in (
            "mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_critical.yaml",
            "mcuboot_head_move_nrf52_upgrade_verify_corrupt_staging_full.yaml",
        ):
            with self.subTest(profile=name):
                raw = yaml.safe_load(
                    (ROOT / "profiles" / name).read_text(encoding="utf-8")
                )
                self.assertEqual(raw["expect"]["control_outcome"], "wrong_image")
                self.assertTrue(raw["expect"]["allow_control_only_issues"])


if __name__ == "__main__":
    unittest.main()
