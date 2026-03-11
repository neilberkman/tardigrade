#!/usr/bin/env python3
"""Tests for multi-fault sweep engine feature."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from fault_inject import (
    MultiFaultPlan,
    MultiFaultResult,
    decode_multi_fault_sequence,
    encode_multi_fault_sequence,
    generate_multi_fault_sequences,
    multi_fault_plan_summary,
    parse_multi_fault_spec,
)
from profile_loader import MultiFaultConfig, load_profile


class TestParseMultiFaultSpec(unittest.TestCase):
    """Existing parse_multi_fault_spec tests (preserved)."""

    def test_single_pair(self) -> None:
        result = parse_multi_fault_spec("100,200")
        self.assertEqual(result, [[100, 200]])

    def test_multiple_runs(self) -> None:
        result = parse_multi_fault_spec("100,200;300,400")
        self.assertEqual(result, [[100, 200], [300, 400]])

    def test_sorts_indices(self) -> None:
        result = parse_multi_fault_spec("500,100")
        self.assertEqual(result, [[100, 500]])

    def test_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            parse_multi_fault_spec("")

    def test_rejects_single_point(self) -> None:
        with self.assertRaises(ValueError):
            parse_multi_fault_spec("100")

    def test_rejects_negative(self) -> None:
        with self.assertRaises(ValueError):
            parse_multi_fault_spec("-1,100")


class TestMultiFaultEncoding(unittest.TestCase):
    """Test encode/decode round-trip for multi-fault sequences."""

    def test_encode_pair(self) -> None:
        enc = encode_multi_fault_sequence([10, 200])
        self.assertEqual(enc, "mf:10:200")

    def test_encode_triple(self) -> None:
        enc = encode_multi_fault_sequence([5, 50, 500])
        self.assertEqual(enc, "mf:5:50:500")

    def test_decode_pair(self) -> None:
        seq = decode_multi_fault_sequence("mf:10:200")
        self.assertEqual(seq, [10, 200])

    def test_decode_triple(self) -> None:
        seq = decode_multi_fault_sequence("mf:5:50:500")
        self.assertEqual(seq, [5, 50, 500])

    def test_round_trip(self) -> None:
        original = [3, 42, 999]
        enc = encode_multi_fault_sequence(original)
        decoded = decode_multi_fault_sequence(enc)
        self.assertEqual(decoded, original)

    def test_encode_rejects_single(self) -> None:
        with self.assertRaises(ValueError):
            encode_multi_fault_sequence([100])

    def test_decode_rejects_non_mf_prefix(self) -> None:
        with self.assertRaises(ValueError):
            decode_multi_fault_sequence("p2:10:20:w:w")

    def test_decode_rejects_single_point(self) -> None:
        with self.assertRaises(ValueError):
            decode_multi_fault_sequence("mf:100")


class TestGenerateExplicit(unittest.TestCase):
    """Test explicit multi-fault sequence generation."""

    def test_explicit_basic(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="explicit",
            interesting_points=[],
            explicit_sequences=[[10, 20], [30, 40]],
        )
        self.assertEqual(plan.strategy, "explicit")
        self.assertEqual(len(plan.sequences), 2)
        self.assertEqual(plan.sequences[0], [10, 20])
        self.assertEqual(plan.sequences[1], [30, 40])

    def test_explicit_sorts_each_sequence(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="explicit",
            interesting_points=[],
            explicit_sequences=[[200, 100]],
        )
        self.assertEqual(plan.sequences[0], [100, 200])

    def test_explicit_requires_sequences(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="explicit",
                interesting_points=[],
                explicit_sequences=None,
            )

    def test_explicit_rejects_single_point_sequence(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="explicit",
                interesting_points=[],
                explicit_sequences=[[100]],
            )

    def test_explicit_rejects_exceeding_max_faults(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="explicit",
                interesting_points=[],
                max_faults_per_run=2,
                explicit_sequences=[[10, 20, 30]],
            )


class TestGeneratePairwiseInteresting(unittest.TestCase):
    """Test pairwise_interesting strategy."""

    def test_small_set_exhaustive(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[10, 20, 30],
        )
        self.assertEqual(plan.strategy, "pairwise_interesting")
        # C(3,2) = 3 pairs
        self.assertEqual(len(plan.sequences), 3)
        self.assertIn([10, 20], plan.sequences)
        self.assertIn([10, 30], plan.sequences)
        self.assertIn([20, 30], plan.sequences)
        self.assertTrue(plan.diagnostics["exhaustive"])

    def test_deduplicates_interesting_points(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[10, 10, 20, 20, 30],
        )
        # Should deduplicate: 3 unique points -> C(3,2) = 3 pairs
        self.assertEqual(len(plan.sequences), 3)
        self.assertEqual(plan.interesting_point_count, 3)

    def test_max_pairs_caps(self) -> None:
        # 20 points -> C(20,2) = 190 pairs, cap at 50.
        pts = list(range(0, 200, 10))  # 20 points
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=pts,
            max_pairs=50,
        )
        self.assertEqual(len(plan.sequences), 50)
        self.assertFalse(plan.diagnostics["exhaustive"])

    def test_empty_interesting_returns_empty(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
        )
        self.assertEqual(plan.sequences, [])
        self.assertEqual(plan.diagnostics.get("reason"), "no_interesting_points")

    def test_single_point_returns_empty(self) -> None:
        # Can't form a pair from 1 point.
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[42],
        )
        self.assertEqual(plan.sequences, [])

    def test_cost_model_100_points(self) -> None:
        """Verify cost for 100 interesting points is manageable."""
        pts = list(range(100))
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=pts,
            max_pairs=5000,
        )
        # C(100,2) = 4950, under 5000 cap.
        self.assertEqual(len(plan.sequences), 4950)
        self.assertTrue(plan.diagnostics["exhaustive"])
        self.assertEqual(plan.diagnostics["theoretical_combinations"], 4950)

    def test_boundary_fallback_used_when_no_interesting_points(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="boundary_pairs",
            fallback_points=[0, 10, 20, 30],
        )
        self.assertEqual(plan.strategy, "boundary_pairs")
        self.assertTrue(plan.diagnostics["fallback_used"])
        self.assertEqual(plan.diagnostics["fallback_strategy"], "boundary_pairs")
        self.assertEqual(plan.diagnostics["primary_reason"], "no_interesting_points")
        self.assertIn([0, 10], plan.sequences)
        self.assertIn([20, 30], plan.sequences)
        self.assertIn([0, 30], plan.sequences)

    def test_boundary_fallback_uses_nonempty_candidate_set(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[42],
            fallback_strategy="boundary_pairs",
            fallback_points=[5, 15],
        )
        self.assertTrue(plan.diagnostics["fallback_used"])
        self.assertEqual(plan.sequences, [[5, 15]])

    def test_fallback_none_preserves_empty_plan(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="none",
            fallback_points=[0, 10, 20],
        )
        self.assertEqual(plan.sequences, [])
        self.assertNotIn("fallback_used", plan.diagnostics)


class TestGenerateRandomSample(unittest.TestCase):
    """Test random_sample strategy."""

    def test_deterministic_with_seed(self) -> None:
        pts = list(range(50))
        plan1 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=42,
        )
        plan2 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=42,
        )
        self.assertEqual(plan1.sequences, plan2.sequences)

    def test_different_seeds_differ(self) -> None:
        pts = list(range(50))
        plan1 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=42,
        )
        plan2 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=99,
        )
        # Very unlikely to be identical with different seeds.
        self.assertNotEqual(plan1.sequences, plan2.sequences)

    def test_caps_at_max_pairs(self) -> None:
        pts = list(range(100))  # C(100,2) = 4950
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=200,
            seed=1,
        )
        self.assertEqual(len(plan.sequences), 200)

    def test_small_set_returns_all(self) -> None:
        pts = [10, 20, 30]
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=1000,
            seed=1,
        )
        # C(3,2) = 3, all fit.
        self.assertEqual(len(plan.sequences), 3)

    def test_no_duplicate_sequences(self) -> None:
        pts = list(range(100))
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=500,
            seed=7,
        )
        tuples = [tuple(s) for s in plan.sequences]
        self.assertEqual(len(tuples), len(set(tuples)))

    def test_empty_interesting_returns_empty(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=[],
            seed=1,
        )
        self.assertEqual(len(plan.sequences), 0)


class TestMultiFaultPlanSummary(unittest.TestCase):
    """Test JSON-serializable summary output."""

    def test_summary_fields(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[10, 20, 30],
        )
        summary = multi_fault_plan_summary(plan)
        self.assertEqual(summary["strategy"], "pairwise_interesting")
        self.assertEqual(summary["sequences"], 3)
        self.assertEqual(summary["interesting_points"], 3)
        self.assertEqual(summary["max_faults_per_run"], 2)
        self.assertIsNone(summary["seed"])
        self.assertEqual(summary["sequence_semantics"], "stage_relative_reboot")
        self.assertIn("successive reboot/recovery stage", summary["sequence_description"])
        self.assertEqual(summary["sample_sequences"], [[10, 20], [10, 30], [20, 30]])
        self.assertFalse(summary["sample_truncated"])
        self.assertIn("diagnostics", summary)

    def test_summary_preview_truncates(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=list(range(6)),
            max_pairs=100,
        )
        summary = multi_fault_plan_summary(plan)
        self.assertEqual(summary["sequences"], 15)
        self.assertEqual(len(summary["sample_sequences"]), 10)
        self.assertTrue(summary["sample_truncated"])


class TestMultiFaultProfileParsing(unittest.TestCase):
    """Test multi_fault YAML profile parsing."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_defaults_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_defaults
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
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertFalse(profile.fault_sweep.multi_fault.enabled)
            self.assertEqual(profile.fault_sweep.multi_fault.strategy, "pairwise_interesting")
            self.assertEqual(profile.fault_sweep.multi_fault.max_faults_per_run, 2)
            self.assertEqual(profile.fault_sweep.multi_fault.max_pairs, 5000)
            self.assertIsNone(profile.fault_sweep.multi_fault.seed)
            self.assertEqual(profile.fault_sweep.multi_fault.sequences, [])

    def test_pairwise_interesting_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_pairwise
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
                  multi_fault:
                    enabled: true
                    strategy: pairwise_interesting
                    max_pairs: 2000
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertTrue(profile.fault_sweep.multi_fault.enabled)
            self.assertEqual(profile.fault_sweep.multi_fault.strategy, "pairwise_interesting")
            self.assertEqual(profile.fault_sweep.multi_fault.fallback_strategy, "boundary_pairs")
            self.assertEqual(profile.fault_sweep.multi_fault.max_pairs, 2000)

    def test_explicit_with_sequences(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_explicit
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
                  multi_fault:
                    enabled: true
                    strategy: explicit
                    sequences:
                      - [100, 200]
                      - [300, 400, 500]
                    max_faults_per_run: 3
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertTrue(profile.fault_sweep.multi_fault.enabled)
            self.assertEqual(profile.fault_sweep.multi_fault.strategy, "explicit")
            self.assertEqual(len(profile.fault_sweep.multi_fault.sequences), 2)
            self.assertEqual(profile.fault_sweep.multi_fault.sequences[0], [100, 200])
            self.assertEqual(profile.fault_sweep.multi_fault.sequences[1], [300, 400, 500])
            self.assertEqual(profile.fault_sweep.multi_fault.max_faults_per_run, 3)

    def test_random_sample_with_seed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_random
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
                  multi_fault:
                    enabled: true
                    strategy: random_sample
                    seed: 42
                    max_pairs: 500
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertTrue(profile.fault_sweep.multi_fault.enabled)
            self.assertEqual(profile.fault_sweep.multi_fault.strategy, "random_sample")
            self.assertEqual(profile.fault_sweep.multi_fault.fallback_strategy, "boundary_pairs")
            self.assertEqual(profile.fault_sweep.multi_fault.seed, 42)
            self.assertEqual(profile.fault_sweep.multi_fault.max_pairs, 500)

    def test_fallback_strategy_parses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_fallback_strategy
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
                  multi_fault:
                    enabled: true
                    strategy: pairwise_interesting
                    fallback_strategy: none
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertEqual(profile.fault_sweep.multi_fault.fallback_strategy, "none")

    def test_invalid_strategy_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_bad_strategy
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
                  multi_fault:
                    enabled: true
                    strategy: bogus
                """,
            )
            from profile_loader import ProfileError
            with self.assertRaises(ProfileError):
                load_profile(str(profile_path))

    def test_max_faults_per_run_below_2_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_bad_max_faults
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
                  multi_fault:
                    enabled: true
                    max_faults_per_run: 1
                """,
            )
            from profile_loader import ProfileError
            with self.assertRaises(ProfileError):
                load_profile(str(profile_path))


class TestMultiFaultValidation(unittest.TestCase):
    """Validate error handling in generate_multi_fault_sequences."""

    def test_unknown_strategy_rejected(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="bogus",
                interesting_points=[10, 20],
            )

    def test_max_faults_below_2_rejected(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="pairwise_interesting",
                interesting_points=[10, 20],
                max_faults_per_run=1,
            )

    def test_unknown_fallback_strategy_rejected(self) -> None:
        with self.assertRaises(ValueError):
            generate_multi_fault_sequences(
                strategy="pairwise_interesting",
                interesting_points=[],
                fallback_strategy="bogus",
            )


class TestLargeCandidateSets(unittest.TestCase):
    """Verify planner handles large candidate sets without blowing up memory."""

    def test_pairwise_interesting_large_input_capped(self) -> None:
        """1000 candidates -> C(1000,2)=499500, but max_pairs=50 caps it."""
        pts = list(range(1000))
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=pts,
            max_pairs=50,
        )
        self.assertEqual(len(plan.sequences), 50)
        self.assertFalse(plan.diagnostics["exhaustive"])
        self.assertEqual(plan.diagnostics["theoretical_combinations"], 499500)
        self.assertEqual(plan.diagnostics["capped_at"], 50)
        # All sequences should be valid pairs from the input range
        for seq in plan.sequences:
            self.assertEqual(len(seq), 2)
            self.assertIn(seq[0], pts)
            self.assertIn(seq[1], pts)

    def test_random_sample_large_input_capped(self) -> None:
        """1000 candidates -> C(1000,2)=499500, sample 100."""
        pts = list(range(1000))
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=42,
        )
        self.assertEqual(len(plan.sequences), 100)
        self.assertFalse(plan.diagnostics["exhaustive"])
        self.assertEqual(plan.diagnostics["theoretical_combinations"], 499500)
        self.assertEqual(plan.diagnostics["sampled"], 100)
        # No duplicates
        tuples = [tuple(s) for s in plan.sequences]
        self.assertEqual(len(tuples), len(set(tuples)))

    def test_random_sample_large_deterministic(self) -> None:
        """Same seed on large input produces identical results."""
        pts = list(range(1000))
        plan1 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=7,
        )
        plan2 = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=100,
            seed=7,
        )
        self.assertEqual(plan1.sequences, plan2.sequences)

    def test_pairwise_large_runs_quickly(self) -> None:
        """5000 candidates with low cap should return near-instantly."""
        import time

        pts = list(range(5000))
        t0 = time.monotonic()
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=pts,
            max_pairs=20,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(len(plan.sequences), 20)
        # C(5000,2) = 12497500 -- must not materialize all of them
        self.assertEqual(plan.diagnostics["theoretical_combinations"], 12497500)
        self.assertLess(elapsed, 2.0, "should complete in under 2 seconds")

    def test_random_sample_large_runs_quickly(self) -> None:
        """5000 candidates sampled down to 50 should return quickly."""
        import time

        pts = list(range(5000))
        t0 = time.monotonic()
        plan = generate_multi_fault_sequences(
            strategy="random_sample",
            interesting_points=pts,
            max_pairs=50,
            seed=1,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(len(plan.sequences), 50)
        self.assertEqual(plan.diagnostics["theoretical_combinations"], 12497500)
        self.assertLess(elapsed, 2.0, "should complete in under 2 seconds")


class TestMultiFaultResult(unittest.TestCase):
    """Test MultiFaultResult data structure."""

    def test_fields(self) -> None:
        result = MultiFaultResult(
            fault_sequence=[10, 200],
            boot_outcome="no_boot",
            boot_slot=None,
            nvm_state={"some": "state"},
            per_fault_states=[
                {"write_index": 10, "partial": True},
                {"write_index": 200, "partial": True},
            ],
            raw_log="test log",
        )
        self.assertEqual(result.fault_sequence, [10, 200])
        self.assertEqual(result.boot_outcome, "no_boot")
        self.assertEqual(len(result.per_fault_states), 2)
        self.assertFalse(result.is_control)


class TestInterestingPointIdentification(unittest.TestCase):
    """Test that interesting fault points are correctly extracted from sweep results."""

    def _identify_interesting(self, sweep_results):
        """Use the actual audit_bootloader helper."""
        from audit_bootloader import _interesting_multi_fault_points

        return _interesting_multi_fault_points(sweep_results, "success")

    def test_bricks_are_interesting(self) -> None:
        results = [
            {"fault_at": 10, "fault_injected": True, "boot_outcome": "no_boot"},
            {"fault_at": 20, "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
            {"fault_at": 30, "fault_injected": True, "boot_outcome": "hard_fault"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [10, 30])

    def test_wrong_image_is_interesting(self) -> None:
        results = [
            {"fault_at": 5, "fault_injected": True, "boot_outcome": "wrong_image"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [5])

    def test_control_excluded(self) -> None:
        results = [
            {"fault_at": 999999, "fault_injected": True, "boot_outcome": "no_boot", "is_control": True},
            {"fault_at": 10, "fault_injected": True, "boot_outcome": "no_boot"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [10])

    def test_no_fault_injected_excluded(self) -> None:
        results = [
            {"fault_at": 10, "fault_injected": False, "boot_outcome": "no_boot"},
            {"fault_at": 20, "fault_injected": True, "boot_outcome": "no_boot"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [20])

    def test_success_not_interesting(self) -> None:
        results = [
            {"fault_at": 10, "fault_injected": True, "boot_outcome": "success", "boot_slot": "exec"},
            {"fault_at": 20, "fault_injected": True, "boot_outcome": "success", "boot_slot": "staging"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [])

    def test_deduplicates(self) -> None:
        results = [
            {"fault_at": 10, "fault_injected": True, "boot_outcome": "no_boot"},
            {"fault_at": 10, "fault_injected": True, "boot_outcome": "hard_fault"},
        ]
        pts = self._identify_interesting(results)
        self.assertEqual(pts, [10])


if __name__ == "__main__":
    unittest.main()
