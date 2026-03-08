#!/usr/bin/env python3
"""Tests for enhanced environmental fault modeling (Priority 7).

Covers:
  1. Correlated (clustered) bit-corruption distribution
  2. Multi-fault injection wiring into sweep engine
  3. reset_at_time Phase 2 support
  4. Multi-fault fallback for redundant systems
"""

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
    FaultDistributionConfig,
    MultiFaultPlan,
    apply_clustered_distribution,
    encode_multi_fault_sequence,
    generate_boundary_pairs,
    generate_multi_fault_sequences,
    maybe_apply_fallback,
    multi_fault_plan_summary,
)
from profile_loader import (
    MultiFaultConfig,
    Phase2FaultConfig,
    ProfileError,
    load_profile,
)


# ---------------------------------------------------------------------------
# Feature 1: Correlated bit-corruption distribution
# ---------------------------------------------------------------------------


class TestFaultDistributionConfig(unittest.TestCase):
    """Test FaultDistributionConfig validation."""

    def test_uniform_default(self) -> None:
        cfg = FaultDistributionConfig()
        self.assertEqual(cfg.mode, "uniform")

    def test_clustered_valid(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10100,
            flip_probability_in_cluster=0.2,
            flip_probability_outside=0.01,
            seed=42,
        )
        self.assertEqual(cfg.mode, "clustered")
        self.assertEqual(cfg.cluster_start, 0x10000)
        self.assertEqual(cfg.cluster_end, 0x10100)

    def test_invalid_mode_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FaultDistributionConfig(mode="bogus")

    def test_clustered_requires_valid_range(self) -> None:
        with self.assertRaises(ValueError):
            FaultDistributionConfig(
                mode="clustered",
                cluster_start=0x10100,
                cluster_end=0x10000,
            )

    def test_clustered_equal_range_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FaultDistributionConfig(
                mode="clustered",
                cluster_start=0x10000,
                cluster_end=0x10000,
            )

    def test_probability_in_cluster_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            FaultDistributionConfig(
                mode="clustered",
                cluster_start=0x10000,
                cluster_end=0x10100,
                flip_probability_in_cluster=1.5,
            )

    def test_probability_outside_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            FaultDistributionConfig(
                mode="clustered",
                cluster_start=0x10000,
                cluster_end=0x10100,
                flip_probability_outside=-0.1,
            )


class TestApplyClusteredDistribution(unittest.TestCase):
    """Test apply_clustered_distribution filtering logic."""

    def test_uniform_returns_all(self) -> None:
        cfg = FaultDistributionConfig(mode="uniform", seed=0)
        fps = [0, 1, 2, 3, 4]
        result = apply_clustered_distribution(fps, cfg)
        self.assertEqual(len(result), 5)
        self.assertEqual([fp for fp, _ in result], fps)

    def test_clustered_probability_100_inside(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10100,
            flip_probability_in_cluster=1.0,
            flip_probability_outside=0.0,
            seed=42,
        )
        # All fault points map to addresses inside cluster
        # with slot_base=0x10000, write_granularity=8:
        #   fp=0 -> 0x10000, fp=1 -> 0x10008, ...
        fps = list(range(32))  # 32 * 8 = 256 = 0x100 bytes
        result = apply_clustered_distribution(
            fps, cfg, slot_base=0x10000, write_granularity=8
        )
        # All points inside cluster should be included.
        self.assertEqual(len(result), 32)

    def test_clustered_probability_0_outside(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x20000,
            cluster_end=0x20100,
            flip_probability_in_cluster=1.0,
            flip_probability_outside=0.0,
            seed=42,
        )
        # Points at slot_base=0x10000, all outside cluster
        fps = list(range(10))
        result = apply_clustered_distribution(
            fps, cfg, slot_base=0x10000, write_granularity=8
        )
        self.assertEqual(len(result), 0)

    def test_clustered_deterministic_with_seed(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10100,
            flip_probability_in_cluster=0.5,
            flip_probability_outside=0.1,
            seed=12345,
        )
        fps = list(range(100))
        result1 = apply_clustered_distribution(
            fps, cfg, slot_base=0x10000, write_granularity=8
        )
        result2 = apply_clustered_distribution(
            fps, cfg, slot_base=0x10000, write_granularity=8
        )
        self.assertEqual(result1, result2)

    def test_different_seeds_produce_different_results(self) -> None:
        fps = list(range(100))
        cfg1 = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10200,
            flip_probability_in_cluster=0.5,
            flip_probability_outside=0.3,
            seed=1,
        )
        cfg2 = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10200,
            flip_probability_in_cluster=0.5,
            flip_probability_outside=0.3,
            seed=99,
        )
        r1 = apply_clustered_distribution(
            fps, cfg1, slot_base=0x10000, write_granularity=8
        )
        r2 = apply_clustered_distribution(
            fps, cfg2, slot_base=0x10000, write_granularity=8
        )
        # Very unlikely to match with different seeds.
        self.assertNotEqual(r1, r2)

    def test_corruption_seed_per_point(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x10000,
            cluster_end=0x10100,
            flip_probability_in_cluster=1.0,
            flip_probability_outside=0.0,
            seed=42,
        )
        fps = [0, 1, 2]
        result = apply_clustered_distribution(
            fps, cfg, slot_base=0x10000, write_granularity=8
        )
        seeds = [s for _, s in result]
        # Each point should get a unique seed.
        self.assertEqual(len(set(seeds)), 3)

    def test_write_addresses_override(self) -> None:
        cfg = FaultDistributionConfig(
            mode="clustered",
            cluster_start=0x20000,
            cluster_end=0x20100,
            flip_probability_in_cluster=1.0,
            flip_probability_outside=0.0,
            seed=42,
        )
        # Provide explicit addresses that place point 1 inside cluster.
        addrs = [0x10000, 0x20050, 0x10100]
        fps = [0, 1, 2]
        result = apply_clustered_distribution(
            fps, cfg, write_addresses=addrs, total_writes=3
        )
        # Only point 1 (addr 0x20050) is inside cluster.
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 1)


class TestFaultDistributionProfileParsing(unittest.TestCase):
    """Test fault_distribution YAML profile parsing."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_default_no_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_no_dist
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
            dist = profile.fault_sweep.fault_distribution
            self.assertEqual(dist.mode, "uniform")

    def test_clustered_with_cluster_sectors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_clustered
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
                  fault_types: [bit_corruption]
                  fault_distribution:
                    mode: clustered
                    cluster_sectors: [0x10082000, 0x100820FF]
                    flip_probability_in_cluster: 0.1
                    flip_probability_outside: 0.001
                """,
            )
            profile = load_profile(str(profile_path))
            dist = profile.fault_sweep.fault_distribution
            self.assertEqual(dist.mode, "clustered")
            self.assertEqual(dist.cluster_start, 0x10082000)
            self.assertEqual(dist.cluster_end, 0x100820FF)
            self.assertAlmostEqual(dist.flip_probability_in_cluster, 0.1)
            self.assertAlmostEqual(dist.flip_probability_outside, 0.001)

    def test_invalid_cluster_range_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_bad_cluster
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
                  fault_distribution:
                    mode: clustered
                    cluster_sectors: [0x10100, 0x10000]
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(str(profile_path))

    def test_invalid_mode_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_bad_mode
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
                  fault_distribution:
                    mode: gaussian
                """,
            )
            with self.assertRaises(ProfileError):
                load_profile(str(profile_path))


# ---------------------------------------------------------------------------
# Feature 2: Multi-fault injection wiring
# ---------------------------------------------------------------------------


class TestMultiFaultEncodingInSweep(unittest.TestCase):
    """Test that multi-fault sequences are correctly encoded for the sweep."""

    def test_encode_pair_format(self) -> None:
        enc = encode_multi_fault_sequence([10, 200])
        self.assertEqual(enc, "mf:10:200")
        self.assertTrue(enc.startswith("mf:"))

    def test_encode_triple_format(self) -> None:
        enc = encode_multi_fault_sequence([5, 50, 500])
        self.assertEqual(enc, "mf:5:50:500")

    def test_plan_with_boundary_pairs_fallback(self) -> None:
        """When pairwise_interesting finds no interesting points,
        boundary_pairs fallback generates sequences from all fault points."""
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="boundary_pairs",
            fallback_points=list(range(0, 100, 10)),
        )
        self.assertTrue(len(plan.sequences) > 0)
        self.assertTrue(plan.diagnostics["fallback_used"])

    def test_plan_with_random_sample_fallback(self) -> None:
        """random_sample fallback generates seeded random pairs."""
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="random_sample",
            fallback_points=list(range(50)),
            seed=42,
        )
        self.assertTrue(len(plan.sequences) > 0)
        self.assertTrue(plan.diagnostics["fallback_used"])


# ---------------------------------------------------------------------------
# Feature 3: reset_at_time Phase 2 support
# ---------------------------------------------------------------------------


class TestResetAtTimePhase2Profile(unittest.TestCase):
    """Test that reset_at_time can be configured as a Phase 2 fault type."""

    def _write_profile(self, tempdir: Path, body: str) -> Path:
        path = tempdir / "profile.yaml"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_phase2_with_reset_at_time(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_p2_timed
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
                  fault_types: [reset_at_time]
                  phase2_fault:
                    enabled: true
                    fault_types: [reset_at_time]
                    max_points: 20
                """,
            )
            profile = load_profile(str(profile_path))
            self.assertTrue(profile.fault_sweep.phase2_fault.enabled)
            self.assertIn("reset_at_time", profile.fault_sweep.phase2_fault.fault_types)
            self.assertEqual(profile.fault_sweep.phase2_fault.max_points, 20)

    def test_phase2_mixed_types_including_timed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profile_path = self._write_profile(
                Path(td),
                """
                schema_version: 1
                name: test_p2_mixed
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
                  fault_types: [power_loss, reset_at_time]
                  phase2_fault:
                    enabled: true
                    fault_types: [power_loss, reset_at_time]
                    max_points: 10
                """,
            )
            profile = load_profile(str(profile_path))
            p2_types = profile.fault_sweep.phase2_fault.fault_types
            self.assertIn("power_loss", p2_types)
            self.assertIn("reset_at_time", p2_types)


class TestFaultTypeLabelWithTimedReset(unittest.TestCase):
    """Test _fault_type_label handles timed reset Phase 2 encodings."""

    def test_phase2_timed_label(self) -> None:
        from audit_bootloader import _fault_type_label

        self.assertEqual(_fault_type_label("p2:10:5:t:t"), "phase2_reset_at_time")

    def test_phase2_write_label(self) -> None:
        from audit_bootloader import _fault_type_label

        self.assertEqual(_fault_type_label("p2:10:5:w:w"), "phase2_power_loss")

    def test_clustered_bit_corruption_label(self) -> None:
        from audit_bootloader import _fault_type_label

        self.assertEqual(_fault_type_label("b:12345"), "bit_corruption_clustered")

    def test_plain_bit_corruption_label(self) -> None:
        from audit_bootloader import _fault_type_label

        self.assertEqual(_fault_type_label("b"), "bit_corruption")


# ---------------------------------------------------------------------------
# Feature 4: Multi-fault fallback for redundant systems
# ---------------------------------------------------------------------------


class TestMultiFaultFallbackRedundantSystems(unittest.TestCase):
    """Test the fallback path for redundant systems that mask single faults."""

    def test_boundary_pairs_fallback_generates_sequences(self) -> None:
        """When pairwise_interesting finds 0 interesting points (as expected
        for a well-designed dual-redundancy system), boundary_pairs fallback
        should still generate compound fault sequences."""
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="boundary_pairs",
            fallback_points=[0, 50, 100, 150, 200, 250],
        )
        self.assertEqual(plan.strategy, "pairwise_interesting")
        self.assertTrue(len(plan.sequences) > 0)
        diag = plan.diagnostics
        self.assertTrue(diag["fallback_used"])
        self.assertEqual(diag["fallback_strategy"], "boundary_pairs")
        self.assertEqual(diag["primary_reason"], "no_interesting_points")

    def test_boundary_pairs_sliding_window(self) -> None:
        """Boundary pairs should include adjacent pairs via sliding window."""
        plan = generate_boundary_pairs(
            candidate_points=[10, 20, 30, 40, 50],
            max_faults_per_run=2,
            max_pairs=100,
        )
        self.assertIn([10, 20], plan.sequences)
        self.assertIn([20, 30], plan.sequences)
        self.assertIn([30, 40], plan.sequences)
        self.assertIn([40, 50], plan.sequences)
        # Wide spanning pair: first + last
        self.assertIn([10, 50], plan.sequences)

    def test_boundary_pairs_caps_at_max(self) -> None:
        pts = list(range(0, 1000, 10))
        plan = generate_boundary_pairs(
            candidate_points=pts,
            max_faults_per_run=2,
            max_pairs=5,
        )
        self.assertEqual(len(plan.sequences), 5)

    def test_random_sample_fallback_generates_sequences(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="random_sample",
            fallback_points=list(range(100)),
            seed=42,
        )
        self.assertTrue(len(plan.sequences) > 0)
        diag = plan.diagnostics
        self.assertTrue(diag["fallback_used"])

    def test_fallback_not_used_when_interesting_points_exist(self) -> None:
        """If interesting points produce sequences, fallback is NOT used."""
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[10, 20, 30],
            fallback_strategy="boundary_pairs",
            fallback_points=[0, 50, 100],
        )
        # Primary plan succeeded: C(3,2)=3 sequences
        self.assertEqual(len(plan.sequences), 3)
        self.assertNotIn("fallback_used", plan.diagnostics)

    def test_fallback_none_skips_even_for_redundant(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="none",
            fallback_points=[0, 50, 100],
        )
        self.assertEqual(plan.sequences, [])

    def test_maybe_apply_fallback_with_empty_primary(self) -> None:
        """Direct test of maybe_apply_fallback."""
        primary = MultiFaultPlan(
            sequences=[],
            strategy="pairwise_interesting",
            interesting_point_count=0,
            max_faults_per_run=2,
            seed=None,
            diagnostics={"reason": "no_interesting_points", "exhaustive": True, "theoretical_combinations": 0},
        )
        result = maybe_apply_fallback(
            primary_plan=primary,
            fallback_strategy="boundary_pairs",
            fallback_points=[5, 15, 25, 35],
            max_faults_per_run=2,
            max_pairs=100,
            seed=None,
        )
        self.assertTrue(len(result.sequences) > 0)
        self.assertTrue(result.diagnostics["fallback_used"])

    def test_maybe_apply_fallback_preserves_nonempty_primary(self) -> None:
        primary = MultiFaultPlan(
            sequences=[[10, 20]],
            strategy="pairwise_interesting",
            interesting_point_count=2,
            max_faults_per_run=2,
            seed=None,
            diagnostics={"exhaustive": True, "theoretical_combinations": 1},
        )
        result = maybe_apply_fallback(
            primary_plan=primary,
            fallback_strategy="boundary_pairs",
            fallback_points=[5, 15, 25, 35],
            max_faults_per_run=2,
            max_pairs=100,
            seed=None,
        )
        # Primary had sequences; fallback should not be used.
        self.assertEqual(result.sequences, [[10, 20]])

    def test_fallback_profile_parsing(self) -> None:
        """Test that fallback_strategy parses from YAML."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.yaml"
            path.write_text(
                textwrap.dedent("""
                schema_version: 1
                name: test_fallback
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
                    fallback_strategy: random_sample
                    seed: 42
                    max_pairs: 200
                """),
                encoding="utf-8",
            )
            profile = load_profile(str(path))
            mf = profile.fault_sweep.multi_fault
            self.assertTrue(mf.enabled)
            self.assertEqual(mf.fallback_strategy, "random_sample")
            self.assertEqual(mf.seed, 42)

    def test_multi_fault_plan_summary_includes_diagnostics(self) -> None:
        plan = generate_multi_fault_sequences(
            strategy="pairwise_interesting",
            interesting_points=[],
            fallback_strategy="boundary_pairs",
            fallback_points=[0, 10, 20, 30, 40],
        )
        summary = multi_fault_plan_summary(plan)
        self.assertIn("diagnostics", summary)
        self.assertTrue(summary["diagnostics"]["fallback_used"])


if __name__ == "__main__":
    unittest.main()
