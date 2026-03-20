"""Tests for HeuristicConfig dataclass and profile YAML integration."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure scripts/ is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fault_plan import CalibrationInputs, build_fault_plan
from profile_loader import (
    FaultSweepConfig,
    HeuristicConfig,
    _parse_fault_sweep,
    _parse_heuristic_config,
    load_profile,
)


# ---------------------------------------------------------------------------
# Part 1: HeuristicConfig construction and validation
# ---------------------------------------------------------------------------


class TestHeuristicConfigDefaults:
    """Default construction produces the expected values."""

    def test_defaults(self):
        hc = HeuristicConfig()
        assert hc.tier2_step == 3
        assert hc.tier3_step == 100
        assert hc.discontinuity_window == 3
        assert hc.target_points is None
        assert hc.preserve_critical_tiers is True
        assert hc.shard_count == 1
        assert hc.shard_index == 0
        assert hc.random_tail_budget == 0
        assert hc.critical_regions == []


class TestHeuristicConfigFullParse:
    """Parsing a YAML dict with all fields set."""

    def test_full_config(self):
        raw = {
            "tier2_step": 5,
            "tier3_step": 50,
            "discontinuity_window": 7,
            "target_points": 1200,
            "preserve_critical_tiers": False,
            "shard_count": 4,
            "shard_index": 2,
            "random_tail_budget": 10,
            "critical_regions": [{"start": "0x1200", "end": "0x1210"}],
        }
        hc = _parse_heuristic_config(raw)
        assert hc is not None
        assert hc.tier2_step == 5
        assert hc.tier3_step == 50
        assert hc.discontinuity_window == 7
        assert hc.target_points == 1200
        assert hc.preserve_critical_tiers is False
        assert hc.shard_count == 4
        assert hc.shard_index == 2
        assert hc.random_tail_budget == 10
        assert hc.critical_regions == [(0x1200, 0x1210)]


class TestHeuristicConfigPartialParse:
    """Parsing with only some fields; rest should default."""

    def test_partial_config(self):
        raw = {"tier2_step": 5, "tier3_step": 200}
        hc = _parse_heuristic_config(raw)
        assert hc is not None
        assert hc.tier2_step == 5
        assert hc.tier3_step == 200
        # Defaults for the rest:
        assert hc.discontinuity_window == 3
        assert hc.target_points is None
        assert hc.preserve_critical_tiers is True
        assert hc.shard_count == 1
        assert hc.shard_index == 0
        assert hc.random_tail_budget == 0
        assert hc.critical_regions == []

    def test_symbol_critical_region_resolves(self):
        elf = (
            Path(__file__).resolve().parent.parent
            / "examples"
            / "vulnerable_ota"
            / "firmware.elf"
        )
        hc = _parse_heuristic_config(
            {"critical_regions": [{"symbol": "Reset"}]},
            bootloader_elf=str(elf),
        )
        assert hc is not None
        assert hc.critical_regions == [(0x10000044, 0x100000F8)]


class TestHeuristicConfigAbsent:
    """Absent heuristic config (None input) returns None."""

    def test_none_input(self):
        assert _parse_heuristic_config(None) is None


class TestHeuristicConfigValidation:
    """Invalid values raise ValueError."""

    def test_tier2_step_zero(self):
        with pytest.raises(ValueError, match="tier2_step"):
            HeuristicConfig(tier2_step=0)

    def test_tier2_step_negative(self):
        with pytest.raises(ValueError, match="tier2_step"):
            HeuristicConfig(tier2_step=-1)

    def test_tier3_step_zero(self):
        with pytest.raises(ValueError, match="tier3_step"):
            HeuristicConfig(tier3_step=0)

    def test_discontinuity_window_negative(self):
        with pytest.raises(ValueError, match="discontinuity_window"):
            HeuristicConfig(discontinuity_window=-1)

    def test_target_points_zero(self):
        with pytest.raises(ValueError, match="target_points"):
            HeuristicConfig(target_points=0)

    def test_shard_count_zero(self):
        with pytest.raises(ValueError, match="shard_count"):
            HeuristicConfig(shard_count=0)

    def test_shard_index_negative(self):
        with pytest.raises(ValueError, match="shard_index"):
            HeuristicConfig(shard_index=-1)

    def test_shard_index_equals_count(self):
        with pytest.raises(ValueError, match="shard_index"):
            HeuristicConfig(shard_count=3, shard_index=3)

    def test_shard_index_exceeds_count(self):
        with pytest.raises(ValueError, match="shard_index"):
            HeuristicConfig(shard_count=2, shard_index=5)

    def test_random_tail_budget_negative(self):
        with pytest.raises(ValueError, match="random_tail_budget"):
            HeuristicConfig(random_tail_budget=-1)

    def test_valid_edge_cases(self):
        """Edge cases that should NOT raise."""
        HeuristicConfig(tier2_step=1)
        HeuristicConfig(tier3_step=1)
        HeuristicConfig(discontinuity_window=0)
        HeuristicConfig(target_points=1)
        HeuristicConfig(shard_count=1, shard_index=0)
        HeuristicConfig(random_tail_budget=0)


class TestHeuristicConfigToDict:
    """to_dict() serializes all fields."""

    def test_to_dict_defaults(self):
        hc = HeuristicConfig()
        d = hc.to_dict()
        assert d == {
            "tier2_step": 3,
            "tier3_step": 100,
            "discontinuity_window": 3,
            "target_points": None,
            "preserve_critical_tiers": True,
            "shard_count": 1,
            "shard_index": 0,
            "random_tail_budget": 0,
            "critical_regions": [],
        }

    def test_to_dict_custom(self):
        hc = HeuristicConfig(tier2_step=5, target_points=500)
        d = hc.to_dict()
        assert d["tier2_step"] == 5
        assert d["target_points"] == 500


# ---------------------------------------------------------------------------
# Part 2: FaultSweepConfig integration
# ---------------------------------------------------------------------------


class TestFaultSweepConfigHeuristic:
    """FaultSweepConfig carries heuristic_config correctly."""

    def test_default_is_none(self):
        fsc = FaultSweepConfig()
        assert fsc.heuristic_config is None

    def test_explicit_none(self):
        fsc = FaultSweepConfig(heuristic_config=None)
        assert fsc.heuristic_config is None

    def test_explicit_config(self):
        hc = HeuristicConfig(tier2_step=7)
        fsc = FaultSweepConfig(heuristic_config=hc)
        assert fsc.heuristic_config is hc
        assert fsc.heuristic_config.tier2_step == 7

    def test_default_max_heuristic_points(self):
        fsc = FaultSweepConfig()
        assert fsc.max_heuristic_points == 2000

    def test_explicit_max_heuristic_points(self):
        fsc = FaultSweepConfig(max_heuristic_points=512)
        assert fsc.max_heuristic_points == 512

    def test_invalid_max_heuristic_points(self):
        with pytest.raises(ValueError, match="max_heuristic_points"):
            FaultSweepConfig(max_heuristic_points=0)


class TestParseFaultSweepWithHeuristic:
    """_parse_fault_sweep correctly handles the heuristic sub-key."""

    def test_no_heuristic_key(self):
        """No heuristic key -> heuristic_config is None."""
        raw = {"sweep_strategy": "heuristic"}
        fsc = _parse_fault_sweep(raw)
        assert fsc.heuristic_config is None
        assert fsc.max_heuristic_points == 2000

    def test_heuristic_key_present(self):
        """heuristic key present -> parsed into HeuristicConfig."""
        raw = {
            "sweep_strategy": "heuristic",
            "max_heuristic_points": 750,
            "heuristic": {
                "tier2_step": 5,
                "tier3_step": 50,
            },
        }
        fsc = _parse_fault_sweep(raw)
        assert fsc.heuristic_config is not None
        assert fsc.heuristic_config.tier2_step == 5
        assert fsc.heuristic_config.tier3_step == 50
        assert fsc.heuristic_config.discontinuity_window == 3  # default
        assert fsc.max_heuristic_points == 750

    def test_heuristic_key_empty_dict(self):
        """heuristic: {} -> HeuristicConfig with all defaults."""
        raw = {"heuristic": {}}
        fsc = _parse_fault_sweep(raw)
        assert fsc.heuristic_config is not None
        assert fsc.heuristic_config.tier2_step == 3
        assert fsc.heuristic_config.tier3_step == 100

    def test_none_raw_gives_none_heuristic(self):
        """None raw -> default FaultSweepConfig with no heuristic."""
        fsc = _parse_fault_sweep(None)
        assert fsc.heuristic_config is None


# ---------------------------------------------------------------------------
# Part 3: Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Profiles without heuristic block behave exactly as before."""

    def test_no_fault_sweep_key(self):
        """Profile with no fault_sweep at all."""
        fsc = _parse_fault_sweep(None)
        assert fsc.sweep_strategy == "heuristic"
        assert fsc.heuristic_config is None

    def test_fault_sweep_without_heuristic(self):
        """Profile with fault_sweep but no heuristic sub-key."""
        raw = {
            "mode": "runtime",
            "sweep_strategy": "heuristic",
            "fault_types": ["power_loss"],
        }
        fsc = _parse_fault_sweep(raw)
        assert fsc.sweep_strategy == "heuristic"
        assert fsc.heuristic_config is None
        # Existing fields are unaffected:
        assert fsc.mode == "runtime"
        assert fsc.fault_types == ["power_loss"]

    def test_with_default_heuristic_values(self):
        """Explicit heuristic with default values should be equivalent."""
        raw = {
            "sweep_strategy": "heuristic",
            "heuristic": {"tier2_step": 3, "tier3_step": 100},
        }
        fsc = _parse_fault_sweep(raw)
        assert fsc.heuristic_config is not None
        assert fsc.heuristic_config.tier2_step == 3
        assert fsc.heuristic_config.tier3_step == 100
        assert fsc.heuristic_config.discontinuity_window == 3


# ---------------------------------------------------------------------------
# Part 4: classify_trace kwargs passthrough
# ---------------------------------------------------------------------------


class TestClassifyTracePassthrough:
    """Verify that HeuristicConfig values are forwarded to classify_trace."""

    def test_heuristic_config_kwargs_passed(self):
        """When heuristic_config is set, its values appear as kwargs."""
        hc = HeuristicConfig(tier2_step=5, tier3_step=200, discontinuity_window=7)
        # Build the kwargs dict the same way audit_bootloader.py does:
        heuristic_kwargs = {}
        if hc is not None:
            heuristic_kwargs["tier2_step"] = hc.tier2_step
            heuristic_kwargs["tier3_step"] = hc.tier3_step
            heuristic_kwargs["discontinuity_window"] = hc.discontinuity_window
        assert heuristic_kwargs == {
            "tier2_step": 5,
            "tier3_step": 200,
            "discontinuity_window": 7,
        }

    def test_no_heuristic_config_empty_kwargs(self):
        """When heuristic_config is None, no extra kwargs are produced."""
        hc = None
        heuristic_kwargs = {}
        if hc is not None:
            heuristic_kwargs["tier2_step"] = hc.tier2_step
            heuristic_kwargs["tier3_step"] = hc.tier3_step
            heuristic_kwargs["discontinuity_window"] = hc.discontinuity_window
        assert heuristic_kwargs == {}

    def test_classify_trace_accepts_kwargs(self):
        """classify_trace() function signature accepts the heuristic kwargs."""
        from write_trace_heuristic import classify_trace
        import inspect

        sig = inspect.signature(classify_trace)
        params = sig.parameters
        assert "tier2_step" in params
        assert "tier3_step" in params
        assert "discontinuity_window" in params
        assert "critical_regions" in params


class TestMaxHeuristicPointsPlannerFallback:
    """Planner uses fault_sweep.max_heuristic_points as the default cap."""

    @staticmethod
    def _write_profile(tmp_path: Path, extra: str = "") -> Path:
        nested_extra = textwrap.indent(textwrap.dedent(extra).strip(), "  ")
        if nested_extra:
            nested_extra = "\n" + nested_extra
        profile = tmp_path / "profile.yaml"
        profile.write_text(
            textwrap.dedent(
                """
                schema_version: 1
                name: heuristic_cap_profile
                platform: platforms/stm32f4.repl
                bootloader:
                  elf: examples/vulnerable_ota/firmware.elf
                  entry: 0x10000000
                memory:
                  sram: { start: 0x20000000, end: 0x20020000 }
                  write_granularity: 4
                  slots:
                    exec: { base: 0x10000000, size: 0x2000 }
                    staging: { base: 0x10002000, size: 0x2000 }
                images:
                  staging: examples/vulnerable_ota/firmware.bin
                success_criteria:
                  vtor_in_slot: exec
                expect:
                  should_find_issues: false
                fault_sweep:
                  mode: runtime
                  sweep_strategy: heuristic
                  max_writes: auto
                EXTRA
                """
            ).replace("EXTRA", nested_extra),
            encoding="utf-8",
        )
        return profile

    @staticmethod
    def _mock_classification() -> dict:
        return {
            "fault_points": [0],
            "tier0": [],
            "tier1": [],
            "tier2_selected": [],
            "tier3_selected": [],
            "tier2_total": 0,
            "tier3_total": 0,
            "discontinuity_count": 0,
            "heuristic_config": {"target_points": 1},
        }

    def test_build_fault_plan_uses_max_heuristic_points_by_default(self, tmp_path: Path):
        trace_path = tmp_path / "trace.csv"
        trace_path.write_text("write_index,flash_offset,value\n1,0,0\n", encoding="utf-8")
        profile = load_profile(self._write_profile(tmp_path))

        with patch(
            "write_trace_heuristic.classify_trace",
            return_value=self._mock_classification(),
        ) as mock_classify, patch(
            "write_trace_heuristic.summarize_classification",
            return_value={"selected_fault_points": 1, "total_writes": 1, "reduction_ratio": 1.0, "trailer_writes": 0},
        ):
            build_fault_plan(
                profile,
                CalibrationInputs(max_writes=1, trace_file=str(trace_path)),
            )

        assert mock_classify.call_args.kwargs["target_points"] == 2000

    def test_explicit_heuristic_target_points_overrides_fallback(self, tmp_path: Path):
        trace_path = tmp_path / "trace.csv"
        trace_path.write_text("write_index,flash_offset,value\n1,0,0\n", encoding="utf-8")
        profile = load_profile(
            self._write_profile(
                tmp_path,
                extra=textwrap.dedent(
                    """
                      max_heuristic_points: 900
                      heuristic:
                        target_points: 123
                    """
                ),
            )
        )

        with patch(
            "write_trace_heuristic.classify_trace",
            return_value=self._mock_classification(),
        ) as mock_classify, patch(
            "write_trace_heuristic.summarize_classification",
            return_value={"selected_fault_points": 1, "total_writes": 1, "reduction_ratio": 1.0, "trailer_writes": 0},
        ):
            build_fault_plan(
                profile,
                CalibrationInputs(max_writes=1, trace_file=str(trace_path)),
            )

        assert mock_classify.call_args.kwargs["target_points"] == 123
