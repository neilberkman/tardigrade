#!/usr/bin/env python3
"""Guardrail tests: every declared fault type must be wired end-to-end.

These tests exist to prevent a common category of drift: a new fault type
gets added to the parser/docs layer but never wired into the planner or
runtime dispatch, so it silently does nothing when a user requests it.

The tests check three layers:

  1. Registration consistency -- every fault type that claims to be
     IMPLEMENTED must appear in the wire-code mapping and vice versa.

  2. Planner reachability -- every wire-coded fault type must have a
     code path in the planner that can emit at least one runtime fault
     point for it (or be explicitly declared as taking a separate path).

  3. Runtime dispatch coverage -- every wire code must be handled by the
     runtime dispatch table, and every EXECUTE_ONLY type must route to
     full-execute mode.

The tests are driven by the actual registry contents, not a hardcoded
matrix -- adding a new type to the registries automatically extends
coverage.  Types that intentionally take a different path (e.g.
nvs_corruption, bootloader_region_write) are exempted with rationale.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from fault_types import (  # noqa: E402
    EXECUTE_ONLY_FAULT_TYPES as FT_EXECUTE_ONLY,
    FAULT_TYPE_NAME_TO_CODE as FT_NAME_TO_CODE,
    _fault_type_label as ft_label,
)
from profile_loader import (  # noqa: E402
    CLASSIFICATION_ONLY_FAULT_TYPES,
    IMPLEMENTED_FAULT_TYPES,
    KNOWN_FAULT_TYPES,
    I2C_FAULT_TYPE_CODES,
    OTP_FAULT_TYPE_CODES,
)

# audit_bootloader.py now imports directly from fault_types.py —
# no separate copies to sync.

# ---------------------------------------------------------------------------
# Read the runtime .resc file as text for dispatch-table verification.
# We parse the Python-in-IronPython source with regex rather than executing
# it -- these are structural checks, not behavioral ones.
# ---------------------------------------------------------------------------
RESC_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"
_resc_text = RESC_PATH.read_text(encoding="utf-8")


def _extract_resc_dict(varname: str) -> dict:
    """Extract a dict literal assigned to *varname* in the .resc source."""
    # Match: varname = { ... }  (possibly multi-line)
    pattern = re.compile(
        r"^" + re.escape(varname) + r"\s*=\s*\{([^}]+)\}",
        re.MULTILINE,
    )
    m = pattern.search(_resc_text)
    if not m:
        return {}
    body = m.group(1)
    result = {}
    # Find all 'key': value pairs (handles both single-line and multi-line dicts).
    for kv in re.finditer(r"'([^']+)'\s*:\s*([^,}]+)", body):
        key = kv.group(1)
        val = kv.group(2).strip().strip("'\"")
        # Skip comments embedded after values.
        val = val.split("#")[0].strip().strip("'\"")
        result[key] = val
    return result


def _extract_resc_frozenset(varname: str) -> set:
    """Extract a frozenset(...) literal assigned to *varname* in the .resc."""
    pattern = re.compile(
        r"^" + re.escape(varname) + r"\s*=\s*frozenset\(\s*\(([^)]+)\)",
        re.MULTILINE,
    )
    m = pattern.search(_resc_text)
    if not m:
        return set()
    body = m.group(1)
    return {s.strip().strip("'\"") for s in body.split(",") if s.strip().strip("'\"").strip()}


# Parsed runtime tables.
RESC_FAULT_CODE_TO_NAME = _extract_resc_dict("_FAULT_CODE_TO_NAME")
RESC_WRITE_FAULT_MODE = _extract_resc_dict("_WRITE_FAULT_MODE")
RESC_I2C_WIRE_TO_TYPE = _extract_resc_dict("_I2C_WIRE_CODE_TO_FAULT_TYPE")
RESC_EXECUTE_ONLY = _extract_resc_frozenset("_EXECUTE_ONLY_FAULT_TYPES")
RESC_TRACE_REPLAY_SUPPORTED = _extract_resc_frozenset("_TRACE_REPLAY_SUPPORTED_FAULT_TYPES")

# ---------------------------------------------------------------------------
# Fault types that intentionally bypass the standard wire-code dispatch.
# Each entry documents WHY it's exempt.
# ---------------------------------------------------------------------------
SEPARATE_SUBSYSTEM_TYPES = {
    # bootloader_region_write is a classification/heuristic label, not an
    # injectable fault type.  It's in CLASSIFICATION_ONLY_FAULT_TYPES.
    "bootloader_region_write",
}


# ====================================================================
# 1. Registration consistency
# ====================================================================


class TestRegistrationConsistency(unittest.TestCase):
    """Verify the fault-type registries across modules agree."""

    def test_implemented_is_subset_of_known(self):
        """IMPLEMENTED_FAULT_TYPES must be a subset of KNOWN_FAULT_TYPES."""
        extra = IMPLEMENTED_FAULT_TYPES - KNOWN_FAULT_TYPES
        self.assertFalse(
            extra,
            "Types in IMPLEMENTED but not KNOWN: {}".format(sorted(extra)),
        )

    def test_known_equals_implemented(self):
        """If a type is KNOWN, it should be IMPLEMENTED or CLASSIFICATION_ONLY."""
        unimplemented = KNOWN_FAULT_TYPES - IMPLEMENTED_FAULT_TYPES - CLASSIFICATION_ONLY_FAULT_TYPES
        self.assertFalse(
            unimplemented,
            "Types in KNOWN but not IMPLEMENTED or CLASSIFICATION_ONLY: {}".format(sorted(unimplemented)),
        )

    def test_wire_coded_types_are_implemented(self):
        """Every type with a wire code must be in IMPLEMENTED_FAULT_TYPES."""
        wire_coded = set(FT_NAME_TO_CODE.keys())
        missing = wire_coded - IMPLEMENTED_FAULT_TYPES
        self.assertFalse(
            missing,
            "Types in FAULT_TYPE_NAME_TO_CODE but not IMPLEMENTED: {}".format(
                sorted(missing)
            ),
        )

    def test_implemented_types_have_wire_code_or_exemption(self):
        """Every IMPLEMENTED type needs a wire code or an explicit exemption."""
        wire_coded = set(FT_NAME_TO_CODE.keys())
        for ft in sorted(IMPLEMENTED_FAULT_TYPES):
            if ft in SEPARATE_SUBSYSTEM_TYPES:
                continue
            self.assertIn(
                ft,
                wire_coded,
                "IMPLEMENTED type '{}' has no wire code and no exemption in "
                "SEPARATE_SUBSYSTEM_TYPES".format(ft),
            )

    def test_wire_codes_are_unique(self):
        """No two fault types may share the same wire code."""
        seen = {}
        for name, code in sorted(FT_NAME_TO_CODE.items()):
            if code in seen:
                self.fail(
                    "Wire code '{}' used by both '{}' and '{}'".format(
                        code, seen[code], name
                    )
                )
            seen[code] = name

    def test_label_round_trip(self):
        """Every wire code must round-trip through _fault_type_label."""
        for name, code in FT_NAME_TO_CODE.items():
            label = ft_label(code)
            self.assertEqual(
                label,
                name,
                "Wire code '{}' -> label '{}', expected '{}'".format(
                    code, label, name
                ),
            )


# ====================================================================
# 2. Planner imports canonical constants (no duplicate definitions)
# ====================================================================


class TestPlannerImportsCanonical(unittest.TestCase):
    """Verify fault_plan.py imports wire codes from fault_types.py.

    After the planner extraction, fault_plan.py must use the canonical
    FAULT_TYPE_NAME_TO_CODE from fault_types.py rather than defining its
    own copy.  This prevents the constants from drifting apart.
    """

    def _read_source(self, name: str) -> str:
        p = ROOT / "scripts" / name
        self.assertTrue(p.exists(), "{} not found".format(p))
        return p.read_text(encoding="utf-8")

    def test_fault_plan_imports_wire_codes(self):
        """fault_plan.py must import FAULT_TYPE_NAME_TO_CODE from fault_types."""
        src = self._read_source("fault_plan.py")
        self.assertIn(
            "from fault_types import",
            src,
            "fault_plan.py does not import from fault_types module",
        )
        self.assertIn(
            "FAULT_TYPE_NAME_TO_CODE",
            src,
            "fault_plan.py does not reference FAULT_TYPE_NAME_TO_CODE",
        )

    def test_fault_plan_does_not_redefine_wire_codes(self):
        """fault_plan.py must not redefine FAULT_TYPE_NAME_TO_CODE locally."""
        src = self._read_source("fault_plan.py")
        self.assertNotIn(
            "FAULT_TYPE_NAME_TO_CODE = {",
            src,
            "fault_plan.py redefines FAULT_TYPE_NAME_TO_CODE instead of "
            "importing it from fault_types.py",
        )

    def test_audit_bootloader_imports_from_fault_plan(self):
        """audit_bootloader.py must import from fault_plan, not duplicate it."""
        src = self._read_source("audit_bootloader.py")
        self.assertIn(
            "from fault_plan import",
            src,
            "audit_bootloader.py does not import from fault_plan module",
        )
        self.assertNotIn(
            "FAULT_TYPE_NAME_TO_CODE = {",
            src,
            "audit_bootloader.py redefines FAULT_TYPE_NAME_TO_CODE instead of "
            "importing it from fault_types.py",
        )


# ====================================================================
# 3. Runtime dispatch coverage
# ====================================================================


class TestRuntimeDispatchCoverage(unittest.TestCase):
    """Verify the .resc runtime dispatch handles every declared wire code."""

    def test_resc_code_to_name_covers_all_wire_codes(self):
        """_FAULT_CODE_TO_NAME in the .resc must include every wire code."""
        expected_codes = set(FT_NAME_TO_CODE.values())
        resc_codes = set(RESC_FAULT_CODE_TO_NAME.keys())
        missing = expected_codes - resc_codes
        self.assertFalse(
            missing,
            "Wire codes in FAULT_TYPE_NAME_TO_CODE but missing from .resc "
            "_FAULT_CODE_TO_NAME: {}".format(sorted(missing)),
        )

    def test_resc_code_to_name_values_match(self):
        """_FAULT_CODE_TO_NAME values must map back to the correct type names."""
        for name, code in FT_NAME_TO_CODE.items():
            resc_name = RESC_FAULT_CODE_TO_NAME.get(code)
            if not resc_name:
                continue  # Covered by test_resc_code_to_name_covers_all_wire_codes
            self.assertEqual(
                resc_name,
                name,
                ".resc _FAULT_CODE_TO_NAME['{}'] = '{}', expected '{}'".format(
                    code, resc_name, name
                ),
            )

    def test_resc_family_override_codes_map_to_family_names(self):
        """Composite fault families must resolve to override keys, not subtypes."""
        self.assertEqual(RESC_FAULT_CODE_TO_NAME.get("m"), "metadata_fault")
        self.assertEqual(RESC_FAULT_CODE_TO_NAME.get("p2"), "phase2_fault")
        self.assertEqual(RESC_FAULT_CODE_TO_NAME.get("h"), "hook_fault")

    def test_write_mode_types_have_mode_codes(self):
        """Write-mode fault types (b, s, r, g, x, d, l) must appear in _WRITE_FAULT_MODE."""
        # 'w' (power_loss) uses mode 0 (the default) -- it's in the map.
        write_mode_types = {"w", "b", "s", "r", "g", "x", "d", "l"}
        resc_modes = set(RESC_WRITE_FAULT_MODE.keys())
        missing = write_mode_types - resc_modes
        self.assertFalse(
            missing,
            "Write-mode types missing from .resc _WRITE_FAULT_MODE: {}".format(
                sorted(missing)
            ),
        )

    def test_trace_replay_supported_codes_are_declared(self):
        expected = {"w"}
        self.assertEqual(RESC_TRACE_REPLAY_SUPPORTED, expected)
        self.assertIn(
            "default_run_fn == run_trace_replay_fault and base_ft in _TRACE_REPLAY_SUPPORTED_FAULT_TYPES",
            _resc_text,
            "trace-replay dispatch override missing from .resc",
        )
        self.assertIn("engine.ReplayWriteFault(", _resc_text)
        self.assertIn("engine.ReplayWriteFaultWithErases(", _resc_text)

    def test_i2c_wire_codes_have_runtime_mapping(self):
        """I2C wire codes must appear in .resc _I2C_WIRE_CODE_TO_FAULT_TYPE."""
        i2c_codes = {
            FT_NAME_TO_CODE[name] for name in I2C_FAULT_TYPE_CODES.keys()
        }
        resc_i2c = set(RESC_I2C_WIRE_TO_TYPE.keys())
        missing = i2c_codes - resc_i2c
        self.assertFalse(
            missing,
            "I2C wire codes missing from .resc: {}".format(sorted(missing)),
        )

    def test_execute_only_types_in_resc(self):
        """EXECUTE_ONLY types from Python must match the .resc frozenset.

        The .resc _EXECUTE_ONLY_FAULT_TYPES only lists codes that route
        through ``run_execute_fault`` via the simple-code path.  Types
        that take different dispatch routes are excluded:

        - OTP codes (op, os, od, oo, on): dispatched through OTP backend kind
        - instruction_skip (i): always dispatched via 'i:<addr>' prefix
        """
        # Codes that take alternative dispatch paths in the .resc and are
        # correctly absent from _EXECUTE_ONLY_FAULT_TYPES there.
        ALTERNATIVE_DISPATCH_CODES = {
            # OTP faults: dispatched through the OTP backend kind, not the
            # simple-code path.
            "op", "os", "od", "oo", "on",
            # timed_bit_corruption: dispatched via 'tb:addr:addr' prefix.
            "tb",
            # instruction_skip: always dispatched via 'i:<addr>' prefix,
            # never as bare 'i'.
            "i",
            # nvs_corruption: dispatched via 'nv:<variant_index>' prefix,
            # not as bare 'nv'.
            "nv",
        }

        # Convert EXECUTE_ONLY names to wire codes for comparison.
        py_codes = {
            FT_NAME_TO_CODE[name]
            for name in FT_EXECUTE_ONLY
            if name in FT_NAME_TO_CODE
        }
        # Expected in .resc = py_codes minus alternative dispatch codes.
        expected_in_resc = py_codes - ALTERNATIVE_DISPATCH_CODES

        missing_from_resc = expected_in_resc - RESC_EXECUTE_ONLY
        extra_in_resc = RESC_EXECUTE_ONLY - py_codes
        self.assertFalse(
            missing_from_resc,
            "EXECUTE_ONLY wire codes missing from .resc: {}".format(
                sorted(missing_from_resc)
            ),
        )
        self.assertFalse(
            extra_in_resc,
            "Extra EXECUTE_ONLY wire codes in .resc not in Python: {}".format(
                sorted(extra_in_resc)
            ),
        )

    def test_alternative_dispatch_codes_are_handled(self):
        """Codes excluded from .resc EXECUTE_ONLY must have alternative handlers."""
        # OTP codes must be in _FAULT_CODE_TO_NAME (handled by OTP backend).
        for code in ("op", "os", "od", "oo"):
            self.assertIn(
                code,
                RESC_FAULT_CODE_TO_NAME,
                "OTP code '{}' not in .resc _FAULT_CODE_TO_NAME".format(code),
            )
        # instruction_skip must have 'i:' prefix dispatch.
        self.assertIn(
            "ft.startswith('i:')",
            _resc_text,
            "instruction_skip prefix dispatch missing from .resc",
        )


# ====================================================================
# 4. Planner point-generation reachability
# ====================================================================


class TestPlannerReachability(unittest.TestCase):
    """Verify that each wire-coded fault type has a planner code path.

    We inspect fault_plan.py (the extracted planner module) for the
    ``include_*`` boolean pattern and the point-generation block that
    emits combined entries for each type.  This catches the "added to
    the registry but the planner never generates points" class of bug.
    """

    # Fault types whose planner path is through a sub-config object
    # (metadata_fault, hook_fault, phase2_fault) rather than the main
    # include_* / combined-append pattern.  These are exercised when
    # their sub-config is enabled, not via a top-level include boolean.
    SUB_CONFIG_TYPES = {
        # Phase 2, hook, metadata faults accept fault_types in their
        # own config blocks; the planner generates points when enabled.
    }

    # Types handled by special dispatch prefixes in _dispatch_fault_point
    # rather than the simple-code path in the planner.  They still need
    # wire codes but point generation uses a different mechanism.
    PREFIX_DISPATCH_TYPES = {
        # instruction_skip: points are 'i:<addr>' with address ranges
        # from instruction_skip_config.target_addresses.
        "instruction_skip",
        # timed_bit_corruption: points are 'tb:<trigger_addr>:<corrupt_addr>'
        # from timed_bit_corruption_config.pairs.
        "timed_bit_corruption",
    }

    # OTP faults use the write-fault mechanism but go through the OTP
    # backend kind.  They share wire codes and the planner generates
    # points using the standard write-fault path (same as power_loss
    # etc.) -- the OTP backend handles the hardware-level differences.
    # They do NOT have separate include_otp_* booleans.  Instead, they
    # rely on the backend being an OTP device and the fault_type code
    # routing through run_execute_fault's write-mode dispatch.
    OTP_TYPES = set(OTP_FAULT_TYPE_CODES.keys())

    def _read_planner_source(self) -> str:
        p = ROOT / "scripts" / "fault_plan.py"
        self.assertTrue(p.exists(), "fault_plan.py not found at {}".format(p))
        return p.read_text(encoding="utf-8")

    def test_standard_types_have_planner_generation(self):
        """Each standard fault type must have point-generation code."""
        src = self._read_planner_source()

        # Standard types use the pattern:
        #   include_<something> = "<fault_name>" in fault_types
        # and then generate combined entries with the wire code.
        #
        # We check that for each wire-coded type not in an exemption set,
        # either (a) its name appears in an `in fault_types` check, or
        # (b) its wire code appears in a combined.append / combined +=
        # expression.

        exempted = (
            SEPARATE_SUBSYSTEM_TYPES
            | self.PREFIX_DISPATCH_TYPES
            | self.OTP_TYPES
        )

        for name, code in sorted(FT_NAME_TO_CODE.items()):
            if name in exempted:
                continue

            # Check 1: name appears in `"<name>" in fault_types`
            name_referenced = '"{}" in fault_types'.format(name) in src
            # Or referenced via startswith for i2c family
            startswith_referenced = (
                'ft.startswith("{}")'.format(name[:4]) in src
                if name.startswith("i2c_")
                else False
            )
            # Check 2: wire code appears in combined-building code
            code_in_combined = (
                "'{}'".format(code) in src or '"{}"'.format(code) in src
            )

            has_planner_path = name_referenced or startswith_referenced or code_in_combined
            self.assertTrue(
                has_planner_path,
                "Fault type '{}' (code='{}') has no visible planner path in "
                "fault_plan.py. Either add point generation or add it "
                "to an exemption set with rationale.".format(name, code),
            )

    def test_otp_types_have_wire_codes_and_runtime_handler(self):
        """OTP types must have wire codes and route through run_execute_fault."""
        for name in sorted(self.OTP_TYPES):
            self.assertIn(
                name,
                FT_NAME_TO_CODE,
                "OTP type '{}' missing from FAULT_TYPE_NAME_TO_CODE".format(name),
            )
            code = FT_NAME_TO_CODE[name]
            self.assertIn(
                code,
                RESC_FAULT_CODE_TO_NAME,
                "OTP wire code '{}' missing from .resc _FAULT_CODE_TO_NAME".format(
                    code
                ),
            )

    def test_instruction_skip_has_dispatch_prefix(self):
        """instruction_skip must be handled by 'i:' prefix dispatch."""
        self.assertIn("i:", _resc_text)
        self.assertIn(
            "ft.startswith('i:')",
            _resc_text,
            "instruction_skip prefix dispatch 'i:' not found in .resc",
        )

    def test_instruction_skip_dispatch_parses_split_parts(self):
        """instruction_skip dispatch must split the encoded fault string first."""
        self.assertIn(
            "parts = ft.split(':')",
            _resc_text,
            "instruction_skip dispatch does not split the encoded fault type",
        )
        self.assertIn(
            "patch_model = parts[2] if len(parts) > 2 else 'nop'",
            _resc_text,
            "instruction_skip patch-model parsing is missing from .resc",
        )

    def test_all_dispatch_prefixes_present(self):
        """All compound-dispatch prefixes must exist in _dispatch_fault_point."""
        expected_prefixes = ["m:", "h:", "p2:", "mf:", "i:", "c:", "b:", "nv:"]
        for prefix in expected_prefixes:
            self.assertIn(
                "ft.startswith('{}')".format(prefix),
                _resc_text,
                "Dispatch prefix '{}' not found in .resc "
                "_dispatch_fault_point".format(prefix),
            )


# ====================================================================
# 5. Exemption hygiene
# ====================================================================


class TestExemptionHygiene(unittest.TestCase):
    """Ensure exemption sets don't contain stale entries."""

    def test_separate_subsystem_types_are_real(self):
        """Every entry in SEPARATE_SUBSYSTEM_TYPES must be in KNOWN_FAULT_TYPES."""
        stale = SEPARATE_SUBSYSTEM_TYPES - KNOWN_FAULT_TYPES
        self.assertFalse(
            stale,
            "SEPARATE_SUBSYSTEM_TYPES contains types not in KNOWN_FAULT_TYPES: "
            "{}. Remove stale exemptions.".format(sorted(stale)),
        )

    def test_separate_subsystem_types_have_no_wire_code(self):
        """Types exempted as separate-subsystem should NOT have wire codes.

        If they gain a wire code, they should be removed from the exemption
        set and wired through the standard dispatch path.
        """
        for ft in sorted(SEPARATE_SUBSYSTEM_TYPES):
            self.assertNotIn(
                ft,
                FT_NAME_TO_CODE,
                "Exempted type '{}' now has a wire code '{}' -- remove it "
                "from SEPARATE_SUBSYSTEM_TYPES and wire it through standard "
                "dispatch.".format(ft, FT_NAME_TO_CODE.get(ft)),
            )

    def test_no_unknown_otp_types(self):
        """OTP_FAULT_TYPE_CODES keys must all be in KNOWN_FAULT_TYPES."""
        unknown = set(OTP_FAULT_TYPE_CODES.keys()) - KNOWN_FAULT_TYPES
        self.assertFalse(
            unknown,
            "OTP_FAULT_TYPE_CODES contains types not in KNOWN_FAULT_TYPES: "
            "{}".format(sorted(unknown)),
        )

    def test_no_unknown_i2c_types(self):
        """I2C_FAULT_TYPE_CODES keys must all be in KNOWN_FAULT_TYPES."""
        unknown = set(I2C_FAULT_TYPE_CODES.keys()) - KNOWN_FAULT_TYPES
        self.assertFalse(
            unknown,
            "I2C_FAULT_TYPE_CODES contains types not in KNOWN_FAULT_TYPES: "
            "{}".format(sorted(unknown)),
        )


if __name__ == "__main__":
    unittest.main()
