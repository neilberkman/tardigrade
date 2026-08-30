#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the TF-M BL2 target-side invariants."""

from __future__ import annotations

import ast
import unittest
from types import SimpleNamespace

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from invariants import InvariantViolation  # noqa: E402
from targets.tf_m_bl2.invariants import (  # noqa: E402
    INVARIANTS,
    check_tfm_multi_image_acceptance_consistency,
    check_tfm_multi_image_consistency,
    check_tfm_no_partial_magic,
)
from targets.tf_m_bl2.probe import (  # noqa: E402
    _get_monitor_var,
    _parse_image_version,
    _slot_probe,
    collect_state,
)
from profile_loader import (  # noqa: E402
    ProfileError,
    _parse_fault_sweep,
    _parse_invariant_config,
    _parse_memory,
)


def _result(secure_state: str, ns_state: str):
    secure_version = {
        "state": "valid",
        "major": 2,
        "minor": 3,
        "revision": 0,
        "build": 1,
        "canonical": "2.3.0+1",
    }
    ns_version = {
        "state": "valid",
        "major": 4,
        "minor": 5,
        "revision": 6,
        "build": 7,
        "canonical": "4.5.6+7",
    }
    return SimpleNamespace(
        nvm_state={
            "flags": {"multi_image": True},
            "slots": {
                "secure_exec": {
                    "image_ok": {"state": secure_state},
                    "version": secure_version,
                },
                "ns_exec": {
                    "image_ok": {"state": ns_state},
                    "version": ns_version,
                },
            },
        }
    )


JOINT_ACCEPTANCE = {"invariant_config": {"tfm_joint_acceptance": True}}


class TfmBl2AcceptanceInvariantTest(unittest.TestCase):
    def test_missing_required_slot_evidence_is_inconclusive(self) -> None:
        result = _result("set", "set")
        del result.nvm_state["slots"]["ns_exec"]
        with self.assertRaisesRegex(ValueError, "requires secure and non-secure"):
            check_tfm_multi_image_acceptance_consistency(
                result, **JOINT_ACCEPTANCE
            )

    def test_rejects_malformed_image_ok_even_when_both_match(self) -> None:
        with self.assertRaises(InvariantViolation):
            check_tfm_multi_image_acceptance_consistency(
                _result("other", "other"), **JOINT_ACCEPTANCE
            )

    def test_rejects_interrupted_acceptance_split(self) -> None:
        for secure_state, ns_state in (("set", "unset"), ("unset", "set")):
            with self.subTest(secure_state=secure_state, ns_state=ns_state):
                with self.assertRaises(InvariantViolation) as ctx:
                    check_tfm_multi_image_acceptance_consistency(
                        _result(secure_state, ns_state), **JOINT_ACCEPTANCE
                    )

                self.assertEqual(
                    ctx.exception.invariant_name,
                    "tfm_multi_image_acceptance_consistency",
                )
                self.assertEqual(
                    ctx.exception.details["secure_exec_image_ok"], secure_state
                )
                self.assertEqual(
                    ctx.exception.details["ns_exec_image_ok"], ns_state
                )
                self.assertEqual(
                    ctx.exception.details["secure_exec_version"]["canonical"],
                    "2.3.0+1",
                )
                self.assertEqual(
                    ctx.exception.details["ns_exec_version"]["canonical"],
                    "4.5.6+7",
                )

    def test_accepts_matching_primary_states(self) -> None:
        for state in ("set", "unset"):
            with self.subTest(state=state):
                check_tfm_multi_image_acceptance_consistency(
                    _result(state, state), **JOINT_ACCEPTANCE
                )

    def test_skips_when_joint_acceptance_is_not_declared(self) -> None:
        check_tfm_multi_image_acceptance_consistency(_result("set", "unset"))

    def test_is_registered(self) -> None:
        self.assertIs(
            INVARIANTS["tfm_multi_image_acceptance_consistency"],
            check_tfm_multi_image_acceptance_consistency,
        )


class TfmBl2JointVersionInvariantTest(unittest.TestCase):
    def test_multi_image_consistency_rejects_missing_slot_evidence(self):
        result = _result("set", "set")
        del result.nvm_state["slots"]["secure_exec"]
        with self.assertRaisesRegex(ValueError, "requires secure and non-secure"):
            check_tfm_multi_image_consistency(result)

    def test_equal_trailer_state_rejects_incompatible_declared_versions(self):
        result = _result("set", "set")
        with self.assertRaises(InvariantViolation) as ctx:
            check_tfm_multi_image_consistency(
                result,
                invariant_config={
                    "tfm_joint_version_policy": {"mode": "compatible"}
                },
            )
        self.assertEqual(ctx.exception.invariant_name, "tfm_multi_image_consistency")
        self.assertEqual(ctx.exception.details["secure_exec_version"]["major"], 2)

    def test_compatible_policy_accepts_equal_major_versions(self):
        result = _result("set", "set")
        result.nvm_state["slots"]["ns_exec"]["version"]["major"] = 2
        check_tfm_multi_image_consistency(
            result,
            invariant_config={
                "tfm_joint_version_policy": {"mode": "compatible"}
            },
        )

    def test_declared_policy_requires_version_evidence(self):
        result = _result("unset", "unset")
        result.nvm_state["slots"]["secure_exec"]["version"] = {
            "state": "erased"
        }
        with self.assertRaises(ValueError):
            check_tfm_multi_image_consistency(
                result,
                invariant_config={"tfm_joint_version_policy": "equal"},
            )

    def test_trailer_magic_rejects_unknown_state_after_recovery(self):
        result = _result("set", "set")
        result.nvm_state["slots"]["secure_exec"]["magic_state"] = "other"
        with self.assertRaises(InvariantViolation):
            check_tfm_no_partial_magic(result)

    def test_trailer_invariant_rejects_absent_or_malformed_slot_evidence(self):
        result = _result("set", "set")
        del result.nvm_state["slots"]
        with self.assertRaises(ValueError):
            check_tfm_no_partial_magic(result)
        result = _result("set", "set")
        result.nvm_state["slots"]["secure_exec"] = None
        with self.assertRaises(ValueError):
            check_tfm_no_partial_magic(result)

    def test_secure_slot_invariant_rejects_missing_evidence_on_non_success(self):
        result = _result("set", "set")
        result.boot_outcome = "crash"
        del result.nvm_state["slots"]["secure_exec"]
        from targets.tf_m_bl2.invariants import check_tfm_secure_slot_not_empty

        with self.assertRaises(ValueError):
            check_tfm_secure_slot_not_empty(result)


class _ProbeMonitor:
    def __init__(self, variables):
        self.variables = variables

    def GetVariable(self, name):
        if name not in self.variables:
            raise KeyError(name)
        return self.variables[name]


class _ProbeBus:
    def ReadBytes(self, _address, size):
        return bytes([0] * int(size))


class _HeaderProbeBus:
    def __init__(self, base, header):
        self.base = int(base)
        self.header = bytes(header)

    def ReadBytes(self, address, size):
        if int(address) == self.base and int(size) == len(self.header):
            return self.header
        return bytes([0xFF] * int(size))


class TfmBl2ProbeImageVersionTest(unittest.TestCase):
    def test_parses_mcu_boot_version_and_canonical_string(self):
        header = bytearray(32)
        header[0:4] = (0x96F3B83D).to_bytes(4, "little")
        header[20:28] = bytes((2, 5)) + (0x1234).to_bytes(2, "little") + (7).to_bytes(4, "little")

        self.assertEqual(
            _parse_image_version(header),
            {
                "state": "valid",
                "major": 2,
                "minor": 5,
                "revision": 0x1234,
                "build": 7,
                "canonical": "2.5.4660+7",
            },
        )

        slot = _slot_probe(_HeaderProbeBus(0x1000, header), 0x1000, 0x1000, 8)
        self.assertEqual(slot["version"]["canonical"], "2.5.4660+7")

    def test_erased_invalid_and_short_headers_are_safe(self):
        for header, state in (
            (b"\xFF" * 32, "erased"),
            (b"\x00" * 32, "invalid"),
            (b"\x01", "invalid"),
        ):
            with self.subTest(state=state):
                version = _parse_image_version(header)
                self.assertEqual(version["state"], state)
                self.assertIsNone(version["canonical"])
                self.assertIsNone(version["major"])

        short_slot = _slot_probe(_HeaderProbeBus(0x1000, b"\x00" * 16), 0x1000, 16, 8)
        self.assertEqual(short_slot["version"]["state"], "invalid")


class TfmBl2ProbeSlotCompatibilityTest(unittest.TestCase):
    def test_generic_runtime_slots_map_to_four_tf_m_slots(self):
        variables = {
            "mcuboot_trailer_align": "8",
            "slot_exec_base": "0x80000",
            "slot_exec_size": "0x80000",
            "slot_staging_base": "0x180000",
            "slot_staging_size": "0x80000",
            "slot_tertiary_base": "0x100000",
            "slot_tertiary_size": "0x80000",
            "slot_recovery_base": "0x200000",
            "slot_recovery_size": "0x80000",
        }
        state = collect_state(_ProbeBus(), _ProbeMonitor(variables))

        self.assertTrue(state["flags"]["multi_image"])
        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x00080000")
        self.assertEqual(state["slots"]["secure_staging"]["base"], "0x00180000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x00100000")
        self.assertEqual(state["slots"]["ns_staging"]["base"], "0x00200000")
        self.assertEqual(state["security_boundary"]["status"], "unavailable")
        self.assertEqual(state["security_boundary"]["mpc"], "not_evaluated")

    def test_dedicated_slot_names_override_generic_aliases(self):
        variables = {
            "slot_exec_base": "0x1000",
            "slot_exec_size": "0x2000",
            "slot_staging_base": "0x3000",
            "slot_staging_size": "0x2000",
            "slot_tertiary_base": "0x5000",
            "slot_tertiary_size": "0x2000",
            "slot_recovery_base": "0x7000",
            "slot_recovery_size": "0x2000",
            "slot_s_exec_base": "0xA000",
            "slot_s_exec_size": "0x1000",
            "slot_s_staging_base": "0xB000",
            "slot_s_staging_size": "0x1000",
            "slot_ns_exec_base": "0xC000",
            "slot_ns_exec_size": "0x1000",
            "slot_ns_staging_base": "0xD000",
            "slot_ns_staging_size": "0x1000",
        }
        state = collect_state(_ProbeBus(), _ProbeMonitor(variables))

        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x0000A000")
        self.assertEqual(state["slots"]["secure_staging"]["base"], "0x0000B000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x0000C000")
        self.assertEqual(state["slots"]["ns_staging"]["base"], "0x0000D000")

    def test_context_slot_geometry_survives_reset_scoped_monitor_vars(self):
        context = {
            "slot_geometry": {
                "exec": {"base": 0x80000, "size": 0x80000},
                "staging": {"base": 0x180000, "size": 0x80000},
                "tertiary": {"base": 0x100000, "size": 0x80000},
                "recovery": {"base": 0x200000, "size": 0x80000},
            }
        }
        state = collect_state(
            _ProbeBus(),
            _ProbeMonitor({"mcuboot_trailer_align": "8"}),
            context=context,
        )
        self.assertEqual(state["slots"]["secure_exec"]["base"], "0x00080000")
        self.assertEqual(state["slots"]["ns_exec"]["base"], "0x00100000")
        self.assertEqual(state["slots"]["ns_staging"]["size"], "0x00080000")

    def test_missing_monitor_values_remain_missing(self):
        self.assertIsNone(_get_monitor_var(_ProbeMonitor({"empty": None}), "empty"))

    def test_profile_parser_exposes_opt_in_vtor_settle_budget(self):
        parsed = _parse_fault_sweep(
            {
                "vtor_settle_iters": 37,
                "fault_types": ["power_loss"],
                "max_writes_cap": 10,
            }
        )
        self.assertEqual(parsed.vtor_settle_iters, 37)

    def test_tracking_start_address_is_parsed_and_emitted(self):
        parsed = _parse_fault_sweep(
            {
                "tracking_start_address": "0x0010072C",
                "fault_types": ["power_loss"],
                "max_writes_cap": 10,
            }
        )
        self.assertEqual(parsed.tracking_start_address, 0x10072C)

    def test_tracking_start_address_defaults_and_validates(self):
        self.assertEqual(_parse_fault_sweep({}).tracking_start_address, 0)
        with self.assertRaises(ProfileError):
            _parse_fault_sweep({"tracking_start_address": "0x100000000"})

    def test_invariant_semantic_state_stage_is_validated(self):
        self.assertEqual(
            _parse_invariant_config({"semantic_state_stage": "fault_snapshot"})[
                "semantic_state_stage"
            ],
            "fault_snapshot",
        )
        with self.assertRaises(ProfileError):
            _parse_invariant_config({"semantic_state_stage": "unknown"})

    def test_trace_address_map_rejects_overlap_and_bad_32_bit_bound(self):
        base = {
            "sram": {"start": 0x38000000, "end": 0x38040000},
            "slots": {"exec": {"base": 0x80000, "size": 0x80000}},
        }
        parsed = _parse_memory({
            **base,
            "trace_address_map": [{
                "offset_start": 0x80000,
                "offset_end": 0x100000,
                "address_addend": 0x10000000,
            }],
        })
        self.assertEqual(parsed.trace_address_map[0]["address_addend"], 0x10000000)
        with self.assertRaises(ProfileError):
            _parse_memory({
                **base,
                "trace_address_map": [
                    {"offset_start": 0, "offset_end": 4, "address_addend": 0},
                    {"offset_start": 3, "offset_end": 8, "address_addend": 0},
                ],
            })
        with self.assertRaises(ProfileError):
            _parse_memory({
                **base,
                "trace_address_map": [{
                    "offset_start": 0xFFFFFFF0,
                    "offset_end": 0x100000000,
                    "address_addend": 1,
                }],
            })

    def test_runtime_tracking_gate_fails_closed_on_unsupported_backend(self):
        source = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_apply_tracking_start_address"
        )
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<runtime_gate>", "exec"), namespace)
        apply_gate = namespace["_apply_tracking_start_address"]
        with self.assertRaisesRegex(Exception, "requires backend"):
            apply_gate(SimpleNamespace(), "unsupported", 0x10072C)
        capable = SimpleNamespace(TrackingStartAddress=0)
        apply_gate(capable, "supported", 0x10072C)
        self.assertEqual(capable.TrackingStartAddress, 0x10072C)

    def test_native_template_is_path_neutral_and_not_discovered_as_profile(self):
        template = ROOT / "profiles" / "tf_m_bl2_an521_native.template.yaml.in"
        text = template.read_text(encoding="utf-8")
        self.assertIn("${TFM_BL2_ELF}", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("/tmp/", text)
        self.assertFalse(template.name.endswith(".yaml"))
        self.assertIn("pc_in_slot: tertiary", text)
        self.assertIn("tracking_start_address: ${TFM_TRACKING_START_ADDRESS}", text)
        self.assertIn("semantic_state_stage: fault_snapshot", text)
        self.assertIn("trace_address_map:", text)
        self.assertIn("address_addend: 0x10000000", text)
        self.assertIn("should_find_issues: false", text)

    def test_vtor_settle_budget_is_wired_through_runtime_boundary(self):
        robot = (ROOT / "tests" / "ota_fault_point.robot").read_text(encoding="utf-8")
        resc = (ROOT / "scripts" / "run_runtime_fault_sweep.resc").read_text(
            encoding="utf-8"
        )
        runtime = (ROOT / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("${VTOR_SETTLE_ITERS}", robot)
        self.assertIn("$vtor_settle_iters", resc)
        self.assertIn("vtor_settle_iters_config", runtime)
        self.assertIn("return vtor_settle_iters_config", runtime)
        self.assertIn("${TRACKING_START_ADDRESS}", robot)
        self.assertIn("$tracking_start_address", resc)
        self.assertIn("tracking_start_address_config", runtime)
        self.assertIn("TrackingStartAddress", runtime)
        self.assertIn("_apply_tracking_start_address", runtime)
        self.assertIn("requires backend", runtime)
        self.assertIn("def _configure_python_tracking_gate(force=False)", runtime)
        self.assertIn("_configure_python_tracking_gate(force=True)", runtime)
        self.assertIn("cpu_ref.AddHook(address, _python_tracking_gate_hook)", runtime)
        self.assertIn("_runtime_slot_geometry", runtime)
        self.assertIn("slot_geometry", runtime)
        self.assertIn("reset_sticky_handoff_state()", runtime)


if __name__ == "__main__":
    unittest.main()
