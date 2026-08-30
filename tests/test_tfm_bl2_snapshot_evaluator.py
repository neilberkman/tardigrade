#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit and fixture coverage for persisted TF-M snapshot evaluation."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from targets.tf_m_bl2.probe import MCUBOOT_GOOD_MAGIC
from targets.tf_m_bl2.snapshot_evaluator import evaluate_snapshot


class TfmSnapshotEvaluatorTest(unittest.TestCase):
    def _run(self, secure_ok: int, ns_ok: int, profile_update=None, snapshot_update=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = bytearray([0xFF] * 0x400)
            profile = {
                "address_base": 0,
                "trailer_align": 8,
                "expected_primary_magic": ["good", "good"],
                "slots": {
                    "secure_exec": {"base": 0, "size": 0x100},
                    "ns_exec": {"base": 0x100, "size": 0x100},
                    "secure_staging": {"base": 0x200, "size": 0x100},
                    "ns_staging": {"base": 0x300, "size": 0x100},
                },
                "invariant_providers": ["targets/tf_m_bl2/invariants.py"],
                "invariants": [
                    "atomic_state_groups",
                    "tfm_multi_image_acceptance_consistency",
                ],
                "invariant_config": {
                    "tfm_joint_acceptance": True,
                    "atomic_state_groups": [{
                        "name": "acceptance",
                        "members": [
                            {"path": "slots.secure_exec.image_ok.state", "before": "unset", "after": "set"},
                            {"path": "slots.ns_exec.image_ok.state", "before": "unset", "after": "set"},
                        ],
                    }],
                },
            }
            for base, value in ((0, secure_ok), (0x100, ns_ok)):
                snapshot[base + 0xF0:base + 0x100] = MCUBOOT_GOOD_MAGIC
                snapshot[base + 0xE8] = value
            if profile_update is not None:
                profile_update(profile)
            if snapshot_update is not None:
                snapshot_update(snapshot)
            snapshot_path = root / "flash.bin"
            profile_path = root / "profile.json"
            snapshot_path.write_bytes(snapshot)
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            return evaluate_snapshot(snapshot_path, profile_path)

    def test_split_is_reported_by_both_normal_invariants(self):
        output = self._run(1, 255)
        names = {item["name"] for item in output["invariant_violations"]}
        self.assertEqual(
            names,
            {"atomic_state_groups", "tfm_multi_image_acceptance_consistency"},
        )

    def test_joint_state_has_no_violation(self):
        output = self._run(1, 1)
        self.assertEqual(output["invariant_violations"], [])

    def test_expected_primary_magic_rejects_zero_filled_magic(self):
        with self.assertRaisesRegex(ValueError, "primary trailer magic precondition"):
            self._run(1, 255, snapshot_update=lambda data: data.__setitem__(0xF0, 0))

    def test_geometry_rejects_overlapping_and_out_of_bounds_slots(self):
        with self.assertRaisesRegex(ValueError, "slot ranges overlap"):
            self._run(
                1,
                255,
                profile_update=lambda profile: profile["slots"]["ns_exec"].update(
                    {"base": 0x80}
                ),
            )
        with self.assertRaisesRegex(ValueError, "lies outside"):
            self._run(
                1,
                255,
                profile_update=lambda profile: profile["slots"]["ns_staging"].update(
                    {"size": 0x200}
                ),
            )

    def test_direct_cli_help_works_from_repository_root(self):
        completed = subprocess.run(
            [sys.executable, "targets/tf_m_bl2/snapshot_evaluator.py", "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--snapshot", completed.stdout)


if __name__ == "__main__":
    unittest.main()
