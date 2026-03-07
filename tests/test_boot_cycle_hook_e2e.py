#!/usr/bin/env python3
"""Real Renode e2e test for boot_cycle_hook behavior."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOCKER_IMAGE = "renode-patched:test"
HOOK_PROFILE = ROOT / "profiles" / "esp_idf_ota_upgrade_confirm_hook.yaml"
HOOK_LINE = "  boot_cycle_hook: examples/esp_idf_ota/hooks/confirm_pending_verify.py\n"


def _docker_image_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", DOCKER_IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


@unittest.skipUnless(_docker_image_available(), "requires docker image renode-patched:test")
class BootCycleHookE2ETests(unittest.TestCase):
    maxDiff = None

    def _run_audit(self, profile_path: Path) -> dict:
        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "audit.json"
            cmd = [
                sys.executable,
                "scripts/audit_bootloader.py",
                "--profile",
                str(profile_path),
                "--output",
                str(output_path),
                "--renode-test",
                "docker://{}".format(DOCKER_IMAGE),
                "--workers",
                "1",
                "--fault-end",
                "1",
                "--robot-var",
                "TEST_TIMEOUT:10 minutes",
                "--no-assert-control-boots",
                "--no-assert-verdict",
            ]
            env = dict(os.environ)
            env["OTA_RENODE_POINT_TIMEOUT_S"] = "900"
            result = subprocess.run(
                cmd,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=900,
                check=False,
            )
            if result.returncode != 0:
                self.fail(
                    "audit_bootloader failed for {}:\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                        profile_path,
                        result.stdout,
                        result.stderr,
                    )
                )
            return json.loads(output_path.read_text(encoding="utf-8"))

    def test_boot_cycle_hook_changes_control_boot_path(self) -> None:
        with_hook = self._run_audit(HOOK_PROFILE)
        with_hook_control = with_hook["summary"]["runtime_sweep"]["control"]
        with_hook_multi = with_hook_control.get("multi_boot_analysis") or {}
        self.assertEqual(with_hook_control.get("boot_outcome"), "success")
        self.assertEqual(with_hook_multi.get("final_slot"), "staging")
        self.assertEqual(with_hook_multi.get("status"), "converged")
        self.assertEqual(with_hook_multi.get("slots_observed"), ["staging", "staging"])

        with tempfile.TemporaryDirectory() as td:
            no_hook_profile = Path(td) / "esp_idf_no_hook.yaml"
            text = HOOK_PROFILE.read_text(encoding="utf-8").replace(HOOK_LINE, "")
            no_hook_profile.write_text(text, encoding="utf-8")
            without_hook = self._run_audit(no_hook_profile)

        without_hook_control = without_hook["summary"]["runtime_sweep"]["control"]
        without_hook_multi = without_hook_control.get("multi_boot_analysis") or {}
        self.assertEqual(without_hook_control.get("boot_outcome"), "success")
        self.assertEqual(without_hook_multi.get("final_slot"), "exec")
        self.assertEqual(without_hook_multi.get("slots_observed"), ["staging", "exec"])
        self.assertIn(without_hook_multi.get("status"), {"oscillating", "rollback_converged"})


if __name__ == "__main__":
    unittest.main()
