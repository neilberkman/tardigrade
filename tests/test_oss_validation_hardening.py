"""Hardening tests for the public-repository validation tooling."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from run_oss_validation import (  # noqa: E402
    BatchProtocolError,
    _layout_contract,
    _validate_batch_payload,
    ensure_source_worktree,
    run_fault_batch,
    run_profile,
    render,
    source_worktree_path,
    validate_profile_name,
    validate_rendered_load_plan,
)


class TestReleaseEnvironmentMetadata(unittest.TestCase):
    def test_documented_python_minimum_matches_test_runner(self):
        guide = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")

        self.assertIn("**Python 3.10+**", guide)
        self.assertNotIn("**Python 3.9+**", guide)

    def test_platform_specific_test_dependencies_are_pinned(self):
        requirements = (ROOT / "requirements-test.txt").read_text(encoding="utf-8")

        for expected in (
            'colorama==0.4.6; sys_platform == "win32"',
            'exceptiongroup==1.3.1; python_version < "3.11"',
            'tomli==2.4.1; python_version < "3.11"',
            'typing_extensions==4.15.0; python_version < "3.11"',
        ):
            with self.subTest(requirement=expected):
                self.assertIn(expected, requirements.splitlines())


class TestValidationWorkflowInputs(unittest.TestCase):
    def test_build_inputs_trigger_push_and_scheduled_validation(self):
        workflow = (ROOT / ".github" / "workflows" / "oss-validation.yml").read_text(
            encoding="utf-8"
        )

        self.assertGreaterEqual(workflow.count("docker/oss-validation.Dockerfile"), 2)
        self.assertGreaterEqual(workflow.count("requirements*.txt"), 2)


class TestValidationContainerArchitecture(unittest.TestCase):
    def test_amd64_guard_precedes_package_install_and_x64_downloads(self):
        dockerfile = (ROOT / "docker" / "oss-validation.Dockerfile").read_text(
            encoding="utf-8"
        )

        declaration = dockerfile.index("ARG TARGETARCH")
        guard = dockerfile.index('test "${TARGETARCH}" = "amd64"')
        first_install = dockerfile.index("RUN apt-get update")
        first_download = dockerfile.index("RUN curl")

        self.assertLess(declaration, guard)
        self.assertLess(guard, first_install)
        self.assertLess(guard, first_download)


class TestReleaseBinaryAttributes(unittest.TestCase):
    def test_firmware_artifacts_are_never_text_normalized(self):
        for suffix in ("axf", "bin", "elf"):
            proc = subprocess.run(
                [
                    "git",
                    "check-attr",
                    "text",
                    "diff",
                    "--",
                    "release-check.{}".format(suffix),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            attributes = {
                line.split(": ", 2)[1]: line.split(": ", 2)[2]
                for line in proc.stdout.splitlines()
            }
            with self.subTest(suffix=suffix):
                self.assertEqual(attributes, {"text": "unset", "diff": "unset"})


class TestProfileNameValidation(unittest.TestCase):
    def test_accepts_public_manifest_identifiers(self):
        for value in ("mcuboot_current", "nxboot-guard", "v1.2"):
            with self.subTest(value=value):
                self.assertEqual(validate_profile_name(value), value)

    def test_rejects_paths_and_ambiguous_names(self):
        for value in (
            "../outside",
            "/tmp/outside",
            "nested/name",
            "UPPERCASE",
            "has space",
            "",
            None,
            "a" * 65,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_profile_name(value)

    def test_worktree_path_is_contained(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = source_worktree_path(root, "public_guard")
            self.assertEqual(
                path,
                (root / "results" / "oss_validation" / "worktrees" / "public_guard").resolve(),
            )


class TestManagedWorktreeRemoval(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        (self.source / "README").write_text("public fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.source), "add", "README"], check=True)
        subprocess.run([
            "git", "-C", str(self.source),
            "-c", "user.name=Tardigrade Tests",
            "-c", "user.email=tests@example.invalid",
            "commit", "-q", "-m", "fixture",
        ], check=True)
        self.checkout = {"repo": "source", "ref": "HEAD"}
        self.target = source_worktree_path(self.root, "public_guard")

    def tearDown(self):
        self.temp.cleanup()

    def test_refuses_to_delete_unowned_existing_directory(self):
        self.target.mkdir(parents=True)
        sentinel = self.target / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "unowned worktree"):
            ensure_source_worktree(
                self.root,
                "public_guard",
                self.checkout,
                self.target,
            )

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_replaces_only_a_marked_registered_worktree(self):
        ensure_source_worktree(
            self.root,
            "public_guard",
            self.checkout,
            self.target,
        )
        marker = self.target.parent / ".public_guard.tardigrade-worktree.json"
        payload = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(payload["source_worktree"], str(self.target))
        first_git_file = (self.target / ".git").read_text(encoding="utf-8")

        ensure_source_worktree(
            self.root,
            "public_guard",
            self.checkout,
            self.target,
        )
        self.assertTrue((self.target / "README").is_file())
        self.assertNotEqual(
            (self.target / ".git").read_text(encoding="utf-8"),
            "",
        )
        self.assertTrue(first_git_file)

    def test_source_repository_must_be_contained(self):
        outside = Path(self.temp.name).parent
        with self.assertRaisesRegex(ValueError, "source checkout repo escapes"):
            ensure_source_worktree(
                self.root,
                "public_guard",
                {"repo": str(outside), "ref": "HEAD"},
                self.target,
            )


class TestCampaignCompleteness(unittest.TestCase):
    @staticmethod
    def passing_control():
        return {
            "fault_at": -1,
            "is_control": True,
            "fault_injected": False,
            "boot_outcome": "success",
            "boot_slot": "A",
            "control_passed": True,
        }

    @classmethod
    def payload(cls, fault_results):
        return {
            "schema_version": 1,
            "aborted": False,
            "abort_reason": None,
            "control_passed": True,
            "results": [cls.passing_control()] + list(fault_results),
        }

    @staticmethod
    def contract():
        return {
            "observation": {"wall_timeout_s": 1.0},
        }

    def run_profile_with_payload(self, profile, payload):
        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation._layout_contract",
            return_value=(self.contract(), []),
        ), mock.patch(
            "run_oss_validation.validate_rendered_load_plan",
        ), mock.patch(
            "run_oss_validation.run_fault_batch",
            return_value=payload,
        ):
            return run_profile(
                Path(td),
                "renode-test",
                profile,
                {},
                workers=1,
                skip_setup=True,
            )

    def test_batch_runner_uses_one_process_and_preserves_telemetry(self):
        payload = self.payload([
            {
                "fault_at": 0,
                "is_control": False,
                "fault_injected": True,
                "boot_outcome": "success",
                "nvm_state": {"faulted": True},
            }
        ])
        calls = []

        def fake_subprocess(cmd, **kwargs):
            del kwargs
            calls.append(cmd)
            result_var = next(
                cmd[index + 1]
                for index, value in enumerate(cmd)
                if value == "--variable" and cmd[index + 1].startswith("RESULT_FILE:")
            )
            result_path = Path(result_var.split(":", 1)[1])
            result_path.write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation.subprocess.run",
            side_effect=fake_subprocess,
        ):
            result = run_fault_batch(
                Path(td),
                "renode-test",
                "tests/generic_fault_point.robot",
                [0],
                [],
                Path(td) / "work",
                1,
                1.0,
            )

        self.assertEqual(len(calls), 1)
        self.assertIn("FAULT_POINTS_CSV:-1,0", calls[0])
        self.assertIs(result["results"][1]["nvm_state"]["faulted"], True)

    def test_batch_protocol_rejects_short_or_reordered_results(self):
        short = self.payload([])
        with self.assertRaisesRegex(BatchProtocolError, "order/cardinality"):
            _validate_batch_payload(short, [0])

        reordered = self.payload([
            {
                "fault_at": 1,
                "is_control": False,
                "fault_injected": True,
                "boot_outcome": "success",
            },
            {
                "fault_at": 0,
                "is_control": False,
                "fault_injected": True,
                "boot_outcome": "success",
            },
        ])
        with self.assertRaisesRegex(BatchProtocolError, "order/cardinality"):
            _validate_batch_payload(reordered, [0, 1])

    def test_failed_control_must_abort_without_fault_results(self):
        payload = {
            "schema_version": 1,
            "aborted": True,
            "abort_reason": "control failed",
            "control_passed": False,
            "results": [dict(self.passing_control(), control_passed=False)],
        }
        payload["results"][0]["boot_outcome"] = "wrong_pc"
        validated = _validate_batch_payload(payload, [0, 1])
        self.assertTrue(validated["aborted"])

        invalid = dict(payload)
        invalid["results"] = payload["results"] + [{
            "fault_at": 0,
            "is_control": False,
            "fault_injected": True,
            "boot_outcome": "no_boot",
        }]
        with self.assertRaisesRegex(BatchProtocolError, "abort before every fault"):
            _validate_batch_payload(invalid, [0, 1])

    def test_failed_control_fails_profile_before_fault_results_exist(self):
        payload = {
            "schema_version": 1,
            "aborted": True,
            "abort_reason": "wrong marker",
            "control_passed": False,
            "results": [dict(self.passing_control(), control_passed=False)],
        }
        payload["results"][0]["boot_outcome"] = "wrong_image"
        profile = {
            "name": "public_guard",
            "fault_range": "0:0",
            "fault_step": 1,
            "total_writes": 1,
        }
        result = self.run_profile_with_payload(profile, payload)
        self.assertFalse(result["passed"])
        self.assertEqual(result["faulted_runs"], 0)
        self.assertIn("aborted before fault dispatch", " ".join(result["failures"]))

    def test_fault_range_cannot_include_nonexistent_terminal_write(self):
        profile = {
            "name": "public_guard",
            "fault_range": "0:2",
            "total_writes": 2,
        }
        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation._layout_contract",
            return_value=(self.contract(), []),
        ), mock.patch(
            "run_oss_validation.validate_rendered_load_plan",
        ), self.assertRaisesRegex(ValueError, "inclusive subset of 0:1"):
            run_profile(Path(td), "renode-test", profile, {}, 1, True)

    def test_nonfiring_fault_cannot_satisfy_clean_expectations(self):
        profile = {
            "name": "public_guard",
            "fault_range": "0:0",
            "fault_step": 1,
            "total_writes": 1,
            "expect": {
                "issues_max": 0,
                "require_control_success": True,
            },
        }
        payload = self.payload([{
            "fault_at": 0,
            "is_control": False,
            "fault_injected": False,
            "boot_outcome": "success",
        }])
        result = self.run_profile_with_payload(profile, payload)

        self.assertFalse(result["passed"])
        self.assertIn("incomplete", " ".join(result["failures"]))

    def test_infrastructure_result_cannot_satisfy_adverse_minimum(self):
        profile = {
            "name": "public_guard",
            "fault_range": "0:1",
            "fault_step": 1,
            "total_writes": 2,
            "expect": {
                "bricks_min": 1,
                "require_control_success": True,
            },
        }
        payload = self.payload([
            {
                "fault_at": 0,
                "is_control": False,
                "fault_injected": True,
                "boot_outcome": "no_boot",
            },
            {
                "fault_at": 1,
                "is_control": False,
                "fault_injected": False,
                "boot_outcome": "infra_error",
                "error": "runner unavailable",
            },
        ])
        result = self.run_profile_with_payload(profile, payload)

        self.assertFalse(result["passed"])
        self.assertEqual(result["infra_errors"], 1)
        self.assertIn("incomplete or infrastructure", " ".join(result["failures"]))

    def test_point_workers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "workers must be 1"):
            run_profile(Path("."), "renode-test", {"name": "public_guard"}, {}, 2, True)


class TestDeclarativeCampaignLayouts(unittest.TestCase):
    def test_public_profiles_have_one_valid_artifact_backed_layout(self):
        manifest = json.loads(
            (ROOT / "docs" / "oss_validation_profiles.json").read_text(encoding="utf-8")
        )
        for raw_profile in manifest["profiles"]:
            variables = {
                "repo_root": str(ROOT),
                "variant_name": raw_profile["name"],
            }
            profile = render(raw_profile, variables)
            robot_vars = [str(value) for value in profile.get("robot_vars", [])]
            for key in (
                "slot_a_image_file",
                "slot_b_image_file",
                "evaluation_mode",
                "boot_mode",
            ):
                value = profile.get(key)
                if value is not None:
                    robot_vars.append("{}:{}".format(key.upper(), value))
            with self.subTest(profile=raw_profile["name"]):
                contract, derived = _layout_contract(profile, robot_vars)
                normalized = validate_rendered_load_plan(
                    ROOT,
                    profile,
                    robot_vars + derived,
                    contract,
                )
                self.assertEqual(contract["version"], 1)
                self.assertTrue(normalized["bootloader"])

    def test_layout_owned_robot_literal_is_rejected(self):
        profile = {
            "layout": {
                "version": 1,
            }
        }
        with self.assertRaisesRegex(ValueError, "must not be repeated"):
            _layout_contract(profile, ["SLOT_A_BASE:0x1000"])


if __name__ == "__main__":
    unittest.main()
