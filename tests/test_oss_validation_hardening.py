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
    ensure_source_worktree,
    run_profile,
    run_single_fault_point,
    source_worktree_path,
    validate_profile_name,
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
    def test_runner_preserves_nested_fault_fired_telemetry(self):
        def fake_subprocess(cmd, **kwargs):
            del kwargs
            result_var = next(
                cmd[index + 1]
                for index, value in enumerate(cmd)
                if value == "--variable" and cmd[index + 1].startswith("RESULT_FILE:")
            )
            result_path = Path(result_var.split(":", 1)[1])
            result_path.write_text(
                json.dumps(
                    {
                        "boot_outcome": "success",
                        "nvm_state": {"faulted": True},
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation.subprocess.run",
            side_effect=fake_subprocess,
        ):
            result = run_single_fault_point(
                Path(td),
                "renode-test",
                "tests/generic_fault_point.robot",
                0,
                [],
                Path(td) / "work",
                1,
                False,
            )

        self.assertIs(result["fault_injected"], True)

    def test_fault_range_cannot_include_nonexistent_terminal_write(self):
        profile = {
            "name": "public_guard",
            "fault_range": "0:2",
            "total_writes": 2,
        }
        with tempfile.TemporaryDirectory() as td, self.assertRaisesRegex(
            ValueError,
            "inclusive subset of 0:1",
        ):
            run_profile(
                Path(td),
                "renode-test",
                profile,
                {},
                workers=1,
                skip_setup=True,
            )

    def test_nonfiring_fault_cannot_satisfy_clean_expectations(self):
        def fake_run(*args, **kwargs):
            del kwargs
            fault_at = args[3]
            is_control = args[7]
            return {
                "fault_at": fault_at,
                "is_control": is_control,
                "fault_injected": False,
                "boot_outcome": "success",
            }

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
        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation.run_single_fault_point",
            side_effect=fake_run,
        ):
            result = run_profile(
                Path(td),
                "renode-test",
                profile,
                {},
                workers=1,
                skip_setup=True,
            )

        self.assertFalse(result["passed"])
        self.assertIn("incomplete", " ".join(result["failures"]))

    def test_infrastructure_result_cannot_satisfy_adverse_minimum(self):
        def fake_run(
            repo_root,
            renode_test,
            robot_suite,
            fault_at,
            robot_vars,
            work_dir,
            total_writes,
            is_control,
        ):
            del (
                repo_root,
                renode_test,
                robot_suite,
                robot_vars,
                work_dir,
                total_writes,
            )
            if is_control:
                return {
                    "fault_at": fault_at,
                    "is_control": True,
                    "fault_injected": False,
                    "boot_outcome": "success",
                }
            if fault_at == 0:
                return {
                    "fault_at": fault_at,
                    "is_control": False,
                    "fault_injected": True,
                    "boot_outcome": "no_boot",
                }
            return {
                "fault_at": fault_at,
                "is_control": False,
                "fault_injected": False,
                "boot_outcome": "infra_error",
                "error": "runner unavailable",
            }

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
        with tempfile.TemporaryDirectory() as td, mock.patch(
            "run_oss_validation.run_single_fault_point",
            side_effect=fake_run,
        ):
            result = run_profile(
                Path(td),
                "renode-test",
                profile,
                {},
                workers=1,
                skip_setup=True,
            )

        self.assertFalse(result["passed"])
        self.assertEqual(result["infra_errors"], 1)
        self.assertIn("incomplete or infrastructure", " ".join(result["failures"]))


if __name__ == "__main__":
    unittest.main()
