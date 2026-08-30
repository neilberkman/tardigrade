"""Security and behavior tests for the composite Action helpers."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from action_helpers import (  # noqa: E402
    download_verified,
    parse_bool,
    parse_positive_int,
    parse_workers,
    publish_report,
    resolve_workspace_path,
    select_github_release_asset,
    validate_git_ref,
    validate_https_url,
    validate_runner,
    validate_sha256,
)


class _Response(io.BytesIO):
    def __init__(self, data: bytes, url: str = "https://example.test/renode.tar.gz"):
        super().__init__(data)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False


class TestActionInputValidation(unittest.TestCase):
    def test_https_url_and_digest_validation(self):
        self.assertEqual(validate_https_url("https://builds.renode.io/a.tgz"),
                         "https://builds.renode.io/a.tgz")
        self.assertEqual(validate_sha256("A" * 64), "a" * 64)
        for invalid in (
            "http://builds.renode.io/a.tgz",
            "file:///tmp/a.tgz",
            "https://user:secret@example.test/a.tgz",
            "not-a-url",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_https_url(invalid)
        for invalid in ("", "a" * 63, "g" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_sha256(invalid)

    def test_strict_boolean_and_bounded_workers(self):
        self.assertTrue(parse_bool("TRUE", name="quick"))
        self.assertFalse(parse_bool("false", name="quick"))
        self.assertEqual(parse_workers("4"), 4)
        for invalid in ("yes", "1; id", "on"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_bool(invalid, name="quick")
        for invalid in ("0", "65", "2; id", "-1", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_workers(invalid)

    def test_positive_integer_and_public_git_ref_validation(self):
        self.assertEqual(parse_positive_int(" 32 ", name="fault_budget", maximum=4096), 32)
        for invalid in ("0", "4097", "-1", "1+1", "1; id", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_positive_int(invalid, name="fault_budget", maximum=4096)

        for ref in ("master", "releases/12.0", "a" * 40, "refs/pull/123/head"):
            with self.subTest(ref=ref):
                self.assertEqual(validate_git_ref(ref, name="nuttx_ref"), ref)
        for invalid in ("--upload-pack=bad", "main;id", "../main", "a//b", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_git_ref(invalid, name="nuttx_ref")

    def test_action_runner_is_linux_x64_only(self):
        self.assertEqual(validate_runner("Linux", "X64"), ("Linux", "X64"))
        self.assertEqual(validate_runner("linux", "amd64"), ("Linux", "X64"))
        for os_name, arch in (("Windows", "X64"), ("macOS", "ARM64"), ("Linux", "ARM64")):
            with self.subTest(os_name=os_name, arch=arch), self.assertRaises(ValueError):
                validate_runner(os_name, arch)

    def test_workspace_resolution_rejects_escape_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as outside:
            root = Path(workspace)
            profile = root / "profile.yaml"
            profile.write_text("name: public-test\n", encoding="utf-8")
            self.assertEqual(
                resolve_workspace_path(workspace, "profile.yaml", kind="file"),
                profile.resolve(),
            )
            with self.assertRaises(ValueError):
                resolve_workspace_path(workspace, outside, kind="directory")
            link = root / "outside"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                resolve_workspace_path(workspace, "outside", kind="directory")


class TestVerifiedDownload(unittest.TestCase):
    def test_verified_download_is_published(self):
        data = b"public Renode archive fixture"
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "renode.tar.gz"
            with mock.patch("action_helpers.urllib.request.urlopen", return_value=_Response(data)):
                download_verified("https://example.test/renode.tar.gz", digest, output)
            self.assertEqual(output.read_bytes(), data)

    def test_digest_mismatch_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "renode.tar.gz"
            output.write_bytes(b"existing")
            with mock.patch(
                "action_helpers.urllib.request.urlopen",
                return_value=_Response(b"different"),
            ), self.assertRaises(ValueError):
                download_verified(
                    "https://example.test/renode.tar.gz",
                    hashlib.sha256(b"expected").hexdigest(),
                    output,
                )
            self.assertEqual(output.read_bytes(), b"existing")
            self.assertEqual(list(Path(td).glob("*.download")), [])

    def test_redirect_must_remain_https(self):
        data = b"archive"
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "renode.tar.gz"
            with mock.patch(
                "action_helpers.urllib.request.urlopen",
                return_value=_Response(data, url="http://example.test/renode.tar.gz"),
            ), self.assertRaisesRegex(ValueError, "HTTPS"):
                download_verified(
                    "https://example.test/renode.tar.gz",
                    hashlib.sha256(data).hexdigest(),
                    output,
                )
            self.assertFalse(output.exists())

    def test_selects_asset_with_publisher_digest(self):
        digest = "a" * 64
        payload = {
            "assets": [
                {
                    "name": "renode-1.16.1.linux-portable.tar.gz",
                    "browser_download_url": (
                        "https://github.com/renode/renode/releases/download/"
                        "v1.16.1/renode-1.16.1.linux-portable.tar.gz"
                    ),
                    "digest": "sha256:{}".format(digest),
                },
                {
                    "name": "renode-1.16.1.linux-dotnet.tar.gz",
                    "browser_download_url": "https://example.test/dotnet.tar.gz",
                    "digest": "sha256:{}".format("b" * 64),
                },
            ]
        }
        name, url, selected_digest = select_github_release_asset(
            payload,
            asset_suffix=".linux-portable.tar.gz",
        )
        self.assertEqual(name, "renode-1.16.1.linux-portable.tar.gz")
        self.assertTrue(url.startswith("https://github.com/renode/renode/"))
        self.assertEqual(selected_digest, digest)

    def test_latest_asset_requires_unique_match_and_published_digest(self):
        with self.assertRaisesRegex(ValueError, "found 0"):
            select_github_release_asset(
                {"assets": []},
                asset_suffix=".linux-portable.tar.gz",
            )
        with self.assertRaisesRegex(ValueError, "does not publish"):
            select_github_release_asset(
                {"assets": [{
                    "name": "renode.linux-portable.tar.gz",
                    "browser_download_url": "https://example.test/renode.tar.gz",
                }]},
                asset_suffix=".linux-portable.tar.gz",
            )


class TestReportPublishing(unittest.TestCase):
    def test_only_well_formed_pass_verdict_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for index, verdict in enumerate(
                (
                    "PASSFAIL",
                    "PASS\nFAIL",
                    "PASS \nFAIL",
                    "PASS \rFAIL",
                    "PASS \tFAIL",
                    "PASS\x00FAIL",
                    "FAIL",
                )
            ):
                with self.subTest(verdict=verdict):
                    report = root / "report-{}.json".format(index)
                    outputs = root / "outputs-{}".format(index)
                    report.write_text(json.dumps({
                        "verdict": verdict,
                        "expect": {"should_find_issues": False},
                        "summary": {"runtime_sweep": {
                            "brick_rate": 0.0,
                            "issue_points": 0,
                        }},
                    }), encoding="utf-8")
                    self.assertFalse(publish_report(report, outputs, audit_exit=0))
                    self.assertIn("verdict=FAIL\n", outputs.read_text(encoding="utf-8"))

            for index, verdict in enumerate((None, 1, True, ""), start=10):
                with self.subTest(verdict=verdict):
                    report = root / "report-{}.json".format(index)
                    outputs = root / "outputs-{}".format(index)
                    report.write_text(json.dumps({
                        "verdict": verdict,
                        "expect": {"should_find_issues": False},
                        "summary": {"runtime_sweep": {
                            "brick_rate": 0.0,
                            "issue_points": 0,
                        }},
                    }), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "non-empty string"):
                        publish_report(report, outputs, audit_exit=0)
                    self.assertFalse(outputs.exists())

            report = root / "pass-report.json"
            outputs = root / "pass-outputs"
            report.write_text(json.dumps({
                "verdict": "  PASS with complete coverage  ",
                "expect": {"should_find_issues": False},
                "summary": {"runtime_sweep": {
                    "brick_rate": 0.0,
                    "issue_points": 0,
                }},
            }), encoding="utf-8")
            self.assertTrue(publish_report(report, outputs, audit_exit=0))
            self.assertIn("verdict=PASS\n", outputs.read_text(encoding="utf-8"))

    def test_nonzero_audit_exit_forces_fail_output(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            outputs = Path(td) / "outputs"
            report.write_text(json.dumps({
                "verdict": "PASS",
                "expect": {"should_find_issues": False},
                "summary": {"runtime_sweep": {
                    "brick_rate": 0.0,
                    "issue_points": 0,
                }},
            }), encoding="utf-8")
            self.assertFalse(publish_report(report, outputs, audit_exit=2))
            written = outputs.read_text(encoding="utf-8")
            self.assertIn("verdict=FAIL\n", written)
            self.assertIn("brick_rate=0.0\n", written)

    def test_expected_findings_fail_safe_unless_regression_mode_is_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            report.write_text(json.dumps({
                "verdict": "PASS",
                "expect": {"should_find_issues": True},
                "summary": {"runtime_sweep": {
                    "brick_rate": 0.25,
                    "issue_points": 3,
                    "security_bypass_points": 1,
                }},
            }), encoding="utf-8")

            safe_outputs = Path(td) / "safe-outputs"
            self.assertFalse(publish_report(report, safe_outputs, audit_exit=0))
            written = safe_outputs.read_text(encoding="utf-8")
            self.assertIn("verdict=FAIL\n", written)
            self.assertIn("assertion_status=PASS\n", written)
            self.assertIn("security_status=FINDINGS\n", written)
            self.assertIn("issue_points=3\n", written)
            self.assertIn("security_bypass_points=1\n", written)

            regression_outputs = Path(td) / "regression-outputs"
            self.assertTrue(publish_report(
                report,
                regression_outputs,
                audit_exit=0,
                regression_mode=True,
            ))
            self.assertIn(
                "verdict=PASS\n",
                regression_outputs.read_text(encoding="utf-8"),
            )

    def test_missing_security_expectation_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            outputs = Path(td) / "outputs"
            report.write_text(json.dumps({
                "verdict": "PASS",
                "summary": {"runtime_sweep": {"brick_rate": 0.0}},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "should_find_issues"):
                publish_report(report, outputs, audit_exit=0)
            self.assertFalse(outputs.exists())

    def test_unused_bricks_fallback_is_not_evaluated(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            outputs = Path(td) / "outputs"
            report.write_text(json.dumps({
                "verdict": "PASS",
                "expect": {"should_find_issues": False},
                "summary": {"runtime_sweep": {
                    "brick_rate": 0.0,
                    "issue_points": 0,
                    "bricks": -1,
                }},
            }), encoding="utf-8")

            self.assertTrue(publish_report(report, outputs, audit_exit=0))
            self.assertIn("issue_points=0\n", outputs.read_text(encoding="utf-8"))

    def test_malformed_bricks_is_rejected_when_used_as_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            outputs = Path(td) / "outputs"
            report.write_text(json.dumps({
                "verdict": "PASS",
                "expect": {"should_find_issues": False},
                "summary": {"runtime_sweep": {
                    "brick_rate": 0.0,
                    "bricks": -1,
                }},
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "bricks"):
                publish_report(report, outputs, audit_exit=0)
            self.assertFalse(outputs.exists())


class TestActionSourceBoundaries(unittest.TestCase):
    def test_caller_inputs_are_not_embedded_in_run_source(self):
        payload = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        for step in payload["runs"]["steps"]:
            self.assertNotIn("${{ inputs.", step.get("run", ""), step.get("name"))

    def test_action_passes_explicit_asset_and_robot_roots(self):
        source = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn('--repo-root "${ASSET_ROOT}"', source)
        self.assertIn('--robot-suite "${TARDIGRADE}/tests/ota_fault_point.robot"', source)
        self.assertIn("--strict-profile", source)

    def test_action_uses_isolated_verified_portable_runtime(self):
        source = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("renode-1.16.1.linux-portable-dotnet.tar.gz", source)
        self.assertIn(
            "00e113cdbd0f5354cf2f64bbe3f5a070d8958409542fca66e45ac97d982938c0",
            source,
        )
        self.assertIn('python3 -m venv "${venv_dir}"', source)
        self.assertIn('"${TARDIGRADE_VENV_PYTHON}"', source)
        self.assertNotIn('>> "${GITHUB_PATH}"', source)
        self.assertIn('export PATH="$(dirname "${TARDIGRADE_VENV_PYTHON}")', source)
        self.assertIn("validate-runner", source)
        self.assertIn('if [ "${QUICK}" = "true" ]', source)
        self.assertNotIn('if [ "${QUICK_INPUT,,}" = "true" ]', source)

    def test_action_smoke_uses_caller_only_asset_names(self):
        source = (
            ROOT / ".github" / "workflows" / "action-validation.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("consumer-platforms/caller-only.repl", source)
        self.assertIn("consumer-assets/caller-only.elf", source)
        self.assertIn("test ! -e tardigrade-action/consumer-assets/caller-only.elf", source)

    def test_pinned_renode_workflows_verify_the_archive(self):
        workflows = ROOT / ".github" / "workflows"
        for path in workflows.glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            if "renode-1.16.1.linux-dotnet.tar.gz" not in source:
                continue
            with self.subTest(workflow=path.name):
                self.assertIn(
                    "62629caa331ed4bd4eb7abe13ee2e4834fbcaa70de492db3965fafa4edc5694f",
                    source,
                )
                self.assertIn("action_helpers.py download-renode", source)
                self.assertIn("requirements-renode-constraints.txt", source)

    def test_external_workflow_actions_use_full_commit_ids(self):
        uses_pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
        commit_pattern = re.compile(r"^[^@]+@[0-9a-f]{40}$")
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            for target in uses_pattern.findall(source):
                if target.startswith("./"):
                    continue
                with self.subTest(workflow=path.name, target=target):
                    self.assertRegex(target, commit_pattern)

    def test_workflows_use_read_only_tokens_and_nonpersistent_checkouts(self):
        workflows = ROOT / ".github" / "workflows"
        for path in workflows.glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertRegex(source, r"(?m)^permissions:\n  contents: read$")
                checkout_count = source.count("uses: actions/checkout@")
                self.assertGreater(checkout_count, 0)
                self.assertEqual(
                    source.count("persist-credentials: false"),
                    checkout_count,
                )

    def test_nuttx_workflows_pin_dependencies_and_validate_dispatch_inputs(self):
        workflows = ROOT / ".github" / "workflows"
        for name in (
            "nuttx-nxboot-multi-fault-canary.yml",
            "nuttx-nxboot-real-exploratory.yml",
            "nuttx-nxboot-revert-canary.yml",
        ):
            source = (workflows / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("requirements-nuttx-build.txt", source)
                self.assertIn("normalize-positive-int", source)
                self.assertIn("--maximum 4096", source)
                self.assertIn("normalize-git-ref", source)
                self.assertIn("checkout --quiet --detach FETCH_HEAD", source)
                self.assertNotIn("pip install kconfiglib", source)
                self.assertNotIn("git clone --depth 1 --branch", source)

    def test_dependency_files_use_exact_public_versions(self):
        requirement_files = (
            "requirements.txt",
            "requirements-test.txt",
            "requirements-renode-constraints.txt",
            "requirements-nuttx-build.txt",
            "requirements-oss-build.txt",
        )
        for name in requirement_files:
            for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-r ")):
                    continue
                with self.subTest(file=name, requirement=stripped):
                    requirement = Requirement(stripped)
                    specifiers = list(requirement.specifier)
                    self.assertEqual(len(specifiers), 1)
                    self.assertEqual(specifiers[0].operator, "==")
                    self.assertNotIn("*", specifiers[0].version)
                    self.assertIsNone(requirement.url)


if __name__ == "__main__":
    unittest.main()
