#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the fail-closed license certification ledger."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "license_certify.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from license_certify import (  # noqa: E402
    CertificationInputError,
    certify,
    refresh_source_inventory,
    render_human,
)


class LicenseCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "artifact.bin").write_bytes(b"artifact")
        (self.root / "build-tool.txt").write_bytes(b"build tool")
        (self.root / "link.json").write_text(
            '{"schema_version": 2, "inputs": [{"artifact_id": "runtime", '
            '"path": "artifact.bin", "sha256": "' + hashlib.sha256(b"artifact").hexdigest() + '"}], '
            '"verification_status": "verified"}\n',
            encoding="utf-8",
        )
        self.policy = {
            "schema_version": 2,
            "build_only_copyleft": "report",
            "licenses": {
                "Apache-2.0": {"decision": "allow", "class": "permissive"},
                "GPL-3.0-only": {"decision": "prohibit", "class": "copyleft"},
            },
        }
        (self.root / "policy.json").write_text(json.dumps(self.policy), encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _entry(self, *, kind="distributed", license_spdx="Apache-2.0"):
        artifact = self.root / ("artifact.bin" if kind != "build-only" else "build-tool.txt")
        entry = {
            "id": kind,
            "kind": kind,
            "path": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "license_status": "known",
            "license_spdx": license_spdx,
            "license_evidence": {
                "type": "upstream-declaration",
                "source": "https://example.invalid/source",
                "basis": "upstream declaration reviewed at pinned revision",
                "path": "artifact.bin",
                "sha256": hashlib.sha256(b"artifact").hexdigest(),
            },
            "provenance": {
                "source": "https://example.invalid/source",
                "revision": "deadbeef",
                "snapshots": {
                    artifact.name: {
                        "path": artifact.name,
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    }
                },
            },
        }
        if kind in {"distributed", "linked"}:
            entry["link_manifest"] = {
                "path": "link.json",
                "sha256": hashlib.sha256((self.root / "link.json").read_bytes()).hexdigest(),
            }
        return entry

    def _write_manifest(self, entries):
        manifest = {"schema_version": 2, "policy": "policy.json", "artifacts": entries}
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def _source_release(self):
        source = self.root / "src"
        source.mkdir(exist_ok=True)
        (source / "main.py").write_text("print('source')\n", encoding="utf-8")
        (source / "fixture.elf").write_bytes(b"excluded firmware")
        return {
            "name": "source-only",
            "include_paths": ["src"],
            "exclude_globs": ["**/*.elf"],
            "file_digests": {
                "src/main.py": hashlib.sha256(b"print('source')\n").hexdigest(),
            },
            "license_status": "known",
            "license_spdx": "Apache-2.0",
            "license_evidence": {
                "type": "license-file",
                "source": "https://example.invalid/project/LICENSE",
                "basis": "project license covering the source package",
                "path": "artifact.bin",
                "sha256": hashlib.sha256(b"artifact").hexdigest(),
            },
            "provenance": {
                "source": "https://example.invalid/project",
                "revision": "per-file SHA-256 inventory",
            },
        }

    def _write_source_manifest(self, source_release):
        manifest = {
            "schema_version": 2,
            "policy": "policy.json",
            "source_release": source_release,
            "artifacts": [],
        }
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_complete_distributed_entry_passes(self):
        result = certify(self._write_manifest([self._entry(kind="runtime")]))
        self.assertTrue(result["certified"])
        self.assertEqual(result["summary"], {"entries": 1, "errors": 0, "warnings": 0})
        self.assertEqual(render_human(result).splitlines()[0], "License certification: PASS")

    def test_source_release_boundary_passes_and_reports_excluded_binary(self):
        result = certify(self._write_source_manifest(self._source_release()), strict=True)
        self.assertTrue(result["certified"])
        self.assertEqual(result["summary"], {"entries": 1, "errors": 0, "warnings": 0})
        self.assertEqual(result["source_release"]["included_files"], ["src/main.py"])
        self.assertEqual(result["source_release"]["excluded_files"], ["src/fixture.elf"])
        self.assertIn(
            "1 files included; 1 package files excluded; 0 tracked paths outside package",
            render_human(result),
        )

    def test_source_release_boundary_fails_on_uninventoried_or_extra_file(self):
        source_release = self._source_release()
        manifest = self._write_source_manifest(source_release)
        (self.root / "src" / "new.py").write_text("new\n", encoding="utf-8")
        result = certify(manifest, strict=True)
        self.assertFalse(result["certified"])
        self.assertIn(
            "source-inventory-missing",
            {item["code"] for item in result["source_release"]["findings"]},
        )

        (self.root / "src" / "new.py").unlink()
        source_release["file_digests"]["src/not-present.py"] = "0" * 64
        result = certify(self._write_source_manifest(source_release), strict=True)
        self.assertFalse(result["certified"])
        self.assertIn(
            "source-inventory-extra",
            {item["code"] for item in result["source_release"]["findings"]},
        )

    def test_source_release_refresh_replaces_only_digest_inventory(self):
        source_release = self._source_release()
        source_release["file_digests"] = {}
        manifest = self._write_source_manifest(source_release)
        self.assertEqual(refresh_source_inventory(manifest), 1)
        refreshed = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(
            refreshed["source_release"]["file_digests"],
            {"src/main.py": hashlib.sha256(b"print('source')\n").hexdigest()},
        )
        self.assertEqual(refreshed["artifacts"], [])

    def test_source_release_rejects_symlinks_and_escaping_paths(self):
        source_release = self._source_release()
        source_release["include_paths"] = ["../outside"]
        with self.assertRaisesRegex(CertificationInputError, "remain under"):
            certify(self._write_source_manifest(source_release), strict=True)

        source_release = self._source_release()
        link = self.root / "src" / "linked.py"
        try:
            link.symlink_to(self.root / "src" / "main.py")
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links unavailable")
        with self.assertRaisesRegex(CertificationInputError, "symbolic links"):
            certify(self._write_source_manifest(source_release), strict=True)

    def test_source_release_tracked_completeness_requires_explicit_classification(self):
        source_release = self._source_release()
        source_release["require_tracked_completeness"] = True
        source_release["tracked_exclude_globs"] = ["**/*.elf", ".github/**"]
        manifest = self._write_source_manifest(source_release)
        tracked = [
            Path("src/main.py"),
            Path("src/fixture.elf"),
            Path(".github/workflows/nested/check.yml"),
        ]
        with mock.patch("license_certify._git_tracked_files", return_value=tracked):
            result = certify(manifest, strict=True)
        self.assertTrue(result["certified"])
        self.assertTrue(result["source_release"]["tracked_completeness_enforced"])
        self.assertEqual(
            result["source_release"]["tracked_excluded_files"],
            ["src/fixture.elf", ".github/workflows/nested/check.yml"],
        )

        tracked.remove(Path("src/main.py"))
        with mock.patch("license_certify._git_tracked_files", return_value=tracked):
            result = certify(manifest, strict=True)
        self.assertFalse(result["certified"])
        self.assertIn(
            "source-file-untracked",
            {item["code"] for item in result["source_release"]["findings"]},
        )
        tracked.insert(0, Path("src/main.py"))

        tracked.append(Path("outside.py"))
        with mock.patch("license_certify._git_tracked_files", return_value=tracked):
            result = certify(manifest, strict=True)
        self.assertFalse(result["certified"])
        self.assertIn(
            "tracked-file-outside-source-boundary",
            {item["code"] for item in result["source_release"]["findings"]},
        )

    def test_source_release_tracked_completeness_fails_when_git_is_unavailable(self):
        source_release = self._source_release()
        source_release["require_tracked_completeness"] = True
        manifest = self._write_source_manifest(source_release)
        with mock.patch(
            "license_certify._git_tracked_files",
            side_effect=CertificationInputError("git unavailable"),
        ):
            with self.assertRaisesRegex(CertificationInputError, "git unavailable"):
                certify(manifest, strict=True)

    def test_missing_provenance_and_link_manifest_fail_closed(self):
        entry = self._entry(kind="distributed")
        del entry["provenance"]
        del entry["link_manifest"]
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        codes = {item["code"] for item in result["entries"][0]["findings"]}
        self.assertIn("provenance-incomplete", codes)
        self.assertIn("link-manifest-missing", codes)

    def test_missing_artifact_digest_fails_closed(self):
        entry = self._entry()
        del entry["sha256"]
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "artifact-digest-missing",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

    def test_unknown_fields_and_duplicate_ids_are_rejected(self):
        entry = self._entry()
        entry["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown field"):
            certify(self._write_manifest([entry]))

        first = self._entry()
        second = self._entry()
        second["kind"] = "runtime"
        with self.assertRaisesRegex(ValueError, "duplicate artifact id"):
            certify(self._write_manifest([first, second]))

        manifest = {
            "schema_version": 2,
            "policy": "policy.json",
            "artifacts": [self._entry()],
            "unexpected": True,
        }
        (self.root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown field"):
            certify(self.root / "manifest.json")

    def test_unknown_nested_fields_are_rejected(self):
        for field_name, nested_name in (
            ("license_evidence", "unexpected"),
            ("provenance", "unexpected"),
            ("link_manifest", "unexpected"),
        ):
            with self.subTest(field_name=field_name):
                entry = self._entry()
                entry[field_name][nested_name] = True
                with self.assertRaisesRegex(ValueError, "unknown field"):
                    certify(self._write_manifest([entry]))

        policy = dict(self.policy)
        policy["unexpected"] = True
        (self.root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown field"):
            certify(self._write_manifest([self._entry()]))

        policy = dict(self.policy)
        policy["licenses"] = dict(self.policy["licenses"])
        policy["licenses"]["Apache-2.0"] = {
            **self.policy["licenses"]["Apache-2.0"],
            "unexpected": True,
        }
        (self.root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown field"):
            certify(self._write_manifest([self._entry()]))

    def test_policy_path_from_manifest_cannot_escape_root(self):
        manifest = {
            "schema_version": 2,
            "policy": "../outside-policy.json",
            "artifacts": [self._entry()],
        }
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "remain under"):
            certify(path)

    def test_digest_read_error_is_reported_as_input_error(self):
        manifest = self._write_manifest([self._entry()])
        original_read_bytes = Path.read_bytes

        def fail_read_bytes(path):
            if path.name == "artifact.bin":
                raise OSError("simulated unreadable artifact")
            return original_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", fail_read_bytes):
            with self.assertRaisesRegex(CertificationInputError, "cannot read .* for digest"):
                certify(manifest)

    def test_link_manifest_requires_parsed_inputs_and_verified_status(self):
        (self.root / "link.json").write_text(
            '{"schema_version": 2, "inputs": [], '
            '"verification_status": "unverified"}\n',
            encoding="utf-8",
        )
        result = certify(self._write_manifest([self._entry()]))
        self.assertFalse(result["certified"])
        findings = result["entries"][0]["findings"]
        messages = " ".join(item["message"] for item in findings)
        self.assertIn("non-empty array", messages)
        self.assertIn("must be 'verified'", messages)

        (self.root / "link.json").write_text(
            '{"schema_version": 2, "inputs": [{"artifact_id": "runtime", '
            '"path": "artifact.bin", "sha256": "' + hashlib.sha256(b"artifact").hexdigest() + '"}], '
            '"verification_status": "verified", "unexpected": true}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unknown field"):
            certify(self._write_manifest([self._entry()]))

    def test_link_inputs_require_independent_certified_entry_and_matching_digest(self):
        owner = self._entry(kind="distributed")
        target = self._entry(kind="runtime")
        result = certify(self._write_manifest([owner, target]))
        self.assertTrue(result["certified"])

        link_payload = {
            "schema_version": 2,
            "inputs": [
                {
                    "artifact_id": "missing",
                    "path": "artifact.bin",
                    "sha256": hashlib.sha256(b"artifact").hexdigest(),
                }
            ],
            "verification_status": "verified",
        }
        (self.root / "link.json").write_text(json.dumps(link_payload), encoding="utf-8")
        result = certify(self._write_manifest([owner, target]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "link-input-unresolved",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

        link_payload["inputs"][0]["artifact_id"] = "runtime"
        link_payload["inputs"][0]["path"] = "build-tool.txt"
        (self.root / "link.json").write_text(json.dumps(link_payload), encoding="utf-8")
        result = certify(self._write_manifest([owner, target]))
        self.assertFalse(result["certified"])
        codes = {item["code"] for item in result["entries"][0]["findings"]}
        self.assertIn("link-manifest-invalid", codes)
        self.assertIn("link-input-unverified", codes)

    def test_duplicate_link_inputs_fail_closed(self):
        duplicate = {
            "schema_version": 2,
            "inputs": [
                {
                    "artifact_id": "runtime",
                    "path": "artifact.bin",
                    "sha256": hashlib.sha256(b"artifact").hexdigest(),
                },
                {
                    "artifact_id": "runtime",
                    "path": "artifact.bin",
                    "sha256": hashlib.sha256(b"artifact").hexdigest(),
                },
            ],
            "verification_status": "verified",
        }
        (self.root / "link.json").write_text(json.dumps(duplicate), encoding="utf-8")
        result = certify(self._write_manifest([self._entry(kind="distributed"), self._entry(kind="runtime")]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "duplicate path",
            " ".join(item["message"] for item in result["entries"][0]["findings"]),
        )

    def test_link_input_missing_required_identity_fails_closed(self):
        payload = {
            "schema_version": 2,
            "inputs": [
                {"path": "artifact.bin", "sha256": hashlib.sha256(b"artifact").hexdigest()}
            ],
            "verification_status": "verified",
        }
        (self.root / "link.json").write_text(json.dumps(payload), encoding="utf-8")
        result = certify(
            self._write_manifest([self._entry(kind="distributed"), self._entry(kind="runtime")])
        )
        self.assertFalse(result["certified"])
        self.assertIn(
            "artifact_id",
            " ".join(item["message"] for item in result["entries"][0]["findings"]),
        )

    def test_glob_expansion_is_sorted_and_requires_complete_digest_map(self):
        (self.root / "a.bin").write_bytes(b"a")
        (self.root / "z.bin").write_bytes(b"z")
        entry = self._entry(kind="runtime")
        entry.pop("path")
        entry.pop("sha256")
        entry["path_glob"] = "*.bin"
        entry["file_digests"] = {
            "a.bin": hashlib.sha256(b"a").hexdigest(),
            "artifact.bin": hashlib.sha256(b"artifact").hexdigest(),
            "z.bin": hashlib.sha256(b"z").hexdigest(),
        }
        entry["provenance"]["snapshots"] = {
            name: {
                "path": name,
                "sha256": digest,
                "artifact_sha256": digest,
            }
            for name, digest in entry["file_digests"].items()
        }
        result = certify(self._write_manifest([entry]))
        self.assertTrue(result["certified"])
        self.assertEqual(result["entries"][0]["matched_files"], ["a.bin", "artifact.bin", "z.bin"])

        del entry["file_digests"]["z.bin"]
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "artifact-digest-missing",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

    def test_unknown_license_is_not_inferred_from_evidence_text(self):
        entry = self._entry(license_spdx="GPL-3.0-only")
        entry["license_status"] = "unknown"
        entry["license_evidence"]["basis"] = "file contains an Apache-looking notice"
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        codes = {item["code"] for item in result["entries"][0]["findings"]}
        self.assertIn("license-unresolved", codes)
        self.assertNotIn("license-prohibited", codes)

    def test_license_evidence_must_be_local_and_provenance_digest_must_verify(self):
        entry = self._entry(kind="runtime")
        del entry["license_evidence"]["path"]
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "license-evidence-invalid",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

        entry = self._entry(kind="runtime")
        entry["provenance"]["snapshots"]["artifact.bin"]["sha256"] = "0" * 64
        result = certify(self._write_manifest([entry]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "provenance-incomplete",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

    def test_prohibited_linked_license_fails(self):
        result = certify(self._write_manifest([self._entry(license_spdx="GPL-3.0-only")]))
        self.assertFalse(result["certified"])
        self.assertIn(
            "license-prohibited",
            {item["code"] for item in result["entries"][0]["findings"]},
        )

    def test_build_only_copyleft_is_warning_unless_strict(self):
        manifest = self._write_manifest([self._entry(kind="build-only", license_spdx="GPL-3.0-only")])
        report = certify(manifest)
        self.assertTrue(report["certified"])
        self.assertEqual(report["summary"]["warnings"], 1)
        strict_report = certify(manifest, strict=True)
        self.assertFalse(strict_report["certified"])
        self.assertEqual(strict_report["summary"]["errors"], 1)

    def test_cli_json_is_machine_readable_and_returns_failure(self):
        entry = self._entry(kind="runtime")
        del entry["provenance"]
        manifest = self._write_manifest([entry])
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(manifest), "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["certified"])
        self.assertEqual(payload["summary"]["errors"], 1)


if __name__ == "__main__":
    unittest.main()
