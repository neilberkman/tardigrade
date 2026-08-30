#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed certification of Tardigrade release inputs.

The manifest is an evidence ledger, not a license scanner.  Every entry must
declare its license and identify the evidence used to establish that
declaration.  The checker deliberately does not infer a license from file
contents, filenames, package metadata, or notice text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


SCHEMA_VERSION = 2
KINDS = frozenset({"build-only", "runtime", "linked", "distributed"})
EVIDENCE_TYPES = frozenset(
    {
        "spdx-header",
        "license-file",
        "upstream-declaration",
        "package-metadata",
        "linker-manifest",
    }
)
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
POLICY_FIELDS = frozenset({"schema_version", "name", "build_only_copyleft", "licenses"})
MANIFEST_FIELDS = frozenset({"schema_version", "policy", "artifacts", "source_release"})
SOURCE_RELEASE_FIELDS = frozenset(
    {
        "name",
        "include_paths",
        "exclude_globs",
        "require_tracked_completeness",
        "tracked_exclude_globs",
        "file_digests",
        "license_status",
        "license_spdx",
        "license_evidence",
        "provenance",
        "notes",
    }
)
SOURCE_PROVENANCE_FIELDS = frozenset({"source", "revision"})
ENTRY_FIELDS = frozenset(
    {
        "id",
        "kind",
        "path",
        "path_glob",
        "file_digests",
        "sha256",
        "license_status",
        "license_spdx",
        "license_evidence",
        "provenance",
        "link_manifest",
        "notes",
    }
)
EVIDENCE_FIELDS = frozenset({"type", "source", "basis", "path", "sha256"})
PROVENANCE_FIELDS = frozenset({"source", "revision", "snapshots"})
SNAPSHOT_FIELDS = frozenset({"path", "sha256", "artifact_sha256"})
LINK_REF_FIELDS = frozenset({"path", "sha256"})
LINK_FILE_FIELDS = frozenset({"schema_version", "inputs", "verification_status", "notes"})
LINK_INPUT_FIELDS = frozenset({"artifact_id", "path", "sha256"})


class CertificationInputError(ValueError):
    """The policy or manifest is malformed and cannot be certified."""


def _relative_path(value: Any, label: str) -> Path:
    relative = Path(_require_string(value, label))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise CertificationInputError(f"{label} must remain under the manifest directory")
    return relative


def _relative_glob(value: Any, label: str) -> str:
    pattern = _require_string(value, label)
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        raise CertificationInputError(f"{label} must remain under the manifest directory")
    return pattern


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CertificationInputError(f"{label} must be an object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CertificationInputError(f"{label} must be a non-empty string")
    return value.strip()


def _reject_unknown(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise CertificationInputError(f"{label} contains unknown field(s): {', '.join(unknown)}")


def _read_json(path: Path, label: str) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificationInputError(f"cannot read {label}: {path}: {exc}") from exc
    return dict(_require_mapping(payload, label))


def _check_sha256(path: Path, expected: Any, label: str) -> str | None:
    if expected is None:
        return None
    digest = _require_string(expected, f"{label}.sha256")
    if not HEX64_RE.fullmatch(digest):
        raise CertificationInputError(f"{label}.sha256 must be 64 hexadecimal characters")
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CertificationInputError(f"cannot read {label} for digest: {path}: {exc}") from exc
    if actual.lower() != digest.lower():
        return f"{label} sha256 does not match ({actual})"
    return None


def _resolve_file(root: Path, value: Any, label: str) -> Path:
    relative = _require_string(value, label)
    candidate = (root / relative).resolve() if not Path(relative).is_absolute() else Path(relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise CertificationInputError(f"{label} escapes manifest directory: {relative}") from exc
    if not candidate.is_file():
        raise CertificationInputError(f"{label} is not a file: {relative}")
    return candidate


def _validate_policy(policy: Mapping[str, Any]) -> None:
    _reject_unknown(policy, POLICY_FIELDS, "policy")
    version = policy.get("schema_version")
    if version != SCHEMA_VERSION:
        raise CertificationInputError(f"policy schema_version must be {SCHEMA_VERSION}")
    licenses = _require_mapping(policy.get("licenses"), "policy.licenses")
    if not licenses:
        raise CertificationInputError("policy.licenses must not be empty")
    for spdx, rule in licenses.items():
        _require_string(spdx, "policy license identifier")
        rule_obj = _require_mapping(rule, f"policy.licenses[{spdx!r}]")
        _reject_unknown(rule_obj, frozenset({"decision", "class", "notes"}), f"policy.licenses[{spdx!r}]")
        decision = _require_string(rule_obj.get("decision"), f"policy.licenses[{spdx!r}].decision")
        if decision not in {"allow", "prohibit"}:
            raise CertificationInputError(f"unsupported license decision: {decision}")
        license_class = _require_string(rule_obj.get("class"), f"policy.licenses[{spdx!r}].class")
        if not license_class:
            raise CertificationInputError(f"missing class for policy license {spdx}")
    mode = policy.get("build_only_copyleft", "fail")
    if mode not in {"report", "fail"}:
        raise CertificationInputError("policy.build_only_copyleft must be 'report' or 'fail'")


def _validate_provenance(value: Any, label: str) -> List[str]:
    errors: List[str] = []
    if isinstance(value, Mapping):
        _reject_unknown(value, PROVENANCE_FIELDS, label)
    try:
        provenance = _require_mapping(value, label)
        _require_string(provenance.get("source"), f"{label}.source")
        _require_string(provenance.get("revision"), f"{label}.revision")
        snapshots = _require_mapping(provenance.get("snapshots"), f"{label}.snapshots")
        if not snapshots:
            errors.append(f"{label}.snapshots must not be empty")
        for name, snapshot in snapshots.items():
            snapshot_obj = _require_mapping(snapshot, f"{label}.snapshots[{name!r}]")
            _reject_unknown(snapshot_obj, SNAPSHOT_FIELDS, f"{label}.snapshots[{name!r}]")
            _require_string(snapshot_obj.get("path"), f"{label}.snapshots[{name!r}].path")
            digest = _require_string(
                snapshot_obj.get("sha256"), f"{label}.snapshots[{name!r}].sha256"
            )
            artifact_digest = _require_string(
                snapshot_obj.get("artifact_sha256"),
                f"{label}.snapshots[{name!r}].artifact_sha256",
            )
            if not HEX64_RE.fullmatch(digest):
                errors.append(f"{label}.snapshots[{name!r}].sha256 must be 64 hexadecimal characters")
            if not HEX64_RE.fullmatch(artifact_digest):
                errors.append(
                    f"{label}.snapshots[{name!r}].artifact_sha256 must be 64 hexadecimal characters"
                )
    except CertificationInputError as exc:
        errors.append(str(exc))
    return errors


def _validate_evidence(value: Any, label: str) -> List[str]:
    errors: List[str] = []
    if isinstance(value, Mapping):
        _reject_unknown(value, EVIDENCE_FIELDS, label)
    try:
        evidence = _require_mapping(value, label)
        evidence_type = _require_string(evidence.get("type"), f"{label}.type")
        if evidence_type not in EVIDENCE_TYPES:
            errors.append(f"unsupported license evidence type: {evidence_type}")
        _require_string(evidence.get("source"), f"{label}.source")
        _require_string(evidence.get("basis"), f"{label}.basis")
        _require_string(evidence.get("path"), f"{label}.path")
        digest = _require_string(evidence.get("sha256"), f"{label}.sha256")
        if not HEX64_RE.fullmatch(digest):
            errors.append(f"{label}.sha256 must be 64 hexadecimal characters")
    except CertificationInputError as exc:
        errors.append(str(exc))
    return errors


def _verify_evidence(value: Any, root: Path, label: str) -> List[str]:
    """Verify the local evidence file named by an otherwise valid declaration."""
    if not isinstance(value, Mapping):
        return []
    try:
        evidence_path = _resolve_file(root, value.get("path"), f"{label}.path")
        digest_error = _check_sha256(evidence_path, value.get("sha256"), label)
        return [digest_error] if digest_error else []
    except CertificationInputError as exc:
        return [str(exc)]


def _verify_provenance(
    value: Any,
    root: Path,
    label: str,
    paths: Sequence[Path],
    expected_digests: Mapping[str, str],
) -> List[str]:
    """Verify local source snapshots and their cryptographic tie to outputs."""
    if not isinstance(value, Mapping):
        return []
    snapshots = value.get("snapshots")
    if not isinstance(snapshots, Mapping):
        return []
    expected_names = {str(path.relative_to(root)) for path in paths}
    snapshot_names = {str(name) for name in snapshots}
    errors: List[str] = []
    for name in sorted(expected_names - snapshot_names):
        errors.append(f"{label}.snapshots lacks {name}")
    for name in sorted(snapshot_names - expected_names):
        errors.append(f"{label}.snapshots contains unmatched path {name}")
    for name in sorted(expected_names & snapshot_names):
        snapshot_obj = snapshots[name]
        if not isinstance(snapshot_obj, Mapping):
            continue
        try:
            snapshot_path = _resolve_file(
                root, snapshot_obj.get("path"), f"{label}.snapshots[{name!r}].path"
            )
            digest_error = _check_sha256(
                snapshot_path,
                snapshot_obj.get("sha256"),
                f"{label}.snapshots[{name!r}]",
            )
            if digest_error:
                errors.append(digest_error)
            artifact_digest = snapshot_obj.get("artifact_sha256")
            expected_artifact_digest = expected_digests.get(name)
            if expected_artifact_digest is None:
                errors.append(f"{label}.snapshots[{name!r}] has no verified artifact digest to bind")
            elif artifact_digest != expected_artifact_digest:
                errors.append(
                    f"{label}.snapshots[{name!r}].artifact_sha256 does not match {name}"
                )
        except CertificationInputError as exc:
            errors.append(str(exc))
    return errors


def _matches_source_exclusion(relative: Path, patterns: Sequence[str]) -> bool:
    """Return whether a repository-relative path matches an explicit exclusion."""
    value = relative.as_posix()
    for pattern in patterns:
        if relative.match(pattern):
            return True
        # ``Path.match('directory/**')`` does not match descendants more than
        # one level below ``directory`` on every supported Python version.
        # Treat a trailing recursive wildcard as matching the named directory
        # and everything beneath it, while retaining Path.match semantics for
        # the directory portion (including ``**/__pycache__``).
        if pattern.endswith("/**"):
            parent_pattern = pattern[:-3].rstrip("/")
            for parent in (relative.parent, *relative.parents):
                if parent == Path("."):
                    continue
                if parent.match(parent_pattern):
                    return True
                if parent_pattern.startswith("**/") and parent.match(parent_pattern[3:]):
                    return True
        # pathlib treats ``**/`` as requiring at least one directory on some
        # Python versions.  Also test the suffix so a rule such as
        # ``**/*.elf`` consistently excludes a root-level ELF.
        if pattern.startswith("**/") and relative.match(pattern[3:]):
            return True
        if value == pattern.rstrip("/"):
            return True
    return False


def _source_release_paths(
    value: Mapping[str, Any], root: Path, label: str
) -> tuple[List[Path], List[Path], List[str]]:
    """Expand an explicit source-package boundary without following symlinks."""
    include_values = value.get("include_paths")
    if not isinstance(include_values, list) or not include_values:
        raise CertificationInputError(f"{label}.include_paths must be a non-empty array")
    exclude_values = value.get("exclude_globs", [])
    if not isinstance(exclude_values, list):
        raise CertificationInputError(f"{label}.exclude_globs must be an array")
    exclude_globs = [
        _relative_glob(item, f"{label}.exclude_globs[{index}]")
        for index, item in enumerate(exclude_values)
    ]

    included: Dict[str, Path] = {}
    excluded: Dict[str, Path] = {}
    root_resolved = root.resolve()
    for index, item in enumerate(include_values):
        relative = _relative_path(item, f"{label}.include_paths[{index}]")
        candidate = root / relative
        if candidate.is_symlink():
            raise CertificationInputError(
                f"{label}.include_paths[{index}] must not be a symbolic link: {relative}"
            )
        if candidate.is_file():
            candidates = [candidate]
        elif candidate.is_dir():
            candidates = sorted(
                (path for path in candidate.rglob("*") if path.is_file() or path.is_symlink()),
                key=lambda path: path.as_posix(),
            )
        else:
            raise CertificationInputError(
                f"{label}.include_paths[{index}] does not exist: {relative}"
            )
        for path in candidates:
            if path.is_symlink():
                raise CertificationInputError(
                    f"{label} does not permit symbolic links: {path.relative_to(root)}"
                )
            resolved = path.resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError as exc:
                raise CertificationInputError(
                    f"{label} source path escapes manifest directory: {path}"
                ) from exc
            name = resolved.relative_to(root_resolved).as_posix()
            if _matches_source_exclusion(Path(name), exclude_globs):
                excluded[name] = resolved
            else:
                included[name] = resolved
    if not included:
        raise CertificationInputError(f"{label} includes no source files")
    return (
        [included[name] for name in sorted(included)],
        [excluded[name] for name in sorted(excluded)],
        exclude_globs,
    )


def _validate_source_provenance(value: Any, label: str) -> List[str]:
    errors: List[str] = []
    if isinstance(value, Mapping):
        _reject_unknown(value, SOURCE_PROVENANCE_FIELDS, label)
    try:
        provenance = _require_mapping(value, label)
        _require_string(provenance.get("source"), f"{label}.source")
        _require_string(provenance.get("revision"), f"{label}.revision")
    except CertificationInputError as exc:
        errors.append(str(exc))
    return errors


def _git_tracked_files(root: Path) -> List[Path]:
    """Return tracked paths, failing if repository classification is unavailable."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CertificationInputError(
            "source_release requires Git tracked-file completeness, but git ls-files failed"
        ) from exc
    paths: List[Path] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CertificationInputError(
                "git tracked path is not valid UTF-8"
            ) from exc
        relative = _relative_path(value, "git tracked path")
        paths.append(relative)
    return sorted(paths, key=lambda item: item.as_posix())


def _certify_source_release(
    raw: Any,
    root: Path,
    license_rules: Mapping[str, Any],
) -> Dict[str, Any]:
    """Certify a complete, explicitly bounded source-only package."""
    label = "manifest.source_release"
    value = _require_mapping(raw, label)
    _reject_unknown(value, SOURCE_RELEASE_FIELDS, label)
    name = _require_string(value.get("name"), f"{label}.name")
    paths, excluded_paths, exclude_globs = _source_release_paths(value, root, label)

    findings: List[Dict[str, str]] = []
    require_tracked = value.get("require_tracked_completeness", False)
    if not isinstance(require_tracked, bool):
        raise CertificationInputError(
            f"{label}.require_tracked_completeness must be boolean"
        )
    raw_tracked_excludes = value.get("tracked_exclude_globs", [])
    if not isinstance(raw_tracked_excludes, list):
        raise CertificationInputError(f"{label}.tracked_exclude_globs must be an array")
    tracked_exclude_globs = [
        _relative_glob(item, f"{label}.tracked_exclude_globs[{index}]")
        for index, item in enumerate(raw_tracked_excludes)
    ]
    tracked_excluded: List[str] = []
    if require_tracked:
        included_names = {path.relative_to(root).as_posix() for path in paths}
        tracked_paths = _git_tracked_files(root)
        tracked_names = {path.as_posix() for path in tracked_paths}
        for included_name in sorted(included_names - tracked_names):
            findings.append(
                _finding(
                    "source-file-untracked",
                    f"included source path is not Git-tracked: {included_name}",
                    "error",
                )
            )
        for tracked_path in tracked_paths:
            tracked_name = tracked_path.as_posix()
            if tracked_name in included_names:
                continue
            if _matches_source_exclusion(tracked_path, tracked_exclude_globs):
                tracked_excluded.append(tracked_name)
                continue
            findings.append(
                _finding(
                    "tracked-file-outside-source-boundary",
                    f"tracked path is neither certified nor explicitly excluded: {tracked_name}",
                    "error",
                )
            )
    raw_digests = value.get("file_digests")
    if not isinstance(raw_digests, Mapping):
        expected_digests: Dict[str, str] = {}
        findings.append(
            _finding(
                "source-inventory-missing",
                "source_release.file_digests must cover every included source file",
                "error",
            )
        )
    else:
        expected_digests = {str(key): item for key, item in raw_digests.items()}
    matched_names = {path.relative_to(root).as_posix() for path in paths}
    for missing in sorted(matched_names - set(expected_digests)):
        findings.append(
            _finding(
                "source-inventory-missing",
                f"source_release.file_digests lacks {missing}",
                "error",
            )
        )
    for extra in sorted(set(expected_digests) - matched_names):
        findings.append(
            _finding(
                "source-inventory-extra",
                f"source_release.file_digests contains excluded or unknown path {extra}",
                "error",
            )
        )
    for path in paths:
        relative = path.relative_to(root).as_posix()
        expected = expected_digests.get(relative)
        if expected is None:
            continue
        if not isinstance(expected, str) or not HEX64_RE.fullmatch(expected):
            findings.append(
                _finding(
                    "source-digest-invalid",
                    f"source_release.file_digests[{relative!r}] must be 64 hexadecimal characters",
                    "error",
                )
            )
            continue
        digest_error = _check_sha256(path, expected, f"{label}.file_digests[{relative!r}]")
        if digest_error:
            findings.append(_finding("source-digest-mismatch", digest_error, "error"))

    license_status = value.get("license_status")
    license_spdx = value.get("license_spdx")
    license_rule = None
    if license_status != "known" or not isinstance(license_spdx, str) or not license_spdx.strip():
        findings.append(
            _finding(
                "license-unresolved",
                "source release license must be explicitly declared with license_status=known",
                "error",
            )
        )
    else:
        license_spdx = license_spdx.strip()
        license_rule = license_rules.get(license_spdx)
        if license_rule is None:
            findings.append(
                _finding(
                    "license-not-in-policy",
                    f"license {license_spdx!r} has no rule in the selected policy",
                    "error",
                )
            )
        elif license_rule.get("decision") != "allow":
            findings.append(
                _finding(
                    "license-prohibited",
                    f"license {license_spdx!r} is prohibited by policy",
                    "error",
                )
            )
    findings.extend(
        _finding("license-evidence-invalid", message, "error")
        for message in _validate_evidence(value.get("license_evidence"), f"{label}.license_evidence")
    )
    findings.extend(
        _finding("license-evidence-invalid", message, "error")
        for message in _verify_evidence(
            value.get("license_evidence"), root, f"{label}.license_evidence"
        )
    )
    findings.extend(
        _finding("provenance-incomplete", message, "error")
        for message in _validate_source_provenance(
            value.get("provenance"), f"{label}.provenance"
        )
    )
    return {
        "name": name,
        "license": license_spdx if isinstance(license_spdx, str) else None,
        "status": "fail" if any(item["severity"] == "error" for item in findings) else "pass",
        "included_files": [path.relative_to(root).as_posix() for path in paths],
        "excluded_files": [path.relative_to(root).as_posix() for path in excluded_paths],
        "exclude_globs": exclude_globs,
        "tracked_excluded_files": tracked_excluded,
        "tracked_exclude_globs": tracked_exclude_globs,
        "tracked_completeness_enforced": require_tracked,
        "findings": findings,
    }


def refresh_source_inventory(manifest_path: Path) -> int:
    """Rewrite only the deterministic source-release digest inventory."""
    manifest_path = manifest_path.resolve()
    manifest = _read_json(manifest_path, "manifest")
    _reject_unknown(manifest, MANIFEST_FIELDS, "manifest")
    raw = _require_mapping(manifest.get("source_release"), "manifest.source_release")
    _reject_unknown(raw, SOURCE_RELEASE_FIELDS, "manifest.source_release")
    paths, _, _ = _source_release_paths(raw, manifest_path.parent, "manifest.source_release")
    source_release = dict(raw)
    source_release["file_digests"] = {
        path.relative_to(manifest_path.parent).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    manifest["source_release"] = source_release
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(paths)


def _validate_link_file(
    path: Path, root: Path, label: str
) -> tuple[List[str], List[Dict[str, str]]]:
    """Validate and return the parsed, explicit list of link inputs."""
    errors: List[str] = []
    inputs_out: List[Dict[str, str]] = []
    payload = _read_json(path, label)
    _reject_unknown(payload, LINK_FILE_FIELDS, label)
    try:
        if payload.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"{label}.schema_version must be {SCHEMA_VERSION}")
        inputs = payload.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            errors.append(f"{label}.inputs must be a non-empty array")
        else:
            seen_inputs: set[str] = set()
            for index, item in enumerate(inputs):
                item_obj = _require_mapping(item, f"{label}.inputs[{index}]")
                _reject_unknown(item_obj, LINK_INPUT_FIELDS, f"{label}.inputs[{index}]")
                artifact_id = _require_string(
                    item_obj.get("artifact_id"), f"{label}.inputs[{index}].artifact_id"
                )
                value = _require_string(item_obj.get("path"), f"{label}.inputs[{index}].path")
                digest = _require_string(
                    item_obj.get("sha256"), f"{label}.inputs[{index}].sha256"
                )
                if not HEX64_RE.fullmatch(digest):
                    errors.append(f"{label}.inputs[{index}].sha256 must be 64 hexadecimal characters")
                input_key = value
                if input_key in seen_inputs:
                    errors.append(f"{label}.inputs contains duplicate path {value}")
                seen_inputs.add(input_key)
                try:
                    _resolve_file(root, value, f"{label}.inputs[{index}]")
                    digest_error = _check_sha256(
                        _resolve_file(root, value, f"{label}.inputs[{index}].path"),
                        digest,
                        f"{label}.inputs[{index}]",
                    )
                    if digest_error:
                        errors.append(digest_error)
                except CertificationInputError as exc:
                    errors.append(str(exc))
                inputs_out.append(
                    {"artifact_id": artifact_id, "path": value, "sha256": digest}
                )
        verification = payload.get("verification_status")
        if verification != "verified":
            errors.append(f"{label}.verification_status must be 'verified'")
    except CertificationInputError as exc:
        errors.append(str(exc))
    return errors, inputs_out


def _expand_entry_paths(
    entry_obj: Mapping[str, Any], root: Path, label: str
) -> tuple[List[Path], str, Dict[str, str], List[Dict[str, str]]]:
    """Return deterministic files, display path, expected digests, and digest findings."""
    has_path = "path" in entry_obj
    has_glob = "path_glob" in entry_obj
    if has_path == has_glob:
        raise CertificationInputError(f"{label} must contain exactly one of path or path_glob")
    if has_path:
        path = _resolve_file(root, entry_obj.get("path"), f"{label}.path")
        expected = entry_obj.get("sha256")
        if not isinstance(expected, str) or not expected.strip():
            digest_findings = [_finding("artifact-digest-missing", "path.sha256 is required", "error")]
            expected_map: Dict[str, str] = {}
        else:
            expected_map = {str(path.relative_to(root)): expected}
            digest_findings = []
        return [path], str(path.relative_to(root)), expected_map, digest_findings

    pattern = _require_string(entry_obj.get("path_glob"), f"{label}.path_glob")
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        raise CertificationInputError(f"{label}.path_glob must remain under the manifest directory")
    matches = sorted(
        (candidate.resolve() for candidate in root.glob(pattern) if candidate.is_file()),
        key=lambda candidate: str(candidate.relative_to(root)),
    )
    if not matches:
        raise CertificationInputError(f"{label}.path_glob matched no files: {pattern}")
    for candidate in matches:
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise CertificationInputError(f"{label}.path_glob matched a file outside the manifest directory") from exc
    raw_digests = entry_obj.get("file_digests")
    if raw_digests is None:
        return matches, pattern, {}, [
            _finding(
                "artifact-digest-missing",
                f"file_digests must cover all {len(matches)} files matched by {pattern!r}",
                "error",
            )
        ]
    digest_map_obj = _require_mapping(raw_digests, f"{label}.file_digests")
    expected_map = {str(key): value for key, value in digest_map_obj.items()}
    matched_names = {str(candidate.relative_to(root)) for candidate in matches}
    digest_findings: List[Dict[str, str]] = []
    for name in sorted(matched_names - set(expected_map)):
        digest_findings.append(_finding("artifact-digest-missing", f"file_digests lacks {name}", "error"))
    for name in sorted(set(expected_map) - matched_names):
        digest_findings.append(_finding("artifact-digest-extra", f"file_digests contains unmatched path {name}", "error"))
    return matches, pattern, expected_map, digest_findings


def _finding(code: str, message: str, severity: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def certify(manifest_path: Path, policy_path: Path | None = None, *, strict: bool = False) -> Dict[str, Any]:
    """Certify a manifest and return a stable, JSON-serializable result."""

    manifest_path = manifest_path.resolve()
    if not manifest_path.is_file():
        raise CertificationInputError(f"manifest is not a file: {manifest_path}")
    manifest = _read_json(manifest_path, "manifest")
    _reject_unknown(manifest, MANIFEST_FIELDS, "manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise CertificationInputError(f"manifest schema_version must be {SCHEMA_VERSION}")

    selected_policy = policy_path
    if selected_policy is None:
        policy_ref = _require_string(manifest.get("policy"), "manifest.policy")
        selected_policy = (manifest_path.parent / policy_ref).resolve()
        try:
            selected_policy.relative_to(manifest_path.parent)
        except ValueError as exc:
            raise CertificationInputError(
                "manifest.policy must remain under the manifest directory"
            ) from exc
    else:
        selected_policy = selected_policy.resolve()
    policy = _read_json(selected_policy, "policy")
    _validate_policy(policy)
    license_rules = policy["licenses"]

    raw_source_release = manifest.get("source_release")
    source_release = (
        _certify_source_release(raw_source_release, manifest_path.parent, license_rules)
        if raw_source_release is not None
        else None
    )

    raw_entries = manifest.get("artifacts", [])
    if not isinstance(raw_entries, list):
        raise CertificationInputError("manifest.artifacts must be an array")
    if not raw_entries and source_release is None:
        raise CertificationInputError(
            "manifest must contain source_release or at least one artifact"
        )

    entries: List[Dict[str, Any]] = []
    link_records: List[tuple[int, List[Dict[str, str]]]] = []
    seen_ids: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        label = f"manifest.artifacts[{index}]"
        entry_obj = _require_mapping(raw_entry, label)
        _reject_unknown(entry_obj, ENTRY_FIELDS, label)
        entry_id = _require_string(entry_obj.get("id"), f"{label}.id")
        if entry_id in seen_ids:
            raise CertificationInputError(f"duplicate artifact id: {entry_id}")
        seen_ids.add(entry_id)
        kind = _require_string(entry_obj.get("kind"), f"{label}.kind")
        if kind not in KINDS:
            raise CertificationInputError(f"{label}.kind must be one of {sorted(KINDS)}")

        findings: List[Dict[str, str]] = []
        paths, display_path, expected_digests, digest_findings = _expand_entry_paths(
            entry_obj, manifest_path.parent, label
        )
        findings.extend(digest_findings)
        for path in paths:
            relative_path = str(path.relative_to(manifest_path.parent))
            expected_digest = expected_digests.get(relative_path)
            if expected_digest is None:
                continue
            path_hash_error = _check_sha256(
                path, expected_digest, f"{label}.file_digests[{relative_path!r}]"
            )
            if path_hash_error:
                findings.append(_finding("artifact-digest-mismatch", path_hash_error, "error"))

        license_status = entry_obj.get("license_status")
        license_spdx = entry_obj.get("license_spdx")
        if license_status != "known" or not isinstance(license_spdx, str) or not license_spdx.strip():
            findings.append(
                _finding(
                    "license-unresolved",
                    "license must be explicitly declared with license_status=known",
                    "error",
                )
            )
            license_rule = None
        else:
            license_spdx = license_spdx.strip()
            license_rule = license_rules.get(license_spdx)
            if license_rule is None:
                findings.append(
                    _finding(
                        "license-not-in-policy",
                        f"license {license_spdx!r} has no rule in the selected policy",
                        "error",
                    )
                )
        findings.extend(
            _finding("license-evidence-invalid", message, "error")
            for message in _validate_evidence(entry_obj.get("license_evidence"), f"{label}.license_evidence")
        )
        findings.extend(
            _finding("license-evidence-invalid", message, "error")
            for message in _verify_evidence(
                entry_obj.get("license_evidence"),
                manifest_path.parent,
                f"{label}.license_evidence",
            )
        )
        findings.extend(
            _finding("provenance-incomplete", message, "error")
            for message in _validate_provenance(entry_obj.get("provenance"), f"{label}.provenance")
        )
        findings.extend(
            _finding("provenance-incomplete", message, "error")
            for message in _verify_provenance(
                entry_obj.get("provenance"),
                manifest_path.parent,
                f"{label}.provenance",
                paths,
                expected_digests,
            )
        )

        copyleft = bool(
            license_rule
            and license_rule.get("class") in {"copyleft", "copyleft-with-exception"}
        )
        if (
            license_rule is not None
            and license_rule.get("decision") == "prohibit"
            and not (kind == "build-only" and copyleft)
        ):
            findings.append(
                _finding(
                    "license-prohibited",
                    f"license {license_spdx!r} is prohibited by policy",
                    "error",
                )
            )

        link_manifest = entry_obj.get("link_manifest")
        if kind in {"linked", "distributed"}:
            if not isinstance(link_manifest, Mapping):
                findings.append(
                    _finding(
                        "link-manifest-missing",
                        "linked/distributed entries require link_manifest.path and link_manifest.sha256",
                        "error",
                    )
                )
            else:
                _reject_unknown(link_manifest, LINK_REF_FIELDS, f"{label}.link_manifest")
                try:
                    link_path = _resolve_file(
                        manifest_path.parent,
                        link_manifest.get("path"),
                        f"{label}.link_manifest.path",
                    )
                    if not isinstance(link_manifest.get("sha256"), str) or not link_manifest.get("sha256", "").strip():
                        findings.append(
                            _finding(
                                "link-manifest-invalid",
                                "link_manifest.sha256 is required",
                                "error",
                            )
                        )
                    link_digest_error = _check_sha256(
                        link_path,
                        link_manifest.get("sha256"),
                        f"{label}.link_manifest",
                    )
                    if link_digest_error:
                        findings.append(_finding("link-manifest-invalid", link_digest_error, "error"))
                except CertificationInputError as exc:
                    link_path = None
                    findings.append(_finding("link-manifest-invalid", str(exc), "error"))
                if link_path is not None:
                    link_errors, link_inputs = _validate_link_file(
                        link_path,
                        manifest_path.parent,
                        f"{label}.link_manifest",
                    )
                    findings.extend(
                        _finding("link-manifest-invalid", message, "error")
                        for message in link_errors
                    )
                    link_records.append((index, link_inputs))

        if kind == "build-only" and copyleft:
            severity = "error" if strict or policy.get("build_only_copyleft", "fail") == "fail" else "warning"
            findings.append(
                _finding(
                    "build-only-copyleft",
                    f"build-only input declares {license_spdx}; it is not linked or distributed",
                    severity,
                )
            )

        has_error = any(item["severity"] == "error" for item in findings)
        has_warning = any(item["severity"] == "warning" for item in findings)
        entries.append(
            {
                "id": entry_id,
                "kind": kind,
                "path": display_path,
                "matched_files": [
                    str(path.relative_to(manifest_path.parent)) for path in paths
                ],
                "license": license_spdx if isinstance(license_spdx, str) else None,
                "status": "fail" if has_error else ("warning" if has_warning else "pass"),
                "findings": findings,
                "_verified_digests": {
                    str(path.relative_to(manifest_path.parent)): expected_digests.get(
                        str(path.relative_to(manifest_path.parent))
                    )
                    for path in paths
                    if expected_digests.get(str(path.relative_to(manifest_path.parent)))
                    and not any(
                        finding["code"] == "artifact-digest-mismatch"
                        for finding in findings
                    )
                },
            }
        )

    # A link manifest is a dependency claim.  Resolve every claim against a
    # different manifest entry whose digest was actually verified above.
    by_id = {entry["id"]: entry for entry in entries}
    for owner_index, link_inputs in link_records:
        owner = entries[owner_index]
        for link_input in link_inputs:
            target = by_id.get(link_input["artifact_id"])
            if target is None or target is owner or target.get("status") != "pass":
                owner["findings"].append(
                    _finding(
                        "link-input-unresolved",
                        f"link input references separately certified artifact {link_input['artifact_id']!r}",
                        "error",
                    )
                )
                continue
            target_path = link_input["path"]
            verified_digest = target.get("_verified_digests", {}).get(target_path)
            if verified_digest is None or verified_digest.lower() != link_input["sha256"].lower():
                owner["findings"].append(
                    _finding(
                        "link-input-unverified",
                        f"link input {target_path!r} is not covered by a verified digest in {target['id']!r}",
                        "error",
                    )
                )

    for entry in entries:
        entry.pop("_verified_digests", None)
        has_error = any(item["severity"] == "error" for item in entry["findings"])
        has_warning = any(item["severity"] == "warning" for item in entry["findings"])
        entry["status"] = "fail" if has_error else ("warning" if has_warning else "pass")

    source_findings = source_release["findings"] if source_release is not None else []
    errors = sum(item["severity"] == "error" for item in source_findings) + sum(
        sum(item["severity"] == "error" for item in entry["findings"])
        for entry in entries
    )
    warnings = sum(item["severity"] == "warning" for item in source_findings) + sum(
        sum(item["severity"] == "warning" for item in entry["findings"])
        for entry in entries
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest": str(manifest_path),
        "policy": str(selected_policy),
        "strict": strict,
        "certified": errors == 0,
        "summary": {
            "entries": len(entries) + (1 if source_release is not None else 0),
            "errors": errors,
            "warnings": warnings,
        },
        "source_release": source_release,
        "entries": entries,
    }


def render_human(result: Mapping[str, Any]) -> str:
    summary = result["summary"]
    status = "PASS" if result["certified"] else "FAIL"
    lines = [
        f"License certification: {status}",
        f"Entries: {summary['entries']}  Errors: {summary['errors']}  Warnings: {summary['warnings']}",
    ]
    source_release = result.get("source_release")
    if isinstance(source_release, Mapping):
        lines.append(
            f"- {source_release['name']} [source-release] {source_release['status']} "
            f"({len(source_release['included_files'])} files included; "
            f"{len(source_release['excluded_files'])} package files excluded; "
            f"{len(source_release['tracked_excluded_files'])} tracked paths outside package)"
        )
        for finding in source_release["findings"]:
            lines.append(
                f"  {finding['severity'].upper()} {finding['code']}: {finding['message']}"
            )
    for entry in result["entries"]:
        lines.append(f"- {entry['id']} [{entry['kind']}] {entry['status']}")
        for finding in entry["findings"]:
            lines.append(f"  {finding['severity'].upper()} {finding['code']}: {finding['message']}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="machine-readable release input manifest")
    parser.add_argument("--policy", type=Path, help="override the policy path in the manifest")
    parser.add_argument("--strict", action="store_true", help="fail on build-only copyleft inputs")
    parser.add_argument(
        "--refresh-source-inventory",
        action="store_true",
        help="rewrite source_release.file_digests from the declared source boundary",
    )
    parser.add_argument("--format", choices=("human", "json"), default="human")
    args = parser.parse_args(argv)
    try:
        if args.refresh_source_inventory:
            count = refresh_source_inventory(args.manifest)
            if args.format == "json":
                print(json.dumps({"refreshed": True, "files": count}, sort_keys=True))
            else:
                print(f"Refreshed source release inventory: {count} files")
            return 0
        result = certify(args.manifest, args.policy, strict=args.strict)
    except CertificationInputError as exc:
        if args.format == "json":
            print(json.dumps({"certified": False, "input_error": str(exc)}, sort_keys=True))
        else:
            print(f"License certification: INPUT ERROR\n{exc}")
        return 2
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_human(result))
    return 0 if result["certified"] else 1


if __name__ == "__main__":
    sys.exit(main())
