from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from audit_bootloader import _report_provenance  # noqa: E402
from profile_loader import ProfileError, load_profile  # noqa: E402
from run_scenario import _consistent_target_source  # noqa: E402


_REVISION = "4f8c0d3e2a1b9876543210fedcba0123456789ab"


def _write_profile(path: Path, target_source: str) -> Path:
    path.write_text(
        """schema_version: 1
name: provenance-test
platform: platforms/test.repl
bootloader:
  elf: target/test.elf
  entry: 0x08000000
memory:
  sram: {{start: 0x20000000, end: 0x20001000}}
  slots:
    exec: {{base: 0x08000000, size: 0x1000}}
    staging: {{base: 0x08001000, size: 0x1000}}
success_criteria:
  vtor_in_slot: exec
initial_states:
  - name: baseline
target_source:
{target_source}
""".format(target_source=target_source),
        encoding="utf-8",
    )
    return path


def test_target_source_is_validated_and_canonicalized(tmp_path: Path) -> None:
    profile_path = _write_profile(
        tmp_path / "profile.yaml",
        "  name: example-target\n  repository: https://example.invalid/target\n  revision: {}".format(
            _REVISION
        ),
    )
    profile = load_profile(profile_path, strict=True)

    assert profile.target_source.to_dict() == {
        "revision": _REVISION,
        "name": "example-target",
        "repository": "https://example.invalid/target",
    }
    resolved = profile.resolve_initial_state(profile.initial_states[0])
    assert resolved.target_source is profile.target_source
    assert resolved.target_source.to_dict() == profile.target_source.to_dict()


@pytest.mark.parametrize(
    "target_source, expected",
    [
        ("  commit: {}\n".format(_REVISION), "revision"),
        ("  revision: a-source-revision-1\n", "revision"),
    ],
)
def test_target_source_commit_alias_is_canonicalized(
    tmp_path: Path, target_source: str, expected: str
) -> None:
    profile = load_profile(_write_profile(tmp_path / "profile.yaml", target_source))
    encoded = profile.target_source.to_dict()
    assert list(encoded) == [expected]
    assert encoded[expected] == (_REVISION if "commit" in target_source else "a-source-revision-1")


@pytest.mark.parametrize(
    "target_source",
    [
        "  revision: ''\n",
        "  revision: 'bad value'\n",
        "  commit: deadbeef\n",
        "  revision: {}\n  commit: {}\n".format(_REVISION, _REVISION),
        "  unknown: value\n  revision: {}\n".format(_REVISION),
    ],
)
def test_target_source_rejects_ambiguous_or_unsafe_values(
    tmp_path: Path, target_source: str
) -> None:
    with pytest.raises(ProfileError):
        load_profile(_write_profile(tmp_path / "profile.yaml", target_source))


def test_report_provenance_uses_declared_target_source_without_path_inference(tmp_path: Path) -> None:
    profile = load_profile(
        _write_profile(
            tmp_path / "profile.yaml",
            "  revision: {}\n".format(_REVISION),
        )
    )
    with mock.patch(
        "audit_bootloader.git_metadata",
        return_value={"commit": "audit-commit"},
    ):
        provenance = _report_provenance(profile, tmp_path / "not-a-repository")

    assert provenance == {
        "git": {"commit": "audit-commit"},
        "target_source": {"revision": _REVISION},
    }
    assert json.dumps(provenance, sort_keys=True)


def test_report_provenance_ignores_dynamic_unconfigured_profile_attributes(tmp_path: Path) -> None:
    profile = mock.Mock()
    with mock.patch(
        "audit_bootloader.git_metadata",
        return_value={"commit": "audit-commit"},
    ):
        provenance = _report_provenance(profile, tmp_path / "not-a-repository")

    assert provenance == {"git": {"commit": "audit-commit"}}


def test_report_provenance_rejects_explicit_malformed_target_source(tmp_path: Path) -> None:
    profile = SimpleNamespace(target_source={"revision": object()})
    with mock.patch(
        "audit_bootloader.git_metadata",
        return_value={"commit": "audit-commit"},
    ), pytest.raises(TypeError, match="target_source.revision"):
        _report_provenance(profile, tmp_path / "not-a-repository")


def test_scenario_wrapper_exposes_only_consistent_child_target_source() -> None:
    source = {"revision": _REVISION}
    results = {
        "steps": {
            "one": {"report": {"target_source": source}},
            "two": {"report": {"target_source": dict(source)}},
        }
    }
    assert _consistent_target_source(results) == source

    results["steps"]["two"]["report"]["target_source"] = {
        "revision": "different-source"
    }
    assert _consistent_target_source(results) is None


def test_scenario_wrapper_rejects_audit_child_without_target_source() -> None:
    results = {
        "steps": {
            "one": {"kind": "audit", "report": {"target_source": {"revision": _REVISION}}},
            "two": {"kind": "replay", "report": {"verdict": "PASS"}},
        }
    }

    assert _consistent_target_source(results) is None


def test_scenario_wrapper_ignores_non_report_assertion_steps() -> None:
    source = {"revision": _REVISION}
    results = {
        "steps": {
            "audit": {"kind": "audit", "report": {"target_source": source}},
            "check": {
                "kind": "assert",
                "assertions": [{"path": "steps.audit.report.verdict", "equals": "PASS"}],
            },
        }
    }

    assert _consistent_target_source(results) == source
