#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the authenticated-equivalence campaign."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.authenticated_equivalence as ae  # noqa: E402
from scripts.authenticated_equivalence import (  # noqa: E402
    CampaignError,
    load_config,
    run_campaign,
)


CONFIG = ROOT / "examples" / "authenticated_equivalence" / "vulnerable.yaml"


def _config(mode: str = "vulnerable") -> dict:
    config = load_config(CONFIG)
    config["mode"] = mode
    return config


def test_vulnerable_and_fixed_harnesses_use_semantic_outcomes() -> None:
    vulnerable = run_campaign(_config("vulnerable"))
    assert vulnerable["status"] == "FINDINGS"
    assert [item["mutation_id"] for item in vulnerable["mutants"]] == ["m0001", "m0002"]
    assert [item["mutation_id"] for item in vulnerable["findings"]] == ["m0001"]
    assert vulnerable["findings"][0]["differing_outcomes"]["size"] == {
        "base": 4,
        "mutant": 8,
    }
    assert vulnerable["findings"][0]["differing_outcomes"]["security_state"] == {
        "base": {"accepted": True, "payload_record_count": 1},
        "mutant": {"accepted": True, "payload_record_count": 2},
    }

    fixed = run_campaign(_config("fixed"))
    assert fixed["status"] == "PASS"
    assert fixed["findings"] == []
    assert fixed["mutants"][0]["outcome"]["accepted"] is False
    assert fixed["mutants"][0]["outcome"]["committed"] is False


def test_explicit_v1_compatibility_preserves_schema_and_legacy_limit() -> None:
    config = _config("vulnerable")
    config["schema_version"] = 1
    config["outcomes"] = ["accepted", "committed"]
    report = run_campaign(config)
    assert report["schema_version"] == 1
    assert report["status"] == "PASS"
    assert report["findings"] == []


@pytest.mark.parametrize("invalid_config", ["schema_version: [", "schema_version: 99\n"])
def test_cli_invalid_or_unsupported_config_fails_closed(tmp_path: Path, invalid_config: str) -> None:
    config_path = tmp_path / "invalid.yaml"
    report_path = tmp_path / "report.json"
    config_path.write_text(invalid_config, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "authenticated_equivalence.py"), "--config", str(config_path), "--report", str(report_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == 2
    assert report["status"] == "FAIL_CLOSED"
    assert isinstance(report["error"], str) and report["error"]


def test_v1_rejects_v2_only_cases_and_coverage() -> None:
    config = _config("vulnerable")
    config["schema_version"] = 1
    config["outcomes"] = ["accepted", "committed"]
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [{"id": "new-case", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]}],
    }
    with pytest.raises(CampaignError, match="does not support mutations.cases"):
        run_campaign(config)
    config["mutations"] = {"duplicate_types": [0x20], "reorder_types": [], "max_mutants": 1}
    config["authentication"] = {"boundary_type": 0xA0, "signature_type": 0xA1, "include_boundary": True, "coverage": "signature_before_boundary"}
    with pytest.raises(CampaignError, match="supports only prefix_through_boundary"):
        run_campaign(config)


def test_v2_requires_canonical_semantic_outcomes() -> None:
    config = _config("vulnerable")
    config["schema_version"] = 2
    config["outcomes"] = ["accepted", "committed"]
    with pytest.raises(CampaignError, match="semantic field 'rollback_outcome'"):
        run_campaign(config)


def test_mutations_start_after_later_signature_record() -> None:
    config = _config("vulnerable")
    # The first payload record is between the boundary and a later signature;
    # only the payload after the signature may be duplicated.
    config["input_hex"] = "a00441555448200444415441a1040102030420044d4f5245"
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    assert [record.type for record in records] == [0xA0, 0x20, 0xA1, 0x20]
    assert [record.type for record in mutations[0].records] == [0xA0, 0x20, 0xA1, 0x20, 0x20]
    assert mutations[0].record_index == 3


def test_single_boundary_signature_record_preserves_identity() -> None:
    config = _config("vulnerable")
    config["input_hex"] = "010441555448040401020304200444415441"
    config["authentication"] = {
        "boundary_type": 0x04,
        "signature_type": 0x04,
        "include_boundary": False,
    }
    config["mutations"] = {
        "duplicate_types": [0x20],
        "reorder_types": [],
        "max_mutants": 8,
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    assert mutations[0].record_index == 2
    assert ae._auth_identity(records, config["authentication"]) == ae._auth_identity(
        mutations[0].records, config["authentication"]
    )


def test_canonical_rejection_fails_closed() -> None:
    config = _config("fixed")
    config["input_hex"] = "a00441555448a104010203041003617070200444415441200444415441110102"
    with pytest.raises(CampaignError, match="canonical base harness outcome is not accepted"):
        run_campaign(config)


def test_committed_false_to_true_escalation_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    expected = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": "f16719742870ca30e8b935bd6d323003b3d5c3c0245fb54286122e5727652a9c",
        "signature_bytes_b64": "AQIDBA==",
        "accepted": True,
        "committed": False,
        "version": 2,
        "target": "app",
        "size": 4,
        "installed_payload_digest": "c97c29c7a71b392b437ee03fd17f09bb10b75e879466fc0eb757b2c4a78ac938",
        "rollback_outcome": "none",
        "security_state": {"accepted": True, "payload_record_count": 1},
        "input_sha256": "",
    }
    mutant = dict(expected)
    mutant["committed"] = True
    def fake_harness(_config: dict, path: Path, mutation_id: str, _index: int) -> dict:
        result = expected if mutation_id == "base" else mutant
        return {**result, "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    monkeypatch.setattr(ae, "_run_harness", fake_harness)
    report = run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert report["findings"][0]["differing_outcomes"]["committed"] == {
        "base": False,
        "mutant": True,
    }


def test_report_and_mutation_ids_are_deterministic() -> None:
    first = run_campaign(_config("vulnerable"))
    second = run_campaign(_config("vulnerable"))
    assert first == second


def test_empty_mutation_set_fails_closed() -> None:
    config = _config()
    config["mutations"] = {"duplicate_types": [], "reorder_types": [], "max_mutants": 8}
    with pytest.raises(CampaignError, match="mutation set is empty"):
        run_campaign(config)


@pytest.mark.parametrize("missing", ae.REQUIRED_SEMANTIC_OUTCOME_FIELDS)
def test_each_missing_canonical_semantic_outcome_fails_closed(missing: str) -> None:
    config = _config()
    config["outcomes"] = [
        "accepted",
        "committed",
        *[field for field in ae.REQUIRED_SEMANTIC_OUTCOME_FIELDS if field != missing],
    ]
    with pytest.raises(CampaignError, match="semantic field {!r}".format(missing)):
        run_campaign(config)


def test_security_state_only_divergence_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    base = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": "f16719742870ca30e8b935bd6d323003b3d5c3c0245fb54286122e5727652a9c",
        "signature_bytes_b64": "AQIDBA==",
        "accepted": True,
        "committed": True,
        "version": 2,
        "target": "app",
        "size": 4,
        "installed_payload_digest": "c97c29c7a71b392b437ee03fd17f09bb10b75e879466fc0eb757b2c4a78ac938",
        "rollback_outcome": "none",
        "security_state": {"phase": "committed"},
    }
    mutant = dict(base)
    mutant["security_state"] = {"phase": "committed", "rollback_floor": 0}

    def fake_harness(_config: dict, path: Path, mutation_id: str, _index: int) -> dict:
        result = base if mutation_id == "base" else mutant
        return {**result, "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    monkeypatch.setattr(ae, "_run_harness", fake_harness)
    report = run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert list(report["findings"][0]["differing_outcomes"]) == ["security_state"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("security_state", [], "security_state must be a JSON object"),
        ("size", -1, "size must be a non-negative integer when accepted"),
        (
            "installed_payload_digest",
            "C97C29C7A71B392B437EE03FD17F09BB10B75E879466FC0EB757B2C4A78AC938",
            "installed_payload_digest must be lowercase",
        ),
        ("rollback_outcome", "  ", "rollback_outcome must be a non-empty string"),
        ("version", None, "version must be meaningful when accepted"),
        ("target", "", "target must be meaningful when accepted"),
        ("target", True, "target must be meaningful when accepted"),
    ],
)
def test_harness_semantic_value_contracts_fail_closed(
    field: str, value: object, message: str
) -> None:
    data = bytes.fromhex("a00441555448a104010203041003617070200444415441110102")
    output = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": "f16719742870ca30e8b935bd6d323003b3d5c3c0245fb54286122e5727652a9c",
        "signature_bytes_b64": "AQIDBA==",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "accepted": True,
        "committed": True,
        "version": 2,
        "target": "app",
        "size": 4,
        "installed_payload_digest": "c97c29c7a71b392b437ee03fd17f09bb10b75e879466fc0eb757b2c4a78ac938",
        "rollback_outcome": "none",
        "security_state": {"phase": "committed"},
    }
    output[field] = value
    with pytest.raises(CampaignError, match=message):
        ae._validate_harness_output(
            output,
            outcome_fields=ae.REQUIRED_OUTCOME_FIELDS + ae.REQUIRED_SEMANTIC_OUTCOME_FIELDS,
            expected_authenticated=data[:6],
            expected_signature=data[8:12],
            expected_input=data,
            context="test harness output",
        )


def test_rejected_result_may_omit_install_value_contracts() -> None:
    data = bytes.fromhex("a00441555448a104010203041003617070200444415441110102")
    output = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": "f16719742870ca30e8b935bd6d323003b3d5c3c0245fb54286122e5727652a9c",
        "signature_bytes_b64": "AQIDBA==",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "accepted": False,
        "committed": False,
        "version": None,
        "target": None,
        "size": -1,
        "installed_payload_digest": "not-applicable",
        "rollback_outcome": "rejected",
        "security_state": {"phase": "rejected"},
    }
    ae._validate_harness_output(
        output,
        outcome_fields=ae.REQUIRED_OUTCOME_FIELDS + ae.REQUIRED_SEMANTIC_OUTCOME_FIELDS,
        expected_authenticated=data[:6],
        expected_signature=data[8:12],
        expected_input=data,
        context="rejected harness output",
    )


def test_signature_before_boundary_is_rejected_during_identity_check() -> None:
    config = _config()
    config["authentication"]["boundary_type"] = 0x10
    with pytest.raises(CampaignError, match="signature record must occur at or after"):
        run_campaign(config)


def test_missing_semantic_output_field_fails_closed() -> None:
    config = _config()
    config["harness"] = {
        "command": [sys.executable, "-c", "print('{\"ok\":true}')", "{input}"],
        "timeout_seconds": 5.0,
        "cwd": str(ROOT),
    }
    with pytest.raises(CampaignError, match="missing output field"):
        run_campaign(config)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_constant_from_harness_fails_closed(constant: str) -> None:
    config = _config()
    config["harness"] = {
        "command": [sys.executable, "-c", "print({!r})".format(constant), "{input}"],
        "timeout_seconds": 5.0,
        "cwd": str(ROOT),
    }
    with pytest.raises(CampaignError, match="is not JSON"):
        run_campaign(config)


def test_input_digest_cannot_be_declared_as_outcome() -> None:
    config = _config()
    config["outcomes"] = [*config["outcomes"], "input_sha256"]
    with pytest.raises(CampaignError, match="authentication evidence fields"):
        run_campaign(config)


def test_harness_timeout_fails_closed() -> None:
    config = _config()
    config["harness"] = {
        "command": [sys.executable, "-c", "import time; time.sleep(1)", "{input}"],
        "timeout_seconds": 0.01,
        "cwd": str(ROOT),
    }
    with pytest.raises(CampaignError, match="harness timed out"):
        run_campaign(config)


def test_harness_command_must_receive_mutant_input() -> None:
    config = _config()
    config["harness"]["command"] = [sys.executable, "-c", "print('{}')"]
    with pytest.raises(CampaignError, match=r"include the \{input\} placeholder"):
        run_campaign(config)


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, -math.inf, "5", True])
def test_timeout_must_be_finite_and_positive(timeout: object) -> None:
    config = _config()
    config["harness"]["timeout_seconds"] = timeout
    with pytest.raises(CampaignError, match="finite and positive"):
        run_campaign(config)


@pytest.mark.parametrize("cwd", [None, "", "  ", 123])
def test_cwd_must_be_absent_or_nonempty_string(cwd: object) -> None:
    config = _config()
    config["harness"]["cwd"] = cwd
    with pytest.raises(CampaignError, match="cwd must be absent or a non-empty string"):
        run_campaign(config)


def test_command_nul_is_rejected_as_campaign_error() -> None:
    config = _config()
    config["harness"]["command"] = [sys.executable + "\x00", "{input}"]
    with pytest.raises(CampaignError, match="command must not contain NUL"):
        run_campaign(config)


def test_cwd_nul_is_rejected_as_campaign_error() -> None:
    config = _config()
    config["harness"]["cwd"] = str(ROOT) + "\x00"
    with pytest.raises(CampaignError, match="cwd must not contain NUL"):
        run_campaign(config)


def test_signature_before_boundary_is_rejected() -> None:
    config = _config()
    config["input_hex"] = "a10401020304a004415554481003617070200444415441110102"
    with pytest.raises(CampaignError, match="signature record must occur at or after"):
        run_campaign(config)


def test_committed_without_acceptance_is_rejected() -> None:
    data = bytes.fromhex("a00441555448a104010203041003617070200444415441110102")
    output = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": hashlib.sha256(data[:6]).hexdigest(),
        "signature_bytes_b64": "AQIDBA==",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "accepted": False,
        "committed": True,
    }
    with pytest.raises(CampaignError, match="committed cannot be true"):
        ae._validate_harness_output(
            output,
            outcome_fields=("accepted", "committed"),
            expected_authenticated=data[:6],
            expected_signature=data[8:12],
            expected_input=data,
            context="test harness output",
        )


def test_committed_true_to_false_escalation_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    base = {
        "authenticated_bytes_b64": "oARBVVRI",
        "authenticated_digest": "f16719742870ca30e8b935bd6d323003b3d5c3c0245fb54286122e5727652a9c",
        "signature_bytes_b64": "AQIDBA==",
        "accepted": True,
        "committed": True,
        "version": 2,
        "target": "app",
        "size": 4,
        "installed_payload_digest": "c97c29c7a71b392b437ee03fd17f09bb10b75e879466fc0eb757b2c4a78ac938",
        "rollback_outcome": "none",
        "security_state": {"accepted": True, "payload_record_count": 1},
    }
    mutant = dict(base)
    mutant["committed"] = False

    def fake_harness(_config: dict, path: Path, mutation_id: str, _index: int) -> dict:
        result = base if mutation_id == "base" else mutant
        return {**result, "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    monkeypatch.setattr(ae, "_run_harness", fake_harness)
    report = run_campaign(config)
    assert report["findings"][0]["differing_outcomes"]["committed"] == {
        "base": True,
        "mutant": False,
    }


def test_reorder_includes_non_adjacent_eligible_pair() -> None:
    config = _config()
    config["input_hex"] = "a00441555448a104010203041003617070110102200444415441"
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [0x10, 0x20],
        "max_mutants": 8,
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    assert [(item.record_index, item.second_record_index) for item in mutations] == [(2, 4)]
    assert [item.type for item in mutations[0].records] == [0xA0, 0xA1, 0x20, 0x11, 0x10]


def test_legacy_reorder_skips_identical_pair_before_real_permutation() -> None:
    config = _config()
    config["input_hex"] = "a00441555448a10401020304200441414141200441414141100141110102"
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [0x10, 0x20],
        "max_mutants": 1,
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    assert len(mutations) == 1
    assert mutations[0].operation == "reorder"
    assert [item.type for item in mutations[0].records] == [0xA0, 0xA1, 0x10, 0x20, 0x20, 0x11]


def test_explicit_cases_reject_duplicate_serialized_outputs() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 2,
        "cases": [
            {"id": "first", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]},
            {"id": "second", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]},
        ],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="duplicates another case output"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


def test_legacy_duplicate_deduplicates_identical_source_outputs() -> None:
    config = _config()
    config["input_hex"] = "a00441555448a10401020304200441414141200441414141110102"
    config["mutations"] = {"duplicate_types": [0x20], "reorder_types": [], "max_mutants": 8}
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    assert len(mutations) == 1
    assert mutations[0].mutation_id == "m0001"


def test_report_retains_normalized_config_and_mutant_hashes() -> None:
    config = _config("vulnerable")
    report = run_campaign(config)
    assert "_config_dir" not in report["configuration"]
    assert report["harness_argv"] == config["harness"]["command"]
    assert "tardigrade-auth-equiv-" not in str(report)
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"])
    for mutant_report, mutation in zip(report["mutants"], mutations):
        mutant_data = b"".join(record.encoded for record in mutation.records)
        assert mutant_report["input_sha256"] == hashlib.sha256(mutant_data).hexdigest()
        assert mutant_report["input_size"] == len(mutant_data)


def test_signature_before_boundary_coverage_reconstructs_exact_identity() -> None:
    data = bytes.fromhex("a103010203100141a00441555448200444415441")
    config = _config()
    config["input_hex"] = data.hex()
    config["authentication"] = {
        "boundary_type": 0xA0,
        "signature_type": 0xA1,
        "include_boundary": True,
        "coverage": "signature_before_boundary",
    }
    records = ae.parse_tlv_stream(data, config["grammar"])
    authenticated, signature = ae._auth_identity(records, config["authentication"])
    assert authenticated == data[5:14]
    assert signature == b"\x01\x02\x03"
    mutant = tuple(records + (records[3],))
    assert ae._auth_identity(mutant, config["authentication"]) == (authenticated, signature)


def test_run_campaign_signature_before_boundary_uses_valid_identity_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    data = bytes.fromhex("a103010203100141a00441555448200444415441110102")
    config = _config()
    config["input_hex"] = data.hex()
    config["authentication"] = {
        "boundary_type": 0xA0,
        "signature_type": 0xA1,
        "include_boundary": True,
        "coverage": "signature_before_boundary",
    }
    config["mutations"] = {"duplicate_types": [0x20], "reorder_types": [], "max_mutants": 1}

    def fake_harness(_config: dict, path: Path, _mutation_id: str, _index: int) -> dict:
        supplied = path.read_bytes()
        records = ae.parse_tlv_stream(supplied, config["grammar"])
        authenticated, signature = ae._auth_identity(records, config["authentication"])
        return {
            "input_sha256": hashlib.sha256(supplied).hexdigest(),
            "authenticated_bytes_b64": ae.base64.b64encode(authenticated).decode("ascii"),
            "authenticated_digest": hashlib.sha256(authenticated).hexdigest(),
            "signature_bytes_b64": ae.base64.b64encode(signature).decode("ascii"),
            "accepted": True,
            "committed": True,
            "version": 2,
            "target": "app",
            "size": 4,
            "installed_payload_digest": hashlib.sha256(b"DATA").hexdigest(),
            "rollback_outcome": "none",
            "security_state": {"verified": True},
        }

    monkeypatch.setattr(ae, "_run_harness", fake_harness)
    report = run_campaign(config)
    assert report["status"] == "PASS"
    assert report["schema_version"] == 2
    assert report["authenticated_identity"]["signature_bytes_b64"] == "AQID"


def test_declarative_paired_mutation_patches_copy_and_tail_value() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 8,
        "cases": [
            {
                "id": "paired",
                "operations": [
                    {
                        "operation": "duplicate",
                        "source": {"type": 0x20, "occurrence": 1},
                        "patches": [{"offset": 0, "bytes_hex": "58"}],
                    },
                    {
                        "operation": "patch",
                        "target": {"type": 0x11, "occurrence": 1},
                        "patches": [{"offset": 0, "bytes_hex": "03"}],
                    },
                ],
            }
        ],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutations = ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])
    mutant = mutations[0]
    assert mutant.mutation_id == "paired"
    assert mutant.operation == "duplicate+patch"
    assert [record.encoded for record in mutant.records] == [
        bytes.fromhex("a00441555448"),
        bytes.fromhex("a10401020304"),
        bytes.fromhex("1003617070"),
        bytes.fromhex("200444415441"),
        bytes.fromhex("110103"),
        bytes.fromhex("200458415441"),
    ]


def test_declarative_replacement_reads_config_relative_file(tmp_path: Path) -> None:
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"\x03")
    config = _config()
    config["_config_dir"] = tmp_path
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [
            {
                "id": "file-replace",
                "operations": [
                    {
                        "operation": "replace",
                        "target": {"type": 0x11, "occurrence": 1},
                        "value_file": "replacement.bin",
                    }
                ],
            }
        ],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutation = ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"], tmp_path)[0]
    assert mutation.records[-1].encoded == bytes.fromhex("110103")


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (
            {"operation": "duplicate", "source": {"type": 0x20, "occurrence": 1}, "insert_index": 0},
            "insertion destination",
        ),
        (
            {"operation": "patch", "target": {"type": 0x11, "occurrence": 1}, "patches": [{"offset": 2, "bytes_hex": "00"}]},
            "out of bounds",
        ),
        (
            {"operation": "patch", "target": {"type": 0x11, "occurrence": 1}, "patches": [{"offset": 0, "bytes_hex": "02"}, {"offset": 0, "bytes_hex": "03"}]},
            "overlaps",
        ),
    ],
)
def test_declarative_mutation_boundaries_fail_closed(operation: dict, message: str) -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [{"id": "bad", "operations": [operation]}],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match=message):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


def test_declarative_selector_without_occurrence_is_rejected() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [{"id": "ambiguous", "operations": [{"operation": "patch", "target": {"type": 0x20}, "patches": [{"offset": 0, "bytes_hex": "58"}]}]}],
    }
    with pytest.raises(CampaignError, match="type selectors require occurrence"):
        ae._parse_config(config)


def test_signature_before_boundary_requires_strict_order() -> None:
    config = _config()
    config["authentication"] = {
        "boundary_type": 0xA0,
        "signature_type": 0xA1,
        "include_boundary": True,
        "coverage": "signature_before_boundary",
    }
    config["input_hex"] = "a00441555448a104010203041003617070200444415441110102"
    with pytest.raises(CampaignError, match="strictly before"):
        run_campaign(config)


def test_declarative_file_reference_must_stay_under_config_directory(tmp_path: Path) -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [
            {
                "id": "escape",
                "operations": [
                    {
                        "operation": "replace",
                        "target": {"type": 0x11, "occurrence": 1},
                        "value_file": "../outside.bin",
                    }
                ],
            }
        ],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="must remain under"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"], tmp_path)


def test_declarative_patch_noop_fails_closed() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [
            {
                "id": "noop",
                "operations": [
                    {
                        "operation": "patch",
                        "target": {"type": 0x11, "occurrence": 1},
                        "patches": [{"offset": 0, "bytes_hex": "02"}],
                    }
                ],
            }
        ],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="no-op"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


@pytest.mark.parametrize("case_id", ["/tmp/escape", "../escape", "a/b", ".", "..", "base", "Base", "a" * 129])
def test_declarative_case_id_is_safe_for_temp_filename(case_id: str) -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [{"id": case_id, "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]}],
    }
    with pytest.raises(CampaignError, match="portable identifier"):
        ae._parse_config(config)


def test_declarative_cases_are_not_silently_truncated() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 1,
        "cases": [
            {"id": "one", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]},
            {"id": "two", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "04"}]}]},
        ],
    }
    with pytest.raises(CampaignError, match="exceeds mutations.max_mutants"):
        ae._mutation_records(
            ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"]),
            config["mutations"],
            config["authentication"],
            config["grammar"],
        )


def test_declarative_case_ids_are_case_insensitively_unique() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [],
        "reorder_types": [],
        "max_mutants": 2,
        "cases": [
            {"id": "Foo", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "03"}]}]},
            {"id": "foo", "operations": [{"operation": "patch", "target": {"index": 4}, "patches": [{"offset": 0, "bytes_hex": "04"}]}]},
        ],
    }
    with pytest.raises(CampaignError, match="duplicate id"):
        ae._parse_config(config)


def test_mutated_record_enforces_grammar_length_limit() -> None:
    config = _config()
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="max_record_length"):
        ae._encode_mutated_record(records[4], b"x" * 65, config["grammar"])


def test_authenticated_prefix_target_is_rejected() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [], "reorder_types": [], "max_mutants": 1,
        "cases": [{"id": "prefix", "operations": [{"operation": "patch", "target": {"index": 0}, "patches": [{"offset": 0, "bytes_hex": "58"}]}]}],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="post-auth tail"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


def test_between_boundary_and_later_signature_target_is_rejected() -> None:
    config = _config()
    config["input_hex"] = "a004415554481003617070a10401020304200444415441"
    config["mutations"] = {
        "duplicate_types": [], "reorder_types": [], "max_mutants": 1,
        "cases": [{"id": "between", "operations": [{"operation": "replace", "target": {"index": 1}, "value_hex": "78797a"}]}],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    with pytest.raises(CampaignError, match="post-auth tail"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


def test_insert_after_tail_anchor_is_allowed_but_pre_tail_anchor_is_rejected() -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [], "reorder_types": [], "max_mutants": 1,
        "cases": [{"id": "after", "operations": [{"operation": "duplicate", "source": {"index": 3}, "insert_after": {"type": 32, "occurrence": 1}}]}],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    mutation = ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])[0]
    assert [record.type for record in mutation.records] == [0xA0, 0xA1, 0x10, 0x20, 0x20, 0x11]
    config["mutations"]["cases"][0]["operations"][0]["insert_after"] = {"index": 0}
    with pytest.raises(CampaignError, match="insertion anchor"):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


def test_missing_and_out_of_range_selectors_fail_closed() -> None:
    config = _config()
    for selector in ({"type": 0x20, "occurrence": 2}, {"index": 99}):
        config["mutations"] = {
            "duplicate_types": [], "reorder_types": [], "max_mutants": 1,
            "cases": [{"id": "missing", "operations": [{"operation": "patch", "target": selector, "patches": [{"offset": 0, "bytes_hex": "58"}]}]}],
        }
        records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
        with pytest.raises(CampaignError, match="(occurrence does not exist|index is out of range)"):
            ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])


@pytest.mark.parametrize("selector", [{"index": 1}, {"index": 0}])
def test_copying_signature_or_boundary_fails_identity_uniqueness(selector: dict) -> None:
    config = _config()
    config["mutations"] = {
        "duplicate_types": [], "reorder_types": [], "max_mutants": 1,
        "cases": [{"id": "delimiter-copy", "operations": [{"operation": "duplicate", "source": selector}]}],
    }
    records = ae.parse_tlv_stream(bytes.fromhex(config["input_hex"]), config["grammar"])
    message = "signature record must occur exactly once" if selector["index"] == 1 else "authentication boundary must occur exactly once"
    with pytest.raises(CampaignError, match=message):
        ae._mutation_records(records, config["mutations"], config["authentication"], config["grammar"])
