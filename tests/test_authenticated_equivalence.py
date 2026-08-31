#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the authenticated-equivalence campaign."""

from __future__ import annotations

import hashlib
import math
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

    fixed = run_campaign(_config("fixed"))
    assert fixed["status"] == "PASS"
    assert fixed["findings"] == []
    assert fixed["mutants"][0]["outcome"]["accepted"] is False
    assert fixed["mutants"][0]["outcome"]["committed"] is False


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
