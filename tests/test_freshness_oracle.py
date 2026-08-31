from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import freshness_oracle as oracle  # noqa: E402


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _config() -> dict:
    return {
        "schema_version": 1,
        "name": "synthetic_metadata_freshness",
        "initial_state": {
            "now": 10,
            "installed": {"version": 3, "target": "stable", "payload_digest": _digest("payload-v3")},
            "metadata": {
                "authenticated_digest": _digest("metadata-v3"),
                "version": 3,
                "target": "stable",
                "payload_digest": _digest("payload-v3"),
                "expires_at": 20,
            },
        },
        "scenarios": [
            {"id": "baseline", "events": []},
            {"id": "expired_refresh_failure", "events": [{"advance_time": 20}, {"refresh_failure": True}]},
            {"id": "installed_channel_advances", "events": [
                {"update_installed": {"version": 4, "target": "stable", "payload_digest": _digest("payload-v4")}},
                {"advance_time": 20},
                {"refresh_failure": True},
            ]},
        ],
        "harness": {"command": ["synthetic", "{scenario}"], "timeout_seconds": 1},
        "mode": "synthetic",
    }


def _output(state: oracle.State, *, metadata_used: bool) -> dict:
    accepted = not (state.now >= state.metadata.expires_at and not metadata_used)
    return {
        "accepted": accepted,
        "committed": accepted,
        "rollback_outcome": "none" if accepted else "rejected-expired",
        "version": state.installed.version if accepted else None,
        "target": state.installed.target if accepted else None,
        "size": 1 if accepted else None,
        "installed_payload_digest": state.installed.payload_digest,
        "metadata": oracle._metadata_view(state),
        "metadata_used": metadata_used,
        "security_state": {"installed_version": state.installed.version},
    }


def test_apply_events_keeps_installed_and_metadata_channels_independent() -> None:
    config = oracle._parse_config(_config())
    state = oracle.apply_events(config["initial_state"], config["scenarios"][2].events)
    assert state.installed.version == 4
    assert state.metadata.version == 3
    assert state.now == 30
    assert state.refresh_failed is True


@pytest.mark.parametrize("digest", ["٠" * 64, "１" * 64, "a" * 63 + "Ａ"])
def test_digest_requires_ascii_lowercase_hex(digest: str) -> None:
    with pytest.raises(oracle.FreshnessOracleError, match="lowercase SHA-256 digest"):
        oracle._digest(digest, "digest")


def test_expired_metadata_use_is_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(config["initial_state"], next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id))
        output = _output(state, metadata_used=scenario_id == "expired_refresh_failure")
        if scenario_id == "expired_refresh_failure":
            output["version"] = 2
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert [item["scenario_id"] for item in report["findings"]] == ["expired_refresh_failure"]
    assert report["findings"][0]["id"] == "EXPIRED_AUTHENTICATED_METADATA_USE"


def test_expired_metadata_rejection_is_not_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(config["initial_state"], next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id))
        return _output(state, metadata_used=False)

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    assert report["status"] == "PASS"
    assert report["findings"] == []


def test_expired_metadata_read_for_rejection_is_not_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(config["initial_state"], next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id))
        output = _output(state, metadata_used=False)
        if state.now >= state.metadata.expires_at:
            output["metadata_used"] = True
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    assert report["status"] == "PASS"
    assert report["findings"] == []


def test_fresh_installed_channel_regression_is_a_distinct_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = oracle._parse_config(_config())
    config["scenarios"] = (
        config["scenarios"][0],
        oracle.Scenario(
            "fresh_installed_channel_advances",
            (
                {
                    "update_installed": oracle.ChannelState(
                        version=4,
                        target="stable",
                        payload_digest=_digest("payload-v4"),
                    )
                },
            ),
        ),
    )

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(
            config["initial_state"],
            next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id),
        )
        output = _output(state, metadata_used=False)
        if scenario_id == "fresh_installed_channel_advances":
            output.update(
                {
                    "committed": True,
                    "version": state.metadata.version,
                    "target": state.metadata.target,
                    "installed_payload_digest": state.metadata.payload_digest,
                }
            )
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert [item["id"] for item in report["findings"]] == [
        "INSTALLED_STATE_REGRESSION"
    ]
    finding = report["findings"][0]
    assert finding["scenario_id"] == "fresh_installed_channel_advances"
    assert finding["differing_outcomes"]["security_state"] == {
        "base": {"installed_version": 3},
        "scenario": {"installed_version": 4},
    }
    assert finding["installed_state_regression"]["version"] == {
        "installed": 4,
        "selected": 3,
    }
    assert finding["installed_state_regression"]["installed_payload_digest"] == {
        "installed": _digest("payload-v4"),
        "selected": _digest("payload-v3"),
    }
    assert finding["metadata"]["expired"] is False


def test_expired_metadata_finding_owns_same_scenario_as_installed_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(
            config["initial_state"],
            next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id),
        )
        output = _output(state, metadata_used=scenario_id == "installed_channel_advances")
        if scenario_id == "installed_channel_advances":
            output.update(
                {
                    "committed": True,
                    "version": state.metadata.version,
                    "target": state.metadata.target,
                    "installed_payload_digest": state.metadata.payload_digest,
                }
            )
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    assert [item["id"] for item in report["findings"]] == [
        "EXPIRED_AUTHENTICATED_METADATA_USE"
    ]


@pytest.mark.parametrize("invalid", [None, [], "not-a-config"])
def test_direct_campaign_rejects_non_mapping_config(invalid: object) -> None:
    with pytest.raises(oracle.FreshnessOracleError, match="config must be a mapping"):
        oracle.run_campaign(invalid)  # type: ignore[arg-type]


def test_baseline_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    config["scenarios"] = [config["scenarios"][1]]
    with pytest.raises(oracle.FreshnessOracleError, match="empty-event baseline"):
        oracle.run_campaign(config)


def test_baseline_must_be_named_and_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    config["scenarios"][0] = {"id": "control", "events": []}
    with pytest.raises(oracle.FreshnessOracleError, match="empty-event baseline"):
        oracle.run_campaign(config)

    config = _config()
    config["initial_state"]["now"] = 20
    with pytest.raises(oracle.FreshnessOracleError, match="must be fresh"):
        oracle.run_campaign(config)


def test_baseline_must_be_the_only_empty_scenario() -> None:
    config = _config()
    config["scenarios"].insert(0, {"id": "other_control", "events": []})
    with pytest.raises(oracle.FreshnessOracleError, match="exactly one empty-event baseline"):
        oracle.run_campaign(config)


def test_baseline_must_be_first() -> None:
    config = _config()
    config["scenarios"] = config["scenarios"][1:] + config["scenarios"][:1]
    with pytest.raises(oracle.FreshnessOracleError, match="begin with exactly one empty-event baseline"):
        oracle.run_campaign(config)


def test_baseline_must_be_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(
            config["initial_state"],
            next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id),
        )
        output = _output(state, metadata_used=False)
        if scenario_id == "baseline":
            output.update({"accepted": False, "committed": False, "version": None, "target": None, "size": None})
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    with pytest.raises(oracle.FreshnessOracleError, match="baseline must be accepted"):
        oracle.run_campaign(config)


def test_baseline_must_not_report_regressed_installed_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = oracle._parse_config(_config())
    calls = []

    def fake_run(_config, _path, scenario_id, _index):
        calls.append(scenario_id)
        state = oracle.apply_events(
            config["initial_state"],
            next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id),
        )
        output = _output(state, metadata_used=False)
        if scenario_id == "baseline":
            output["version"] = state.installed.version - 1
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    with pytest.raises(oracle.FreshnessOracleError, match="installed-state regression"):
        oracle.run_campaign(config)
    assert calls == ["baseline"]


def test_committed_payload_digest_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(config["initial_state"], next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id))
        output = _output(state, metadata_used=False)
        output["committed"] = True
        output["installed_payload_digest"] = "not-a-digest"
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    with pytest.raises(oracle.FreshnessOracleError, match="installed_payload_digest"):
        oracle.run_campaign(config)


def test_installed_payload_digest_is_required_even_without_commit() -> None:
    config = oracle._parse_config(_config())
    state = config["initial_state"]
    output = _output(state, metadata_used=False)
    output.update({"accepted": False, "committed": False, "version": None, "target": None, "size": None})
    output["installed_payload_digest"] = "not-a-digest"
    with pytest.raises(oracle.FreshnessOracleError, match="installed_payload_digest"):
        oracle._validate_output(output, state, "control")


@pytest.mark.parametrize(
    ("field", "value"),
    [("version", []), ("target", 7), ("size", {})],
)
def test_rejected_output_still_validates_non_null_install_fields(field: str, value: object) -> None:
    config = oracle._parse_config(_config())
    state = config["initial_state"]
    output = _output(state, metadata_used=False)
    output.update({"accepted": False, "committed": False, "version": None, "target": None, "size": None})
    output[field] = value
    with pytest.raises(oracle.FreshnessOracleError, match=field):
        oracle._validate_output(output, state, "control")


def test_nonstandard_json_output_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = oracle._parse_config(_config())
    config["_config_dir"] = tmp_path
    monkeypatch.setattr(
        oracle.subprocess,
        "run",
        lambda *args, **kwargs: oracle.subprocess.CompletedProcess(
            args[0], 0, stdout='{"accepted": NaN}', stderr=""
        ),
    )
    with pytest.raises(oracle.FreshnessOracleError, match="is not JSON"):
        oracle._run_harness(config, tmp_path / "scenario.json", "baseline", 0)


def test_installed_state_regression_does_not_require_security_state_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    config = oracle._parse_config(_config())

    def fake_run(_config, _path, scenario_id, _index):
        state = oracle.apply_events(config["initial_state"], next(s.events for s in config["scenarios"] if s.scenario_id == scenario_id))
        output = _output(state, metadata_used=scenario_id == "installed_channel_advances")
        output["security_state"] = {}
        if scenario_id == "installed_channel_advances":
            output["version"] = 3
            output["installed_payload_digest"] = state.metadata.payload_digest
            output["committed"] = True
        return output

    monkeypatch.setattr(oracle, "_run_harness", fake_run)
    report = oracle.run_campaign(config)
    finding = next(item for item in report["findings"] if item["scenario_id"] == "installed_channel_advances")
    assert finding["differing_outcomes"] == {}
    assert finding["installed_state_regression"]["version"] == {"installed": 4, "selected": 3}


def test_checked_in_example_runs_from_another_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = ROOT / "examples/freshness_oracle/profile.yaml"
    config = oracle.load_config(config_path)
    monkeypatch.chdir(tmp_path)
    report = oracle.run_campaign(config)
    assert report["status"] == "FINDINGS"
    assert [item["scenario_id"] for item in report["findings"]] == [
        "installed_channel_advances"
    ]
