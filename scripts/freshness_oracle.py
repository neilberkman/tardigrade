#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freshness-aware authenticated-metadata state oracle.

This module models a small, target-neutral update state machine.  It is useful
for systems where installed image state and authenticated metadata are stored
or refreshed through different channels.  Scenarios can advance time, make a
refresh fail, or update either channel independently.  A black-box harness is
then asked to report the security decision it made for the resulting state.

The oracle reports use of expired authenticated metadata only when the harness
explicitly says that metadata participated in an accepted or committed
decision and an unsafe canonical outcome or installed-state regression is
observed. Harness setup errors,
malformed output, and timeouts are failures of the test infrastructure, never
product findings.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - JSON remains available
    yaml = None


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 10.0
ALLOWED_PLACEHOLDERS = ("{scenario}", "{scenario_id}", "{scenario_index}", "{mode}")
OUTCOME_FIELDS = (
    "accepted",
    "committed",
    "rollback_outcome",
    "version",
    "target",
    "size",
    "installed_payload_digest",
)
DIFF_FIELDS = (*OUTCOME_FIELDS, "security_state")


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-standard JSON constant {!r}".format(value))


class FreshnessOracleError(ValueError):
    """Raised for invalid configuration, state, or harness evidence."""


@dataclass(frozen=True)
class ChannelState:
    version: int
    target: str
    payload_digest: str


@dataclass(frozen=True)
class MetadataState:
    authenticated_digest: str
    version: int
    target: str
    payload_digest: str
    expires_at: int


@dataclass(frozen=True)
class State:
    now: int
    installed: ChannelState
    metadata: MetadataState
    refresh_failed: bool = False


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    events: tuple[Mapping[str, Any], ...]


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FreshnessOracleError("{} must be a mapping".format(context))
    return value


def _reject_unknown(value: Mapping[str, Any], allowed: Iterable[str], context: str) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise FreshnessOracleError("{} has unknown field(s): {}".format(context, ", ".join(unknown)))


def _integer(value: Any, context: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FreshnessOracleError("{} must be an integer".format(context))
    if minimum is not None and value < minimum:
        raise FreshnessOracleError("{} must be at least {}".format(context, minimum))
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FreshnessOracleError("{} must be a non-empty string".format(context))
    if "\x00" in value:
        raise FreshnessOracleError("{} must not contain NUL characters".format(context))
    return value.strip()


def _digest(value: Any, context: str) -> str:
    text = _text(value, context)
    # ``int(..., 16)`` accepts several Unicode digit classes.  Digests are
    # serialized protocol values, so keep the grammar to ASCII lowercase
    # hexadecimal rather than accepting visually similar alternatives.
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise FreshnessOracleError("{} must be a lowercase SHA-256 digest".format(context))
    return text


def _channel(raw: Any, context: str) -> ChannelState:
    value = _mapping(raw, context)
    _reject_unknown(value, {"version", "target", "payload_digest"}, context)
    return ChannelState(
        version=_integer(value.get("version"), context + ".version", minimum=0),
        target=_text(value.get("target"), context + ".target"),
        payload_digest=_digest(value.get("payload_digest"), context + ".payload_digest"),
    )


def _metadata(raw: Any, context: str) -> MetadataState:
    value = _mapping(raw, context)
    _reject_unknown(value, {"authenticated_digest", "version", "target", "payload_digest", "expires_at"}, context)
    return MetadataState(
        authenticated_digest=_digest(value.get("authenticated_digest"), context + ".authenticated_digest"),
        version=_integer(value.get("version"), context + ".version", minimum=0),
        target=_text(value.get("target"), context + ".target"),
        payload_digest=_digest(value.get("payload_digest"), context + ".payload_digest"),
        expires_at=_integer(value.get("expires_at"), context + ".expires_at", minimum=0),
    )


def _parse_event(raw: Any, index: int) -> Mapping[str, Any]:
    context = "scenarios[].events[{}]".format(index)
    event = _mapping(raw, context)
    if len(event) != 1:
        raise FreshnessOracleError("{} must contain exactly one event".format(context))
    kind, value = next(iter(event.items()))
    if kind == "advance_time":
        return {kind: _integer(value, context + ".advance_time", minimum=0)}
    if kind == "refresh_failure":
        if not isinstance(value, bool):
            raise FreshnessOracleError("{}.refresh_failure must be boolean".format(context))
        return {kind: value}
    if kind in ("update_installed", "update_metadata"):
        if kind == "update_installed":
            return {kind: _channel(value, context + ".update_installed")}
        return {kind: _metadata(value, context + ".update_metadata")}
    raise FreshnessOracleError("{} has unknown event {!r}".format(context, kind))


def _parse_config(raw: Mapping[str, Any]) -> dict[str, Any]:
    root = _mapping(raw, "config")
    _reject_unknown(root, {"schema_version", "name", "initial_state", "scenarios", "harness", "mode", "_config_dir"}, "config")
    version = _integer(root.get("schema_version", SCHEMA_VERSION), "schema_version", minimum=1)
    if version != SCHEMA_VERSION:
        raise FreshnessOracleError("unsupported schema_version {}".format(version))
    name = _text(root.get("name"), "name")
    initial = _mapping(root.get("initial_state"), "initial_state")
    _reject_unknown(initial, {"now", "installed", "metadata"}, "initial_state")
    state = State(
        now=_integer(initial.get("now"), "initial_state.now", minimum=0),
        installed=_channel(initial.get("installed"), "initial_state.installed"),
        metadata=_metadata(initial.get("metadata"), "initial_state.metadata"),
    )
    scenarios_raw = root.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise FreshnessOracleError("scenarios must be a non-empty list")
    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for index, raw_scenario in enumerate(scenarios_raw):
        context = "scenarios[{}]".format(index)
        item = _mapping(raw_scenario, context)
        _reject_unknown(item, {"id", "events"}, context)
        scenario_id = _text(item.get("id"), context + ".id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", scenario_id):
            raise FreshnessOracleError("{}.id contains unsupported characters".format(context))
        if scenario_id in seen:
            raise FreshnessOracleError("duplicate scenario id {!r}".format(scenario_id))
        seen.add(scenario_id)
        events_raw = item.get("events", [])
        if not isinstance(events_raw, list):
            raise FreshnessOracleError("{}.events must be a list".format(context))
        scenarios.append(Scenario(scenario_id, tuple(_parse_event(value, i) for i, value in enumerate(events_raw))))

    harness = _mapping(root.get("harness"), "harness")
    _reject_unknown(harness, {"command", "timeout_seconds", "cwd"}, "harness")
    command = harness.get("command")
    if not isinstance(command, list) or not command or not all(
        isinstance(x, str) and x.strip() and "\x00" not in x for x in command
    ):
        raise FreshnessOracleError("harness.command must be a non-empty list of strings")
    if not any("{scenario}" in token for token in command):
        raise FreshnessOracleError("harness.command must include the {scenario} placeholder")
    names = {item[1:-1] for item in ALLOWED_PLACEHOLDERS}
    for token in command:
        for placeholder in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", token):
            if placeholder not in names:
                raise FreshnessOracleError("harness.command contains an unknown placeholder")
    timeout = harness.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise FreshnessOracleError("harness.timeout_seconds must be finite and positive")
    cwd = harness.get("cwd")
    if cwd is not None:
        cwd = _text(cwd, "harness.cwd")
    mode = _text(root.get("mode", "default"), "mode")
    return {
        "schema_version": version,
        "name": name,
        "initial_state": state,
        "scenarios": tuple(scenarios),
        "harness": {"command": list(command), "timeout_seconds": float(timeout), "cwd": cwd},
        "mode": mode,
    }


def load_config(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if yaml is not None else json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise FreshnessOracleError("config is not valid YAML/JSON: {}".format(exc)) from exc
    config = _parse_config(raw)
    config["_config_dir"] = path.resolve().parent
    return config


def apply_events(initial: State, events: Sequence[Mapping[str, Any]]) -> State:
    """Apply declarative channel/time events and return the resulting state."""
    state = initial
    for event in events:
        if "advance_time" in event:
            state = replace(state, now=state.now + int(event["advance_time"]))
        elif "refresh_failure" in event:
            state = replace(state, refresh_failed=bool(event["refresh_failure"]))
        elif "update_installed" in event:
            value = event["update_installed"]
            state = replace(state, installed=value if isinstance(value, ChannelState) else _channel(value, "update_installed"))
        elif "update_metadata" in event:
            value = event["update_metadata"]
            state = replace(state, metadata=value if isinstance(value, MetadataState) else _metadata(value, "update_metadata"))
        else:  # pragma: no cover - config parser rejects this
            raise FreshnessOracleError("unknown event")
    return state


def _metadata_view(state: State) -> dict[str, Any]:
    return {
        "authenticated_digest": state.metadata.authenticated_digest,
        "version": state.metadata.version,
        "target": state.metadata.target,
        "payload_digest": state.metadata.payload_digest,
        "expires_at": state.metadata.expires_at,
        "now": state.now,
        "expired": state.now >= state.metadata.expires_at,
        "refresh_failed": state.refresh_failed,
    }


def _render_command(command: Sequence[str], scenario_path: Path, scenario_id: str, index: int, mode: str) -> list[str]:
    replacements = {"{scenario}": str(scenario_path), "{scenario_id}": scenario_id, "{scenario_index}": str(index), "{mode}": mode}
    return [_replace_token(token, replacements) for token in command]


def _replace_token(token: str, replacements: Mapping[str, str]) -> str:
    result = token
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def _run_harness(config: Mapping[str, Any], scenario_path: Path, scenario_id: str, index: int) -> dict[str, Any]:
    harness = config["harness"]
    cwd = harness.get("cwd")
    cwd_path = Path(cwd) if cwd else Path(config.get("_config_dir") or Path.cwd())
    if not cwd_path.is_absolute():
        cwd_path = Path(config.get("_config_dir") or Path.cwd()) / cwd_path
    try:
        result = subprocess.run(
            _render_command(harness["command"], scenario_path, scenario_id, index, config["mode"]),
            cwd=str(cwd_path.resolve()), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=harness["timeout_seconds"], check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FreshnessOracleError("harness timed out for {}".format(scenario_id)) from exc
    except (OSError, ValueError) as exc:
        raise FreshnessOracleError("harness could not start for {}: {}".format(scenario_id, exc)) from exc
    if result.returncode != 0:
        raise FreshnessOracleError("harness returned {} for {}".format(result.returncode, scenario_id))
    try:
        output = json.loads(result.stdout, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FreshnessOracleError("harness output for {} is not JSON".format(scenario_id)) from exc
    if not isinstance(output, dict):
        raise FreshnessOracleError("harness output for {} must be an object".format(scenario_id))
    return output


def _validate_output(output: Mapping[str, Any], state: State, context: str) -> dict[str, Any]:
    required = (*OUTCOME_FIELDS, "metadata", "metadata_used", "security_state")
    for field in required:
        if field not in output:
            raise FreshnessOracleError("{} is missing output field '{}'".format(context, field))
    for field in ("accepted", "committed", "metadata_used"):
        if not isinstance(output[field], bool):
            raise FreshnessOracleError("{}.{} must be boolean".format(context, field))
    if output["committed"] and not output["accepted"]:
        raise FreshnessOracleError("{} committed without acceptance".format(context))
    if not isinstance(output["rollback_outcome"], str) or not output["rollback_outcome"].strip():
        raise FreshnessOracleError("{}.rollback_outcome must be a non-empty string".format(context))
    metadata = _mapping(output["metadata"], context + ".metadata")
    expected_metadata = _metadata_view(state)
    for field in expected_metadata:
        if field not in metadata or metadata[field] != expected_metadata[field]:
            raise FreshnessOracleError("{}.metadata.{} disagrees with the model".format(context, field))
    if not isinstance(output["security_state"], Mapping):
        raise FreshnessOracleError("{}.security_state must be an object".format(context))
    _digest(output["installed_payload_digest"], context + ".installed_payload_digest")
    version = output["version"]
    if version is not None and (
        isinstance(version, bool) or not isinstance(version, int) or version < 0
    ):
        raise FreshnessOracleError(
            "{}.version must be null or a non-negative integer".format(context)
        )
    target = output["target"]
    if target is not None and (not isinstance(target, str) or not target.strip()):
        raise FreshnessOracleError(
            "{}.target must be null or a non-empty string".format(context)
        )
    size = output["size"]
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise FreshnessOracleError(
            "{}.size must be null or a non-negative integer".format(context)
        )
    if output["accepted"] and (version is None or target is None or size is None):
        raise FreshnessOracleError(
            "{}.accepted requires non-null version, target, and size".format(context)
        )
    return {field: output[field] for field in required}


def _scenario_payload(state: State, scenario: Scenario) -> dict[str, Any]:
    serial_events = []
    for event in scenario.events:
        kind, value = next(iter(event.items()))
        if isinstance(value, ChannelState):
            value = {"version": value.version, "target": value.target, "payload_digest": value.payload_digest}
        elif isinstance(value, MetadataState):
            value = {
                "authenticated_digest": value.authenticated_digest,
                "version": value.version,
                "target": value.target,
                "payload_digest": value.payload_digest,
                "expires_at": value.expires_at,
            }
        serial_events.append({kind: value})
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_id": scenario.scenario_id,
        "events": serial_events,
        "state": {
            "now": state.now,
            "refresh_failed": state.refresh_failed,
            "installed": {
                "version": state.installed.version,
                "target": state.installed.target,
                "payload_digest": state.installed.payload_digest,
            },
            "metadata": {
                "authenticated_digest": state.metadata.authenticated_digest,
                "version": state.metadata.version,
                "target": state.metadata.target,
                "payload_digest": state.metadata.payload_digest,
                "expires_at": state.metadata.expires_at,
            },
        },
    }


def _installed_state_regression(state: State, outcome: Mapping[str, Any]) -> dict[str, Any]:
    """Return evidence that an accepted result selected older installed state."""
    if not outcome["accepted"]:
        return {}
    version = outcome["version"]
    regression: dict[str, Any] = {}
    if isinstance(version, int) and version < state.installed.version:
        regression["version"] = {
            "installed": state.installed.version,
            "selected": version,
        }
    if isinstance(version, int) and version == state.installed.version:
        if outcome["target"] != state.installed.target:
            regression["target"] = {
                "installed": state.installed.target,
                "selected": outcome["target"],
            }
    if outcome["committed"] and isinstance(version, int) and version <= state.installed.version:
        digest = outcome["installed_payload_digest"]
        if digest != state.installed.payload_digest:
            regression["installed_payload_digest"] = {
                "installed": state.installed.payload_digest,
                "selected": digest,
            }
    return regression


def run_campaign(config: Mapping[str, Any]) -> dict[str, Any]:
    """Run a freshness campaign and return PASS/FINDINGS evidence."""
    if not isinstance(config, Mapping):
        raise FreshnessOracleError("config must be a mapping")
    normalized = config if isinstance(config.get("initial_state"), State) else _parse_config(config)
    normalized = dict(normalized)
    normalized["_config_dir"] = config.get("_config_dir", Path.cwd())
    initial: State = normalized["initial_state"]
    scenarios: tuple[Scenario, ...] = tuple(normalized["scenarios"])
    if initial.now >= initial.metadata.expires_at:
        raise FreshnessOracleError("initial_state metadata must be fresh for the baseline")
    baseline = [scenario for scenario in scenarios if scenario.scenario_id == "baseline"]
    empty_scenarios = [scenario for scenario in scenarios if not scenario.events]
    if (len(baseline) != 1 or baseline[0].events or empty_scenarios != baseline
            or scenarios[0] is not baseline[0]):
        raise FreshnessOracleError("scenarios must begin with exactly one empty-event baseline")
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "campaign": normalized["name"],
        "status": "PASS",
        "base": None,
        "scenarios": [],
        "findings": [],
    }
    with tempfile.TemporaryDirectory(prefix="tardigrade-freshness-") as directory:
        temp = Path(directory)
        outputs: dict[str, dict[str, Any]] = {}
        states: dict[str, State] = {}
        for index, scenario in enumerate(scenarios):
            state = apply_events(initial, scenario.events)
            states[scenario.scenario_id] = state
            path = temp / "scenario-{:04d}.json".format(index)
            path.write_text(json.dumps(_scenario_payload(state, scenario), sort_keys=True) + "\n", encoding="utf-8")
            output = _validate_output(_run_harness(normalized, path, scenario.scenario_id, index), state, scenario.scenario_id)
            if scenario.scenario_id == "baseline" and not output["accepted"]:
                raise FreshnessOracleError("baseline must be accepted by the harness")
            if scenario.scenario_id == "baseline" and _installed_state_regression(state, output):
                raise FreshnessOracleError("baseline reports an installed-state regression")
            outputs[scenario.scenario_id] = output
            item = {
                "scenario_id": scenario.scenario_id,
                "events": _scenario_payload(state, scenario)["events"],
                "state": _scenario_payload(state, scenario)["state"],
                "outcome": output,
            }
            report["scenarios"].append(item)

        base_id = "baseline"
        base_output = outputs[base_id]
        report["base"] = {"scenario_id": base_id, "outcome": base_output}
        for item in report["scenarios"]:
            scenario_id = item["scenario_id"]
            state = states[scenario_id]
            outcome = outputs[scenario_id]
            installed_regression = _installed_state_regression(state, outcome)
            expired = state.now >= state.metadata.expires_at
            differing = {
                field: {"base": base_output[field], "scenario": outcome[field]}
                for field in DIFF_FIELDS
                if outcome[field] != base_output[field]
            }
            # metadata_used is the authoritative signal from the target
            # harness for expired-metadata findings. A changed security
            # outcome is retained as supporting evidence, but does not become
            # an expired-metadata finding unless expired metadata was actually
            # consumed by the decision. Installed-channel regressions are
            # independent of metadata expiry and are reported separately.
            # Reading an expired record in order to reject it is safe. The
            # expired-metadata finding requires the harness to both report
            # that metadata participated in the decision and accept/commit
            # the result.
            expired_finding = (
                expired
                and outcome["metadata_used"]
                and (outcome["accepted"] or outcome["committed"])
                and (differing or installed_regression)
            )
            if expired_finding:
                report["findings"].append({
                    "id": "EXPIRED_AUTHENTICATED_METADATA_USE",
                    "scenario_id": scenario_id,
                    "differing_outcomes": differing,
                    "installed_state_regression": installed_regression,
                    "metadata": item["outcome"]["metadata"],
                })
            elif installed_regression:
                report["findings"].append({
                    "id": "INSTALLED_STATE_REGRESSION",
                    "scenario_id": scenario_id,
                    "differing_outcomes": differing,
                    "installed_state_regression": installed_regression,
                    "metadata": item["outcome"]["metadata"],
                })
    if report["findings"]:
        report["status"] = "FINDINGS"
    return report


def write_report(report: Mapping[str, Any], path: Path | None = None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_campaign(load_config(args.config))
        write_report(report, args.report)
        return 1 if report["status"] == "FINDINGS" else 0
    except FreshnessOracleError as exc:
        write_report({"schema_version": SCHEMA_VERSION, "status": "FAIL_CLOSED", "error": str(exc)}, args.report)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
