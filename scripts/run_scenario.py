#!/usr/bin/env python3
"""Generic scenario/replay runner for tardigrade discovery workflows.

Scenarios orchestrate one or more audit runs without encoding bootloader-
specific semantics in the core tool. A scenario uses a base profile and
applies per-step profile overrides or replay specs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import yaml
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit("PyYAML is required for run_scenario.py (pip install pyyaml).") from exc


SUPPORTED_SCHEMA_VERSIONS = {1}
SUPPORTED_REPLAY_KINDS = {"replay"}
SUPPORTED_STEP_KINDS = {"audit", "replay", "assert"}


class ScenarioError(Exception):
    """Raised when a scenario or replay spec is invalid."""


def _progress(message: str) -> None:
    print("[scenario] {}".format(message), flush=True)


def _run_command_streamed(cmd: List[str], cwd: Path) -> Tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    lines: List[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        lines.append(line)
        print(line, end="", flush=True)
    proc.stdout.close()
    return_code = proc.wait()
    combined = "".join(lines)
    return return_code, combined, ""


def _summarize_step_report(step_id: str, report: Optional[Dict[str, Any]]) -> None:
    if not isinstance(report, dict):
        return
    verdict = report.get("verdict")
    runtime = ((report.get("summary") or {}).get("runtime_sweep") or {})
    if not isinstance(runtime, dict):
        if verdict:
            _progress("step {} verdict={}".format(step_id, verdict))
        return
    control = runtime.get("control") or {}
    total_points = runtime.get("total_fault_points")
    issue_points = runtime.get("issue_points")
    bricks = runtime.get("bricks")
    control_outcome = control.get("boot_outcome")
    details: List[str] = []
    if verdict is not None:
        details.append("verdict={}".format(verdict))
    if total_points is not None:
        details.append("points={}".format(total_points))
    if issue_points is not None:
        details.append("issues={}".format(issue_points))
    if bricks is not None:
        details.append("bricks={}".format(bricks))
    if control_outcome is not None:
        details.append("control={}".format(control_outcome))
    if details:
        _progress("step {} {}".format(step_id, " ".join(details)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a generic multi-step tardigrade scenario."
    )
    parser.add_argument("--scenario", required=True, help="Scenario YAML/JSON path.")
    parser.add_argument("--output", required=True, help="Output JSON report path.")
    parser.add_argument(
        "--renode-test",
        default="",
        help="Override renode-test path or docker://IMAGE for all audit steps.",
    )
    parser.add_argument(
        "--renode-remote-server-dir",
        default="",
        help="Forward Renode remote server directory to audit steps.",
    )
    parser.add_argument(
        "--robot-var",
        action="append",
        default=[],
        metavar="KEY:VALUE",
        help="Extra Robot variable forwarded to every audit step (repeatable).",
    )
    parser.add_argument(
        "--keep-run-artifacts",
        action="store_true",
        help="Preserve per-step audit artifacts under results/scenario_runs.",
    )
    return parser.parse_args()


def _load_data(path: Path) -> Dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ScenarioError("{} must be a mapping/object".format(path))
    return raw


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            if key in merged:
                merged[key] = _deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    return override


def _tokenize_path(path: str) -> List[Any]:
    tokens: List[Any] = []
    current = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if current:
                tokens.append(current)
                current = ""
            i += 1
            continue
        if ch == "[":
            if current:
                tokens.append(current)
                current = ""
            end = path.find("]", i)
            if end == -1:
                raise ScenarioError("unterminated path index in {!r}".format(path))
            index_text = path[i + 1:end].strip()
            if not index_text:
                raise ScenarioError("empty path index in {!r}".format(path))
            tokens.append(int(index_text))
            i = end + 1
            continue
        current += ch
        i += 1
    if current:
        tokens.append(current)
    return tokens


_MISSING = object()


def _lookup_path(data: Any, path: str) -> Any:
    current = data
    for token in _tokenize_path(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token < 0 or token >= len(current):
                return _MISSING
            current = current[token]
            continue
        if not isinstance(current, dict) or token not in current:
            return _MISSING
        current = current[token]
    return current


def _resolve_path(base_dir: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((base_dir / path).resolve())


def _resolve_repo_or_scenario_path(repo_root: Path, scenario_dir: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    scenario_candidate = (scenario_dir / path).resolve()
    if scenario_candidate.exists():
        return str(scenario_candidate)
    repo_candidate = (repo_root / path).resolve()
    if repo_candidate.exists():
        return str(repo_candidate)
    return str(scenario_candidate)


def _parse_step_assertions(raw: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ScenarioError("assertions[{}]: expected mapping".format(idx))
        path = str(entry.get("path", "")).strip()
        if not path:
            raise ScenarioError("assertions[{}].path: expected non-empty string".format(idx))
        op = str(entry.get("op", "equals")).strip().lower()
        if op not in {"equals", "not_equals", "ge", "gt", "le", "lt", "exists", "in"}:
            raise ScenarioError(
                "assertions[{}].op: unsupported operator '{}'".format(idx, op)
            )
        parsed.append(
            {
                "path": path,
                "op": op,
                "value": entry.get("value"),
            }
        )
    return parsed


def evaluate_assertions(context: Dict[str, Any], assertions: Sequence[Dict[str, Any]]) -> List[str]:
    failures: List[str] = []
    for assertion in assertions:
        path = assertion["path"]
        op = assertion["op"]
        expected = assertion.get("value")
        actual = _lookup_path(context, path)
        if op == "exists":
            if actual is _MISSING:
                failures.append("{} missing".format(path))
            continue
        if actual is _MISSING:
            failures.append("{} missing".format(path))
            continue
        if op == "equals" and actual != expected:
            failures.append("{} expected {!r}, got {!r}".format(path, expected, actual))
        elif op == "not_equals" and actual == expected:
            failures.append("{} unexpectedly matched {!r}".format(path, expected))
        elif op == "in" and actual not in (expected or []):
            failures.append("{} expected one of {!r}, got {!r}".format(path, expected, actual))
        elif op == "ge" and not (actual >= expected):
            failures.append("{} expected >= {!r}, got {!r}".format(path, expected, actual))
        elif op == "gt" and not (actual > expected):
            failures.append("{} expected > {!r}, got {!r}".format(path, expected, actual))
        elif op == "le" and not (actual <= expected):
            failures.append("{} expected <= {!r}, got {!r}".format(path, expected, actual))
        elif op == "lt" and not (actual < expected):
            failures.append("{} expected < {!r}, got {!r}".format(path, expected, actual))
    return failures


def load_replay_spec(path: Path) -> Dict[str, Any]:
    data = _load_data(path)
    schema_version = int(data.get("schema_version", 0))
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ScenarioError(
            "Unsupported replay schema_version {} in {}".format(schema_version, path)
        )
    kind = str(data.get("kind", "replay")).strip().lower()
    if kind not in SUPPORTED_REPLAY_KINDS:
        raise ScenarioError("Unsupported replay kind '{}' in {}".format(kind, path))
    overrides = data.get("profile_overrides", {})
    if not isinstance(overrides, dict):
        raise ScenarioError("replay.profile_overrides must be a mapping in {}".format(path))
    return data


def apply_replay_to_profile(
    profile_raw: Dict[str, Any],
    replay_raw: Dict[str, Any],
    inline_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    merged = _deep_merge(profile_raw, replay_raw.get("profile_overrides", {}))
    if inline_overrides:
        merged = _deep_merge(merged, inline_overrides)
    return merged


def build_audit_command(
    repo_root: Path,
    profile_path: Path,
    output_path: Path,
    step_audit: Dict[str, Any],
    args: argparse.Namespace,
) -> List[str]:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "audit_bootloader.py"),
        "--profile",
        str(profile_path),
        "--output",
        str(output_path),
        "--no-assert-verdict",
        "--no-assert-control-boots",
    ]
    if args.renode_test:
        cmd.extend(["--renode-test", args.renode_test])
    if args.renode_remote_server_dir:
        cmd.extend(["--renode-remote-server-dir", args.renode_remote_server_dir])
    for robot_var in args.robot_var:
        cmd.extend(["--robot-var", robot_var])
    if step_audit.get("quick"):
        cmd.append("--quick")
    if step_audit.get("no_control"):
        cmd.append("--no-control")
    if step_audit.get("no_trace_replay"):
        cmd.append("--no-trace-replay")
    if step_audit.get("no_hash_bypass"):
        cmd.append("--no-hash-bypass")
    if step_audit.get("keep_run_artifacts") or args.keep_run_artifacts:
        cmd.append("--keep-run-artifacts")
    for key in ("fault_start", "fault_end", "fault_step", "workers", "max_batch_points"):
        value = step_audit.get(key)
        if value is not None:
            cmd.extend(["--{}".format(key.replace("_", "-")), str(value)])
    evaluation_mode = step_audit.get("evaluation_mode")
    if evaluation_mode:
        cmd.extend(["--evaluation-mode", str(evaluation_mode)])
    for robot_var in step_audit.get("robot_vars", []) or []:
        cmd.extend(["--robot-var", str(robot_var)])
    return cmd


def run_audit_step(
    repo_root: Path,
    scenario_dir: Path,
    default_base_profile_path: Path,
    step: Dict[str, Any],
    tempdir: Path,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    step_id = str(step.get("id") or "step")
    step_kind = str(step.get("kind", "audit")).strip().lower()
    step_audit = step.get("audit", {})
    if step_audit is None:
        step_audit = {}
    if not isinstance(step_audit, dict):
        raise ScenarioError("step {} audit: expected mapping".format(step_id))
    inline_overrides = step.get("profile_overrides", {})
    if inline_overrides is None:
        inline_overrides = {}
    if not isinstance(inline_overrides, dict):
        raise ScenarioError("step {} profile_overrides: expected mapping".format(step_id))

    step_base_profile_raw = step.get("base_profile")
    if step_base_profile_raw:
        base_profile_path = Path(
            _resolve_repo_or_scenario_path(repo_root, scenario_dir, str(step_base_profile_raw))
        )
    else:
        base_profile_path = default_base_profile_path
    profile_raw = dict(_load_data(base_profile_path))
    replay_meta: Optional[Dict[str, Any]] = None
    if step_kind == "replay":
        replay_file = step.get("replay_file")
        if replay_file:
            replay_raw = load_replay_spec(
                Path(_resolve_repo_or_scenario_path(repo_root, scenario_dir, str(replay_file)))
            )
        else:
            replay_inline = step.get("replay")
            if not isinstance(replay_inline, dict):
                raise ScenarioError(
                    "step {} replay: expected replay mapping or replay_file".format(step_id)
                )
            replay_raw = replay_inline
        profile_raw = apply_replay_to_profile(profile_raw, replay_raw, inline_overrides)
        replay_meta = {
            "name": replay_raw.get("name"),
            "description": replay_raw.get("description"),
            "source": replay_raw.get("source"),
        }
    else:
        profile_raw = _deep_merge(profile_raw, inline_overrides)

    step_profile = tempdir / "{}_profile.yaml".format(step_id)
    step_output = tempdir / "{}_report.json".format(step_id)
    step_profile.write_text(yaml.safe_dump(profile_raw, sort_keys=False), encoding="utf-8")

    cmd = build_audit_command(repo_root, step_profile, step_output, step_audit, args)
    _progress("starting step {} ({})".format(step_id, step_kind))
    _progress("profile {}".format(step_profile))
    proc_returncode, proc_stdout, proc_stderr = _run_command_streamed(cmd, repo_root)
    report: Optional[Dict[str, Any]] = None
    if step_output.exists():
        report = json.loads(step_output.read_text(encoding="utf-8"))
    if proc_returncode != 0 and report is None:
        raise RuntimeError(
            "audit step '{}' failed with exit {} and no report\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                step_id, proc_returncode, proc_stdout, proc_stderr
            )
        )
    _summarize_step_report(step_id, report)
    _progress(
        "completed step {} status={} exit={}".format(
            step_id,
            "PASS" if proc_returncode == 0 else "FAIL",
            proc_returncode,
        )
    )

    return {
        "id": step_id,
        "kind": step_kind,
        "base_profile": str(base_profile_path),
        "exit_code": proc_returncode,
        "status": "PASS" if proc_returncode == 0 else "FAIL",
        "command": cmd,
        "report": report,
        "stdout": proc_stdout,
        "stderr": proc_stderr,
        "replay": replay_meta,
    }


def load_scenario(path: Path) -> Dict[str, Any]:
    data = _load_data(path)
    schema_version = int(data.get("schema_version", 0))
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ScenarioError(
            "Unsupported scenario schema_version {} in {}".format(schema_version, path)
        )
    base_profile = str(data.get("base_profile", "")).strip()
    if not base_profile:
        raise ScenarioError("scenario.base_profile: expected non-empty string")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ScenarioError("scenario.steps: expected non-empty list")
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ScenarioError("steps[{}]: expected mapping".format(idx))
        kind = str(step.get("kind", "audit")).strip().lower()
        if kind not in SUPPORTED_STEP_KINDS:
            raise ScenarioError("steps[{}].kind: unsupported '{}'".format(idx, kind))
        step_id = str(step.get("id", "")).strip()
        if not step_id:
            raise ScenarioError("steps[{}].id: expected non-empty string".format(idx))
        if kind == "assert":
            assertions = step.get("assertions")
            if not isinstance(assertions, list) or not assertions:
                raise ScenarioError("steps[{}].assertions: expected non-empty list".format(idx))
    return data


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    scenario_path = Path(args.scenario).resolve()
    scenario_dir = scenario_path.parent
    scenario = load_scenario(scenario_path)
    base_profile_path = Path(
        _resolve_repo_or_scenario_path(repo_root, scenario_dir, str(scenario["base_profile"]))
    )

    results: Dict[str, Any] = {
        "scenario": {
            "name": scenario.get("name"),
            "path": str(scenario_path),
            "base_profile": str(base_profile_path),
        },
        "steps": {},
        "status": "PASS",
    }

    with tempfile.TemporaryDirectory(prefix="tardigrade_scenario_") as td:
        tempdir = Path(td)
        _progress("running scenario {}".format(scenario.get("name") or scenario_path.name))
        for step in scenario["steps"]:
            step_id = str(step["id"])
            kind = str(step.get("kind", "audit")).strip().lower()
            if kind in {"audit", "replay"}:
                step_result = run_audit_step(
                    repo_root=repo_root,
                    scenario_dir=scenario_dir,
                    default_base_profile_path=base_profile_path,
                    step=step,
                    tempdir=tempdir,
                    args=args,
                )
                if step_result["exit_code"] != 0:
                    results["status"] = "FAIL"
                results["steps"][step_id] = step_result
                continue

            assertions = _parse_step_assertions(step.get("assertions", []))
            failures = evaluate_assertions(results, assertions)
            step_result = {
                "id": step_id,
                "kind": kind,
                "assertions": assertions,
                "failures": failures,
                "status": "PASS" if not failures else "FAIL",
            }
            _progress(
                "completed step {} status={} failures={}".format(
                    step_id,
                    step_result["status"],
                    len(failures),
                )
            )
            if failures:
                results["status"] = "FAIL"
            results["steps"][step_id] = step_result

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(results, indent=2, sort_keys=True))
    return 1 if results["status"] != "PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main())
