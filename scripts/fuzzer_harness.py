#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Preflight qualification for black-box parser fuzzer harnesses.

The preflight runs one known-valid seed and one known-invalid control before a
fuzzer campaign.  It accepts JSON evidence with a declared boolean field
(usually ``accepted``), or output markers declared by the caller. The harness
process must always exit successfully; non-zero exits are infrastructure
failures.
Any setup error, timeout, abort, non-zero exit, malformed evidence, or control
that does not produce its expected result is classified as
``INFRASTRUCTURE_FAILURE``.  Preflight never emits a product finding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


DEFAULT_TIMEOUT_SECONDS = 10.0
ALLOWED_PLACEHOLDERS = ("{input}",)


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-standard JSON constant {!r}".format(value))


class HarnessPreflightError(ValueError):
    """Raised when a preflight declaration is invalid."""


@dataclass(frozen=True)
class CaseExpectation:
    name: str
    outcome: bool | None = None
    exit_code: int = 0
    stdout_contains: str | None = None
    stderr_contains: str | None = None


@dataclass(frozen=True)
class CaseResult:
    name: str
    status: str
    reason: str
    returncode: int | None = None
    evidence: Mapping[str, Any] | None = None


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise HarnessPreflightError("{} must be a non-empty string".format(context))
    return value.strip()


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HarnessPreflightError("{} must be a mapping".format(context))
    return value


def _expectation(raw: Any, context: str) -> CaseExpectation:
    value = _mapping(raw, context)
    allowed = {"outcome", "exit_code", "stdout_contains", "stderr_contains"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise HarnessPreflightError("{} has unknown field(s): {}".format(context, ", ".join(unknown)))
    outcome = value.get("outcome")
    if outcome is not None and not isinstance(outcome, bool):
        raise HarnessPreflightError("{}.outcome must be boolean when provided".format(context))
    exit_code = value.get("exit_code", 0)
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise HarnessPreflightError("{}.exit_code must be an integer".format(context))
    if exit_code != 0:
        raise HarnessPreflightError("{}.exit_code must be 0; non-zero exits are infrastructure failures".format(context))
    stdout = value.get("stdout_contains")
    stderr = value.get("stderr_contains")
    if stdout is not None:
        stdout = _text(stdout, context + ".stdout_contains")
    if stderr is not None:
        stderr = _text(stderr, context + ".stderr_contains")
    if outcome is None and stdout is None and stderr is None:
        raise HarnessPreflightError("{} must declare outcome or output evidence".format(context))
    return CaseExpectation(context.rsplit(".", 1)[-1], outcome, exit_code, stdout, stderr)


def _validate_config(raw: Mapping[str, Any], *, base_dir: Path | None = None) -> dict[str, Any]:
    root = _mapping(raw, "config")
    allowed = {"command", "valid_seed", "invalid_seed", "valid", "invalid", "timeout_seconds", "cwd", "outcome_field"}
    unknown = sorted(set(root) - allowed)
    if unknown:
        raise HarnessPreflightError("config has unknown field(s): {}".format(", ".join(unknown)))
    command = root.get("command")
    if not isinstance(command, list) or not command or not all(
        isinstance(x, str) and x.strip() and "\x00" not in x for x in command
    ):
        raise HarnessPreflightError("command must be a non-empty list of strings")
    if not any("{input}" in token for token in command):
        raise HarnessPreflightError("command must include the {input} placeholder")
    for token in command:
        for placeholder in re.findall(r"\{[^{}]*\}", token):
            if placeholder not in ALLOWED_PLACEHOLDERS:
                raise HarnessPreflightError("command contains an unknown placeholder")
    root_dir = (base_dir or Path.cwd()).resolve()
    valid_seed = Path(_text(root.get("valid_seed"), "valid_seed"))
    invalid_seed = Path(_text(root.get("invalid_seed"), "invalid_seed"))
    if not valid_seed.is_absolute():
        valid_seed = root_dir / valid_seed
    if not invalid_seed.is_absolute():
        invalid_seed = root_dir / invalid_seed
    timeout = root.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise HarnessPreflightError("timeout_seconds must be finite and positive")
    cwd = root.get("cwd")
    if cwd is not None:
        cwd = _text(cwd, "cwd")
        cwd_path = Path(cwd)
        if not cwd_path.is_absolute():
            cwd = str(root_dir / cwd_path)
    field = root.get("outcome_field", "accepted")
    field = _text(field, "outcome_field")
    return {
        "command": list(command), "valid_seed": valid_seed, "invalid_seed": invalid_seed,
        "valid": _expectation(root.get("valid"), "valid"),
        "invalid": _expectation(root.get("invalid"), "invalid"),
        "timeout_seconds": float(timeout), "cwd": cwd, "outcome_field": field,
    }


def _render(command: Sequence[str], input_path: Path) -> list[str]:
    return [token.replace("{input}", str(input_path)) for token in command]


def _run_case(config: Mapping[str, Any], expectation: CaseExpectation, input_path: Path) -> CaseResult:
    if not input_path.is_file():
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "seed does not exist: {}".format(input_path))
    cwd = Path(config["cwd"]) if config["cwd"] else Path.cwd()
    try:
        result = subprocess.run(
            _render(config["command"], input_path),
            cwd=str(cwd.resolve()), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=config["timeout_seconds"], check=False,
        )
    except subprocess.TimeoutExpired:
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "harness timed out")
    except UnicodeDecodeError as exc:
        return CaseResult(
            expectation.name,
            "INFRASTRUCTURE_FAILURE",
            "harness output is not UTF-8: {}".format(exc),
        )
    except (OSError, ValueError) as exc:
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "harness could not start: {}".format(exc))
    if result.returncode != expectation.exit_code:
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "expected exit {}, got {}".format(expectation.exit_code, result.returncode), result.returncode)
    if expectation.stdout_contains and expectation.stdout_contains not in result.stdout:
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "expected stdout marker is absent", result.returncode)
    if expectation.stderr_contains and expectation.stderr_contains not in result.stderr:
        return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "expected stderr marker is absent", result.returncode)
    evidence: Mapping[str, Any] | None = None
    if expectation.outcome is not None:
        try:
            parsed = json.loads(result.stdout, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError):
            return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "harness output is not JSON", result.returncode)
        if not isinstance(parsed, Mapping) or config["outcome_field"] not in parsed or not isinstance(parsed[config["outcome_field"]], bool):
            return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "harness JSON lacks boolean '{}'".format(config["outcome_field"]), result.returncode)
        evidence = parsed
        if parsed[config["outcome_field"]] != expectation.outcome:
            return CaseResult(expectation.name, "INFRASTRUCTURE_FAILURE", "declared outcome was not observed", result.returncode, evidence)
    return CaseResult(expectation.name, "PASS", "expected control behavior observed", result.returncode, evidence)


def _require_distinguishable_controls(normalized: Mapping[str, Any]) -> None:
    valid = normalized["valid"]
    invalid = normalized["invalid"]
    if valid.outcome is not None and invalid.outcome is not None:
        if valid.outcome == invalid.outcome:
            raise HarnessPreflightError("valid and invalid controls must declare opposite outcomes")
        return
    valid_signature = (valid.outcome, valid.exit_code, valid.stdout_contains, valid.stderr_contains)
    invalid_signature = (invalid.outcome, invalid.exit_code, invalid.stdout_contains, invalid.stderr_contains)
    if valid_signature == invalid_signature:
        raise HarnessPreflightError("valid and invalid controls must have distinguishable expectations")


def _run_seed_controls(normalized: Mapping[str, Any]) -> tuple[list[CaseResult], dict[str, str]]:
    """Read and stage controls, keeping seed/setup failures non-fatal."""
    paths = {"valid": normalized["valid_seed"], "invalid": normalized["invalid_seed"]}
    expectations = {"valid": normalized["valid"], "invalid": normalized["invalid"]}
    seed_bytes: dict[str, bytes] = {}
    seed_errors: dict[str, str] = {}
    for name, path in paths.items():
        try:
            if path.is_file():
                seed_bytes[name] = path.read_bytes()
        except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
            seed_errors[name] = "seed could not be read: {} ({})".format(path, exc)

    digests: dict[str, str] = {}
    if len(seed_bytes) == len(paths):
        digests = {
            name: hashlib.sha256(data).hexdigest() for name, data in seed_bytes.items()
        }
        if digests["valid"] == digests["invalid"]:
            raise HarnessPreflightError(
                "valid and invalid seeds are byte-identical (sha256 {})".format(
                    digests["valid"]
                )
            )

    def run_with_paths(input_paths: Mapping[str, Path]) -> list[CaseResult]:
        results = []
        for name in ("valid", "invalid"):
            if name in seed_errors:
                results.append(
                    CaseResult(name, "INFRASTRUCTURE_FAILURE", seed_errors[name])
                )
            else:
                results.append(
                    _run_case(normalized, expectations[name], input_paths[name])
                )
        return results

    # Stage every readable control, including when its peer is missing. This
    # prevents a harness from learning the case from the source filename.
    if not seed_bytes:
        return run_with_paths(paths), digests
    try:
        with tempfile.TemporaryDirectory(prefix="tardigrade-preflight-") as directory:
            staged_paths: dict[str, Path] = {}
            for name, data in seed_bytes.items():
                with tempfile.NamedTemporaryFile(
                    dir=directory, prefix="seed-", delete=False
                ) as staged:
                    staged.write(data)
                    staged_paths[name] = Path(staged.name)
            input_paths = {
                name: staged_paths.get(name, path) for name, path in paths.items()
            }
            return run_with_paths(input_paths), digests
    except (OSError, ValueError) as exc:
        reason = "seed staging failed: {}".format(exc)
        return [
            CaseResult(name, "INFRASTRUCTURE_FAILURE", reason)
            for name in ("valid", "invalid")
        ], digests


def qualify_harness(config: Mapping[str, Any], *, base_dir: Path | None = None) -> dict[str, Any]:
    """Run valid and invalid controls, returning a non-finding report."""
    normalized = _validate_config(config, base_dir=base_dir)
    _require_distinguishable_controls(normalized)
    results, digests = _run_seed_controls(normalized)
    passed = all(item.status == "PASS" for item in results)
    return {
        "status": "PASS" if passed else "INFRASTRUCTURE_FAILURE",
        "product_findings": [],
        "cases": [item.__dict__ for item in results],
        "command": list(normalized["command"]),
        "seed_sha256": digests or {},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        import yaml
        raw = yaml.safe_load(args.config.read_text(encoding="utf-8"))
        result = qualify_harness(raw, base_dir=args.config.resolve().parent)
    except Exception as exc:
        result = {"status": "INFRASTRUCTURE_FAILURE", "product_findings": [], "error": str(exc), "cases": []}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["status"])
        for case in result.get("cases", []):
            print("{}: {} ({})".format(case["name"], case["status"], case["reason"]))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
