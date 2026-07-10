#!/usr/bin/env python3
"""Small, testable helpers used by the Tardigrade composite action.

GitHub Action inputs are data, never Python or shell source.  Keeping input
validation and report parsing here lets ``action.yml`` pass every caller value
through an argv boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, TextIO

from verdicts import is_pass_verdict


SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


def validate_https_url(value: str) -> str:
    """Return *value* when it is an absolute HTTPS URL without credentials."""
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Renode URL must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Renode URL must not contain credentials")
    return value


def validate_sha256(value: str) -> str:
    """Validate and normalize a hexadecimal SHA-256 digest."""
    digest = value.strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("Renode SHA-256 must contain exactly 64 hexadecimal characters")
    return digest


def parse_bool(value: str, *, name: str) -> bool:
    """Parse a strict Action boolean input."""
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError("{} must be 'true' or 'false'".format(name))


def parse_workers(value: str, *, maximum: int = 64) -> int:
    """Parse a bounded worker count."""
    if not re.fullmatch(r"[0-9]+", value.strip()):
        raise ValueError("workers must be an integer")
    workers = int(value)
    if workers < 1 or workers > maximum:
        raise ValueError("workers must be between 1 and {}".format(maximum))
    return workers


def parse_positive_int(value: str, *, name: str, maximum: int) -> int:
    """Parse a strictly positive, bounded decimal integer."""
    normalized = value.strip()
    if not re.fullmatch(r"[0-9]+", normalized):
        raise ValueError("{} must be a positive decimal integer".format(name))
    parsed = int(normalized)
    if parsed < 1 or parsed > maximum:
        raise ValueError("{} must be between 1 and {}".format(name, maximum))
    return parsed


def validate_git_ref(value: str, *, name: str) -> str:
    """Return a conservative public Git ref or full commit identifier."""
    ref = value.strip()
    if not GIT_REF_RE.fullmatch(ref):
        raise ValueError("{} contains unsupported characters".format(name))
    if ".." in ref or "//" in ref or ref.endswith(("/", ".")):
        raise ValueError("{} is not a valid Git ref".format(name))
    return ref


def validate_runner(os_name: str, arch: str) -> tuple[str, str]:
    """Require the platform supported by the bundled Renode archive."""
    normalized_os = os_name.strip().lower()
    normalized_arch = arch.strip().lower()
    if normalized_os != "linux" or normalized_arch not in {"x64", "amd64", "x86_64"}:
        raise ValueError(
            "Tardigrade Action supports Linux x86-64 runners; got {}/{}".format(
                os_name,
                arch,
            )
        )
    return "Linux", "X64"


def resolve_workspace_path(
    workspace: str,
    value: str,
    *,
    kind: str,
) -> Path:
    """Resolve a caller path and require it to remain inside the workspace."""
    root = Path(workspace).resolve(strict=True)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes the GitHub workspace: {}".format(value)) from exc

    if kind == "file" and not resolved.is_file():
        raise ValueError("expected a file: {}".format(value))
    if kind == "directory" and not resolved.is_dir():
        raise ValueError("expected a directory: {}".format(value))
    return resolved


def download_verified(url: str, expected_sha256: str, output: Path) -> None:
    """Download *url* to *output* and atomically publish it after verification."""
    url = validate_https_url(url)
    expected_sha256 = validate_sha256(expected_sha256)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".{}-".format(output.name),
            suffix=".download",
            dir=str(output.parent),
            delete=False,
        ) as temp_file:
            temp_name = temp_file.name
            digest = hashlib.sha256()
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "tardigrade-github-action"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                validate_https_url(response.geturl())
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    temp_file.write(chunk)
                    digest.update(chunk)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ValueError(
                "Renode archive SHA-256 mismatch: expected {}, got {}".format(
                    expected_sha256,
                    actual,
                )
            )
        os.replace(temp_name, output)
        temp_name = None
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def select_github_release_asset(
    payload: Any,
    *,
    asset_suffix: str,
) -> tuple[str, str, str]:
    """Return ``(name, URL, digest)`` for one GitHub release asset."""
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise ValueError("GitHub release response does not contain an asset list")
    matches = [
        asset
        for asset in payload["assets"]
        if isinstance(asset, dict)
        and str(asset.get("name", "")).endswith(asset_suffix)
    ]
    if len(matches) != 1:
        raise ValueError(
            "expected one GitHub release asset ending in {!r}, found {}".format(
                asset_suffix,
                len(matches),
            )
        )
    asset = matches[0]
    name = str(asset.get("name", ""))
    url = validate_https_url(str(asset.get("browser_download_url", "")))
    published_digest = str(asset.get("digest", ""))
    if not published_digest.startswith("sha256:"):
        raise ValueError("GitHub release asset does not publish a SHA-256 digest")
    digest = validate_sha256(published_digest.split(":", 1)[1])
    return name, url, digest


def download_latest_github_release(
    repository: str,
    asset_suffix: str,
    output: Path,
) -> str:
    """Download and verify one asset from an open GitHub project's latest release."""
    if not GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise ValueError("GitHub repository must use the owner/name form")
    api_url = "https://api.github.com/repos/{}/releases/latest".format(repository)
    request = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "tardigrade-github-action",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        validate_https_url(response.geturl())
        payload = json.loads(response.read())
    name, url, digest = select_github_release_asset(
        payload,
        asset_suffix=asset_suffix,
    )
    download_verified(url, digest, output)
    return name


def _github_output_line(stream: TextIO, name: str, value: Any) -> None:
    text = str(value)
    if "\n" in text or "\r" in text:
        raise ValueError("GitHub output '{}' contains a newline".format(name))
    stream.write("{}={}\n".format(name, text))


def publish_report(report_path: Path, output_path: Path, audit_exit: int) -> bool:
    """Publish sanitized Action outputs and return whether the audit passed."""
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    verdict_value = payload.get("verdict")
    if not isinstance(verdict_value, str) or not verdict_value.strip():
        raise ValueError("report verdict must be a non-empty string")
    report_passed = is_pass_verdict(verdict_value)
    passed = report_passed and audit_exit == 0
    runtime = payload.get("summary", {}).get("runtime_sweep", {})
    brick_rate = runtime.get("brick_rate", 0)
    if not isinstance(brick_rate, (int, float)) or isinstance(brick_rate, bool):
        raise ValueError("report brick_rate must be numeric")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as stream:
        _github_output_line(stream, "verdict", "PASS" if passed else "FAIL")
        _github_output_line(stream, "brick_rate", brick_rate)
        _github_output_line(stream, "report_path", report_path)
    return passed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    download = subparsers.add_parser("download-renode")
    download.add_argument("--url", required=True)
    download.add_argument("--sha256", required=True)
    download.add_argument("--output", required=True)

    latest = subparsers.add_parser("download-latest-github-release")
    latest.add_argument("--repository", required=True)
    latest.add_argument("--asset-suffix", required=True)
    latest.add_argument("--output", required=True)

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--workspace", required=True)
    resolve.add_argument("--path", required=True)
    resolve.add_argument("--kind", choices=("file", "directory"), required=True)

    validate = subparsers.add_parser("validate-run-inputs")
    validate.add_argument("--quick", required=True)
    validate.add_argument("--workers", required=True)

    normalize_bool = subparsers.add_parser("normalize-bool")
    normalize_bool.add_argument("--name", required=True)
    normalize_bool.add_argument("--value", required=True)

    normalize_int = subparsers.add_parser("normalize-positive-int")
    normalize_int.add_argument("--name", required=True)
    normalize_int.add_argument("--value", required=True)
    normalize_int.add_argument("--maximum", required=True, type=int)

    normalize_ref = subparsers.add_parser("normalize-git-ref")
    normalize_ref.add_argument("--name", required=True)
    normalize_ref.add_argument("--value", required=True)

    runner = subparsers.add_parser("validate-runner")
    runner.add_argument("--os", required=True)
    runner.add_argument("--arch", required=True)

    report = subparsers.add_parser("publish-report")
    report.add_argument("--report", required=True)
    report.add_argument("--github-output", required=True)
    report.add_argument("--audit-exit", required=True, type=int)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        if args.command == "download-renode":
            download_verified(args.url, args.sha256, Path(args.output))
        elif args.command == "download-latest-github-release":
            name = download_latest_github_release(
                args.repository,
                args.asset_suffix,
                Path(args.output),
            )
            print("verified GitHub release asset: {}".format(name))
        elif args.command == "resolve":
            print(resolve_workspace_path(args.workspace, args.path, kind=args.kind))
        elif args.command == "validate-run-inputs":
            quick = parse_bool(args.quick, name="quick")
            workers = parse_workers(args.workers)
            print(json.dumps({"quick": quick, "workers": workers}, sort_keys=True))
        elif args.command == "normalize-bool":
            print("true" if parse_bool(args.value, name=args.name) else "false")
        elif args.command == "normalize-positive-int":
            print(parse_positive_int(args.value, name=args.name, maximum=args.maximum))
        elif args.command == "normalize-git-ref":
            print(validate_git_ref(args.value, name=args.name))
        elif args.command == "validate-runner":
            os_name, arch = validate_runner(args.os, args.arch)
            print("{}/{}".format(os_name, arch))
        elif args.command == "publish-report":
            passed = publish_report(
                Path(args.report),
                Path(args.github_output),
                args.audit_exit,
            )
            return 0 if passed else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("ERROR: {}".format(exc), file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
