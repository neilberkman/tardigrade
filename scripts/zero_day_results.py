#!/usr/bin/env python3
"""Collect MCUboot zero-day canary artifacts and render docs/zero-day-results.md.

Lists recent runs of ``mcuboot-head-zero-day.yml`` with ``gh run list`` and
``gh api``, downloads each run's artifacts, and renders one table row per
upstream MCUboot commit with per-profile verdicts and a link to the workflow
run.  Pass ``--from-dir`` to render directly from an existing directory of
downloaded or synthetic artifacts without network access.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from zero_day_summary import extract_summary_record


DEFAULT_WORKFLOW = "mcuboot-head-zero-day.yml"
DEFAULT_OUTPUT = Path("docs/zero-day-results.md")

CANONICAL_PROFILES: tuple[tuple[str, str], ...] = (
    ("mcuboot_head_move_nrf52_revert_full_fault_coverage", "move-nrf52-revert"),
    ("mcuboot_head_move_nrf52_upgrade_extended", "move-nrf52-upgrade"),
    ("mcuboot_head_offset_nrf52_revert_extended", "offset-nrf52-revert"),
    ("mcuboot_head_offset_nrf52_upgrade_multifault", "offset-nrf52-upgrade"),
    ("mcuboot_head_scratch_nrf52_revert_extended", "scratch-nrf52-revert"),
    ("mcuboot_head_scratch_nrf52_upgrade_extended", "scratch-nrf52-upgrade"),
    ("mcuboot_head_scratch_stm32f4_writeback", "scratch-stm32f4-writeback"),
)

PROFILE_TO_SLUG: dict[str, str] = {}
for _profile_name, _slug in CANONICAL_PROFILES:
    PROFILE_TO_SLUG[_profile_name] = _slug
    PROFILE_TO_SLUG[f"profiles/{_profile_name}.yaml"] = _slug
    PROFILE_TO_SLUG[_slug] = _slug

COMMIT_SUFFIX_RE = re.compile(r"([0-9a-f]{7,40})$")


def canonical_profile_slug(name: str | None) -> str | None:
    """Map a profile name, YAML path, or matrix slug to the table column slug."""
    if not isinstance(name, str) or not name.strip():
        return None
    cleaned = name.strip()
    if cleaned in PROFILE_TO_SLUG:
        return PROFILE_TO_SLUG[cleaned]
    stem = Path(cleaned).stem
    return PROFILE_TO_SLUG.get(stem, stem)


def _run_gh(args: list[str]) -> str:
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "gh command failed"
        raise RuntimeError(f"gh {' '.join(args)} failed: {detail}")
    return proc.stdout


def list_workflow_runs(
    *,
    workflow: str = DEFAULT_WORKFLOW,
    limit: int = 20,
    repo: str | None = None,
) -> list[dict[str, Any]]:
    """Return recent workflow runs from ``gh run list``."""
    cmd = [
        "run",
        "list",
        "--workflow",
        workflow,
        "--limit",
        str(limit),
        "--json",
        "databaseId,url,createdAt,status,conclusion,headSha",
    ]
    if repo:
        cmd.extend(["--repo", repo])
    output = _run_gh(cmd)
    payload = json.loads(output)
    if not isinstance(payload, list):
        raise ValueError("gh run list did not return a JSON list")
    return [item for item in payload if isinstance(item, dict)]


def list_run_artifacts(
    run_id: int | str,
    *,
    repo: str | None = None,
) -> list[dict[str, Any]]:
    """Return non-expired zero-day artifacts for *run_id* via ``gh api``."""
    repo_Token = repo if repo else "{owner}/{repo}"
    endpoint = f"repos/{repo_Token}/actions/runs/{run_id}/artifacts"
    output = _run_gh(["api", endpoint])
    payload = json.loads(output)
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        raise ValueError(f"gh api {endpoint} did not return an artifact list")
    selected: list[dict[str, Any]] = []
    for artifact in payload["artifacts"]:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("expired") is True:
            continue
        name = str(artifact.get("name", ""))
        if not name.startswith("mcuboot-zero-day"):
            continue
        selected.append(artifact)
    return selected


def download_workflow_artifacts(
    dest_dir: Path,
    *,
    workflow: str = DEFAULT_WORKFLOW,
    limit: int = 20,
    repo: str | None = None,
) -> Path:
    """Download recent workflow artifacts into *dest_dir* and return *dest_dir*."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    runs = list_workflow_runs(workflow=workflow, limit=limit, repo=repo)
    for run in runs:
        run_id = run.get("databaseId")
        if run_id is None:
            continue
        artifacts = list_run_artifacts(run_id, repo=repo)
        if not artifacts:
            continue
        run_dir = dest_dir / f"run-{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "run.json").write_text(
            json.dumps(run, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # Prefer the combined per-commit artifact when present so files are not
        # downloaded twice, otherwise download every per-profile artifact.
        combined = [
            art
            for art in artifacts
            if not any(
                str(art.get("name", "")).startswith(f"mcuboot-zero-day-{slug}")
                for _, slug in CANONICAL_PROFILES
            )
        ]
        to_download = combined if combined else artifacts
        for art in to_download:
            art_name = str(art.get("name", ""))
            if not art_name:
                continue
            target = run_dir / art_name
            target.mkdir(parents=True, exist_ok=True)
            cmd = [
                "run",
                "download",
                str(run_id),
                "--name",
                art_name,
                "--dir",
                str(target),
            ]
            if repo:
                cmd.extend(["--repo", repo])
            _run_gh(cmd)
    return dest_dir


def _find_nearest_file(start_dir: Path, root_dir: Path, relative_name: str) -> Path | None:
    current = start_dir
    while True:
        direct = current / relative_name
        if direct.is_file():
            return direct
        nested = current / "oss_validation" / "assets" / relative_name
        if nested.is_file():
            return nested
        results_nested = current / "results" / "oss_validation" / "assets" / relative_name
        if results_nested.is_file():
            return results_nested
        if current == root_dir or current.parent == current:
            break
        current = current.parent
    return None


def _find_run_metadata(start_dir: Path, root_dir: Path) -> dict[str, Any]:
    current = start_dir
    while True:
        candidate = current / "run.json"
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except (OSError, json.JSONDecodeError):
                pass
        if current == root_dir or current.parent == current:
            break
        current = current.parent
    return {}


def _infer_commit_from_path(path: Path, root_dir: Path) -> str | None:
    current = path.parent
    while True:
        match = COMMIT_SUFFIX_RE.search(current.name)
        if match and current.name.startswith("mcuboot-zero-day"):
            return match.group(1)
        if current == root_dir or current.parent == current:
            break
        current = current.parent
    return None


def _normalize_loaded_record(
    raw: Mapping[str, Any],
    *,
    run_meta: Mapping[str, Any],
    fallback_mcuboot: str | None = None,
    fallback_zephyr: str | None = None,
) -> dict[str, Any] | None:
    slug = canonical_profile_slug(str(raw.get("profile", "")))
    if not slug:
        return None
    mcuboot_commit = str(raw.get("mcuboot_commit") or "").strip()
    if not mcuboot_commit or mcuboot_commit == "unknown":
        mcuboot_commit = (fallback_mcuboot or "unknown").strip()
    zephyr_commit = str(raw.get("zephyr_commit") or "").strip()
    if not zephyr_commit or zephyr_commit == "unknown":
        zephyr_commit = (fallback_zephyr or "unknown").strip()

    sec_status = raw.get("security_status")
    if not isinstance(sec_status, str) or not sec_status.strip():
        sec_agg = raw.get("security_aggregate")
        if isinstance(sec_agg, Mapping):
            sec_status = str(sec_agg.get("status", "UNKNOWN"))
        else:
            sec_status = "UNKNOWN"

    run_id = raw.get("run_id") or run_meta.get("databaseId") or run_meta.get("run_id")
    run_url = raw.get("run_url") or run_meta.get("url") or run_meta.get("run_url")
    created_at = (
        raw.get("created_at")
        or run_meta.get("createdAt")
        or run_meta.get("created_at")
        or ""
    )

    verdict = str(raw.get("verdict", "UNKNOWN")).replace("\u2014", "--").strip()
    points = int(raw.get("points", raw.get("total_fault_points", 0)) or 0)
    issue_points = int(raw.get("issue_points", 0) or 0)
    bricks = int(raw.get("bricks", 0) or 0)
    timeouts = int(raw.get("timeouts", 0) or 0)
    wall_raw = raw.get("wall_time_s")
    wall_time_s = round(float(wall_raw), 1) if wall_raw is not None else 0.0

    return {
        "bricks": bricks,
        "created_at": str(created_at),
        "issue_points": issue_points,
        "mcuboot_commit": mcuboot_commit,
        "points": points,
        "profile": str(raw.get("profile", slug)),
        "run_id": int(run_id) if str(run_id or "").isdigit() else run_id,
        "run_url": str(run_url) if run_url else "",
        "security_status": sec_status.strip(),
        "slug": slug,
        "timeouts": timeouts,
        "verdict": verdict,
        "wall_time_s": wall_time_s,
        "zephyr_commit": zephyr_commit,
    }


def load_results_from_dir(root_dir: Path) -> list[dict[str, Any]]:
    """Load and aggregate per-commit zero-day results from *root_dir*."""
    if not root_dir.is_dir():
        raise ValueError(f"artifact directory does not exist: {root_dir}")

    collected: list[dict[str, Any]] = []

    for jsonl_path in sorted(root_dir.rglob("*.jsonl")):
        run_meta = _find_run_metadata(jsonl_path.parent, root_dir)
        mcuboot_file = _find_nearest_file(
            jsonl_path.parent, root_dir, "mcuboot_head_commit.txt"
        )
        zephyr_file = _find_nearest_file(
            jsonl_path.parent, root_dir, "zephyr_head_commit.txt"
        )
        fallback_mcuboot = (
            mcuboot_file.read_text(encoding="utf-8").strip()
            if mcuboot_file is not None
            else _infer_commit_from_path(jsonl_path, root_dir)
        )
        fallback_zephyr = (
            zephyr_file.read_text(encoding="utf-8").strip()
            if zephyr_file is not None
            else None
        )
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            raw = json.loads(stripped)
            if not isinstance(raw, dict):
                continue
            normalized = _normalize_loaded_record(
                raw,
                run_meta=run_meta,
                fallback_mcuboot=fallback_mcuboot,
                fallback_zephyr=fallback_zephyr,
            )
            if normalized is not None:
                collected.append(normalized)

    for json_path in sorted(root_dir.rglob("*.json")):
        if json_path.name == "run.json":
            continue
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if "verdict" not in payload or (
            "summary" not in payload and "profile" not in payload
        ):
            continue
        run_meta = _find_run_metadata(json_path.parent, root_dir)
        mcuboot_file = _find_nearest_file(
            json_path.parent, root_dir, "mcuboot_head_commit.txt"
        )
        zephyr_file = _find_nearest_file(
            json_path.parent, root_dir, "zephyr_head_commit.txt"
        )
        inferred_commit = _infer_commit_from_path(json_path, root_dir)
        record = extract_summary_record(
            json_path,
            mcuboot_commit=(
                None if mcuboot_file is not None else inferred_commit
            ),
            mcuboot_commit_file=mcuboot_file,
            zephyr_commit_file=zephyr_file,
        )
        normalized = _normalize_loaded_record(
            record,
            run_meta=run_meta,
            fallback_mcuboot=inferred_commit,
        )
        if normalized is not None:
            collected.append(normalized)

    by_commit: dict[str, dict[str, Any]] = {}
    for item in collected:
        commit = item["mcuboot_commit"]
        entry = by_commit.get(commit)
        if entry is None:
            entry = {
                "created_at": item["created_at"],
                "mcuboot_commit": commit,
                "profiles": {},
                "run_id": item["run_id"],
                "run_url": item["run_url"],
                "zephyr_commit": item["zephyr_commit"],
            }
            by_commit[commit] = entry

        if item["zephyr_commit"] != "unknown" and entry["zephyr_commit"] == "unknown":
            entry["zephyr_commit"] = item["zephyr_commit"]
        if item["created_at"] and item["created_at"] >= entry["created_at"]:
            entry["created_at"] = item["created_at"]
            if item["run_url"]:
                entry["run_url"] = item["run_url"]
            if item["run_id"]:
                entry["run_id"] = item["run_id"]
        else:
            if not entry["run_url"] and item["run_url"]:
                entry["run_url"] = item["run_url"]
            if not entry["run_id"] and item["run_id"]:
                entry["run_id"] = item["run_id"]

        slug = item["slug"]
        existing = entry["profiles"].get(slug)
        if existing is None or item["created_at"] >= existing.get("created_at", ""):
            entry["profiles"][slug] = item

    rows = list(by_commit.values())
    rows.sort(
        key=lambda row: (
            row.get("created_at") or "",
            str(row.get("run_id") or ""),
            row["mcuboot_commit"],
        ),
        reverse=True,
    )
    return rows


def format_profile_cell(record: Mapping[str, Any] | None) -> str:
    """Format a single profile verdict cell without em-dashes or parentheses."""
    if record is None:
        return "not run"
    verdict_raw = str(record.get("verdict", "UNKNOWN")).strip()
    verdict_head = verdict_raw.split()[0].rstrip(":,;").upper() if verdict_raw else "UNKNOWN"
    sec_status = str(record.get("security_status", "UNKNOWN")).strip()
    points = int(record.get("points", 0) or 0)
    issues = int(record.get("issue_points", 0) or 0)
    bricks = int(record.get("bricks", 0) or 0)
    timeouts = int(record.get("timeouts", 0) or 0)

    parts = [f"`{verdict_head}`", f"`{sec_status}`", f"{issues}/{points} issues"]
    if bricks:
        parts.append(f"{bricks} bricks")
    if timeouts:
        parts.append(f"{timeouts} timeouts")
    return ", ".join(parts)


def render_results_markdown(
    rows: Iterable[Mapping[str, Any]],
    *,
    synthetic_note: bool = False,
) -> str:
    """Render ``docs/zero-day-results.md`` from aggregated commit rows."""
    row_list = list(rows)
    slug_headers = [slug for _, slug in CANONICAL_PROFILES]

    lines: list[str] = [
        "# MCUboot HEAD zero-day canary results",
        "",
        "In `.github/workflows/mcuboot-head-zero-day.yml`, `scripts/zero_day_summary.py` records the upstream MCUboot commit, the paired Zephyr commit, and the seven zero-day canary profile verdicts, and `scripts/zero_day_results.py` formats one row per MCUboot commit with a link to the workflow run.",
        "",
    ]

    if synthetic_note:
        lines.extend(
            [
                "Note: `gh auth status` was not authenticated on the build host when this file was generated, so the table below was rendered from synthetic fixture artifacts. After authenticating `gh auth login`, run `python3 scripts/zero_day_results.py --output docs/zero-day-results.md` to refresh this document from live GitHub Actions workflow artifacts.",
                "",
            ]
        )

    header_cols = ["MCUboot commit", "Zephyr commit", "Run", *slug_headers]
    lines.append("| " + " | ".join(header_cols) + " |")
    lines.append("| " + " | ".join("---" for _ in header_cols) + " |")

    ref_links: list[str] = []
    seen_refs: set[str] = set()

    for index, row in enumerate(row_list, start=1):
        mcuboot_full = str(row.get("mcuboot_commit", "unknown"))
        mcuboot_short = mcuboot_full[:12] if mcuboot_full != "unknown" else "unknown"
        zephyr_full = str(row.get("zephyr_commit", "unknown"))
        zephyr_short = zephyr_full[:12] if zephyr_full != "unknown" else "unknown"

        run_id = row.get("run_id")
        run_url = str(row.get("run_url") or "").strip()
        if run_url:
            ref_id = f"run-{run_id}" if run_id is not None else f"run-{index}"
            label = f"run {run_id}" if run_id is not None else f"run {index}"
            run_cell = f"[{label}][{ref_id}]"
            if ref_id not in seen_refs:
                ref_links.append(f"[{ref_id}]: {run_url}")
                seen_refs.add(ref_id)
        elif run_id is not None:
            run_cell = f"run `{run_id}`"
        else:
            run_cell = "local"

        profiles_map = row.get("profiles")
        profiles_dict = profiles_map if isinstance(profiles_map, Mapping) else {}
        cells = [
            f"`{mcuboot_short}`",
            f"`{zephyr_short}`",
            run_cell,
        ]
        for _, slug in CANONICAL_PROFILES:
            cells.append(format_profile_cell(profiles_dict.get(slug)))
        lines.append("| " + " | ".join(cells) + " |")

    if ref_links:
        lines.append("")
        lines.extend(ref_links)

    lines.extend(
        [
            "",
            "## Regenerating this table",
            "",
            "Authenticate the GitHub CLI and run `scripts/zero_day_results.py` from the repository root:",
            "",
            "```bash",
            "gh auth status",
            "python3 scripts/zero_day_results.py --output docs/zero-day-results.md",
            "```",
            "",
            "To render from an existing directory of downloaded artifacts without network calls:",
            "",
            "```bash",
            "python3 scripts/zero_day_results.py --from-dir path/to/artifacts --output docs/zero-day-results.md",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def write_synthetic_fixtures(target_dir: Path) -> Path:
    """Populate *target_dir* with two synthetic workflow run artifact trees."""
    runs_spec = [
        {
            "run_id": 24019002,
            "created_at": "2026-10-17T09:00:00Z",
            "url": "https://github.com/xuku/tardigrade/actions/runs/24019002",
            "mcuboot_commit": "f84b9d3fd019fb1945e532924bee7a9c03c77373",
            "zephyr_commit": "36940db938a8f4a1e919496793ed439850a221c2",
            "writeback_verdict": "PASS -- found 1 expected issue point",
            "writeback_status": "FINDINGS",
            "writeback_issues": 1,
        },
        {
            "run_id": 23981001,
            "created_at": "2026-10-10T09:00:00Z",
            "url": "https://github.com/xuku/tardigrade/actions/runs/23981001",
            "mcuboot_commit": "5c039f4842cf9e88d5d33f7d4d2c71b08a18e921",
            "zephyr_commit": "e35b686be50a4c7d82a9b1031e5f7c92a4018d12",
            "writeback_verdict": "FAIL -- found 1 issue point",
            "writeback_status": "FINDINGS",
            "writeback_issues": 1,
        },
    ]

    for spec in runs_spec:
        run_dir = target_dir / f"run-{spec['run_id']}"
        art_dir = (
            run_dir
            / f"mcuboot-zero-day-{spec['mcuboot_commit']}"
        )
        assets_dir = art_dir / "results" / "oss_validation" / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "conclusion": "success",
                    "createdAt": spec["created_at"],
                    "databaseId": spec["run_id"],
                    "status": "completed",
                    "url": spec["url"],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (assets_dir / "mcuboot_head_commit.txt").write_text(
            spec["mcuboot_commit"] + "\n",
            encoding="utf-8",
        )
        (assets_dir / "zephyr_head_commit.txt").write_text(
            spec["zephyr_commit"] + "\n",
            encoding="utf-8",
        )

        for profile_name, slug in CANONICAL_PROFILES:
            is_writeback = slug == "scratch-stm32f4-writeback"
            verdict = (
                spec["writeback_verdict"]
                if is_writeback
                else "PASS -- all 3 fault points recovered"
            )
            sec_status = spec["writeback_status"] if is_writeback else "CLEAN"
            issues = spec["writeback_issues"] if is_writeback else 0
            wall_s = 148.4 if is_writeback else 92.5

            report_path = art_dir / "results" / f"{profile_name}.json"
            jsonl_path = art_dir / "results" / f"{profile_name}.jsonl"
            report_payload = {
                "expect": {"should_find_issues": is_writeback},
                "profile": profile_name,
                "security_aggregate": {
                    "brick_rate": 0.0,
                    "finding_sources": {"runtime_sweep": issues} if issues else {},
                    "inconclusive_reasons": [],
                    "issue_points": issues,
                    "schema_version": 1,
                    "security_bypass_points": 0,
                    "security_bypass_sources": {},
                    "status": sec_status,
                },
                "summary": {
                    "runtime_sweep": {
                        "brick_rate": 0.0,
                        "bricks": 0,
                        "campaign_complete": True,
                        "campaign_integrity": {
                            "complete": True,
                            "control_timeouts": 0,
                            "timeouts": 0,
                        },
                        "issue_points": issues,
                        "timeout_points": 0,
                        "total_fault_points": 3,
                        "wall_time_s": wall_s,
                    }
                },
                "verdict": verdict,
            }
            report_path.write_text(
                json.dumps(report_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            record = extract_summary_record(
                report_path,
                mcuboot_commit_file=assets_dir / "mcuboot_head_commit.txt",
                zephyr_commit_file=assets_dir / "zephyr_head_commit.txt",
            )
            jsonl_path.write_text(
                json.dumps(record, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    return target_dir


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-dir",
        type=Path,
        default=None,
        help="Render from an existing directory of downloaded artifacts without network",
    )
    parser.add_argument(
        "--write-synthetic-fixtures",
        type=Path,
        default=None,
        help="Populate the given directory with synthetic artifacts before rendering",
    )
    parser.add_argument(
        "--synthetic-note",
        action="store_true",
        help="Include a note in the rendered Markdown stating synthetic fixtures were used",
    )
    parser.add_argument(
        "--workflow",
        default=DEFAULT_WORKFLOW,
        help="Workflow file name for gh run list",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of recent workflow runs to inspect",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Optional owner/name repository override for gh commands",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output Markdown path",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.write_synthetic_fixtures is not None:
        write_synthetic_fixtures(args.write_synthetic_fixtures)
        source_dir = args.from_dir or args.write_synthetic_fixtures
        rows = load_results_from_dir(source_dir)
        markdown = render_results_markdown(
            rows,
            synthetic_note=True,
        )
    elif args.from_dir is not None:
        rows = load_results_from_dir(args.from_dir)
        markdown = render_results_markdown(
            rows,
            synthetic_note=args.synthetic_note,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="zero_day_artifacts_") as tmp_dir:
            download_root = download_workflow_artifacts(
                Path(tmp_dir),
                workflow=args.workflow,
                limit=args.limit,
                repo=args.repo,
            )
            rows = load_results_from_dir(download_root)
            markdown = render_results_markdown(
                rows,
                synthetic_note=args.synthetic_note,
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
