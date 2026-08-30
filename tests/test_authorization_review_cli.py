"""Direct CLI regression for the authorization-review analyzer."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent


def test_direct_cli_uses_one_analyzer_module_instance():
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "authorization_review_analyzer.py"),
            "--profile",
            str(ROOT / "profiles" / "authorization_review_fixed.yaml"),
            "--trace",
            str(ROOT / "examples" / "authorization_review" / "fixed_trace.json"),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verdict"] == "PASS"


def test_cli_emits_incomplete_templates_without_verdict(tmp_path):
    output_dir = tmp_path / "templates"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "authorization_review_analyzer.py"),
            "--profile",
            str(ROOT / "profiles" / "authorization_review_fixed.yaml"),
            "--emit-trace-template-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "incomplete observations" in result.stdout
    assert "Verdict" not in result.stdout
    paths = sorted(output_dir.glob("*.json"))
    assert [path.name for path in paths] == ["0000-normal.json"]
    template = json.loads(paths[0].read_text(encoding="utf-8"))
    assert template["sequence"] == "normal"
    assert all(event["complete"] is False for event in template["events"])


def test_cli_emits_and_reanalyzes_all_variants_with_repeated_trace(tmp_path):
    profile_path = tmp_path / "multi_variant.yaml"
    profile_path.write_text(
        (ROOT / "profiles" / "authorization_review_fixed.yaml")
        .read_text(encoding="utf-8")
        .replace(
            "events: [parse, review, digest, signature, authorize]",
            "events: [parse, {event: review, optional: true}, digest, signature, authorize]",
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "templates"
    emit = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "authorization_review_analyzer.py"),
            "--profile",
            str(profile_path),
            "--emit-trace-template-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert emit.returncode == 0, emit.stderr
    paths = sorted(output_dir.glob("*.json"))
    assert [path.name for path in paths] == [
        "0000-normal-without-0-1.json",
        "0001-normal.json",
    ]
    analyze_args = [
        sys.executable,
        str(ROOT / "scripts" / "authorization_review_analyzer.py"),
        "--profile",
        str(profile_path),
    ]
    for path in paths:
        analyze_args.extend(["--trace", str(path)])
    analyze = subprocess.run(
        analyze_args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert analyze.returncode != 0
    assert "Verdict: INCONCLUSIVE" in analyze.stdout
    assert "2 traces" in analyze.stdout


def test_cli_rejects_template_emission_with_trace(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "authorization_review_analyzer.py"),
            "--profile",
            str(ROOT / "profiles" / "authorization_review_fixed.yaml"),
            "--trace",
            str(ROOT / "examples" / "authorization_review" / "fixed_trace.json"),
            "--emit-trace-template-dir",
            str(tmp_path / "templates"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr


def test_cli_does_not_overwrite_existing_template(tmp_path):
    output_dir = tmp_path / "templates"
    output_dir.mkdir()
    existing = output_dir / "0000-normal.json"
    existing.write_text("keep me\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "authorization_review_analyzer.py"),
            "--profile",
            str(ROOT / "profiles" / "authorization_review_fixed.yaml"),
            "--emit-trace-template-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "already exists" in result.stderr
    assert existing.read_text(encoding="utf-8") == "keep me\n"
