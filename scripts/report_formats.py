# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Optional audit report outputs, also usable on previously saved JSON."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from report_points import ReportRun

FORMATS = ("junit", "sarif", "html")


def add_report_options(parser):
    for name in FORMATS:
        parser.add_argument("--" + name, type=Path, metavar="FILE",
                            help=f"Also write a {name.upper()} report to FILE.")


def validate_report_paths(parser, args, inputs=()):
    reserved = {Path(p).resolve() for p in inputs if p}
    if getattr(args, "output", None):
        reserved.add(Path(args.output).resolve())
    for name in FORMATS:
        path = vars(args).get(name)
        if path:
            if path.resolve() in reserved:
                parser.error(f"--{name} must have a distinct output path")
            reserved.add(path.resolve())


def requested(args):
    return any(vars(args).get(name) for name in FORMATS)


def write_formats(args, runs, root):
    """Serialize only requested formats. The audit JSON is already on disk."""
    if getattr(args, "junit", None):
        from report_junit import junit_report
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        args.junit.write_text(junit_report(runs), encoding="utf-8")
    if getattr(args, "sarif", None):
        from report_sarif import sarif_report
        location_root = Path(os.environ.get("GITHUB_WORKSPACE") or root)
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps(sarif_report(runs, location_root), indent=2) + "\n", encoding="utf-8")
    if getattr(args, "html", None):
        from render_results_html import write_html
        write_html([(r.profile_path or Path(r.name), {**r.data, "profile": r.name}) for r in runs],
                   args.html, vars(args).get("clause_mapping"))


def profile_run(args, data, profile, root, name=None):
    elf = None
    if args.sarif and profile.bootloader_elf:
        elf = Path(profile.resolve_path(root, profile.bootloader_elf))
    return ReportRun(data, name or profile.name, Path(args.profile).resolve(), elf)


def write_audit_report(args, data, profile, root, runs=None):
    from clause_evidence import clause_evidence
    data = {**data, "clause_evidence": clause_evidence(data, vars(args).get("clause_mapping"))}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    if requested(args):
        if runs is None:
            runs = [profile_run(args, data, profile, root)]
        write_formats(args, runs, root)


def child_report_args(args, output):
    """Keep machine-readable child results while the orchestration tempdir exists."""
    options = []
    for name in ("junit", "sarif"):
        if vars(args).get(name):
            options.extend(["--" + name, str(output.with_suffix("." + name))])
    return options


def collect_child_reports(args, children, root=None):
    """Combine suites and SARIF runs while preserving matrix child detail.

    Each entry provides a run label, its temporary JSON path, the permanent
    profile path, and the reason to surface if that child produced no report.
    """
    from xml.etree import ElementTree as ET
    from report_junit import junit_report
    from report_sarif import SARIF_SCHEMA, SourceLocations

    locations = SourceLocations(None, Path(os.environ.get("GITHUB_WORKSPACE") or root or Path.cwd()))
    suites = ET.Element("testsuites")
    sarif_runs = []
    for label, path, profile, reason in children:
        for name in ("junit", "sarif"):
            if not vars(args).get(name):
                continue
            source = path.with_suffix("." + name)
            if name == "junit":
                if source.is_file():
                    suites.extend(ET.parse(source).getroot())
                else:
                    missing = ReportRun({"verdict": "INCONCLUSIVE", "error": reason}, label, profile)
                    suites.extend(ET.fromstring(junit_report([missing])))
            elif source.is_file():
                child_runs = json.loads(source.read_text(encoding="utf-8"))["runs"]
                for child in child_runs:
                    child["automationDetails"]["id"] = label + "/" + child["automationDetails"]["id"]
                    if root is not None:
                        # Scenario overrides are materialized in this temporary sibling.
                        temporary = locations.uri(path.with_name(label + "_profile.yaml"))
                        for result in child["results"]:
                            artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
                            if artifact["uri"] == temporary:
                                artifact["uri"] = locations.uri(profile)
                sarif_runs.extend(child_runs)
            else:
                sarif_runs.append({"tool": {"driver": {"name": "Tardigrade"}}, "results": [],
                                   "automationDetails": {"id": label + "/"},
                                   "invocations": [{"executionSuccessful": False,
                                                    "toolExecutionNotifications": [{"message": {"text": reason}}]}]})
    if args.junit:
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        ET.indent(suites)
        suites_tree = ET.ElementTree(suites)
        suites_tree.write(args.junit, encoding="utf-8", xml_declaration=True)
    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps({"version": "2.1.0", "$schema": SARIF_SCHEMA, "runs": sarif_runs},
                                         indent=2) + "\n", encoding="utf-8")


def saved_run(data, path, root, profile_path=None, elf=None, name=None):
    from render_results_html import classify_payload, runtime_payload
    kind = classify_payload(data)
    if kind not in {"audit", "runtime"}:
        raise ValueError(f"{path} has no runtime audit records")
    if kind == "audit":
        if data.get("initial_states"):
            raise ValueError(f"{path} is a summary of an initial-state matrix. Export its child audits or use the audit CLI.")
        profile_path = profile_path or data.get("profile_path")
    profile_path = Path(profile_path) if profile_path else None
    if profile_path and not profile_path.is_absolute() and (root / profile_path).is_file():
        profile_path = (root / profile_path).resolve()
    raw_profile = {}
    if profile_path and profile_path.is_file():
        from profile_loader import _resolve_profile_input_path, load_profile_raw
        raw_profile = load_profile_raw(profile_path)
        raw_elf = (raw_profile.get("bootloader") or {}).get("elf")
        if not elf and raw_elf:
            elf = _resolve_profile_input_path(raw_elf, repo_root=root, profile_path=profile_path)
    if kind == "runtime":
        data = runtime_payload(data, name or raw_profile.get("name") or path.stem, raw_profile)
    from recovery_explanation import explain_recovery_failures
    expected = (data.get("expect") or {}).get("control_outcome") or "success"
    raw_bootloader = raw_profile.get("bootloader") if isinstance(raw_profile.get("bootloader"), dict) else {}
    raw_fs = raw_profile.get("fault_sweep") if isinstance(raw_profile.get("fault_sweep"), dict) else {}
    raw_mem = raw_profile.get("memory") if isinstance(raw_profile.get("memory"), dict) else {}
    driver_functions = []
    for src in (
        raw_bootloader.get("driver_functions"),
        raw_profile.get("driver_functions"),
        raw_fs.get("driver_functions"),
    ):
        if isinstance(src, list):
            for item in src:
                if isinstance(item, str) and item.strip() and item.strip() not in driver_functions:
                    driver_functions.append(item.strip())
    raw_probe = raw_profile.get("state_probe")
    if isinstance(raw_probe, dict):
        raw_probe = raw_probe.get("script")
    if not raw_probe:
        contracts = data.get("contracts") if isinstance(data.get("contracts"), dict) else {}
        contract_probe = contracts.get("state_probe")
        if isinstance(contract_probe, dict):
            raw_probe = contract_probe.get("script")
    probe_path = None
    if isinstance(raw_probe, str) and raw_probe.strip():
        from profile_loader import _resolve_profile_input_path
        probe_path = str(_resolve_profile_input_path(raw_probe.strip(), repo_root=root, profile_path=profile_path))
    raw_slots = raw_mem.get("slots") if isinstance(raw_mem.get("slots"), dict) else None
    raw_page_size = raw_mem.get("page_size", 4096)
    try:
        page_size = int(str(raw_page_size), 0)
    except Exception:
        page_size = 4096
    explain_recovery_failures(
        data.get("runtime_sweep_results", []),
        expected,
        elf,
        root,
        page_size=page_size,
        driver_functions=driver_functions,
        state_probe=probe_path,
        slots=raw_slots,
    )
    return ReportRun(data, name or data.get("profile") or path.stem, profile_path, elf)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, action="append", type=Path, help="Audit JSON (repeatable).")
    parser.add_argument("--profile", type=Path, help="Profile location for raw or relocated reports.")
    parser.add_argument("--elf", type=Path, help="ELF with debug line information for relocated reports.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    add_report_options(parser)
    args = parser.parse_args()
    validate_report_paths(parser, args, [*args.input, args.profile, args.elf])
    if not requested(args):
        parser.error("choose --junit, --sarif or --html")
    runs = []
    for path in args.input:
        data = json.loads(path.read_text(encoding="utf-8"))
        run = saved_run(data, path, args.repo_root, args.profile, args.elf)
        if args.sarif and not run.profile_path:
            parser.error("--sarif requires --profile when the report has no profile_path")
        runs.append(run)
    write_formats(args, runs, args.repo_root)


if __name__ == "__main__":
    main()
