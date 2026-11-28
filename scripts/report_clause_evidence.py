#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Extract a clause evidence section from a saved audit without opening any profile assets."""

import argparse
import json
from pathlib import Path

from clause_evidence import clause_evidence, clause_html
from clause_mapping import load_mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Saved audit JSON")
    parser.add_argument("--output", type=Path, required=True, help="Standalone section JSON")
    parser.add_argument("--html", type=Path, help="Standalone HTML summary")
    parser.add_argument("--clause-map", type=Path, help="Replace the saved or default mapping")
    args = parser.parse_args()
    paths = [p.resolve() for p in (args.input, args.output, args.html, args.clause_map) if p]
    if len(paths) != len(set(paths)):
        parser.error("input, mapping and output paths must be distinct")
    try:
        report = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(report, dict) or not any(k in report for k in ("summary", "runtime_sweep_results", "error")):
            raise ValueError("input must be an audit report object")
        mapping = load_mapping(args.clause_map) if args.clause_map else None
        section = clause_evidence(report, mapping)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(section, indent=2) + "\n", encoding="utf-8")
        if args.html:
            args.html.parent.mkdir(parents=True, exist_ok=True)
            args.html.write_text('<!doctype html><html lang="en"><meta charset="utf-8">'
                                 '<title>Software update clause evidence</title><main>'
                                 + clause_html(section) + '</main></html>\n', encoding="utf-8")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
