# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Validate saved reports against the published OASIS and Jenkins schemas."""

import argparse
import json
from pathlib import Path
from urllib.request import urlopen

from jsonschema import Draft7Validator, FormatChecker
from lxml import etree

from report_sarif import SARIF_SCHEMA

JUNIT_XSD = ("https://raw.githubusercontent.com/jenkinsci/xunit-plugin/master/"
             "src/main/resources/org/jenkinsci/plugins/xunit/types/model/xsd/junit-10.xsd")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--sarif", type=Path, required=True)
    args = parser.parse_args()
    with urlopen(SARIF_SCHEMA, timeout=30) as schema:
        Draft7Validator(json.load(schema), format_checker=FormatChecker()).validate(
            json.loads(args.sarif.read_text(encoding="utf-8")))
    with urlopen(JUNIT_XSD, timeout=30) as schema:
        etree.XMLSchema(etree.parse(schema)).assertValid(etree.parse(str(args.junit)))
    print(f"Validated {args.sarif} (SARIF 2.1.0) and {args.junit} (Jenkins junit-10.xsd)")


if __name__ == "__main__":
    main()
