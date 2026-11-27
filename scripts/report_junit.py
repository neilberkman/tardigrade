# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""JUnit XML for returned audit records, including the unfaulted control."""

import json
import re
import xml.etree.ElementTree as ET

from report_points import point_time

# XML 1.0 forbids a subset of characters JSON strings can contain.
_INVALID_XML = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def junit_report(runs):
    suites = ET.Element("testsuites")
    for run in runs:
        suite = ET.SubElement(suites, "testsuite", name=run.name)
        properties = ET.SubElement(suite, "properties")
        ET.SubElement(properties, "property", name="point_counts", value=json.dumps(run.counts, sort_keys=True))
        ET.SubElement(properties, "property", name="verdict", value=str(run.data.get("verdict", "")))
        counters = dict(tests=0, failures=0, errors=0, skipped=0)
        duration = 0
        for point in run.points():
            elapsed = point_time(point.row)
            duration += elapsed
            case = ET.SubElement(suite, "testcase", classname=f"{run.name}.{point.kind}",
                                 name=point.name, time=f"{elapsed:.3f}")
            counters["tests"] += 1
            if point.status:
                category = point.findings[0].rule if point.findings else point.status
                ET.SubElement(case, point.status, type=category, message=point.message).text = point.message
                counter = {"error": "errors", "failure": "failures", "skipped": "skipped"}[point.status]
                counters[counter] += 1
        suite.attrib.update({key: str(value) for key, value in counters.items()})
        suite.set("time", f"{duration:.3f}")
    ET.indent(suites)
    return _INVALID_XML.sub("\ufffd", ET.tostring(suites, encoding="unicode")) + "\n"
