# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""JUnit XML for returned audit records, including the unfaulted control."""

import json
import re
import xml.etree.ElementTree as ET

from report_points import point_time, suite_time

# XML 1.0 forbids a subset of characters JSON strings can contain.
_INVALID_XML = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def junit_report(runs):
    suites = ET.Element("testsuites")
    for run in runs:
        suite = ET.SubElement(suites, "testsuite", name=run.name)
        properties = ET.SubElement(suite, "properties")
        ET.SubElement(properties, "property", name="point_counts", value=json.dumps(run.counts, sort_keys=True))
        ET.SubElement(properties, "property", name="verdict", value=str(run.data.get("verdict", "")))
        summary = run.data.get("summary") or {}
        sweep = summary.get("runtime_sweep") if isinstance(summary.get("runtime_sweep"), dict) else summary
        if isinstance(sweep, dict) and sweep.get("fault_evidence"):
            ET.SubElement(
                properties,
                "property",
                name="fault_evidence",
                value=json.dumps(sweep["fault_evidence"], sort_keys=True),
            )
        counters = dict(tests=0, failures=0, errors=0, skipped=0)
        case_times = []
        for point in run.points():
            case = ET.SubElement(suite, "testcase", classname=f"{run.name}.{point.kind}", name=point.name)
            row = point.row if isinstance(point.row, dict) else {}
            if "fault_at" in row and not row.get("is_control") and row.get("fault_type") != "control":
                case.set("fault_at", str(row.get("fault_at")))
                raw_op = str(row.get("operation_kind") or "").strip().lower()
                ft = str(row.get("fault_type") or ("e" if raw_op == "erase" else "w"))
                ft_base = ft.split(":", 1)[0].strip().lower()
                op_kind = str(
                    row.get("operation_kind")
                    or (
                        "erase"
                        if ft_base in ("e", "a", "interrupted_erase", "multi_sector_atomicity")
                        else "program"
                    )
                )
                case.set("fault_type", ft)
                case.set("operation_kind", op_kind)
            if isinstance(row.get("mram_fault_evidence"), dict):
                case.set("fault_evidence", json.dumps(row["mram_fault_evidence"], sort_keys=True))
            if isinstance(row.get("fault_snapshot"), dict):
                case.set("fault_snapshot", json.dumps(row["fault_snapshot"], sort_keys=True))
            elapsed = point_time(point.row)
            if elapsed is not None:
                case.set("time", f"{elapsed:.3f}")
                case_times.append(elapsed)
            counters["tests"] += 1
            if point.status:
                category = point.findings[0].rule if point.findings else point.status
                explanation = point.row.get("failure_explanation") if point.status == "failure" else None
                message = explanation["message"] if explanation else point.message
                failure = ET.SubElement(case, point.status, type=category, message=message)
                failure.text = point.message
                if explanation:
                    failure.text += "\n" + json.dumps(explanation, sort_keys=True)
                counter = {"error": "errors", "failure": "failures", "skipped": "skipped"}[point.status]
                counters[counter] += 1
        suite.attrib.update({key: str(value) for key, value in counters.items()})
        if (duration := suite_time(run, case_times)) is not None:
            suite.set("time", f"{duration:.3f}")
    ET.indent(suites)
    return _INVALID_XML.sub("\ufffd", ET.tostring(suites, encoding="unicode")) + "\n"
