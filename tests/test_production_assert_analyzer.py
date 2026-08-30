"""Tests for production assertion review analysis."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from production_assert_analyzer import analyze_tree, main


class ProductionAssertAnalyzerTests(unittest.TestCase):
    def test_ranks_argument_guard_before_authorization_as_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "authorization" / "policy.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                "def approve(level):\n"
                "    assert level >= 0\n"
                "    return verify_policy(level)\n",
                encoding="utf-8",
            )
            report = analyze_tree(root, ["authorization"])

        self.assertEqual(report["verdict"], "REVIEW")
        self.assertEqual(report["counts"]["high"], 1)
        self.assertEqual(report["findings"][0]["condition"], "level >= 0")

    def test_type_narrowing_is_low_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "authorization" / "policy.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                "def approve(value):\n"
                "    assert value is not None  # checked in validation\n"
                "    return verify_policy(value)\n",
                encoding="utf-8",
            )
            report = analyze_tree(root, ["authorization"])

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["counts"]["low"], 1)

    def test_cli_json_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "authorization.py"
            path.write_text(
                "def confirm(level):\n"
                "    assert level < 10\n"
                "    return verify_policy(level)\n",
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["--source-root", str(root), "--json"])

        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.getvalue())["verdict"], "REVIEW")

    def test_parse_error_is_inconclusive_and_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "authorization.py"
            path.write_text("def authorize(:\n    pass\n", encoding="utf-8")
            report = analyze_tree(root, ["authorization.py"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["--source-root", str(root), "--json"])

        self.assertEqual(report["verdict"], "INCONCLUSIVE")
        self.assertEqual(len(report["parse_errors"]), 1)
        self.assertNotEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
