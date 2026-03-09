#!/usr/bin/env python3
"""Regression tests for generic self-test profile discovery."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from self_test import discover_profiles


class SelfTestProfileDiscoveryTests(unittest.TestCase):
    def test_benchmark_and_execute_only_profiles_are_skipped(self):
        repo_root = ROOT
        discovered = {p.name for p in discover_profiles(repo_root)}

        self.assertNotIn("nuttx_nxboot_128.yaml", discovered)
        self.assertNotIn("security_toctou_no_protection.yaml", discovered)
        self.assertNotIn("security_toctou_with_protection.yaml", discovered)


if __name__ == "__main__":
    unittest.main()
