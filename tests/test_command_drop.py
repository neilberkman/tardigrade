#!/usr/bin/env python3
"""Unit tests for generic controller command-drop fault support."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_bootloader import EXECUTE_ONLY_FAULT_TYPES, _fault_type_label  # noqa: E402
from profile_loader import IMPLEMENTED_FAULT_TYPES, KNOWN_FAULT_TYPES  # noqa: E402


class CommandDropRegistrationTest(unittest.TestCase):
    def test_command_drop_in_known_types(self) -> None:
        self.assertIn("command_drop", KNOWN_FAULT_TYPES)

    def test_command_drop_in_implemented_types(self) -> None:
        self.assertIn("command_drop", IMPLEMENTED_FAULT_TYPES)

    def test_command_drop_is_execute_only(self) -> None:
        self.assertIn("command_drop", EXECUTE_ONLY_FAULT_TYPES)

    def test_fault_type_label(self) -> None:
        self.assertEqual(_fault_type_label("k"), "command_drop")


if __name__ == "__main__":
    unittest.main()
