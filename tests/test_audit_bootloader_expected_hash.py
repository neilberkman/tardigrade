#!/usr/bin/env python3
"""Tests for execute-mode expected image hash handling in audit_bootloader."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


from audit_bootloader import _merge_calibration_expected_exec_hash  # noqa: E402


def test_merge_calibration_expected_exec_hash_injects_when_missing():
    merged, used = _merge_calibration_expected_exec_hash(
        ["SUCCESS_IMAGE_HASH:true"],
        "deadbeef",
    )
    assert used is True
    assert "EXPECTED_EXEC_SHA256:deadbeef" in merged


def test_merge_calibration_expected_exec_hash_preserves_profile_expectation():
    merged, used = _merge_calibration_expected_exec_hash(
        [
            "SUCCESS_IMAGE_HASH:true",
            "EXPECTED_EXEC_SHA256:staginghash",
        ],
        "calibrationhash",
    )
    assert used is False
    assert "EXPECTED_EXEC_SHA256:staginghash" in merged
    assert "EXPECTED_EXEC_SHA256:calibrationhash" not in merged
