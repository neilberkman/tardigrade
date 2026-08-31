"""Strict parsing for top-level audit verdict tokens."""

from __future__ import annotations

import re
from typing import Any


_PASS_VERDICT = re.compile(r"^PASS(?: [^\x00-\x1f\x7f]+)?$")

EXPLORATORY_EXPECTATION_MODES = frozenset({"exploratory", "hunt"})
EXPECTATION_MODES = frozenset({"regression", "exploratory", "hunt"})


def expectation_mode(expect: Any) -> str:
    """Return the normalized expectation mode, preserving old callers."""
    mode = getattr(expect, "mode", "regression")
    if isinstance(expect, dict):
        mode = expect.get("mode", "regression")
    value = str(mode or "regression").strip().lower()
    return "exploratory" if value == "hunt" else value


def expectation_requires_findings(expect: Any) -> bool:
    """Whether a zero-finding result violates the profile expectation."""
    should_find = (
        expect.get("should_find_issues", False)
        if isinstance(expect, dict)
        else getattr(expect, "should_find_issues", False)
    )
    return bool(should_find) and expectation_mode(expect) not in EXPLORATORY_EXPECTATION_MODES


def is_exploratory_expectation(expect: Any) -> bool:
    """Whether findings are informative rather than an expectation failure."""
    return expectation_mode(expect) in EXPLORATORY_EXPECTATION_MODES


def is_pass_verdict(value: Any) -> bool:
    """Accept ``PASS`` or ``PASS`` plus printable single-line details."""
    if not isinstance(value, str):
        return False
    return _PASS_VERDICT.fullmatch(value.strip(" ")) is not None
