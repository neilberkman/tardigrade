"""Strict parsing for top-level audit verdict tokens."""

from __future__ import annotations

import re
from typing import Any


_PASS_VERDICT = re.compile(r"^PASS(?: [^\x00-\x1f\x7f]+)?$")


def is_pass_verdict(value: Any) -> bool:
    """Accept ``PASS`` or ``PASS`` plus printable single-line details."""
    if not isinstance(value, str):
        return False
    return _PASS_VERDICT.fullmatch(value.strip(" ")) is not None
