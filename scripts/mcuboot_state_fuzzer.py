#!/usr/bin/env python3
"""Compatibility wrapper for the MCUboot target-side state fuzzer."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any


TARGET_IMPL = (
    Path(__file__).resolve().parents[1] / "targets" / "mcuboot" / "state_fuzzer.py"
)

_SPEC = importlib.util.spec_from_file_location(
    "tardigrade_targets_mcuboot_state_fuzzer",
    TARGET_IMPL,
)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - fatal import guard
    raise RuntimeError("failed to load MCUboot state fuzzer from {}".format(TARGET_IMPL))
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)


def __getattr__(name: str) -> Any:
    return getattr(_MODULE, name)


def main() -> int:
    return int(_MODULE.main())


if __name__ == "__main__":
    raise SystemExit(main())
