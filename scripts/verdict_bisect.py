#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0
"""Checkout entry point for the verdict bisector."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tardigrade.verdict_bisect import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
