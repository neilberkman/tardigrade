#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Emit a minimal synthetic persistent-state operation trace."""

from __future__ import annotations

import argparse
import json


def build_trace(mode: str) -> dict:
    if mode not in {"vulnerable", "fixed"}:
        raise ValueError("mode must be vulnerable or fixed")
    vulnerable = mode == "vulnerable"
    return {
        "semantic_state": {
            "persistent_state_operations": [
                {
                    "operation": "security_metadata",
                    "read_ok": False,
                    "write_count": 1 if vulnerable else 0,
                    "outcome": "committed" if vulnerable else "aborted",
                }
            ]
        },
        "boot_outcome": "success" if vulnerable else "no_boot",
        "mode": mode,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    args = parser.parse_args()
    print(json.dumps(build_trace(args.mode), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
