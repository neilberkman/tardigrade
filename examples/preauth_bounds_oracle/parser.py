#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal synthetic nested-header parser used by the bounds-oracle example.

The vulnerable mode intentionally omits the component and authentication
extent checks.  It is original fixture code and is not derived from a vendor
implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


COMPONENT_LENGTH = 40
AUTH_OFFSET = 8
AUTH_LENGTH = 16
AUTH_HEADER_SIZE = 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    args = parser.parse_args()
    data = args.input.read_bytes()
    if len(data) < COMPONENT_LENGTH:
        raise ValueError("short synthetic component")
    total = int.from_bytes(data[0:2], "little")
    used = int.from_bytes(data[2:4], "little")
    signature = int.from_bytes(data[8:10], "little")
    key = int.from_bytes(data[10:12], "little")
    auth_end = AUTH_OFFSET + AUTH_LENGTH
    material_end = AUTH_OFFSET + AUTH_HEADER_SIZE + signature + key
    violations = (
        total > COMPONENT_LENGTH
        or used > total
        or used > COMPONENT_LENGTH
        or material_end > auth_end
        or material_end > COMPONENT_LENGTH
    )
    # This flag models actual signature/key consumption or verification, not
    # merely dispatching to an authentication wrapper.
    auth_attempted = args.mode == "vulnerable" or not violations
    accepted = auth_attempted and not (args.mode == "fixed" and violations)
    result = {
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "accepted": accepted,
        "committed": accepted,
        "auth_attempted": auth_attempted,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
