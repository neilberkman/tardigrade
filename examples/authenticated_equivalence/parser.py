#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small synthetic vulnerable/fixed parser for the equivalence example."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


BOUNDARY = 0xA0
SIGNATURE = 0xA1


def parse(data: bytes) -> list[tuple[int, bytes, bytes]]:
    records = []
    cursor = 0
    while cursor < len(data):
        if len(data) - cursor < 2:
            raise ValueError("partial TLV header")
        record_type = data[cursor]
        length = data[cursor + 1]
        end = cursor + 2 + length
        if end > len(data):
            raise ValueError("TLV extends beyond input")
        records.append((record_type, data[cursor + 2:end], data[cursor:end]))
        cursor = end
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    args = parser.parse_args()
    data = args.input.read_bytes()
    records = parse(data)
    boundary_indexes = [index for index, item in enumerate(records) if item[0] == BOUNDARY]
    signature_values = [item[1] for item in records if item[0] == SIGNATURE]
    if len(boundary_indexes) != 1 or len(signature_values) != 1:
        raise ValueError("invalid authentication records")
    boundary_index = boundary_indexes[0]
    authenticated = b"".join(item[2] for item in records[:boundary_index + 1])
    tail = [item for item in records[boundary_index + 1:] if item[0] != SIGNATURE]

    target_values = [item[1] for item in tail if item[0] == 0x10]
    version_values = [item[1] for item in tail if item[0] == 0x11]
    payload_values = [item[1] for item in tail if item[0] == 0x20]
    duplicate = any(
        len(values) > 1
        for values in (target_values, version_values, payload_values)
    )
    if args.mode == "fixed":
        # The fixed parser rejects duplicate unauthenticated records.  This is
        # a safe semantic rejection, not a divergence finding.
        target_values = target_values[:1]
        version_values = version_values[:1]
        payload_values = payload_values[:1]

    accepted = bool(target_values and version_values and payload_values) and not (
        args.mode == "fixed" and duplicate
    )
    payload = b"".join(payload_values)
    result = {
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "accepted": accepted,
        "committed": accepted,
        "version": int.from_bytes(version_values[-1], "little") if version_values else None,
        "target": target_values[-1].decode("ascii") if target_values else None,
        "size": len(payload),
        "installed_payload_digest": hashlib.sha256(payload).hexdigest(),
        "rollback_outcome": "none" if accepted else "rejected",
        # Model persistent security state observed after the parser's decision.
        # A safe rejection leaves the installed state unchanged; the
        # vulnerable implementation exposes duplicate records to the state
        # transition before accepting them.
        "security_state": {
            "installed_payload_record_count": len(payload_values),
        },
        # The explicit transition lets the campaign distinguish a rejected
        # input that leaves the pre-existing install untouched from one that
        # mutates persistent state before rejecting.
        "security_state_before": {
            "installed_payload_record_count": 1,
        },
        "security_state_after": {
            "installed_payload_record_count": len(payload_values),
        },
        "authenticated_bytes_b64": base64.b64encode(authenticated).decode("ascii"),
        "authenticated_digest": hashlib.sha256(authenticated).hexdigest(),
        "signature_bytes_b64": base64.b64encode(signature_values[0]).decode("ascii"),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
