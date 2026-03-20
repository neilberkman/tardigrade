#!/usr/bin/env python3
"""Create a deterministic tampered copy of a binary image."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def _parse_byte(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFF:
        raise argparse.ArgumentTypeError("byte value must be in range 0..255")
    return parsed


def mutate_binary(
    input_path: Path,
    output_path: Path,
    *,
    offset: int,
    value: int | None = None,
    xor_value: int | None = None,
) -> dict[str, object]:
    data = bytearray(input_path.read_bytes())
    if offset < 0 or offset >= len(data):
        raise ValueError(
            "offset {} out of range for {} ({} bytes)".format(
                offset, input_path, len(data)
            )
        )
    original = data[offset]
    if value is not None and xor_value is not None:
        raise ValueError("choose either value or xor_value, not both")
    if value is not None:
        mutated = value
    else:
        mutated = original ^ (xor_value if xor_value is not None else 0x01)
    if mutated == original:
        raise ValueError("mutation did not change byte at offset {}".format(offset))
    data[offset] = mutated
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(data))
    return {
        "input": str(input_path),
        "output": str(output_path),
        "offset": offset,
        "original_byte": original,
        "mutated_byte": mutated,
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(bytes(data)).hexdigest(),
        "size": len(data),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--offset", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--value", type=_parse_byte)
    parser.add_argument("--xor", dest="xor_value", type=_parse_byte)
    args = parser.parse_args()

    result = mutate_binary(
        args.input,
        args.output,
        offset=args.offset,
        value=args.value,
        xor_value=args.xor_value,
    )
    for key in (
        "input",
        "output",
        "offset",
        "original_byte",
        "mutated_byte",
        "input_sha256",
        "output_sha256",
        "size",
    ):
        print("{}={}".format(key, result[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
