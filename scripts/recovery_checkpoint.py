# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""JSON checkpoint helpers shared by the host and Renode's Python runtime."""

import base64
import hashlib
import json

from recovery_state import PersistentState, RegionState


def json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_checkpoint(data, inputs, host_only=False):
    if data.get("version") != 1:
        raise ValueError("unsupported state search checkpoint version")
    if data.get("final"):
        raise ValueError("state search checkpoint is final")
    recorded = data["inputs"]
    keys = set(inputs) if host_only else set(inputs) | set(recorded)
    mismatches = sorted(key for key in keys if key not in recorded or key not in inputs
                        or recorded[key] != inputs[key])
    if mismatches:
        raise ValueError("state search checkpoint mismatch: " + ", ".join(mismatches))


def remaining_wall_time(checkpoint):
    return checkpoint["limits"]["max_wall_time_s"] - checkpoint["elapsed_s"]


class SnapshotWriter(object):
    """Store each immutable NVM chunk once across all pending states."""

    def __init__(self):
        self.states = {}
        self.chunks = []
        self._chunk_indices = {}

    def reference(self, state):
        identity = state.identity_hex()
        if identity not in self.states:
            regions = []
            for region in state.regions:
                indices = []
                for chunk in region.chunks:
                    index = self._chunk_indices.get(chunk)
                    if index is None:
                        index = len(self.chunks)
                        self.chunks.append(base64.b64encode(chunk).decode("ascii"))
                        self._chunk_indices[chunk] = index
                    indices.append(index)
                regions.append([region.name, region.base_address, region.chunk_size, indices])
            self.states[identity] = {
                "regions": regions,
                "uncorrectable_words": sorted(state.uncorrectable_words),
                "persistent_values": dict(
                    (name, base64.b64encode(value).decode("ascii"))
                    for name, value in state.persistent_values
                ),
            }
        return identity


def _decode_bytes(value):
    raw = base64.b64decode(value)
    if isinstance(raw, bytes):
        return raw
    # IronPython's base64 module returns one character per decoded octet.
    return bytes(bytearray(raw, "latin-1"))


def restore_snapshots(data):
    chunks = [_decode_bytes(chunk) for chunk in data["chunks"]]
    states = {}
    for identity, entry in data["snapshots"].items():
        regions = [
            RegionState(name, base, [chunks[i] for i in indices], size)
            for name, base, size, indices in entry["regions"]
        ]
        state = PersistentState(
            regions, entry["uncorrectable_words"],
            dict((name, _decode_bytes(value))
                 for name, value in entry["persistent_values"].items()),
        )
        if state.identity_hex() != identity:
            raise ValueError("state search checkpoint snapshot mismatch: " + identity)
        states[identity] = state
    return states
