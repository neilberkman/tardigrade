"""Authenticated persistent-memory artifacts for boundary follow-up runs."""

from __future__ import absolute_import

import hashlib
import json
import os

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


MAGIC = b"TARDIGRADE_BOUNDARY_SNAPSHOT_V1\n"


def _header(components, identity):
    return {
        "version": 1,
        "identity": str(identity),
        "components": [
            {
                "name": name,
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in sorted(components.items())
        ],
    }


def digest_components(components):
    return hashlib.sha256(
        b"".join(components[name] for name in sorted(components))
    ).hexdigest()


def write_snapshot(path, components, identity):
    path = str(path)
    if not path:
        raise ValueError("snapshot path is missing")
    normalized = {
        str(name): bytes(data) for name, data in components.items()
    }
    header = _header(normalized, identity)
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        os.makedirs(parent)
    temporary = path + ".tmp.{}".format(os.getpid())
    try:
        with open(temporary, "wb") as stream:
            stream.write(MAGIC)
            stream.write(json.dumps(header, sort_keys=True).encode("utf-8"))
            stream.write(b"\n")
            for name in sorted(normalized):
                stream.write(normalized[name])
        # Renode deployments may use IronPython, whose os module has no
        # os.replace. The temporary path is unique and the destination is
        # runner-owned, so rename provides the same atomic handoff here.
        rename = getattr(os, "replace", os.rename)
        rename(temporary, path)
    except Exception:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except Exception:
            pass
        raise
    return header


def read_snapshot(path, identity, expected_lengths):
    path = str(path)
    if not path or not os.path.isfile(path):
        raise ValueError("snapshot is missing")
    with open(path, "rb") as stream:
        if stream.readline() != MAGIC:
            raise ValueError("snapshot has invalid magic")
        try:
            header = json.loads(stream.readline(1 << 16).decode("utf-8"))
        except Exception as exc:
            raise ValueError("snapshot header is malformed: {}".format(exc))
        if (
            not isinstance(header, dict)
            or header.get("version") != 1
            or header.get("identity") != str(identity)
            or not isinstance(header.get("components"), list)
        ):
            raise ValueError("snapshot identity is invalid")
        components = {}
        for descriptor in header["components"]:
            if not isinstance(descriptor, dict):
                raise ValueError("snapshot component metadata is malformed")
            name = descriptor.get("name")
            length = descriptor.get("length")
            digest = descriptor.get("sha256")
            # Validate before dictionary membership: malformed JSON such as
            # a list-valued name must become a controlled artifact error, and
            # must be rejected before any caller can restore bytes.
            if not isinstance(name, string_types) or not name.strip():
                raise ValueError("snapshot component metadata name is invalid")
            if (
                name in components
                or name not in expected_lengths
                or isinstance(length, bool)
                or not isinstance(length, integer_types)
                or length != expected_lengths[name]
                or not isinstance(digest, string_types)
            ):
                raise ValueError("snapshot component metadata is invalid")
            data = stream.read(length)
            if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("snapshot component is incomplete or corrupted")
            components[name] = data
        if set(components) != set(expected_lengths) or stream.read(1):
            raise ValueError("snapshot component set or length is invalid")
    return components, header
