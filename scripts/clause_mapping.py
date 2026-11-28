# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Read a versioned, local regulation-to-observation mapping."""

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import unicodedata

import fastjsonschema
import yaml

MAP_DIR = Path(__file__).with_name("clause_maps")
DEFAULT_MAP = MAP_DIR / "update-v1.yaml"

# Clause text describes obligations. Assessment decisions have no place in
# identifiers, descriptions, limitations or the profile label displayed here.
_DECISION = re.compile(
    r"\b(?:non[ -]?)?(?:compl(?:y|ies|ied|iant|iance)|conform\w*|certif\w*|"
    r"approv\w*|accredit\w*|attest\w*)\b|"
    r"\b(?:meets?|satisf(?:y|ies|ied)|fulfil(?:l|ls|led)?|passes?|passed)\b"
    r".{0,60}\b(?:clauses?|paragraphs?|articles?|regulations?|requirements?|standards?|annex|CRA|R156)\b|"
    r"\b(?:requirements?|clauses?|paragraphs?|articles?|regulations?|standards?|CRA|R156)\b.{0,50}"
    r"\b(?:met|satisfied|fulfilled|passed)\b",
    re.IGNORECASE,
)


def decision_wording(text):
    normalized = unicodedata.normalize("NFKC", text).replace("_", " ")
    return _DECISION.search(" ".join(normalized.split())) is not None


def profile_label(name):
    if isinstance(name, str) and re.fullmatch(r"[\w./-]{1,160}", name) and not decision_wording(name):
        return name
    if isinstance(name, str) and name:
        return "profile-" + hashlib.sha256(name.encode()).hexdigest()[:12]
    return "unrecorded"


class _MappingLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = super().construct_mapping(node, deep)
        if len(result) != len(node.value):
            raise ValueError(f"duplicate YAML key near line {node.start_mark.line + 1}")
        return result


@lru_cache(maxsize=1)
def _validator():
    return fastjsonschema.compile(json.loads((MAP_DIR / "schema.json").read_text(encoding="utf-8")))


def validate_mapping(mapping):
    try:
        _validator()(mapping)
    except fastjsonschema.JsonSchemaException as exc:
        raise ValueError(f"clause mapping: {exc.message}") from exc
    seen = set()
    for index, clause in enumerate(mapping["clauses"]):
        key = (clause["regulation"], clause["paragraph"])
        if key in seen:
            raise ValueError(f"clauses[{index}]: duplicate regulation and paragraph {key!r}")
        seen.add(key)
        for field, value in clause.items():
            if isinstance(value, str) and decision_wording(value):
                raise ValueError(f"clauses[{index}].{field}: assessment wording is outside the mapping vocabulary")
    return mapping


def load_mapping(path=DEFAULT_MAP):
    try:
        return validate_mapping(yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_MappingLoader))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: {exc}") from exc
