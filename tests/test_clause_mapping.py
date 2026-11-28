# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def test_default_mapping_and_replacement(tmp_path):
    from clause_mapping import load_mapping
    mapping = load_mapping()
    assert [item["paragraph"] for item in mapping["clauses"]] == [
        "7.2.2.1.1", "7.2.1.1", "Annex I, Part I, point (2)(f)"
    ]
    mapping["mapping_version"] = 2
    mapping["clauses"] = mapping["clauses"][:1]
    path = tmp_path / "subset.yaml"
    path.write_text(yaml.safe_dump(mapping))
    assert load_mapping(path) == mapping


@pytest.mark.parametrize(("field", "value"), [
    ("campaigns", ["made_up"]), ("fault_scope", "everything"), ("criteria", []),
    ("citation", "file:///source"), ("unexpected", "field"), ("paragraph", "  "),
])
def test_closed_schema_names_invalid_field(field, value):
    from clause_mapping import load_mapping, validate_mapping
    mapping = load_mapping()
    mapping["clauses"][0][field] = value
    with pytest.raises(ValueError, match=field):
        validate_mapping(mapping)


def test_duplicate_paragraph_and_yaml_keys(tmp_path):
    from clause_mapping import load_mapping, validate_mapping
    mapping = load_mapping()
    mapping["clauses"].append(mapping["clauses"][0])
    with pytest.raises(ValueError, match="duplicate regulation and paragraph"):
        validate_mapping(mapping)
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: 1\nschema_version: 2\n")
    with pytest.raises(ValueError, match="duplicate YAML key"):
        load_mapping(path)


@pytest.mark.parametrize("claim", [
    "complies", "conformity", "cErTiFiEd", "type approval",
    "the product meets all requirements", "all clauses satisfied", "passes the CRA",
])
def test_mapping_and_profile_wording(claim):
    from clause_mapping import load_mapping, profile_label, validate_mapping
    mapping = load_mapping()
    mapping["clauses"][0]["paraphrase"] = claim
    with pytest.raises(ValueError, match=r"clauses\[0\].paraphrase"):
        validate_mapping(mapping)
    assert profile_label(claim).startswith("profile-")
