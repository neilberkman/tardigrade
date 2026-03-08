"""Tests for scripts/cbmc_to_profile.py."""

from __future__ import annotations

import json
import struct
import textwrap
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

# Import the module under test.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import cbmc_to_profile as ctp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEMPLATE_YAML = textwrap.dedent("""\
    schema_version: 1
    name: test_template
    description: "Test template"
    platform: platforms/cortex_m0_nvm.repl
    flash_backend: nvm_ctrl
    bootloader:
      elf: examples/vulnerable_ota/firmware.elf
      entry: 0x10000000
    memory:
      sram: { start: 0x20000000, end: 0x20020000 }
      write_granularity: 8
      slots:
        exec:    { base: 0x10000000, size: 0x38000 }
        staging: { base: 0x10038000, size: 0x38000 }
    images:
      staging: examples/vulnerable_ota/firmware.bin
    success_criteria:
      vtor_in_slot: exec
    fault_sweep:
      mode: runtime
      max_writes: 28672
    expect:
      should_find_issues: false
""")


def _make_json_trace(byte_values: Dict[int, int]) -> str:
    """Build a minimal CBMC JSON output with one failing trace."""
    steps = []
    for idx in sorted(byte_values):
        steps.append({
            "stepType": "assignment",
            "lhs": "meta_bytes[{}]".format(idx),
            "value": str(byte_values[idx]),
        })
    steps.append({
        "stepType": "failure",
        "property": "test_property",
        "reason": "test failure",
    })
    return json.dumps([{
        "result": [{
            "property": "test_property",
            "status": "FAILURE",
            "trace": steps,
        }]
    }])


def _make_xml_trace(byte_values: Dict[int, int]) -> str:
    """Build a minimal CBMC XML output with one failing trace."""
    assignments = ""
    for idx in sorted(byte_values):
        assignments += textwrap.dedent("""\
            <assignment>
              <lhs>meta_bytes[{idx}]</lhs>
              <full_lhs>meta_bytes[(signed long int){idx}]</full_lhs>
              <full_lhs_value>{val}</full_lhs_value>
              <type>unsigned char</type>
            </assignment>
        """).format(idx=idx, val=byte_values[idx])
    return textwrap.dedent("""\
        <?xml version="1.0" encoding="UTF-8"?>
        <cprover>
          <result property="test_property" status="FAILURE">
            <goto_trace>
              {assignments}
              <failure property="test_property" reason="test failure"/>
            </goto_trace>
          </result>
        </cprover>
    """).format(assignments=assignments)


# ---------------------------------------------------------------------------
# Tests: _parse_scalar_int
# ---------------------------------------------------------------------------

class TestParseScalarInt:
    def test_plain_int(self):
        assert ctp._parse_scalar_int(42) == 42

    def test_hex_string(self):
        assert ctp._parse_scalar_int("0xFF") == 255

    def test_binary_string(self):
        assert ctp._parse_scalar_int("0b1010") == 10

    def test_bool_true(self):
        assert ctp._parse_scalar_int(True) == 1

    def test_bool_false(self):
        assert ctp._parse_scalar_int(False) == 0

    def test_empty_string(self):
        assert ctp._parse_scalar_int("") is None

    def test_dict_with_data(self):
        assert ctp._parse_scalar_int({"data": "0x10"}) == 16

    def test_none(self):
        assert ctp._parse_scalar_int(None) is None


# ---------------------------------------------------------------------------
# Tests: _extract_byte_assignments
# ---------------------------------------------------------------------------

class TestExtractByteAssignments:
    def test_basic_extraction(self):
        trace = [
            {"lhs": "meta_bytes[0]", "value": "77"},
            {"lhs": "meta_bytes[1]", "value": "65"},
        ]
        name, bmap = ctp._extract_byte_assignments(trace)
        assert name == "meta_bytes"
        assert bmap == {0: 77, 1: 65}

    def test_nvm_array(self):
        trace = [{"lhs": "nvm[5]", "value": "0xFF"}]
        name, bmap = ctp._extract_byte_assignments(trace)
        assert name == "nvm"
        assert bmap == {5: 255}

    def test_extra_arrays(self):
        trace = [{"lhs": "header[0]", "value": "42"}]
        name, bmap = ctp._extract_byte_assignments(trace, extra_arrays=["header"])
        assert name == "header"
        assert bmap == {0: 42}

    def test_empty_trace(self):
        name, bmap = ctp._extract_byte_assignments([])
        assert name == ""
        assert bmap == {}

    def test_aggregate_assignment(self):
        trace = [{
            "lhs": "meta_bytes",
            "value": {
                "elements": [
                    {"index": 0, "value": 10},
                    {"index": 1, "value": 20},
                ]
            },
        }]
        name, bmap = ctp._extract_byte_assignments(trace)
        assert name == "meta_bytes"
        assert bmap == {0: 10, 1: 20}


# ---------------------------------------------------------------------------
# Tests: _bytes_to_pre_boot_state
# ---------------------------------------------------------------------------

class TestBytesToPreBootState:
    def test_single_word(self):
        writes = ctp._bytes_to_pre_boot_state(0x10070000, {0: 0x4D, 1: 0x41, 2: 0x54, 3: 0x4F})
        assert len(writes) == 1
        assert writes[0]["address"] == "0x10070000"
        assert writes[0]["u32"] == "0x4F54414D"

    def test_two_words(self):
        bmap = {0: 1, 1: 0, 2: 0, 3: 0, 4: 2, 5: 0, 6: 0, 7: 0}
        writes = ctp._bytes_to_pre_boot_state(0x1000, bmap)
        assert len(writes) == 2
        assert writes[0]["address"] == "0x00001000"
        assert writes[0]["u32"] == "0x00000001"
        assert writes[1]["address"] == "0x00001004"
        assert writes[1]["u32"] == "0x00000002"

    def test_sparse_bytes(self):
        # Only byte 0 and byte 5 are set -- should produce 2 words
        writes = ctp._bytes_to_pre_boot_state(0x0, {0: 0xAA, 5: 0xBB})
        assert len(writes) == 2
        assert writes[0]["u32"] == "0x000000AA"
        assert writes[1]["u32"] == "0x0000BB00"


# ---------------------------------------------------------------------------
# Tests: JSON end-to-end
# ---------------------------------------------------------------------------

class TestJsonEndToEnd:
    def test_json_conversion(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        byte_vals = {i: (0x4D, 0x41, 0x54, 0x4F, 1, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0)[i] for i in range(16)}
        cbmc_file = tmp_path / "cbmc.json"
        cbmc_file.write_text(_make_json_trace(byte_vals))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "cbmc_to_profile.py",
            "--cbmc-output", str(cbmc_file),
            "--template", str(template_file),
            "--output", str(output_file),
            "--meta-size", "16",
            "--meta-base", "0x10070000",
        ]
        rc = ctp.main()
        assert rc == 0
        assert output_file.exists()

        profile = yaml.safe_load(output_file.read_text())
        assert "cbmc_001" in profile["name"]
        assert len(profile["pre_boot_state"]) == 4
        assert profile["pre_boot_state"][0]["address"] == "0x10070000"
        assert profile["pre_boot_state"][0]["u32"] == "0x4F54414D"
        assert profile["expect"]["should_find_issues"] is True


# ---------------------------------------------------------------------------
# Tests: XML end-to-end
# ---------------------------------------------------------------------------

class TestXmlEndToEnd:
    def test_xml_conversion(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        byte_vals = {0: 0x4D, 1: 0x41, 2: 0x54, 3: 0x4F, 4: 1, 5: 0, 6: 0, 7: 0}
        xml_file = tmp_path / "cbmc.xml"
        xml_file.write_text(_make_xml_trace(byte_vals))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "cbmc_to_profile.py",
            "--cbmc-output", str(xml_file),
            "--template", str(template_file),
            "--output", str(output_file),
            "--meta-size", "16",
            "--meta-base", "0x10070000",
        ]
        rc = ctp.main()
        assert rc == 0

        profile = yaml.safe_load(output_file.read_text())
        assert len(profile["pre_boot_state"]) == 2
        assert profile["pre_boot_state"][0]["u32"] == "0x4F54414D"

    def test_xml_success_no_output(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        xml_file = tmp_path / "cbmc_ok.xml"
        xml_file.write_text(textwrap.dedent("""\
            <?xml version="1.0"?>
            <cprover>
              <result property="p1" status="SUCCESS"/>
            </cprover>
        """))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "cbmc_to_profile.py",
            "--cbmc-output", str(xml_file),
            "--template", str(template_file),
            "--output", str(output_file),
            "--meta-size", "16",
        ]
        rc = ctp.main()
        assert rc == 0
        assert not output_file.exists()


# ---------------------------------------------------------------------------
# Tests: address map
# ---------------------------------------------------------------------------

class TestAddressMap:
    def test_load_yaml_map(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text("meta_bytes: 0x10070000\nheader: 0x10038000\n")
        result = ctp.load_address_map(str(m))
        assert result == {"meta_bytes": 0x10070000, "header": 0x10038000}

    def test_load_json_map(self, tmp_path):
        m = tmp_path / "map.json"
        m.write_text('{"nvm": "0x1000"}')
        result = ctp.load_address_map(str(m))
        assert result == {"nvm": 0x1000}

    def test_no_map(self):
        assert ctp.load_address_map(None) == {}
        assert ctp.load_address_map("") == {}

    def test_address_map_overrides_meta_base(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        addr_map_file = tmp_path / "map.yaml"
        addr_map_file.write_text("meta_bytes: 0xDEAD0000\n")

        byte_vals = {0: 0xAA, 1: 0xBB, 2: 0xCC, 3: 0xDD}
        cbmc_file = tmp_path / "cbmc.json"
        cbmc_file.write_text(_make_json_trace(byte_vals))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "cbmc_to_profile.py",
            "--cbmc-output", str(cbmc_file),
            "--template", str(template_file),
            "--address-map", str(addr_map_file),
            "--output", str(output_file),
            "--meta-size", "16",
        ]
        rc = ctp.main()
        assert rc == 0

        profile = yaml.safe_load(output_file.read_text())
        assert profile["pre_boot_state"][0]["address"] == "0xDEAD0000"


# ---------------------------------------------------------------------------
# Tests: format detection
# ---------------------------------------------------------------------------

class TestFormatDetection:
    def test_json_detected(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text('[{"foo": 1}]')
        assert ctp._detect_format(f) == "json"

    def test_xml_detected(self, tmp_path):
        f = tmp_path / "test.xml"
        f.write_text('<?xml version="1.0"?><root/>')
        assert ctp._detect_format(f) == "xml"

    def test_xml_no_declaration(self, tmp_path):
        f = tmp_path / "test.xml"
        f.write_text("<cprover></cprover>")
        assert ctp._detect_format(f) == "xml"
