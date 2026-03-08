"""Tests for scripts/fuzz_to_profile.py."""

from __future__ import annotations

import struct
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import fuzz_to_profile as ftp


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


# ---------------------------------------------------------------------------
# Tests: region map loading
# ---------------------------------------------------------------------------

class TestLoadRegionMap:
    def test_load_valid_map(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text(textwrap.dedent("""\
            regions:
              - name: metadata
                address: 0x10070000
                size: 16
              - name: header
                address: 0x10038000
                size: 32
        """))
        regions = ftp._load_region_map(str(m))
        assert len(regions) == 2
        assert regions[0]["name"] == "metadata"
        assert regions[0]["address"] == 0x10070000
        assert regions[0]["size"] == 16
        assert regions[1]["name"] == "header"
        assert regions[1]["address"] == 0x10038000
        assert regions[1]["size"] == 32

    def test_no_map(self):
        assert ftp._load_region_map(None) == []
        assert ftp._load_region_map("") == []

    def test_missing_regions_key(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text("foo: bar\n")
        with pytest.raises(RuntimeError, match="regions"):
            ftp._load_region_map(str(m))

    def test_missing_address(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text(textwrap.dedent("""\
            regions:
              - name: bad
                size: 16
        """))
        with pytest.raises(RuntimeError, match="address.*size.*required"):
            ftp._load_region_map(str(m))


# ---------------------------------------------------------------------------
# Tests: crash bytes -> writes (with regions)
# ---------------------------------------------------------------------------

class TestCrashBytesToWritesWithRegions:
    def test_single_region(self):
        data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)  # 8 bytes
        regions = [{"name": "meta", "address": 0x1000, "size": 8}]
        writes = ftp._crash_bytes_to_writes_with_regions(data, regions)
        assert len(writes) == 2
        assert writes[0] == {"address": "0x00001000", "u32": "0xDEADBEEF"}
        assert writes[1] == {"address": "0x00001004", "u32": "0xCAFEBABE"}

    def test_two_regions(self):
        data = struct.pack("<II", 0x11111111, 0x22222222)
        regions = [
            {"name": "a", "address": 0x1000, "size": 4},
            {"name": "b", "address": 0x2000, "size": 4},
        ]
        writes = ftp._crash_bytes_to_writes_with_regions(data, regions)
        assert len(writes) == 2
        assert writes[0]["address"] == "0x00001000"
        assert writes[1]["address"] == "0x00002000"

    def test_excess_data_ignored(self):
        data = b"\x01\x02\x03\x04" + b"\xFF" * 100
        regions = [{"name": "a", "address": 0x1000, "size": 4}]
        writes = ftp._crash_bytes_to_writes_with_regions(data, regions)
        assert len(writes) == 1

    def test_short_data(self):
        # Data shorter than region size -- only available bytes are used
        data = b"\xAA\xBB"
        regions = [{"name": "a", "address": 0x1000, "size": 8}]
        writes = ftp._crash_bytes_to_writes_with_regions(data, regions)
        assert len(writes) == 1  # only 1 word (2 bytes padded to 4)
        assert writes[0]["u32"] == "0x0000BBAA"


# ---------------------------------------------------------------------------
# Tests: crash bytes -> writes (flat)
# ---------------------------------------------------------------------------

class TestCrashBytesToWritesFlat:
    def test_basic(self):
        data = struct.pack("<I", 0xDEADBEEF)
        writes = ftp._crash_bytes_to_writes_flat(data, 0x10070000)
        assert len(writes) == 1
        assert writes[0] == {"address": "0x10070000", "u32": "0xDEADBEEF"}

    def test_multiple_words(self):
        data = struct.pack("<III", 1, 2, 3)
        writes = ftp._crash_bytes_to_writes_flat(data, 0x0)
        assert len(writes) == 3
        assert writes[2]["u32"] == "0x00000003"

    def test_non_aligned_data(self):
        data = b"\xAA\xBB\xCC"  # 3 bytes -> 1 word
        writes = ftp._crash_bytes_to_writes_flat(data, 0x0)
        assert len(writes) == 1
        assert writes[0]["u32"] == "0x00CCBBAA"


# ---------------------------------------------------------------------------
# Tests: end-to-end
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_with_region_map(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        crash_file = tmp_path / "crash.bin"
        crash_file.write_bytes(struct.pack("<IIII", 0x4F54414D, 1, 0, 0x12345678))

        addr_map = tmp_path / "map.yaml"
        addr_map.write_text(textwrap.dedent("""\
            regions:
              - name: metadata
                address: 0x10070000
                size: 16
        """))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "fuzz_to_profile.py",
            "--crash-input", str(crash_file),
            "--template", str(template_file),
            "--address-map", str(addr_map),
            "--output", str(output_file),
        ]
        rc = ftp.main()
        assert rc == 0
        assert output_file.exists()

        profile = yaml.safe_load(output_file.read_text())
        assert "fuzz" in profile["name"]
        assert len(profile["pre_boot_state"]) == 4
        assert profile["pre_boot_state"][0]["address"] == "0x10070000"
        assert profile["pre_boot_state"][0]["u32"] == "0x4F54414D"
        assert profile["expect"]["should_find_issues"] is True

    def test_flat_mode(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        crash_file = tmp_path / "crash.bin"
        crash_file.write_bytes(struct.pack("<II", 0xAAAAAAAA, 0xBBBBBBBB))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "fuzz_to_profile.py",
            "--crash-input", str(crash_file),
            "--template", str(template_file),
            "--meta-base", "0x10070000",
            "--output", str(output_file),
        ]
        rc = ftp.main()
        assert rc == 0

        profile = yaml.safe_load(output_file.read_text())
        assert len(profile["pre_boot_state"]) == 2
        assert profile["pre_boot_state"][0]["address"] == "0x10070000"
        assert profile["pre_boot_state"][1]["address"] == "0x10070004"

    def test_empty_crash_raises(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        crash_file = tmp_path / "crash.bin"
        crash_file.write_bytes(b"")

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "fuzz_to_profile.py",
            "--crash-input", str(crash_file),
            "--template", str(template_file),
            "--output", str(output_file),
        ]
        with pytest.raises(RuntimeError, match="empty"):
            ftp.main()

    def test_name_suffix(self, tmp_path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text(TEMPLATE_YAML)

        crash_file = tmp_path / "crash.bin"
        crash_file.write_bytes(struct.pack("<I", 0xDEADBEEF))

        output_file = tmp_path / "output.yaml"
        sys.argv = [
            "fuzz_to_profile.py",
            "--crash-input", str(crash_file),
            "--template", str(template_file),
            "--meta-base", "0x0",
            "--name-suffix", "id000",
            "--output", str(output_file),
        ]
        rc = ftp.main()
        assert rc == 0

        profile = yaml.safe_load(output_file.read_text())
        assert "id000" in profile["name"]
