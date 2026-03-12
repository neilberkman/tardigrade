"""Tests for scripts/fuzz_crash_to_profile.py."""

from __future__ import annotations

import hashlib
import struct
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import fuzz_crash_to_profile as fcp


BASE_PROFILE_YAML = textwrap.dedent("""\
    schema_version: 1
    name: test_base
    description: "Base profile for fuzzer regression tests"
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
        staging: { base: 0x00040000, size: 0x38000 }
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
# Tests: crash metadata
# ---------------------------------------------------------------------------

class TestComputeCrashMetadata:
    def test_basic_metadata(self, tmp_path):
        data = b"\xDE\xAD\xBE\xEF"
        path = tmp_path / "crash-abc123"
        meta = fcp.compute_crash_metadata(data, path)
        assert meta["crash_file"] == "crash-abc123"
        assert meta["crash_sha256"] == hashlib.sha256(data).hexdigest()
        assert meta["crash_size_bytes"] == "4"
        assert "generated_at" in meta

    def test_explicit_fuzzer(self, tmp_path):
        path = tmp_path / "some_file"
        meta = fcp.compute_crash_metadata(b"\x00", path, fuzzer="honggfuzz")
        assert meta["fuzzer"] == "honggfuzz"

    def test_afl_detection(self, tmp_path):
        path = tmp_path / "id:000000,sig:11,src:000000"
        meta = fcp.compute_crash_metadata(b"\x00", path)
        assert meta["fuzzer"] == "afl"

    def test_libfuzzer_detection(self, tmp_path):
        path = tmp_path / "crash-1234567890abcdef"
        meta = fcp.compute_crash_metadata(b"\x00", path)
        assert meta["fuzzer"] == "libfuzzer"

    def test_oom_detection(self, tmp_path):
        path = tmp_path / "oom-abcdef"
        meta = fcp.compute_crash_metadata(b"\x00", path)
        assert meta["fuzzer"] == "libfuzzer"

    def test_unknown_fuzzer(self, tmp_path):
        path = tmp_path / "random_file.bin"
        meta = fcp.compute_crash_metadata(b"\x00", path)
        assert "fuzzer" not in meta


# ---------------------------------------------------------------------------
# Tests: region map loading
# ---------------------------------------------------------------------------

class TestLoadRegionMap:
    def test_load_valid(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text(textwrap.dedent("""\
            regions:
              - name: meta
                address: 0x00080000
                size: 16
        """))
        regions = fcp.load_region_map(str(m))
        assert len(regions) == 1
        assert regions[0]["address"] == 0x00080000

    def test_no_map(self):
        assert fcp.load_region_map(None) == []
        assert fcp.load_region_map("") == []

    def test_missing_regions_key(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text("foo: bar\n")
        with pytest.raises(ValueError, match="regions"):
            fcp.load_region_map(str(m))

    def test_missing_address(self, tmp_path):
        m = tmp_path / "map.yaml"
        m.write_text(textwrap.dedent("""\
            regions:
              - name: bad
                size: 16
        """))
        with pytest.raises(ValueError, match="address.*size.*required"):
            fcp.load_region_map(str(m))


# ---------------------------------------------------------------------------
# Tests: crash bytes to writes
# ---------------------------------------------------------------------------

class TestCrashBytesToWrites:
    def test_flat_mode(self):
        data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)
        writes = fcp.crash_bytes_to_writes(data, [], base_address=0x1000)
        assert len(writes) == 2
        assert writes[0] == {"address": "0x00001000", "u32": "0xDEADBEEF"}
        assert writes[1] == {"address": "0x00001004", "u32": "0xCAFEBABE"}

    def test_region_mode(self):
        data = struct.pack("<II", 0x11111111, 0x22222222)
        regions = [
            {"name": "a", "address": 0x1000, "size": 4},
            {"name": "b", "address": 0x2000, "size": 4},
        ]
        writes = fcp.crash_bytes_to_writes(data, regions)
        assert len(writes) == 2
        assert writes[0]["address"] == "0x00001000"
        assert writes[1]["address"] == "0x00002000"

    def test_excess_data_ignored(self):
        data = b"\x01\x02\x03\x04" + b"\xFF" * 100
        regions = [{"name": "a", "address": 0x1000, "size": 4}]
        writes = fcp.crash_bytes_to_writes(data, regions)
        assert len(writes) == 1

    def test_non_aligned(self):
        data = b"\xAA\xBB\xCC"
        writes = fcp.crash_bytes_to_writes(data, [], base_address=0x0)
        assert len(writes) == 1
        assert writes[0]["u32"] == "0x00CCBBAA"


# ---------------------------------------------------------------------------
# Tests: derive_meta_base
# ---------------------------------------------------------------------------

class TestDeriveMetaBase:
    def test_override(self):
        assert fcp.derive_meta_base({}, 0x5000) == 0x5000

    def test_from_slots(self):
        template = {
            "memory": {
                "slots": {
                    "exec": {"base": 0x00008000, "size": 0x38000},
                    "staging": {"base": 0x00040000, "size": 0x38000},
                }
            }
        }
        assert fcp.derive_meta_base(template, None) == 0x00078000

    def test_default(self):
        assert fcp.derive_meta_base({}, None) == 0x00080000


# ---------------------------------------------------------------------------
# Tests: staging image mode
# ---------------------------------------------------------------------------

class TestCrashAsStagingImage:
    def test_writes_file(self, tmp_path):
        data = b"\xDE\xAD" * 100
        crash_path = tmp_path / "crash-001"
        path = fcp.crash_as_staging_image(data, crash_path, tmp_path)
        assert Path(path).exists()
        assert Path(path).read_bytes() == data

    def test_deduplication(self, tmp_path):
        data = b"\xAA\xBB"
        crash1 = tmp_path / "crash-001"
        crash2 = tmp_path / "crash-002"
        path1 = fcp.crash_as_staging_image(data, crash1, tmp_path)
        path2 = fcp.crash_as_staging_image(data, crash2, tmp_path)
        # Same data -> same file name (SHA-based)
        assert Path(path1).name == Path(path2).name


# ---------------------------------------------------------------------------
# Tests: generate_profile
# ---------------------------------------------------------------------------

class TestGenerateProfile:
    def _template(self):
        return yaml.safe_load(BASE_PROFILE_YAML)

    def test_pre_boot_state_mode(self):
        data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)
        crash_path = Path("crash-test")
        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=crash_path,
            template=self._template(),
            regions=[],
            meta_base=0x00080000,
        )
        assert "fuzz" in profile["name"]
        assert len(profile["pre_boot_state"]) == 2
        assert profile["pre_boot_state"][0]["address"] == "0x00080000"
        assert profile["expect"]["should_find_issues"] is True
        assert "fuzz_metadata" in profile
        assert profile["fuzz_metadata"]["crash_file"] == "crash-test"

    def test_staging_image_mode(self, tmp_path):
        data = b"\x01\x02\x03\x04"
        crash_path = Path("crash-staging")
        staging_path = str(tmp_path / "staging.bin")
        (tmp_path / "staging.bin").write_bytes(data)

        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=crash_path,
            template=self._template(),
            regions=[],
            mode="staging_image",
            staging_image_path=staging_path,
        )
        assert profile["images"]["staging"] == staging_path
        # pre_boot_state should NOT be set in staging mode
        assert "pre_boot_state" not in profile or profile.get("pre_boot_state") is None

    def test_staging_image_requires_path(self):
        with pytest.raises(ValueError, match="staging_image_path"):
            fcp.generate_profile(
                crash_data=b"\x01",
                crash_path=Path("crash"),
                template=self._template(),
                regions=[],
                mode="staging_image",
                staging_image_path=None,
            )

    def test_no_expect_rejection(self):
        data = struct.pack("<I", 0x12345678)
        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=Path("crash"),
            template=self._template(),
            regions=[],
            meta_base=0x0,
            expect_rejection=False,
        )
        # Original template has should_find_issues: false
        assert profile["expect"]["should_find_issues"] is False

    def test_name_suffix(self):
        data = struct.pack("<I", 0xAAAAAAAA)
        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=Path("crash"),
            template=self._template(),
            regions=[],
            meta_base=0x0,
            name_suffix="regression_42",
        )
        assert "regression_42" in profile["name"]

    def test_with_regions(self):
        data = struct.pack("<IIII", 0x11, 0x22, 0x33, 0x44)
        regions = [
            {"name": "meta", "address": 0x00080000, "size": 8},
            {"name": "hdr", "address": 0x00040000, "size": 8},
        ]
        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=Path("crash"),
            template=self._template(),
            regions=regions,
        )
        writes = profile["pre_boot_state"]
        assert len(writes) == 4
        assert writes[0]["address"] == "0x00080000"
        assert writes[2]["address"] == "0x00040000"

    def test_metadata_sha256(self):
        data = b"hello fuzzer"
        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=Path("crash-hello"),
            template=self._template(),
            regions=[],
            meta_base=0x0,
        )
        expected_sha = hashlib.sha256(data).hexdigest()
        assert profile["fuzz_metadata"]["crash_sha256"] == expected_sha

    def test_staging_image_removes_stale_pre_boot_state(self, tmp_path):
        """staging_image mode must remove pre_boot_state from the template."""
        tmpl = self._template()
        # Inject a pre_boot_state into the template (simulates a template
        # that was originally written for pre_boot_state mode).
        tmpl["pre_boot_state"] = [
            {"address": "0x00080000", "u32": "0xDEADBEEF"},
        ]

        data = b"\x01\x02\x03\x04"
        staging_path = str(tmp_path / "staging.bin")
        (tmp_path / "staging.bin").write_bytes(data)

        profile = fcp.generate_profile(
            crash_data=data,
            crash_path=Path("crash-stale"),
            template=tmpl,
            regions=[],
            mode="staging_image",
            staging_image_path=staging_path,
        )
        assert "pre_boot_state" not in profile
        assert profile["images"]["staging"] == staging_path

    def test_empty_writes_raises(self):
        # Zero-length region that produces no writes
        regions = [{"name": "empty", "address": 0x1000, "size": 0}]
        with pytest.raises(ValueError, match="No pre_boot_state writes"):
            fcp.generate_profile(
                crash_data=b"\xFF" * 4,
                crash_path=Path("crash"),
                template=self._template(),
                regions=regions,
            )


# ---------------------------------------------------------------------------
# Tests: find_crash_files
# ---------------------------------------------------------------------------

class TestFindCrashFiles:
    def test_afl_pattern(self, tmp_path):
        (tmp_path / "id:000000,sig:11").write_bytes(b"\x00")
        (tmp_path / "id:000001,sig:06").write_bytes(b"\x01")
        (tmp_path / "README").write_text("ignore me")
        files = fcp.find_crash_files(tmp_path)
        assert len(files) == 2
        assert all("id:" in f.name for f in files)

    def test_libfuzzer_pattern(self, tmp_path):
        (tmp_path / "crash-abc123").write_bytes(b"\x00")
        (tmp_path / "oom-def456").write_bytes(b"\x01")
        (tmp_path / "timeout-ghi789").write_bytes(b"\x02")
        files = fcp.find_crash_files(tmp_path)
        assert len(files) == 3

    def test_fallback_to_all(self, tmp_path):
        (tmp_path / "file1.bin").write_bytes(b"\x00")
        (tmp_path / "file2.bin").write_bytes(b"\x01")
        files = fcp.find_crash_files(tmp_path)
        assert len(files) == 2

    def test_skips_directories(self, tmp_path):
        (tmp_path / "crash-real").write_bytes(b"\x00")
        (tmp_path / "subdir").mkdir()
        files = fcp.find_crash_files(tmp_path)
        assert len(files) == 1

    def test_empty_dir(self, tmp_path):
        files = fcp.find_crash_files(tmp_path)
        assert files == []

    def test_skips_symlinks(self, tmp_path):
        """Symlinks in crash dir must be excluded to prevent traversal."""
        real_file = tmp_path / "crash-real"
        real_file.write_bytes(b"\xAA")

        # Create a symlink that points to an arbitrary file outside the dir
        target = tmp_path / "outside" / "secret.key"
        target.parent.mkdir()
        target.write_text("sensitive data")
        link = tmp_path / "crash-link"
        link.symlink_to(target)

        files = fcp.find_crash_files(tmp_path)
        names = [f.name for f in files]
        assert "crash-real" in names
        assert "crash-link" not in names


# ---------------------------------------------------------------------------
# Tests: CLI end-to-end (single crash)
# ---------------------------------------------------------------------------

class TestCLISingleCrash:
    def test_pre_boot_state_mode(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash = tmp_path / "crash-deadbeef"
        crash.write_bytes(struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE))
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "--meta-base", "0x00080000",
            "-o", str(output),
        ])
        assert rc == 0
        assert output.exists()

        profile = yaml.safe_load(output.read_text())
        assert "fuzz" in profile["name"]
        assert len(profile["pre_boot_state"]) == 2
        assert profile["fuzz_metadata"]["crash_file"] == "crash-deadbeef"
        assert profile["expect"]["should_find_issues"] is True

    def test_staging_image_mode(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash = tmp_path / "crash-staging"
        crash.write_bytes(b"\x01\x02\x03\x04" * 16)
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "--mode", "staging_image",
            "-o", str(output),
        ])
        assert rc == 0

        profile = yaml.safe_load(output.read_text())
        assert "staging" in profile["images"]
        staging_bin = Path(profile["images"]["staging"])
        assert staging_bin.exists()
        assert staging_bin.read_bytes() == b"\x01\x02\x03\x04" * 16

    def test_with_address_map(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)

        addr_map = tmp_path / "map.yaml"
        addr_map.write_text(textwrap.dedent("""\
            regions:
              - name: metadata
                address: 0x00080000
                size: 8
        """))

        crash = tmp_path / "crash-mapped"
        crash.write_bytes(struct.pack("<II", 0xAAAAAAAA, 0xBBBBBBBB))
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "--address-map", str(addr_map),
            "-o", str(output),
        ])
        assert rc == 0

        profile = yaml.safe_load(output.read_text())
        assert len(profile["pre_boot_state"]) == 2
        assert profile["pre_boot_state"][0]["address"] == "0x00080000"

    def test_empty_crash_fails(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash = tmp_path / "crash-empty"
        crash.write_bytes(b"")
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "-o", str(output),
        ])
        assert rc == 1

    def test_no_expect_rejection(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash = tmp_path / "crash-norej"
        crash.write_bytes(struct.pack("<I", 0x12345678))
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "--meta-base", "0x0",
            "--no-expect-rejection",
            "-o", str(output),
        ])
        assert rc == 0

        profile = yaml.safe_load(output.read_text())
        assert profile["expect"]["should_find_issues"] is False

    def test_name_suffix(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash = tmp_path / "crash-suffix"
        crash.write_bytes(struct.pack("<I", 0xDEAD))
        output = tmp_path / "out.yaml"

        rc = fcp.main([
            "--crash-input", str(crash),
            "--base-profile", str(template),
            "--meta-base", "0x0",
            "--name-suffix", "reg001",
            "-o", str(output),
        ])
        assert rc == 0
        profile = yaml.safe_load(output.read_text())
        assert "reg001" in profile["name"]


# ---------------------------------------------------------------------------
# Tests: CLI batch mode
# ---------------------------------------------------------------------------

class TestCLIBatch:
    def test_batch_generates_profiles(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash-001").write_bytes(struct.pack("<I", 0x11111111))
        (crash_dir / "crash-002").write_bytes(struct.pack("<I", 0x22222222))
        (crash_dir / "crash-003").write_bytes(b"")  # empty, should be skipped

        out_dir = tmp_path / "regression"

        rc = fcp.main([
            "--crash-dir", str(crash_dir),
            "--base-profile", str(template),
            "--meta-base", "0x0",
            "--output-dir", str(out_dir),
        ])
        assert rc == 0

        profiles = list(out_dir.glob("*.yaml"))
        assert len(profiles) == 2

        # Each profile should have fuzz_metadata
        for p in profiles:
            profile = yaml.safe_load(p.read_text())
            assert "fuzz_metadata" in profile
            assert "fuzz" in profile["name"]

    def test_batch_empty_dir(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)
        crash_dir = tmp_path / "empty_crashes"
        crash_dir.mkdir()
        out_dir = tmp_path / "out"

        rc = fcp.main([
            "--crash-dir", str(crash_dir),
            "--base-profile", str(template),
            "--output-dir", str(out_dir),
        ])
        assert rc == 1

    def test_batch_not_a_dir(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)

        rc = fcp.main([
            "--crash-dir", str(tmp_path / "nonexistent"),
            "--base-profile", str(template),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 1

    def test_batch_staging_image_mode(self, tmp_path):
        template = tmp_path / "base.yaml"
        template.write_text(BASE_PROFILE_YAML)

        crash_dir = tmp_path / "crashes"
        crash_dir.mkdir()
        (crash_dir / "crash-001").write_bytes(b"\xAA" * 32)

        out_dir = tmp_path / "regression"

        rc = fcp.main([
            "--crash-dir", str(crash_dir),
            "--base-profile", str(template),
            "--mode", "staging_image",
            "--output-dir", str(out_dir),
        ])
        assert rc == 0

        profiles = list(out_dir.glob("*.yaml"))
        assert len(profiles) == 1
        profile = yaml.safe_load(profiles[0].read_text())
        assert "staging" in profile["images"]

        # The staging binary should exist
        staging_bins = list(out_dir.glob("fuzz_staging_*.bin"))
        assert len(staging_bins) == 1
        assert staging_bins[0].read_bytes() == b"\xAA" * 32


# ---------------------------------------------------------------------------
# Tests: fuzz_corpus profile field (schema validation)
# ---------------------------------------------------------------------------

class TestFuzzCorpusField:
    def test_fuzz_corpus_parsed(self, tmp_path):
        """fuzz_corpus field is parsed and stored on ProfileConfig."""
        profile_yaml = textwrap.dedent("""\
            schema_version: 1
            name: fuzz_corpus_test
            description: "Test fuzz_corpus field"
            platform: platforms/cortex_m0_nvm.repl
            flash_backend: nvm_ctrl
            bootloader:
              elf: examples/vulnerable_ota/firmware.elf
              entry: 0x10000000
            memory:
              sram: { start: 0x20000000, end: 0x20020000 }
              write_granularity: 8
              slots:
                exec: { base: 0x10000000, size: 0x38000 }
                staging: { base: 0x00040000, size: 0x38000 }
            images:
              staging: examples/vulnerable_ota/firmware.bin
            success_criteria:
              vtor_in_slot: exec
            fault_sweep:
              mode: runtime
              max_writes: 100
            expect:
              should_find_issues: true
            fuzz_corpus: corpus/crashes/
        """)
        p = tmp_path / "profile.yaml"
        p.write_text(profile_yaml)

        import profile_loader
        config = profile_loader.load_profile(str(p))
        assert config.fuzz_corpus == "corpus/crashes/"

    def test_fuzz_corpus_optional(self, tmp_path):
        """fuzz_corpus is optional -- profiles without it still load."""
        profile_yaml = textwrap.dedent("""\
            schema_version: 1
            name: no_corpus
            description: "No fuzz_corpus"
            platform: platforms/cortex_m0_nvm.repl
            flash_backend: nvm_ctrl
            bootloader:
              elf: examples/vulnerable_ota/firmware.elf
              entry: 0x10000000
            memory:
              sram: { start: 0x20000000, end: 0x20020000 }
              write_granularity: 8
              slots:
                exec: { base: 0x10000000, size: 0x38000 }
                staging: { base: 0x00040000, size: 0x38000 }
            images:
              staging: examples/vulnerable_ota/firmware.bin
            success_criteria:
              vtor_in_slot: exec
            fault_sweep:
              mode: runtime
              max_writes: 100
            expect:
              should_find_issues: false
        """)
        p = tmp_path / "profile.yaml"
        p.write_text(profile_yaml)

        import profile_loader
        config = profile_loader.load_profile(str(p))
        assert config.fuzz_corpus is None
