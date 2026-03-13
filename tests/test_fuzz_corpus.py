from __future__ import annotations

import hashlib
import sys
import textwrap
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import fuzz_corpus  # noqa: E402


BASE_PROFILE_YAML = textwrap.dedent(
    """\
    schema_version: 1
    name: test_base
    description: "Base profile for fuzz corpus tests"
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
      max_writes: 8
    expect:
      should_find_issues: false
    """
)


def _write_base_profile(tmp_path: Path) -> Path:
    path = tmp_path / "base.yaml"
    path.write_text(BASE_PROFILE_YAML, encoding="utf-8")
    return path


def test_minimize_deduplicates_identical_pre_boot_state(tmp_path: Path) -> None:
    crash_dir = tmp_path / "crashes"
    crash_dir.mkdir()
    (crash_dir / "crash-a").write_bytes(b"\xAA\xBB\xCC\xDD")
    (crash_dir / "crash-b").write_bytes(b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44")

    address_map = tmp_path / "map.yaml"
    address_map.write_text(
        "regions:\n  - name: meta\n    address: 0x00080000\n    size: 4\n",
        encoding="utf-8",
    )

    output_dir = tmp_path / "minimized"
    summary = fuzz_corpus.minimize_corpus(
        crash_dir,
        output_dir,
        address_map=str(address_map),
    )

    assert summary["kept_count"] == 1
    assert summary["skipped_count"] == 1
    assert summary["skipped"][0]["reason"] == "duplicate_pre_boot_state"
    assert len(list(output_dir.iterdir())) == 1


def test_corpus_status_matches_profiles_by_crash_hash(tmp_path: Path) -> None:
    crash_dir = tmp_path / "crashes"
    crash_dir.mkdir()
    crash_a = crash_dir / "crash-a"
    crash_b = crash_dir / "crash-b"
    crash_a.write_bytes(b"AAAA")
    crash_b.write_bytes(b"BBBB")

    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    crash_a_sha = hashlib.sha256(b"AAAA").hexdigest()
    (profile_dir / "fuzz_regression_a.yaml").write_text(
        yaml.safe_dump({"fuzz_metadata": {"crash_sha256": crash_a_sha}}, sort_keys=False),
        encoding="utf-8",
    )

    summary = fuzz_corpus.corpus_status(crash_dir, profile_dir)
    assert summary["converted_count"] == 1
    assert summary["new_count"] == 1
    assert summary["converted"][0]["crash_file"] == "crash-a"
    assert summary["new"][0]["crash_file"] == "crash-b"


def test_convert_corpus_skip_existing_is_idempotent(tmp_path: Path) -> None:
    crash_dir = tmp_path / "crashes"
    crash_dir.mkdir()
    (crash_dir / "crash-a").write_bytes(b"\x01\x02\x03\x04")

    output_dir = tmp_path / "profiles"
    base_profile = _write_base_profile(tmp_path)

    first = fuzz_corpus.convert_corpus(
        crash_dir,
        base_profile,
        output_dir,
        skip_existing=False,
    )
    second = fuzz_corpus.convert_corpus(
        crash_dir,
        base_profile,
        output_dir,
        skip_existing=True,
    )

    assert first["generated_count"] == 1
    assert second["generated_count"] == 0
    assert second["skipped_count"] == 1
    assert second["skipped"][0]["reason"] == "existing_profile"
