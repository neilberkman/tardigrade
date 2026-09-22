import os
import sys
import textwrap

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from audit_report import qualify_ownership_verdict  # noqa: E402
from fault_inject import FaultResult  # noqa: E402
from invariants import InvariantViolation, check_no_oob_writes  # noqa: E402
from profile_loader import ProfileError, load_profile  # noqa: E402
from render_results_html import render_ownership_layout_panel  # noqa: E402
from result_checks import _profile_partition_ranges  # noqa: E402


BASE_PROFILE = """
schema_version: 1
name: ownership_test
description: vendor-neutral durable-memory ownership fixture
platform: platforms/cortex_m4_flash_fast.repl
bootloader:
  elf: firmware.elf
  entry: 0x08000000
bootloader_region: { base: 0x08000000, size: 0x1000 }
ownership_manifest_complete: true
memory:
  sram: { start: 0x20000000, end: 0x20010000 }
  write_granularity: 4
  erase_regions:
    - { base: 0x08000000, size: 0x10000, sector_size: 0x1000 }
  slots:
    exec: { base: 0x08001000, size: 0x2000 }
    staging: { base: 0x08003000, size: 0x2000 }
images: {}
nvs_region: { address: 0x08005000, size: 0x1000 }
metadata_fault_regions:
  - { name: trailer, slot: staging, offset: 0x1F00, size: 0x100 }
persistent_state_layout:
  erase_regions:
    - { start: 0x08005000, end: 0x08006000, erase_size: 0x1000 }
  fields:
    - { name: rollback, base: 0x08005000, size: 8, role: security_monotonic, parent: nvs }
success_criteria:
  vtor_in_slot: exec
fault_sweep:
  mode: runtime
  max_writes: 1
  fault_types: [power_loss]
expect:
  should_find_issues: false
"""


def _load(tmp_path, profile_text=BASE_PROFILE):
    path = tmp_path / "profile.yaml"
    path.write_text(textwrap.dedent(profile_text), encoding="utf-8")
    return load_profile(path)


def test_complete_profile_ownership_is_assessed_and_reused_at_runtime(tmp_path):
    profile = _load(tmp_path)

    assert profile.ownership_plan["status"] == "assessed"
    expected = [
        (region["start"], region["end"])
        for region in profile.ownership_plan["write_ranges"]
    ]
    assert _profile_partition_ranges(profile) == expected
    trailer = next(
        region
        for region in profile.ownership_plan["regions"]
        if region["id"] == "metadata:trailer"
    )
    assert trailer["parent"] == "slot:staging"


def test_complete_profile_without_bootloader_ownership_fails_closed(tmp_path):
    text = BASE_PROFILE.replace(
        "bootloader_region: { base: 0x08000000, size: 0x1000 }\n", ""
    )
    with pytest.raises(ProfileError, match="requires bootloader_region"):
        _load(tmp_path, text)


def test_complete_profile_rejects_ownership_declaration_typo(tmp_path):
    text = BASE_PROFILE.replace("sector_size: 0x1000", "sector_szie: 0x1000")
    with pytest.raises(ProfileError, match="unknown field.*sector_szie"):
        _load(tmp_path, text)


def test_complete_profile_rejects_top_level_ownership_typo(tmp_path):
    text = BASE_PROFILE.replace(
        "metadata_fault_regions:", "metadata_fault_regoins:"
    )
    with pytest.raises(ProfileError, match="unknown field.*metadata_fault_regoins"):
        _load(tmp_path, text)


def test_profile_owner_outside_durable_bounds_is_rejected(tmp_path):
    text = BASE_PROFILE.replace("0x08005000", "0x08100000").replace(
        "0x08006000", "0x08101000"
    )
    with pytest.raises(ProfileError, match="outside declared durable-memory bounds"):
        _load(tmp_path, text)


def test_absolute_metadata_containment_must_be_explicit(tmp_path):
    text = BASE_PROFILE.replace(
        "- { name: trailer, slot: staging, offset: 0x1F00, size: 0x100 }",
        "- { name: trailer, start: 0x08004F00, end: 0x08005000 }",
    )
    with pytest.raises(ProfileError, match="overlaps peer.*explicit containment"):
        _load(tmp_path, text)


def test_unasserted_profile_reports_whole_device_safety_not_assessed(tmp_path):
    profile = _load(
        tmp_path,
        BASE_PROFILE.replace("ownership_manifest_complete: true", "ownership_manifest_complete: false"),
    )

    assert profile.ownership_plan["status"] == "not_assessed"
    assert profile.ownership_plan["reason"]


def test_explicit_partition_and_nvs_containment_is_accepted(tmp_path):
    text = BASE_PROFILE.replace(
        "    staging: { base: 0x08003000, size: 0x2000 }",
        "    staging: { base: 0x08003000, size: 0x2000 }\n"
        "  postmortem_partitions:\n"
        "    - { name: exec_state, base: 0x08001800, size: 0x100, parent: slot:exec }\n"
        "    - { name: config, base: 0x08005000, size: 0x1000 }",
    ).replace(
        "nvs_region: { address: 0x08005000, size: 0x1000 }",
        "nvs_region: { address: 0x08005000, size: 0x1000, parent: partition:config }",
    )
    profile = _load(tmp_path, text)

    regions = {region["id"]: region for region in profile.ownership_plan["regions"]}
    assert regions["partition:exec_state"]["parent"] == "slot:exec"
    assert regions["nvs"]["parent"] == "partition:config"


def _multi_component_profile(*, missing_component_bounds=False, misspelled=False):
    component_memory = textwrap.dedent("""
    memory:
      sram: { start: 0x20000000, end: 0x20010000 }
      write_granularity: 4
      erase_regions:
        - { base: 0x08000000, size: 0x10000, sector_size: 0x1000 }
      slots:
        exec: { base: 0x08001000, size: 0x2000 }
        staging: { base: 0x08003000, size: 0x2000 }
    """).strip()
    second_memory = component_memory
    if missing_component_bounds:
        second_memory = second_memory.replace(
            "  erase_regions:\n"
            "    - { base: 0x08000000, size: 0x10000, sector_size: 0x1000 }\n",
            "",
        )
    if misspelled:
        second_memory = second_memory.replace("sector_size", "sector_szie")
    components = """
multi_component:
  components:
    - name: first
      platform: platforms/cortex_m4_flash_fast.repl
      bootloader: { elf: first.elf, entry: 0x08000000 }
%s
    - name: second
      platform: platforms/cortex_m4_flash_fast.repl
      bootloader: { elf: second.elf, entry: 0x08000000 }
%s
""" % (
        textwrap.indent(component_memory, "      "),
        textwrap.indent(second_memory, "      "),
    )
    return BASE_PROFILE + components


def test_complete_multi_component_profile_assesses_every_component(tmp_path):
    profile = _load(tmp_path, _multi_component_profile())

    assert set(profile.ownership_plan["components"]) == {"first", "second"}
    assert all(
        plan["status"] == "assessed"
        for plan in profile.ownership_plan["components"].values()
    )


def test_complete_multi_component_profile_rejects_missing_component_bounds(tmp_path):
    with pytest.raises(ProfileError, match="requires memory.erase_regions bounds"):
        _load(tmp_path, _multi_component_profile(missing_component_bounds=True))


def test_complete_multi_component_profile_rejects_component_ownership_typo(tmp_path):
    with pytest.raises(ProfileError, match="unknown field.*sector_szie"):
        _load(tmp_path, _multi_component_profile(misspelled=True))


def test_pass_verdict_and_html_disclose_unassessed_ownership():
    plan = {
        "status": "not_assessed",
        "reason": "ownership manifest completeness was not asserted",
        "regions": [],
        "bounds": [],
    }

    assert qualify_ownership_verdict("PASS", plan).endswith(
        "whole-device layout not assessed"
    )
    panel = render_ownership_layout_panel(
        {"summary": {"ownership_layout": plan}}
    )
    assert "durable-memory ownership" in panel
    assert "NOT ASSESSED" in panel


def test_no_oob_writes_checks_the_full_program_width():
    result = FaultResult(1, "success", "exec", {}, "")
    check_no_oob_writes(
        result,
        write_log=[0x1FFC],
        partition_ranges=[(0x1000, 0x2000)],
        write_width=4,
    )
    with pytest.raises(InvariantViolation):
        check_no_oob_writes(
            result,
            write_log=[0x1FFD],
            partition_ranges=[(0x1000, 0x2000)],
            write_width=4,
        )
