"""Synthetic acceptance tests for logical counter boundary campaigns."""

from __future__ import annotations

import sys
import json
import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from boundary_campaigns import (  # noqa: E402
    BoundaryCampaignError,
    aggregate_boundary_results,
    parse_boundary_campaign,
    resolve_boundary_capacity,
    resolve_boundary_value,
    resolve_boundary_values,
    resolve_followup_value,
)
from profile_loader import load_profile  # noqa: E402
import audit_bootloader  # noqa: E402
from render_results_html import render_boundary_campaign_panel  # noqa: E402
from boundary_snapshot import MAGIC, read_snapshot, write_snapshot  # noqa: E402
from boundary_reserved import BOUNDARY_RESERVED_VARIABLES  # noqa: E402


def _campaign(**overrides):
    value = {
        "name": "synthetic_epoch_capacity",
        "parameter": "candidate_epoch",
        "type": "unsigned_integer",
        "width_bits": 32,
        "capacity": {"elements": 16},
        "values": ["zero", "one", "capacity_minus_one", "capacity", "capacity_plus_one", "type_max"],
        "setup_environment": "CANDIDATE_EPOCH",
        "follow_up": {"parameter_value": "previous", "expect": "rejected"},
    }
    value.update(overrides)
    return parse_boundary_campaign(value)


def _evidence():
    descriptor = {"name": "flash", "length": 1, "sha256": "a" * 64}
    return {
        "path": "/tmp/candidate.bin",
        "backend_identity": "sysbus.faultFlash|fast|otp=",
        "sha256": "b" * 64,
        "components": [descriptor],
    }


def _observed(row):
    return {
        **row,
        "boundary_snapshot_capture": _evidence(),
        "boundary_snapshot_restore": _evidence(),
    }


class BoundaryCampaignTest(unittest.TestCase):
    def test_named_and_literal_values_are_ordered_and_deduplicated(self):
        campaign = _campaign(values=["capacity", 16, "capacity_plus_one", 17, "zero"], follow_up=None)
        self.assertEqual(resolve_boundary_values(campaign), [16, 17, 0])
        self.assertEqual(resolve_boundary_value("capacity_plus_one", campaign), 17)

    def test_capacities(self):
        self.assertEqual(resolve_boundary_capacity({"elements": 16}), 16)
        self.assertEqual(resolve_boundary_capacity({"storage_bytes": 64, "element_bytes": 4}), 16)
        self.assertEqual(resolve_boundary_capacity({"storage_bytes": 8, "bits_per_increment": 1}), 64)

    def test_invalid_campaigns_fail_closed(self):
        for changes in (
            {"width_bits": 0},
            {"width_bits": 65},
            {"capacity": {"storage_bytes": 63, "element_bytes": 4}},
            {"capacity": {"storage_bytes": 8, "element_bytes": 0}},
            {"capacity": {"storage_bytes": 7, "bits_per_increment": 3}},
        ):
            with self.assertRaises(BoundaryCampaignError):
                _campaign(**changes)
        with self.assertRaises(BoundaryCampaignError):
            resolve_followup_value(0)
        with self.assertRaises(BoundaryCampaignError):
            _campaign(values=["zero"])
        with self.assertRaises(BoundaryCampaignError):
            _campaign(setup_environment="BOUNDARY_ACCEPTANCE")
        with self.assertRaises(BoundaryCampaignError):
            _campaign(follow_up={"parameter_value": "current", "expect": "rejected"})
        with self.assertRaises(BoundaryCampaignError):
            _campaign(follow_up={"parameter_value": "previous", "expect": "accepted"})

        # A setup hook cannot shadow any shared-suite input, not only the
        # handful of variables used to transport the campaign value.
        for name in (
            "IMAGE_EXEC_PATH", "NVS_REGION_ADDR", "CONFIRM_CYCLE_ENABLED",
            "BACKEND_BUS_BASE", "BACKEND_BUS_SIZE", "FUNCTION_RETURN_PROBES",
        ):
            self.assertIn(name, BOUNDARY_RESERVED_VARIABLES)
            with self.assertRaises(BoundaryCampaignError):
                _campaign(setup_environment=name)

    def test_runtime_monitor_inputs_are_all_reserved(self):
        source = (Path(__file__).parents[1] / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        keys = set(re.findall(
            r"(?:get_optional_var|get_optional_int_var|GetVariable)\(\s*['\"]([A-Za-z0-9_]+)['\"]",
            source,
        ))
        self.assertTrue(keys)
        self.assertEqual(
            {key.upper() for key in keys} - BOUNDARY_RESERVED_VARIABLES,
            set(),
        )

    def test_defective_counter_is_rollback_failure(self):
        campaign = _campaign(values=["capacity", "capacity_plus_one"])
        result = aggregate_boundary_results(
            campaign,
            [
                _observed({"resolved_value": 16, "candidate_status": "accepted", "persisted_value": 16, "follow_up_status": "rejected", "follow_up_value": 15}),
                _observed({"resolved_value": 17, "candidate_status": "accepted", "persisted_value": 16, "follow_up_status": "accepted", "follow_up_value": 16}),
            ],
        )
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["summary"]["follow_up_rollback_accepted"], 1)

    def test_corrected_counter_passes(self):
        campaign = _campaign(values=["capacity", "capacity_plus_one"])
        result = aggregate_boundary_results(
            campaign,
            [
                _observed({"resolved_value": 16, "candidate_status": "accepted", "persisted_value": 16, "follow_up_status": "rejected", "follow_up_value": 15}),
                _observed({"resolved_value": 17, "candidate_status": "rejected", "follow_up_status": "rejected", "follow_up_value": 16}),
            ],
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_unknown_status_or_missing_follow_up_is_inconclusive(self):
        campaign = _campaign(values=[16])
        unknown = aggregate_boundary_results(
            campaign,
            [_observed({"resolved_value": 16, "candidate_status": "maybe", "persisted_value": 16,
              "follow_up_status": "rejected", "follow_up_value": 15})],
        )
        missing_follow_up = aggregate_boundary_results(
            campaign,
            [_observed({"resolved_value": 16, "candidate_status": "accepted", "persisted_value": 16})],
        )
        self.assertEqual(unknown["verdict"], "INCONCLUSIVE")
        self.assertEqual(missing_follow_up["verdict"], "INCONCLUSIVE")

    def test_display_status_aliases_are_not_protocol_tokens(self):
        result = aggregate_boundary_results(
            _campaign(values=[16]),
            [_observed({"resolved_value": 16,
                        "candidate_status": "candidate accepted",
                        "persisted_value": 16,
                        "follow_up_status": "follow-up rejected",
                        "follow_up_value": 15})],
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_acceptance_tokens_are_case_sensitive(self):
        self.assertIsNone(audit_bootloader._boundary_acceptance_status(
            {"signals": {"boundary_acceptance_status": "ACCEPTED"}}
        ))
        result = aggregate_boundary_results(
            _campaign(values=[16]),
            [_observed({"resolved_value": 16,
                        "candidate_status": "Accepted",
                        "persisted_value": 16,
                        "follow_up_status": "rejected",
                        "follow_up_value": 15})],
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_snapshot_evidence_must_match_between_phases(self):
        row = _observed({
            "resolved_value": 16,
            "candidate_status": "accepted",
            "persisted_value": 16,
            "follow_up_status": "rejected",
            "follow_up_value": 15,
        })
        row["boundary_snapshot_restore"] = dict(_evidence(), sha256="c" * 64)
        result = aggregate_boundary_results(_campaign(values=[16]), [row])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("digests differ", result["results"][0]["infrastructure_reason"])

    def test_boot_success_does_not_imply_candidate_acceptance(self):
        observation = audit_bootloader._boundary_observation(
            {
                "boundary_campaign": {"name": "synthetic_epoch_capacity", "resolved_value": 17},
                "runtime_sweep_results": [{
                    "is_control": True,
                    "boot_outcome": "success",
                    "signals": {"boundary_acceptance_status": "rejected"},
                    "semantic_state": {"candidate_epoch": 16},
                }],
            },
            _campaign(values=[17]),
            17,
        )
        self.assertEqual(observation["candidate_status"], "rejected")
        self.assertEqual(observation["persisted_value"], 16)

    def test_child_must_echo_the_expected_resolved_value(self):
        observation = audit_bootloader._boundary_observation(
            {
                "boundary_campaign": {"name": "synthetic_epoch_capacity", "resolved_value": 17},
                "runtime_sweep_results": [{
                    "is_control": True,
                    "boot_outcome": "success",
                    "signals": {"boundary_acceptance_status": "rejected"},
                }],
            },
            _campaign(values=[16]),
            16,
        )
        self.assertTrue(observation["infrastructure_failure"])

    def test_html_reports_verdict_infrastructure_and_each_value(self):
        campaign_report = aggregate_boundary_results(
            _campaign(values=[16]),
            [_observed({"resolved_value": 16, "candidate_status": "accepted", "persisted_value": 16,
              "follow_up_status": "rejected", "follow_up_value": 15})],
        )
        rendered = render_boundary_campaign_panel(
            {"boundary_campaign_results": [campaign_report]}
        )
        self.assertIn("PASS", rendered)
        self.assertIn("infrastructure", rendered)
        self.assertIn("per-value evidence", rendered)
        self.assertIn("candidate accepted and correctly persisted", rendered)
        self.assertIn("/tmp/candidate.bin", rendered)
        self.assertIn("sysbus.faultFlash|fast|otp=", rendered)
        self.assertIn("flash", rendered)
        self.assertIn("sha256=", rendered)

    def test_snapshot_backend_identity_mismatch_is_inconclusive(self):
        row = _observed({
            "resolved_value": 16,
            "candidate_status": "accepted",
            "persisted_value": 16,
            "follow_up_status": "rejected",
            "follow_up_value": 15,
        })
        row["boundary_snapshot_restore"] = dict(
            _evidence(), backend_identity="sysbus.other|fast|otp="
        )
        result = aggregate_boundary_results(_campaign(values=[16]), [row])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("backend identities", result["results"][0]["infrastructure_reason"])

    def test_boundary_fail_exit_is_suppressed_by_no_assert_verdict(self):
        from profile_loader import InitialStateConfig

        campaign = _campaign(values=[16], follow_up=None)
        state = InitialStateConfig(
            name="synthetic_epoch_capacity__16",
            boundary_campaign=campaign,
            boundary_value=16,
            boundary_previous_value=None,
        )
        profile = mock.Mock()
        profile.initial_states = [state]
        profile.boundary_campaigns = [campaign]
        profile.name = "boundary_test"
        profile.profile_path = None
        profile.schema_version = 1

        def fake_run(command, **_kwargs):
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps({
                "verdict": "PASS",
                "boundary_campaign": {"name": campaign.name, "resolved_value": 16},
                "runtime_sweep_results": [{
                    "is_control": True,
                    "boot_outcome": "success",
                    "signals": {"boundary_acceptance_status": "accepted"},
                    "semantic_state": {"candidate_epoch": 15},
                }],
            }), encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            audit_bootloader.subprocess, "run", side_effect=fake_run
        ), mock.patch.object(audit_bootloader, "git_metadata", return_value={}):
            args = mock.Mock(
                repo_root=str(Path.cwd()), output=str(Path(td) / "matrix.json"),
                no_assert_verdict=True,
            )
            self.assertEqual(audit_bootloader._run_initial_state_matrix(args, profile), 0)

    def test_boundary_inconclusive_exit_is_not_suppressed(self):
        from profile_loader import InitialStateConfig

        campaign = _campaign(values=[16], follow_up=None)
        state = InitialStateConfig(
            name="synthetic_epoch_capacity__16",
            boundary_campaign=campaign,
            boundary_value=16,
            boundary_previous_value=None,
        )
        profile = mock.Mock()
        profile.initial_states = [state]
        profile.boundary_campaigns = [campaign]
        profile.name = "boundary_test"
        profile.profile_path = None
        profile.schema_version = 1

        def fake_run(command, **_kwargs):
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps({
                "verdict": "PASS",
                "boundary_campaign": {"name": campaign.name, "resolved_value": 16},
                "runtime_sweep_results": [{
                    "is_control": True,
                    "boot_outcome": "success",
                    "signals": {},
                }],
            }), encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            audit_bootloader.subprocess, "run", side_effect=fake_run
        ), mock.patch.object(audit_bootloader, "git_metadata", return_value={}):
            args = mock.Mock(
                repo_root=str(Path.cwd()), output=str(Path(td) / "matrix.json"),
                no_assert_verdict=True,
            )
            self.assertEqual(
                audit_bootloader._run_initial_state_matrix(args, profile),
                audit_bootloader.EXIT_INFRA_FAILURE,
            )

    def test_transport_reaches_renode_setup_path_without_dynamic_robot_name(self):
        """The resolved value crosses Robot into the Renode setup hook."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profile_path = root / "profile.yaml"
            profile_path.write_text(
                """
schema_version: 1
name: boundary_transport
platform: platforms/cortex_m4_flash_fast.repl
bootloader:
  elf: examples/vulnerable_ota/firmware.elf
  entry: 0x10000000
memory:
  sram: {start: 0x20000000, end: 0x20020000}
  write_granularity: 4
  slots:
    exec: {base: 0x10000000, size: 0x1000}
    staging: {base: 0x10001000, size: 0x1000}
images:
  staging: examples/vulnerable_ota/firmware.bin
success_criteria:
  vtor_in_slot: exec
boundary_campaigns:
  - name: synthetic_epoch_capacity
    parameter: candidate_epoch
    type: unsigned_integer
    width_bits: 32
    capacity: {elements: 16}
    values: [17]
    setup_environment: CANDIDATE_EPOCH
expect:
  should_find_issues: false
""",
                encoding="utf-8",
            )
            profile = load_profile(profile_path)
            resolved = profile.resolve_initial_state(profile.initial_states[0])
            robot_vars = resolved.robot_vars(root)

        self.assertIn("BOUNDARY_SETUP_ENV:CANDIDATE_EPOCH", robot_vars)
        self.assertIn("BOUNDARY_VALUE:17", robot_vars)
        self.assertNotIn("CANDIDATE_EPOCH:17", robot_vars)
        follow_vars = audit_bootloader._common_robot_vars(
            resolved, root, evaluation_mode="state", stall_timeout=1.0,
            extra_robot_vars=["BOUNDARY_VALUE:16", "BOUNDARY_PHASE:follow_up"],
        )
        self.assertIn("BOUNDARY_VALUE:16", follow_vars)
        self.assertNotIn("BOUNDARY_VALUE:17", follow_vars)
        robot_text = (Path(__file__).parents[1] / "tests" / "ota_fault_point.robot").read_text(
            encoding="utf-8"
        )
        runtime_text = (Path(__file__).parents[1] / "scripts" / "run_runtime_fault_sweep.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('$boundary_value="${BOUNDARY_VALUE}"', robot_text)
        self.assertIn("apply_boundary_setup_environment()", runtime_text)
        self.assertIn("monitor.Parse('${}={}'.format", runtime_text)

    def test_matrix_runs_candidate_then_n_minus_one_follow_up(self):
        """The matrix owns the two child runs and transports the durable state."""
        campaign = _campaign(values=[17])
        from profile_loader import InitialStateConfig

        state = InitialStateConfig(
            name="synthetic_epoch_capacity__17",
            boundary_campaign=campaign,
            boundary_value=17,
            boundary_previous_value=16,
        )
        profile = mock.Mock()
        profile.initial_states = [state]
        profile.boundary_campaigns = [campaign]
        profile.name = "boundary_test"
        profile.profile_path = None
        profile.schema_version = 1

        def fake_run(command, **_kwargs):
            output = Path(command[command.index("--output") + 1])
            is_follow_up = "BOUNDARY_PHASE:follow_up" in command
            if is_follow_up:
                durable = next(
                    item.split(":", 1)[1]
                    for item in command
                    if item.startswith("BOUNDARY_DURABLE_STATE_FILE:")
                )
                restored, _header = read_snapshot(
                    durable, "|", {"flash": 1}
                )
                payload = {
                    "verdict": "PASS",
                    "boundary_campaign": {"name": campaign.name, "resolved_value": 16},
                    "runtime_sweep_results": [{
                        "is_control": True,
                        "boot_outcome": "rejected",
                        "signals": {
                            "boundary_acceptance_status": "rejected",
                            "boundary_snapshot_restore": _evidence(),
                        },
                        "semantic_state": {"candidate_epoch": restored["flash"][0]},
                    }],
                }
            else:
                payload = {
                    "verdict": "PASS",
                    "boundary_campaign": {"name": campaign.name, "resolved_value": 17},
                    "runtime_sweep_results": [{
                        "is_control": True,
                        "boot_outcome": "success",
                        "signals": {
                            "boundary_acceptance_status": "accepted",
                            "boundary_snapshot_capture": _evidence(),
                        },
                        "semantic_state": {"candidate_epoch": 17},
                    }],
                }
                durable = next(
                    item.split(":", 1)[1]
                    for item in command
                    if item.startswith("BOUNDARY_DURABLE_STATE_FILE:")
                )
                write_snapshot(
                    durable, {"flash": bytes([17])}, "|"
                )
            output.write_text(json.dumps(payload), encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "matrix.json"
            args = mock.Mock(repo_root=str(Path.cwd()), output=str(output))
            with mock.patch.object(audit_bootloader.sys, "argv", ["audit_bootloader.py"]), \
                    mock.patch.object(audit_bootloader, "git_metadata", return_value={}), \
                    mock.patch.object(audit_bootloader.subprocess, "run", side_effect=fake_run) as run:
                self.assertEqual(audit_bootloader._run_initial_state_matrix(args, profile), 0)
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(run.call_count, 2)
        follow_command = run.call_args_list[1].args[0]
        self.assertIn("BOUNDARY_VALUE:16", follow_command)
        self.assertIn("BOUNDARY_PHASE:follow_up", follow_command)
        self.assertTrue(any(item.startswith("BOUNDARY_DURABLE_STATE_FILE:") for item in follow_command))
        self.assertEqual(report["boundary_campaign_results"][0]["verdict"], "PASS")

    def test_follow_up_reads_exact_candidate_persistent_bytes(self):
        """The durable artifact round-trips bytes, identity, and completeness."""
        candidate = {"flash": bytes([0x00, 0x11, 0x22]), "otp": bytes([0xFE, 0xED])}
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "candidate.bin"
            write_snapshot(artifact, candidate, "fast|fast")
            follow_up, header = read_snapshot(
                artifact, "fast|fast", {"flash": 3, "otp": 2}
            )
        self.assertEqual(follow_up, candidate)
        self.assertEqual([item["name"] for item in header["components"]], ["flash", "otp"])

    def test_snapshot_rejects_list_component_name_as_controlled_error(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "malformed.bin"
            header = {
                "version": 1,
                "identity": "identity",
                "components": [{"name": [], "length": 0, "sha256": hashlib.sha256(b"").hexdigest()}],
            }
            artifact.write_bytes(
                MAGIC + json.dumps(header).encode("utf-8") + b"\n"
            )
            with self.assertRaisesRegex(ValueError, "metadata name"):
                read_snapshot(artifact, "identity", {"flash": 0})

    def test_snapshot_writer_has_ironpython_rename_fallback(self):
        source = (Path(__file__).parents[1] / "scripts" / "boundary_snapshot.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('getattr(os, "replace", os.rename)', source)


if __name__ == "__main__":
    unittest.main()
