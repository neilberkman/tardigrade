"""Tests for update-protocol artifact-binding and security-path analysis."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from profile_loader import load_profile
from update_protocol_analyzer import (
    UpdateProtocolError,
    analyze_update_protocol,
    iter_sequence_variants,
    main,
    parse_update_protocol,
)


VULNERABLE_PROFILE = ROOT / "profiles" / "update_protocol_artifact_binding_vulnerable.yaml"
FIXED_PROFILE = ROOT / "profiles" / "update_protocol_artifact_binding_fixed.yaml"


def _minimal_model():
    return {
        "metadata": {
            "routing_class": {
                "source": "unsigned_routing_hint",
                "semantic": "deployment_class",
                "authenticated": False,
                "available_after": "receive_hint",
            },
            "signed_class": {
                "source": "signed_control_record",
                "semantic": "deployment_class",
                "authenticated": True,
                "available_after": "authenticate_record",
            },
        },
        "events": {
            "receive_hint": {"kind": "message"},
            "check_routing_class": {
                "kind": "security_gate",
                "policy": "deployment_authorization",
                "metadata": "routing_class",
            },
            "authenticate_record": {"kind": "authentication"},
            "bind_classes": {"kind": "binding", "binding": "class_binding"},
            "commit": {"kind": "commit"},
        },
        "bindings": {
            "class_binding": {
                "fields": ["routing_class", "signed_class"],
                "before": "commit",
            }
        },
        "required_policies": ["deployment_authorization"],
        "sequences": [
            {
                "name": "normal",
                "events": [
                    "receive_hint",
                    "check_routing_class",
                    "authenticate_record",
                    "commit",
                ],
            }
        ],
    }


class RegressionProfileTests(unittest.TestCase):
    def test_vulnerable_profile_detects_untrusted_metadata_and_binding_failures(self):
        profile = load_profile(VULNERABLE_PROFILE, strict=True)
        report = analyze_update_protocol(profile.update_protocol, profile.security_policy)

        self.assertEqual(report["verdict"], "FAIL")
        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn("UNAUTHENTICATED_SECURITY_METADATA", finding_ids)
        self.assertIn("MISSING_EXPECTED_BINDING", finding_ids)
        self.assertIn("SECURITY_GATE_BYPASS", finding_ids)
        bypass = next(
            finding
            for finding in report["findings"]
            if finding["id"] == "SECURITY_GATE_BYPASS"
        )
        self.assertIn("without routing_hint", bypass["sequence"])
        self.assertEqual(report["variants_analyzed"], 2)
        self.assertEqual(report["commit_paths_analyzed"], 2)

    def test_fixed_profile_protects_normal_and_no_hint_paths(self):
        profile = load_profile(FIXED_PROFILE, strict=True)
        report = analyze_update_protocol(profile.update_protocol, profile.security_policy)

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["variants_analyzed"], 2)
        self.assertEqual(report["commit_paths_analyzed"], 2)

    def test_profile_loader_exposes_inherited_protocol_model(self):
        profile = load_profile(FIXED_PROFILE)
        self.assertIsNotNone(profile.update_protocol)
        self.assertIn("signed_class", profile.update_protocol.metadata)

    def test_cli_json_and_exit_statuses(self):
        for profile_path, expected_status, expected_verdict in (
            (VULNERABLE_PROFILE, 1, "FAIL"),
            (FIXED_PROFILE, 0, "PASS"),
        ):
            output = io.StringIO()
            with self.subTest(profile=profile_path.name), contextlib.redirect_stdout(output):
                status = main(["--profile", str(profile_path), "--json"])
            self.assertEqual(status, expected_status)
            self.assertEqual(json.loads(output.getvalue())["verdict"], expected_verdict)

    def test_cli_rejects_profile_without_protocol_model(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(
                ["--profile", str(ROOT / "profiles" / "naive_bare_copy.yaml")]
            )
        self.assertEqual(status, 2)
        self.assertIn("no update_protocol block", stderr.getvalue())


class OptionalPathTests(unittest.TestCase):
    def test_optional_group_is_removed_atomically(self):
        raw = _minimal_model()
        raw["sequences"][0]["events"] = [
            {"event": "receive_hint", "optional_group": "routing_hint"},
            {"event": "check_routing_class", "optional_group": "routing_hint"},
            "authenticate_record",
            "commit",
        ]
        model = parse_update_protocol(raw)
        variants = list(iter_sequence_variants(model))

        self.assertEqual(len(variants), 2)
        self.assertEqual(
            {events for _, events in variants},
            {
                ("authenticate_record", "commit"),
                ("receive_hint", "check_routing_class", "authenticate_record", "commit"),
            },
        )

    def test_explicit_alternative_sequence_is_analyzed(self):
        raw = _minimal_model()
        raw["sequences"].append(
            {"name": "direct", "events": ["authenticate_record", "commit"]}
        )
        report = analyze_update_protocol(parse_update_protocol(raw))

        bypass_sequences = {
            finding["sequence"]
            for finding in report["findings"]
            if finding["id"] == "SECURITY_GATE_BYPASS"
        }
        self.assertEqual(bypass_sequences, {"direct"})


class MetadataBindingTests(unittest.TestCase):
    def test_untrusted_gate_without_authenticated_peer_is_reported(self):
        raw = _minimal_model()
        del raw["metadata"]["signed_class"]
        del raw["events"]["authenticate_record"]
        del raw["events"]["bind_classes"]
        raw["bindings"] = {}
        raw["sequences"][0]["events"] = [
            "receive_hint",
            "check_routing_class",
            "commit",
        ]

        report = analyze_update_protocol(parse_update_protocol(raw))
        finding = next(
            item
            for item in report["findings"]
            if item["id"] == "UNAUTHENTICATED_SECURITY_METADATA"
        )
        self.assertEqual(finding["evidence"]["authenticated_metadata"], [])

    def test_authenticated_gate_is_sufficient_for_policy(self):
        raw = _minimal_model()
        raw["events"]["check_signed_class"] = {
            "kind": "security_gate",
            "policy": "deployment_authorization",
            "metadata": "signed_class",
        }
        raw["bindings"]["class_binding"]["required"] = False
        raw["sequences"][0]["events"] = [
            "authenticate_record",
            "check_signed_class",
            "commit",
        ]

        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertEqual(report["verdict"], "PASS")

    def test_valid_binding_protects_untrusted_gate(self):
        raw = _minimal_model()
        raw["sequences"][0]["events"].insert(-1, "bind_classes")

        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertEqual(report["verdict"], "PASS")

    def test_binding_before_authenticated_metadata_does_not_count(self):
        raw = _minimal_model()
        raw["sequences"][0]["events"] = [
            "receive_hint",
            "check_routing_class",
            "bind_classes",
            "authenticate_record",
            "commit",
        ]

        report = analyze_update_protocol(parse_update_protocol(raw))
        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn("UNAUTHENTICATED_SECURITY_METADATA", finding_ids)
        self.assertIn("MISSING_EXPECTED_BINDING", finding_ids)

    def test_gate_before_metadata_is_available_does_not_dominate_commit(self):
        raw = _minimal_model()
        raw["bindings"]["class_binding"]["required"] = False
        raw["sequences"][0]["events"] = [
            "check_routing_class",
            "receive_hint",
            "authenticate_record",
            "commit",
        ]

        report = analyze_update_protocol(parse_update_protocol(raw))
        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn("GATE_METADATA_UNAVAILABLE", finding_ids)
        self.assertIn("SECURITY_GATE_BYPASS", finding_ids)


class ValidationTests(unittest.TestCase):
    def test_unknown_metadata_reference_is_rejected(self):
        raw = _minimal_model()
        raw["events"]["check_routing_class"]["metadata"] = "unknown_class"
        with self.assertRaisesRegex(UpdateProtocolError, "unknown field"):
            parse_update_protocol(raw)


def _content_model(events, sequence=None, *, size=16, destinations=None):
    return {
        "content": {
            "control_record": {"semantic": "signed_control_record"},
            "resource_bundle": {"semantic": "resource_bundle", "size": size},
        },
        "destinations": destinations or {
            "quarantine": {"role": "staging"},
            "active_store": {"role": "executable", "require_modeled_content": True},
        },
        "content_bindings": {
            "resource_digest": {
                "authenticated_parent": "control_record",
                "child": "resource_bundle",
                "method": "digest",
            }
        },
        "events": events,
        "sequences": [{"name": "content", "events": sequence or list(events)}],
    }


class AuthenticatedContentTests(unittest.TestCase):
    def test_omitted_commit_destinations_fail_when_committed_destination_is_modeled(self):
        raw = _content_model(
            {
                "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
                "write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
                "commit": {"kind": "commit"},
            },
            ["auth", "write", "commit"],
        )

        report = analyze_update_protocol(parse_update_protocol(raw))

        finding = next(
            finding
            for finding in report["findings"]
            if finding["id"] == "COMMIT_WITHOUT_DECLARED_DESTINATIONS"
        )
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(finding["severity"], "configuration")
        self.assertEqual(
            finding["evidence"]["declared_committed_destinations"],
            ["active_store"],
        )
        self.assertEqual(finding["evidence"]["commit_event"], "commit")

    def test_legacy_metadata_only_commit_without_destinations_is_unchanged(self):
        raw = _minimal_model()
        raw["required_policies"] = []
        raw["bindings"]["class_binding"]["required"] = False

        report = analyze_update_protocol(parse_update_protocol(raw))

        self.assertEqual(report["verdict"], "PASS")
        self.assertNotIn(
            "COMMIT_WITHOUT_DECLARED_DESTINATIONS",
            {finding["id"] for finding in report["findings"]},
        )

    def test_control_record_authentication_does_not_cover_resource(self):
        raw = _content_model(
            {
                "record_auth": {"kind": "authentication", "covers": ["control_record"]},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["record_auth", "write", "commit"],
        )
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertIn("UNAUTHENTICATED_COMMITTED_CONTENT", {f["id"] for f in report["findings"]})

    def test_record_digest_binding_covers_resource(self):
        raw = _content_model(
            {
                "record_auth": {"kind": "authentication", "covers": ["control_record"]},
                "digest": {"kind": "content_binding", "content_binding": "resource_digest"},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["record_auth", "digest", "write", "commit"],
        )
        self.assertEqual(analyze_update_protocol(parse_update_protocol(raw))["verdict"], "PASS")

    def test_binding_before_parent_authentication_does_not_cover(self):
        raw = _content_model(
            {
                "record_auth": {"kind": "authentication", "covers": ["control_record"]},
                "digest": {"kind": "content_binding", "content_binding": "resource_digest"},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["digest", "record_auth", "write", "commit"],
        )
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertIn("UNAUTHENTICATED_COMMITTED_CONTENT", {f["id"] for f in report["findings"]})

    def test_direct_and_block_authentication_cover_resource(self):
        direct = _content_model(
            {
                "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["auth", "write", "commit"],
        )
        self.assertEqual(analyze_update_protocol(parse_update_protocol(direct))["verdict"], "PASS")
        block = _content_model(
            {
                "a": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 0, "size": 8}]},
                "b": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 7, "size": 9}]},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["a", "b", "write", "commit"],
        )
        self.assertEqual(analyze_update_protocol(parse_update_protocol(block))["verdict"], "PASS")

    def test_range_gap_and_after_commit_are_reported(self):
        raw = _content_model(
            {
                "a": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 0, "size": 4}]},
                "b": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 8, "size": 8}]},
                "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["a", "b", "write", "commit"],
        )
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertIn("UNAUTHENTICATED_COMMITTED_CONTENT", {f["id"] for f in report["findings"]})
        raw["events"]["late"] = {"kind": "authentication", "covers": ["resource_bundle"]}
        raw["sequences"][0]["events"] = ["write", "commit", "late"]
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertIn("CONTENT_AUTHENTICATED_AFTER_COMMIT", {f["id"] for f in report["findings"]})
        late_finding = next(f for f in report["findings"] if f["id"] == "CONTENT_AUTHENTICATED_AFTER_COMMIT")
        self.assertEqual(late_finding["evidence"]["authentication_events"], ["late"])

    def test_range_union_must_cover_each_written_range(self):
        raw = _content_model(
            {
                "first": {
                    "kind": "authentication",
                    "covers": [
                        {"content": "resource_bundle", "offset": 0, "size": 8},
                    ],
                },
                "second": {
                    "kind": "authentication",
                    "covers": [
                        {"content": "resource_bundle", "offset": 8, "size": 8},
                    ],
                },
                "write_first": {
                    "kind": "write",
                    "content": {"content": "resource_bundle", "offset": 0, "size": 4},
                    "destination": "active_store",
                },
                "write_second": {
                    "kind": "write",
                    "content": {"content": "resource_bundle", "offset": 4, "size": 12},
                    "destination": "active_store",
                },
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["first", "second", "write_first", "write_second", "commit"],
        )
        self.assertEqual(analyze_update_protocol(parse_update_protocol(raw))["verdict"], "PASS")

        raw["events"]["second"]["covers"][0]["offset"] = 9
        raw["events"]["second"]["covers"][0]["size"] = 7
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertIn(
            "UNAUTHENTICATED_COMMITTED_CONTENT",
            {finding["id"] for finding in report["findings"]},
        )

    def test_optional_verification_and_staging_behavior(self):
        events = {
            "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
            "write": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
            "commit": {"kind": "commit", "destinations": ["active_store"]},
        }
        raw = _content_model(events, [{"event": "auth", "optional": True}, "write", "commit"])
        report = analyze_update_protocol(parse_update_protocol(raw))
        self.assertEqual(report["variants_analyzed"], 2)
        self.assertEqual(
            {f["sequence"] for f in report["findings"] if f["id"] == "UNAUTHENTICATED_COMMITTED_CONTENT"},
            {"content [without 0:0]"},
        )
        quarantine = _content_model(
            {"write": {"kind": "write", "content": "resource_bundle", "destinations": ["quarantine"]},
             "commit": {"kind": "commit", "destinations": ["quarantine"]}},
            ["write", "commit"],
            destinations={"quarantine": {"role": "staging"}},
        )
        self.assertEqual(analyze_update_protocol(parse_update_protocol(quarantine))["verdict"], "PASS")
        quarantine["sequences"] = [{"name": "prepare", "events": ["write"]}]
        self.assertEqual(analyze_update_protocol(parse_update_protocol(quarantine))["verdict"], "PASS")

    def test_staging_copy_and_unknown_destination_content(self):
        raw = _content_model(
            {"copy": {"kind": "write", "content": "resource_bundle", "destinations": ["active_store"]},
             "commit": {"kind": "commit", "destinations": ["active_store"]}},
            ["copy", "commit"],
        )
        self.assertIn("UNAUTHENTICATED_COMMITTED_CONTENT", {f["id"] for f in analyze_update_protocol(parse_update_protocol(raw))["findings"]})
        raw["sequences"] = [{"name": "empty", "events": ["commit"]}]
        self.assertIn("COMMIT_DESTINATION_WITH_UNKNOWN_CONTENT", {f["id"] for f in analyze_update_protocol(parse_update_protocol(raw))["findings"]})

    def test_safe_sequence_does_not_mask_uncommitted_executable_write(self):
        raw = _content_model(
            {
                "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
                "safe_write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
                "bad_write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["auth", "safe_write", "commit"],
        )
        raw["sequences"].append(
            {"name": "uncommitted", "events": ["bad_write"]}
        )

        report = analyze_update_protocol(parse_update_protocol(raw))

        finding = next(
            finding
            for finding in report["findings"]
            if finding["id"] == "WRITE_WITHOUT_GOVERNING_COMMIT"
        )
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(finding["sequence"], "uncommitted")
        self.assertEqual(finding["evidence"]["write_event"], "bad_write")
        self.assertEqual(finding["evidence"]["destination"], "active_store")

    def test_write_after_last_relevant_commit_is_reported(self):
        raw = _content_model(
            {
                "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
                "commit": {"kind": "commit", "destinations": ["active_store"]},
                "late_write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
            },
            ["auth", "commit", "late_write"],
        )

        report = analyze_update_protocol(parse_update_protocol(raw))

        finding = next(
            finding
            for finding in report["findings"]
            if finding["id"] == "WRITE_WITHOUT_GOVERNING_COMMIT"
        )
        self.assertEqual(finding["sequence"], "content")
        self.assertEqual(finding["evidence"]["write_event"], "late_write")

    def test_uncommitted_staging_only_variant_remains_valid(self):
        raw = _content_model(
            {
                "auth": {"kind": "authentication", "covers": ["resource_bundle"]},
                "active_write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
                "stage_write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "quarantine",
                },
                "commit": {"kind": "commit", "destinations": ["active_store"]},
            },
            ["auth", "active_write", "commit"],
        )
        raw["sequences"].append(
            {"name": "prepare_only", "events": ["stage_write"]}
        )

        report = analyze_update_protocol(parse_update_protocol(raw))

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["findings"], [])

    def test_content_findings_name_the_commit_event(self):
        raw = _content_model(
            {
                "write": {
                    "kind": "write",
                    "content": "resource_bundle",
                    "destination": "active_store",
                },
                "activate": {
                    "kind": "commit",
                    "destinations": ["active_store"],
                },
            },
            ["write", "activate"],
        )
        finding = next(
            finding
            for finding in analyze_update_protocol(parse_update_protocol(raw))["findings"]
            if finding["id"] == "UNAUTHENTICATED_COMMITTED_CONTENT"
        )
        self.assertEqual(finding["evidence"]["write_event"], "write")
        self.assertEqual(finding["evidence"]["commit_event"], "activate")

    def test_content_reference_validation(self):
        raw = _content_model({"auth": {"kind": "authentication", "covers": ["typo"]}, "commit": {"kind": "commit", "destinations": ["active_store"]}}, ["auth", "commit"])
        with self.assertRaisesRegex(UpdateProtocolError, "unknown content"):
            parse_update_protocol(raw)
        raw = _content_model({"auth": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 10, "size": 7}]}, "commit": {"kind": "commit", "destinations": ["active_store"]}}, ["auth", "commit"])
        with self.assertRaisesRegex(UpdateProtocolError, "outside declared size"):
            parse_update_protocol(raw)
        raw = _content_model({"auth": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": -1, "size": 2}]}, "commit": {"kind": "commit", "destinations": ["active_store"]}}, ["auth", "commit"])
        with self.assertRaisesRegex(UpdateProtocolError, "non-negative"):
            parse_update_protocol(raw)
        raw = _content_model({"auth": {"kind": "authentication", "covers": [{"content": "resource_bundle", "offset": 0, "size": 0}]}, "commit": {"kind": "commit", "destinations": ["active_store"]}}, ["auth", "commit"])
        with self.assertRaisesRegex(UpdateProtocolError, "positive"):
            parse_update_protocol(raw)

    def test_destination_and_content_binding_references_are_validated(self):
        raw = _content_model(
            {"write": {"kind": "write", "content": "resource_bundle", "destination": "typo"},
             "commit": {"kind": "commit", "destinations": ["active_store"]}},
            ["write", "commit"],
        )
        with self.assertRaisesRegex(UpdateProtocolError, "unknown destination"):
            parse_update_protocol(raw)
        raw = _content_model(
            {"bind": {"kind": "content_binding", "content_binding": "typo"},
             "commit": {"kind": "commit", "destinations": ["active_store"]}},
            ["bind", "commit"],
        )
        with self.assertRaisesRegex(UpdateProtocolError, "unknown content binding"):
            parse_update_protocol(raw)
        raw = _content_model(
            {"commit": {"kind": "commit", "destinations": ["active_store", "active_store"]}},
            ["commit"],
        )
        with self.assertRaisesRegex(UpdateProtocolError, "duplicate destination"):
            parse_update_protocol(raw)

    def test_unknown_event_field_is_rejected(self):
        raw = _minimal_model()
        raw["events"]["commit"]["ignored"] = True
        with self.assertRaisesRegex(UpdateProtocolError, "unknown field"):
            parse_update_protocol(raw)

    def test_non_boolean_authenticated_is_rejected(self):
        raw = _minimal_model()
        raw["metadata"]["routing_class"]["authenticated"] = "false"
        with self.assertRaisesRegex(UpdateProtocolError, "expected boolean"):
            parse_update_protocol(raw)

    def test_path_expansion_is_bounded(self):
        raw = _minimal_model()
        raw["sequences"][0]["events"] = [
            {"event": "receive_hint", "optional": True} for _ in range(9)
        ] + ["commit"]
        with self.assertRaisesRegex(UpdateProtocolError, "more than 256"):
            parse_update_protocol(raw)

if __name__ == "__main__":
    unittest.main()
