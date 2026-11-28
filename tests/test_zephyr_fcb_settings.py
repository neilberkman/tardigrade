#!/usr/bin/env python3
# Copyright (c) 2026 Neil Berkman
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Zephyr Flash Circular Buffer (FCB) and settings-on-FCB
targets (v3.7.0 and upstream head), deterministic pre-cut seed images,
profiles, upstream issue citations (#121749, #122446, #121748), and
kind-qualified durability oracle.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from fault_inject import FaultResult  # noqa: E402
from invariants import resolve_invariants, run_invariants  # noqa: E402
from profile_loader import load_profile  # noqa: E402
from result_checks import annotate_result_checks  # noqa: E402
from zephyr_fcb_oracle import (  # noqa: E402
    FCB_EXPECTED_POST_MASK,
    FCB_RAW_MAGIC,
    FCB_REC_FLAG_LIVE,
    FCB_REC_MAGIC_BASE,
    FCB_VERDICT_MAGIC_RAW,
    FCB_VERDICT_MAGIC_SETTINGS,
    FCB_VERDICT_SRAM_BASE,
    SETTINGS_FCB_MAGIC,
    VERDICT_WORD_NAMES,
    crc8_ccitt,
    evaluate_durability_verdict,
    expected_val0,
    expected_val1,
    parse_ack_boundary,
    parse_fcb_sector,
)

PINNED_ZEPHYR_COMMIT = "36940db938a8f4a1e919496793ed439850a221c2"
HEAD_ZEPHYR_COMMIT = "06b50e7c66d27d519826a49e3c524ed762873cb6"


def _make_memory_checks_signals(words: dict[str, int]) -> dict:
    checks = []
    for index, name in enumerate(VERDICT_WORD_NAMES):
        addr = FCB_VERDICT_SRAM_BASE + (index * 4)
        val = int(words.get(name, 0)) & 0xFFFFFFFF
        checks.append(
            {
                "index": index,
                "address": f"0x{addr:X}",
                "actual": val,
                "actual_hex": f"0x{val:08X}",
                "ok": True,
            }
        )
    return {
        "success_checks": {
            "requested": True,
            "all_ok": True,
            "memory_checks_ok": True,
            "memory_checks": checks,
        }
    }


def _clean_verdict_words(magic: int = FCB_VERDICT_MAGIC_RAW) -> dict[str, int]:
    return {
        "magic": magic,
        "oracle_ok": 1,
        "mount_ok": 1,
        "mount_oracle_ok": 1,
        "write_ok": 1,
        "post_oracle_ok": 1,
        "mount_present_mask": 0x3B,  # K0, K1, K3, K4, K5 present at mount
        "mount_torn_count": 0,
        "mount_seq_0": 1,
        "mount_seq_1": 10,
        "mount_seq_2": 0,
        "mount_seq_3": 4,
        "mount_seq_4": 12,
        "mount_seq_5": 13,
        "mount_seq_6": 0,
        "post_present_mask": FCB_EXPECTED_POST_MASK,
        "post_torn_count": 0,
        "post_seq_0": 1,
        "post_seq_1": 10,
        "post_seq_2": 0,
        "post_seq_3": 24,
        "post_seq_4": 21,
        "post_seq_5": 0,
        "post_seq_6": 23,
        "last_ack_seq": 24,
        "ack_count": 4,
        "write_err": 0,
    }


class TestZephyrFcbSettingsTargetsAndSeeds(unittest.TestCase):
    def setUp(self) -> None:
        self.target_dir = ROOT / "targets" / "zephyr_fcb_settings"
        self.build_dir = self.target_dir / "build"

    def test_build_script_pins_upstream_zephyr_and_verifies_provenance(self) -> None:
        script = (self.target_dir / "build_public_targets.sh").read_text(encoding="utf-8")
        self.assertIn(PINNED_ZEPHYR_COMMIT, script)
        self.assertIn(HEAD_ZEPHYR_COMMIT, script)
        self.assertIn("#121749", script)
        self.assertIn("#122446", script)
        self.assertIn('"${WEST}" init', script)
        self.assertIn('"${WEST}" manifest --freeze --active-only', script)
        self.assertIn("refusing unverifiable source provenance", script)

        provenance = json.loads((self.build_dir / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["board"], "nrf52840dk/nrf52840")
        self.assertEqual(
            provenance["sources"]["zephyr_base"]["commit"],
            PINNED_ZEPHYR_COMMIT,
        )
        self.assertEqual(
            provenance["sources"]["zephyr_head"]["commit"],
            HEAD_ZEPHYR_COMMIT,
        )
        self.assertIn("#121749", provenance["upstream_issues"])
        self.assertIn("#122446", provenance["upstream_issues"])
        self.assertIn("#121748", provenance["upstream_issues"])

        for manifest_key in ("west_manifest", "head_west_manifest"):
            manifest_path = self.build_dir / provenance[manifest_key]["file"]
            self.assertTrue(manifest_path.is_file(), manifest_key)
            self.assertEqual(
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                provenance[manifest_key]["sha256"],
            )

        self.assertEqual(len(provenance["artifacts"]), 16)
        for name, meta in provenance["artifacts"].items():
            artifact = self.build_dir / name
            with self.subTest(artifact=name):
                self.assertTrue(artifact.is_file(), name)
                raw = artifact.read_bytes()
                self.assertEqual(len(raw), meta["size"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), meta["sha256"])

    def test_rotation_and_compaction_seeds_fill_sectors_to_exact_thresholds(self) -> None:
        self.assertTrue(self.build_dir.is_dir())
        cases = [
            ("fcb_raw_internal_rotation_seed.bin", 4, FCB_RAW_MAGIC, 64),
            ("fcb_raw_spi_nor_rotation_seed.bin", 1, FCB_RAW_MAGIC, 52),
            ("settings_fcb_internal_compaction_seed.bin", 4, SETTINGS_FCB_MAGIC, 56),
            ("settings_fcb_spi_nor_compaction_seed.bin", 1, SETTINGS_FCB_MAGIC, 44),
        ]
        for filename, align, magic, expected_s1_free in cases:
            with self.subTest(seed=filename):
                raw = (self.build_dir / filename).read_bytes()
                self.assertEqual(len(raw), 3 * 4096)
                s0 = parse_fcb_sector(raw[0:4096], align=align, expected_magic=magic)
                s1 = parse_fcb_sector(raw[4096:8192], align=align, expected_magic=magic)
                s2 = parse_fcb_sector(raw[8192:12288], align=align, expected_magic=magic)

                self.assertEqual(s0["status"], "active")
                self.assertEqual(s0["fd_id"], 1)
                self.assertTrue(all(e["crc_ok"] for e in s0["entries"]))
                last_s0 = s0["entries"][-1]
                s0_end = (
                    last_s0["data_off"]
                    + ((last_s0["data_len"] + align - 1) & ~(align - 1) if align > 1 else last_s0["data_len"])
                    + align
                )
                self.assertEqual(s0_end, 4096)

                self.assertEqual(s1["status"], "active")
                self.assertEqual(s1["fd_id"], 2)
                self.assertTrue(all(e["crc_ok"] for e in s1["entries"]))
                last_s1 = s1["entries"][-1]
                s1_end = (
                    last_s1["data_off"]
                    + ((last_s1["data_len"] + align - 1) & ~(align - 1) if align > 1 else last_s1["data_len"])
                    + align
                )
                self.assertEqual(4096 - s1_end, expected_s1_free)

                self.assertEqual(s2["status"], "erased")

    def test_torn_sector_header_parses_as_negative_one_sector_id(self) -> None:
        # Simulate power cut between word 0 (fd_magic) and word 1 (fd_ver, _pad, fd_id)
        # of fcb_sector_hdr_init() (Zephyr issue #121749).
        sector = bytearray(b"\xFF" * 4096)
        struct.pack_into("<I", sector, 0, SETTINGS_FCB_MAGIC)
        parsed = parse_fcb_sector(bytes(sector), align=4, expected_magic=SETTINGS_FCB_MAGIC)
        self.assertEqual(parsed["status"], "torn_header")
        self.assertEqual(parsed["fd_id"], 0xFFFF)
        self.assertEqual(parsed["fd_id_signed"], -1)

    def test_uncommitted_entry_crc8_0xff_collision_on_spi_nor(self) -> None:
        # When power is lost after 18 bytes of the 33-byte FCB entry for
        # settings_save_one("nvm/k03", rec(seq=24)) on SPI NOR (f_align=1),
        # the remaining 15 payload bytes and the 1-byte FCB CRC slot are still
        # erased (0xFF). Because crc8_ccitt(0xFF, partial_33_bytes) == 0xFF,
        # fcb_elem_crc8() accepts the uncommitted torn record as valid (Zephyr issue #122446).
        import zlib

        body = struct.pack(
            "<IIIII",
            FCB_REC_MAGIC_BASE | FCB_REC_FLAG_LIVE,
            3,
            24,
            expected_val0(3, 24),
            expected_val1(3, 24),
        )
        rec = body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
        full_entry_without_crc = b"\x20nvm/k03=" + rec
        self.assertEqual(len(full_entry_without_crc), 33)
        sector = bytearray(b"\xFF" * 4096)
        struct.pack_into("<IBBH", sector, 0, SETTINGS_FCB_MAGIC, 1, 0xFF, 1)
        sector[8 : 8 + 18] = full_entry_without_crc[:18]
        parsed = parse_fcb_sector(bytes(sector), align=1, expected_magic=SETTINGS_FCB_MAGIC)
        self.assertEqual(len(parsed["entries"]), 1)
        entry = parsed["entries"][0]
        self.assertEqual(entry["flash_crc"], 0xFF)
        self.assertEqual(entry["calc_crc"], 0xFF)
        self.assertTrue(entry["crc_ok"])
        torn_rec = entry["payload"][8:]
        self.assertEqual(len(torn_rec), 24)
        self.assertNotEqual(
            zlib.crc32(torn_rec[:20]) & 0xFFFFFFFF,
            struct.unpack_from("<I", torn_rec, 20)[0],
        )


class TestZephyrFcbSettingsProfilesAndOracle(unittest.TestCase):
    EXPECTED_PROFILES = {
        "zephyr_fcb_raw_internal_rotation_control.yaml": ("faultFlash", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_internal_ordinary_sweep.yaml": ("faultFlash", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_internal_rotation_sweep.yaml": ("faultFlash", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_internal_state_search.yaml": ("faultFlash", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_spi_nor_rotation_control.yaml": ("spiNor", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_spi_nor_ordinary_sweep.yaml": ("spiNor", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_spi_nor_rotation_sweep.yaml": ("spiNor", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_spi_nor_state_search.yaml": ("spiNor", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_internal_compaction_control.yaml": ("faultFlash", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_internal_ordinary_sweep.yaml": ("faultFlash", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_internal_compaction_sweep.yaml": ("faultFlash", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_internal_state_search.yaml": ("faultFlash", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_spi_nor_compaction_control.yaml": ("spiNor", False, PINNED_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_spi_nor_ordinary_sweep.yaml": ("spiNor", True, PINNED_ZEPHYR_COMMIT, ("#122446",)),
        "zephyr_settings_fcb_spi_nor_compaction_sweep.yaml": ("spiNor", True, PINNED_ZEPHYR_COMMIT, ("#121749", "#122446")),
        "zephyr_settings_fcb_spi_nor_state_search.yaml": ("spiNor", True, PINNED_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_internal_head_rotation_control.yaml": ("faultFlash", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_internal_head_ordinary_sweep.yaml": ("faultFlash", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_internal_head_rotation_sweep.yaml": ("faultFlash", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_internal_head_state_search.yaml": ("faultFlash", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_spi_nor_head_rotation_control.yaml": ("spiNor", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_spi_nor_head_ordinary_sweep.yaml": ("spiNor", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_fcb_raw_spi_nor_head_rotation_sweep.yaml": ("spiNor", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_fcb_raw_spi_nor_head_state_search.yaml": ("spiNor", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_internal_head_compaction_control.yaml": ("faultFlash", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_internal_head_ordinary_sweep.yaml": ("faultFlash", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_internal_head_compaction_sweep.yaml": ("faultFlash", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_internal_head_state_search.yaml": ("faultFlash", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
        "zephyr_settings_fcb_spi_nor_head_compaction_control.yaml": ("spiNor", False, HEAD_ZEPHYR_COMMIT, ()),
        "zephyr_settings_fcb_spi_nor_head_ordinary_sweep.yaml": ("spiNor", True, HEAD_ZEPHYR_COMMIT, ("#122446",)),
        "zephyr_settings_fcb_spi_nor_head_compaction_sweep.yaml": ("spiNor", True, HEAD_ZEPHYR_COMMIT, ("#121749", "#122446")),
        "zephyr_settings_fcb_spi_nor_head_state_search.yaml": ("spiNor", True, HEAD_ZEPHYR_COMMIT, ("#121749",)),
    }

    def test_all_fcb_and_settings_profiles_load_strict(self) -> None:
        self.assertTrue(callable(evaluate_durability_verdict))
        self.assertTrue(callable(parse_ack_boundary))
        for filename, (
            expected_backend,
            expected_issues,
            expected_commit,
            expected_citations,
        ) in self.EXPECTED_PROFILES.items():
            with self.subTest(profile=filename):
                cfg = load_profile(ROOT / "profiles" / filename, strict=True)
                self.assertEqual(cfg.flash_backend, expected_backend)
                self.assertIsNotNone(cfg.target_source)
                self.assertEqual(cfg.target_source.revision, expected_commit)
                self.assertIn("zephyr_fcb_durability", cfg.invariants)
                self.assertEqual(cfg.expect.should_find_issues, expected_issues)
                self.assertEqual(len(cfg.success_criteria.memory_checks), 27)
                for issue_num in expected_citations:
                    self.assertIn(issue_num, cfg.description)
                if filename.endswith("_sweep.yaml"):
                    boundaries = cfg.invariant_config["zephyr_fcb_durability"]["ack_write_boundaries"]
                    for seq_key, val in boundaries.items():
                        self.assertTrue(
                            isinstance(val, str) and val.startswith("w["),
                            f"{filename} boundary {seq_key}={val!r} should use kind-qualified w[N]",
                        )
                        self.assertEqual(parse_ack_boundary(val)[0], "program")

    def test_durability_oracle_accepts_clean_and_in_flight_states(self) -> None:
        # 1. Cut before Op 1 completes (Op 1 in flight -> absent at mount: K4 @ seq=12).
        words_op1_absent = _clean_verdict_words(FCB_VERDICT_MAGIC_SETTINGS)
        issues = evaluate_durability_verdict(
            {
                **words_op1_absent,
                "mount_seq": [1, 10, 0, 4, 12, 13, 0],
                "post_seq": [1, 10, 0, 24, 21, 0, 23],
            },
            fault_at=3,
            fault_type="w",
            operation_kind="program",
            ack_write_boundaries={"21": "w[6]", "22": "w[12]", "23": "w[40]", "24": "w[50]"},
        )
        self.assertEqual(issues, [])

        # 2. Erase cut e[0] must not be confused with write boundaries w[N].
        issues_erase = evaluate_durability_verdict(
            {
                **words_op1_absent,
                "mount_seq": [1, 10, 0, 4, 21, 0, 23],
                "mount_present_mask": 0x5B,
                "post_seq": [1, 10, 0, 24, 21, 0, 23],
            },
            fault_at=0,
            fault_type="e",
            operation_kind="erase",
            ack_write_boundaries={"21": "w[6]", "22": "w[12]", "23": "w[40]", "24": "w[50]"},
        )
        self.assertEqual(issues_erase, [])

        # 3. Cut while Op 2 (delete K5) is in flight: K4 @ seq=21 applied, K5 either
        # present (seq=13) or deleted (seq=0) are both valid.
        for k5_mask, k5_seq in ((0x3B, 13), (0x1B, 0)):
            with self.subTest(k5_seq=k5_seq):
                words = _clean_verdict_words(FCB_VERDICT_MAGIC_SETTINGS)
                words["mount_present_mask"] = k5_mask
                issues = evaluate_durability_verdict(
                    {
                        **words,
                        "mount_seq": [1, 10, 0, 4, 21, k5_seq, 0],
                        "post_seq": [1, 10, 0, 24, 21, 0, 23],
                    },
                    fault_at=8,
                    fault_type="w",
                    operation_kind="program",
                    ack_write_boundaries={"21": "w[6]", "22": "w[12]", "23": "w[40]", "24": "w[50]"},
                )
                self.assertEqual(issues, [])

    def test_durability_oracle_rejects_lost_acknowledged_and_resurrected_deleted_keys(self) -> None:
        # Simulate settings_fcb_src() flattening active sector S1 after a torn header
        # on scratch sector S2 (Zephyr issue #121749):
        #   - K1 rolls back from seq=10 to stale seq=2 (from S0)
        #   - Deleted key K2 (deleted at seq=11 in S1) reappears at seq=3 (from S0)
        #   - K4 (acknowledged at seq=21 in S1) disappears at mount (seq=0)
        words = _clean_verdict_words(FCB_VERDICT_MAGIC_SETTINGS)
        words.update(
            {
                "oracle_ok": 0,
                "mount_oracle_ok": 0,
                "post_oracle_ok": 0,
                "mount_present_mask": 0x0F,  # K0, K1, K2(resurrected!), K3
                "mount_seq_1": 2,
                "mount_seq_2": 3,
                "mount_seq_4": 0,
                "mount_seq_5": 0,
                "post_present_mask": 0x5F,  # K2 still resurrected
                "post_seq_1": 2,
                "post_seq_2": 3,
            }
        )
        fns = resolve_invariants(["zephyr_fcb_durability"])
        fault_res = FaultResult(
            fault_at=15,
            boot_outcome="memory_checks_unmet",
            boot_slot="exec",
            nvm_state=None,
            raw_log="",
        )
        violations = run_invariants(
            fault_res,
            fns,
            result_signals=_make_memory_checks_signals(words),
            result_dict={"fault_type": "w", "operation_kind": "program"},
        )
        self.assertEqual(len(violations), 1)
        details = violations[0].details
        self.assertEqual(details["fault_at"], 15)
        self.assertEqual(details["operation_kind"], "program")
        self.assertEqual(details["point"], "w[15]")
        codes = {item["finding_code"] for item in details["issues"]}
        self.assertIn("acknowledged_record_lost_or_stale", codes)
        self.assertIn("deleted_key_reappeared", codes)

    def test_durability_oracle_rejects_torn_values_and_post_recovery_enospc(self) -> None:
        # 1. Torn value detected at mount (Zephyr issue #122446).
        torn_words = _clean_verdict_words(FCB_VERDICT_MAGIC_RAW)
        torn_words["oracle_ok"] = 0
        torn_words["mount_oracle_ok"] = 0
        torn_words["mount_torn_count"] = 1
        fns = resolve_invariants(["zephyr_fcb_durability"])
        fault_res = FaultResult(
            fault_at=37,
            boot_outcome="memory_checks_unmet",
            boot_slot="exec",
            nvm_state=None,
            raw_log="",
        )
        violations = run_invariants(
            fault_res,
            fns,
            result_signals=_make_memory_checks_signals(torn_words),
            result_dict={"fault_type": "w", "operation_kind": "program"},
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].details["finding_code"], "torn_record_value")
        self.assertEqual(violations[0].details["operation_kind"], "program")
        self.assertEqual(violations[0].details["point"], "w[37]")

        # 2. Raw FCB torn sector header (Zephyr issue #121749): mount succeeds,
        # but store refuses new writes with -ENOSPC (write_err = 28, write_ok = 0).
        enospc_words = _clean_verdict_words(FCB_VERDICT_MAGIC_RAW)
        enospc_words.update(
            {
                "oracle_ok": 0,
                "write_ok": 0,
                "post_oracle_ok": 0,
                "write_err": 28,  # ENOSPC
                "mount_present_mask": 0x1B,  # Op 1 (K4=21) and Op 2 (delete K5) committed
                "mount_seq_4": 21,
                "mount_seq_5": 0,
                "post_present_mask": 0x1B,  # K6 never written
                "post_seq_3": 4,
                "post_seq_6": 0,
            }
        )
        cfg = load_profile(
            ROOT / "profiles" / "zephyr_fcb_raw_internal_rotation_sweep.yaml",
            strict=True,
        )
        results = [
            {
                "fault_at": 17,
                "fault_type": "w",
                "operation_kind": "program",
                "fault_injected": True,
                "boot_outcome": "memory_checks_unmet",
                "boot_slot": "exec",
                "signals": _make_memory_checks_signals(enospc_words),
            }
        ]
        annotate_result_checks(results, cfg, repo_root=ROOT)
        self.assertIn("invariant_violations", results[0])
        self.assertEqual(
            results[0]["invariant_violations"][0]["finding"],
            "post_recovery_write_failed",
        )
        self.assertEqual(
            results[0]["invariant_violations"][0]["details"]["point"],
            "w[17]",
        )


if __name__ == "__main__":
    unittest.main()
