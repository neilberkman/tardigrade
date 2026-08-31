"""Tests for calibration_cache module."""

from __future__ import annotations

import base64
import json
import os
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Ensure scripts/ is on sys.path for imports.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from calibration_cache import (
    _file_sha256,
    _read_binary_b64,
    _write_binary_b64,
    compute_cache_key,
    load_calibration,
    save_calibration,
)
from renode_runner import CalibrationResult


class TestFilesha256(unittest.TestCase):
    def test_deterministic(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"hello world")
            path = f.name
        try:
            h1 = _file_sha256(path)
            h2 = _file_sha256(path)
            self.assertEqual(h1, h2)
            self.assertEqual(len(h1), 64)  # hex SHA-256
        finally:
            os.unlink(path)

    def test_different_content_different_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"aaa")
            path_a = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"bbb")
            path_b = f.name
        try:
            self.assertNotEqual(_file_sha256(path_a), _file_sha256(path_b))
        finally:
            os.unlink(path_a)
            os.unlink(path_b)


class TestBinaryB64RoundTrip(unittest.TestCase):
    def test_round_trip(self):
        data = b"\x00\x01\x02\xff" * 100
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            src = f.name
        try:
            b64 = _read_binary_b64(src)
            self.assertIsNotNone(b64)

            with tempfile.TemporaryDirectory() as td:
                dest = os.path.join(td, "out.bin")
                result_path = _write_binary_b64(b64, dest)
                self.assertEqual(result_path, dest)
                with open(dest, "rb") as f:
                    self.assertEqual(f.read(), data)
        finally:
            os.unlink(src)

    def test_none_input(self):
        self.assertIsNone(_read_binary_b64(None))
        self.assertIsNone(_read_binary_b64(""))
        self.assertIsNone(_write_binary_b64(None, "/tmp/x"))
        self.assertIsNone(_write_binary_b64("", "/tmp/x"))


class TestComputeCacheKey(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.elf_path = os.path.join(self.td, "boot.elf")
        self.img_path = os.path.join(self.td, "update.bin")
        self.platform_path = os.path.join(self.td, "platform.repl")
        self.setup_path = os.path.join(self.td, "setup.resc")
        self.hook_path = os.path.join(self.td, "boot-hook.resc")
        with open(self.elf_path, "wb") as f:
            f.write(b"ELF_CONTENT")
        with open(self.img_path, "wb") as f:
            f.write(b"IMAGE_CONTENT")
        with open(self.platform_path, "wb") as f:
            f.write(b"PLATFORM_CONTENT")
        with open(self.setup_path, "wb") as f:
            f.write(b"SETUP_CONTENT")
        with open(self.hook_path, "wb") as f:
            f.write(b"HOOK_CONTENT")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td)

    def _default_kwargs(self):
        return dict(
            bootloader_elf=self.elf_path,
            images={"update": self.img_path},
            fault_types=["power_loss"],
            flash_backend="nvm",
            memory_slots={"exec": {"base": 0x10000, "size": 0x20000}},
            pre_boot_state=[],
            hash_bypass_symbols=[],
            write_granularity=4,
            platform_files={"main": self.platform_path},
            setup_files={"main": self.setup_path},
            hook_files={"boot_cycle": self.hook_path},
            entry_point=0x10000,
            image_load_addresses={"update": 0x30000},
            tool_versions={"renode": "1.16.1"},
            runtime_config={"run_duration": "0.5", "reset_mode": "warm"},
        )

    def test_deterministic(self):
        k1 = compute_cache_key(**self._default_kwargs())
        k2 = compute_cache_key(**self._default_kwargs())
        self.assertEqual(k1, k2)

    def test_different_elf_different_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        # Change the ELF content.
        with open(self.elf_path, "wb") as f:
            f.write(b"DIFFERENT_ELF")
        k2 = compute_cache_key(**self._default_kwargs())
        self.assertNotEqual(k1, k2)

    def test_different_fault_types_different_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        kw = self._default_kwargs()
        kw["fault_types"] = ["bit_corruption"]
        k2 = compute_cache_key(**kw)
        self.assertNotEqual(k1, k2)

    def test_different_image_different_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        with open(self.img_path, "wb") as f:
            f.write(b"DIFFERENT_IMAGE")
        k2 = compute_cache_key(**self._default_kwargs())
        self.assertNotEqual(k1, k2)

    def test_different_flash_backend_different_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        kw = self._default_kwargs()
        kw["flash_backend"] = "mram"
        k2 = compute_cache_key(**kw)
        self.assertNotEqual(k1, k2)

    def test_slot_objects_with_attributes(self):
        """SlotConfig-like objects with .base/.size attributes work."""

        class FakeSlot:
            def __init__(self, base, size):
                self.base = base
                self.size = size

        kw = self._default_kwargs()
        kw["memory_slots"] = {"exec": FakeSlot(0x10000, 0x20000)}
        k1 = compute_cache_key(**kw)
        # Should be the same as the dict version with same values.
        k2 = compute_cache_key(**self._default_kwargs())
        self.assertEqual(k1, k2)

    def test_different_write_granularity_different_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        kw = self._default_kwargs()
        kw["write_granularity"] = 8
        k2 = compute_cache_key(**kw)
        self.assertNotEqual(k1, k2)

    def test_pre_boot_state_affects_key(self):
        k1 = compute_cache_key(**self._default_kwargs())
        kw = self._default_kwargs()
        kw["pre_boot_state"] = [{"address": 0x1000, "u32": 0xDEAD}]
        k2 = compute_cache_key(**kw)
        self.assertNotEqual(k1, k2)

    def test_platform_setup_and_hook_contents_affect_key(self):
        for key, path in (
            ("platform_files", self.platform_path),
            ("setup_files", self.setup_path),
            ("hook_files", self.hook_path),
        ):
            with self.subTest(key=key):
                with open(path, "rb") as stream:
                    original = stream.read()
                k1 = compute_cache_key(**self._default_kwargs())
                with open(path, "wb") as stream:
                    stream.write(original + b"_CHANGED")
                try:
                    k2 = compute_cache_key(**self._default_kwargs())
                    self.assertNotEqual(k1, k2)
                finally:
                    with open(path, "wb") as stream:
                        stream.write(original)

    def test_entry_image_address_tool_and_runtime_inputs_affect_key(self):
        changes = {
            "entry_point": 0x20000,
            "image_load_addresses": {"update": 0x40000},
            "tool_versions": {"renode": "1.17.0"},
            "runtime_config": {"run_duration": "1.0", "reset_mode": "cold"},
        }
        baseline = compute_cache_key(**self._default_kwargs())
        for key, value in changes.items():
            with self.subTest(key=key):
                kwargs = self._default_kwargs()
                kwargs[key] = value
                self.assertNotEqual(baseline, compute_cache_key(**kwargs))

    def test_checkout_location_does_not_affect_file_content_key(self):
        copied_platform = os.path.join(self.td, "same-platform-elsewhere.repl")
        with open(self.platform_path, "rb") as source, open(copied_platform, "wb") as dest:
            dest.write(source.read())
        baseline = compute_cache_key(**self._default_kwargs())
        kwargs = self._default_kwargs()
        kwargs["platform_files"] = {"main": copied_platform}
        self.assertEqual(baseline, compute_cache_key(**kwargs))


class TestSaveLoadCalibration(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.td, "cal_cache.json")
        self.work_dir = Path(self.td) / "work"
        self.work_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td)

    def _make_cal(self, total_writes=100, trace_data=None, trace_bin_data=None):
        trace_file = None
        trace_file_bin = None
        if trace_data is not None:
            trace_file = os.path.join(self.td, "trace.csv")
            with open(trace_file, "wb") as f:
                f.write(trace_data)
            trace_file_bin = os.path.join(self.td, "trace.bin")
            with open(trace_file_bin, "wb") as f:
                f.write(trace_bin_data if trace_bin_data is not None else b"")
        return CalibrationResult(
            total_writes=total_writes,
            total_erases=5,
            trace_file=trace_file,
            erase_trace_file=None,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=None,
            calibration_exec_hash="ab" * 32,
            stop_reason="done",
            emulated_s=1.5,
            elapsed_s=55.0,
            pc="0x10000100",
            setup_writes=10,
            total_i2c_transactions=2,
            total_otp_blows=0,
        )

    def test_save_and_load_match(self):
        cal = self._make_cal(total_writes=42)
        cache_key = "test_key_123"

        save_calibration(self.cache_path, cal, cache_key)
        self.assertTrue(os.path.exists(self.cache_path))

        loaded = load_calibration(
            self.cache_path, cache_key, self.work_dir, allow_unsigned=True
        )
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.total_writes, 42)
        self.assertEqual(loaded.total_erases, 5)
        self.assertEqual(loaded.calibration_exec_hash, "ab" * 32)
        self.assertEqual(loaded.stop_reason, "done")
        self.assertEqual(loaded.setup_writes, 10)
        self.assertEqual(loaded.total_i2c_transactions, 2)
        self.assertEqual(loaded.total_otp_blows, 0)

    def test_cache_miss_wrong_key(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "key_a")

        loaded = load_calibration(
            self.cache_path, "key_b", self.work_dir, allow_unsigned=True
        )
        self.assertIsNone(loaded)

    def test_cache_miss_no_file(self):
        loaded = load_calibration("/nonexistent/path.json", "key", self.work_dir)
        self.assertIsNone(loaded)

    def test_trace_files_round_trip(self):
        trace_data = (
            b"write_index,flash_offset,value\n"
            b"1,0x1000,0xDEADBEEF\n"
            b"2,0x1004,0xCAFEBABE\n"
        )
        trace_bin_data = struct.pack(
            "<IIIIII",
            1,
            0x1000,
            0xDEADBEEF,
            2,
            0x1004,
            0xCAFEBABE,
        )
        cal = self._make_cal(
            total_writes=2,
            trace_data=trace_data,
            trace_bin_data=trace_bin_data,
        )
        cache_key = "trace_key"

        save_calibration(self.cache_path, cal, cache_key)
        loaded = load_calibration(
            self.cache_path, cache_key, self.work_dir, allow_unsigned=True
        )

        self.assertIsNotNone(loaded)
        self.assertIsNotNone(loaded.trace_file)
        self.assertTrue(os.path.exists(loaded.trace_file))
        with open(loaded.trace_file, "rb") as f:
            self.assertEqual(f.read(), trace_data)

        self.assertIsNotNone(loaded.trace_file_bin)
        self.assertTrue(os.path.exists(loaded.trace_file_bin))
        with open(loaded.trace_file_bin, "rb") as f:
            self.assertEqual(f.read(), trace_bin_data)

    def test_width_bearing_trace_files_round_trip(self):
        trace_data = (
            b"write_index,flash_offset,value,width\n"
            b"1,0x1000,0xBEEF,4\n"
            b"2,0x1004,0xCAFEBABE,4\n"
        )
        trace_bin_data = struct.pack(
            "<IIIIII",
            1,
            0x1000,
            0xBEEF,
            2,
            0x1004,
            0xCAFEBABE,
        )
        cal = self._make_cal(
            total_writes=2,
            trace_data=trace_data,
            trace_bin_data=trace_bin_data,
        )

        save_calibration(self.cache_path, cal, "width_trace_key")
        loaded = load_calibration(
            self.cache_path,
            "width_trace_key",
            self.work_dir,
            allow_unsigned=True,
        )

        self.assertIsNotNone(loaded)
        with open(loaded.trace_file, "rb") as stream:
            self.assertEqual(stream.read(), trace_data)

    def test_width_bearing_binary_rejects_non_four_byte_width(self):
        trace_data = (
            b"write_index,flash_offset,value,width\n"
            b"1,0x1000,0xBEEF,4\n"
            b"2,0x1004,0xCAFE,2\n"
        )
        trace_bin_data = struct.pack(
            "<IIIIII", 1, 0x1000, 0xBEEF, 2, 0x1004, 0xCAFE
        )
        cal = self._make_cal(
            total_writes=1,
            trace_data=trace_data,
            trace_bin_data=trace_bin_data,
        )
        with self.assertRaisesRegex(ValueError, "binary companion"):
            save_calibration(self.cache_path, cal, "width_binary_reject_key")

    def test_width_bearing_csv_only_trace_round_trip(self):
        trace_data = (
            b"write_index,flash_offset,value,width\n"
            b"1,0x1000,0xBEEF,2\n"
            b"2,0x1004,0xCAFEBABE,4\n"
        )
        trace_file = os.path.join(self.td, "width-only.csv")
        with open(trace_file, "wb") as stream:
            stream.write(trace_data)
        cal = CalibrationResult(
            total_writes=2,
            total_erases=0,
            trace_file=trace_file,
            erase_trace_file=None,
            trace_file_bin=None,
            erase_trace_file_bin=None,
        )

        save_calibration(self.cache_path, cal, "width_csv_only_key")
        loaded = load_calibration(
            self.cache_path,
            "width_csv_only_key",
            self.work_dir,
            allow_unsigned=True,
        )

        self.assertIsNotNone(loaded)
        self.assertIsNotNone(loaded.trace_file)
        self.assertIsNone(loaded.trace_file_bin)
        with open(loaded.trace_file, "rb") as stream:
            self.assertEqual(stream.read(), trace_data)

    def test_eight_byte_csv_only_value_round_trip(self):
        trace_data = (
            b"write_index,flash_offset,value,width\n"
            b"1,0x1000,0x1000000000000001,8\n"
        )
        trace_file = os.path.join(self.td, "width-eight-only.csv")
        with open(trace_file, "wb") as stream:
            stream.write(trace_data)
        cal = CalibrationResult(
            total_writes=1,
            total_erases=0,
            trace_file=trace_file,
            erase_trace_file=None,
            trace_file_bin=None,
            erase_trace_file_bin=None,
        )

        save_calibration(self.cache_path, cal, "width_eight_csv_only_key")
        loaded = load_calibration(
            self.cache_path,
            "width_eight_csv_only_key",
            self.work_dir,
            allow_unsigned=True,
        )

        self.assertIsNotNone(loaded)
        with open(loaded.trace_file, "rb") as stream:
            self.assertEqual(stream.read(), trace_data)

    def test_write_trace_may_be_a_subset_of_total_write_counter(self):
        trace_data = (
            b"write_index,flash_offset,value\n"
            b"1,0x1000,0xDEADBEEF\n"
            b"2,0x1004,0xCAFEBABE\n"
        )
        trace_bin_data = struct.pack(
            "<IIIIII",
            1,
            0x1000,
            0xDEADBEEF,
            2,
            0x1004,
            0xCAFEBABE,
        )
        cal = self._make_cal(
            total_writes=3,
            trace_data=trace_data,
            trace_bin_data=trace_bin_data,
        )

        save_calibration(self.cache_path, cal, "subset_key")
        loaded = load_calibration(
            self.cache_path,
            "subset_key",
            self.work_dir,
            allow_unsigned=True,
        )

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.total_writes, 3)

    def test_no_trace_files_round_trip(self):
        cal = self._make_cal(trace_data=None)
        cache_key = "no_trace_key"

        save_calibration(self.cache_path, cal, cache_key)
        loaded = load_calibration(
            self.cache_path, cache_key, self.work_dir, allow_unsigned=True
        )

        self.assertIsNotNone(loaded)
        self.assertIsNone(loaded.trace_file)
        self.assertIsNone(loaded.trace_file_bin)

    def test_cache_file_is_valid_json(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "k")

        with open(self.cache_path, "r") as f:
            payload = json.load(f)

        self.assertEqual(payload["cache_key"], "k")
        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["total_writes"], 100)

    def test_rejects_tampered_counter_and_trace(self):
        trace_data = (
            b"write_index,flash_offset,value\n"
            b"1,4096,3735928559\n"
        )
        trace_bin_data = struct.pack("<III", 1, 4096, 3735928559)
        cal = self._make_cal(
            total_writes=1,
            trace_data=trace_data,
            trace_bin_data=trace_bin_data,
        )
        save_calibration(self.cache_path, cal, "key")
        payload = json.loads(Path(self.cache_path).read_text(encoding="utf-8"))

        payload["total_writes"] = -1
        Path(self.cache_path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "total_writes"):
            load_calibration(
                self.cache_path, "key", self.work_dir, allow_unsigned=True
            )

        payload["total_writes"] = 0
        Path(self.cache_path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inconsistent with total_writes"):
            load_calibration(
                self.cache_path, "key", self.work_dir, allow_unsigned=True
            )

        save_calibration(self.cache_path, cal, "key")
        payload = json.loads(Path(self.cache_path).read_text(encoding="utf-8"))
        payload["trace_file_bin_b64"] = payload["trace_file_bin_b64"][:-1] + "A"
        Path(self.cache_path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "trace_file_bin_b64"):
            load_calibration(
                self.cache_path, "key", self.work_dir, allow_unsigned=True
            )

        save_calibration(self.cache_path, cal, "key")
        payload = json.loads(Path(self.cache_path).read_text(encoding="utf-8"))
        changed_binary = struct.pack("<III", 1, 8192, 3735928559)
        payload["trace_file_bin_b64"] = base64.b64encode(changed_binary).decode("ascii")
        payload["trace_file_bin_sha256"] = hashlib.sha256(changed_binary).hexdigest()
        Path(self.cache_path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "binary records do not match CSV"):
            load_calibration(
                self.cache_path, "key", self.work_dir, allow_unsigned=True
            )

    def test_optional_cache_digest_pins_provenance(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "key")
        digest = hashlib.sha256(Path(self.cache_path).read_bytes()).hexdigest()
        self.assertIsNotNone(load_calibration(
            self.cache_path,
            "key",
            self.work_dir,
            expected_sha256=digest,
        ))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            load_calibration(
                self.cache_path,
                "key",
                self.work_dir,
                expected_sha256="0" * 64,
            )

    def test_rejects_legacy_cache_version(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "key")
        payload = json.loads(Path(self.cache_path).read_text(encoding="utf-8"))
        payload["version"] = 1
        Path(self.cache_path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported calibration cache version"):
            load_calibration(
                self.cache_path, "key", self.work_dir, allow_unsigned=True
            )

    def test_rejects_unsigned_existing_cache_by_default(self):
        save_calibration(self.cache_path, self._make_cal(), "key")
        with self.assertRaisesRegex(ValueError, "refusing unsigned"):
            load_calibration(self.cache_path, "key", self.work_dir)

    def test_save_creates_parent_dirs(self):
        nested_path = os.path.join(self.td, "a", "b", "c", "cache.json")
        cal = self._make_cal()
        save_calibration(nested_path, cal, "k")
        self.assertTrue(os.path.exists(nested_path))

    def test_failed_atomic_replace_preserves_existing_cache(self):
        original = b'{"old": true}\n'
        Path(self.cache_path).write_bytes(original)
        cal = self._make_cal()

        with mock.patch("calibration_cache.os.replace", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                save_calibration(self.cache_path, cal, "new-key")

        self.assertEqual(Path(self.cache_path).read_bytes(), original)
        leftovers = list(Path(self.td).glob(".cal_cache.json-*.tmp"))
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
