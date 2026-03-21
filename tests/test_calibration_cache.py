"""Tests for calibration_cache module."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

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
        with open(self.elf_path, "wb") as f:
            f.write(b"ELF_CONTENT")
        with open(self.img_path, "wb") as f:
            f.write(b"IMAGE_CONTENT")

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


class TestSaveLoadCalibration(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.td, "cal_cache.json")
        self.work_dir = Path(self.td) / "work"
        self.work_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td)

    def _make_cal(self, total_writes=100, trace_data=None):
        trace_file = None
        trace_file_bin = None
        if trace_data is not None:
            trace_file = os.path.join(self.td, "trace.csv")
            with open(trace_file, "wb") as f:
                f.write(trace_data)
            trace_file_bin = os.path.join(self.td, "trace.bin")
            with open(trace_file_bin, "wb") as f:
                f.write(trace_data[::-1])
        return CalibrationResult(
            total_writes=total_writes,
            total_erases=5,
            trace_file=trace_file,
            erase_trace_file=None,
            trace_file_bin=trace_file_bin,
            erase_trace_file_bin=None,
            calibration_exec_hash="abc123",
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

        loaded = load_calibration(self.cache_path, cache_key, self.work_dir)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.total_writes, 42)
        self.assertEqual(loaded.total_erases, 5)
        self.assertEqual(loaded.calibration_exec_hash, "abc123")
        self.assertEqual(loaded.stop_reason, "done")
        self.assertEqual(loaded.setup_writes, 10)
        self.assertEqual(loaded.total_i2c_transactions, 2)
        self.assertEqual(loaded.total_otp_blows, 0)

    def test_cache_miss_wrong_key(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "key_a")

        loaded = load_calibration(self.cache_path, "key_b", self.work_dir)
        self.assertIsNone(loaded)

    def test_cache_miss_no_file(self):
        loaded = load_calibration("/nonexistent/path.json", "key", self.work_dir)
        self.assertIsNone(loaded)

    def test_trace_files_round_trip(self):
        trace_data = b"1,0x1000,0xDEADBEEF\n2,0x1004,0xCAFEBABE\n"
        cal = self._make_cal(trace_data=trace_data)
        cache_key = "trace_key"

        save_calibration(self.cache_path, cal, cache_key)
        loaded = load_calibration(self.cache_path, cache_key, self.work_dir)

        self.assertIsNotNone(loaded)
        self.assertIsNotNone(loaded.trace_file)
        self.assertTrue(os.path.exists(loaded.trace_file))
        with open(loaded.trace_file, "rb") as f:
            self.assertEqual(f.read(), trace_data)

        self.assertIsNotNone(loaded.trace_file_bin)
        self.assertTrue(os.path.exists(loaded.trace_file_bin))
        with open(loaded.trace_file_bin, "rb") as f:
            self.assertEqual(f.read(), trace_data[::-1])

    def test_no_trace_files_round_trip(self):
        cal = self._make_cal(trace_data=None)
        cache_key = "no_trace_key"

        save_calibration(self.cache_path, cal, cache_key)
        loaded = load_calibration(self.cache_path, cache_key, self.work_dir)

        self.assertIsNotNone(loaded)
        self.assertIsNone(loaded.trace_file)
        self.assertIsNone(loaded.trace_file_bin)

    def test_cache_file_is_valid_json(self):
        cal = self._make_cal()
        save_calibration(self.cache_path, cal, "k")

        with open(self.cache_path, "r") as f:
            payload = json.load(f)

        self.assertEqual(payload["cache_key"], "k")
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["total_writes"], 100)

    def test_save_creates_parent_dirs(self):
        nested_path = os.path.join(self.td, "a", "b", "c", "cache.json")
        cal = self._make_cal()
        save_calibration(nested_path, cal, "k")
        self.assertTrue(os.path.exists(nested_path))


if __name__ == "__main__":
    unittest.main()
