#!/usr/bin/env python3
"""Regression coverage for check_mcuboot_image_vectors.py."""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_mcuboot_image_vectors.py"
ASSETS = ROOT / "results" / "oss_validation" / "assets"
sys.path.insert(0, str(ROOT / "scripts"))

from check_mcuboot_image_vectors import (  # noqa: E402
    IMAGE_MAGIC,
    check_image,
    read_zephyr_config,
)

# nucleo_f429zi application linked at slot0 of the mirrored scratch layout.
F429_CONFIG = {
    "CONFIG_FLASH_BASE_ADDRESS": 0x08000000,
    "CONFIG_FLASH_LOAD_OFFSET": 0x8000,
    "CONFIG_FLASH_SIZE": 2048,
    "CONFIG_SRAM_BASE_ADDRESS": 0x20000000,
    "CONFIG_SRAM_SIZE": 192,
}


def _config(rom_start_offset: int) -> dict:
    return {**F429_CONFIG, "CONFIG_ROM_START_OFFSET": rom_start_offset}


def _signed_image(hdr_size: int, rom_start_offset: int) -> bytes:
    """Build an image the way imgtool signs a Zephyr binary without --pad-header."""
    vectors = struct.pack("<II", 0x20001100, 0x08008000 + rom_start_offset + 0x100 | 1)
    code = vectors + b"\x00" * 0x200
    body = b"\x00" * rom_start_offset + code
    img_size = len(body) - hdr_size
    header = struct.pack("<IIHHI", IMAGE_MAGIC, 0, hdr_size, 0, img_size)
    return header + body[len(header):]


def test_matching_header_and_rom_start_offset_passes() -> None:
    for offset in (0x200, 0x400):
        assert check_image(_signed_image(offset, offset), _config(offset)) == []


def test_header_smaller_than_rom_start_offset_is_rejected() -> None:
    # Current Zephyr links STM32 MCUboot applications at 0x400. A 0x200 header
    # leaves MCUboot reading zero padding, so its handoff branches to address 0.
    errors = check_image(_signed_image(0x200, 0x400), _config(0x400))
    assert len(errors) == 3
    assert "sign with --header-size 0x400" in errors[0]
    assert "initial SP 0x00000000" in errors[1]
    assert "reset vector 0x00000000" in errors[2]


def test_reset_vector_outside_signed_image_is_rejected() -> None:
    image = bytearray(_signed_image(0x200, 0x200))
    struct.pack_into("<I", image, 0x204, 0x08100001)
    errors = check_image(bytes(image), _config(0x200))
    assert errors == [
        "reset vector 0x08100001 at image offset 0x204 is not a Thumb address "
        "inside the signed image 0x08008200..0x08008408"
    ]


def test_mapped_partition_config_checks_reset_vector_against_flash() -> None:
    # Zephyr builds with mapped partitions omit CONFIG_FLASH_LOAD_OFFSET.
    config = _config(0x200)
    del config["CONFIG_FLASH_LOAD_OFFSET"]
    assert check_image(_signed_image(0x200, 0x200), config) == []

    image = bytearray(_signed_image(0x200, 0x200))
    struct.pack_into("<I", image, 0x204, 0x08200001)
    assert check_image(bytes(image), config) == [
        "reset vector 0x08200001 at image offset 0x204 is not a Thumb address "
        "inside flash 0x08000200..0x08200000"
    ]
    assert len(check_image(_signed_image(0x200, 0x400), {**config, "CONFIG_ROM_START_OFFSET": 0x400})) == 3


def test_bad_magic_and_missing_config_are_rejected() -> None:
    image = bytearray(_signed_image(0x200, 0x200))
    struct.pack_into("<I", image, 0, 0)
    assert check_image(bytes(image), _config(0x200)) == [
        "image magic is 0x00000000, expected 0x96F3B83D"
    ]
    assert check_image(_signed_image(0x200, 0x200), F429_CONFIG) == [
        "application .config lacks CONFIG_ROM_START_OFFSET"
    ]


def test_tracked_stm32f4_scratch_images_have_real_vectors() -> None:
    # The tracked images come from the pinned Zephyr 3.7 workspace, which links
    # MCUboot applications at 0x200.
    for slot in ("slot0", "slot1"):
        image = (ASSETS / "zephyr_head_scratch_stm32f4_mirrored_{}.bin".format(slot)).read_bytes()
        assert check_image(image, _config(0x200)) == []
        assert check_image(image, _config(0x400))[0].startswith("ih_hdr_size is 0x200")


def test_cli_reads_zephyr_config_and_exits_nonzero_on_mismatch(tmp_path: Path) -> None:
    config = tmp_path / ".config"
    config.write_text(
        "# CONFIG_FOO is not set\n"
        'CONFIG_BOARD="nucleo_f429zi"\n'
        "CONFIG_ROM_START_OFFSET=0x400\n"
        "CONFIG_FLASH_BASE_ADDRESS=0x8000000\n"
        "CONFIG_FLASH_LOAD_OFFSET=0x8000\n"
        "CONFIG_FLASH_SIZE=2048\n"
        "CONFIG_SRAM_BASE_ADDRESS=0x20000000\n"
        "CONFIG_SRAM_SIZE=192\n",
        encoding="utf-8",
    )
    assert read_zephyr_config(config) == _config(0x400)

    good = tmp_path / "good.bin"
    good.write_bytes(_signed_image(0x400, 0x400))
    bad = tmp_path / "bad.bin"
    bad.write_bytes(_signed_image(0x200, 0x400))

    ok = subprocess.run(
        [sys.executable, str(SCRIPT), "--image", str(good), "--app-config", str(config)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    failed = subprocess.run(
        [sys.executable, str(SCRIPT), "--image", str(bad), "--app-config", str(config)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "CONFIG_ROM_START_OFFSET=0x400" in failed.stderr
