from pathlib import Path

from scripts.mutate_binary import mutate_binary


def test_mutate_binary_flips_default_bit(tmp_path: Path) -> None:
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(bytes([0x00, 0xAA, 0x55]))

    result = mutate_binary(src, dst, offset=1)

    assert dst.read_bytes() == bytes([0x00, 0xAB, 0x55])
    assert result["offset"] == 1
    assert result["original_byte"] == 0xAA
    assert result["mutated_byte"] == 0xAB
    assert result["input_sha256"] != result["output_sha256"]


def test_mutate_binary_sets_explicit_value(tmp_path: Path) -> None:
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(bytes([0x10, 0x20]))

    result = mutate_binary(src, dst, offset=0, value=0xFE)

    assert dst.read_bytes() == bytes([0xFE, 0x20])
    assert result["original_byte"] == 0x10
    assert result["mutated_byte"] == 0xFE
