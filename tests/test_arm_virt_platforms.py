from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_qemu_virt_a53_platform_has_expected_peripherals() -> None:
    text = _read("/Users/neil/source/tardigrade/platforms/qemu_virt_a53.repl")
    assert "cpu: CPU.ARMv8A" in text
    assert "flash0: Memory.MappedMemory @ sysbus 0x00000000" in text
    assert "flash1: Tardigrade.CFIFlash @ sysbus 0x04000000" in text
    assert "fw_cfg: Tardigrade.QEMUFwCfg @ sysbus 0x09020000" in text
    assert "gpio0: Tardigrade.PL061Stub @ sysbus 0x09030000" in text


def test_qemu_vexpress_a9_platform_has_expected_peripherals() -> None:
    text = _read("/Users/neil/source/tardigrade/platforms/qemu_vexpress_a9.repl")
    assert "cpu: CPU.ARMv7A" in text
    assert "timer1: Tardigrade.ARM_SP804PrimeCellTimer @ sysbus 0x10011000" in text
    assert "timer2: Tardigrade.ARM_SP804PrimeCellTimer @ sysbus 0x10012000" in text
    assert "nor0: Tardigrade.CFIFlash @ sysbus 0x40000000" in text
    assert "nor1: Tardigrade.CFIFlash @ sysbus 0x44000000" in text


def test_barebox_helper_loads_custom_a9_board() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/boot_barebox_vexpress_renode.py")
    assert "qemu_vexpress_a9.repl" in text
    assert "ARM_SP804PrimeCellTimer.cs" in text
    assert "CFIFlash.cs" in text


def test_optee_helper_loads_custom_a9_board() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/boot_optee_vexpress_renode.py")
    assert "qemu_vexpress_a9.repl" in text
    assert "ARM_SP804PrimeCellTimer.cs" in text
