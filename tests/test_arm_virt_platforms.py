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
    assert "ram: Memory.MappedMemory @ sysbus 0x60000000" in text


def test_qemu_vexpress_a9_secure_platform_enables_security_states() -> None:
    text = _read("/Users/neil/source/tardigrade/platforms/qemu_vexpress_a9_secure.repl")
    assert "supportsTwoSecurityStates: true" in text
    assert "ram: Memory.MappedMemory @ sysbus 0x60000000" in text


def test_qemu_virt_a15_platform_matches_optee_qemu_virt_layout() -> None:
    text = _read("/Users/neil/source/tardigrade/platforms/qemu_virt_a15.repl")
    assert "cpu: Tardigrade.QEMUVirtARMv7A" in text
    assert 'cpuType: "cortex-a15"' in text
    assert "uart1: UART.PL011 @ sysbus 0x09040000" in text
    assert "secureRam: Memory.MappedMemory @ sysbus 0x0E000000" in text
    assert "size: 0x80000000" in text


def test_qemu_virt_armv7_wrapper_handles_optee_cp15_surface() -> None:
    text = _read("/Users/neil/source/tardigrade/peripherals/QEMUVirtARMv7A.cs")
    assert "PrimaryRegionRemapRegister" in text
    assert "NormalMemoryRemapRegister" in text
    assert "PhysicalAddressRegister" in text
    assert "SetCompatRegister32" in text
    assert "addressTranslationCurrentPrivilegeReadInstruction" in text


def test_optee_qemu_virt_dts_has_console_and_memory() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/optee_qemu_virt_arm32_renode.dts")
    assert 'stdout-path = "serial1:115200n8"' in text
    assert "memory@80000000" in text
    assert "pl011@9040000" in text


def test_barebox_helper_loads_custom_a9_board() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/boot_barebox_vexpress_renode.py")
    assert "qemu_vexpress_a9.repl" in text
    assert "ARM_SP804PrimeCellTimer.cs" in text
    assert "CFIFlash.cs" in text


def test_optee_helper_loads_custom_a9_board() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/boot_optee_vexpress_renode.py")
    assert "qemu_virt_a15.repl" in text
    assert "QEMUVirtARMv7A.cs" in text
    assert "connector Connect sysbus.uart1 u0" in text
    assert "build_optee_embdata" in text
    assert "resolve_symbol_values" in text
    assert "render_va2pa_compat_hook" in text
    assert "arch_va2pa_helper" in text
    assert "static_memory_map" in text
    assert "sysbus LoadBinary" in text
    assert "sysbus.cpu SetRegister 2" in text
