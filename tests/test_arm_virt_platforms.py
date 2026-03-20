from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_optee_helper():
    path = Path("/Users/neil/source/tardigrade/scripts/boot_optee_vexpress_renode.py")
    spec = importlib.util.spec_from_file_location("boot_optee_vexpress_renode", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    assert 'address: 0x10E00000; size: 0x010000; region: "distributor"' in text
    assert "uart1: UART.PL011 @ { sysbus 0x09040000; sysbus 0x10F40000 }" in text
    assert "secureRam: Memory.MappedMemory @ { sysbus 0x0E000000; sysbus 0x11000000 }" in text
    assert "size: 0x80000000" in text


def test_qemu_virt_armv7_wrapper_handles_optee_cp15_surface() -> None:
    text = _read("/Users/neil/source/tardigrade/peripherals/QEMUVirtARMv7A.cs")
    assert "PrimaryRegionRemapRegister" in text
    assert "NormalMemoryRemapRegister" in text
    assert "PhysicalAddressRegister" in text
    assert "OpteeStaticMemoryMapAddress" in text
    assert "GetCompatRegister32" in text
    assert "ReturnCompatRegister32" in text
    assert "ReturnCompatRegister32AndJump" in text
    assert "ReturnCompatValue32" in text
    assert "SetCompatRegister32IfZeroFromRegister" in text
    assert "TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled" in text
    assert "ReturnVirtualAddressForPhysicalOrContinue" in text
    assert "ReturnArchVa2PaHelperResultOrContinue" in text
    assert "ReturnMemoryValue32AtRegister" in text
    assert "ReturnMemoryValue32AtRegisterAndJump" in text
    assert "LoadTranslatedMemoryValue32IntoRegisterAndJump" in text
    assert "LoadTranslatedMemoryValue8IntoRegisterAndJump" in text
    assert "CompleteCompatMemmoveFromRegistersIfMmuEnabled" in text
    assert "CompleteFdtOpenIntoHeaderFixupIfMmuEnabled" in text
    assert "ReturnCompatValue64" in text
    assert "ReturnFdt32LoadTranslatedOrContinue" in text
    assert "ReturnFdt64LoadTranslatedOrContinue" in text
    assert "ForceDisableMmu" in text
    assert "ReturnFromFunctionIfMmuEnabled" in text
    assert "ReturnCompatValue32IfMmuEnabled" in text
    assert "SkipCoreMmuDuplicateMapOrContinue" in text
    assert "Write64CP15Inner" in text
    assert "Read64CP15Inner" in text
    assert "SetCompatRegister32" in text
    assert "AnnounceBootStage" in text
    assert "if(value == BootStageMarker)" in text
    assert "GetCompatRegister32(linkRegisterIndex) & ~0x1u" in text
    assert "TryTranslateUsingOpteeStaticMap" in text
    assert "TryTranslatePhysicalToVirtualUsingOpteeStaticMap" in text
    assert "OPTEE_P2V" in text
    assert "addressTranslationCurrentPrivilegeReadInstruction" in text


def test_optee_qemu_virt_dts_has_console_and_memory() -> None:
    text = _read("/Users/neil/source/tardigrade/scripts/optee_qemu_virt_arm32_renode.dts")
    assert 'stdout-path = "serial1:115200n8"' in text
    assert "memory@40000000" in text
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
    assert "ReturnFromFunctionIfMmuEnabled" in text
    assert "build_optee_embdata" in text
    assert "resolve_symbol_values" in text
    assert "hook_address" in text
    assert "static_memory_map" in text
    assert "OpteeStaticMemoryMapAddress" in text
    assert "boot_init_primary_early" in text
    assert "plat_console_init" in text
    assert "boot_init_primary_runtime" in text
    assert "boot_init_primary_final" in text
    assert "call_early_initcalls" in text
    assert "call_service_initcalls" in text
    assert "call_driver_initcalls" in text
    assert "thread_init_boot_thread" in text
    assert "AnnounceBootStage" in text
    assert "OPTEE_STAGE_BOOT_EARLY" in text
    assert "OPTEE_STAGE_CONSOLE_INIT" in text
    assert "OPTEE_STAGE_BOOT_RUNTIME" in text
    assert "OPTEE_STAGE_BOOT_FINAL" in text
    assert "OPTEE_STAGE_PL011_INIT" in text
    assert "OPTEE_STAGE_PL011_FLUSH" in text
    assert "OPTEE_STAGE_PL011_PUTC" in text
    assert "OPTEE_STAGE_ARCH_VA2PA" in text
    assert "OPTEE_STAGE_VIRT_TO_PHYS" in text
    assert "OPTEE_STAGE_CORE_MMU_DUPLICATE_MAP" in text
    assert "OPTEE_STAGE_ASSERT_BREAK" in text
    assert "OPTEE_STAGE_REGISTER_SERIAL_CONSOLE" in text
    assert "OPTEE_STAGE_PHYS_TO_VIRT_IO" in text
    assert "OPTEE_STAGE_IO_PA_OR_VA_RETURN" in text
    assert "OPTEE_STAGE_PL011_POST_IO" in text
    assert "OPTEE_STAGE_CONFIGURE_CONSOLE_FROM_DT" in text
    assert "pl011_init" in text
    assert "pl011_flush" in text
    assert "pl011_putc" in text
    assert "register_serial_console" in text
    assert "virt_to_phys" in text
    assert "core_mmu_map_region" in text
    assert "_assert_break" in text
    assert "phys_to_virt_io" in text
    assert "io_pa_or_va" in text
    assert "configure_console_from_dt" in text
    assert "fdt_open_into" in text
    assert "fdt_move" in text
    assert "fdt_next_tag" in text
    assert "fdt32_ld" in text
    assert "fdt64_ld" in text
    assert "maybe_open_uart_fd" in text
    assert "pty_path: Path | None = None" in text
    assert "read_until_any_stream" in text
    assert "sysbus LoadBinary" in text
    assert "sysbus.cpu SetRegister 2" in text


def test_optee_helper_uses_safe_dtb_default() -> None:
    helper = _load_optee_helper()
    assert helper.DEFAULT_DTB_LOAD_ADDR == 0x7FE00000


def test_optee_marker_matching_does_not_collapse_stage_11_into_stage_1() -> None:
    helper = _load_optee_helper()
    output = b"01:23:45 [WARNING] cpu: OPTEE_STAGE:11\n"
    assert helper.find_marker_in_output(output, ("OPTEE_STAGE:1",)) is None
    assert helper.find_marker_in_output(output, ("OPTEE_STAGE:1", "OPTEE_STAGE:11")) == "OPTEE_STAGE:11"
