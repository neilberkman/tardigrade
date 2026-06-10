from __future__ import annotations

from pathlib import Path

from scripts import boot_uboot_qemu_arm64_renode as harness


def test_dts_template_advertises_required_devices() -> None:
    text = harness.load_dts_template()
    assert 'compatible = "qemu,fw-cfg-mmio";' in text
    assert "pl011@9000000" in text
    assert "flash@0" in text


def test_render_resc_includes_fw_cfg_and_external_elf() -> None:
    resc = harness.render_resc(
        platform_path=Path("/tmp/platform.repl"),
        fw_cfg_cs_path=Path("/tmp/QEMUFwCfg.cs"),
        dtb_path=Path("/tmp/board.dtb"),
        elf_path=Path("/tmp/u-boot"),
        pty_link=Path("/tmp/uart0.pty"),
    )
    repo_root = harness.repo_root()
    assert "include @{}/peripherals/CFIFlash.cs".format(repo_root) in resc
    assert 'include @/tmp/QEMUFwCfg.cs' in resc
    assert "include @{}/peripherals/PL061Stub.cs".format(repo_root) in resc
    assert 'machine LoadPlatformDescription @/tmp/platform.repl' in resc
    assert 'sysbus LoadELF @/tmp/u-boot' in resc
    assert 'sysbus LoadBinary @/tmp/board.dtb 0x40000000' in resc


def test_default_renode_repo_prefers_env(monkeypatch, tmp_path: Path) -> None:
    renode_repo = tmp_path / "renode"
    renode_repo.mkdir()
    monkeypatch.setenv("RENODE_REPO", str(renode_repo))
    assert harness.default_renode_repo() == renode_repo


def test_default_uboot_elf_prefers_env(monkeypatch, tmp_path: Path) -> None:
    elf = tmp_path / "u-boot"
    elf.write_text("stub", encoding="utf-8")
    monkeypatch.setenv("UBOOT_QEMU_ARM64_ELF", str(elf))
    assert harness.default_uboot_elf() == elf
