"""Installation, starter-profile and CLI dispatch regressions."""
import json
from pathlib import Path
import shutil
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "results/oss_validation/assets"


@pytest.fixture
def cli():
    from tardigrade import cli
    return cli


def arguments(directory, board="nrf52"):
    return ["init", "--bootloader", str(ASSETS / f"oss_mcuboot_head_move_{board}.elf"),
            "--primary", str(ASSETS / f"zephyr_head_move_{board}_slot0.bin"),
            "--update", str(ASSETS / f"zephyr_head_move_{board}_slot1.bin"),
            "--output", str(directory / "starter.yaml")]


def test_dispatch_report(cli, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("result.json").write_text(json.dumps({
        "engine": "renode-test",
        "profile": "my-control",
        "summary": {},
        "verdict": "PASS",
        "runtime_sweep_results": [],
    }))
    assert cli.main(["report", "--input", "result.json", "--output", "index.html"]) == 0
    assert "my-control" in Path("index.html").read_text()


def test_dispatch_demo_runs_from_installed_runtime(cli, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: calls.append(cmd) or 7)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["demo", "--renode-test", "my-renode"]) == 7
    assert calls[0][:4] == [sys.executable, str(cli.RUNTIME / "scripts/run_demo.py"), "--renode-test", "my-renode"]
    assert calls[0][-1] == str(tmp_path / "results/demo")


def test_dispatch_audit_uses_existing_audit_runtime_and_forwards_flags(cli, tmp_path, monkeypatch):
    recorded = {}

    class DummyProcess:
        pid = 12345

        def __init__(self, command, *, cwd, env, start_new_session):
            recorded["command"] = command
            recorded["cwd"] = cwd
            recorded["env"] = env
            recorded["session"] = start_new_session

        def wait(self, timeout=None):
            recorded["timeout"] = timeout
            return 0

    monkeypatch.setattr(cli.subprocess, "Popen", DummyProcess)
    monkeypatch.chdir(tmp_path)
    profile = ROOT / "profiles/naive_bare_copy.yaml"
    output = tmp_path / "audit.json"
    assert cli.main([
        "audit",
        "--profile", str(profile),
        "--output", str(output),
        "--renode-test", "my-renode",
        "--timeout", "180",
        "--quick",
        "--workers", "1",
    ]) == 0
    assert recorded["command"] == [
        sys.executable,
        str(cli.RUNTIME / "scripts/audit_bootloader.py"),
        "--profile", str(profile.resolve()),
        "--output", str(output.resolve()),
        "--renode-test", "my-renode",
        "--quick",
        "--workers", "1",
    ]
    assert recorded["cwd"] == str(ROOT)
    assert recorded["timeout"] == 180
    assert recorded["env"]["OTA_RENODE_POINT_TIMEOUT_S"] == "180"


def test_doctor_checks_server_and_version(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda cmd: str(tmp_path / cmd))
    monkeypatch.setattr(cli, "probe", lambda cmd: "Renode v1.17.0.123" if cmd[-1] == "--version" else "")
    assert cli.main(["doctor"]) == 0
    assert "Renode 1.17.0" in capsys.readouterr().out
    monkeypatch.setattr(cli, "probe", lambda cmd: "")
    assert cli.main(["doctor"]) == 1
    assert "Renode unavailable" in capsys.readouterr().out


@pytest.mark.parametrize("board,base,size", [("nrf52", 0xC000, 0x76000), ("stm32f4", 0x8020000, 0x60000)])
def test_init_compiled_slots_and_image(cli, tmp_path, monkeypatch, board, base, size):
    monkeypatch.chdir(tmp_path)
    assert cli.main(arguments(tmp_path, board)) == 0
    profile = yaml.safe_load(Path("starter.yaml").read_text())
    assert profile["memory"]["slots"]["exec"] == {"base": base, "size": size}
    assert profile["success_criteria"]["vector_table_offset"] == 0x200
    assert profile["update_trigger"]["max_align"] == 8
    assert (tmp_path / profile["bootloader"]["elf"]).is_file()
    monkeypatch.syspath_prepend(str(cli.RUNTIME / "scripts"))
    from profile_loader import load_profile
    loaded = load_profile(tmp_path / "starter.yaml", strict=True, repo_root=cli.RUNTIME)
    assert Path(loaded.resolve_path(cli.RUNTIME, loaded.platform)).is_file()
    assert Path(loaded.resolve_path(cli.RUNTIME, loaded.bootloader_elf)).is_file()
    for path in (
        cli.RUNTIME / "scripts/audit_bootloader.py",
        cli.RUNTIME / "scripts/run_runtime_fault_sweep.py",
        cli.RUNTIME / "scripts/run_runtime_fault_sweep.resc",
        cli.RUNTIME / "tests/ota_fault_point.robot",
    ):
        assert path.is_file()


def build_fixture(directory):
    (directory / ".config").write_text("CONFIG_SOC_NRF52840=y\nCONFIG_FLASH_BASE_ADDRESS=0\nCONFIG_BOOT_SWAP_USING_MOVE=y\n")
    (directory / "zephyr.dts").write_text("""/dts-v1/;
/ {
    chosen { zephyr,sram = &ram; zephyr,flash = &flash; zephyr,code-partition = &loader; };
    soc {
        compatible = "nordic,nrf52840";
        ram: memory@20000000 { reg = <0x20000000 0x40000>; };
        flash: flash@0 {
            reg = <0 0x100000>; write-block-size = <4>; erase-block-size = <0x1000>;
            partitions {
                compatible = "fixed-partitions";
                loader: partition@0 { label = "mcuboot"; reg = <0 0xc000>; };
                partition@c000 { label = "image-0"; reg = <0xc000 0x76000>; };
                partition@82000 { label = "image-1"; reg = <0x82000 0x76000>; };
            };
        };
    };
};
""")


def test_init_uses_supplied_build_and_rejects_conflicting_map(cli, tmp_path, capsys):
    build_fixture(tmp_path)
    assert cli.main([*arguments(tmp_path), "--build-dir", str(tmp_path)]) == 0
    tree = tmp_path / "zephyr.dts"
    tree.write_text(tree.read_text().replace("0x82000 0x76000", "0x83000 0x75000"))
    with pytest.raises(SystemExit) as failure:
        cli.main([*arguments(tmp_path / "bad"), "--build-dir", str(tmp_path)])
    assert failure.value.code == 2
    assert "disagrees with compiled ELF flash map" in capsys.readouterr().err
    assert "UNRESOLVED" in (tmp_path / "bad/starter.yaml").read_text()


def test_init_rejects_unknown_build_even_with_a_familiar_name(cli, tmp_path, capsys):
    args = arguments(tmp_path)
    loader = tmp_path / "oss_mcuboot_head_move_nrf52.elf"
    loader.write_bytes(Path(args[2]).read_bytes() + b"different-build")
    args[2] = str(loader)
    with pytest.raises(SystemExit):
        cli.main(args)
    assert "cannot establish board" in capsys.readouterr().err


def test_init_refuses_truncated_tlv(cli, tmp_path, capsys):
    args = arguments(tmp_path)
    image = tmp_path / "short.bin"
    image.write_bytes(Path(args[6]).read_bytes()[:-1])
    args[6] = str(image)
    with pytest.raises(SystemExit):
        cli.main(args)
    assert "MCUboot image with TLVs" in capsys.readouterr().err


def test_wheel_contains_runtime_and_demo_outside_checkout(tmp_path):
    import subprocess
    import zipfile

    wheel_dir = tmp_path / "wheels"
    for artifact in (ROOT / "build", ROOT / "tardigrade.egg-info"):
        shutil.rmtree(artifact, ignore_errors=True)
    try:
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--disable-pip-version-check",
                        "--no-build-isolation", "--no-deps", "-w", str(wheel_dir), str(ROOT)], check=True)
    finally:
        for artifact in (ROOT / "build", ROOT / "tardigrade.egg-info"):
            shutil.rmtree(artifact, ignore_errors=True)
    site = tmp_path / "installed"
    with zipfile.ZipFile(next(wheel_dir.glob("tardigrade-*.whl"))) as wheel:
        wheel.extractall(site)
    check = """
import sys
from pathlib import Path
checkout = Path(sys.argv[2]).resolve()
sys.path[:] = [p for p in sys.path if not (p and Path(p).resolve().is_relative_to(checkout))]
sys.path.insert(0, sys.argv[1])
from tardigrade.cli import PACKAGE, RUNTIME, main
assert PACKAGE == Path(sys.argv[1]) / 'tardigrade'
assert RUNTIME.is_relative_to(PACKAGE)
for resource in [
    'peripherals/NRF52NVMC.cs',
    'platforms/stm32f4_fast.repl',
    'scripts/profile_loader.py',
    'scripts/audit_bootloader.py',
    'scripts/run_runtime_fault_sweep.py',
    'scripts/run_runtime_fault_sweep.resc',
    'scripts/run_demo.py',
    'tests/ota_fault_point.robot',
    'targets/mcuboot/probe.py',
    'profiles/naive_bare_copy.yaml',
    'profiles/demo_mcuboot_offset_upgrade.yaml',
    'profiles/mcuboot_offset_upgrade.yaml',
    'examples/vulnerable_ota/firmware.elf',
    'examples/vulnerable_ota/firmware.bin',
    'results/oss_validation/assets/oss_mcuboot_head_offset.elf',
]:
    assert (RUNTIME / resource).is_file(), resource
assert not (PACKAGE / 'control.py').exists()
assert not (PACKAGE / 'control.robot').exists()
assert not (PACKAGE / 'control.resc').exists()
raise SystemExit(main(sys.argv[3:]))
"""
    subprocess.run([sys.executable, "-c", check, str(site), str(ROOT), *arguments(tmp_path)], cwd=tmp_path, check=True)


def test_nxboot_partition_device_roles_match_compiled_table(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    from tardigrade.starter import inspect_image, nuttx_layout
    image = inspect_image((ROOT / "examples/nxboot_style/nxboot_update.bin").read_bytes())
    assert image.header == 0x200 and image.family == "nxboot"
    table = {f"/dev/ota{i}": (off, 0x80000) for i, off in enumerate((0x40000, 0xc0000, 0x140000))}
    cfg = {"CONFIG_ARCH_BOARD_NUCLEO_H743ZI": "y", "CONFIG_ARCH_CHIP_STM32H743ZI": "y",
           "CONFIG_NXBOOT_BOOTLOADER": "y", "CONFIG_NXBOOT_PLATFORM_IDENTIFIER": "0", "CONFIG_NXBOOT_HEADER_SIZE": "0x200", "CONFIG_STM32_OTA_SLOT_SIZE": "0x80000"}
    for index, role in enumerate(("PRIMARY", "SECONDARY", "TERTIARY")):
        cfg[f"CONFIG_STM32_OTA_{role}_SLOT_OFFSET"] = hex(0x40000 + 0x80000 * index)
        cfg[f"CONFIG_NXBOOT_{role}_SLOT_PATH"] = cfg[f"CONFIG_STM32_OTA_{role}_SLOT_DEVPATH"] = f"/dev/ota{index}"
    args = (cfg, 0x08000000, {"nxboot_partitions": table}, image, image)
    assert nuttx_layout(*args).slots["tertiary"]["base"] == 0x08140000
    cfg["CONFIG_NXBOOT_SECONDARY_SLOT_PATH"] = "/dev/ota0"
    with pytest.raises(ValueError, match="SECONDARY"):
        nuttx_layout(*args)


def test_offset_swap_places_raw_signed_image_after_one_sector(cli, tmp_path):
    build_fixture(tmp_path)
    config = tmp_path / ".config"
    config.write_text(config.read_text().replace("USING_MOVE", "USING_OFFSET"))
    args = [s.replace("head_move_", "head_offset_") for s in arguments(tmp_path)]
    raw = Path(args[6]).read_bytes()
    assert cli.main([*args, "--build-dir", str(tmp_path)]) == 0
    profile = yaml.safe_load((tmp_path / "starter.yaml").read_text())
    prepared = (tmp_path / profile["images"]["staging"]).read_bytes()
    assert prepared == b"\xff" * 4096 + raw
    assert profile["success_criteria"]["marker_address"] == 0xC014


def test_audit_and_init_control_run_existing_audit_runtime_on_starter(cli, tmp_path):
    fake_runner = tmp_path / "fake-renode-test"
    fake_runner.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "vars_map = {}\n"
        "args = sys.argv[1:]\n"
        "for i, arg in enumerate(args):\n"
        "    if arg == '--variable' and i + 1 < len(args) and ':' in args[i + 1]:\n"
        "        k, v = args[i + 1].split(':', 1)\n"
        "        vars_map[k] = v\n"
        "mode = pathlib.Path(vars_map.get('MODE_FILE', '')).read_text().strip() if 'MODE_FILE' in vars_map else 'pass'\n"
        "result = {\n"
        "    'fault_at': int(vars_map['FAULT_AT']),\n"
        "    'fault_requested': int(vars_map['FAULT_AT']),\n"
        "    'fault_type': 'control',\n"
        "    'fault_injected': False,\n"
        "    'fault_address': '0x00000000',\n"
        "    'boot_outcome': 'success' if mode == 'pass' else 'wrong_image',\n"
        "    'boot_slot': 'exec',\n"
        "    'signals': {\n"
        "        'vtor': '0x0000C200',\n"
        "        'marker_ok': mode == 'pass',\n"
        "        'image_hash_match': 'staging_image' if mode == 'pass' else 'exec_image',\n"
        "        'matched_image': 'staging' if mode == 'pass' else 'exec',\n"
        "        'image_hash_actual': vars_map.get('EXPECTED_EXEC_SHA256', '') if mode == 'pass' else '0' * 64,\n"
        "    },\n"
        "}\n"
        "pathlib.Path(vars_map['RESULT_FILE']).write_text(json.dumps(result))\n"
    )
    fake_runner.chmod(0o755)
    mode_file = tmp_path / "mode.txt"
    mode_file.write_text("pass")
    assert cli.main([
        *arguments(tmp_path),
        "--control",
        "--renode-test", str(fake_runner),
    ]) == 0
    control_report = json.loads((tmp_path / "starter.control.json").read_text())
    assert control_report["engine"] == "renode-test"
    assert control_report["verdict"].startswith("PASS")
    assert control_report["runtime_sweep_results"][0]["is_control"] is True
    assert control_report["runtime_sweep_results"][0]["boot_outcome"] == "success"

    mode_file.write_text("fail")
    bad_report = tmp_path / "bad.json"
    assert cli.main([
        "audit",
        "--profile", str(tmp_path / "starter.yaml"),
        "--output", str(bad_report),
        "--renode-test", str(fake_runner),
        "--robot-var", f"MODE_FILE:{mode_file}",
    ]) == 2
