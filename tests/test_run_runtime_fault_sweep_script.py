from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "run_runtime_fault_sweep.py"


def test_apply_pre_boot_state_runs_setup_script_before_pre_boot_state() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    start = source.index("def apply_pre_boot_state():")
    end = source.index("def capture_pre_boot_state_debug():", start)
    block = source[start:end]

    assert block.index("if setup_script:") < block.index("if pre_boot_bin:")
    assert block.index("monitor.Parse('include @' + setup_script)") < block.index(
        "bus.WriteDoubleWord(addr, val)"
    )
