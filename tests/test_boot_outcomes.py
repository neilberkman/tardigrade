import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.boot_outcomes import boot_outcome_after_stop, count_followup_boot_cycles


def test_wall_timeout_is_not_no_boot_evidence() -> None:
    assert boot_outcome_after_stop("no_boot", "wall_timeout(30s)") == "timeout"


def test_no_boot_stall_remains_valid_no_boot_evidence() -> None:
    assert boot_outcome_after_stop("no_boot", "no_boot_stall(20s_emulated)") == "no_boot"


def test_successful_observation_is_unchanged() -> None:
    assert boot_outcome_after_stop("success", "vtor_captured") == "success"


def test_followup_cycle_count_excludes_initial_cycle() -> None:
    assert count_followup_boot_cycles([{"cycle": 0}]) == 0
    assert count_followup_boot_cycles([{"cycle": 0}, {"cycle": 1}]) == 1
    assert count_followup_boot_cycles(None) == 0
