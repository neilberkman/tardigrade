"""Canonical boot outcomes accepted at profile and runner boundaries."""

DEVICE_BOOT_OUTCOMES = frozenset(
    {
        "bus_fault",
        "hard_fault",
        "misaligned_vtor",
        "no_boot",
        "success",
        "wrong_image",
        "wrong_pc",
    }
)
RUNNER_STATUS_OUTCOMES = frozenset({"infra_error", "skipped", "timeout"})
SUPPORTED_BOOT_OUTCOMES = DEVICE_BOOT_OUTCOMES | RUNNER_STATUS_OUTCOMES


def boot_outcome_after_stop(boot_outcome, stop_reason):
    """Promote an uncompleted wall-clock observation to the timeout status."""
    if str(stop_reason or "").strip().startswith("wall_timeout"):
        return "timeout"
    return boot_outcome


def count_followup_boot_cycles(cycle_records):
    """Return recorded follow-up boot attempts, excluding the initial cycle."""
    if not isinstance(cycle_records, list):
        return 0
    return max(0, len(cycle_records) - 1)


def is_canonical_boot_outcome(value):
    """Return whether *value* is an exact supported wire/profile token."""
    return isinstance(value, str) and value in SUPPORTED_BOOT_OUTCOMES
