"""Canonical boot outcomes accepted at profile and runner boundaries."""

from __future__ import annotations

from typing import Any


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


def is_canonical_boot_outcome(value: Any) -> bool:
    """Return whether *value* is an exact supported wire/profile token."""
    return isinstance(value, str) and value in SUPPORTED_BOOT_OUTCOMES
