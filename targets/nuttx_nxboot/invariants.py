#!/usr/bin/env python3
"""NuttX nxboot invariants for tardigrade replay and audit runs.

Thin wrappers around the shared nxboot invariants that use
``nuttx_nxboot_`` prefixed names for backward-compatible profile references.
"""

from targets.nxboot.invariants import (
    _flags,
    _roles,
    _semantic_root,
    _slot,
    check_nxboot_confirmed_has_recovery as _base_confirmed_has_recovery,
    check_nxboot_duplicate_update_consumed as _base_duplicate_update_consumed,
    check_nxboot_roles_distinct as _base_roles_distinct,
    check_nxboot_unconfirmed_internal_requires_revert as _base_unconfirmed_revert,
)
from invariants import InvariantViolation


def check_nuttx_nxboot_roles_distinct(result, **kw):
    """Wrapper that re-raises with nuttx_nxboot-prefixed invariant name."""
    try:
        _base_roles_distinct(result, **kw)
    except InvariantViolation as exc:
        raise InvariantViolation(
            invariant_name="nuttx_nxboot_roles_distinct",
            description="NuttX nxboot update and recovery roles collapsed onto the same slot.",
            result=exc.result,
            details=exc.details,
        ) from None


def check_nuttx_nxboot_confirmed_has_recovery(result, **kw):
    """Wrapper that re-raises with nuttx_nxboot-prefixed invariant name."""
    try:
        _base_confirmed_has_recovery(result, **kw)
    except InvariantViolation as exc:
        raise InvariantViolation(
            invariant_name="nuttx_nxboot_confirmed_has_recovery",
            description=exc.description,
            result=exc.result,
            details=exc.details,
        ) from None


def check_nuttx_nxboot_duplicate_update_consumed(result, **kw):
    """Wrapper that re-raises with nuttx_nxboot-prefixed invariant name."""
    try:
        _base_duplicate_update_consumed(result, **kw)
    except InvariantViolation as exc:
        raise InvariantViolation(
            invariant_name="nuttx_nxboot_duplicate_update_consumed",
            description=exc.description,
            result=exc.result,
            details=exc.details,
        ) from None


def check_nuttx_nxboot_unconfirmed_internal_requires_revert(result, **kw):
    """Wrapper that re-raises with nuttx_nxboot-prefixed invariant name."""
    try:
        _base_unconfirmed_revert(result, **kw)
    except InvariantViolation as exc:
        raise InvariantViolation(
            invariant_name="nuttx_nxboot_unconfirmed_internal_requires_revert",
            description=exc.description,
            result=exc.result,
            details=exc.details,
        ) from None


INVARIANTS = {
    "nuttx_nxboot_roles_distinct": check_nuttx_nxboot_roles_distinct,
    "nuttx_nxboot_confirmed_has_recovery": check_nuttx_nxboot_confirmed_has_recovery,
    "nuttx_nxboot_duplicate_update_consumed": check_nuttx_nxboot_duplicate_update_consumed,
    "nuttx_nxboot_unconfirmed_internal_requires_revert": (
        check_nuttx_nxboot_unconfirmed_internal_requires_revert
    ),
}
