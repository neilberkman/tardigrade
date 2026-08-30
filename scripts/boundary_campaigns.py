"""Validation and expansion helpers for logical security-counter campaigns.

Boundary campaigns deliberately live outside the fault injector.  They are
ordinary profile runs with one deterministic parameter value, which keeps
control-only counter bugs visible and makes the resulting runs cacheable.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from boundary_reserved import BOUNDARY_RESERVED_VARIABLES


MAX_BOUNDARY_WIDTH_BITS = 64
MAX_BOUNDARY_ARITHMETIC = (1 << 64) - 1
_VALUE_NAMES = {
    "zero",
    "one",
    "capacity_minus_one",
    "capacity",
    "capacity_plus_one",
    "type_max",
}

class BoundaryCampaignError(ValueError):
    """Raised when a boundary campaign is malformed or unsafe."""


def _integer(value: Any, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BoundaryCampaignError("{} must be an integer".format(field))
    if value < (1 if positive else 0):
        relation = "positive" if positive else "non-negative"
        raise BoundaryCampaignError("{} must be {}".format(field, relation))
    if value > MAX_BOUNDARY_ARITHMETIC:
        raise BoundaryCampaignError(
            "{} exceeds implementation safety limit {}".format(
                field, MAX_BOUNDARY_ARITHMETIC
            )
        )
    return value


def _checked_add(value: int, delta: int, field: str) -> int:
    result = value + delta
    if result < 0 or result > MAX_BOUNDARY_ARITHMETIC:
        raise BoundaryCampaignError(
            "{} exceeds implementation safety limit {}".format(
                field, MAX_BOUNDARY_ARITHMETIC
            )
        )
    return result


@dataclass(frozen=True)
class BoundaryFollowUp:
    parameter_value: str
    expect: str


@dataclass(frozen=True)
class BoundaryCampaign:
    name: str
    parameter: str
    type: str
    width_bits: int
    capacity: Dict[str, int]
    values: Tuple[Any, ...]
    setup_environment: str
    follow_up: Optional[BoundaryFollowUp] = None

    @property
    def logical_capacity(self) -> int:
        return resolve_boundary_capacity(self.capacity)

    @property
    def resolved_values(self) -> List[int]:
        return resolve_boundary_values(self)

    @property
    def run_names(self) -> List[str]:
        return ["{}__{}".format(self.name, value) for value in self.resolved_values]


def resolve_boundary_capacity(capacity: Mapping[str, Any]) -> int:
    """Resolve one explicit, entry-array, or bit-packed capacity form."""
    if not isinstance(capacity, Mapping):
        raise BoundaryCampaignError("capacity must be a mapping")
    keys = set(capacity)
    forms = (
        {"elements"},
        {"storage_bytes", "element_bytes"},
        {"storage_bytes", "bits_per_increment"},
    )
    matches = [form for form in forms if keys == form]
    if len(matches) != 1:
        raise BoundaryCampaignError(
            "capacity must contain exactly one of elements, "
            "storage_bytes+element_bytes, or storage_bytes+bits_per_increment"
        )
    form = matches[0]
    if form == {"elements"}:
        return _integer(capacity["elements"], "capacity.elements", positive=True)
    storage = _integer(capacity["storage_bytes"], "capacity.storage_bytes", positive=True)
    if form == {"storage_bytes", "element_bytes"}:
        element = _integer(capacity["element_bytes"], "capacity.element_bytes", positive=True)
        if storage % element:
            raise BoundaryCampaignError(
                "capacity.storage_bytes must divide exactly by capacity.element_bytes"
            )
        result = storage // element
    else:
        bits = _integer(
            capacity["bits_per_increment"],
            "capacity.bits_per_increment",
            positive=True,
        )
        numerator = _checked_add(storage * 8, 0, "capacity bit arithmetic")
        if numerator % bits:
            raise BoundaryCampaignError(
                "capacity.storage_bytes * 8 must divide exactly by "
                "capacity.bits_per_increment"
            )
        result = numerator // bits
    if result <= 0 or result > MAX_BOUNDARY_ARITHMETIC:
        raise BoundaryCampaignError("resolved capacity is outside implementation limits")
    return result


def _resolve_value(value: Any, capacity: int, width_bits: int) -> int:
    if isinstance(value, bool):
        raise BoundaryCampaignError("boundary value must be an integer or named value")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        name = value.strip()
        if name == "zero":
            result = 0
        elif name == "one":
            result = 1
        elif name == "capacity_minus_one":
            result = capacity - 1
        elif name == "capacity":
            result = capacity
        elif name == "capacity_plus_one":
            result = _checked_add(capacity, 1, "capacity_plus_one")
        elif name == "type_max":
            result = (1 << width_bits) - 1
        else:
            raise BoundaryCampaignError("unknown boundary value {!r}".format(value))
    else:
        raise BoundaryCampaignError("boundary value must be an integer or named value")
    if result < 0:
        raise BoundaryCampaignError("boundary values must be non-negative")
    if result > MAX_BOUNDARY_ARITHMETIC:
        raise BoundaryCampaignError(
            "boundary value exceeds implementation safety limit {}".format(
                MAX_BOUNDARY_ARITHMETIC
            )
        )
    type_max = (1 << width_bits) - 1
    if result > type_max:
        raise BoundaryCampaignError(
            "boundary value {} does not fit unsigned width {}".format(
                result, width_bits
            )
        )
    return result


def resolve_boundary_values(campaign: BoundaryCampaign) -> List[int]:
    """Resolve and deduplicate values, retaining declaration order."""
    if isinstance(campaign, Mapping):
        campaign = parse_boundary_campaign(campaign)
    capacity = campaign.logical_capacity
    result: List[int] = []
    seen = set()
    for raw in campaign.values:
        value = _resolve_value(raw, capacity, campaign.width_bits)
        if value not in seen:
            seen.add(value)
            result.append(value)
    if not result:
        raise BoundaryCampaignError("values must contain at least one entry")
    if campaign.follow_up is not None:
        if campaign.follow_up.parameter_value != "previous":
            raise BoundaryCampaignError(
                "follow_up.parameter_value must be 'previous'"
            )
        if campaign.follow_up.expect != "rejected":
            raise BoundaryCampaignError(
                "follow_up.expect must be 'rejected'"
            )
    return result


def resolve_boundary_value(value: Any, campaign: BoundaryCampaign) -> int:
    """Resolve one named or literal value (public single-value helper)."""
    if isinstance(campaign, Mapping):
        campaign = parse_boundary_campaign(campaign)
    return _resolve_value(value, campaign.logical_capacity, campaign.width_bits)


def resolve_followup_value(candidate: int) -> int:
    """Resolve the supported ``previous`` relation for one candidate."""
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise BoundaryCampaignError(
            "follow-up previous is invalid for candidate value {}".format(candidate)
        )
    return candidate - 1


def parse_boundary_campaign(raw: Mapping[str, Any], index: int = 0) -> BoundaryCampaign:
    """Strictly parse one YAML campaign mapping."""
    if not isinstance(raw, Mapping):
        raise BoundaryCampaignError("boundary_campaigns[{}] must be a mapping".format(index))
    allowed = {
        "name", "parameter", "type", "width_bits", "capacity", "values",
        "setup_environment", "follow_up",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise BoundaryCampaignError(
            "boundary_campaigns[{}]: unknown field(s): {}".format(index, ", ".join(unknown))
        )
    context = "boundary_campaigns[{}]".format(index)
    name = raw.get("name")
    parameter = raw.get("parameter")
    setup_environment = raw.get("setup_environment")
    for value, field in ((name, "name"), (parameter, "parameter"), (setup_environment, "setup_environment")):
        if not isinstance(value, str) or not value.strip():
            raise BoundaryCampaignError("{}.{} must be a non-empty string".format(context, field))
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(name)) is None:
        raise BoundaryCampaignError("{}.name is not a valid identifier".format(context))
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(setup_environment)) is None:
        raise BoundaryCampaignError("{}.setup_environment must be an environment variable name".format(context))
    if str(setup_environment) in BOUNDARY_RESERVED_VARIABLES:
        raise BoundaryCampaignError(
            "{}.setup_environment conflicts with a reserved harness variable".format(context)
        )
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(parameter)) is None:
        raise BoundaryCampaignError("{}.parameter must be an identifier".format(context))
    if raw.get("type") != "unsigned_integer":
        raise BoundaryCampaignError("{}.type must be 'unsigned_integer'".format(context))
    width_bits = _integer(raw.get("width_bits"), "{}.width_bits".format(context), positive=True)
    if width_bits > MAX_BOUNDARY_WIDTH_BITS:
        raise BoundaryCampaignError("{}.width_bits exceeds implementation safety limit {}".format(context, MAX_BOUNDARY_WIDTH_BITS))
    capacity = raw.get("capacity")
    if not isinstance(capacity, Mapping):
        raise BoundaryCampaignError("{}.capacity must be a mapping".format(context))
    # Validate now so malformed campaigns fail during profile loading.
    resolve_boundary_capacity(capacity)
    values = raw.get("values")
    if not isinstance(values, list) or not values:
        raise BoundaryCampaignError("{}.values must be a non-empty list".format(context))
    follow_raw = raw.get("follow_up")
    follow_up = None
    if follow_raw is not None:
        if not isinstance(follow_raw, Mapping) or set(follow_raw) != {"parameter_value", "expect"}:
            raise BoundaryCampaignError("{}.follow_up must contain parameter_value and expect".format(context))
        parameter_value = follow_raw.get("parameter_value")
        expect = follow_raw.get("expect")
        if parameter_value != "previous":
            raise BoundaryCampaignError(
                "{}.follow_up.parameter_value must be 'previous'".format(context)
            )
        if expect != "rejected":
            raise BoundaryCampaignError(
                "{}.follow_up.expect must be 'rejected'".format(context)
            )
        follow_up = BoundaryFollowUp(parameter_value, expect)
    campaign = BoundaryCampaign(
        name=str(name), parameter=str(parameter), type="unsigned_integer",
        width_bits=width_bits, capacity={str(k): v for k, v in capacity.items()},
        values=tuple(values), setup_environment=str(setup_environment), follow_up=follow_up,
    )
    resolve_boundary_values(campaign)
    if campaign.follow_up is not None:
        for candidate in resolve_boundary_values(campaign):
            resolve_followup_value(candidate)
    return campaign


def boundary_campaign_dict(campaign: BoundaryCampaign) -> Dict[str, Any]:
    values = resolve_boundary_values(campaign)
    result: Dict[str, Any] = {
        "name": campaign.name,
        "parameter": campaign.parameter,
        "type": campaign.type,
        "width_bits": campaign.width_bits,
        "capacity": dict(campaign.capacity),
        "logical_capacity": campaign.logical_capacity,
        "values": values,
        "setup_environment": campaign.setup_environment,
    }
    if campaign.follow_up is not None:
        result["follow_up"] = {
            "parameter_value": campaign.follow_up.parameter_value,
            "expect": campaign.follow_up.expect,
        }
    return result


def aggregate_boundary_results(
    campaign: BoundaryCampaign, results: Sequence[Mapping[str, Any]]
) -> Dict[str, Any]:
    """Aggregate candidate/follow-up observations into a fail-closed report."""
    def canonical_int(value: Any) -> Optional[int]:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value.strip()) is None:
            return None
        parsed = int(value, 10)
        return parsed if str(parsed) == value.strip() else None

    def snapshot_reason(item: Mapping[str, Any]) -> Optional[str]:
        capture = item.get("boundary_snapshot_capture")
        restore = item.get("boundary_snapshot_restore")
        if not isinstance(capture, Mapping) or not isinstance(restore, Mapping):
            return "missing candidate capture or follow-up restore evidence"
        capture_path = capture.get("path")
        restore_path = restore.get("path")
        if (
            not isinstance(capture_path, str)
            or not capture_path
            or not isinstance(restore_path, str)
            or capture_path != restore_path
        ):
            return "candidate/follow-up snapshot paths differ"
        capture_identity = capture.get("backend_identity")
        restore_identity = restore.get("backend_identity")
        if (
            not isinstance(capture_identity, str)
            or not capture_identity
            or not isinstance(restore_identity, str)
            or capture_identity != restore_identity
        ):
            return "candidate/follow-up snapshot backend identities differ or are missing"
        capture_digest = str(capture.get("sha256", "")).lower()
        restore_digest = str(restore.get("sha256", "")).lower()
        if (
            re.fullmatch(r"[0-9a-f]{64}", capture_digest) is None
            or capture_digest != restore_digest
        ):
            return "candidate/follow-up snapshot digests differ or are malformed"

        def components(value: Any) -> Optional[List[Tuple[str, int, str]]]:
            if not isinstance(value, list):
                return None
            normalized: List[Tuple[str, int, str]] = []
            for descriptor in value:
                if not isinstance(descriptor, Mapping):
                    return None
                name = descriptor.get("name")
                length = descriptor.get("length")
                digest = str(descriptor.get("sha256", "")).lower()
                if (
                    not isinstance(name, str)
                    or not isinstance(length, int)
                    or isinstance(length, bool)
                    or length < 0
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                ):
                    return None
                normalized.append((name, length, digest))
            return normalized

        capture_components = components(capture.get("components"))
        restore_components = components(restore.get("components"))
        if (
            capture_components is None
            or restore_components is None
            or not capture_components
            or not any(item[0] == "flash" for item in capture_components)
            or capture_components != restore_components
            or len({item[0] for item in capture_components}) != len(capture_components)
        ):
            return "candidate/follow-up snapshot components or lengths differ"
        return None

    values = resolve_boundary_values(campaign)
    by_value: Dict[int, Mapping[str, Any]] = {}
    malformed = False
    for item in results:
        if not isinstance(item, Mapping):
            malformed = True
            continue
        raw_value = item.get("resolved_value")
        resolved_value = canonical_int(raw_value)
        if resolved_value is None:
            malformed = True
            continue
        if resolved_value not in values or resolved_value in by_value:
            malformed = True
            continue
        by_value[resolved_value] = item
    rows: List[Dict[str, Any]] = []
    for value in values:
        item = dict(by_value.get(value, {}))
        item["campaign"] = campaign.name
        item["resolved_value"] = value
        # The child runner emits these exact protocol tokens.  Do not accept
        # historical/display labels here: accepting aliases would turn a
        # malformed or stale report into a security verdict.
        candidate = item.get("candidate_status", "")
        persisted = item.get(
            "persisted_value",
            item.get("persisted_state", item.get("candidate_persisted_value")),
        )
        accepted_statuses = {"accepted"}
        rejected_statuses = {"rejected"}
        if (
            malformed
            or item.get("infrastructure_failure")
            or not isinstance(candidate, str)
            or candidate in {"infrastructure/setup failure", "infrastructure_failure", "setup_failure", "error", ""}
        ):
            classification = "infrastructure/setup failure"
        elif candidate in rejected_statuses:
            classification = "candidate rejected before persistence"
        elif candidate not in accepted_statuses:
            classification = "infrastructure/setup failure"
        elif persisted is None:
            classification = "infrastructure/setup failure"
        else:
            persisted_int = canonical_int(persisted)
            if persisted_int is None or persisted_int != value:
                classification = (
                    "candidate accepted but persisted state is smaller"
                    if persisted_int is not None and persisted_int < value
                    else "infrastructure/setup failure"
                )
            else:
                classification = "candidate accepted and correctly persisted"
        item["classification"] = classification
        if campaign.follow_up is not None:
            evidence_error = snapshot_reason(item)
            if evidence_error:
                item["infrastructure_reason"] = evidence_error
            follow = item.get("follow_up_status", "")
            follow_value = item.get("follow_up_value", item.get("follow_up_parameter_value"))
            expected_follow = value - 1
            follow_ok = isinstance(follow, str) and follow == "rejected"
            follow_accepted = isinstance(follow, str) and follow == "accepted"
            if follow_value is not None:
                parsed_follow_value = canonical_int(follow_value)
                follow_ok = follow_ok and parsed_follow_value == expected_follow
                follow_accepted = follow_accepted and parsed_follow_value == expected_follow
            else:
                follow_ok = False
                follow_accepted = False
            if evidence_error:
                item["follow_up_classification"] = "infrastructure/setup failure"
                item["classification"] = "infrastructure/setup failure"
            elif follow_accepted:
                item["follow_up_classification"] = "follow-up rollback accepted"
            elif follow_ok:
                item["follow_up_classification"] = "follow-up rollback rejected"
            else:
                item["follow_up_classification"] = "infrastructure/setup failure"
                item["classification"] = "infrastructure/setup failure"
        rows.append(item)
    rollback_failure = any(
        row.get("follow_up_classification") == "follow-up rollback accepted"
        or row.get("classification") == "candidate accepted but persisted state is smaller"
        for row in rows
    )
    infra = any(
        row.get("classification") == "infrastructure/setup failure"
        or row.get("follow_up_classification") == "infrastructure/setup failure"
        for row in rows
    )
    verdict = "INCONCLUSIVE" if infra else ("FAIL" if rollback_failure else "PASS")
    return {
        "campaign": campaign.name,
        "parameter": campaign.parameter,
        "logical_capacity": campaign.logical_capacity,
        "results": rows,
        "summary": {
            "candidate_rejected_before_persistence": sum(r["classification"] == "candidate rejected before persistence" for r in rows),
            "candidate_accepted_and_correctly_persisted": sum(r["classification"] == "candidate accepted and correctly persisted" for r in rows),
            "candidate_accepted_but_persisted_state_is_smaller": sum(r["classification"] == "candidate accepted but persisted state is smaller" for r in rows),
            "follow_up_rollback_accepted": sum(r.get("follow_up_classification") == "follow-up rollback accepted" for r in rows),
            "follow_up_rollback_rejected": sum(r.get("follow_up_classification") == "follow-up rollback rejected" for r in rows),
            "infrastructure_setup_failure": sum(r["classification"] == "infrastructure/setup failure" for r in rows),
        },
        "verdict": verdict,
    }
