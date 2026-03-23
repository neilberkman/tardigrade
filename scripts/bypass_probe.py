"""Verification bypass probe: offline classification of defense-in-depth layers.

Extracts and re-classifies verification probe signals from sweep results,
providing a structured per-layer breakdown that enriches the audit report
with ``defense_in_depth_layers``.

The RESC hooks capture per-function return values during instruction-skip
sweeps.  This module consumes that captured data (from ``signals``) and
produces:

- Per-layer status: ``held``, ``breached``, ``not_reached``
- Per-fault-point classification: ``all_layers_breached``,
  ``first_layer_breached``, ``defense_in_depth_held``, ``cpu_crash``, etc.
- Aggregate ``defense_in_depth_layers`` summary for the report JSON.

Usage::

    from bypass_probe import classify_probe_result, build_defense_in_depth_layers

"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Per-result classification
# ---------------------------------------------------------------------------

# Classification constants — match the RESC classifications plus the
# additional offline categories.
CLASSIFICATION_ALL_LAYERS_BREACHED = "all_layers_breached"
CLASSIFICATION_SINGLE_LAYER_BREACHED = "single_layer_breached"
CLASSIFICATION_FIRST_LAYER_BREACHED_SECOND_CAUGHT = "first_layer_breached_second_caught"
CLASSIFICATION_FIRST_LAYER_HELD = "first_layer_held"
CLASSIFICATION_FIRST_LAYER_NOT_REACHED = "first_layer_not_reached"
CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_HELD = "first_layer_breached_following_held"
CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_NOT_REACHED = "first_layer_breached_following_not_reached"
CLASSIFICATION_PARTIAL_MULTILAYER_BYPASS = "partial_multilayer_bypass"
CLASSIFICATION_NOT_REACHED = "not_reached"
CLASSIFICATION_NO_PROBES = "no_probes"

# Defense-in-depth verdicts
DEFENSE_HELD = "held"
DEFENSE_DEFEATED = "defeated"
DEFENSE_PARTIAL = "partial"
DEFENSE_UNKNOWN = "unknown"
DEFENSE_NOT_APPLICABLE = "not_applicable"

# Per-layer status
LAYER_HELD = "held"
LAYER_BREACHED = "breached"
LAYER_NOT_REACHED = "not_reached"


def _extract_probe_data(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract verification probe data from a sweep result's signals."""
    signals = result.get("signals") or {}
    if not isinstance(signals, dict):
        return None
    probes = signals.get("verification_probes")
    if not isinstance(probes, dict) or not probes:
        return None
    return probes


def classify_layer_status(probe: Dict[str, Any]) -> str:
    """Classify a single verification layer as held/breached/not_reached.

    A layer is ``breached`` if its first invocation returned the configured
    success value (``first_bypassed`` is True) or if any invocation was
    bypassed (``bypassed`` is True).  A layer that was reached but neither
    ``first_bypassed`` nor ``bypassed`` is True is ``held``.  A layer
    never executed is ``not_reached``.
    """
    if not probe.get("reached"):
        return LAYER_NOT_REACHED
    if probe.get("first_bypassed") or probe.get("bypassed"):
        return LAYER_BREACHED
    return LAYER_HELD


def classify_probe_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a single fault-point result based on verification probe data.

    Returns a dict with:
    - ``classification``: one of the CLASSIFICATION_* constants
    - ``defense_in_depth``: aggregate defense verdict
    - ``layers``: ordered list of ``{label, symbol, status}`` dicts
    - ``bypassed_labels``: labels of breached layers
    - ``full_bypass``: True if all layers were breached
    """
    probes = _extract_probe_data(result)
    if probes is None:
        return {
            "classification": CLASSIFICATION_NO_PROBES,
            "defense_in_depth": DEFENSE_NOT_APPLICABLE,
            "layers": [],
            "bypassed_labels": [],
            "full_bypass": False,
        }

    # Preserve insertion order (Python 3.7+).
    layers: List[Dict[str, Any]] = []
    bypassed_labels: List[str] = []
    for label, probe in probes.items():
        if not isinstance(probe, dict):
            continue
        status = classify_layer_status(probe)
        layers.append({
            "label": label,
            "symbol": probe.get("symbol", label),
            "status": status,
            "return_value": probe.get("first_return_value") or probe.get("return_value"),
            "call_count": int(probe.get("call_count") or 0),
        })
        if status == LAYER_BREACHED:
            bypassed_labels.append(label)

    if not layers:
        return {
            "classification": CLASSIFICATION_NO_PROBES,
            "defense_in_depth": DEFENSE_NOT_APPLICABLE,
            "layers": [],
            "bypassed_labels": [],
            "full_bypass": False,
        }

    # Use the same logic as the RESC capture_verification_probe_summary.
    # Re-read from signals first; if present, use the RESC classification
    # directly since it has the authoritative per-call ordering.
    signals = result.get("signals") or {}
    resc_classification = str(
        signals.get("verification_probe_classification") or ""
    ).strip()
    resc_defense = str(
        signals.get("verification_defense_in_depth") or ""
    ).strip()

    if resc_classification:
        classification = resc_classification
        defense = resc_defense or DEFENSE_UNKNOWN
    else:
        # Offline fallback classification from layer statuses.
        ordered_probes = [
            probes[label]
            for label in probes
            if isinstance(probes.get(label), dict)
        ]
        first = ordered_probes[0] if ordered_probes else None
        later = ordered_probes[1:] if len(ordered_probes) > 1 else []

        if first is None or not any(l["status"] != LAYER_NOT_REACHED for l in layers):
            classification = CLASSIFICATION_NOT_REACHED
            defense = DEFENSE_UNKNOWN
        elif not first.get("reached"):
            classification = CLASSIFICATION_FIRST_LAYER_NOT_REACHED
            defense = DEFENSE_UNKNOWN
        elif not (first.get("first_bypassed") or first.get("bypassed")):
            classification = CLASSIFICATION_FIRST_LAYER_HELD
            defense = DEFENSE_HELD
        elif not later:
            classification = CLASSIFICATION_SINGLE_LAYER_BREACHED
            defense = DEFENSE_DEFEATED
        elif any(item.get("reached") and not item.get("first_bypassed") for item in later):
            classification = CLASSIFICATION_FIRST_LAYER_BREACHED_SECOND_CAUGHT
            defense = DEFENSE_HELD
        elif later and all(item.get("reached") and item.get("first_bypassed") for item in later):
            classification = CLASSIFICATION_ALL_LAYERS_BREACHED
            defense = DEFENSE_DEFEATED
        elif any(item.get("first_bypassed") for item in later):
            classification = CLASSIFICATION_PARTIAL_MULTILAYER_BYPASS
            defense = DEFENSE_PARTIAL
        elif any(item.get("reached") for item in later):
            classification = CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_HELD
            defense = DEFENSE_HELD
        else:
            classification = CLASSIFICATION_FIRST_LAYER_BREACHED_FOLLOWING_NOT_REACHED
            defense = DEFENSE_UNKNOWN

    full_bypass = classification in (
        CLASSIFICATION_SINGLE_LAYER_BREACHED,
        CLASSIFICATION_ALL_LAYERS_BREACHED,
    )

    return {
        "classification": classification,
        "defense_in_depth": defense,
        "layers": layers,
        "bypassed_labels": bypassed_labels,
        "full_bypass": full_bypass,
    }


# ---------------------------------------------------------------------------
# Aggregate: build defense_in_depth_layers summary for the report
# ---------------------------------------------------------------------------

def build_defense_in_depth_layers(
    results: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Build a ``defense_in_depth_layers`` summary from sweep results.

    Returns None if no results contain verification probe data.

    The returned dict contains:
    - ``layers``: ordered list of per-layer summaries with counts
    - ``aggregate_classification``: overall defense-in-depth verdict
    - ``points_by_classification``: count of fault points per classification
    - ``full_bypass_count``: number of fault points with all layers breached
    """
    layer_stats: Dict[str, Dict[str, int]] = {}  # label -> {held, breached, not_reached}
    layer_symbols: Dict[str, str] = {}
    layer_order: List[str] = []
    classification_counts: Dict[str, int] = {}
    full_bypass_count = 0
    total_probed = 0

    for result in results:
        if result.get("is_control", False):
            continue
        if not result.get("fault_injected", False):
            continue

        probe_result = classify_probe_result(result)
        if probe_result["classification"] == CLASSIFICATION_NO_PROBES:
            continue

        total_probed += 1
        classification = probe_result["classification"]
        classification_counts[classification] = (
            classification_counts.get(classification, 0) + 1
        )
        if probe_result["full_bypass"]:
            full_bypass_count += 1

        for layer in probe_result["layers"]:
            label = layer["label"]
            if label not in layer_stats:
                layer_stats[label] = {"held": 0, "breached": 0, "not_reached": 0}
                layer_symbols[label] = layer.get("symbol", label)
                layer_order.append(label)
            layer_stats[label][layer["status"]] = (
                layer_stats[label].get(layer["status"], 0) + 1
            )

    if not total_probed:
        return None

    # Build per-layer summaries.
    layer_summaries: List[Dict[str, Any]] = []
    for label in layer_order:
        stats = layer_stats[label]
        total_reached = stats.get("held", 0) + stats.get("breached", 0)
        layer_summaries.append({
            "label": label,
            "symbol": layer_symbols.get(label, label),
            "held": stats.get("held", 0),
            "breached": stats.get("breached", 0),
            "not_reached": stats.get("not_reached", 0),
            "total_reached": total_reached,
            "breach_rate": (
                float(stats.get("breached", 0)) / float(total_reached)
                if total_reached > 0
                else 0.0
            ),
        })

    if full_bypass_count == total_probed:
        aggregate = DEFENSE_DEFEATED
    elif full_bypass_count > 0:
        aggregate = DEFENSE_PARTIAL
    else:
        defense_counts: Dict[str, int] = {}
        for result in results:
            if result.get("is_control", False) or not result.get("fault_injected", False):
                continue
            probe_result = classify_probe_result(result)
            if probe_result["classification"] == CLASSIFICATION_NO_PROBES:
                continue
            defense = str(probe_result.get("defense_in_depth") or DEFENSE_UNKNOWN)
            defense_counts[defense] = defense_counts.get(defense, 0) + 1
        if defense_counts.get(DEFENSE_PARTIAL, 0) > 0:
            aggregate = DEFENSE_PARTIAL
        elif defense_counts.get(DEFENSE_UNKNOWN, 0) > 0:
            aggregate = DEFENSE_UNKNOWN
        else:
            aggregate = DEFENSE_HELD

    return {
        "layers": layer_summaries,
        "aggregate_classification": aggregate,
        "points_by_classification": classification_counts,
        "total_probed_points": total_probed,
        "full_bypass_count": full_bypass_count,
        "full_bypass_rate": (
            float(full_bypass_count) / float(total_probed)
            if total_probed > 0
            else 0.0
        ),
    }
