#!/usr/bin/env python3
"""Trailer state-table fuzzer for MCUboot-style swap bootloaders.

Models MCUboot's trailer state machine, generates scenarios covering all
meaningful state combinations (including known bug classes), provides an
oracle predicting correct behavior, and serializes to binary for Renode.

Usage as library::

    from mcuboot_state_fuzzer import generate_scenarios, predict_boot
    for scenario in generate_scenarios(count=100, seed=42):
        result = predict_boot(scenario)
        blob = scenario.slot0_trailer.to_bytes()

Usage as CLI::

    python3 scripts/mcuboot_state_fuzzer.py --count 100 --seed 42 --output /tmp/states.json
"""
from __future__ import annotations

import argparse
import enum
import json
import random
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BOOT_MAGIC = bytes([0x77, 0xC2, 0x95, 0xF3, 0x60, 0xD2, 0xEF, 0x7F])
ERASED_BYTE = 0xFF
DEFAULT_SECTOR_SIZE = 4096


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Magic(enum.Enum):
    GOOD = "good"
    UNSET = "unset"       # All 0xFF (erased flash).
    BAD = "bad"           # All 0x00 (corrupt).
    PARTIAL = "partial"   # Interrupted write: first 4 bytes valid, rest 0xFF.


class SwapType(enum.Enum):
    NONE = 0xFF; TEST = 0x02; PERM = 0x03; REVERT = 0x04  # noqa: E702


class FlagState(enum.Enum):
    UNSET = 0xFF; SET = 0x01; BAD = 0x00  # noqa: E702


class BootAction(enum.Enum):
    BOOT_SLOT0 = "boot_slot0"
    SWAP_AND_BOOT = "swap_and_boot"
    REVERT = "revert_and_boot_slot0"
    RESUME_SWAP = "resume_swap"
    RESUME_REVERT = "resume_revert"
    STUCK = "stuck"


class BugClass(enum.Enum):
    PARTIAL_MAGIC = "partial_magic_write"
    RESUME_2109 = "copy_done_set_swap_incomplete"
    STUCK_REVERT_2199 = "both_slots_revert"
    NOOP_UPGRADE = "test_with_image_ok_set"
    SWAP_SIZE_ZERO = "swap_size_zero"
    MOVE_PARTIAL = "swap_move_partial_status"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

def _magic_bytes(m: Magic) -> bytes:
    if m == Magic.GOOD: return BOOT_MAGIC
    if m == Magic.UNSET: return b'\xFF' * 8
    if m == Magic.BAD: return b'\x00' * 8
    return BOOT_MAGIC[:4] + b'\xFF' * 4  # PARTIAL


def _sectors(n: int, *, done: int = 0, all_done: bool = False) -> List[int]:
    if all_done: return [0x00] * n
    return [0x00] * done + [ERASED_BYTE] * (n - done)


@dataclass
class TrailerState:
    """Full trailer state for one flash slot."""
    magic: Magic = Magic.UNSET
    image_ok: FlagState = FlagState.UNSET
    copy_done: FlagState = FlagState.UNSET
    swap_type: SwapType = SwapType.NONE
    swap_size: int = 0xFFFFFFFF
    sector_status: List[int] = field(default_factory=list)
    num_sectors: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to binary trailer blob for flash injection."""
        parts = []
        for s in self.sector_status:
            parts.append(struct.pack('BBB', ERASED_BYTE, s & 0xFF, ERASED_BYTE))
        parts.append(struct.pack('<I', self.swap_size & 0xFFFFFFFF))
        parts.append(struct.pack('B', self.image_ok.value))
        parts.append(struct.pack('B', self.copy_done.value))
        parts.append(b'\xFF')
        parts.append(struct.pack('B', self.swap_type.value))
        parts.append(_magic_bytes(self.magic))
        return b''.join(parts)


@dataclass
class MCUbootScenario:
    """Complete state of both slots' trailers plus slot validity."""
    slot0_trailer: TrailerState
    slot1_trailer: TrailerState
    slot0_valid: bool = True
    slot1_valid: bool = True
    description: str = ""
    bug_class: Optional[BugClass] = None


@dataclass
class BootPrediction:
    """Oracle prediction for what MCUboot should do given a scenario."""
    action: BootAction
    boots: bool
    boot_slot: Optional[int]
    triggers_swap: bool
    reason: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _swap_started(t: TrailerState) -> bool:
    return any(s != ERASED_BYTE for s in t.sector_status)

def _swap_incomplete(t: TrailerState) -> bool:
    return bool(t.sector_status) and any(s != 0x00 for s in t.sector_status)

def _ts(n: int, **kw) -> TrailerState:
    """Shorthand trailer constructor with sensible defaults."""
    kw.setdefault('num_sectors', n)
    if 'sector_status' not in kw:
        kw['sector_status'] = [ERASED_BYTE] * n
    return TrailerState(**kw)

def _boot0(scenario, reason, swap=False):
    return BootPrediction(BootAction.BOOT_SLOT0 if not swap else BootAction.REVERT,
                          scenario.slot0_valid, 0 if scenario.slot0_valid else None,
                          swap, reason)

# ---------------------------------------------------------------------------
# Oracle: predict_boot
# ---------------------------------------------------------------------------

def predict_boot(scenario: MCUbootScenario) -> BootPrediction:
    """Predict MCUboot's behavior for the given trailer state.

    Models the swap algorithm from boot/bootutil/src/loader.c:
    1. slot 0 magic GOOD + swap_type REVERT -> revert path
    2. slot 1 magic GOOD + swap_type TEST/PERM -> swap path
    3. Otherwise -> boot slot 0
    """
    s0, s1 = scenario.slot0_trailer, scenario.slot1_trailer

    # --- REVERT path ---
    if s0.magic == Magic.GOOD and s0.swap_type == SwapType.REVERT:
        if s1.magic == Magic.GOOD and s1.swap_type == SwapType.REVERT:
            return BootPrediction(BootAction.STUCK, False, None, False,
                "both slots swap_type=REVERT (bug #2199); brick or infinite-loop")
        if _swap_started(s0) and _swap_incomplete(s0):
            return BootPrediction(BootAction.RESUME_REVERT,
                scenario.slot0_valid, 0 if scenario.slot0_valid else None, True,
                "resuming interrupted revert")
        return _boot0(scenario, "revert requested; swap back and boot slot 0", swap=True)

    # --- TEST / PERM swap path ---
    if s1.magic == Magic.GOOD and s1.swap_type in (SwapType.TEST, SwapType.PERM):
        if s0.copy_done == FlagState.SET:
            # Swap already completed on previous boot.
            if s0.image_ok == FlagState.SET:
                return _boot0(scenario, "swap done, image_ok confirmed; normal boot")
            if s1.swap_type == SwapType.PERM:
                return _boot0(scenario, "swap done (PERM); auto-confirmed")
            # TEST + not confirmed -> revert.
            return _boot0(scenario, "swap done but image_ok unset (TEST); revert", swap=True)

        # copy_done not set: swap not yet completed.
        if _swap_started(s0) or _swap_started(s1):
            return BootPrediction(BootAction.RESUME_SWAP,
                scenario.slot0_valid or scenario.slot1_valid,
                0 if scenario.slot0_valid else (1 if scenario.slot1_valid else None),
                True, "swap in progress; resuming")
        # Fresh swap.
        return BootPrediction(BootAction.SWAP_AND_BOOT,
            scenario.slot1_valid, 0 if scenario.slot1_valid else None, True,
            "slot 1 magic+swap_type={}; starting swap".format(s1.swap_type.name))

    # --- Partial magic ---
    if s1.magic == Magic.PARTIAL:
        return _boot0(scenario, "slot 1 magic partial (interrupted); ignored, boot slot 0")
    if s0.magic == Magic.PARTIAL:
        return _boot0(scenario, "slot 0 magic partial; no swap, boot slot 0")

    # --- Default: boot slot 0 ---
    return _boot0(scenario, "no swap trigger; default boot slot 0")


# ---------------------------------------------------------------------------
# Edge case scenarios
# ---------------------------------------------------------------------------

def _edge_cases(ns: int = 8) -> List[MCUbootScenario]:
    sz = ns * DEFAULT_SECTOR_SIZE
    E, G = Magic.UNSET, Magic.GOOD
    U, S, B = FlagState.UNSET, FlagState.SET, FlagState.BAD
    erased = lambda: _ts(ns)
    confirmed = lambda: _ts(ns, magic=G, image_ok=S)

    def sc(s0, s1, desc, **kw):
        return MCUbootScenario(slot0_trailer=s0, slot1_trailer=s1, description=desc, **kw)

    return [
        sc(confirmed(), erased(), "baseline: confirmed slot 0, slot 1 erased"),
        sc(confirmed(), _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=sz),
           "TEST upgrade pending; swap not started"),
        sc(confirmed(), _ts(ns, magic=G, swap_type=SwapType.PERM, swap_size=sz),
           "PERM upgrade pending; swap not started"),
        sc(_ts(ns, magic=G, image_ok=S, copy_done=S, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           "swap complete, image_ok confirmed"),
        sc(_ts(ns, magic=G, copy_done=S, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           "swap complete, image_ok NOT set; will revert"),
        sc(_ts(ns, magic=G, swap_type=SwapType.REVERT, swap_size=sz,
               sector_status=_sectors(ns, done=ns//2)),
           erased(), "revert in progress ({}/{} sectors)".format(ns//2, ns)),
        # Bug classes:
        sc(confirmed(), _ts(ns, magic=Magic.PARTIAL, swap_type=SwapType.TEST, swap_size=sz),
           "partial magic in slot 1; swap must NOT trigger",
           bug_class=BugClass.PARTIAL_MAGIC),
        sc(_ts(ns, magic=G, copy_done=S, swap_size=sz,
               sector_status=_sectors(ns, done=ns//2)),
           _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=sz,
               sector_status=_sectors(ns, done=ns//2)),
           "copy_done SET but {}/{} sectors done (bug #2109)".format(ns//2, ns),
           slot0_valid=False, bug_class=BugClass.RESUME_2109),
        sc(_ts(ns, magic=G, swap_type=SwapType.REVERT, swap_size=sz),
           _ts(ns, magic=G, swap_type=SwapType.REVERT, swap_size=sz),
           "both slots REVERT (bug #2199); brick/loop",
           bug_class=BugClass.STUCK_REVERT_2199),
        sc(confirmed(), _ts(ns, magic=G, image_ok=S, swap_type=SwapType.TEST, swap_size=sz),
           "TEST with image_ok pre-set (no-op upgrade risk)",
           bug_class=BugClass.NOOP_UPGRADE),
        sc(confirmed(), _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=0),
           "swap_size=0; potential divide-by-zero",
           bug_class=BugClass.SWAP_SIZE_ZERO),
        sc(_ts(ns, magic=G, swap_size=sz, sector_status=_sectors(ns, done=1)),
           _ts(ns, magic=G, swap_type=SwapType.TEST, swap_size=sz,
               sector_status=_sectors(ns, done=1)),
           "swap interrupted after 1/{} sectors".format(ns),
           bug_class=BugClass.MOVE_PARTIAL),
        sc(erased(), erased(), "factory-fresh: both erased"),
        sc(_ts(ns, magic=Magic.BAD, image_ok=B, copy_done=B, swap_size=0,
               sector_status=[0]*ns), erased(),
           "slot 0 all-zero (corrupt); fall through to boot"),
        sc(_ts(ns, magic=G, copy_done=S, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           _ts(ns, magic=G, swap_type=SwapType.PERM, swap_size=sz,
               sector_status=_sectors(ns, all_done=True)),
           "PERM swap complete; image_ok irrelevant"),
        sc(confirmed(), _ts(ns, magic=G, swap_type=SwapType.PERM, swap_size=sz),
           "PERM pending but slot 1 image invalid", slot1_valid=False),
    ]


# ---------------------------------------------------------------------------
# Random + combined generation
# ---------------------------------------------------------------------------

def _random_trailer(rng: random.Random, ns: int) -> TrailerState:
    return TrailerState(
        magic=rng.choice(list(Magic)),
        image_ok=rng.choice(list(FlagState)),
        copy_done=rng.choice(list(FlagState)),
        swap_type=rng.choice(list(SwapType)),
        swap_size=rng.choice([0xFFFFFFFF, 0, ns * DEFAULT_SECTOR_SIZE,
                              rng.randint(0, ns * DEFAULT_SECTOR_SIZE)]),
        sector_status=_sectors(ns, done=rng.randint(0, ns)),
        num_sectors=ns,
    )


def generate_scenarios(count: int = 100, seed: Optional[int] = None,
                       num_sectors: int = 8) -> List[MCUbootScenario]:
    """Generate targeted edge cases + random scenarios."""
    rng = random.Random(seed)
    scenarios = _edge_cases(num_sectors)
    for i in range(max(0, count - len(scenarios))):
        scenarios.append(MCUbootScenario(
            slot0_trailer=_random_trailer(rng, num_sectors),
            slot1_trailer=_random_trailer(rng, num_sectors),
            slot0_valid=rng.random() > 0.25,
            slot1_valid=rng.random() > 0.5,
            description="random #{}".format(i),
        ))
    return scenarios[:count]


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

def _trailer_dict(t: TrailerState) -> Dict[str, Any]:
    return {
        "magic": t.magic.value, "image_ok": t.image_ok.name,
        "copy_done": t.copy_done.name, "swap_type": t.swap_type.name,
        "swap_size": t.swap_size,
        "swap_size_hex": "0x{:08X}".format(t.swap_size & 0xFFFFFFFF),
        "sectors_complete": sum(1 for s in t.sector_status if s == 0x00),
        "sectors_total": len(t.sector_status),
    }

def _scenario_dict(s: MCUbootScenario) -> Dict[str, Any]:
    p = predict_boot(s)
    return {
        "description": s.description,
        "bug_class": s.bug_class.value if s.bug_class else None,
        "slot0_trailer": _trailer_dict(s.slot0_trailer),
        "slot1_trailer": _trailer_dict(s.slot1_trailer),
        "slot0_valid": s.slot0_valid, "slot1_valid": s.slot1_valid,
        "prediction": {"action": p.action.value, "boots": p.boots,
                        "boot_slot": p.boot_slot, "triggers_swap": p.triggers_swap,
                        "reason": p.reason},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="MCUboot trailer state-table fuzzer.")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--sectors", type=int, default=8)
    ap.add_argument("--output", type=str, default=None)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--dump-blobs", type=str, default=None, metavar="DIR")
    args = ap.parse_args()

    scenarios = generate_scenarios(args.count, args.seed, args.sectors)
    payload = [_scenario_dict(s) for s in scenarios]
    text = json.dumps(payload, indent=2, sort_keys=True)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(text + '\n')
        print("Wrote {} scenarios to {}".format(len(scenarios), args.output),
              file=sys.stderr)
    else:
        print(text)

    if args.dump_blobs:
        import os
        os.makedirs(args.dump_blobs, exist_ok=True)
        for i, s in enumerate(scenarios):
            for slot, trailer in [("slot0", s.slot0_trailer), ("slot1", s.slot1_trailer)]:
                p = os.path.join(args.dump_blobs, "{:04d}_{}.bin".format(i, slot))
                with open(p, 'wb') as f:
                    f.write(trailer.to_bytes())
        print("Wrote {} blob pairs to {}".format(len(scenarios), args.dump_blobs),
              file=sys.stderr)

    if args.summary:
        preds = [predict_boot(s) for s in scenarios]
        n = len(scenarios)
        boots = sum(1 for p in preds if p.boots)
        stuck = sum(1 for p in preds if p.action == BootAction.STUCK)
        swaps = sum(1 for p in preds if p.triggers_swap)
        s0 = sum(1 for p in preds if p.boot_slot == 0)
        s1 = sum(1 for p in preds if p.boot_slot == 1)
        bugs: Dict[str, int] = {}
        for s in scenarios:
            if s.bug_class:
                bugs[s.bug_class.value] = bugs.get(s.bug_class.value, 0) + 1
        pct = lambda v: "{:.1f}%".format(100.0 * v / n) if n else "0%"
        print("\nSummary ({} scenarios):".format(n), file=sys.stderr)
        print("  Boots: {} ({})".format(boots, pct(boots)), file=sys.stderr)
        print("    Slot 0: {}  Slot 1: {}".format(s0, s1), file=sys.stderr)
        print("  Stuck: {} ({})".format(stuck, pct(stuck)), file=sys.stderr)
        print("  Triggers swap: {} ({})".format(swaps, pct(swaps)), file=sys.stderr)
        if bugs:
            print("  Bug classes: {}".format(
                ", ".join("{}: {}".format(k, v) for k, v in sorted(bugs.items()))),
                file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
