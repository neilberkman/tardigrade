"""Report the persistent hook marker and the firmware's volatile observation."""

HOOK_VALUE = 0x484F4F4B4150504C
HOOK_SEEN = 0x484F4F4B


def collect_state(bus=None, monitor=None, context=None):
    context = context or {}
    hook_low = int(bus.ReadDoubleWord(0x10100110))
    hook_high = int(bus.ReadDoubleWord(0x10100114))
    hook_word = hook_low | (hook_high << 32)
    return {
        "target": "phase2_mram_parity",
        "stage": context.get("stage"),
        "cycle": context.get("cycle"),
        "phase2_cut": context.get("phase2_cut"),
        "hook_persisted": hook_word == HOOK_VALUE,
        "hook_seen": int(bus.ReadDoubleWord(0x20000104)) == HOOK_SEEN,
    }
