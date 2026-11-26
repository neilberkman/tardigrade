"""Persist a marker between the final boot and its follow-up boot."""

HOOK_ADDRESS = 0x10100110
HOOK_VALUE = 0x484F4F4B4150504C

bus.WriteQuadWord(HOOK_ADDRESS, HOOK_VALUE)
