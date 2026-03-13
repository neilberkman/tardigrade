"""Simulate application confirming the nxboot primary image.

nxboot uses a confirm flag at a fixed address. Writing 1 tells the
bootloader the current primary image has been validated by the
application, preventing revert on next boot.
"""

CONFIRM_FLAG_ADDR = 0x1006B000
CONFIRMED = 1

if previous_record.get("boot_slot") == success_vtor_slot:
    bus.WriteDoubleWord(CONFIRM_FLAG_ADDR, CONFIRMED)
