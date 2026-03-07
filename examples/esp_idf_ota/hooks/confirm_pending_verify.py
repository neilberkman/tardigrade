"""Simulate an ESP-IDF app confirming a PENDING_VERIFY image.

This hook runs between follow-up boots. ESP-IDF stores OTA state in two
redundant 4KB sectors; the CRC covers ota_seq only, so changing ota_state from
PENDING_VERIFY to VALID does not require recomputing the CRC.
"""

PENDING_VERIFY = 0x00000001
VALID = 0x00000002
STATE_OFFSET = 0x18
OTADATA_ENTRY_BASES = (0x000F8000, 0x000F9000)


if previous_record.get("boot_slot") == success_vtor_slot:
    for base in OTADATA_ENTRY_BASES:
        current = int(bus.ReadDoubleWord(base + STATE_OFFSET))
        if current == PENDING_VERIFY:
            bus.WriteDoubleWord(base + STATE_OFFSET, VALID)
