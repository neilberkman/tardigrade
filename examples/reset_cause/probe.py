# SPDX-License-Identifier: Apache-2.0
"""Collect firmware-observed reset cause, retained RAM, and backup register."""


def collect_state(bus, monitor, context):
    return {
        "cause": "0x{:08x}".format(int(bus.ReadDoubleWord(0x20000100)) & 0xFFFFFFFF),
        "retained": "0x{:08x}".format(int(bus.ReadDoubleWord(0x20000104)) & 0xFFFFFFFF),
        "backup": "0x{:08x}".format(int(bus.ReadDoubleWord(0x20000108)) & 0xFFFFFFFF),
        "marker": "0x{:08x}".format(int(bus.ReadDoubleWord(0x2000010c)) & 0xFFFFFFFF),
    }
