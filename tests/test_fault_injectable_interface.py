#!/usr/bin/env python3
"""Guardrail: every NVM/flash peripheral the audit can bind must implement the
full ITardigradeFaultInjectable interface.

The runtime fault sweep binds to a flash/NVM peripheral and drives it through
the fault-injection interface.  A backend that omits a member (e.g.
``DriverErrorFired``) aborts the campaign with a missing-member error *after*
the fault points have already run, wasting the whole sweep.  Declaring the C#
interface turns that into a load-time compile error; this test is the CI-time
mirror of that guard so a regression is caught without launching Renode.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PERIPHERALS = ROOT / "peripherals"
INTERFACE_FILE = PERIPHERALS / "ITardigradeFaultInjectable.cs"

# Peripherals that resolve_backend() in run_runtime_fault_sweep.py can hand to
# the fault engine as ``backend['data']`` (fast/mram paths) or whose members the
# engine touches directly.  Each MUST implement the interface so no binding path
# can abort mid-campaign on a missing member.
FAULT_BACKENDS = (
    "NRF52NVMC.cs",
    "STM32F4FastFlash.cs",
    "STM32H7FastFlash.cs",
    "STM32F4FlashController.cs",
    "STM32H7FlashController.cs",
    "GenericNvmController.cs",
    "NVMemoryController.cs",
)


def _interface_members(source: str) -> tuple[list[str], list[str]]:
    """Return (property_names, method_names) declared in the interface body."""

    body = source[source.index("{", source.index("interface")) :]
    properties: list[str] = []
    methods: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("//") or line in ("{", "}"):
            continue
        # Property: "<type> Name { get; ... }"
        prop = re.match(r"^[\w\[\]<>]+(?:\s*\[\])?\s+(\w+)\s*\{", line)
        if prop and "{" in line and "(" not in line.split("{", 1)[0]:
            properties.append(prop.group(1))
            continue
        # Method: "<ret> Name(...);"
        method = re.match(r"^[\w\[\]<>]+\s+(\w+)\s*\(", line)
        if method:
            methods.append(method.group(1))
    return properties, methods


class TestFaultInjectableInterface(unittest.TestCase):
    def setUp(self) -> None:
        self.interface_source = INTERFACE_FILE.read_text(encoding="utf-8")
        self.properties, self.methods = _interface_members(self.interface_source)
        # Sanity: the parser found the interface surface we expect.
        self.assertIn("DriverErrorFired", self.properties)
        self.assertIn("InvalidateShadow", self.methods)
        self.assertGreaterEqual(len(self.properties), 30)

    def test_each_backend_declares_the_interface(self) -> None:
        for name in FAULT_BACKENDS:
            with self.subTest(peripheral=name):
                source = (PERIPHERALS / name).read_text(encoding="utf-8")
                self.assertRegex(
                    source,
                    r"class\s+\w+\s*:[^\{]*\bITardigradeFaultInjectable\b",
                    "%s must declare ': ITardigradeFaultInjectable' so a "
                    "missing member fails at load, not mid-campaign." % name,
                )

    def test_each_backend_defines_every_member(self) -> None:
        for name in FAULT_BACKENDS:
            source = (PERIPHERALS / name).read_text(encoding="utf-8")
            for member in self.properties:
                with self.subTest(peripheral=name, member=member):
                    self.assertRegex(
                        source,
                        r"\b%s\b" % re.escape(member),
                        "%s is missing interface property %s" % (name, member),
                    )
            for member in self.methods:
                with self.subTest(peripheral=name, member=member):
                    self.assertRegex(
                        source,
                        r"\b%s\s*\(" % re.escape(member),
                        "%s is missing interface method %s()" % (name, member),
                    )


if __name__ == "__main__":
    unittest.main()
