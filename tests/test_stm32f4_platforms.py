from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Stm32f4PlatformTests(unittest.TestCase):
    def test_stm32f4_platforms_expose_2mb_flash(self) -> None:
        for relpath in ("platforms/stm32f4.repl", "platforms/stm32f4_fast.repl"):
            with self.subTest(platform=relpath):
                text = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn("size: 0x200000", text)
                self.assertIn("FlashSize: 0x200000", text)
                self.assertIn('Tag <0x00000000 0x200000> "FLASH_LO"', text)
                self.assertIn('Tag <0x08000000 0x200000> "FLASH_HI"', text)

    def test_stm32f4_platforms_stub_hot_boot_mmio_ranges(self) -> None:
        for relpath in ("platforms/stm32f4.repl", "platforms/stm32f4_fast.repl"):
            with self.subTest(platform=relpath):
                text = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn("uart6: Miscellaneous.STM32DummyUSART @ sysbus 0x40011400", text)
                self.assertIn("gpioD: Memory.MappedMemory @ sysbus 0x40020C00", text)
                self.assertIn("pwr: Memory.MappedMemory @ sysbus 0x40007000", text)
                self.assertIn("dbgmcu: Memory.MappedMemory @ sysbus 0xE0042000", text)
                self.assertIn('Tag <0x40007000 0x400> "PWR"', text)
                self.assertIn('Tag <0x40020000 0x2400> "GPIO"', text)
                self.assertIn('Tag <0xE0042000 0x400> "DBGMCU"', text)

    def test_stm32f4_peripherals_model_second_bank_sector_geometry(self) -> None:
        for relpath in (
            "peripherals/STM32F4FlashController.cs",
            "peripherals/STM32F4FastFlash.cs",
        ):
            with self.subTest(source=relpath):
                text = (ROOT / relpath).read_text(encoding="utf-8")
                self.assertIn("(0x100000L, 0x04000)", text)
                self.assertIn("(0x104000L, 0x04000)", text)
                self.assertIn("(0x108000L, 0x04000)", text)
                self.assertIn("(0x10C000L, 0x04000)", text)
                self.assertIn("(0x110000L, 0x10000)", text)
                self.assertIn("(0x120000L, 0x20000)", text)
                self.assertIn("(0x1E0000L, 0x20000)", text)
