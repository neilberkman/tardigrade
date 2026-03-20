// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Minimal PL061 GPIO model for QEMU virt bringup. This is intentionally small:
// enough for PrimeCell discovery and basic direction/data register accesses.

using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Miscellaneous;
using Antmicro.Renode.Core;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public sealed class PL061Stub : IDoubleWordPeripheral, IKnownSize
    {
        public PL061Stub()
        {
            idHelper = new PrimeCellIDHelper((int)Size, new byte[] { 0x61, 0x10, 0x04, 0x00, 0x0D, 0xF0, 0x05, 0xB1 }, this);
        }

        public long Size => 0x1000;
        public GPIO IRQ { get; } = new GPIO();

        public uint ReadDoubleWord(long offset)
        {
            if(offset >= Size - 8 * 4)
            {
                return idHelper.Read(offset);
            }

            switch(offset)
            {
                case 0x400:
                    return direction;
                case 0x51C:
                    return 0x1;
                default:
                    if(offset >= 0x0 && offset <= 0x3FC)
                    {
                        return data;
                    }
                    return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case 0x400:
                    direction = value & 0xFF;
                    break;
                default:
                    if(offset >= 0x0 && offset <= 0x3FC)
                    {
                        var mask = (uint)((offset >> 2) & 0xFF);
                        if(mask == 0)
                        {
                            data = value & 0xFF;
                        }
                        else
                        {
                            data = (data & ~mask) | (value & mask);
                        }
                    }
                    break;
            }
        }

        public void Reset()
        {
            data = 0;
            direction = 0;
        }

        private uint data;
        private uint direction;
        private readonly PrimeCellIDHelper idHelper;
    }
}
