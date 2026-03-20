// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// ARM SP804 wrapper with PrimeCell identification registers. Barebox probes
// the AMBA peripheral ID bytes at 0xFE0-0xFFC and panics early if they read
// back as zero.

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Miscellaneous;
using Antmicro.Renode.Peripherals.Timers;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    public sealed class ARM_SP804PrimeCellTimer : ARM_SP804_Timer
    {
        public ARM_SP804PrimeCellTimer(IMachine machine, ulong frequency = 1000000) : base(machine, frequency)
        {
            idHelper = new PrimeCellIDHelper((int)Size, new byte[] { 0x04, 0x18, 0x14, 0x00, 0x0D, 0xF0, 0x05, 0xB1 }, this);
        }

        public override uint ReadDoubleWord(long offset)
        {
            if(offset >= Size - 8 * 4)
            {
                return idHelper.Read(offset);
            }
            return base.ReadDoubleWord(offset);
        }

        private readonly PrimeCellIDHelper idHelper;
    }
}
