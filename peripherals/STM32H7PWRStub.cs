// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Minimal STM32H7 PWR block for nxboot/NuttX boot flows.
//
// The public H7 platforms in Renode tag this region but do not model it.
// Boot code polls a small subset of these registers very heavily, so leaving
// the block unmapped forces every access down the expensive "missing
// peripheral" path. This stub keeps the platform realistic enough for the
// bootloader workload while avoiding that overhead.

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public sealed class STM32H7PWRStub : IDoubleWordPeripheral, IKnownSize
    {
        public STM32H7PWRStub(IMachine machine)
        {
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case 0x04:
                // CSR1: ACTVOSRDY (bit 13) = ready. NuttX polls this during
                // clock init and spins in a busy-wait loop until it's set.
                return 0x2000;
            case 0x18:
                // D3CR: VOSRDY (bit 13) = ready.
                return 0x2000;
            default:
                return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
        }

        public void Reset()
        {
        }
    }
}
