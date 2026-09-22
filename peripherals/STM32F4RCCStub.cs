// SPDX-License-Identifier: Apache-2.0
//
// Minimal STM32F4 RCC (Reset and Clock Control) stub.
//
// Registered at 0x40023800, size 0x400 (up to the FLASH register boundary).
// Clock ready bits follow the corresponding oscillator enable immediately,
// including clearing when firmware disables a source.
// SWS mirrors SW for instant clock switching.
// Unhandled offsets use dictionary store/return.

using System.Collections.Generic;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32F4RCCStub : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        // RCC_CR oscillator enable/ready pairs.
        private const uint RCC_HSION   = 1U << 0;
        private const uint RCC_HSIRDY  = 1U << 1;
        private const uint RCC_HSEON   = 1U << 16;
        private const uint RCC_HSERDY  = 1U << 17;
        private const uint RCC_PLLON   = 1U << 24;
        private const uint RCC_PLLRDY  = 1U << 25;
        private const uint RCC_CR_READY_BITS = RCC_HSIRDY | RCC_HSERDY | RCC_PLLRDY;

        // BDCR / CSR bits.
        private const uint LSEON  = 1U << 0;
        private const uint LSERDY = 1U << 1;
        private const uint LSION  = 1U << 0;
        private const uint LSIRDY = 1U << 1;

        // Dedicated registers.
        private uint rccCr = RCC_HSION;
        private uint rccPllCfgr;
        private uint rccCfgr;

        // Generic storage for all other offsets.
        private readonly Dictionary<long, uint> genericStorage = new Dictionary<long, uint>();

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case 0x00: // RCC_CR
                    return RccCrWithReadyBits();

                case 0x04: // RCC_PLLCFGR
                    return rccPllCfgr;

                case 0x08: // RCC_CFGR: SWS mirrors SW.
                {
                    uint sw = rccCfgr & 0x3U;
                    return (rccCfgr & ~0xCU) | (sw << 2);
                }

                case 0x70: // RCC_BDCR: LSERDY auto-set when LSEON.
                {
                    uint val;
                    genericStorage.TryGetValue(offset, out val);
                    if((val & LSEON) != 0)
                        val |= LSERDY;
                    return val;
                }

                case 0x74: // RCC_CSR: LSIRDY auto-set when LSION.
                {
                    uint val;
                    genericStorage.TryGetValue(offset, out val);
                    if((val & LSION) != 0)
                        val |= LSIRDY;
                    return val;
                }

                default:
                {
                    uint val;
                    genericStorage.TryGetValue(offset, out val);
                    return val;
                }
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case 0x00:
                    rccCr = value & ~RCC_CR_READY_BITS;
                    break;
                case 0x04:
                    rccPllCfgr = value;
                    break;
                case 0x08:
                    rccCfgr = value;
                    break;
                default:
                    genericStorage[offset] = value;
                    break;
            }
        }

        public void Reset()
        {
            rccCr = RCC_HSION;
            rccPllCfgr = 0;
            rccCfgr = 0;
            genericStorage.Clear();
        }

        private uint RccCrWithReadyBits()
        {
            uint value = rccCr & ~RCC_CR_READY_BITS;
            if((rccCr & RCC_HSION) != 0)
                value |= RCC_HSIRDY;
            if((rccCr & RCC_HSEON) != 0)
                value |= RCC_HSERDY;
            if((rccCr & RCC_PLLON) != 0)
                value |= RCC_PLLRDY;
            return value;
        }
    }
}
