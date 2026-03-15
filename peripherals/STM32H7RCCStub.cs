// SPDX-License-Identifier: Apache-2.0
//
// Minimal STM32H7 RCC (Reset and Clock Control) stub.
//
// The upstream Renode STM32H7 RCC model implements only a subset of the H7
// register file. Early H7 boot code touches additional RCC offsets heavily,
// and every unhandled access pays the expensive warning path. This stub keeps
// the boot-critical behavior realistic enough for the bootloader workload:
// - oscillator / PLL ready bits follow the corresponding enable bits
// - SWS mirrors SW for immediate clock switching
// - LSERDY / LSIRDY follow LSEON / LSION
// - all other offsets retain written values via dictionary-backed storage

using System.Collections.Generic;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public sealed class STM32H7RCCStub : IDoubleWordPeripheral, IKnownSize
    {
        public STM32H7RCCStub(IMachine machine)
        {
        }

        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
            case RegisterCr:
                return ComposeCr();

            case RegisterCfgr:
            {
                var sw = cfgr & 0x7U;
                return (cfgr & ~SwsMask) | (sw << 3);
            }

            case RegisterBdcr:
            {
                uint val;
                genericStorage.TryGetValue(offset, out val);
                if((val & LseOnBit) != 0)
                {
                    val |= LseReadyBit;
                }
                return val;
            }

            case RegisterCsr:
            {
                uint val;
                genericStorage.TryGetValue(offset, out val);
                if((val & LsiOnBit) != 0)
                {
                    val |= LsiReadyBit;
                }
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
            case RegisterCr:
                cr = value;
                break;

            case RegisterCfgr:
                cfgr = value;
                break;

            default:
                genericStorage[offset] = value;
                break;
            }
        }

        public void Reset()
        {
            cr = DefaultCr;
            cfgr = 0;
            genericStorage.Clear();
        }

        private uint ComposeCr()
        {
            var value = cr;
            if((value & HsiOnBit) != 0)
            {
                value |= HsiReadyBit;
            }
            if((value & CsiOnBit) != 0)
            {
                value |= CsiReadyBit;
            }
            if((value & Hsi48OnBit) != 0)
            {
                value |= Hsi48ReadyBit;
            }
            if((value & HseOnBit) != 0)
            {
                value |= HseReadyBit;
            }
            if((value & Pll1OnBit) != 0)
            {
                value |= Pll1ReadyBit;
            }
            if((value & Pll2OnBit) != 0)
            {
                value |= Pll2ReadyBit;
            }
            if((value & Pll3OnBit) != 0)
            {
                value |= Pll3ReadyBit;
            }
            return value;
        }

        private uint cr = DefaultCr;
        private uint cfgr;
        private readonly Dictionary<long, uint> genericStorage = new Dictionary<long, uint>();

        private const long RegisterCr = 0x00;
        private const long RegisterCfgr = 0x10;
        private const long RegisterBdcr = 0x70;
        private const long RegisterCsr = 0x74;

        private const uint HsiOnBit = 1U << 0;
        private const uint HsiReadyBit = 1U << 2;
        private const uint CsiOnBit = 1U << 7;
        private const uint CsiReadyBit = 1U << 8;
        private const uint Hsi48OnBit = 1U << 12;
        private const uint Hsi48ReadyBit = 1U << 13;
        private const uint HseOnBit = 1U << 16;
        private const uint HseReadyBit = 1U << 17;
        private const uint Pll1OnBit = 1U << 24;
        private const uint Pll1ReadyBit = 1U << 25;
        private const uint Pll2OnBit = 1U << 26;
        private const uint Pll2ReadyBit = 1U << 27;
        private const uint Pll3OnBit = 1U << 28;
        private const uint Pll3ReadyBit = 1U << 29;
        private const uint LseOnBit = 1U << 0;
        private const uint LseReadyBit = 1U << 1;
        private const uint LsiOnBit = 1U << 0;
        private const uint LsiReadyBit = 1U << 1;
        private const uint SwsMask = 0x38;
        private const uint DefaultCr = 0x83;
    }
}
