// SPDX-License-Identifier: Apache-2.0

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;
using System.Collections.Generic;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    /// <summary>
    /// Minimal SIE-200 MPC register model for the AN521 memory map.
    ///
    /// The model implements the register behavior needed by TF-M's MPC
    /// driver: a read-only block maximum/configuration pair, an indexed LUT,
    /// control, and interrupt status/enable/clear registers.  Security
    /// attributes start secure (LUT zero), matching an initialized AN521
    /// memory controller before TF-M configures a non-secure range.
    /// </summary>
    public sealed class Sse200MpcStub : BasicDoubleWordPeripheral, IKnownSize
    {
        public Sse200MpcStub(IMachine machine) : base(machine)
        {
            Reset();
        }

        public long Size => 0x1000;

        // AN521 SIE-200 geometry: BLK_CFG=8 and 512 indexed LUT words
        // (BLK_MAX=511).
        public uint BlockConfiguration { get; set; } = 8U;
        public uint MaximumBlockWordIndex { get; set; } = 511U;

        public override void Reset()
        {
            base.Reset();
            control = 0U;
            blockIndex = 0U;
            lutWords.Clear();
            interruptStatus = 0U;
            interruptEnable = 0U;
        }

        public override uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case 0x00: return control;
                case 0x10: return MaximumBlockWordIndex;
                case 0x14: return BlockConfiguration;
                case 0x18: return blockIndex;
                case 0x1C:
                    return lutWords.TryGetValue(blockIndex, out var lutWord)
                        ? lutWord
                        : 0U;
                case 0x20: return interruptStatus;
                case 0x28: return interruptEnable;
                default: return 0U;
            }
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case 0x00:
                    control = value;
                    break;
                case 0x18:
                    blockIndex = value;
                    break;
                case 0x1C:
                    // Keep the indexed LUT semantics and reject indices past
                    // BLK_MAX, as the hardware register does.
                    if(blockIndex <= MaximumBlockWordIndex)
                    {
                        lutWords[blockIndex] = value;
                    }
                    break;
                case 0x24:
                    interruptStatus &= ~value;
                    break;
                case 0x28:
                    interruptEnable = value;
                    break;
            }
        }

        private uint control;
        private uint blockIndex;
        private readonly Dictionary<uint, uint> lutWords = new Dictionary<uint, uint>();
        private uint interruptStatus;
        private uint interruptEnable;
    }
}
