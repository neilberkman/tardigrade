// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Memory
{
    /// <summary>
    /// Minimal cache controller stub: reflects control-register enable bit
    /// into a status register so firmware polling loops terminate.
    /// </summary>
    public class SimpleCacheController : BasicDoubleWordPeripheral, IKnownSize
    {
        public SimpleCacheController(IMachine machine) : base(machine)
        {
            Reset();
        }

        public override void Reset()
        {
            base.Reset();
            controlRegister = 0U;
        }

        public override uint ReadDoubleWord(long offset)
        {
            if(offset == ControlRegisterOffset)
            {
                return controlRegister;
            }

            if(offset == StatusRegisterOffset)
            {
                return (controlRegister & EnableBitMask) != 0
                    ? EnabledStatusValue
                    : DisabledStatusValue;
            }

            return 0U;
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            if(offset == ControlRegisterOffset)
            {
                controlRegister = value;
            }
        }

        public long Size => 0x1000;

        public long ControlRegisterOffset { get; set; } = 0x0;
        public long StatusRegisterOffset { get; set; } = 0x4;
        public uint EnableBitMask { get; set; } = 0x1;
        public uint EnabledStatusValue { get; set; } = 0x2;
        public uint DisabledStatusValue { get; set; } = 0x0;

        private uint controlRegister;
    }
}
