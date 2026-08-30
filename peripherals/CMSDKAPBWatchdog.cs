// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Tardigrade contributors

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Timers;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    /// <summary>
    /// Arm CMSDK APB watchdog.
    ///
    /// The counter is enabled by CONTROL.INTEN.  Its first expiry latches
    /// RAWINTSTAT; if software has not cleared that status, the next expiry
    /// reaches the reset stage and asserts reset when CONTROL.RESEN is set.
    /// LOAD and INTCLEAR both restart the counter from LOAD, as specified by
    /// the CMSDK programmer's model.  LOCK protects every register except
    /// itself.
    /// </summary>
    public sealed class CMSDKAPBWatchdog : BasicDoubleWordPeripheral, IKnownSize
    {
        public CMSDKAPBWatchdog(IMachine machine) : base(machine)
        {
            watchdogTimer = new LimitTimer(
                machine.ClockSource,
                DefaultFrequency,
                this,
                "CMSDK_APB_WATCHDOG",
                uint.MaxValue,
                Direction.Descending,
                enabled: false,
                workMode: WorkMode.Periodic,
                eventEnabled: true,
                autoUpdate: true);
            watchdogTimer.LimitReached += OnWatchdogExpiry;
            Reset();
        }

        public long Size => 0x1000;

        /// <summary>Watchdog clock in Hz; the platform overrides the fallback.</summary>
        public ulong ClockFrequency
        {
            get => watchdogTimer.Frequency;
            set => watchdogTimer.Frequency = value == 0 ? DefaultFrequency : value;
        }

        public GPIO IRQ { get; } = new GPIO();

        public override void Reset()
        {
            base.Reset();
            watchdogTimer.Reset();
            loadValue = uint.MaxValue;
            control = 0;
            rawInterrupt = false;
            resetPending = false;
            locked = false;
            integrationTestEnabled = false;
            integrationTestOutput = 0;
            resetOutputActive = false;
            UpdateOutputs();
        }

        public override uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case LoadOffset:
                    return loadValue;
                case ValueOffset:
                    return (uint)watchdogTimer.Value;
                case ControlOffset:
                    return control;
                case RawInterruptStatusOffset:
                    return rawInterrupt ? 1U : 0U;
                case MaskedInterruptStatusOffset:
                    return MaskedInterrupt ? 1U : 0U;
                case LockOffset:
                    return locked ? 1U : 0U;
                case IntegrationTestControlOffset:
                    return integrationTestEnabled ? 1U : 0U;
                case PeripheralId4Offset:
                case PeripheralId5Offset:
                case PeripheralId6Offset:
                case PeripheralId7Offset:
                case PeripheralId0Offset:
                case PeripheralId1Offset:
                case PeripheralId2Offset:
                case PeripheralId3Offset:
                case ComponentId0Offset:
                case ComponentId1Offset:
                case ComponentId2Offset:
                case ComponentId3Offset:
                    return ReadIdentification(offset);
                default:
                    return 0U;
            }
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            // WDOGLOCK remains writable while locked; all other writes are
            // ignored until the documented unlock value is supplied.
            if(locked && offset != LockOffset)
            {
                return;
            }

            switch(offset)
            {
                case LoadOffset:
                    loadValue = value == 0 ? 1U : value;
                    ReloadCounter();
                    break;
                case ControlOffset:
                    WriteControl(value);
                    break;
                case InterruptClearOffset:
                    rawInterrupt = false;
                    resetPending = false;
                    ReloadCounter();
                    UpdateOutputs();
                    break;
                case LockOffset:
                    locked = value != UnlockValue;
                    break;
                case IntegrationTestControlOffset:
                    integrationTestEnabled = (value & 1U) != 0;
                    UpdateOutputs();
                    break;
                case IntegrationTestOutputOffset:
                    integrationTestOutput = value & 0x3U;
                    UpdateOutputs();
                    break;
                default:
                    // VALUE, status, ID and reserved registers are read-only.
                    break;
            }
        }

        private void WriteControl(uint value)
        {
            var previous = control;
            control = value & (InterruptEnableBit | ResetEnableBit);

            var wasEnabled = (previous & InterruptEnableBit) != 0;
            var isEnabled = (control & InterruptEnableBit) != 0;
            if(wasEnabled != isEnabled)
            {
                if(isEnabled)
                {
                    rawInterrupt = false;
                    resetPending = false;
                    ReloadCounter();
                    watchdogTimer.Enabled = true;
                }
                else
                {
                    watchdogTimer.Enabled = false;
                }
            }

            UpdateOutputs();
        }

        private void ReloadCounter()
        {
            // AutoUpdate makes changing Limit restart a descending timer at
            // the new limit.  A second-stage expiry stops the timer; a LOAD
            // or INTCLEAR write starts it again when INTEN remains set.
            watchdogTimer.Limit = loadValue;
            watchdogTimer.Enabled = (control & InterruptEnableBit) != 0;
        }

        private void OnWatchdogExpiry()
        {
            if(!rawInterrupt)
            {
                rawInterrupt = true;
            }
            else
            {
                resetPending = true;
                watchdogTimer.Enabled = false;
            }
            UpdateOutputs();
        }

        private bool MaskedInterrupt => rawInterrupt && (control & InterruptEnableBit) != 0;

        private void UpdateOutputs()
        {
            var interrupt = integrationTestEnabled
                ? (integrationTestOutput & IntegrationInterruptBit) != 0
                : MaskedInterrupt;
            var reset = integrationTestEnabled
                ? (integrationTestOutput & IntegrationResetBit) != 0
                : resetPending && (control & ResetEnableBit) != 0;
            IRQ.Set(interrupt);
            if(reset && !resetOutputActive)
            {
                // Mark the edge before requesting reset. RequestReset may reset
                // peripherals synchronously; assigning this afterwards would
                // restore stale asserted state over Reset().
                resetOutputActive = true;
                machine.RequestReset();
                return;
            }
            resetOutputActive = reset;
        }

        private uint ReadIdentification(long offset)
        {
            switch(offset)
            {
                case PeripheralId4Offset: return 0x04;
                case PeripheralId5Offset: return 0x00;
                case PeripheralId6Offset: return 0x00;
                case PeripheralId7Offset: return 0x00;
                case PeripheralId0Offset: return 0x24;
                case PeripheralId1Offset: return 0xB8;
                case PeripheralId2Offset: return 0x1B;
                case PeripheralId3Offset: return 0x00;
                case ComponentId0Offset: return 0x0D;
                case ComponentId1Offset: return 0xF0;
                case ComponentId2Offset: return 0x05;
                case ComponentId3Offset: return 0xB1;
                default: return 0U;
            }
        }

        private readonly LimitTimer watchdogTimer;
        private uint loadValue;
        private uint control;
        private bool rawInterrupt;
        private bool resetPending;
        private bool locked;
        private bool integrationTestEnabled;
        private uint integrationTestOutput;
        private bool resetOutputActive;

        private const ulong DefaultFrequency = 25_000_000;
        private const uint UnlockValue = 0x1ACCE551;
        private const uint InterruptEnableBit = 1U << 0;
        private const uint ResetEnableBit = 1U << 1;
        private const uint IntegrationResetBit = 1U << 0;
        private const uint IntegrationInterruptBit = 1U << 1;

        private const long LoadOffset = 0x000;
        private const long ValueOffset = 0x004;
        private const long ControlOffset = 0x008;
        private const long InterruptClearOffset = 0x00C;
        private const long RawInterruptStatusOffset = 0x010;
        private const long MaskedInterruptStatusOffset = 0x014;
        private const long LockOffset = 0xC00;
        private const long IntegrationTestControlOffset = 0xF00;
        private const long IntegrationTestOutputOffset = 0xF04;
        private const long PeripheralId4Offset = 0xFD0;
        private const long PeripheralId5Offset = 0xFD4;
        private const long PeripheralId6Offset = 0xFD8;
        private const long PeripheralId7Offset = 0xFDC;
        private const long PeripheralId0Offset = 0xFE0;
        private const long PeripheralId1Offset = 0xFE4;
        private const long PeripheralId2Offset = 0xFE8;
        private const long PeripheralId3Offset = 0xFEC;
        private const long ComponentId0Offset = 0xFF0;
        private const long ComponentId1Offset = 0xFF4;
        private const long ComponentId2Offset = 0xFF8;
        private const long ComponentId3Offset = 0xFFC;
    }
}
