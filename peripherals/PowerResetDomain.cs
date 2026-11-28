// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.Linq;
using Antmicro.Renode.Core;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Timers;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    // Reset() without these notifications is an ordinary warm reset.
    public interface IPowerLossAware : IPeripheral
    {
        void PowerLost(bool vbatPresent);
        void PowerRestored();
    }

    public enum ResetFamily { Generic, NRF52840, STM32F1, STM32F4, STM32H7, STM32L4 }

    public sealed class PowerResetDomain : IPowerLossAware
    {
        public PowerResetDomain(IMachine machine, ResetFamily family = ResetFamily.Generic)
        {
            this.machine = machine;
            this.family = family;
            flags = PowerOnFlags;
        }

        // Called after loading the base platform so the bus registrations exist.
        public void Initialize()
        {
            if(initialized)
            {
                return;
            }
            var bus = machine.SystemBus;
            switch(family)
            {
            case ResetFamily.NRF52840:
                InstallRegisterHooks(0x40000000, ReadPower, WritePower);
                foreach(var watchdog in machine.GetPeripheralsOfType<NRF52840_Watchdog>())
                {
                    watchdog.LimitReached += NoteWatchdog;
                }
                break;
            case ResetFamily.STM32F1:
                InstallRcc(0x40021000, 0x24);
                InstallF1Backup();
                break;
            case ResetFamily.STM32F4:
                InstallRcc(0x40023800, 0x74);
                break;
            case ResetFamily.STM32H7:
                InstallRcc(0x58024400, 0xd0);
                InstallExtendedBackup(0x58004000);
                break;
            case ResetFamily.STM32L4:
                InstallRcc(0x40021000, 0x94);
                InstallExtendedBackup(0x40002800);
                break;
            }
            if(family != ResetFamily.Generic)
            {
                // The independent watchdog owns a public clock entry. Its
                // LimitTimer announces expiry before the queued machine reset.
                foreach(var entry in machine.ClockSource.GetAllClockEntries())
                {
                    var timer = entry.Handler != null ? entry.Handler.Target as LimitTimer : null;
                    if(entry.Owner is STM32_IndependentWatchdog && timer != null)
                    {
                        timer.LimitReached += NoteWatchdog;
                    }
                }
                bus.AddWatchpointHook(0xe000ed0c, SysbusAccessWidth.DoubleWord, Access.Write,
                    (cpu, address, width, value) =>
                    {
                        if((value & 0xffff0004) == 0x05fa0004)
                        {
                            pending = Source.Software;
                        }
                    });
            }
            initialized = true;
        }

        public bool VbatPresent { get; set; }
        public string[] BootResetKinds => history.ToArray();
        public int BootCount => history.Count;
        public string LastResetKind => history.Count > 0 ? history[history.Count - 1] : "power_on";

        public void ClearRetainedRegions()
        {
            regions.Clear();
        }

        // Check the whole range before writing. Only memory-backed mappings
        // have the no-op warm reset that this retention contract requires.
        public void AddRetainedRegion(ulong address, uint size, byte fill = 0)
        {
            if(size == 0 || address > uint.MaxValue || size > 0x100000000UL - address)
            {
                throw new RecoverableException("Invalid retained region");
            }
            var range = new Core.Range(address, size);
            if(family == ResetFamily.STM32F4 && range.Intersects(new Core.Range(0x40024000, 4096))
                || family == ResetFamily.STM32H7 && range.Intersects(new Core.Range(0x38800000, 4096)))
            {
                throw new RecoverableException("Backup SRAM belongs to the VBAT domain");
            }
            var mapping = machine.SystemBus.WhatIsAt(address);
            if(mapping == null || !mapping.RegistrationPoint.Range.Contains(range)
                || !(mapping.Peripheral is MappedMemory || mapping.Peripheral is ArrayMemory))
            {
                throw new RecoverableException("Retained region must fit in one RAM mapping");
            }
            if(regions.Any(region => region.Key.Intersects(range)))
            {
                throw new RecoverableException("Retained regions overlap");
            }
            regions.Add(new KeyValuePair<Core.Range, byte>(range, fill));
        }

        public void PowerCycle()
        {
            using(machine.ObtainPausedState())
            {
                var failures = new List<Exception>();
                try
                {
                    BeginPowerLoss();
                    machine.Reset();
                }
                catch(Exception error)
                {
                    failures.Add(error);
                }
                EndPowerLoss(failures);
            }
        }

        public void PreparePowerOn()
        {
            pending = Source.PowerOn;
        }

        public void StartTrial()
        {
            history.Clear();
            history.Add("power_on");
        }

        public void BeginPowerLoss()
        {
            notified.Clear();
            var failures = new List<Exception>();
            foreach(var peripheral in machine.GetPeripheralsOfType<IPowerLossAware>().Distinct())
            {
                notified.Push(peripheral);
                try
                {
                    peripheral.PowerLost(VbatPresent);
                }
                catch(Exception error)
                {
                    failures.Add(error);
                }
            }
            if(failures.Count != 0)
            {
                EndPowerLoss(failures);
            }
        }

        public void EndPowerLoss() => EndPowerLoss(new List<Exception>());

        private void EndPowerLoss(List<Exception> failures)
        {
            while(notified.Count != 0)
            {
                try
                {
                    notified.Pop().PowerRestored();
                }
                catch(Exception error)
                {
                    failures.Add(error);
                }
            }
            if(failures.Count != 0)
            {
                throw new AggregateException("Power cycle failed", failures);
            }
        }

        public void ResetFromPin() => WarmReset(Source.Pin);
        public void ResetFromWatchdog() => WarmReset(Source.Watchdog);

        public void PowerLost(bool vbatPresent)
        {
            pending = Source.PowerLoss;
            backupPowered = vbatPresent;
        }

        public void PowerRestored()
        {
            pending = Source.Unspecified;
            EnableReleasedCpuTimeHandles();
        }

        public void Reset()
        {
            if(pending == Source.PowerOn)
            {
                flags = PowerOnFlags;
                gpregret = gpregret2 = 0;
                if(family != ResetFamily.Generic && family != ResetFamily.NRF52840)
                {
                    ClearBackup();
                }
                foreach(var region in regions)
                {
                    FillRam(region.Key, 0);
                }
                history.Clear();
                history.Add("power_on");
            }
            else if(pending == Source.PowerLoss)
            {
                flags = PowerOnFlags;
                gpregret = gpregret2 = 0;
                if(family != ResetFamily.Generic && family != ResetFamily.NRF52840 && !backupPowered)
                {
                    ClearBackup();
                }
                foreach(var region in regions)
                {
                    FillRam(region.Key, region.Value);
                }
                history.Add("power_loss");
            }
            else
            {
                if(family == ResetFamily.NRF52840 && (pending == Source.Pin || pending == Source.Watchdog))
                {
                    gpregret = gpregret2 = 0;
                }
                flags |= WarmFlags(pending);
                history.Add("warm");
            }
            pending = Source.Unspecified;
            EnableReleasedCpuTimeHandles();
        }

        private void WarmReset(Source source)
        {
            using(machine.ObtainPausedState())
            {
                pending = source;
                machine.Reset();
                EnableReleasedCpuTimeHandles();
            }
        }

        private void EnableReleasedCpuTimeHandles()
        {
            foreach(var cpu in machine.SystemBus.GetCPUs().OfType<BaseCPU>())
            {
                if(cpu.TimeHandle != null)
                {
                    cpu.TimeHandle.Enabled = true;
                }
            }
        }

        private void NoteWatchdog() => pending = Source.Watchdog;

        private uint PowerOnFlags
        {
            get
            {
                switch(family)
                {
                case ResetFamily.STM32F1:
                case ResetFamily.STM32L4: return 0x0c000000;
                case ResetFamily.STM32F4: return 0x0e000000;
                case ResetFamily.STM32H7: return 0x00fe0000;
                default: return 0;
                }
            }
        }

        private uint WarmFlags(Source source)
        {
            if(family == ResetFamily.Generic || source == Source.Unspecified)
            {
                return 0;
            }
            if(family == ResetFamily.NRF52840)
            {
                return source == Source.Pin ? 1u : source == Source.Watchdog ? 2u : 4u;
            }
            // System resets also assert the external reset line on these parts.
            if(family == ResetFamily.STM32H7)
            {
                const uint system = (1u << 22) | (1u << 17);
                return system | (source == Source.Watchdog ? 1u << 26 : source == Source.Software ? 1u << 24 : 0);
            }
            return (1u << 26) | (source == Source.Watchdog ? 1u << 29 : source == Source.Software ? 1u << 28 : 0);
        }

        private uint ReadPower(uint original, long offset)
        {
            switch(offset)
            {
            case 0x400: return flags;
            case 0x51c: return gpregret;
            case 0x520: return gpregret2;
            default: return original;
            }
        }

        private uint WritePower(uint value, long offset)
        {
            switch(offset)
            {
            case 0x400: flags &= ~value; break;
            case 0x51c: gpregret = (byte)value; break;
            case 0x520: gpregret2 = (byte)value; break;
            }
            return value;
        }

        private void InstallRegisterHooks(ulong address, Func<uint, long, uint> read, Func<uint, long, uint> write)
        {
            var bus = machine.SystemBus;
            var mapping = bus.WhatIsAt(address);
            if(mapping == null)
            {
                throw new RecoverableException("Missing peripheral at 0x" + address.ToString("x"));
            }
            bus.SetHookAfterPeripheralRead<uint>(mapping.Peripheral, read);
            bus.SetHookBeforePeripheralWrite<uint>(mapping.Peripheral, write);
        }

        private void InstallRcc(ulong address, long statusOffset)
        {
            uint clear = family == ResetFamily.STM32H7 ? 1u << 16
                : family == ResetFamily.STM32L4 ? 1u << 23 : 1u << 24;
            uint lowMask = family == ResetFamily.STM32H7 ? 0 : clear - 1;
            Func<long, bool> isStatus = offset =>
            {
                long aligned = offset & ~3L;
                return aligned == statusOffset || (family == ResetFamily.STM32H7 && aligned == 0x130);
            };
            Func<uint, long, uint> read = (value, offset) =>
            {
                if(!isStatus(offset))
                {
                    return value;
                }
                int shift = 8 * (int)(offset % 4);
                return (value & (lowMask >> shift)) | (flags >> shift);
            };
            Func<uint, long, uint> write = (value, offset) =>
            {
                if(!isStatus(offset))
                {
                    return value;
                }
                int shift = 8 * (int)(offset % 4);
                if(((value << shift) & clear) != 0)
                {
                    flags = 0;
                }
                return value & ((lowMask | clear) >> shift);
            };
            var bus = machine.SystemBus;
            var rcc = bus.WhatIsAt(address).Peripheral;
            bus.SetHookAfterPeripheralRead<byte>(rcc, (v, o) => { return (byte)read(v, o); });
            bus.SetHookAfterPeripheralRead<ushort>(rcc, (v, o) => { return (ushort)read(v, o); });
            bus.SetHookAfterPeripheralRead<uint>(rcc, read);
            bus.SetHookBeforePeripheralWrite<byte>(rcc, (v, o) => { return (byte)write(v, o); });
            bus.SetHookBeforePeripheralWrite<ushort>(rcc, (v, o) => { return (ushort)write(v, o); });
            bus.SetHookBeforePeripheralWrite<uint>(rcc, write);
        }

        private void InstallF1Backup()
        {
            // DR1..DR10 each expose 16 bits, at a four-byte stride.
            Func<uint, long, uint> mask = (value, offset) =>
            {
                if(offset < 4 || offset >= 0x2c)
                {
                    return value;
                }
                return value & (0xffffu >> (8 * (int)(offset % 4)));
            };
            var bus = machine.SystemBus;
            var backup = bus.WhatIsAt(0x40006c00).Peripheral;
            bus.SetHookAfterPeripheralRead<uint>(backup, mask);
            bus.SetHookAfterPeripheralRead<ushort>(backup, (v, o) => { return (ushort)mask(v, o); });
            bus.SetHookAfterPeripheralRead<byte>(backup, (v, o) => { return (byte)mask(v, o); });
        }

        // The built-in RTC implements BKP0R..BKP19R. These two families have 32.
        private void InstallExtendedBackup(ulong address)
        {
            InstallRegisterHooks(address,
                (value, offset) => IsExtraBackup(offset) ? extraBackup[(offset - 0xa0) / 4] : value,
                (value, offset) =>
                {
                    if(IsExtraBackup(offset))
                    {
                        extraBackup[(offset - 0xa0) / 4] = value;
                    }
                    return value;
                });
        }

        private static bool IsExtraBackup(long offset) => offset >= 0xa0 && offset <= 0xcc && offset % 4 == 0;

        private void ClearBackup()
        {
            if(family == ResetFamily.STM32F1)
            {
                for(uint index = 0; index < 10; ++index)
                {
                    machine.SystemBus.WriteDoubleWord(0x40006c04 + 4 * index, 0);
                }
                return;
            }
            uint rtc = family == ResetFamily.STM32H7 ? 0x58004000u : 0x40002800u;
            for(uint index = 0; index < 20; ++index)
            {
                machine.SystemBus.WriteDoubleWord(rtc + 0x50 + 4 * index, 0);
            }
            Array.Clear(extraBackup, 0, extraBackup.Length);
            if(family == ResetFamily.STM32F4 || family == ResetFamily.STM32H7)
            {
                ulong sram = family == ResetFamily.STM32F4 ? 0x40024000u : 0x38800000u;
                FillRam(new Core.Range(sram, 4096), 0);
            }
        }

        private void FillRam(Core.Range range, byte fill)
        {
            var bytes = new byte[Math.Min(range.Size, 65536UL)];
            if(fill != 0)
            {
                for(var index = 0; index < bytes.Length; ++index)
                {
                    bytes[index] = fill;
                }
            }
            for(ulong offset = 0; offset < range.Size; offset += (ulong)bytes.Length)
            {
                var count = (int)Math.Min((ulong)bytes.Length, range.Size - offset);
                machine.SystemBus.WriteBytes(bytes, range.StartAddress + offset, count);
            }
        }

        private enum Source { Unspecified, Pin, Software, Watchdog, PowerLoss, PowerOn }
        private readonly IMachine machine;
        private readonly ResetFamily family;
        private readonly List<KeyValuePair<Core.Range, byte>> regions = new List<KeyValuePair<Core.Range, byte>>();
        private readonly List<string> history = new List<string> { "power_on" };
        private readonly Stack<IPowerLossAware> notified = new Stack<IPowerLossAware>();
        private readonly uint[] extraBackup = new uint[12];
        private bool initialized, backupPowered;
        private uint flags;
        private byte gpregret, gpregret2;
        private Source pending;
    }
}
