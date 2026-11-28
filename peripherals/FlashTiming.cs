// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Timers;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public enum FlashTiming
    {
        Off,
        Typical,
        Maximum
    }

    // A separate clean boot counts the physical commands selected by the model.
    // A one-tick busy interval preserves asynchronous completion and unit chaining.
    public sealed class FlashTimingCalibration
    {
        public bool Enabled { get; set; }
        public Dictionary<ulong, ulong> Counts { get; } = new Dictionary<ulong, ulong>();

        public ulong Interval(ulong microseconds)
        {
            if(!Enabled || microseconds == 0)
            {
                return microseconds;
            }
            Counts.TryGetValue(microseconds, out var count);
            Counts[microseconds] = checked(count + 1);
            return 1;
        }
    }

    public sealed class FlashOperationTimer
    {
        public FlashOperationTimer(IPeripheral owner, FlashTimingCalibration calibration = null)
        {
            this.owner = owner;
            Calibration = calibration ?? new FlashTimingCalibration();
        }

        public FlashTimingCalibration Calibration { get; }
        public bool Busy => completion != null;

        public void Start(ulong microseconds, Action complete)
        {
            if(Busy)
            {
                throw new InvalidOperationException("Flash operation already in progress");
            }
            if(microseconds == 0)
            {
                complete();
                return;
            }
            if(timer == null)
            {
                timer = new LimitTimer(owner.GetMachine().ClockSource, 1000000, owner,
                    "flash operation", direction: Direction.Descending, enabled: false,
                    workMode: WorkMode.OneShot, eventEnabled: true, autoUpdate: true);
                timer.LimitReached += Finish;
            }
            completion = complete;
            microseconds = Calibration.Interval(microseconds);
            timer.Limit = microseconds;
            timer.Value = microseconds;
            timer.Enabled = true;
        }

        public void Reset()
        {
            if(timer != null)
            {
                timer.Enabled = false;
            }
            completion = null;
        }

        private void Finish()
        {
            var complete = completion;
            completion = null;
            complete?.Invoke();
        }

        private readonly IPeripheral owner;
        private LimitTimer timer;
        private Action completion;
    }

    // MappedMemory has already accepted the native CPU store by the time its
    // memory-access hook runs. Keep committed bytes separately until expiry.
    public sealed class FlashProgramBuffer
    {
        public void Prepare(IMemory memory, long size)
        {
            if(bytes == null)
            {
                bytes = memory.ReadBytes(0, checked((int)size));
            }
        }

        public void UndoStore(IMemory memory, long offset, int width)
        {
            memory.WriteBytes(offset, bytes, checked((int)offset), width);
        }

        public void Program(IMemory memory, long offset, byte[] data)
        {
            memory.WriteBytes(offset, data, 0, data.Length);
            Array.Copy(data, 0, bytes, offset, data.Length);
        }

        public void RefreshIfPrepared(IMemory memory)
        {
            if(bytes != null && memory != null)
            {
                bytes = memory.ReadBytes(0, bytes.Length);
            }
        }

        public byte ReadByte(int offset)
        {
            return bytes[offset];
        }

        public uint ReadU32(int offset)
        {
            return (uint)(bytes[offset]
                | (bytes[offset + 1] << 8)
                | (bytes[offset + 2] << 16)
                | (bytes[offset + 3] << 24));
        }

        public void Invalidate()
        {
            bytes = null;
        }

        public static byte[] StoreBytes(ulong value, int width)
        {
            var data = new byte[width];
            for(int i = 0; i < width; i++)
            {
                data[i] = (byte)(value >> (8 * i));
            }
            return data;
        }

        private byte[] bytes;
    }

    // One operation engine per bank allows independent bank deadlines.
    public sealed class H7BankTiming
    {
        public H7BankTiming(ITardigradeFaultInjectable controller, FlashTimingCalibration calibration)
        {
            this.controller = controller;
            timer = new FlashOperationTimer((IPeripheral)controller, calibration);
        }

        public bool Busy => timer.Busy;
        public int Buffered { get; private set; }

        public void Prepare(IMemory backing, long size)
        {
            memory = backing;
            committed.Prepare(memory, size);
            Buffered = 0;
        }

        public bool Stage(long offset, uint width, ulong value)
        {
            committed.UndoStore(memory, offset, (int)width);
            if(Busy || width > 8 || width == 0)
            {
                return false;
            }
            if(Buffered == 0)
            {
                wordStart = offset & ~31L;
                pending = memory.ReadBytes(wordStart, 32);
            }
            int position = (int)(offset - wordStart);
            if(position != Buffered || position + width > 32)
            {
                return false;
            }
            for(int i = 0; i < width; i++)
            {
                pending[position + i] = (byte)(value >> (8 * i));
            }
            Buffered += (int)width;
            return true;
        }

        public void UpdateStaged(long offset, uint width, ulong value)
        {
            if(pending == null || width == 0 || width > 8)
            {
                return;
            }
            int position = (int)(offset - wordStart);
            if(position < 0 || position + width > 32)
            {
                return;
            }
            for(int i = 0; i < width; i++)
            {
                pending[position + i] = (byte)(value >> (8 * i));
            }
        }

        public void AbortInFlight()
        {
            timer.Reset();
            Buffered = 0;
            committed.RefreshIfPrepared(memory);
        }

        public void Program(FlashTiming mode, uint psize, Action complete)
        {
            if(Busy || Buffered == 0)
            {
                return;
            }
            var data = pending;
            var address = wordStart;
            Buffered = 0;
            timer.Start(ProgramMicros[psize] * Factor(mode), () =>
            {
                committed.Program(memory, address, data);
                complete();
            });
        }

        public void Erase(FlashTiming mode, uint psize, bool mass, Action complete)
        {
            if(Busy)
            {
                return;
            }
            if(!controller.PassthroughMode && !controller.AnyFaultFired
                && controller.TotalPageErases + 1 == controller.FaultAtPageErase)
            {
                complete();
                committed.RefreshIfPrepared(memory);
                return;
            }
            var typical = mass ? MassEraseMillis[psize] : SectorEraseMillis[psize];
            timer.Start(typical * 1000UL * Factor(mode), () =>
            {
                complete();
                committed.RefreshIfPrepared(memory);
            });
        }

        public void RefreshCommittedBytes()
        {
            committed.RefreshIfPrepared(memory);
        }

        public void Reset()
        {
            timer.Reset();
            Buffered = 0;
            committed.Invalidate();
        }

        private static ulong Factor(FlashTiming mode) => mode == FlashTiming.Maximum ? 2UL : 1UL;

        private readonly ITardigradeFaultInjectable controller;
        private readonly FlashOperationTimer timer;
        private readonly FlashProgramBuffer committed = new FlashProgramBuffer();
        private IMemory memory;
        private long wordStart;
        private byte[] pending;

        private static readonly uint[] ProgramMicros = { 290, 180, 130, 100 };
        private static readonly uint[] SectorEraseMillis = { 2000, 1800, 1100, 1000 };
        private static readonly uint[] MassEraseMillis = { 13000, 8000, 6000, 5000 };
    }

    public static class FlashDurations
    {
        public static ulong F4Sector(FlashTiming timing, uint control, int size)
        {
            var psize = (control >> 8) & 3;
            if(psize == 3)
            {
                if(timing == FlashTiming.Maximum)
                {
                    throw new ArgumentException("F429 external VPP erase maximum is unspecified");
                }
                switch(size)
                {
                    case 0x4000: return 230000;
                    case 0x10000: return 490000;
                    case 0x20000: return 875000;
                    default: throw new ArgumentException("Unsupported F429 sector size");
                }
            }
            int row;
            switch(size)
            {
                case 0x4000: row = 0; break;
                case 0x10000: row = 1; break;
                case 0x20000: row = 2; break;
                default: throw new ArgumentException("Unsupported F429 sector size");
            }
            return F4SectorMilliseconds[row, psize] * (timing == FlashTiming.Maximum ? 2000UL : 1000UL);
        }

        public static bool StartF4MassErase(FlashTiming mode, uint control,
            ITardigradeFaultInjectable controller, FlashOperationTimer timer, Action<int> eraseSector,
            FlashProgramBuffer committed)
        {
            const uint start = 1u << 16, bank1 = 1u << 2, bank2 = 1u << 15;
            if(mode == FlashTiming.Off || (control & start) == 0 || (control & (bank1 | bank2)) == 0)
            {
                return false;
            }
            uint psize = (control >> 8) & 3;
            if(psize == 3 && mode == FlashTiming.Maximum)
            {
                throw new ArgumentException("F429 external VPP erase maximum is unspecified");
            }
            Action runErase = () =>
            {
                int firstSector = (control & bank1) != 0 ? 0 : 12;
                int endSector = (control & bank2) != 0 ? 24 : 12;
                for(int i = firstSector; i < endSector; i++)
                {
                    eraseSector(i);
                }
                committed.RefreshIfPrepared(controller.Flash);
            };
            if(!controller.PassthroughMode && !controller.AnyFaultFired
                && controller.TotalPageErases + 1 == controller.FaultAtPageErase)
            {
                runErase();
                return true;
            }
            timer.Start(F4MassEraseMillis[psize] * (mode == FlashTiming.Maximum ? 2000UL : 1000UL), runErase);
            return true;
        }

        private static readonly uint[] F4MassEraseMillis = { 16000, 11000, 8000, 6900 };

        public static void RequireUnarmed(ITardigradeFaultInjectable controller)
        {
            if(controller.FaultAtWordWrite != ulong.MaxValue || controller.FaultAtPageErase != ulong.MaxValue)
            {
                throw new InvalidOperationException("Device timing requires an unarmed flash controller");
            }
        }

        public static void SetCpuWriteHook(IMachine machine, IBusPeripheral controller, MemoryAccessHook hook)
        {
            foreach(var cpu in machine.GetSystemBus(controller).GetCPUs().OfType<ICPUWithMemoryAccessHooks>())
            {
                cpu.SetHookAtMemoryAccess(hook);
            }
        }

        private static readonly uint[,] F4SectorMilliseconds =
        {
            { 400, 300, 250 },
            { 1200, 700, 550 },
            { 2000, 1300, 1000 }
        };
    }
}
