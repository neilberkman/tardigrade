// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Exact MRAM program tracking over executable MappedMemory. Firmware fetches
// stay on Renode's native memory path; this sidecar observes CPU writes and
// reapplies modeled partial-program results to the same backing memory.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Logging.Profiling;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public sealed class MappedMRAMTracker : IBytePeripheral, IWordPeripheral,
                                             IDoubleWordPeripheral, IQuadWordPeripheral,
                                             IKnownSize, ITardigradeFaultInjectable
    {
        public MappedMRAMTracker(IMachine machine)
        {
            this.machine = machine;
        }

        public MappedMemory BackingMemory { get; set; }
        public IMemory Flash => BackingMemory;
        public long Size => BackingMemory != null ? BackingMemory.Size : FlashSize;
        public long FlashBaseAddress { get; set; }
        public long FlashSize { get; set; } = 0x1000;
        public int PageSize { get; set; } = 0x1000;
        public byte EraseFill { get; set; }

        public int ProgramUnitSize
        {
            get { return programUnitSize; }
            set
            {
                if(value <= 0 || (value & (value - 1)) != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        "ProgramUnitSize must be a positive power of two");
                }
                programUnitSize = value;
            }
        }

        // Runtime geometry uses the established NVMemory name.
        public long WordSize
        {
            get { return ProgramUnitSize; }
            set { ProgramUnitSize = checked((int)value); }
        }

        public ulong ProgramAddressBase
        {
            get { return programAddressBase != 0 ? programAddressBase : (ulong)FlashBaseAddress; }
            set { programAddressBase = value; }
        }

        public ulong TotalWordWrites { get; set; }
        public ulong FaultAtWordWrite
        {
            get { return faultAtWordWrite; }
            set
            {
                faultAtWordWrite = value;
                UpdateHooks();
                if(value != ulong.MaxValue && trackingStarted)
                {
                    EnsureShadow();
                }
            }
        }
        public bool FaultFired { get; set; }
        public bool LastFaultInjected { get; set; }
        public bool FaultEverFired { get; set; }
        public bool DriverErrorFired { get; set; }
        public bool PerWriteAccurate => true;
        public bool AnyFaultFired => FaultEverFired;
        public bool FaultRequiresImmediateStop => FaultEverFired && WriteFaultMode == 0;
        public uint LastFaultAddress { get; set; }
        public byte[] FaultFlashSnapshot
        {
            get { return CloneBytes(faultMemorySnapshot); }
            set { faultMemorySnapshot = CloneBytes(value); }
        }

        public int WriteFaultMode
        {
            get { return writeFaultMode; }
            set
            {
                if(value < 0 || value > 6)
                {
                    throw new ArgumentOutOfRangeException(nameof(value));
                }
                writeFaultMode = value;
            }
        }
        public int EraseFaultMode { get; set; }
        public uint CorruptionSeed { get; set; }
        public int DiffLookahead { get; set; } = 32;
        public bool SkipShadowScan { get; set; } = true;
        public bool PassthroughMode { get; set; }

        public ulong TotalPageErases { get; set; }
        public ulong FaultAtPageErase { get; set; } = ulong.MaxValue;
        public bool EraseFaultFired { get; set; }
        public bool EraseTraceEnabled { get; set; }
        public int EraseTraceCount => 0;
        public string EraseTraceToString() { return string.Empty; }
        public void EraseTraceClear() { }

        public bool WriteTraceEnabled
        {
            get { return writeTraceEnabled; }
            set
            {
                writeTraceEnabled = value;
                UpdateHooks();
                if(value && trackingStarted)
                {
                    EnsureShadow();
                }
            }
        }
        public bool WriteTraceWidthExplicit => true;
        public int WriteTraceCount => writeTrace.Count;
        public string WriteTraceToString()
        {
            var result = new StringBuilder(writeTrace.Count * 40);
            foreach(var entry in writeTrace)
            {
                result.Append(entry.Index);
                result.Append(':');
                result.Append(entry.Offset);
                result.Append(':');
                result.Append(entry.Value);
                result.Append(':');
                result.Append(entry.Width);
                result.Append('\n');
            }
            return result.ToString();
        }
        public void WriteTraceClear()
        {
            writeTrace.Clear();
        }

        public int ProgramTraceCount => programTrace.Count;
        public string ProgramTraceToString()
        {
            var result = new StringBuilder(programTrace.Count * 128);
            foreach(var entry in programTrace)
            {
                result.Append(entry.Index);
                result.Append(':');
                result.Append(entry.Offset);
                result.Append(':');
                result.Append(entry.Width);
                result.Append(':');
                AppendHex(result, entry.Intended);
                result.Append(':');
                AppendHex(result, entry.PreProgram);
                result.Append(':');
                AppendHex(result, entry.PostProgram);
                result.Append(':');
                result.Append(entry.Faulted ? '1' : '0');
                result.Append('\n');
            }
            return result.ToString();
        }
        public void ProgramTraceClear()
        {
            programTrace.Clear();
            ClearFaultEvidence();
        }

        public ulong LastFaultWriteIndex => lastFaultWriteIndex;
        public ulong LastFaultProgramAddress => lastFaultProgramAddress;
        public long LastFaultOffset => lastFaultOffset;
        public int LastFaultProgramWidth => lastFaultProgramWidth;
        public byte[] LastFaultIntendedBytes => CloneBytes(lastFaultIntendedBytes);
        public byte[] LastFaultPreProgramBytes => CloneBytes(lastFaultPreProgramBytes);
        public byte[] LastFaultPostFaultBytes => CloneBytes(lastFaultPostFaultBytes);
        public byte[] FaultMemorySnapshot => CloneBytes(faultMemorySnapshot);
        public int FaultMemorySnapshotSize => faultMemorySnapshot != null ? faultMemorySnapshot.Length : 0;
        public bool FaultEvidenceExact =>
            lastFaultWriteIndex != 0
            && lastFaultOffset >= 0
            && lastFaultProgramWidth == ProgramUnitSize
            && lastFaultIntendedBytes != null
            && lastFaultIntendedBytes.Length == ProgramUnitSize
            && lastFaultPreProgramBytes != null
            && lastFaultPreProgramBytes.Length == ProgramUnitSize
            && lastFaultPostFaultBytes != null
            && lastFaultPostFaultBytes.Length == ProgramUnitSize
            && faultMemorySnapshot != null
            && faultMemorySnapshot.Length == Size;

        public ulong TrackingStartAddress
        {
            get { return trackingStartAddress; }
            set
            {
                RemoveStartHook();
                configuredTrackingStartAddress = value;
                trackingStartAddress = value;
                trackingStarted = value == 0;
                if(!trackingStarted)
                {
                    ResetCampaignObservability();
                }
                UpdateHooks();
            }
        }
        public bool TrackingStarted => trackingStarted;
        public bool NativeTrackingStartReliable => true;
        public bool StartHookInstalled => startHookInstalled;
        public bool MemoryAccessHookInstalled => memoryAccessHookInstalled;

        // A native boundary snapshot avoids calling back into the monitor from
        // an active RunFor. The snapshot survives the firmware-requested reset.
        public ulong TrackingStopAddress
        {
            get { return trackingStopAddress; }
            set
            {
                RemoveStopHook();
                trackingStopAddress = value;
                trackingStopHit = false;
                trackingStopWrites = 0;
                trackingStopErases = 0;
                UpdateHooks();
            }
        }
        public bool TrackingStopHit => trackingStopHit;
        public ulong TrackingStopWrites => trackingStopWrites;
        public ulong TrackingStopErases => trackingStopErases;
        public bool StopHookInstalled => stopHookInstalled;

        public void InvalidateShadow()
        {
            flashShadow = null;
            if(memoryAccessHookInstalled)
            {
                EnsureShadow();
            }
        }

        public byte ReadByte(long offset) => BackingMemory.ReadByte(offset);
        public ushort ReadWord(long offset) => BackingMemory.ReadWord(offset);
        public uint ReadDoubleWord(long offset) => BackingMemory.ReadDoubleWord(offset);
        public ulong ReadQuadWord(long offset)
        {
            return (ulong)BackingMemory.ReadDoubleWord(offset)
                | ((ulong)BackingMemory.ReadDoubleWord(offset + 4) << 32);
        }

        // Host-side setup and snapshot restoration intentionally bypass
        // campaign accounting. CPU writes are observed through the native
        // memory-access hook below.
        public void WriteByte(long offset, byte value) => BackingMemory.WriteByte(offset, value);
        public void WriteWord(long offset, ushort value) => BackingMemory.WriteWord(offset, value);
        public void WriteDoubleWord(long offset, uint value) => BackingMemory.WriteDoubleWord(offset, value);
        public void WriteQuadWord(long offset, ulong value)
        {
            BackingMemory.WriteDoubleWord(offset, (uint)value);
            BackingMemory.WriteDoubleWord(offset + 4, (uint)(value >> 32));
        }
        public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
        {
            if(!ValidRange(offset, count))
            {
                return new byte[0];
            }
            return BackingMemory.ReadBytes(offset, count);
        }
        public void WriteBytes(long offset, byte[] array, int startingIndex, int count,
                               IPeripheral context = null)
        {
            if(array == null || startingIndex < 0 || count < 0
               || startingIndex > array.Length - count || !ValidRange(offset, count))
            {
                return;
            }
            BackingMemory.WriteBytes(offset, array, startingIndex, count);
            flashShadow = null;
        }

        public void Reset()
        {
            RemoveStartHook();
            RemoveStopHook();
            flashShadow = null;

            if(trackingStopHit || FaultEverFired)
            {
                // Keep the pre-reset calibration boundary or immediate fault
                // evidence stable. A SYSRESETREQ can occur before RunFor
                // returns, so clearing here would make an injected fault look
                // like an out-of-range request. The runner explicitly resets
                // campaign state before the next boot.
                trackingStartAddress = 0;
                trackingStarted = false;
            }
            else
            {
                trackingStartAddress = configuredTrackingStartAddress;
                trackingStarted = trackingStartAddress == 0;
                ResetCampaignObservability();
            }
            UpdateHooks();
        }

        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        private void OnMemoryWrite(ulong virtualPC, MemoryOperation operation,
                                   ulong virtualAddress, ulong physicalAddress,
                                   uint width, ulong value)
        {
            if(operation != MemoryOperation.MemoryWrite || width == 0 || !trackingStarted)
            {
                return;
            }
            long offset;
            if(!TryResolveAddress((long)virtualAddress, out offset))
            {
                return;
            }

            EnsureShadow();
            var byteCount = (int)Math.Min(width, sizeof(ulong));
            var cursor = 0;
            while(cursor < byteCount)
            {
                var writeOffset = offset + cursor;
                var unitOffset = AlignDown(writeOffset, ProgramUnitSize);
                var inUnit = checked((int)(writeOffset - unitOffset));
                var copied = Math.Min(ProgramUnitSize - inUnit, byteCount - cursor);
                var preProgram = ReadShadowUnit(unitOffset);
                var intended = CloneBytes(preProgram);
                for(var index = 0; index < copied; index++)
                {
                    intended[inUnit + index] = (byte)(value >> ((cursor + index) * 8));
                }

                var writeIndex = TotalWordWrites + 1;
                TotalWordWrites = writeIndex;
                if(WriteTraceEnabled)
                {
                    writeTrace.Add(new WriteTraceEntry(
                        writeIndex, unitOffset, LowValue(intended), ProgramUnitSize));
                }

                var faulted = !PassthroughMode && writeIndex == FaultAtWordWrite;
                byte[] postProgram;
                if(faulted)
                {
                    postProgram = ApplyFault(unitOffset, preProgram, intended);
                    LastFaultInjected = true;
                    FaultEverFired = true;
                    FaultFired = true;
                    LastFaultAddress = checked((uint)(ProgramAddressBase + (ulong)unitOffset));
                    WriteBackingUnit(unitOffset, postProgram);
                    CaptureFaultEvidence(
                        writeIndex, unitOffset, intended, preProgram, postProgram);
                }
                else
                {
                    // MappedMemory has already committed the CPU write. The
                    // full intended unit is its modeled post-program state.
                    postProgram = intended;
                }

                programTrace.Add(new ProgramTraceEntry(
                    writeIndex, unitOffset, ProgramUnitSize,
                    CloneBytes(intended), CloneBytes(preProgram),
                    CloneBytes(postProgram), faulted));
                WriteShadowUnit(unitOffset, postProgram);
                cursor += copied;
            }
        }

        private byte[] ApplyFault(long unitOffset, byte[] preProgram, byte[] intended)
        {
            var result = CloneBytes(intended);
            if(WriteFaultMode == 1)
            {
                var seed = CorruptionSeed != 0
                    ? CorruptionSeed
                    : (uint)(TotalWordWrites ^ (ulong)unitOffset);
                for(var index = 0; index < result.Length; index++)
                {
                    seed = FaultTracker.NextLcg(ref seed);
                    if((seed & 0x7) == 0)
                    {
                        seed = FaultTracker.NextLcg(ref seed);
                        var mask = (byte)(seed >> 16);
                        result[index] ^= mask == 0 ? (byte)1 : mask;
                    }
                }
            }
            else if(WriteFaultMode == 6 || WriteFaultMode == 3)
            {
                result = CloneBytes(preProgram);
                DriverErrorFired = WriteFaultMode == 6;
            }
            else
            {
                var partial = ProgramUnitSize / 2;
                for(var index = partial; index < ProgramUnitSize; index++)
                {
                    result[index] = EraseFill;
                }
            }
            return result;
        }

        private void OnTrackingStart(ICpuSupportingGdb cpu, ulong address)
        {
            RemoveStartHook();
            trackingStartAddress = 0;
            trackingStarted = true;
            ResetCampaignObservability();
            UpdateHooks();
        }

        private void OnTrackingStop(ICpuSupportingGdb cpu, ulong address)
        {
            if(trackingStopHit)
            {
                return;
            }
            trackingStopHit = true;
            trackingStopWrites = TotalWordWrites;
            trackingStopErases = TotalPageErases;
            RemoveStopHook();
        }

        private void UpdateHooks()
        {
            if(!machine.IsRegistered(this))
            {
                return;
            }
            var enabled = trackingStarted || WriteTraceEnabled
                || FaultAtWordWrite != ulong.MaxValue;
            var cpus = machine.GetSystemBus(this).GetCPUs()
                .OfType<ICPUWithMemoryAccessHooks>();
            foreach(var cpu in cpus)
            {
                cpu.SetHookAtMemoryAccess(
                    enabled && trackingStarted ? (MemoryAccessHook)OnMemoryWrite : null);
                var hookCpu = cpu as ICPUWithHooks;
                if(hookCpu == null)
                {
                    continue;
                }
                if(trackingStartAddress != 0 && !trackingStarted && !startHookInstalled)
                {
                    hookCpu.AddHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart);
                    startHookInstalled = true;
                }
                if(trackingStopAddress != 0 && !trackingStopHit && !stopHookInstalled)
                {
                    hookCpu.AddHook(trackingStopAddress, (CpuAddressHook)OnTrackingStop);
                    stopHookInstalled = true;
                }
            }
            memoryAccessHookInstalled = enabled && trackingStarted;
        }

        private void RemoveStartHook()
        {
            if(!startHookInstalled || !machine.IsRegistered(this))
            {
                startHookInstalled = false;
                return;
            }
            foreach(var cpu in machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>())
            {
                cpu.RemoveHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart);
            }
            startHookInstalled = false;
        }

        private void RemoveStopHook()
        {
            if(!stopHookInstalled || !machine.IsRegistered(this))
            {
                stopHookInstalled = false;
                return;
            }
            foreach(var cpu in machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>())
            {
                cpu.RemoveHook(trackingStopAddress, (CpuAddressHook)OnTrackingStop);
            }
            stopHookInstalled = false;
        }

        private bool TryResolveAddress(long address, out long offset)
        {
            if(address >= FlashBaseAddress && address < FlashBaseAddress + FlashSize)
            {
                offset = address - FlashBaseAddress;
                return true;
            }
            offset = 0;
            return false;
        }

        private bool ValidRange(long offset, int count)
        {
            return BackingMemory != null && offset >= 0 && count >= 0
                && offset <= Size - count;
        }

        private void EnsureShadow()
        {
            if(flashShadow == null && BackingMemory != null)
            {
                flashShadow = BackingMemory.ReadBytes(0, checked((int)Size));
            }
        }

        private byte[] ReadShadowUnit(long offset)
        {
            var result = new byte[ProgramUnitSize];
            Array.Copy(flashShadow, checked((int)offset), result, 0, ProgramUnitSize);
            return result;
        }

        private void WriteShadowUnit(long offset, byte[] data)
        {
            Array.Copy(data, 0, flashShadow, checked((int)offset), data.Length);
        }

        private void WriteBackingUnit(long offset, byte[] data)
        {
            BackingMemory.WriteBytes(offset, data, 0, data.Length);
        }

        private void CaptureFaultEvidence(ulong index, long offset, byte[] intended,
                                          byte[] preProgram, byte[] postFault)
        {
            lastFaultWriteIndex = index;
            lastFaultOffset = offset;
            lastFaultProgramAddress = ProgramAddressBase + (ulong)offset;
            lastFaultProgramWidth = ProgramUnitSize;
            lastFaultIntendedBytes = CloneBytes(intended);
            lastFaultPreProgramBytes = CloneBytes(preProgram);
            lastFaultPostFaultBytes = CloneBytes(postFault);
            faultMemorySnapshot = BackingMemory.ReadBytes(0, checked((int)Size));
        }

        private void ResetCampaignObservability()
        {
            TotalWordWrites = 0;
            TotalPageErases = 0;
            FaultFired = false;
            LastFaultInjected = false;
            FaultEverFired = false;
            DriverErrorFired = false;
            writeTrace.Clear();
            programTrace.Clear();
            ClearFaultEvidence();
            flashShadow = null;
        }

        private void ClearFaultEvidence()
        {
            lastFaultWriteIndex = 0;
            lastFaultProgramAddress = 0;
            lastFaultOffset = -1;
            lastFaultProgramWidth = 0;
            lastFaultIntendedBytes = null;
            lastFaultPreProgramBytes = null;
            lastFaultPostFaultBytes = null;
            faultMemorySnapshot = null;
        }

        private static long AlignDown(long value, int alignment)
        {
            return value & ~(alignment - 1L);
        }

        private static ulong LowValue(byte[] data)
        {
            ulong result = 0;
            var count = Math.Min(data.Length, sizeof(ulong));
            for(var index = 0; index < count; index++)
            {
                result |= (ulong)data[index] << (index * 8);
            }
            return result;
        }

        private static byte[] CloneBytes(byte[] source)
        {
            if(source == null)
            {
                return null;
            }
            var result = new byte[source.Length];
            Array.Copy(source, result, source.Length);
            return result;
        }

        private static void AppendHex(StringBuilder builder, byte[] data)
        {
            foreach(var value in data)
            {
                builder.Append(value.ToString("x2"));
            }
        }

        private readonly IMachine machine;
        private readonly List<WriteTraceEntry> writeTrace = new List<WriteTraceEntry>();
        private readonly List<ProgramTraceEntry> programTrace = new List<ProgramTraceEntry>();
        private int programUnitSize = 16;
        private ulong programAddressBase;
        private ulong faultAtWordWrite = ulong.MaxValue;
        private int writeFaultMode;
        private bool writeTraceEnabled;
        private byte[] flashShadow;
        private ulong configuredTrackingStartAddress;
        private ulong trackingStartAddress;
        private bool trackingStarted = true;
        private bool startHookInstalled;
        private bool memoryAccessHookInstalled;
        private ulong trackingStopAddress;
        private bool trackingStopHit;
        private ulong trackingStopWrites;
        private ulong trackingStopErases;
        private bool stopHookInstalled;
        private ulong lastFaultWriteIndex;
        private ulong lastFaultProgramAddress;
        private long lastFaultOffset = -1;
        private int lastFaultProgramWidth;
        private byte[] lastFaultIntendedBytes;
        private byte[] lastFaultPreProgramBytes;
        private byte[] lastFaultPostFaultBytes;
        private byte[] faultMemorySnapshot;

        private sealed class WriteTraceEntry
        {
            public WriteTraceEntry(ulong index, long offset, ulong value, int width)
            {
                Index = index;
                Offset = offset;
                Value = value;
                Width = width;
            }
            public readonly ulong Index;
            public readonly long Offset;
            public readonly ulong Value;
            public readonly int Width;
        }

        private sealed class ProgramTraceEntry
        {
            public ProgramTraceEntry(ulong index, long offset, int width,
                                     byte[] intended, byte[] preProgram,
                                     byte[] postProgram, bool faulted)
            {
                Index = index;
                Offset = offset;
                Width = width;
                Intended = intended;
                PreProgram = preProgram;
                PostProgram = postProgram;
                Faulted = faulted;
            }
            public readonly ulong Index;
            public readonly long Offset;
            public readonly int Width;
            public readonly byte[] Intended;
            public readonly byte[] PreProgram;
            public readonly byte[] PostProgram;
            public readonly bool Faulted;
        }
    }
}
