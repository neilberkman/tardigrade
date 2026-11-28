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
using Antmicro.Renode.Peripherals.IRQControllers;
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
        public bool AnyFaultFired => FaultEverFired || EraseFaultFired;
        public bool FaultRequiresImmediateStop => EraseFaultFired || (FaultEverFired && WriteFaultMode == 0);
        public uint LastFaultAddress { get; set; }
        public ulong LastFaultPC { get; set; }
        public string LastFaultCallContext { get; set; }
        private ulong cachedStackStart;
        private ulong cachedStackEnd;
        private readonly Dictionary<ulong, string> writeCallContexts = new Dictionary<ulong, string>();
        private readonly Dictionary<ulong, string> eraseCallContexts = new Dictionary<ulong, string>();

        private string CaptureCpuCallContext(ulong overridePc = 0)
        {
            return FaultTracker.CaptureCpuCallContext(
                machine, this, ref cachedStackStart, ref cachedStackEnd, overridePc);
        }

        public string WriteCallContextToString()
        {
            if(writeCallContexts.Count == 0)
            {
                return string.Empty;
            }
            var sb = new StringBuilder(writeCallContexts.Count * 128);
            foreach(var kv in writeCallContexts.OrderBy(k => k.Key))
            {
                if(!string.IsNullOrEmpty(kv.Value))
                {
                    sb.Append(kv.Key).Append(':').Append(kv.Value).Append('\n');
                }
            }
            return sb.ToString();
        }

        public string EraseCallContextToString()
        {
            if(eraseCallContexts.Count == 0)
            {
                return string.Empty;
            }
            var sb = new StringBuilder(eraseCallContexts.Count * 128);
            foreach(var kv in eraseCallContexts.OrderBy(k => k.Key))
            {
                if(!string.IsNullOrEmpty(kv.Value))
                {
                    sb.Append(kv.Key).Append(':').Append(kv.Value).Append('\n');
                }
            }
            return sb.ToString();
        }
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
        public uint MramTornWordSeed { get; set; }
        public string MramTornWordMode
        {
            get { return mramTornWordMode; }
            set
            {
                var normalized = (value ?? "half").Trim().ToLowerInvariant();
                if(normalized != "half" && normalized != "half_retain"
                   && normalized != "untouched" && normalized != "erased"
                   && normalized != "programmed" && normalized != "uncorrectable"
                   && normalized != "corrupted")
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(value),
                        "MramTornWordMode must be half, half_retain, untouched, erased, programmed, uncorrectable, or corrupted");
                }
                mramTornWordMode = normalized;
            }
        }
        public int UncorrectableWordCount => uncorrectableWords.Count;
        public bool LastFaultMarkedUncorrectable => lastFaultMarkedUncorrectable;
        public ulong UncorrectableReadCount => uncorrectableReadCount;
        public ulong LastUncorrectableReadWordAddress => lastUncorrectableReadWordAddress;
        public ulong LastUncorrectableReadAddress => lastUncorrectableReadAddress;
        public ulong LastUncorrectableReadPC => lastUncorrectableReadPC;

        public bool IsWordUncorrectable(long offset)
        {
            if(offset < 0 || offset >= Size)
            {
                return false;
            }
            return uncorrectableWords.Contains(AlignDown(offset, ProgramUnitSize));
        }

        public bool IsAddressUncorrectable(ulong busAddress)
        {
            long offset;
            if(!TryResolveBusAddress(busAddress, out offset))
            {
                return false;
            }
            return IsWordUncorrectable(offset);
        }

        public void MarkWordUncorrectable(long offset)
        {
            if(offset < 0 || offset >= Size)
            {
                return;
            }
            MarkWordUncorrectableInternal(AlignDown(offset, ProgramUnitSize));
            UpdateHooks();
        }

        public void ClearUncorrectableWord(long offset)
        {
            if(offset < 0 || offset >= Size)
            {
                return;
            }
            if(uncorrectableWords.Remove(AlignDown(offset, ProgramUnitSize)))
            {
                UpdateHooks();
            }
        }

        public void ClearUncorrectableWords()
        {
            var hadWords = uncorrectableWords.Count > 0;
            uncorrectableWords.Clear();
            ClearUncorrectableReadLog();
            if(hadWords)
            {
                UpdateHooks();
            }
        }

        public string UncorrectableWordsToString()
        {
            return FormatWordOffsets(uncorrectableWords);
        }

        public string FaultUncorrectableWordsToString()
        {
            return FormatWordOffsets(faultUncorrectableWords);
        }

        private string FormatWordOffsets(IEnumerable<long> offsets)
        {
            var sorted = new List<long>(offsets);
            if(sorted.Count == 0)
            {
                return string.Empty;
            }
            sorted.Sort();
            var result = new StringBuilder(sorted.Count * 24);
            foreach(var unitOffset in sorted)
            {
                result.Append(unitOffset);
                result.Append(':');
                result.Append("0x");
                result.Append((ProgramAddressBase + (ulong)unitOffset).ToString("X8"));
                result.Append('\n');
            }
            return result.ToString();
        }

        public string UncorrectableReadsToString()
        {
            if(uncorrectableReads.Count == 0)
            {
                return string.Empty;
            }
            var result = new StringBuilder(uncorrectableReads.Count * 64);
            foreach(var entry in uncorrectableReads)
            {
                result.Append(entry.Index);
                result.Append(':');
                result.Append(entry.WordOffset);
                result.Append(":0x");
                result.Append(entry.WordBusAddress.ToString("X8"));
                result.Append(":0x");
                result.Append(entry.AccessBusAddress.ToString("X8"));
                result.Append(':');
                result.Append(entry.Width);
                result.Append(":0x");
                result.Append(entry.PC.ToString("X8"));
                result.Append('\n');
            }
            return result.ToString();
        }

        public void ClearUncorrectableReadLog()
        {
            uncorrectableReads.Clear();
            uncorrectableReadCount = 0;
            lastUncorrectableReadWordAddress = 0;
            lastUncorrectableReadAddress = 0;
            lastUncorrectableReadPC = 0;
        }
        public bool PreserveCountersAcrossReset { get; set; }
        public int DiffLookahead { get; set; } = 32;
        public bool SkipShadowScan { get; set; } = true;
        public bool PassthroughMode { get; set; }

        public ulong TotalPageErases { get; set; }
        public ulong FaultAtPageErase
        {
            get { return faultAtPageErase; }
            set
            {
                faultAtPageErase = value;
                if(value != ulong.MaxValue && trackingStarted)
                {
                    EnsureShadow();
                }
            }
        }
        public bool EraseFaultFired { get; set; }
        public bool EraseTraceEnabled { get; set; }
        public int EraseTraceCount => eraseTrace.Count;
        public string EraseTraceToString()
        {
            if(eraseTrace.Count == 0)
            {
                return string.Empty;
            }
            var result = new StringBuilder(eraseTrace.Count * 40);
            foreach(var entry in eraseTrace)
            {
                result.Append(entry.Index);
                result.Append(':');
                result.Append(entry.Offset);
                result.Append(':');
                result.Append(entry.WritesAt);
                result.Append(':');
                result.Append(entry.EraseSize);
                if(entry.PC != 0)
                {
                    result.Append(":0x");
                    result.Append(entry.PC.ToString("X8"));
                }
                result.Append('\n');
            }
            return result.ToString();
        }
        public void EraseTraceClear()
        {
            eraseTrace.Clear();
            eraseCallContexts.Clear();
        }

        // Optional MMIO erase trigger registers (disabled by default at -1 so
        // existing direct-memory sidecar accesses remain completely unchanged).
        public long EraseSizeRegisterOffset { get; set; } = -1;
        public long EraseAddressRegisterOffset { get; set; } = -1;
        public long EraseWordRegisterOffset { get; set; } = -1;

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
            var result = new StringBuilder(writeTrace.Count * 48);
            foreach(var entry in writeTrace)
            {
                result.Append(entry.Index);
                result.Append(':');
                result.Append(entry.Offset);
                result.Append(':');
                result.Append(entry.Value);
                result.Append(':');
                result.Append(entry.Width);
                if(entry.PC != 0)
                {
                    result.Append(":0x");
                    result.Append(entry.PC.ToString("X8"));
                }
                result.Append('\n');
            }
            return result.ToString();
        }
        public void WriteTraceClear()
        {
            writeTrace.Clear();
        }

        public RecoveryTraceTimes TraceTimes { get; } = new RecoveryTraceTimes();

        public int ProgramTraceCount => programTrace.Count;
        public string ProgramTraceToString()
        {
            var result = new StringBuilder(programTrace.Count * 140);
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
                if(entry.PC != 0)
                {
                    result.Append(":0x");
                    result.Append(entry.PC.ToString("X8"));
                }
                result.Append('\n');
            }
            return result.ToString();
        }
        public void ProgramTraceClear()
        {
            programTrace.Clear();
            writeCallContexts.Clear();
            ClearFaultEvidence();
        }

        public bool TrackingBaseSnapshotAvailable =>
            trackingBaseSnapshot != null
            && trackingBaseSnapshot.Length == Size;
        public byte[] TrackingBaseSnapshot => CloneBytes(trackingBaseSnapshot);
        public int TrackingBaseSnapshotSize =>
            trackingBaseSnapshot != null ? trackingBaseSnapshot.Length : 0;
        public string TrackingBaseUncorrectableWordsToString()
        {
            return FormatWordOffsets(trackingBaseUncorrectableWords);
        }
        public void TrackingBaseSnapshotClear()
        {
            trackingBaseSnapshot = null;
            trackingBaseUncorrectableWords.Clear();
        }

        public ulong LastFaultWriteIndex => lastFaultWriteIndex;
        public ulong LastFaultEraseIndex => lastFaultEraseIndex;
        public ulong LastFaultProgramAddress => lastFaultProgramAddress;
        public long LastFaultOffset => lastFaultOffset;
        public int LastFaultProgramWidth => lastFaultProgramWidth;
        public int LastFaultEraseSize => lastFaultProgramWidth;
        public byte[] LastFaultIntendedBytes => CloneBytes(lastFaultIntendedBytes);
        public byte[] LastFaultPreProgramBytes => CloneBytes(lastFaultPreProgramBytes);
        public byte[] LastFaultPreEraseBytes => CloneBytes(lastFaultPreProgramBytes);
        public byte[] LastFaultPostFaultBytes => CloneBytes(lastFaultPostFaultBytes);
        public byte[] LastFaultPostEraseBytes => CloneBytes(lastFaultPostFaultBytes);
        public byte[] FaultMemorySnapshot => CloneBytes(faultMemorySnapshot);
        public int FaultMemorySnapshotSize => faultMemorySnapshot != null ? faultMemorySnapshot.Length : 0;
        public bool FaultEvidenceExact =>
            ((lastFaultWriteIndex != 0 && lastFaultProgramWidth == ProgramUnitSize)
             || (lastFaultEraseIndex != 0 && lastFaultProgramWidth > 0))
            && lastFaultOffset >= 0
            && lastFaultIntendedBytes != null
            && lastFaultIntendedBytes.Length == lastFaultProgramWidth
            && lastFaultPreProgramBytes != null
            && lastFaultPreProgramBytes.Length == lastFaultProgramWidth
            && lastFaultPostFaultBytes != null
            && lastFaultPostFaultBytes.Length == lastFaultProgramWidth
            && faultMemorySnapshot != null
            && faultMemorySnapshot.Length == Size;
        public bool EraseFaultEvidenceExact =>
            lastFaultEraseIndex != 0 && FaultEvidenceExact;

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
                    TrackingBaseSnapshotClear();
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
        public void WriteByte(long offset, byte value)
        {
            BackingMemory.WriteByte(offset, value);
            ClearUncorrectableRange(offset, 1);
        }
        public void WriteWord(long offset, ushort value)
        {
            BackingMemory.WriteWord(offset, value);
            ClearUncorrectableRange(offset, 2);
        }
        public void WriteDoubleWord(long offset, uint value)
        {
            if(EraseSizeRegisterOffset >= 0 && offset == EraseSizeRegisterOffset)
            {
                mmioEraseSize = value;
                return;
            }
            if(EraseAddressRegisterOffset >= 0 && offset == EraseAddressRegisterOffset)
            {
                if(TryResolveBusAddress((ulong)value, out var targetOffset))
                {
                    var sectorLen = mmioEraseSize != 0U
                        ? checked((int)mmioEraseSize)
                        : (PageSize > 0 ? PageSize : 0x1000);
                    EraseSector(targetOffset, sectorLen);
                }
                return;
            }
            if(EraseWordRegisterOffset >= 0 && offset == EraseWordRegisterOffset)
            {
                if(TryResolveBusAddress((ulong)value, out var wordOffset))
                {
                    EraseWord(wordOffset);
                }
                return;
            }
            BackingMemory.WriteDoubleWord(offset, value);
            ClearUncorrectableRange(offset, 4);
        }
        public void WriteQuadWord(long offset, ulong value)
        {
            BackingMemory.WriteDoubleWord(offset, (uint)value);
            BackingMemory.WriteDoubleWord(offset + 4, (uint)(value >> 32));
            ClearUncorrectableRange(offset, 8);
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
            ClearUncorrectableRange(offset, count);
            flashShadow = null;
        }

        public void EraseWord(long offset)
        {
            if(offset < 0 || offset >= Size)
            {
                return;
            }
            var unitOffset = AlignDown(offset, ProgramUnitSize);
            if(!ValidRange(unitOffset, ProgramUnitSize))
            {
                return;
            }
            EraseSpan(unitOffset, ProgramUnitSize);
        }

        public void EraseSector(long offset, int sectorSize)
        {
            if(sectorSize <= 0 || !ValidRange(offset, sectorSize))
            {
                return;
            }
            EraseSpan(offset, sectorSize);
        }

        private ulong CurrentCpuPc()
        {
            if(!machine.IsRegistered(this))
            {
                return 0UL;
            }
            ICPU cpu;
            var bus = machine.GetSystemBus(this);
            if(bus != null && bus.TryGetCurrentCPU(out cpu) && cpu != null)
            {
                return cpu.PC.RawValue;
            }
            return 0UL;
        }

        private void EraseSpan(long offset, int spanSize)
        {
            if(!trackingStarted)
            {
                WriteErasedSpanRaw(offset, spanSize);
                return;
            }

            if(!PassthroughMode && EraseFaultFired)
            {
                // Power has already been cut during an erase; suppress further erases.
                return;
            }

            var erasePc = CurrentCpuPc();
            var eraseCtx = CaptureCpuCallContext(erasePc);
            var eraseIndex = TotalPageErases + 1;
            TotalPageErases = eraseIndex;
            if(EraseTraceEnabled || (!PassthroughMode && faultAtPageErase != ulong.MaxValue))
            {
                TraceTimes.Record(true, eraseIndex);
                eraseTrace.Add(new EraseTraceEntry(
                    eraseIndex, offset, TotalWordWrites, spanSize, erasePc));
                if(!string.IsNullOrEmpty(eraseCtx))
                {
                    eraseCallContexts[eraseIndex] = eraseCtx;
                }
            }

            if(!PassthroughMode && eraseIndex == faultAtPageErase)
            {
                EnsureShadow();
                var preErase = BackingMemory.ReadBytes(offset, spanSize);
                lastFaultMarkedUncorrectable = false;
                var postErase = ApplyTornEraseSpan(offset, spanSize, preErase, eraseIndex);
                BackingMemory.WriteBytes(offset, postErase, 0, postErase.Length);
                if(flashShadow != null)
                {
                    Array.Copy(postErase, 0, flashShadow, checked((int)offset), postErase.Length);
                }
                var intendedErase = new byte[spanSize];
                if(EraseFill != 0)
                {
                    for(var i = 0; i < intendedErase.Length; i++)
                    {
                        intendedErase[i] = EraseFill;
                    }
                }
                EraseFaultFired = true;
                LastFaultInjected = true;
                LastFaultAddress = checked((uint)(ProgramAddressBase + (ulong)offset));
                LastFaultPC = erasePc;
                LastFaultCallContext = eraseCtx;
                lastFaultWriteIndex = 0;
                lastFaultEraseIndex = eraseIndex;
                lastFaultOffset = offset;
                lastFaultProgramAddress = ProgramAddressBase + (ulong)offset;
                lastFaultProgramWidth = spanSize;
                lastFaultIntendedBytes = intendedErase;
                lastFaultPreProgramBytes = CloneBytes(preErase);
                lastFaultPostFaultBytes = CloneBytes(postErase);
                faultMemorySnapshot = BackingMemory.ReadBytes(0, checked((int)Size));
                faultUncorrectableWords.Clear();
                faultUncorrectableWords.AddRange(uncorrectableWords);
                if(lastFaultMarkedUncorrectable)
                {
                    UpdateHooks();
                }
                return;
            }

            WriteErasedSpanRaw(offset, spanSize);
        }

        private void WriteErasedSpanRaw(long offset, int spanSize)
        {
            var erased = new byte[spanSize];
            if(EraseFill != 0)
            {
                for(var i = 0; i < erased.Length; i++)
                {
                    erased[i] = EraseFill;
                }
            }
            BackingMemory.WriteBytes(offset, erased, 0, erased.Length);
            ClearUncorrectableRange(offset, spanSize);
            if(flashShadow != null)
            {
                Array.Copy(erased, 0, flashShadow, checked((int)offset), erased.Length);
            }
        }

        private byte[] ApplyTornEraseSpan(long offset, int spanSize, byte[] preErase, ulong eraseIndex)
        {
            if(EraseFaultMode == 1)
            {
                var multiResult = CloneBytes(preErase);
                var halfSpan = Math.Max(1, spanSize / 2);
                for(var i = 0; i < halfSpan; i++)
                {
                    multiResult[i] = EraseFill;
                }
                ClearUncorrectableRange(offset, halfSpan);
                var quarterSpan = Math.Max(1, spanSize / 4);
                var neighbor = offset + spanSize;
                if(ValidRange(neighbor, quarterSpan))
                {
                    WriteErasedSpanRaw(neighbor, quarterSpan);
                }
                return multiResult;
            }

            var mode = mramTornWordMode;
            byte[] result;
            switch(mode)
            {
                case "untouched":
                    result = CloneBytes(preErase);
                    break;
                case "erased":
                case "programmed":
                    result = new byte[spanSize];
                    if(EraseFill != 0)
                    {
                        for(var i = 0; i < spanSize; i++)
                        {
                            result[i] = EraseFill;
                        }
                    }
                    ClearUncorrectableRange(offset, spanSize);
                    break;
                case "uncorrectable":
                    result = CloneBytes(preErase);
                    var firstUnit = AlignDown(offset, ProgramUnitSize);
                    var lastUnit = AlignDown(offset + spanSize - 1, ProgramUnitSize);
                    for(var unit = firstUnit; unit <= lastUnit; unit += ProgramUnitSize)
                    {
                        MarkWordUncorrectableInternal(unit);
                    }
                    lastFaultMarkedUncorrectable = true;
                    break;
                case "corrupted":
                    result = new byte[spanSize];
                    if(EraseFill != 0)
                    {
                        for(var i = 0; i < spanSize; i++)
                        {
                            result[i] = EraseFill;
                        }
                    }
                    ClearUncorrectableRange(offset, spanSize);
                    var cFirst = AlignDown(offset, ProgramUnitSize);
                    var cLast = AlignDown(offset + spanSize - 1, ProgramUnitSize);
                    for(var unit = cFirst; unit <= cLast; unit += ProgramUnitSize)
                    {
                        var segStart = Math.Max(offset, unit);
                        var segEnd = Math.Min(offset + spanSize, unit + ProgramUnitSize);
                        var segLen = checked((int)(segEnd - segStart));
                        var unitBytes = new byte[segLen];
                        Array.Copy(result, checked((int)(segStart - offset)), unitBytes, 0, segLen);
                        ApplyCorruptedTornWord(unitBytes, eraseIndex, unit, EffectiveMramTornWordSeed());
                        Array.Copy(unitBytes, 0, result, checked((int)(segStart - offset)), segLen);
                    }
                    break;
                default:
                    result = CloneBytes(preErase);
                    var half = spanSize / 2;
                    if(half <= 0 && spanSize > 0)
                    {
                        half = spanSize;
                    }
                    for(var i = 0; i < half; i++)
                    {
                        result[i] = EraseFill;
                    }
                    if(half > 0)
                    {
                        ClearUncorrectableRange(offset, half);
                    }
                    break;
            }
            return result;
        }

        public void Reset()
        {
            RemoveStartHook();
            RemoveStopHook();
            mmioEraseSize = 0;

            if(trackingStopHit || FaultEverFired)
            {
                // Keep the pre-reset calibration boundary or immediate fault
                // evidence stable. A SYSRESETREQ can occur before RunFor
                // returns, so clearing here would make an injected fault look
                // like an out-of-range request. The runner explicitly resets
                // campaign state before the next boot.
                flashShadow = null;
                trackingStartAddress = 0;
                trackingStarted = false;
            }
            else if(EraseFaultFired)
            {
                flashShadow = null;
                trackingStartAddress = 0;
                trackingStarted = false;
            }
            else if(PreserveCountersAcrossReset)
            {
                // Preserve campaign counters, traces, and shadow bytes across
                // a firmware-initiated reset within one run. When tracking has
                // already started, keep it active without re-arming the start
                // address hook so post-reset writes advance the same counter.
                if(trackingStarted)
                {
                    trackingStartAddress = 0;
                }
                else
                {
                    trackingStartAddress = configuredTrackingStartAddress;
                }
            }
            else
            {
                flashShadow = null;
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

        private void OnMemoryAccess(ulong virtualPC, MemoryOperation operation,
                                    ulong virtualAddress, ulong physicalAddress,
                                    uint width, ulong value)
        {
            if(operation == MemoryOperation.MemoryRead
               || operation == MemoryOperation.MemoryIORead
               || operation == MemoryOperation.InsnFetch)
            {
                if(uncorrectableWords.Count == 0)
                {
                    return;
                }
                long readOffset;
                if(!TryResolveAddress((long)virtualAddress, out readOffset))
                {
                    return;
                }
                var accessWidth = Math.Max(1, (int)Math.Min(width == 0 ? 1u : width, (uint)sizeof(ulong)));
                var firstUnit = AlignDown(readOffset, ProgramUnitSize);
                var lastUnit = AlignDown(readOffset + accessWidth - 1, ProgramUnitSize);
                long hitUnit = -1;
                for(var unit = firstUnit; unit <= lastUnit; unit += ProgramUnitSize)
                {
                    if(uncorrectableWords.Contains(unit))
                    {
                        hitUnit = unit;
                        break;
                    }
                }
                if(hitUnit >= 0)
                {
                    RecordUncorrectableRead(hitUnit, readOffset, accessWidth, virtualPC);
                    ICPU cpu;
                    var bus = machine.GetSystemBus(this);
                    if(!bus.TryGetCurrentCPU(out cpu) || cpu == null)
                    {
                        cpu = bus.GetCPUs().FirstOrDefault();
                    }
                    RaiseBusError(cpu);
                }
                return;
            }

            if((operation != MemoryOperation.MemoryWrite
                && operation != MemoryOperation.MemoryIOWrite)
               || width == 0)
            {
                return;
            }
            long offset;
            if(!TryResolveAddress((long)virtualAddress, out offset))
            {
                return;
            }

            var byteCount = (int)Math.Min(width, sizeof(ulong));
            if(!trackingStarted)
            {
                // Programming a marked MRAM word clears its ECC error even
                // outside the campaign tracking gate.
                ClearUncorrectableRange(offset, byteCount);
                return;
            }

            EnsureShadow();
            var writePowerLossLatched = FaultEverFired && WriteFaultMode == 0;
            if(!PassthroughMode && (EraseFaultFired || writePowerLossLatched))
            {
                // Power has already been cut. Revert any later fast-path CPU
                // write to the pre-cut shadow bytes and suppress its accounting.
                // This also catches the second store of a multi-store CPU
                // instruction when its first store triggered the cut.
                var revertFirst = AlignDown(offset, ProgramUnitSize);
                var revertLast = AlignDown(offset + byteCount - 1, ProgramUnitSize);
                for(var rUnit = revertFirst; rUnit <= revertLast; rUnit += ProgramUnitSize)
                {
                    WriteBackingUnit(rUnit, ReadShadowUnit(rUnit));
                }
                return;
            }
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
                var writeCtx = CaptureCpuCallContext(virtualPC);
                if(!string.IsNullOrEmpty(writeCtx))
                {
                    writeCallContexts[writeIndex] = writeCtx;
                }
                if(WriteTraceEnabled)
                {
                    writeTrace.Add(new WriteTraceEntry(
                        writeIndex, unitOffset, LowValue(intended), ProgramUnitSize, virtualPC));
                }

                var faulted = !PassthroughMode && writeIndex == FaultAtWordWrite;
                byte[] postProgram;
                if(faulted)
                {
                    var markedBefore = uncorrectableWords.Contains(unitOffset);
                    lastFaultMarkedUncorrectable = false;
                    postProgram = ApplyFault(unitOffset, preProgram, intended);
                    if(WriteFaultMode == 0 && mramTornWordMode == "uncorrectable")
                    {
                        lastFaultMarkedUncorrectable = true;
                    }
                    else if(WriteFaultMode != 6 && WriteFaultMode != 3 && markedBefore)
                    {
                        uncorrectableWords.Remove(unitOffset);
                    }
                    LastFaultInjected = true;
                    FaultEverFired = true;
                    FaultFired = true;
                    LastFaultAddress = checked((uint)(ProgramAddressBase + (ulong)unitOffset));
                    LastFaultPC = virtualPC;
                    LastFaultCallContext = writeCtx;
                    WriteBackingUnit(unitOffset, postProgram);
                    CaptureFaultEvidence(
                        writeIndex, unitOffset, intended, preProgram, postProgram);
                    if(lastFaultMarkedUncorrectable)
                    {
                        UpdateHooks();
                    }
                }
                else
                {
                    // MappedMemory has already committed the CPU write. The
                    // full intended unit is its modeled post-program state.
                    postProgram = intended;
                    uncorrectableWords.Remove(unitOffset);
                }

                TraceTimes.Record(false, writeIndex);
                programTrace.Add(new ProgramTraceEntry(
                    writeIndex, unitOffset, ProgramUnitSize,
                    CloneBytes(intended), CloneBytes(preProgram),
                    CloneBytes(postProgram), faulted, virtualPC));
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
                switch(mramTornWordMode)
                {
                    case "half_retain":
                        var retainSplit = ProgramUnitSize / 2;
                        for(var index = retainSplit; index < ProgramUnitSize; index++)
                        {
                            result[index] = preProgram[index];
                        }
                        break;
                    case "untouched":
                        result = CloneBytes(preProgram);
                        break;
                    case "erased":
                        for(var index = 0; index < ProgramUnitSize; index++)
                        {
                            result[index] = EraseFill;
                        }
                        break;
                    case "programmed":
                        result = CloneBytes(intended);
                        break;
                    case "uncorrectable":
                        result = CloneBytes(preProgram);
                        MarkWordUncorrectableInternal(unitOffset);
                        break;
                    case "corrupted":
                        result = CloneBytes(intended);
                        ApplyCorruptedTornWord(result, TotalWordWrites, unitOffset, EffectiveMramTornWordSeed());
                        break;
                    default:
                        var partial = ProgramUnitSize / 2;
                        for(var index = partial; index < ProgramUnitSize; index++)
                        {
                            result[index] = EraseFill;
                        }
                        break;
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
            CaptureTrackingBaseState();
            UpdateHooks();
            if(memoryAccessHookInstalled)
            {
                EnsureShadow();
            }
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
            var writeTrackingActive = trackingStarted;
            var hookNeeded = writeTrackingActive || uncorrectableWords.Count > 0;
            var cpus = machine.GetSystemBus(this).GetCPUs()
                .OfType<ICPUWithMemoryAccessHooks>();
            foreach(var cpu in cpus)
            {
                cpu.SetHookAtMemoryAccess(
                    hookNeeded ? (MemoryAccessHook)OnMemoryAccess : null);
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
            memoryAccessHookInstalled = hookNeeded;
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
            lastFaultEraseIndex = 0;
            lastFaultOffset = offset;
            lastFaultProgramAddress = ProgramAddressBase + (ulong)offset;
            lastFaultProgramWidth = ProgramUnitSize;
            lastFaultIntendedBytes = CloneBytes(intended);
            lastFaultPreProgramBytes = CloneBytes(preProgram);
            lastFaultPostFaultBytes = CloneBytes(postFault);
            faultMemorySnapshot = BackingMemory.ReadBytes(0, checked((int)Size));
            faultUncorrectableWords.Clear();
            faultUncorrectableWords.AddRange(uncorrectableWords);
        }

        private void ResetCampaignObservability()
        {
            TotalWordWrites = 0;
            TotalPageErases = 0;
            FaultFired = false;
            EraseFaultFired = false;
            LastFaultInjected = false;
            FaultEverFired = false;
            DriverErrorFired = false;
            LastFaultAddress = 0;
            LastFaultPC = 0;
            LastFaultCallContext = null;
            writeTrace.Clear();
            writeCallContexts.Clear();
            eraseTrace.Clear();
            eraseCallContexts.Clear();
            programTrace.Clear();
            ClearFaultEvidence();
            flashShadow = null;
        }

        private void CaptureTrackingBaseState()
        {
            if(BackingMemory == null || Size < 0 || Size > int.MaxValue)
            {
                TrackingBaseSnapshotClear();
                return;
            }
            trackingBaseSnapshot = BackingMemory.ReadBytes(0, checked((int)Size));
            trackingBaseUncorrectableWords.Clear();
            trackingBaseUncorrectableWords.AddRange(uncorrectableWords);
        }

        private void ClearFaultEvidence()
        {
            lastFaultWriteIndex = 0;
            lastFaultEraseIndex = 0;
            lastFaultProgramAddress = 0;
            lastFaultOffset = -1;
            lastFaultProgramWidth = 0;
            lastFaultIntendedBytes = null;
            lastFaultPreProgramBytes = null;
            lastFaultPostFaultBytes = null;
            faultMemorySnapshot = null;
            lastFaultMarkedUncorrectable = false;
            faultUncorrectableWords.Clear();
        }

        private bool TryResolveBusAddress(ulong busAddress, out long offset)
        {
            var baseAddr = ProgramAddressBase;
            if(busAddress >= baseAddr && busAddress < baseAddr + (ulong)Size)
            {
                offset = checked((long)(busAddress - baseAddr));
                return true;
            }
            return TryResolveAddress(checked((long)busAddress), out offset);
        }

        private uint EffectiveMramTornWordSeed()
        {
            return MramTornWordSeed != 0 ? MramTornWordSeed : CorruptionSeed;
        }

        private static void ApplyCorruptedTornWord(byte[] wordBytes, ulong writeIndex,
                                                   long wordOffset, uint seedValue)
        {
            var totalBits = wordBytes.Length * 8;
            if(totalBits <= 0)
            {
                return;
            }
            var seed = seedValue != 0 ? seedValue : 0x5A3C96A5u;
            seed ^= unchecked((uint)writeIndex * 2654435761u);
            seed ^= unchecked((uint)wordOffset * 2246822519u);
            if(seed == 0)
            {
                seed = 0x9E3779B9u;
            }
            seed = unchecked(seed * 1103515245u + 12345u);
            var flipCount = Math.Min(totalBits, 3 + (int)(seed % 3u));
            var flipped = new bool[totalBits];
            for(var i = 0; i < flipCount; i++)
            {
                seed = unchecked(seed * 1103515245u + 12345u);
                var bitPos = (int)(seed % (uint)totalBits);
                while(flipped[bitPos])
                {
                    bitPos = (bitPos + 1) % totalBits;
                }
                flipped[bitPos] = true;
                wordBytes[bitPos / 8] ^= (byte)(1 << (bitPos % 8));
            }
        }

        private void MarkWordUncorrectableInternal(long unitOffset)
        {
            uncorrectableWords.Add(AlignDown(unitOffset, ProgramUnitSize));
        }

        private void ClearUncorrectableRange(long offset, int count)
        {
            if(uncorrectableWords.Count == 0 || count <= 0 || offset < 0)
            {
                return;
            }
            var firstUnit = AlignDown(offset, ProgramUnitSize);
            var lastUnit = AlignDown(offset + count - 1, ProgramUnitSize);
            var removed = false;
            for(var unit = firstUnit; unit <= lastUnit; unit += ProgramUnitSize)
            {
                if(uncorrectableWords.Remove(unit))
                {
                    removed = true;
                }
            }
            if(removed && uncorrectableWords.Count == 0)
            {
                UpdateHooks();
            }
        }

        private void RecordUncorrectableRead(long wordOffset, long accessOffset, int width, ulong pc)
        {
            var wordBusAddr = ProgramAddressBase + (ulong)wordOffset;
            var accessBusAddr = ProgramAddressBase + (ulong)accessOffset;
            uncorrectableReadCount++;
            lastUncorrectableReadWordAddress = wordBusAddr;
            lastUncorrectableReadAddress = accessBusAddr;
            lastUncorrectableReadPC = pc;
            if(uncorrectableReads.Count < 256)
            {
                uncorrectableReads.Add(new UncorrectableReadEntry(
                    uncorrectableReadCount, wordOffset, wordBusAddr, accessBusAddr, width, pc));
            }
        }

        private void RaiseBusError(ICPU cpu)
        {
            if(cpu == null || machine == null)
            {
                return;
            }
            var cortexM = cpu as CortexM;
            if(cortexM != null)
            {
                var nvic = machine.GetPeripheralsOfType<NVIC>().FirstOrDefault();
                if(nvic != null)
                {
                    var model = (cortexM.Model ?? string.Empty).ToLowerInvariant();
                    var isArmv6M = model.Contains("m0");
                    int exceptionNumber = 3; // HardFault
                    if(!isArmv6M)
                    {
                        // PRECISERR (CFSR bit 9): precise data bus error.
                        cortexM.FaultStatus |= 0x00000200u;
                        var shcsr = nvic.ReadDoubleWord(0xD24);
                        if((shcsr & (1u << 17)) != 0
                           && cortexM.PRIMASK.RawValue == 0
                           && cortexM.FAULTMASK.RawValue == 0)
                        {
                            exceptionNumber = 5; // BusFault
                        }
                    }
                    nvic.SetPendingIRQ(exceptionNumber);
                    cortexM.RaiseException(5); // tlib EXCP_IRQ -> dispatches pending NVIC exception
                    return;
                }
                cortexM.RaiseException(4);
                return;
            }
            var tcpu = cpu as TranslationCPU;
            if(tcpu != null)
            {
                tcpu.RaiseException(4);
            }
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
        private readonly List<EraseTraceEntry> eraseTrace = new List<EraseTraceEntry>();
        private readonly List<ProgramTraceEntry> programTrace = new List<ProgramTraceEntry>();
        private readonly HashSet<long> uncorrectableWords = new HashSet<long>();
        private readonly List<UncorrectableReadEntry> uncorrectableReads = new List<UncorrectableReadEntry>();
        private int programUnitSize = 16;
        private ulong programAddressBase;
        private ulong faultAtWordWrite = ulong.MaxValue;
        private ulong faultAtPageErase = ulong.MaxValue;
        private uint mmioEraseSize;
        private int writeFaultMode;
        private string mramTornWordMode = "half";
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
        private ulong lastFaultEraseIndex;
        private ulong lastFaultProgramAddress;
        private long lastFaultOffset = -1;
        private int lastFaultProgramWidth;
        private byte[] lastFaultIntendedBytes;
        private byte[] lastFaultPreProgramBytes;
        private byte[] lastFaultPostFaultBytes;
        private byte[] faultMemorySnapshot;
        private bool lastFaultMarkedUncorrectable;
        private readonly List<long> faultUncorrectableWords = new List<long>();
        private byte[] trackingBaseSnapshot;
        private readonly List<long> trackingBaseUncorrectableWords = new List<long>();
        private ulong uncorrectableReadCount;
        private ulong lastUncorrectableReadWordAddress;
        private ulong lastUncorrectableReadAddress;
        private ulong lastUncorrectableReadPC;

        private sealed class UncorrectableReadEntry
        {
            public UncorrectableReadEntry(ulong index, long wordOffset, ulong wordBusAddress,
                                          ulong accessBusAddress, int width, ulong pc)
            {
                Index = index;
                WordOffset = wordOffset;
                WordBusAddress = wordBusAddress;
                AccessBusAddress = accessBusAddress;
                Width = width;
                PC = pc;
            }
            public readonly ulong Index;
            public readonly long WordOffset;
            public readonly ulong WordBusAddress;
            public readonly ulong AccessBusAddress;
            public readonly int Width;
            public readonly ulong PC;
        }

        private sealed class WriteTraceEntry
        {
            public WriteTraceEntry(ulong index, long offset, ulong value, int width, ulong pc = 0)
            {
                Index = index;
                Offset = offset;
                Value = value;
                Width = width;
                PC = pc;
            }
            public readonly ulong Index;
            public readonly long Offset;
            public readonly ulong Value;
            public readonly int Width;
            public readonly ulong PC;
        }

        private sealed class EraseTraceEntry
        {
            public EraseTraceEntry(ulong index, long offset, ulong writesAt, int eraseSize, ulong pc = 0)
            {
                Index = index;
                Offset = offset;
                WritesAt = writesAt;
                EraseSize = eraseSize;
                PC = pc;
            }
            public readonly ulong Index;
            public readonly long Offset;
            public readonly ulong WritesAt;
            public readonly int EraseSize;
            public readonly ulong PC;
        }

        private sealed class ProgramTraceEntry
        {
            public ProgramTraceEntry(ulong index, long offset, int width,
                                     byte[] intended, byte[] preProgram,
                                     byte[] postProgram, bool faulted, ulong pc = 0)
            {
                Index = index;
                Offset = offset;
                Width = width;
                Intended = intended;
                PreProgram = preProgram;
                PostProgram = postProgram;
                Faulted = faulted;
                PC = pc;
            }
            public readonly ulong Index;
            public readonly long Offset;
            public readonly int Width;
            public readonly byte[] Intended;
            public readonly byte[] PreProgram;
            public readonly byte[] PostProgram;
            public readonly bool Faulted;
            public readonly ulong PC;
        }
    }
}
