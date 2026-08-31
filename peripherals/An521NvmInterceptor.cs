// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// RAM-backed AN521 flash view.  The secure image uses the fast MappedMemory
// alias; this view is installed at the non-secure alias so CPU writes made by
// TF-M's flash driver can be counted and faulted without a shadow scan.

using System;
using System.Linq;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Logging.Profiling;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public sealed class An521NvmInterceptor : IBytePeripheral, IWordPeripheral,
                                               IDoubleWordPeripheral, IQuadWordPeripheral,
                                               IKnownSize,
                                               ITardigradeFaultInjectable
    {
        public An521NvmInterceptor(IMachine machine)
        {
            this.machine = machine;
            trackingStarted = true;
        }

        // Wired to the secure MappedMemory in the platform description.
        public MappedMemory BackingMemory { get; set; }

        public long Size => BackingMemory != null ? BackingMemory.Size : FlashSize;

        public IMemory Flash => BackingMemory;
        public long FlashBaseAddress { get; set; } = 0x00000000;
        public long FlashSize { get; set; } = 0x400000;
        public int PageSize { get; set; } = 0x20000;
        public byte EraseFill { get; set; } = 0xFF;

        private readonly FaultTracker tracker = new FaultTracker();

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite
        {
            get => tracker.FaultAtWordWrite;
            set
            {
                tracker.FaultAtWordWrite = value;
                UpdateMemoryAccessHook();
                if(value != ulong.MaxValue && trackingStarted)
                {
                    EnsureShadow();
                }
            }
        }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public bool DriverErrorFired { get => tracker.DriverErrorFired; set => tracker.DriverErrorFired = value; }
        public bool PerWriteAccurate => true;
        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }
        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }
        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }
        public bool AnyFaultFired => tracker.AnyFaultFired;
        public bool FaultRequiresImmediateStop => tracker.FaultRequiresImmediateStop;
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }
        public int WriteFaultMode
        {
            get => tracker.WriteFaultMode;
            set
            {
                // Keep unsupported modes from silently looking like an
                // applied campaign.  The AN521 interceptor implements the
                // common write modes 0 through 6.
                if(value < 0 || value > 6)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        "Unsupported AN521 write fault mode");
                }
                tracker.WriteFaultMode = value;
            }
        }
        public int EraseFaultMode { get => tracker.EraseFaultMode; set => tracker.EraseFaultMode = value; }
        public uint CorruptionSeed { get => tracker.CorruptionSeed; set => tracker.CorruptionSeed = value; }
        public int DiffLookahead { get; set; } = 32;
        public bool SkipShadowScan { get; set; } = true;
        public bool PassthroughMode { get; set; }
        public void InvalidateShadow()
        {
            flashShadow = null;
            if(memoryAccessHookInstalled)
            {
                EnsureShadow();
            }
        }

        public bool WriteTraceEnabled
        {
            get => tracker.WriteTraceEnabled;
            set
            {
                tracker.WriteTraceEnabled = value;
                UpdateMemoryAccessHook();
                if(value && trackingStarted)
                {
                    EnsureShadow();
                }
            }
        }
        public int WriteTraceCount => tracker.WriteTraceCount;
        public bool WriteTraceWidthExplicit => true;

        // Optional run-time gate used by long boot traces.  Zero preserves
        // the historical behavior and starts tracking from reset.
        public ulong TrackingStartAddress
        {
            get => trackingStartAddress;
            set
            {
                // Reconcile even when the value is unchanged: machine Reset
                // can clear CPU hooks after peripheral Reset, leaving the
                // marker true for a hook that no longer exists.
                if(startHookInstalled)
                {
                    RemoveTrackingStartHook();
                }
                trackingStartAddress = value;
                trackingStarted = value == 0;
                UpdateMemoryAccessHook();
            }
        }
        // Read-only diagnostics for profile-driven calibration.  These make
        // hook lifecycle failures visible without changing tracking behavior.
        public bool TrackingStarted => trackingStarted;
        public bool StartHookInstalled => startHookInstalled;
        public bool MemoryAccessHookInstalled => memoryAccessHookInstalled;
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public void WriteTraceClear() => tracker.WriteTraceClear();

        // Erase is not part of AN521's RAM-backed flash path.  These members
        // are intentionally inert so generic fault tooling can bind without
        // pretending that this view implements a hardware erase operation.
        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;
        public string EraseTraceToString() => tracker.EraseTraceToString();
        public void EraseTraceClear() => tracker.EraseTraceClear();

        // Reads are deliberately transparent.  The non-secure alias must be
        // executable and must see exactly the bytes stored in secure SSRAM1.
        public byte ReadByte(long offset) => BackingMemory.ReadByte(offset);
        public ushort ReadWord(long offset) => BackingMemory.ReadWord(offset);
        public uint ReadDoubleWord(long offset) => BackingMemory.ReadDoubleWord(offset);
        public ulong ReadQuadWord(long offset)
        {
            var lo = BackingMemory.ReadDoubleWord(offset);
            var hi = BackingMemory.ReadDoubleWord(offset + 4);
            return (ulong)lo | ((ulong)hi << 32);
        }

        public void WriteByte(long offset, byte value)
        {
            WriteAccess(offset, 1, value);
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteAccess(offset, 2, value);
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteAccess(offset, 4, value);
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            WriteAccess(offset, 4, (uint)value);
            WriteAccess(offset + 4, 4, (uint)(value >> 32));
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
        {
            if(BackingMemory == null || offset < 0 || count < 0 || offset > BackingMemory.Size - count)
            {
                return new byte[0];
            }
            return BackingMemory.ReadBytes(offset, count);
        }

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count,
                               IPeripheral context = null)
        {
            if(array == null || startingIndex < 0 || count < 0 || startingIndex > array.Length - count)
            {
                return;
            }

            // Keep primitive CPU-write accounting exact for the operations
            // represented by this interface rather than bypassing the fault
            // point through the backing MappedMemory.
            for(var i = 0; i < count; i++)
            {
                WriteByte(offset + i, array[startingIndex + i]);
            }
        }

        public void Reset()
        {
            if(startHookInstalled)
            {
                RemoveTrackingStartHook();
            }
            tracker.Reset();
            flashShadow = null;
            trackingStarted = trackingStartAddress == 0;
            UpdateMemoryAccessHook();
        }

        // Read-fault properties are present for generic binding, but this
        // transparent executable view does not synthesize read corruption.
        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        private void WriteAccess(long offset, int width, uint value)
        {
            if(BackingMemory == null || width <= 0 || width > 4 || offset < 0 ||
               offset > BackingMemory.Size - width || (offset & 3) + width > 4)
            {
                return;
            }

            var aligned = offset & ~3L;
            var oldBytes = BackingMemory.ReadBytes(aligned, 4);
            var result = FaultTracker.ReadU32(oldBytes, 0);
            var shift = (int)((offset - aligned) * 8);
            var mask = width == 4 ? 0xFFFFFFFFU : ((1U << (width * 8)) - 1U) << shift;
            result = (result & ~mask) | ((value & (mask >> shift)) << shift);

            if(PassthroughMode)
            {
                // Recovery boots preserve write accounting for diagnostics, but
                // must not arm or apply a fault. Keep an already-created shadow
                // coherent so a later campaign cannot compare against stale
                // recovery data.
                WriteResult(aligned, offset, width, result);
                tracker.IncrementWriteCount();
                WriteShadowWord(aligned, result);
                return;
            }

            if(!trackingStarted)
            {
                // A precise instruction hook will arm tracking at the
                // requested boundary; preserve earlier boot writes normally.
                WriteResult(aligned, offset, width, result);
                return;
            }

            EnsureShadow();
            // Fault application operates on the containing aligned word.
            // Record the same canonical post-state dword so trace replay has
            // exactly the granularity used by the fault model, including for
            // narrow byte and halfword accesses.
            var traceOffset = (int)aligned;
            var traceValue = (ulong)result;
            var traceWidth = 4;
            var faultArmed = tracker.RecordWriteAndCheckFault(
                traceOffset, traceValue, traceWidth);
            if(faultArmed)
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + aligned);
                FaultFlashSnapshot = (byte[])flashShadow.Clone();

                var faultWord = FaultWord(ReadShadowWord(aligned), result, aligned);
                if(WriteFaultMode == 0 || WriteFaultMode == 3 ||
                   (WriteFaultMode == 6 && DriverErrorFired))
                {
                    // Power loss, write rejection, and driver error leave
                    // the target word at its pre-write value.
                    return;
                }

                WriteBackingWord(aligned, faultWord);
                WriteShadowWord(aligned, faultWord);
                return;
            }

            if(!tracker.AnyFaultFired && !DriverErrorFired)
            {
                WriteResult(aligned, offset, width, result);
                WriteShadowWord(aligned, result);
            }
        }

        private void WriteResult(long aligned, long offset, int width, uint result)
        {
            var shift = (int)((offset - aligned) * 8);
            var value = result >> shift;
            for(var i = 0; i < width; i++)
            {
                BackingMemory.WriteByte(offset + i, (byte)(value >> (i * 8)));
            }
        }

        // MappedMemory performs direct CPU writes without invoking MMIO
        // callbacks.  Observe that fast path while leaving MemoryIOWrite to
        // WriteAccess, so one operation cannot be counted twice.
        private void OnMemoryWrite(ulong virtualPC, MemoryOperation operation, ulong virtualAddress,
                                   ulong __, uint width, ulong value)
        {
            if(operation != MemoryOperation.MemoryWrite || width == 0)
            {
                return;
            }

            // Renode's physicalAddress is peripheral-relative for MappedMemory
            // fast paths.  Resolve the CPU virtual/bus alias instead, or an
            // SSRAM2 offset can be mistaken for an SSRAM1 flash offset.
            if(!TryResolveAlias((long)virtualAddress, out var offset))
            {
                return;
            }

            if(PassthroughMode)
            {
                // The MappedMemory fast path has already committed this write.
                // Count recovery writes for diagnostics, but do not snapshot or
                // fault them; only mirror them into an existing shadow used by a
                // later campaign.
                MirrorShadowWrite(offset, width, value);
                return;
            }

            EnsureShadow();
            var byteCount = (int)Math.Min(width, sizeof(ulong));
            for(var cursor = 0; cursor < byteCount;)
            {
                var chunkOffset = offset + cursor;
                var aligned = chunkOffset & ~3L;
                var inWord = (int)(chunkOffset - aligned);
                var bytes = Math.Min(4 - inWord, byteCount - cursor);
                var oldWord = ReadShadowWord(aligned);
                var newWord = OverlayWriteChunk(oldWord, value, cursor, inWord, bytes);

                // Fault application operates on the containing aligned word.
                // Record the same canonical post-state dword for every chunk;
                // this preserves untouched bytes and makes replay exact.
                var traceOffset = (int)aligned;
                var traceValue = (ulong)newWord;
                var traceWidth = 4;

                if(tracker.RecordWriteAndCheckFault(traceOffset, traceValue, traceWidth))
                {
                    FaultFired = true;
                    LastFaultAddress = (uint)(FlashBaseAddress + aligned);
                    FaultFlashSnapshot = (byte[])flashShadow.Clone();
                    var faultWord = FaultWord(oldWord, newWord, aligned);
                    // The MappedMemory fast path has already committed the
                    // requested word when this hook runs.  Re-apply the
                    // fault word even for power-loss/rejection/error modes
                    // so those modes restore the pre-write value.
                    WriteBackingWord(aligned, faultWord);
                    WriteShadowWord(aligned, faultWord);
                    return;
                }

                WriteShadowWord(aligned, newWord);
                cursor += bytes;
            }
        }

        private uint FaultWord(uint oldWord, uint newWord, long aligned)
        {
            switch(WriteFaultMode)
            {
            case 1:
                return ApplyBitCorruption(aligned, oldWord, newWord);
            case 2:
                return (TotalWordWrites & 1UL) == 0UL ? 0xFFFFFFFFU : 0U;
            case 3:
                return oldWord;
            case 4:
                ApplyWriteDisturb(aligned);
                return newWord;
            case 5:
                ApplyWearLevelingCorruption(aligned);
                return newWord;
            case 6:
                DriverErrorFired = true;
                return oldWord;
            default:
                return oldWord;
            }
        }

        private void ApplyWriteDisturb(long aligned)
        {
            // The target commits; adjacent words receive unintended 1->0
            // transitions, matching the flash-controller backends.
            uint seed = tracker.BuildFaultSeed((int)aligned);
            foreach(var neighbor in new[] { aligned - 4, aligned + 4 })
            {
                if(neighbor < 0 || neighbor > FlashSize - 4)
                {
                    continue;
                }
                var neighborWord = ReadShadowWord(neighbor);
                var disturbMask = FaultTracker.NextLcg(ref seed) & 0x11111111U;
                var disturbed = neighborWord & ~disturbMask;
                WriteBackingWord(neighbor, disturbed);
                WriteShadowWord(neighbor, disturbed);
            }
        }

        private void ApplyWearLevelingCorruption(long aligned)
        {
            // The target commits, then deterministic age-dependent bit errors
            // appear elsewhere in its erase page.
            var pageSize = Math.Max(4, PageSize);
            var pageStart = (aligned / pageSize) * pageSize;
            var wordsPerPage = Math.Max(1, pageSize / 4);
            var errorCount = 2 + (int)Math.Min(10UL, TotalPageErases / 8UL);
            uint seed = tracker.BuildFaultSeed((int)aligned);
            for(var i = 0; i < errorCount; i++)
            {
                var target = pageStart + (FaultTracker.NextLcg(ref seed) % (uint)wordsPerPage) * 4;
                if(target < 0 || target > FlashSize - 4)
                {
                    continue;
                }
                var word = ReadShadowWord(target);
                var mask = FaultTracker.NextLcg(ref seed) & 0x01010101U;
                if(mask == 0)
                {
                    mask = 1U << (int)(FaultTracker.NextLcg(ref seed) % 32U);
                }
                var aged = word & ~mask;
                WriteBackingWord(target, aged);
                WriteShadowWord(target, aged);
            }
        }

        private uint ApplyBitCorruption(long aligned, uint oldWord, uint newWord)
        {
            var seed = tracker.BuildFaultSeed((int)aligned);
            var keepMask = FaultTracker.NextLcg(ref seed);
            var bitsToFlip = oldWord & ~newWord;
            return oldWord & ~(bitsToFlip & keepMask);
        }

        private void WriteBackingWord(long aligned, uint value)
        {
            var bytes = FaultTracker.WordToBytes(value);
            BackingMemory.WriteBytes(aligned, bytes, 0, bytes.Length);
        }

        private static uint OverlayWriteChunk(uint oldWord, ulong value, int sourceOffset,
                                              int targetOffset, int count)
        {
            var result = oldWord;
            for(var i = 0; i < count; i++)
            {
                var source = sourceOffset + i;
                var byteValue = source < sizeof(ulong) ? (uint)((value >> (source * 8)) & 0xFFUL) : 0U;
                var shift = (targetOffset + i) * 8;
                result = (result & ~(0xFFU << shift)) | (byteValue << shift);
            }
            return result;
        }

        private void MirrorShadowWrite(long offset, uint width, ulong value)
        {
            if(width == 0)
            {
                return;
            }

            var byteCount = (int)Math.Min(width, sizeof(ulong));
            for(var cursor = 0; cursor < byteCount;)
            {
                var chunkOffset = offset + cursor;
                var aligned = chunkOffset & ~3L;
                var inWord = (int)(chunkOffset - aligned);
                var bytes = Math.Min(4 - inWord, byteCount - cursor);
                tracker.IncrementWriteCount();
                if(flashShadow != null)
                {
                    var oldWord = ReadShadowWord(aligned);
                    var newWord = OverlayWriteChunk(oldWord, value, cursor, inWord, bytes);
                    WriteShadowWord(aligned, newWord);
                }
                cursor += bytes;
            }
        }

        private bool TryResolveAlias(long address, out long offset)
        {
            if(address >= 0 && address < FlashSize)
            {
                offset = address;
                return true;
            }

            if(address >= 0x10000000 && address < 0x10000000 + FlashSize)
            {
                offset = address - 0x10000000;
                return true;
            }

            if(address >= 0x00400000 && address < 0x00400000 + FlashSize)
            {
                offset = address - 0x00400000;
                return true;
            }

            if(address >= 0x10400000 && address < 0x10400000 + FlashSize)
            {
                offset = address - 0x10400000;
                return true;
            }

            offset = 0;
            return false;
        }

        private void OnTrackingStart(ICpuSupportingGdb cpu, ulong address)
        {
            if(startHookInstalled)
            {
                if(cpu is ICPUWithHooks hookCpu)
                {
                    hookCpu.RemoveHook(trackingStartHookAddress, (CpuAddressHook)OnTrackingStart);
                }
                startHookInstalled = false;
            }
            trackingStarted = true;
            tracker.TotalWordWrites = 0;
            tracker.FaultFired = false;
            tracker.DriverErrorFired = false;
            tracker.WriteTraceClear();
            flashShadow = null;
            UpdateMemoryAccessHook();
        }

        private void UpdateMemoryAccessHook()
        {
            // Counting is a backend contract, not a trace/fault side effect:
            // calibration leaves both optional features off but still needs
            // every write after the configured boundary.  Address zero means
            // that boundary is reset, so install the memory hook immediately.
            var trackingRequested = trackingStartAddress != 0 || trackingStarted;
            var enabled = trackingRequested || tracker.WriteTraceEnabled ||
                          tracker.FaultAtWordWrite != ulong.MaxValue;
            if(!machine.IsRegistered(this))
            {
                return;
            }

            if(!enabled && startHookInstalled)
            {
                RemoveTrackingStartHook();
            }

            var cpus = machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithMemoryAccessHooks>();
            foreach(var cpu in cpus)
            {
                // Always reconcile this hook, including the gated/reset
                // state.  Leaving the old hook installed across Reset would
                // count pre-boundary writes in a later calibration phase.
                cpu.SetHookAtMemoryAccess(enabled && trackingStarted ? (MemoryAccessHook)OnMemoryWrite : null);
                if(enabled && trackingStartAddress != 0 && !trackingStarted && !startHookInstalled && cpu is ICPUWithHooks hookCpu)
                {
                    hookCpu.AddHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart);
                    trackingStartHookAddress = trackingStartAddress;
                    startHookInstalled = true;
                }
            }
            memoryAccessHookInstalled = enabled && trackingStarted;
        }

        private void RemoveTrackingStartHook()
        {
            if(!startHookInstalled)
            {
                return;
            }

            var cpus = machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>();
            foreach(var cpu in cpus)
            {
                cpu.RemoveHook(trackingStartHookAddress, (CpuAddressHook)OnTrackingStart);
            }
            startHookInstalled = false;
        }

        private void EnsureShadow()
        {
            if(flashShadow == null && BackingMemory != null)
            {
                flashShadow = BackingMemory.ReadBytes(0, checked((int)FlashSize));
            }
        }

        private uint ReadShadowWord(long aligned)
        {
            var off = checked((int)aligned);
            return (uint)(flashShadow[off] | (flashShadow[off + 1] << 8) |
                          (flashShadow[off + 2] << 16) | (flashShadow[off + 3] << 24));
        }

        private void WriteShadowWord(long aligned, uint value)
        {
            if(flashShadow == null)
            {
                return;
            }
            var bytes = FaultTracker.WordToBytes(value);
            Array.Copy(bytes, 0, flashShadow, checked((int)aligned), bytes.Length);
        }

        private readonly IMachine machine;
        private bool memoryAccessHookInstalled;
        private bool startHookInstalled;
        private bool trackingStarted;
        private ulong trackingStartAddress;
        private ulong trackingStartHookAddress;
        private byte[] flashShadow;
    }
}
