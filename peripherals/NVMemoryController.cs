// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Miscellaneous;

namespace Antmicro.Renode.Peripherals.Memory
{
    // Persistent non-volatile memory model with configurable write granularity and optional sector erase.
    // Supports MRAM (word-write, no sector erase), flash (sector erase + word program), FRAM, and other NVM.
    public class NVMemory : IMemory, IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IQuadWordPeripheral, IKnownSize
    {
        public NVMemory(long size = DefaultSize, long wordSize = DefaultWordSize)
        {
            if(size <= 0 || size > int.MaxValue)
            {
                throw new ArgumentException("NVM size must be between 1 and Int32.MaxValue");
            }

            this.size = size;
            WordSize = wordSize;
            storage = new byte[size];

            // Default: fill with EraseFill so fresh memory looks erased.
            for(var i = 0L; i < size; i++)
            {
                storage[i] = EraseFill;
            }
        }

        public void Reset()
        {
            // Intentionally do NOT clear storage: this models non-volatile memory.
            WriteInProgress = false;
            LastFaultInjected = false;
            FaultEverFired = false;
            DriverErrorFired = false;
            if(configuredTrackingStartAddress != 0)
            {
                trackingStartAddress = configuredTrackingStartAddress;
                trackingStarted = false;
                ResetCampaignObservability();
            }
            else
            {
                trackingStarted = true;
            }
            // Read-fault state is intentionally NOT cleared on Reset: the
            // sweep engine re-arms between iterations, and clearing here
            // would hide the fact that a fault was scheduled but the boot
            // path never read the armed address.
        }

        public byte ReadByte(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadByte(offset);
            }
            if(!TryValidateRange(offset, 1))
            {
                LogOutOfRangeRead(offset, 1);
                return 0xFF;
            }
            var value = storage[offset];
            return (byte)ApplyReadFault(offset, 1, value);
        }

        public ushort ReadWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadWord(offset);
            }
            if(!TryValidateRange(offset, 2))
            {
                LogOutOfRangeRead(offset, 2);
                return 0xFFFF;
            }
            var value = (ushort)(storage[offset]
                | (storage[offset + 1] << 8));
            return (ushort)ApplyReadFault(offset, 2, value);
        }

        public uint ReadDoubleWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadDoubleWord(offset);
            }
            if(!TryValidateRange(offset, 4))
            {
                LogOutOfRangeRead(offset, 4);
                return 0xFFFFFFFF;
            }
            var value = (uint)(storage[offset]
                | (storage[offset + 1] << 8)
                | (storage[offset + 2] << 16)
                | (storage[offset + 3] << 24));
            return ApplyReadFault(offset, 4, value);
        }

        public ulong ReadQuadWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadQuadWord(offset);
            }
            if(!TryValidateRange(offset, 8))
            {
                LogOutOfRangeRead(offset, 8);
                return 0xFFFFFFFFFFFFFFFFUL;
            }
            var lo = (uint)(storage[offset]
                | (storage[offset + 1] << 8)
                | (storage[offset + 2] << 16)
                | (storage[offset + 3] << 24));
            var hi = (uint)(storage[offset + 4]
                | (storage[offset + 5] << 8)
                | (storage[offset + 6] << 16)
                | (storage[offset + 7] << 24));
            var value = (ulong)lo | ((ulong)hi << 32);
            return (ulong)ApplyReadFault(offset, 4, lo)
                | ((ulong)ApplyReadFault(offset + 4, 4, hi) << 32);
        }

        public void WriteByte(long offset, byte value)
        {
            WriteBytesInternal(offset, new[] { value });
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
            });
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
            });
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 32) & 0xFF),
                (byte)((value >> 40) & 0xFF),
                (byte)((value >> 48) & 0xFF),
                (byte)((value >> 56) & 0xFF),
            });
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadBytes(offset, count, context);
            }

            if(count < 0 || !TryValidateRange(offset, count))
            {
                LogOutOfRangeRead(offset, count);
                return CreateErasedBytes(Math.Max(0, count));
            }
            var result = new byte[count];
            Array.Copy(storage, offset, result, 0, count);
            return result;
        }

        public byte[] ReadBytes(long offset, int count)
        {
            return ReadBytes(offset, count, null);
        }

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count, IPeripheral context)
        {
            if(array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if(startingIndex < 0 || count < 0 || startingIndex > array.Length - count)
            {
                return;
            }

            var data = new byte[count];
            Array.Copy(array, startingIndex, data, 0, count);
            WriteBytesInternal(offset, data);
        }

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count)
        {
            WriteBytes(offset, array, startingIndex, count, null);
        }

        public void InjectFault(long address, long length, byte pattern = 0x00)
        {
            if(AliasTarget != null)
            {
                AliasTarget.InjectFault(address, length, pattern);
                return;
            }

            if(length <= 0)
            {
                return;
            }

            if(!TryValidateRange(address, length))
            {
                LogOutOfRangeWrite(address, length);
                return;
            }
            for(var i = 0L; i < length; i++)
            {
                storage[address + i] = pattern;
            }
            LastFaultInjected = true;
            FaultEverFired = true;
            LastFaultPattern = pattern;
        }

        public void InjectPartialWrite(long address)
        {
            if(AliasTarget != null)
            {
                AliasTarget.InjectPartialWrite(address);
                return;
            }

            var aligned = AlignDown(address, WordSize);
            if(!TryValidateRange(aligned, WordSize))
            {
                LogOutOfRangeWrite(aligned, WordSize);
                return;
            }

            var half = WordSize / 2;
            for(var i = half; i < WordSize; i++)
            {
                storage[aligned + i] = EraseFill;
            }

            LastFaultInjected = true;
            FaultEverFired = true;
            LastFaultPattern = EraseFill;
        }

        public ulong GetWordWriteCount()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.GetWordWriteCount();
            }
            return TotalWordWrites;
        }

        public bool IsWriteInProgress()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.IsWriteInProgress();
            }
            return WriteInProgress;
        }

        public long Size
        {
            get { return size; }
            set
            {
                if(AliasTarget != null)
                {
                    // Aliases inherit target geometry.
                    return;
                }

                if(value <= 0)
                {
                    throw new ArgumentException("NVM size must be > 0");
                }

                if(value > int.MaxValue)
                {
                    throw new ArgumentException("NVM size exceeds max supported backing array size");
                }

                if(value == size)
                {
                    return;
                }

                var newStorage = new byte[value];
                var bytesToCopy = Math.Min(size, value);
                Array.Copy(storage, newStorage, bytesToCopy);
                storage = newStorage;
                size = value;
            }
        }

        public long WordSize
        {
            get { return wordSize; }
            set
            {
                if(value <= 0)
                {
                    throw new ArgumentException("WordSize must be > 0");
                }

                // Keep word boundaries power-of-two for efficient alignment logic.
                if((value & (value - 1)) != 0)
                {
                    throw new ArgumentException("WordSize must be a power-of-two");
                }

                wordSize = value;
            }
        }

        public byte EraseFill
        {
            get { return eraseFill; }
            set
            {
                if(value != eraseFill)
                {
                    var oldFill = eraseFill;
                    eraseFill = value;

                    // Re-fill storage bytes that still hold the old erase pattern.
                    // This handles the Renode construction order issue: the constructor
                    // fills storage with the default EraseFill (0x00), then the .repl
                    // property setter fires with the actual value (e.g. 0xFF for flash).
                    // Only touch bytes that match the old fill to avoid clobbering data
                    // loaded between construction and property-set (e.g. LoadBinary).
                    if(storage != null)
                    {
                        for(var i = 0L; i < storage.Length; i++)
                        {
                            if(storage[i] == oldFill)
                            {
                                storage[i] = value;
                            }
                        }
                    }
                }
            }
        }

        public bool EnforceWordWriteSemantics { get; set; } = true;

        public bool ReadOnly { get; set; }

        // Optional alias to expose NV_READ_OFFSET style mirrored view.
        public NVMemory AliasTarget { get; set; }

        // Optional campaign boundary. The runtime installs the CPU hook and
        // clears this property when execution reaches the requested address.
        // Until then, storage behaves normally but campaign accounting and
        // write-fault injection remain dormant.
        public ulong TrackingStartAddress
        {
            get
            {
                return AliasTarget != null
                    ? AliasTarget.TrackingStartAddress
                    : trackingStartAddress;
            }
            set
            {
                if(AliasTarget != null)
                {
                    AliasTarget.TrackingStartAddress = value;
                    return;
                }
                if(value != 0)
                {
                    configuredTrackingStartAddress = value;
                    trackingStartAddress = value;
                    trackingStarted = false;
                    ResetCampaignObservability();
                    return;
                }

                // Activation is one transition: discard any pre-campaign
                // diagnostics, enable tracking, and leave the armed fault
                // index untouched. The next program is therefore write 1.
                if(!trackingStarted)
                {
                    ResetCampaignObservability();
                }
                trackingStartAddress = 0;
                trackingStarted = true;
            }
        }

        public bool TrackingStarted
        {
            get { return AliasTarget != null ? AliasTarget.TrackingStarted : trackingStarted; }
        }

        public bool WriteTraceEnabled
        {
            get { return AliasTarget != null ? AliasTarget.WriteTraceEnabled : writeTraceEnabled; }
            set
            {
                if(AliasTarget != null) AliasTarget.WriteTraceEnabled = value;
                else writeTraceEnabled = value;
            }
        }

        public bool WriteTraceWidthExplicit => true;

        public int WriteTraceCount
        {
            get { return AliasTarget != null ? AliasTarget.WriteTraceCount : writeTrace.Count; }
        }

        public string WriteTraceToString()
        {
            if(AliasTarget != null) return AliasTarget.WriteTraceToString();
            var result = new StringBuilder(writeTrace.Count * 32);
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
            if(AliasTarget != null) AliasTarget.WriteTraceClear();
            else writeTrace.Clear();
        }

        // Exact program evidence is separate from the legacy integer trace.
        // The latter can encode at most eight data bytes, while MRAM program
        // units are commonly 16 bytes and must not lose their upper half.
        public ulong ProgramAddressBase
        {
            get { return AliasTarget != null ? AliasTarget.ProgramAddressBase : programAddressBase; }
            set
            {
                if(AliasTarget != null) AliasTarget.ProgramAddressBase = value;
                else programAddressBase = value;
            }
        }

        public ulong LastFaultWriteIndex
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultWriteIndex : lastFaultWriteIndex; }
        }

        public ulong LastFaultProgramAddress
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultProgramAddress : lastFaultProgramAddress; }
        }

        public long LastFaultOffset
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultOffset : lastFaultOffset; }
        }

        public int LastFaultProgramWidth
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultProgramWidth : lastFaultProgramWidth; }
        }

        public byte[] LastFaultIntendedBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultIntendedBytes : CloneBytes(lastFaultIntendedBytes); }
        }

        public byte[] LastFaultPreProgramBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPreProgramBytes : CloneBytes(lastFaultPreProgramBytes); }
        }

        public byte[] LastFaultPostFaultBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPostFaultBytes : CloneBytes(lastFaultPostFaultBytes); }
        }

        public byte[] FaultMemorySnapshot
        {
            get { return AliasTarget != null ? AliasTarget.FaultMemorySnapshot : CloneBytes(faultMemorySnapshot); }
        }

        public int FaultMemorySnapshotSize
        {
            get
            {
                if(AliasTarget != null) return AliasTarget.FaultMemorySnapshotSize;
                return faultMemorySnapshot != null ? faultMemorySnapshot.Length : 0;
            }
        }

        public bool FaultEvidenceExact
        {
            get
            {
                if(AliasTarget != null) return AliasTarget.FaultEvidenceExact;
                return lastFaultWriteIndex != 0
                    && lastFaultOffset >= 0
                    && lastFaultProgramWidth > 0
                    && lastFaultIntendedBytes != null
                    && lastFaultIntendedBytes.Length == lastFaultProgramWidth
                    && lastFaultPreProgramBytes != null
                    && lastFaultPreProgramBytes.Length == lastFaultProgramWidth
                    && lastFaultPostFaultBytes != null
                    && lastFaultPostFaultBytes.Length == lastFaultProgramWidth
                    && faultMemorySnapshot != null
                    && faultMemorySnapshot.Length == storage.Length;
            }
        }

        public int ProgramTraceCount
        {
            get { return AliasTarget != null ? AliasTarget.ProgramTraceCount : programTrace.Count; }
        }

        public string ProgramTraceToString()
        {
            if(AliasTarget != null) return AliasTarget.ProgramTraceToString();
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
            if(AliasTarget != null)
            {
                AliasTarget.ProgramTraceClear();
                return;
            }
            programTrace.Clear();
            ClearFaultEvidence();
        }

        public ulong FaultAtWordWrite { get; set; } = ulong.MaxValue;

        // Fault mode: 0 = power_loss (partial write), 1 = bit_corruption (random bit flips),
        // 6 = driver_error (write rejected with sticky error flag).
        public int WriteFaultMode { get; set; }

        // Deterministic PRNG seed for bit corruption. Advanced on each corrupted byte.
        public uint CorruptionSeed { get; set; }

        public uint WriteLatencyMicros { get; set; }

        public bool WriteInProgress { get; private set; }

        public bool LastFaultInjected { get; set; }

        // Sticky fault flag: set when any fault fires, cleared only by Reset()
        // or explicit assignment. Unlike LastFaultInjected (which is cleared at
        // the start of each WriteBytesInternal), this survives subsequent writes.
        public bool FaultEverFired { get; set; }
        public bool DriverErrorFired { get; set; }

        public byte LastFaultPattern { get; private set; }

        public ulong TotalWordWrites { get; set; }

        public long LastWriteAddress { get; private set; }

        public List<long> WriteLog { get { return writeLog; } }

        // --- Read-fault injection ---
        //
        // One-shot transient read corruption: the underlying NVM is unchanged,
        // but the first ReadDoubleWord that overlaps the armed address returns
        // data with deterministic bit flips.  Subsequent reads return correct
        // data.  Models single-event upsets (SEU) on the read bus.

        // Master switch: when false, read-fault logic is completely bypassed.
        public bool ReadFaultEnabled { get; set; }

        // NVM-relative byte offset of the word to corrupt on read.
        // Must be word-aligned (aligned to WordSize).
        public long ReadFaultAddress { get; set; } = -1;

        // PRNG seed for deterministic bit selection during read corruption.
        public uint ReadFaultSeed { get; set; }

        // Number of bits to flip when the read fault fires.
        public int ReadFaultBitFlips { get; set; } = 1;

        // Sticky: set when the read fault fires, cleared when re-arming.
        public bool ReadFaultFired { get; set; }

        // Number of reads of the armed address to skip before firing.
        // 0 = fire on the very first read.
        public ulong ReadFaultSkipCount { get; set; }

        // Total reads counted against the armed address (for diagnostics).
        public ulong ReadFaultTotalReads { get; set; }

        public void EraseSector(long offset, int sectorSize)
        {
            if(AliasTarget != null)
            {
                AliasTarget.EraseSector(offset, sectorSize);
                return;
            }

            if(!TryValidateRange(offset, sectorSize))
            {
                LogOutOfRangeWrite(offset, sectorSize);
                return;
            }
            for(var i = 0; i < sectorSize; i++)
            {
                storage[offset + i] = EraseFill;
            }
        }

        public void ClearWriteLog()
        {
            writeLog.Clear();
        }

        // Apply one-shot read-fault injection if the access overlaps the
        // armed address.  Returns the (possibly corrupted) value.
        private uint ApplyReadFault(long offset, int accessSize, uint value)
        {
            if(!ReadFaultEnabled || ReadFaultFired || ReadFaultAddress < 0)
            {
                return value;
            }

            // Check overlap: armed region is [ReadFaultAddress, ReadFaultAddress + WordSize),
            // access region is [offset, offset + accessSize).
            var armedEnd = ReadFaultAddress + Math.Max(4, WordSize);
            var accessEnd = offset + accessSize;
            if(offset >= armedEnd || accessEnd <= ReadFaultAddress)
            {
                return value;
            }

            // This read overlaps the armed address. Count it.
            ReadFaultTotalReads++;
            if(ReadFaultTotalReads <= ReadFaultSkipCount)
            {
                return value;
            }

            // Fire the fault: flip deterministic bits. NVM is NOT modified.
            ReadFaultFired = true;
            ReadFaultEnabled = false;  // one-shot semantics
            var seed = ReadFaultSeed != 0 ? ReadFaultSeed : (uint)(ReadFaultAddress ^ 0xDEAD);
            // Deterministic bit-flip: LCG PRNG selects bit positions.
            if(seed == 0) seed = 0xDEAD;
            var flipCount = ReadFaultBitFlips > 0 ? (uint)ReadFaultBitFlips : 1u;
            for(var i = 0u; i < flipCount; i++)
            {
                seed = (uint)((seed * 1103515245u + 12345u) & 0xFFFFFFFF);
                var bitPos = (int)(seed % 32);
                value ^= (uint)(1 << bitPos);
            }
            return value;
        }

        private void WriteBytesInternal(long offset, byte[] data)
        {
            if(AliasTarget != null)
            {
                if(ReadOnly)
                {
                    return;
                }

                AliasTarget.WriteBytesInternal(offset, data);
                return;
            }

            if(ReadOnly)
            {
                return;
            }

            if(data.Length == 0)
            {
                return;
            }

            if(!TryValidateRange(offset, data.Length))
            {
                LogOutOfRangeWrite(offset, data.Length);
                return;
            }
            LastWriteAddress = offset;

            if(!TrackingStarted)
            {
                ProgramWithoutCampaignTracking(offset, data);
                return;
            }

            if(!EnforceWordWriteSemantics)
            {
                // Fast path: commit one word at a time.  A simulated power
                // loss must preserve preceding words but must never persist
                // bytes from words that occur after the targeted write.
                var fastFirst = AlignDown(offset, WordSize);
                var fastLast = AlignDown(offset + data.Length - 1, WordSize);
                for(var wordStart = fastFirst; wordStart <= fastLast; wordStart += WordSize)
                {
                    var previousWord = new byte[WordSize];
                    Array.Copy(storage, wordStart, previousWord, 0, WordSize);
                    var intendedWord = CloneBytes(previousWord);

                    var writeStart = Math.Max(offset, wordStart);
                    var writeEnd = Math.Min(offset + data.Length, wordStart + WordSize);
                    for(var address = writeStart; address < writeEnd; address++)
                    {
                        intendedWord[address - wordStart] = data[(int)(address - offset)];
                    }
                    ProgramWord(wordStart, intendedWord);

                    var currentWriteIndex = TotalWordWrites + 1;
                    if(currentWriteIndex == FaultAtWordWrite)
                    {
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: data already written above; flip random bits.
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                        }
                        else if(WriteFaultMode == 6)
                        {
                            for(var i = 0; i < (int)WordSize; i++)
                            {
                                storage[wordStart + i] = previousWord[i];
                            }
                            DriverErrorFired = true;
                        }
                        else
                        {
                            // Power-loss: corrupt second half of faulted word with EraseFill.
                            var half = WordSize / 2;
                            for(var i = wordStart + half; i < wordStart + WordSize; i++)
                            {
                                if(i >= offset && i < offset + data.Length)
                                {
                                    storage[i] = EraseFill;
                                }
                            }
                        }
                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : EraseFill);
                        TotalWordWrites++;
                        LastWriteAddress = wordStart;
                        RecordWriteTrace(wordStart);
                        var postFaultWord = ReadStorageWord(wordStart);
                        RecordProgramTrace(
                            currentWriteIndex, wordStart, intendedWord,
                            previousWord, postFaultWord, true
                        );
                        CaptureFaultEvidence(
                            currentWriteIndex, wordStart, intendedWord,
                            previousWord, postFaultWord
                        );
                        return;
                    }

                    RecordProgramTrace(
                        currentWriteIndex, wordStart, intendedWord,
                        previousWord, ReadStorageWord(wordStart), false
                    );
                    TotalWordWrites++;
                    RecordWriteTrace(wordStart);
                }

                return;
            }

            var firstWordStart = AlignDown(offset, WordSize);
            var lastWordStart = AlignDown(offset + data.Length - 1, WordSize);

            WriteInProgress = true;
            LastFaultInjected = false;

            try
            {
                for(var wordStart = firstWordStart; wordStart <= lastWordStart; wordStart += WordSize)
                {
                    var previousWord = new byte[WordSize];
                    Array.Copy(storage, wordStart, previousWord, 0, WordSize);
                    var mergedWord = new byte[WordSize];
                    for(var i = 0L; i < WordSize; i++)
                    {
                        mergedWord[i] = storage[wordStart + i];
                    }

                    for(var i = 0; i < data.Length; i++)
                    {
                        var absoluteAddress = offset + i;
                        if(absoluteAddress < wordStart || absoluteAddress >= wordStart + WordSize)
                        {
                            continue;
                        }

                        mergedWord[absoluteAddress - wordStart] = data[i];
                    }

                    EraseWord(wordStart);

                    var currentWriteIndex = TotalWordWrites + 1;
                    if(currentWriteIndex == FaultAtWordWrite)
                    {
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: write full word, then flip random bits.
                            ProgramWord(wordStart, mergedWord);
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                        }
                        else if(WriteFaultMode == 6)
                        {
                            for(var i = 0; i < (int)WordSize; i++)
                            {
                                storage[wordStart + i] = previousWord[i];
                            }
                            DriverErrorFired = true;
                        }
                        else
                        {
                            // Power-loss: partial write (first half only).
                            var partialBytes = WordSize / 2;
                            for(var i = 0L; i < partialBytes; i++)
                            {
                                storage[wordStart + i] = mergedWord[i];
                            }

                            for(var i = partialBytes; i < WordSize; i++)
                            {
                                storage[wordStart + i] = EraseFill;
                            }
                        }

                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : EraseFill);
                        TotalWordWrites++;
                        writeLog.Add(wordStart);
                        RecordWriteTrace(wordStart);
                        var postFaultWord = ReadStorageWord(wordStart);
                        RecordProgramTrace(
                            currentWriteIndex, wordStart, mergedWord,
                            previousWord, postFaultWord, true
                        );
                        CaptureFaultEvidence(
                            currentWriteIndex, wordStart, mergedWord,
                            previousWord, postFaultWord
                        );
                        break;
                    }

                    ProgramWord(wordStart, mergedWord);
                    RecordProgramTrace(
                        currentWriteIndex, wordStart, mergedWord,
                        previousWord, ReadStorageWord(wordStart), false
                    );
                    TotalWordWrites++;
                    writeLog.Add(wordStart);
                    RecordWriteTrace(wordStart);

                    if(WriteLatencyMicros > 0)
                    {
                        var milliseconds = (int)Math.Max(1, WriteLatencyMicros / 1000);
                        Thread.Sleep(milliseconds);
                    }
                }
            }
            finally
            {
                WriteInProgress = false;
            }
        }

        private uint AdvancePrng()
        {
            corruptionSeed = corruptionSeed * 1103515245u + 12345u;
            return corruptionSeed;
        }

        // Apply random bit flips to a word already in storage.
        // MRAM physics: bits can flip in either direction (unlike NOR flash 1->0 only).
        private void ApplyBitCorruptionToWord(long wordStart)
        {
            for(var i = 0L; i < WordSize && (wordStart + i) < size; i++)
            {
                var r = AdvancePrng();
                if((r & 0x7) == 0) // ~12.5% chance per byte
                {
                    var flipMask = (byte)(AdvancePrng() >> 16);
                    if(flipMask == 0)
                    {
                        flipMask = 1;
                    }
                    storage[wordStart + i] ^= flipMask;
                }
            }
        }

        private void EraseWord(long wordStart)
        {
            for(var i = 0L; i < WordSize; i++)
            {
                storage[wordStart + i] = EraseFill;
            }
        }

        private void ProgramWord(long wordStart, byte[] mergedWord)
        {
            for(var i = 0L; i < WordSize; i++)
            {
                storage[wordStart + i] = mergedWord[i];
            }
        }

        private void ProgramWithoutCampaignTracking(long offset, byte[] data)
        {
            LastFaultInjected = false;
            if(!EnforceWordWriteSemantics)
            {
                Array.Copy(data, 0, storage, offset, data.Length);
                return;
            }

            var firstWordStart = AlignDown(offset, WordSize);
            var lastWordStart = AlignDown(offset + data.Length - 1, WordSize);
            WriteInProgress = true;
            try
            {
                for(var wordStart = firstWordStart; wordStart <= lastWordStart; wordStart += WordSize)
                {
                    var mergedWord = new byte[WordSize];
                    Array.Copy(storage, wordStart, mergedWord, 0, WordSize);
                    for(var i = 0; i < data.Length; i++)
                    {
                        var address = offset + i;
                        if(address >= wordStart && address < wordStart + WordSize)
                        {
                            mergedWord[address - wordStart] = data[i];
                        }
                    }
                    EraseWord(wordStart);
                    ProgramWord(wordStart, mergedWord);
                    if(WriteLatencyMicros > 0)
                    {
                        Thread.Sleep((int)Math.Max(1, WriteLatencyMicros / 1000));
                    }
                }
            }
            finally
            {
                WriteInProgress = false;
            }
        }

        private void RecordWriteTrace(long wordStart)
        {
            if(!WriteTraceEnabled)
            {
                return;
            }
            var encodedWidth = (int)Math.Min(8L, WordSize);
            ulong value = 0;
            for(var i = 0; i < encodedWidth; i++)
            {
                value |= (ulong)storage[wordStart + i] << (8 * i);
            }
            // The legacy integer value carries at most eight bytes, but the
            // explicit width remains authoritative. Full program bytes live
            // in ProgramTraceToString and are never truncated there.
            writeTrace.Add(new WriteTraceEntry(
                TotalWordWrites, wordStart, value, checked((int)WordSize)
            ));
        }

        private void RecordProgramTrace(ulong index, long offset, byte[] intended,
                                        byte[] preProgram, byte[] postProgram, bool faulted)
        {
            programTrace.Add(new ProgramTraceEntry(
                index, offset, (int)WordSize,
                CloneBytes(intended), CloneBytes(preProgram), CloneBytes(postProgram),
                faulted
            ));
        }

        private void CaptureFaultEvidence(ulong index, long offset, byte[] intended,
                                          byte[] preProgram, byte[] postFault)
        {
            lastFaultWriteIndex = index;
            lastFaultOffset = offset;
            lastFaultProgramAddress = programAddressBase + (ulong)offset;
            lastFaultProgramWidth = (int)WordSize;
            lastFaultIntendedBytes = CloneBytes(intended);
            lastFaultPreProgramBytes = CloneBytes(preProgram);
            lastFaultPostFaultBytes = CloneBytes(postFault);
            faultMemorySnapshot = CloneBytes(storage);
        }

        private byte[] ReadStorageWord(long offset)
        {
            var result = new byte[WordSize];
            Array.Copy(storage, offset, result, 0, WordSize);
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
            if(data == null)
            {
                return;
            }
            foreach(var value in data)
            {
                builder.Append(value.ToString("x2"));
            }
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

        private void ResetCampaignObservability()
        {
            TotalWordWrites = 0;
            writeLog.Clear();
            writeTrace.Clear();
            programTrace.Clear();
            ClearFaultEvidence();
            LastFaultInjected = false;
            FaultEverFired = false;
            DriverErrorFired = false;
        }

        private long AlignDown(long value, long alignment)
        {
            return value & ~(alignment - 1);
        }

        private bool TryValidateRange(long offset, long length)
        {
            return offset >= 0 && length >= 0 && length <= size && offset <= size - length;
        }

        private void LogOutOfRangeRead(long offset, long length)
        {
        }

        private void LogOutOfRangeWrite(long offset, long length)
        {
        }

        private byte[] CreateErasedBytes(int count)
        {
            if(count <= 0)
            {
                return Array.Empty<byte>();
            }

            var result = new byte[count];
            for(var i = 0; i < count; i++)
            {
                result[i] = 0xFF;
            }
            return result;
        }

        private byte eraseFill;
        private long size;
        private long wordSize;
        private byte[] storage;
        private uint corruptionSeed;
        private readonly List<long> writeLog = new List<long>();
        private readonly List<WriteTraceEntry> writeTrace = new List<WriteTraceEntry>();
        private readonly List<ProgramTraceEntry> programTrace = new List<ProgramTraceEntry>();
        private bool writeTraceEnabled;
        private ulong trackingStartAddress;
        private ulong configuredTrackingStartAddress;
        private bool trackingStarted = true;
        private ulong programAddressBase;
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

        private const long DefaultSize = 0x80000;
        private const long DefaultWordSize = 8;
    }
}

namespace Antmicro.Renode.Peripherals
{
    // Control/register block companion for NVMemory.
    //
    // ITardigradeFaultInjectable is implemented so the audit engine can bind to
    // this controller as a fault backend without a mid-campaign missing-member
    // abort; declaring the interface turns any missing member into a load-time
    // C# compile error instead of a runtime failure deep in a sweep.
    public class NVMemoryController : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        public NVMemoryController(Machine machine) : base(machine)
        {
            DefineRegisters();
            Reset();
        }

        public override void Reset()
        {
            base.Reset();

            efuseStrobeLen.Value = 0;
            efuseCtrl.Value = 0;
            efuseOp.Value = 0;
            nvmCfg.Value = 0;
            nvmOverride.Value = 0;
            nvmCtrlWriteableBits = 0;
            nvmUe.Value = 0;

            for(var i = 0; i < eccCounters.Length; i++)
            {
                eccCounters[i] = 0;
            }

            illegalOperation = false;

            // Intentionally do NOT clear efuseSpareValue: eFuse bits are OTP
            // and survive reset, just like real hardware.

            // Intentionally do not touch Nvm.Reset() here; memory persistence is critical.
        }

        public void InjectFault(long address, long length)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            if(!TryNormalizeAddress(address, out var normalized))
            {
                return;
            }

            Nvm.InjectFault(normalized, length);
        }

        public void InjectPartialWrite(long address)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            if(!TryNormalizeAddress(address, out var normalized))
            {
                return;
            }

            Nvm.InjectPartialWrite(normalized);
        }

        public void EraseSector(long address, int sectorSize = 0x1000)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            if(!TryNormalizeAddress(address, out var normalized))
            {
                return;
            }

            Nvm.EraseSector(normalized, sectorSize);
        }

        public void InjectPartialErase(long address, int sectorSize = 0x1000)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            if(!TryNormalizeAddress(address, out var normalized))
            {
                return;
            }

            var half = sectorSize / 2;
            // Erase first half of sector, leave second half intact.
            Nvm.EraseSector(normalized, half);
        }

        public bool WriteInProgress
        {
            get { return Nvm != null && Nvm.IsWriteInProgress(); }
        }

        public ulong WordWriteCount
        {
            get { return Nvm == null ? 0UL : Nvm.GetWordWriteCount(); }
        }

        public List<long> GetWriteLog()
        {
            return Nvm != null ? Nvm.WriteLog : new List<long>();
        }

        public void ClearWriteLog()
        {
            Nvm?.ClearWriteLog();
        }

        public long Size
        {
            get { return ControllerWindowSize; }
        }

        public bool FullMode { get; set; } = true;

        // OTP eFuse spare bits. Test scripts can preset via this property.
        // Writes OR bits in (never clears). Survives Reset().
        public uint EfuseSpare
        {
            get { return efuseSpareValue; }
            set { efuseSpareValue = value; }
        }

        public Antmicro.Renode.Peripherals.Memory.NVMemory Nvm { get; set; }

        public long NvmBaseAddress { get; set; } = 0x10000000;

        public long NvReadOffset { get; set; } = 0x80000;

        // --- ITardigradeFaultInjectable ---------------------------------------
        //
        // Persistent-fault state lives in the backing NVMemory, so members that
        // model it forward to Nvm (null-guarded, because the .repl sets Nvm after
        // construction).  Page-erase counters, shadow/diff, and execution trace
        // are not modelled by this control block, so those members are inert
        // stubs.  A null Nvm returns benign defaults instead of throwing.

        public IMemory Flash
        {
            get { return Nvm; }
        }

        public long FlashBaseAddress
        {
            get { return NvmBaseAddress; }
            set { NvmBaseAddress = value; }
        }

        public long FlashSize
        {
            get { return Nvm != null ? Nvm.Size : 0L; }
            set { }
        }

        public int PageSize { get; set; }

        public byte EraseFill
        {
            get { return Nvm != null ? Nvm.EraseFill : (byte)0xFF; }
            set { if(Nvm != null) { Nvm.EraseFill = value; } }
        }

        public ulong TotalWordWrites
        {
            get { return Nvm != null ? Nvm.TotalWordWrites : 0UL; }
            set { if(Nvm != null) { Nvm.TotalWordWrites = value; } }
        }

        public ulong FaultAtWordWrite
        {
            get { return Nvm != null ? Nvm.FaultAtWordWrite : ulong.MaxValue; }
            set { if(Nvm != null) { Nvm.FaultAtWordWrite = value; } }
        }

        public ulong TrackingStartAddress
        {
            get { return Nvm != null ? Nvm.TrackingStartAddress : 0UL; }
            set { if(Nvm != null) { Nvm.TrackingStartAddress = value; } }
        }

        public bool TrackingStarted
        {
            get { return Nvm == null || Nvm.TrackingStarted; }
        }

        public ulong ProgramAddressBase
        {
            get { return Nvm != null ? Nvm.ProgramAddressBase : 0UL; }
            set { if(Nvm != null) { Nvm.ProgramAddressBase = value; } }
        }

        public ulong LastFaultWriteIndex => Nvm != null ? Nvm.LastFaultWriteIndex : 0UL;
        public ulong LastFaultProgramAddress => Nvm != null ? Nvm.LastFaultProgramAddress : 0UL;
        public long LastFaultOffset => Nvm != null ? Nvm.LastFaultOffset : -1L;
        public int LastFaultProgramWidth => Nvm != null ? Nvm.LastFaultProgramWidth : 0;
        public byte[] LastFaultIntendedBytes => Nvm != null ? Nvm.LastFaultIntendedBytes : null;
        public byte[] LastFaultPreProgramBytes => Nvm != null ? Nvm.LastFaultPreProgramBytes : null;
        public byte[] LastFaultPostFaultBytes => Nvm != null ? Nvm.LastFaultPostFaultBytes : null;
        public byte[] FaultMemorySnapshot => Nvm != null ? Nvm.FaultMemorySnapshot : null;
        public int FaultMemorySnapshotSize => Nvm != null ? Nvm.FaultMemorySnapshotSize : 0;
        public bool FaultEvidenceExact => Nvm != null && Nvm.FaultEvidenceExact;
        public int ProgramTraceCount => Nvm != null ? Nvm.ProgramTraceCount : 0;
        public string ProgramTraceToString() { return Nvm != null ? Nvm.ProgramTraceToString() : string.Empty; }
        public void ProgramTraceClear() { Nvm?.ProgramTraceClear(); }

        public bool FaultFired
        {
            get { return Nvm != null && Nvm.FaultEverFired; }
            set { if(Nvm != null) { Nvm.FaultEverFired = value; } }
        }

        public bool PerWriteAccurate
        {
            get { return true; }
        }

        public ulong TotalPageErases { get; set; }
        public ulong FaultAtPageErase { get; set; } = ulong.MaxValue;
        public bool EraseFaultFired { get; set; }

        public bool AnyFaultFired
        {
            get { return Nvm != null && Nvm.FaultEverFired; }
        }

        public bool FaultRequiresImmediateStop
        {
            get { return Nvm != null && Nvm.FaultEverFired; }
        }

        public bool DriverErrorFired
        {
            get { return Nvm != null && Nvm.DriverErrorFired; }
            set { if(Nvm != null) { Nvm.DriverErrorFired = value; } }
        }

        public uint LastFaultAddress { get; set; }
        public byte[] FaultFlashSnapshot { get; set; }

        public int WriteFaultMode
        {
            get { return Nvm != null ? Nvm.WriteFaultMode : 0; }
            set { if(Nvm != null) { Nvm.WriteFaultMode = value; } }
        }

        public int EraseFaultMode { get; set; }

        public uint CorruptionSeed
        {
            get { return Nvm != null ? Nvm.CorruptionSeed : 0U; }
            set { if(Nvm != null) { Nvm.CorruptionSeed = value; } }
        }

        public int DiffLookahead { get; set; }
        public bool SkipShadowScan { get; set; }
        public bool PassthroughMode { get; set; }
        public void InvalidateShadow() { }

        public bool WriteTraceEnabled
        {
            get { return Nvm != null && Nvm.WriteTraceEnabled; }
            set { if(Nvm != null) { Nvm.WriteTraceEnabled = value; } }
        }
        public bool WriteTraceWidthExplicit => Nvm != null && Nvm.WriteTraceWidthExplicit;
        public int WriteTraceCount { get { return Nvm != null ? Nvm.WriteTraceCount : 0; } }
        public string WriteTraceToString() { return Nvm != null ? Nvm.WriteTraceToString() : string.Empty; }
        public void WriteTraceClear() { Nvm?.WriteTraceClear(); }
        public bool EraseTraceEnabled { get; set; }
        public int EraseTraceCount { get { return 0; } }
        public string EraseTraceToString() { return string.Empty; }
        public void EraseTraceClear() { }

        public bool ReadFaultEnabled
        {
            get { return Nvm != null && Nvm.ReadFaultEnabled; }
            set { if(Nvm != null) { Nvm.ReadFaultEnabled = value; } }
        }

        public long ReadFaultAddress
        {
            get { return Nvm != null ? Nvm.ReadFaultAddress : -1L; }
            set { if(Nvm != null) { Nvm.ReadFaultAddress = value; } }
        }

        public uint ReadFaultSeed
        {
            get { return Nvm != null ? Nvm.ReadFaultSeed : 0U; }
            set { if(Nvm != null) { Nvm.ReadFaultSeed = value; } }
        }

        public int ReadFaultBitFlips
        {
            get { return Nvm != null ? Nvm.ReadFaultBitFlips : 1; }
            set { if(Nvm != null) { Nvm.ReadFaultBitFlips = value; } }
        }

        public bool ReadFaultFired
        {
            get { return Nvm != null && Nvm.ReadFaultFired; }
            set { if(Nvm != null) { Nvm.ReadFaultFired = value; } }
        }

        public ulong ReadFaultSkipCount
        {
            get { return Nvm != null ? Nvm.ReadFaultSkipCount : 0UL; }
            set { if(Nvm != null) { Nvm.ReadFaultSkipCount = value; } }
        }

        public ulong ReadFaultTotalReads
        {
            get { return Nvm != null ? Nvm.ReadFaultTotalReads : 0UL; }
            set { if(Nvm != null) { Nvm.ReadFaultTotalReads = value; } }
        }

        private void DefineRegisters()
        {
            Registers.MiscStatus.Define(this)
                .WithValueField(0, 32, FieldMode.Read, valueProviderCallback: _ => ComposeMiscStatus());

            Registers.EfuseStrobeLen.Define(this)
                .WithValueField(0, 32, out efuseStrobeLen, FieldMode.Read | FieldMode.Write);

            Registers.EfuseCtrl.Define(this)
                .WithValueField(0, 32, out efuseCtrl, FieldMode.Read | FieldMode.Write);

            Registers.EfuseOp.Define(this)
                .WithValueField(0, 32, out efuseOp, FieldMode.Read | FieldMode.Write);

            Registers.EfuseSpare.Define(this)
                .WithValueField(0, 32,
                    valueProviderCallback: _ => efuseSpareValue,
                    writeCallback: (_, value) =>
                    {
                        // OTP semantics: bits can only be set, never cleared.
                        efuseSpareValue |= (uint)value;
                    });

            Registers.NvmCfg.Define(this)
                .WithValueField(0, 32, out nvmCfg, FieldMode.Read | FieldMode.Write);

            Registers.NvmOverride.Define(this)
                .WithValueField(0, 32, out nvmOverride, FieldMode.Read | FieldMode.Write);

            Registers.NvmCtrl.Define(this)
                .WithValueField(0, 32,
                    valueProviderCallback: _ => ComposeNvmCtrl(),
                    writeCallback: (_, value) =>
                    {
                        // Writable bits: ECC_BYPASS[0], ERASE_EN[2:1], PROG_EN[3].
                        nvmCtrlWriteableBits = (uint)(value & 0xF);
                    });

            Registers.NvmEc0.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[0], writeCallback: (_, value) => eccCounters[0] = (uint)value);
            Registers.NvmEc1.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[1], writeCallback: (_, value) => eccCounters[1] = (uint)value);
            Registers.NvmEc2.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[2], writeCallback: (_, value) => eccCounters[2] = (uint)value);
            Registers.NvmEc3.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[3], writeCallback: (_, value) => eccCounters[3] = (uint)value);

            Registers.NvmUe.Define(this)
                .WithValueField(0, 32, out nvmUe, FieldMode.Read | FieldMode.Write);

            Registers.NvmEcUeRst.Define(this)
                .WithValueField(0, 32, FieldMode.Write, writeCallback: (_, value) =>
                {
                    if(value == 0)
                    {
                        return;
                    }

                    for(var i = 0; i < eccCounters.Length; i++)
                    {
                        eccCounters[i] = 0;
                    }
                    nvmUe.Value = 0;
                });
        }

        private uint ComposeMiscStatus()
        {
            // Keep ROM-useful flags set while emulating operational bits 8..11.
            var status = 0U;
            status |= (1U << 2); // TRIM_FUSED
            status |= (1U << 3); // NVM_PROGRAMMED

            if(Nvm != null && Nvm.IsWriteInProgress())
            {
                status |= (1U << 9);  // PROG_ACTIVE
                status |= (1U << 10); // ERASE_ACTIVE
            }

            if(illegalOperation)
            {
                status |= (1U << 11); // ILLEGAL_OPERATION
            }

            return status;
        }

        private uint ComposeNvmCtrl()
        {
            var ctrl = nvmCtrlWriteableBits;

            // Model immediate readiness in the simplified timing model.
            ctrl |= (1U << 8); // RDY_FOR_ERASE
            ctrl |= (1U << 9); // RDY_FOR_PROG

            return ctrl;
        }

        private bool TryNormalizeAddress(long address, out long normalized)
        {
            if(Nvm == null)
            {
                normalized = address;
                return true;
            }

            if(address >= 0 && address < Nvm.Size)
            {
                normalized = address;
                return true;
            }

            if(address >= NvmBaseAddress && address < NvmBaseAddress + Nvm.Size)
            {
                normalized = address - NvmBaseAddress;
                return true;
            }

            var nvReadBase = NvmBaseAddress + NvReadOffset;
            if(address >= nvReadBase && address < nvReadBase + Nvm.Size)
            {
                normalized = address - nvReadBase;
                return true;
            }

            normalized = 0;
            return false;
        }

        private uint efuseSpareValue;

        private IValueRegisterField efuseStrobeLen;
        private IValueRegisterField efuseCtrl;
        private IValueRegisterField efuseOp;
        private IValueRegisterField nvmCfg;
        private IValueRegisterField nvmOverride;
        private IValueRegisterField nvmUe;

        private uint nvmCtrlWriteableBits;
        private readonly uint[] eccCounters = new uint[4];
        private bool illegalOperation;

        private const long ControllerWindowSize = 0x58;

        private enum Registers : long
        {
            MiscStatus = 0x00,
            EfuseStrobeLen = 0x04,
            EfuseCtrl = 0x08,
            EfuseOp = 0x0C,
            EfuseSpare = 0x10,
            NvmCfg = 0x20,
            NvmOverride = 0x24,
            NvmCtrl = 0x30,
            NvmEc0 = 0x40,
            NvmEc1 = 0x44,
            NvmEc2 = 0x48,
            NvmEc3 = 0x4C,
            NvmUe = 0x50,
            NvmEcUeRst = 0x54,
        }
    }
}
