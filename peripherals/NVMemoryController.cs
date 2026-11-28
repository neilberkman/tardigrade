// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.IRQControllers;
using Antmicro.Renode.Peripherals.Miscellaneous;

namespace Antmicro.Renode.Peripherals.Memory
{
    // Persistent non-volatile memory model with configurable write granularity and optional sector erase.
    // Supports MRAM (word-write, no sector erase), flash (sector erase + word program), FRAM, and other NVM.
    public class NVMemory : IMemory, IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IQuadWordPeripheral, IKnownSize
    {
        public NVMemory(IMachine machine, long size = DefaultSize, long wordSize = DefaultWordSize)
        {
            if(size <= 0 || size > int.MaxValue)
            {
                throw new ArgumentException("NVM size must be between 1 and Int32.MaxValue");
            }

            operationTimer = new FlashOperationTimer(this);
            this.machine = machine;
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
            operationTimer.Reset();
            eraseInProgress = false;
            WriteInProgress = false;
            if(FaultEverFired || EraseFaultFired)
            {
                trackingStartAddress = 0;
                trackingStarted = false;
            }
            else if(PreserveCountersAcrossReset)
            {
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
                LastFaultInjected = false;
                FaultEverFired = false;
                EraseFaultFired = false;
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
            CheckUncorrectableCpuRead(offset, 1);
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
            CheckUncorrectableCpuRead(offset, 2);
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
            CheckUncorrectableCpuRead(offset, 4);
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
            CheckUncorrectableCpuRead(offset, 8);
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
            return WriteInProgress || operationTimer.Busy;
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
                    TrackingBaseSnapshotClear();
                    ResetCampaignObservability();
                    return;
                }

                // Activation is one transition: discard any pre-campaign
                // diagnostics, enable tracking, and leave the armed fault
                // index untouched. The next program is therefore write 1.
                if(!trackingStarted)
                {
                    ResetCampaignObservability();
                    CaptureTrackingBaseState();
                }
                trackingStartAddress = 0;
                trackingStarted = true;
            }
        }

        public bool TrackingStarted
        {
            get { return AliasTarget != null ? AliasTarget.TrackingStarted : trackingStarted; }
        }

        public bool TrackingBaseSnapshotAvailable
        {
            get
            {
                return AliasTarget != null
                    ? AliasTarget.TrackingBaseSnapshotAvailable
                    : trackingBaseSnapshot != null && trackingBaseSnapshot.Length == Size;
            }
        }

        public byte[] TrackingBaseSnapshot
        {
            get
            {
                return AliasTarget != null
                    ? AliasTarget.TrackingBaseSnapshot
                    : CloneBytes(trackingBaseSnapshot);
            }
        }

        public int TrackingBaseSnapshotSize
        {
            get
            {
                return AliasTarget != null
                    ? AliasTarget.TrackingBaseSnapshotSize
                    : (trackingBaseSnapshot != null ? trackingBaseSnapshot.Length : 0);
            }
        }

        public string TrackingBaseUncorrectableWordsToString()
        {
            return AliasTarget != null
                ? AliasTarget.TrackingBaseUncorrectableWordsToString()
                : FormatWordOffsets(trackingBaseUncorrectableWords);
        }

        public void TrackingBaseSnapshotClear()
        {
            if(AliasTarget != null)
            {
                AliasTarget.TrackingBaseSnapshotClear();
                return;
            }
            trackingBaseSnapshot = null;
            trackingBaseUncorrectableWords.Clear();
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
            if(AliasTarget != null) AliasTarget.WriteTraceClear();
            else
            {
                writeTrace.Clear();
                writeCallContexts.Clear();
            }
        }

        public string WriteCallContextToString()
        {
            if(AliasTarget != null) return AliasTarget.WriteCallContextToString();
            if(writeCallContexts.Count == 0) return string.Empty;
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

        public ulong LastFaultEraseIndex
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultEraseIndex : lastFaultEraseIndex; }
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

        public int LastFaultEraseSize
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultEraseSize : lastFaultProgramWidth; }
        }

        public byte[] LastFaultIntendedBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultIntendedBytes : CloneBytes(lastFaultIntendedBytes); }
        }

        public byte[] LastFaultPreProgramBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPreProgramBytes : CloneBytes(lastFaultPreProgramBytes); }
        }

        public byte[] LastFaultPreEraseBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPreEraseBytes : CloneBytes(lastFaultPreProgramBytes); }
        }

        public byte[] LastFaultPostFaultBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPostFaultBytes : CloneBytes(lastFaultPostFaultBytes); }
        }

        public byte[] LastFaultPostEraseBytes
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPostEraseBytes : CloneBytes(lastFaultPostFaultBytes); }
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
                return (lastFaultWriteIndex != 0 || lastFaultEraseIndex != 0)
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

        public bool EraseFaultEvidenceExact
        {
            get
            {
                if(AliasTarget != null) return AliasTarget.EraseFaultEvidenceExact;
                return lastFaultEraseIndex != 0 && FaultEvidenceExact;
            }
        }

        public int ProgramTraceCount
        {
            get { return AliasTarget != null ? AliasTarget.ProgramTraceCount : programTrace.Count; }
        }

        public string ProgramTraceToString()
        {
            if(AliasTarget != null) return AliasTarget.ProgramTraceToString();
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

        public uint MramTornWordSeed
        {
            get { return AliasTarget != null ? AliasTarget.MramTornWordSeed : mramTornWordSeed; }
            set
            {
                if(AliasTarget != null)
                {
                    AliasTarget.MramTornWordSeed = value;
                    return;
                }
                mramTornWordSeed = value;
            }
        }

        public string MramTornWordMode
        {
            get { return AliasTarget != null ? AliasTarget.MramTornWordMode : mramTornWordMode; }
            set
            {
                if(AliasTarget != null)
                {
                    AliasTarget.MramTornWordMode = value;
                    return;
                }
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

        public int UncorrectableWordCount
        {
            get { return AliasTarget != null ? AliasTarget.UncorrectableWordCount : uncorrectableWords.Count; }
        }

        public bool LastFaultMarkedUncorrectable
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultMarkedUncorrectable : lastFaultMarkedUncorrectable; }
        }

        public ulong UncorrectableReadCount
        {
            get { return AliasTarget != null ? AliasTarget.UncorrectableReadCount : uncorrectableReadCount; }
        }

        public ulong LastUncorrectableReadWordAddress
        {
            get { return AliasTarget != null ? AliasTarget.LastUncorrectableReadWordAddress : lastUncorrectableReadWordAddress; }
        }

        public ulong LastUncorrectableReadAddress
        {
            get { return AliasTarget != null ? AliasTarget.LastUncorrectableReadAddress : lastUncorrectableReadAddress; }
        }

        public ulong LastUncorrectableReadPC
        {
            get { return AliasTarget != null ? AliasTarget.LastUncorrectableReadPC : lastUncorrectableReadPC; }
        }

        public bool IsWordUncorrectable(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.IsWordUncorrectable(offset);
            }
            if(offset < 0 || offset >= size)
            {
                return false;
            }
            return uncorrectableWords.Contains(AlignDown(offset, WordSize));
        }

        public bool IsAddressUncorrectable(ulong busAddress)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.IsAddressUncorrectable(busAddress);
            }
            if(programAddressBase == 0)
            {
                return false;
            }
            if(busAddress < programAddressBase || busAddress >= programAddressBase + (ulong)size)
            {
                return false;
            }
            return IsWordUncorrectable((long)(busAddress - programAddressBase));
        }

        public void MarkWordUncorrectable(long offset)
        {
            if(AliasTarget != null)
            {
                AliasTarget.MarkWordUncorrectable(offset);
                return;
            }
            if(offset < 0 || offset >= size)
            {
                return;
            }
            MarkWordUncorrectableInternal(AlignDown(offset, WordSize));
        }

        public void ClearUncorrectableWord(long offset)
        {
            if(AliasTarget != null)
            {
                AliasTarget.ClearUncorrectableWord(offset);
                return;
            }
            if(offset < 0 || offset >= size)
            {
                return;
            }
            ClearUncorrectableWordInternal(AlignDown(offset, WordSize));
        }

        public void ClearUncorrectableWords()
        {
            if(AliasTarget != null)
            {
                AliasTarget.ClearUncorrectableWords();
                return;
            }
            uncorrectableWords.Clear();
            ClearUncorrectableReadLog();
        }

        public string UncorrectableWordsToString()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.UncorrectableWordsToString();
            }
            return FormatWordOffsets(uncorrectableWords);
        }

        public string FaultUncorrectableWordsToString()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.FaultUncorrectableWordsToString();
            }
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
            foreach(var wordOffset in sorted)
            {
                result.Append(wordOffset);
                result.Append(':');
                result.Append("0x");
                result.Append((programAddressBase + (ulong)wordOffset).ToString("X8"));
                result.Append('\n');
            }
            return result.ToString();
        }

        public string UncorrectableReadsToString()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.UncorrectableReadsToString();
            }
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
            if(AliasTarget != null)
            {
                AliasTarget.ClearUncorrectableReadLog();
                return;
            }
            uncorrectableReads.Clear();
            uncorrectableReadCount = 0;
            lastUncorrectableReadWordAddress = 0;
            lastUncorrectableReadAddress = 0;
            lastUncorrectableReadPC = 0;
        }

        public bool PreserveCountersAcrossReset
        {
            get { return AliasTarget != null ? AliasTarget.PreserveCountersAcrossReset : preserveCountersAcrossReset; }
            set
            {
                if(AliasTarget != null)
                {
                    AliasTarget.PreserveCountersAcrossReset = value;
                    return;
                }
                preserveCountersAcrossReset = value;
            }
        }

        public uint WriteLatencyMicros { get; set; }
        public uint EraseLatencyMicros { get; set; }
        // An attached NVMC can own the program clock and one-word write buffer.
        public Action<long, int, Action> ProgramScheduler { get; set; }
        public bool EraseInProgress => AliasTarget != null ? AliasTarget.EraseInProgress : eraseInProgress;
        private bool eraseInProgress;
        public FlashTimingCalibration TimingCalibration => operationTimer.Calibration;
        private readonly FlashOperationTimer operationTimer;

        public bool WriteInProgress { get; private set; }

        public bool LastFaultInjected { get; set; }

        // Sticky fault flag: set when any fault fires, cleared only by Reset()
        // or explicit assignment. Unlike LastFaultInjected (which is cleared at
        // the start of each WriteBytesInternal), this survives subsequent writes.
        public bool FaultEverFired { get; set; }
        public bool DriverErrorFired { get; set; }

        public byte LastFaultPattern { get; private set; }

        public ulong TotalWordWrites { get; set; }

        public ulong TotalPageErases
        {
            get { return AliasTarget != null ? AliasTarget.TotalPageErases : totalPageErases; }
            set
            {
                if(AliasTarget != null) AliasTarget.TotalPageErases = value;
                else totalPageErases = value;
            }
        }

        public ulong FaultAtPageErase
        {
            get { return AliasTarget != null ? AliasTarget.FaultAtPageErase : faultAtPageErase; }
            set
            {
                if(AliasTarget != null) AliasTarget.FaultAtPageErase = value;
                else faultAtPageErase = value;
            }
        }

        public bool EraseFaultFired
        {
            get { return AliasTarget != null ? AliasTarget.EraseFaultFired : eraseFaultFired; }
            set
            {
                if(AliasTarget != null) AliasTarget.EraseFaultFired = value;
                else eraseFaultFired = value;
            }
        }

        public int EraseFaultMode
        {
            get { return AliasTarget != null ? AliasTarget.EraseFaultMode : eraseFaultMode; }
            set
            {
                if(AliasTarget != null) AliasTarget.EraseFaultMode = value;
                else eraseFaultMode = value;
            }
        }

        public bool EraseTraceEnabled
        {
            get { return AliasTarget != null ? AliasTarget.EraseTraceEnabled : eraseTraceEnabled; }
            set
            {
                if(AliasTarget != null) AliasTarget.EraseTraceEnabled = value;
                else eraseTraceEnabled = value;
            }
        }

        public int EraseTraceCount
        {
            get { return AliasTarget != null ? AliasTarget.EraseTraceCount : eraseTrace.Count; }
        }

        public string EraseTraceToString()
        {
            if(AliasTarget != null) return AliasTarget.EraseTraceToString();
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
            if(AliasTarget != null) AliasTarget.EraseTraceClear();
            else
            {
                eraseTrace.Clear();
                eraseCallContexts.Clear();
            }
        }

        public string EraseCallContextToString()
        {
            if(AliasTarget != null) return AliasTarget.EraseCallContextToString();
            if(eraseCallContexts.Count == 0) return string.Empty;
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

        public uint LastFaultAddress
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultAddress : lastFaultAddress; }
            set
            {
                if(AliasTarget != null) AliasTarget.LastFaultAddress = value;
                else lastFaultAddress = value;
            }
        }

        public ulong LastFaultPC
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultPC : lastFaultPC; }
            set
            {
                if(AliasTarget != null) AliasTarget.LastFaultPC = value;
                else lastFaultPC = value;
            }
        }

        public string LastFaultCallContext
        {
            get { return AliasTarget != null ? AliasTarget.LastFaultCallContext : lastFaultCallContext; }
            set
            {
                if(AliasTarget != null) AliasTarget.LastFaultCallContext = value;
                else lastFaultCallContext = value;
            }
        }

        public byte[] FaultFlashSnapshot
        {
            get { return AliasTarget != null ? AliasTarget.FaultFlashSnapshot : CloneBytes(faultMemorySnapshot); }
            set
            {
                if(AliasTarget != null) AliasTarget.FaultFlashSnapshot = value;
                else faultMemorySnapshot = CloneBytes(value);
            }
        }

        public bool AnyFaultFired
        {
            get { return AliasTarget != null ? AliasTarget.AnyFaultFired : (FaultEverFired || eraseFaultFired); }
        }

        public bool FaultRequiresImmediateStop
        {
            get
            {
                if(AliasTarget != null) return AliasTarget.FaultRequiresImmediateStop;
                return eraseFaultFired || (FaultEverFired && WriteFaultMode == 0);
            }
        }

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

        public void EraseSectorRaw(long offset, int sectorSize)
        {
            if(AliasTarget != null)
            {
                AliasTarget.EraseSectorRaw(offset, sectorSize);
                return;
            }

            if(sectorSize <= 0 || !TryValidateRange(offset, sectorSize))
            {
                LogOutOfRangeWrite(offset, sectorSize);
                return;
            }
            for(var i = 0; i < sectorSize; i++)
            {
                storage[offset + i] = EraseFill;
            }
            ClearUncorrectableRangeInternal(offset, sectorSize);
        }

        public void WriteSpanRaw(long offset, byte[] data)
        {
            if(AliasTarget != null)
            {
                AliasTarget.WriteSpanRaw(offset, data);
                return;
            }

            if(data == null || data.Length == 0 || !TryValidateRange(offset, data.Length))
            {
                if(data != null && data.Length > 0)
                {
                    LogOutOfRangeWrite(offset, data.Length);
                }
                return;
            }
            Array.Copy(data, 0, storage, offset, data.Length);
            ClearUncorrectableRangeInternal(offset, data.Length);
        }

        public void RestoreSnapshotRaw(byte[] snapshot)
        {
            if(AliasTarget != null)
            {
                AliasTarget.RestoreSnapshotRaw(snapshot);
                return;
            }
            if(snapshot == null || snapshot.Length == 0)
            {
                return;
            }
            var count = Math.Min(storage.Length, snapshot.Length);
            Array.Copy(snapshot, 0, storage, 0, count);
            ClearUncorrectableRangeInternal(0, count);
        }

        public void EraseSector(long offset, int sectorSize)
        {
            if(AliasTarget != null)
            {
                AliasTarget.EraseSector(offset, sectorSize);
                return;
            }

            if(sectorSize <= 0 || !TryValidateRange(offset, sectorSize))
            {
                LogOutOfRangeWrite(offset, sectorSize);
                return;
            }
            EraseSpanInternal(offset, sectorSize);
        }

        public void EraseWord(long offset)
        {
            if(AliasTarget != null)
            {
                AliasTarget.EraseWord(offset);
                return;
            }

            var aligned = AlignDown(offset, WordSize);
            if(!TryValidateRange(aligned, WordSize))
            {
                LogOutOfRangeWrite(aligned, WordSize);
                return;
            }
            EraseSpanInternal(aligned, checked((int)WordSize));
        }

        private void EraseSpanInternal(long offset, int spanSize)
        {
            if(operationTimer.Busy)
            {
                return;
            }
            if(EraseLatencyMicros == 0
                || (TrackingStarted && !eraseFaultFired && totalPageErases + 1 == faultAtPageErase))
            {
                CompleteEraseSpan(offset, spanSize);
                return;
            }
            eraseInProgress = true;
            operationTimer.Start(EraseLatencyMicros, () =>
            {
                eraseInProgress = false;
                CompleteEraseSpan(offset, spanSize);
            });
        }

        private void CompleteEraseSpan(long offset, int spanSize)
        {
            if(!TrackingStarted)
            {
                EraseSectorRaw(offset, spanSize);
                return;
            }

            if(eraseFaultFired)
            {
                // Power has already been cut during an erase; suppress further erases.
                return;
            }

            var erasePc = CurrentCpuPc();
            var eraseCtx = CaptureCpuCallContext(erasePc);
            var currentEraseIndex = totalPageErases + 1;
            totalPageErases = currentEraseIndex;
            if(eraseTraceEnabled || faultAtPageErase != ulong.MaxValue)
            {
                TraceTimes.Record(true, currentEraseIndex);
                eraseTrace.Add(new EraseTraceEntry(
                    currentEraseIndex, offset, TotalWordWrites, spanSize, erasePc));
                if(!string.IsNullOrEmpty(eraseCtx))
                {
                    eraseCallContexts[currentEraseIndex] = eraseCtx;
                }
            }

            if(currentEraseIndex == faultAtPageErase)
            {
                var preErase = new byte[spanSize];
                Array.Copy(storage, offset, preErase, 0, spanSize);
                lastFaultMarkedUncorrectable = false;

                ApplyTornEraseToStorage(offset, spanSize, preErase, currentEraseIndex);
                var postErase = new byte[spanSize];
                Array.Copy(storage, offset, postErase, 0, spanSize);
                var intendedErase = new byte[spanSize];
                if(EraseFill != 0)
                {
                    for(var i = 0; i < intendedErase.Length; i++)
                    {
                        intendedErase[i] = EraseFill;
                    }
                }

                eraseFaultFired = true;
                LastFaultInjected = true;
                LastFaultPattern = EraseFill;
                lastFaultAddress = unchecked((uint)(programAddressBase + (ulong)offset));
                lastFaultPC = erasePc;
                lastFaultCallContext = eraseCtx;
                lastFaultWriteIndex = 0;
                lastFaultEraseIndex = currentEraseIndex;
                lastFaultOffset = offset;
                lastFaultProgramAddress = programAddressBase + (ulong)offset;
                lastFaultProgramWidth = spanSize;
                lastFaultIntendedBytes = intendedErase;
                lastFaultPreProgramBytes = preErase;
                lastFaultPostFaultBytes = postErase;
                faultMemorySnapshot = CloneBytes(storage);
                faultUncorrectableWords.Clear();
                faultUncorrectableWords.AddRange(uncorrectableWords);
                return;
            }

            EraseSectorRaw(offset, spanSize);
        }

        private void ApplyTornEraseToStorage(long offset, int spanSize, byte[] preErase, ulong eraseIndex)
        {
            if(eraseFaultMode == 1)
            {
                var halfSpan = Math.Max(1, spanSize / 2);
                for(var i = 0; i < halfSpan; i++)
                {
                    storage[offset + i] = EraseFill;
                }
                ClearUncorrectableRangeInternal(offset, halfSpan);
                var quarterSpan = Math.Max(1, spanSize / 4);
                var neighbor = offset + spanSize;
                if(TryValidateRange(neighbor, quarterSpan))
                {
                    for(var i = 0; i < quarterSpan; i++)
                    {
                        storage[neighbor + i] = EraseFill;
                    }
                    ClearUncorrectableRangeInternal(neighbor, quarterSpan);
                }
                return;
            }

            var mode = mramTornWordMode;
            switch(mode)
            {
                case "untouched":
                    // Power cut before erase took effect: retain pre-erase bytes and marks.
                    break;
                case "erased":
                case "programmed":
                    // Erase completed immediately before power cut (cuts between erase and program).
                    for(var i = 0; i < spanSize; i++)
                    {
                        storage[offset + i] = EraseFill;
                    }
                    ClearUncorrectableRangeInternal(offset, spanSize);
                    break;
                case "uncorrectable":
                    // Interrupted erase leaves every affected program unit with an uncorrectable ECC error.
                    var firstUnit = AlignDown(offset, WordSize);
                    var lastUnit = AlignDown(offset + spanSize - 1, WordSize);
                    for(var unit = firstUnit; unit <= lastUnit; unit += WordSize)
                    {
                        MarkWordUncorrectableInternal(unit);
                    }
                    lastFaultMarkedUncorrectable = true;
                    break;
                case "corrupted":
                    // Erased fill with deterministic multi-bit corruption across each affected unit.
                    for(var i = 0; i < spanSize; i++)
                    {
                        storage[offset + i] = EraseFill;
                    }
                    ClearUncorrectableRangeInternal(offset, spanSize);
                    var cFirst = AlignDown(offset, WordSize);
                    var cLast = AlignDown(offset + spanSize - 1, WordSize);
                    for(var unit = cFirst; unit <= cLast; unit += WordSize)
                    {
                        var unitLen = (int)Math.Min(WordSize, size - unit);
                        var unitBytes = new byte[unitLen];
                        Array.Copy(storage, unit, unitBytes, 0, unitLen);
                        ApplyCorruptedTornWord(unitBytes, eraseIndex, unit, EffectiveMramTornWordSeed());
                        Array.Copy(unitBytes, 0, storage, unit, unitLen);
                    }
                    break;
                default:
                    // half / half_retain: first half erased to EraseFill, second half retains pre-erase bytes.
                    var half = spanSize / 2;
                    if(half <= 0 && spanSize > 0)
                    {
                        half = spanSize;
                    }
                    for(var i = 0; i < half; i++)
                    {
                        storage[offset + i] = EraseFill;
                    }
                    for(var i = half; i < spanSize; i++)
                    {
                        storage[offset + i] = preErase[i];
                    }
                    if(half > 0)
                    {
                        ClearUncorrectableRangeInternal(offset, half);
                    }
                    break;
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
            if(operationTimer.Busy)
            {
                return;
            }
            if(ProgramScheduler != null)
            {
                ProgramScheduler(offset, data.Length, () => CompleteProgram(offset, data));
                return;
            }
            if(WriteLatencyMicros != 0)
            {
                StartProgramUnit(offset, data, 0, WriteLatencyMicros);
                return;
            }
            CompleteProgram(offset, data);
        }

        private void StartProgramUnit(long offset, byte[] data, int cursor, uint delay)
        {
            var address = offset + cursor;
            int count = (int)Math.Min(data.Length - cursor, WordSize - address % WordSize);
            if(TrackingStarted && !eraseFaultFired && !(FaultEverFired && WriteFaultMode == 0)
                && FaultAtWordWrite != ulong.MaxValue
                && TotalWordWrites + 1 == FaultAtWordWrite
                && WriteFaultMode == 0)
            {
                var immediateSlice = new byte[count];
                Array.Copy(data, cursor, immediateSlice, 0, count);
                CompleteProgram(address, immediateSlice);
                return;
            }
            operationTimer.Start(delay, () =>
            {
                var slice = new byte[count];
                Array.Copy(data, cursor, slice, 0, count);
                CompleteProgram(address, slice);
                if(cursor + count < data.Length && !(FaultEverFired && WriteFaultMode == 0) && !eraseFaultFired)
                {
                    StartProgramUnit(offset, data, cursor + count, delay);
                }
            });
        }

        private void CompleteProgram(long offset, byte[] data)
        {
            LastWriteAddress = offset;

            if(!TrackingStarted)
            {
                ProgramWithoutCampaignTracking(offset, data);
                return;
            }

            if(eraseFaultFired)
            {
                // Power has already been cut during an erase; suppress post-cut writes.
                return;
            }

            var writePc = CurrentCpuPc();

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
                        lastFaultMarkedUncorrectable = false;
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: data already written above; flip random bits.
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                            ClearUncorrectableWordInternal(wordStart);
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
                            switch(mramTornWordMode)
                            {
                                case "half_retain":
                                    var retainSplit = WordSize / 2;
                                    for(var i = 0L; i < retainSplit; i++)
                                    {
                                        storage[wordStart + i] = intendedWord[i];
                                    }

                                    for(var i = retainSplit; i < WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "untouched":
                                    for(var i = 0; i < (int)WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "erased":
                                    for(var i = 0L; i < WordSize; i++)
                                    {
                                        storage[wordStart + i] = EraseFill;
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "programmed":
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "uncorrectable":
                                    for(var i = 0; i < (int)WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    MarkWordUncorrectableInternal(wordStart);
                                    lastFaultMarkedUncorrectable = true;
                                    break;
                                case "corrupted":
                                    ApplyCorruptedWordAt(wordStart, intendedWord, currentWriteIndex);
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                default:
                                    // Power-loss: corrupt second half of faulted word with EraseFill.
                                    var half = WordSize / 2;
                                    for(var i = wordStart + half; i < wordStart + WordSize; i++)
                                    {
                                        if(i >= offset && i < offset + data.Length)
                                        {
                                            storage[i] = EraseFill;
                                        }
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                            }
                        }
                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : EraseFill);
                        TotalWordWrites++;
                        LastWriteAddress = wordStart;
                        RecordWriteTrace(wordStart, writePc);
                        var postFaultWord = ReadStorageWord(wordStart);
                        RecordProgramTrace(
                            currentWriteIndex, wordStart, intendedWord,
                            previousWord, postFaultWord, true, writePc
                        );
                        CaptureFaultEvidence(
                            currentWriteIndex, wordStart, intendedWord,
                            previousWord, postFaultWord, writePc
                        );
                        return;
                    }

                    ClearUncorrectableWordInternal(wordStart);
                    RecordProgramTrace(
                        currentWriteIndex, wordStart, intendedWord,
                        previousWord, ReadStorageWord(wordStart), false, writePc
                    );
                    TotalWordWrites++;
                    RecordWriteTrace(wordStart, writePc);
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

                    EraseWordStorage(wordStart);

                    var currentWriteIndex = TotalWordWrites + 1;
                    if(currentWriteIndex == FaultAtWordWrite)
                    {
                        lastFaultMarkedUncorrectable = false;
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: write full word, then flip random bits.
                            ProgramWord(wordStart, mergedWord);
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                            ClearUncorrectableWordInternal(wordStart);
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
                            switch(mramTornWordMode)
                            {
                                case "half_retain":
                                    var retainSplit = WordSize / 2;
                                    for(var i = 0L; i < retainSplit; i++)
                                    {
                                        storage[wordStart + i] = mergedWord[i];
                                    }

                                    for(var i = retainSplit; i < WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "untouched":
                                    for(var i = 0; i < (int)WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "erased":
                                    for(var i = 0L; i < WordSize; i++)
                                    {
                                        storage[wordStart + i] = EraseFill;
                                    }
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "programmed":
                                    ProgramWord(wordStart, mergedWord);
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                case "uncorrectable":
                                    for(var i = 0; i < (int)WordSize; i++)
                                    {
                                        storage[wordStart + i] = previousWord[i];
                                    }
                                    MarkWordUncorrectableInternal(wordStart);
                                    lastFaultMarkedUncorrectable = true;
                                    break;
                                case "corrupted":
                                    ApplyCorruptedWordAt(wordStart, mergedWord, currentWriteIndex);
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                                default:
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
                                    ClearUncorrectableWordInternal(wordStart);
                                    break;
                            }
                        }

                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : EraseFill);
                        TotalWordWrites++;
                        writeLog.Add(wordStart);
                        RecordWriteTrace(wordStart, writePc);
                        var postFaultWord = ReadStorageWord(wordStart);
                        RecordProgramTrace(
                            currentWriteIndex, wordStart, mergedWord,
                            previousWord, postFaultWord, true, writePc
                        );
                        CaptureFaultEvidence(
                            currentWriteIndex, wordStart, mergedWord,
                            previousWord, postFaultWord, writePc
                        );
                        break;
                    }

                    ProgramWord(wordStart, mergedWord);
                    ClearUncorrectableWordInternal(wordStart);
                    RecordProgramTrace(
                        currentWriteIndex, wordStart, mergedWord,
                        previousWord, ReadStorageWord(wordStart), false, writePc
                    );
                    TotalWordWrites++;
                    writeLog.Add(wordStart);
                    RecordWriteTrace(wordStart);

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

        private void EraseWordStorage(long wordStart)
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
                ClearUncorrectableRangeInternal(offset, data.Length);
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
                    EraseWordStorage(wordStart);
                    ProgramWord(wordStart, mergedWord);
                    ClearUncorrectableWordInternal(wordStart);
                }
            }
            finally
            {
                WriteInProgress = false;
            }
        }

        private ulong CurrentCpuPc()
        {
            if(machine == null)
            {
                return 0UL;
            }
            try
            {
                var bus = machine.GetSystemBus(this);
                ICPU cpu;
                if(bus != null && bus.TryGetCurrentCPU(out cpu) && cpu != null)
                {
                    return cpu.PC.RawValue;
                }
            }
            catch
            {
            }
            return 0UL;
        }

        private void RecordWriteTrace(long wordStart)
        {
            RecordWriteTrace(wordStart, CurrentCpuPc());
        }

        private void RecordWriteTrace(long wordStart, ulong pc)
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
                TotalWordWrites, wordStart, value, checked((int)WordSize), pc
            ));
        }

        public RecoveryTraceTimes TraceTimes => AliasTarget != null ? AliasTarget.TraceTimes : traceTimes;
        private readonly RecoveryTraceTimes traceTimes = new RecoveryTraceTimes();

        private void RecordProgramTrace(ulong index, long offset, byte[] intended,
                                        byte[] preProgram, byte[] postProgram, bool faulted, ulong pc = 0)
        {
            var ctx = CaptureCpuCallContext(pc);
            if(!string.IsNullOrEmpty(ctx))
            {
                writeCallContexts[index] = ctx;
            }
            TraceTimes.Record(false, index);
            programTrace.Add(new ProgramTraceEntry(
                index, offset, (int)WordSize,
                CloneBytes(intended), CloneBytes(preProgram), CloneBytes(postProgram),
                faulted, pc
            ));
        }

        private void CaptureFaultEvidence(ulong index, long offset, byte[] intended,
                                          byte[] preProgram, byte[] postFault, ulong pc = 0)
        {
            lastFaultWriteIndex = index;
            lastFaultEraseIndex = 0;
            lastFaultOffset = offset;
            lastFaultProgramAddress = programAddressBase + (ulong)offset;
            lastFaultAddress = unchecked((uint)lastFaultProgramAddress);
            lastFaultPC = pc;
            string ctx;
            lastFaultCallContext = writeCallContexts.TryGetValue(index, out ctx) ? ctx : CaptureCpuCallContext(pc);
            lastFaultProgramWidth = (int)WordSize;
            lastFaultIntendedBytes = CloneBytes(intended);
            lastFaultPreProgramBytes = CloneBytes(preProgram);
            lastFaultPostFaultBytes = CloneBytes(postFault);
            faultMemorySnapshot = CloneBytes(storage);
            faultUncorrectableWords.Clear();
            faultUncorrectableWords.AddRange(uncorrectableWords);
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

        private uint EffectiveMramTornWordSeed()
        {
            return mramTornWordSeed != 0 ? mramTornWordSeed : CorruptionSeed;
        }

        private void ApplyCorruptedWordAt(long wordStart, byte[] intendedWord, ulong writeIndex)
        {
            var corrupted = CloneBytes(intendedWord);
            ApplyCorruptedTornWord(corrupted, writeIndex, wordStart, EffectiveMramTornWordSeed());
            ProgramWord(wordStart, corrupted);
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

        private void MarkWordUncorrectableInternal(long wordStart)
        {
            uncorrectableWords.Add(AlignDown(wordStart, WordSize));
        }

        private void ClearUncorrectableWordInternal(long wordStart)
        {
            if(uncorrectableWords.Count > 0)
            {
                uncorrectableWords.Remove(AlignDown(wordStart, WordSize));
            }
        }

        private void ClearUncorrectableRangeInternal(long offset, long length)
        {
            if(uncorrectableWords.Count == 0 || length <= 0 || offset < 0)
            {
                return;
            }
            var firstWord = AlignDown(offset, WordSize);
            var lastWord = AlignDown(offset + length - 1, WordSize);
            for(var word = firstWord; word <= lastWord; word += WordSize)
            {
                uncorrectableWords.Remove(word);
            }
        }

        private void CheckUncorrectableCpuRead(long offset, int accessSize)
        {
            if(uncorrectableWords.Count == 0 || machine == null || accessSize <= 0)
            {
                return;
            }
            var firstWord = AlignDown(offset, WordSize);
            var lastWord = AlignDown(offset + accessSize - 1, WordSize);
            long hitWord = -1;
            for(var word = firstWord; word <= lastWord; word += WordSize)
            {
                if(uncorrectableWords.Contains(word))
                {
                    hitWord = word;
                    break;
                }
            }
            if(hitWord < 0)
            {
                return;
            }
            IBusController bus = null;
            try
            {
                bus = machine.GetSystemBus(this);
            }
            catch
            {
                return;
            }
            ICPU cpu;
            if(bus == null || !bus.TryGetCurrentCPU(out cpu) || cpu == null)
            {
                // Tooling reads (snapshots, image hashing, memory checks, monitor)
                // have no active CPU context and must return stored bytes without raising.
                return;
            }
            ulong pc = 0;
            try
            {
                pc = cpu.PC.RawValue;
            }
            catch
            {
            }
            RecordUncorrectableRead(hitWord, offset, accessSize, pc);
            RaiseBusError(cpu);
        }

        private void RecordUncorrectableRead(long wordOffset, long accessOffset, int width, ulong pc)
        {
            var wordBusAddr = programAddressBase + (ulong)wordOffset;
            var accessBusAddr = programAddressBase + (ulong)accessOffset;
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

        private void ResetCampaignObservability()
        {
            TotalWordWrites = 0;
            totalPageErases = 0;
            writeLog.Clear();
            writeTrace.Clear();
            writeCallContexts.Clear();
            eraseTrace.Clear();
            eraseCallContexts.Clear();
            programTrace.Clear();
            ClearFaultEvidence();
            LastFaultInjected = false;
            FaultEverFired = false;
            eraseFaultFired = false;
            lastFaultAddress = 0;
            lastFaultPC = 0;
            lastFaultCallContext = null;
            DriverErrorFired = false;
        }

        private ulong cachedStackStart;
        private ulong cachedStackEnd;
        private readonly Dictionary<ulong, string> writeCallContexts = new Dictionary<ulong, string>();
        private readonly Dictionary<ulong, string> eraseCallContexts = new Dictionary<ulong, string>();

        private string CaptureCpuCallContext(ulong overridePc = 0)
        {
            if(machine == null)
            {
                return null;
            }
            try
            {
                var bus = machine.GetSystemBus(this);
                ICPU cpu;
                if(bus == null || !bus.TryGetCurrentCPU(out cpu) || cpu == null)
                {
                    return null;
                }
                var pc = overridePc != 0 ? overridePc : cpu.PC.RawValue;
                if(pc == 0)
                {
                    return null;
                }
                ulong lr = 0;
                ulong sp = 0;
                ulong r7 = 0;
                ulong r11 = 0;
                var tcpu = cpu as TranslationCPU;
                if(tcpu != null)
                {
                    try { lr = tcpu.GetRegisterUnsafe(14).RawValue; } catch { }
                    try { sp = tcpu.GetRegisterUnsafe(13).RawValue; } catch { }
                    try { r7 = tcpu.GetRegisterUnsafe(7).RawValue; } catch { }
                    try { r11 = tcpu.GetRegisterUnsafe(11).RawValue; } catch { }
                }
                var stackHex = string.Empty;
                var alignedSp = sp & ~3UL;
                if(alignedSp != 0)
                {
                    try
                    {
                        const int maxStackBytes = 256;
                        int readableLen = 0;
                        if(alignedSp >= cachedStackStart && (alignedSp + (ulong)maxStackBytes) <= cachedStackEnd)
                        {
                            readableLen = maxStackBytes;
                        }
                        else
                        {
                            var reg = bus.WhatIsAt(alignedSp, cpu);
                            if(reg != null && reg.Peripheral is IMemory)
                            {
                                var pageBase = alignedSp & ~0xFFFUL;
                                var endAddr = pageBase + 0x1000UL;
                                var regEnd = bus.WhatIsAt(endAddr - 4, cpu);
                                if(regEnd != null && regEnd.Peripheral == reg.Peripheral)
                                {
                                    var regNext = bus.WhatIsAt(endAddr, cpu);
                                    if(regNext != null && regNext.Peripheral == reg.Peripheral)
                                    {
                                        endAddr += 0x1000UL;
                                    }
                                    cachedStackStart = pageBase;
                                    cachedStackEnd = endAddr;
                                }
                                if(alignedSp >= cachedStackStart && alignedSp < cachedStackEnd)
                                {
                                    var avail = cachedStackEnd - alignedSp;
                                    readableLen = (int)(avail >= (ulong)maxStackBytes ? (ulong)maxStackBytes : (avail & ~3UL));
                                }
                                else
                                {
                                    readableLen = 64;
                                }
                            }
                        }
                        if(readableLen > 0)
                        {
                            var bytes = bus.ReadBytes(alignedSp, readableLen, true, cpu);
                            if(bytes != null && bytes.Length > 0)
                            {
                                var sb = new StringBuilder(bytes.Length * 2);
                                for(var i = 0; i < bytes.Length; i++)
                                {
                                    sb.Append(bytes[i].ToString("x2"));
                                }
                                stackHex = sb.ToString();
                            }
                        }
                    }
                    catch
                    {
                    }
                }
                return string.Format("0x{0:X8}@0x{1:X8}@0x{2:X8}@0x{3:X8}@0x{4:X8}@{5}",
                    pc, lr, alignedSp, r7, r11, stackHex);
            }
            catch
            {
                return null;
            }
        }

        private void CaptureTrackingBaseState()
        {
            trackingBaseSnapshot = CloneBytes(storage);
            trackingBaseUncorrectableWords.Clear();
            trackingBaseUncorrectableWords.AddRange(uncorrectableWords);
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

        private readonly IMachine machine;
        private byte eraseFill;
        private long size;
        private long wordSize;
        private byte[] storage;
        private uint corruptionSeed;
        private uint mramTornWordSeed;
        private string mramTornWordMode = "half";
        private bool preserveCountersAcrossReset;
        private readonly List<long> writeLog = new List<long>();
        private readonly List<WriteTraceEntry> writeTrace = new List<WriteTraceEntry>();
        private readonly List<EraseTraceEntry> eraseTrace = new List<EraseTraceEntry>();
        private readonly List<ProgramTraceEntry> programTrace = new List<ProgramTraceEntry>();
        private readonly HashSet<long> uncorrectableWords = new HashSet<long>();
        private readonly List<UncorrectableReadEntry> uncorrectableReads = new List<UncorrectableReadEntry>();
        private bool writeTraceEnabled;
        private bool eraseTraceEnabled;
        private ulong totalPageErases;
        private ulong faultAtPageErase = ulong.MaxValue;
        private bool eraseFaultFired;
        private int eraseFaultMode;
        private uint lastFaultAddress;
        private ulong lastFaultPC;
        private string lastFaultCallContext;
        private ulong trackingStartAddress;
        private ulong configuredTrackingStartAddress;
        private bool trackingStarted = true;
        private ulong programAddressBase;
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
            nvmEraseSizeValue = 0;
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
            Nvm.EraseSectorRaw(normalized, half);
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
        public ulong LastFaultEraseIndex => Nvm != null ? Nvm.LastFaultEraseIndex : 0UL;
        public ulong LastFaultProgramAddress => Nvm != null ? Nvm.LastFaultProgramAddress : 0UL;
        public long LastFaultOffset => Nvm != null ? Nvm.LastFaultOffset : -1L;
        public int LastFaultProgramWidth => Nvm != null ? Nvm.LastFaultProgramWidth : 0;
        public int LastFaultEraseSize => Nvm != null ? Nvm.LastFaultEraseSize : 0;
        public byte[] LastFaultIntendedBytes => Nvm != null ? Nvm.LastFaultIntendedBytes : null;
        public byte[] LastFaultPreProgramBytes => Nvm != null ? Nvm.LastFaultPreProgramBytes : null;
        public byte[] LastFaultPreEraseBytes => Nvm != null ? Nvm.LastFaultPreEraseBytes : null;
        public byte[] LastFaultPostFaultBytes => Nvm != null ? Nvm.LastFaultPostFaultBytes : null;
        public byte[] LastFaultPostEraseBytes => Nvm != null ? Nvm.LastFaultPostEraseBytes : null;
        public byte[] FaultMemorySnapshot => Nvm != null ? Nvm.FaultMemorySnapshot : null;
        public int FaultMemorySnapshotSize => Nvm != null ? Nvm.FaultMemorySnapshotSize : 0;
        public bool FaultEvidenceExact => Nvm != null && Nvm.FaultEvidenceExact;
        public bool EraseFaultEvidenceExact => Nvm != null && Nvm.EraseFaultEvidenceExact;
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

        public ulong TotalPageErases
        {
            get { return Nvm != null ? Nvm.TotalPageErases : 0UL; }
            set { if(Nvm != null) { Nvm.TotalPageErases = value; } }
        }

        public ulong FaultAtPageErase
        {
            get { return Nvm != null ? Nvm.FaultAtPageErase : ulong.MaxValue; }
            set { if(Nvm != null) { Nvm.FaultAtPageErase = value; } }
        }

        public bool EraseFaultFired
        {
            get { return Nvm != null && Nvm.EraseFaultFired; }
            set { if(Nvm != null) { Nvm.EraseFaultFired = value; } }
        }

        public bool AnyFaultFired
        {
            get { return Nvm != null && Nvm.AnyFaultFired; }
        }

        public bool FaultRequiresImmediateStop
        {
            get { return Nvm != null && Nvm.FaultRequiresImmediateStop; }
        }

        public bool DriverErrorFired
        {
            get { return Nvm != null && Nvm.DriverErrorFired; }
            set { if(Nvm != null) { Nvm.DriverErrorFired = value; } }
        }

        public uint LastFaultAddress
        {
            get { return Nvm != null ? Nvm.LastFaultAddress : 0U; }
            set { if(Nvm != null) { Nvm.LastFaultAddress = value; } }
        }

        public ulong LastFaultPC
        {
            get { return Nvm != null ? Nvm.LastFaultPC : 0UL; }
            set { if(Nvm != null) { Nvm.LastFaultPC = value; } }
        }

        public string LastFaultCallContext
        {
            get { return Nvm != null ? Nvm.LastFaultCallContext : null; }
            set { if(Nvm != null) { Nvm.LastFaultCallContext = value; } }
        }

        public string WriteCallContextToString()
        {
            return Nvm != null ? Nvm.WriteCallContextToString() : string.Empty;
        }

        public string EraseCallContextToString()
        {
            return Nvm != null ? Nvm.EraseCallContextToString() : string.Empty;
        }

        public byte[] FaultFlashSnapshot
        {
            get { return Nvm != null ? Nvm.FaultFlashSnapshot : null; }
            set { if(Nvm != null) { Nvm.FaultFlashSnapshot = value; } }
        }

        public int WriteFaultMode
        {
            get { return Nvm != null ? Nvm.WriteFaultMode : 0; }
            set { if(Nvm != null) { Nvm.WriteFaultMode = value; } }
        }

        public int EraseFaultMode
        {
            get { return Nvm != null ? Nvm.EraseFaultMode : 0; }
            set { if(Nvm != null) { Nvm.EraseFaultMode = value; } }
        }

        public uint CorruptionSeed
        {
            get { return Nvm != null ? Nvm.CorruptionSeed : 0U; }
            set { if(Nvm != null) { Nvm.CorruptionSeed = value; } }
        }

        public string MramTornWordMode
        {
            get { return Nvm != null ? Nvm.MramTornWordMode : "half"; }
            set { if(Nvm != null) { Nvm.MramTornWordMode = value; } }
        }

        public uint MramTornWordSeed
        {
            get { return Nvm != null ? Nvm.MramTornWordSeed : 0U; }
            set { if(Nvm != null) { Nvm.MramTornWordSeed = value; } }
        }

        public int UncorrectableWordCount => Nvm != null ? Nvm.UncorrectableWordCount : 0;
        public bool LastFaultMarkedUncorrectable => Nvm != null && Nvm.LastFaultMarkedUncorrectable;
        public ulong UncorrectableReadCount => Nvm != null ? Nvm.UncorrectableReadCount : 0UL;
        public ulong LastUncorrectableReadWordAddress => Nvm != null ? Nvm.LastUncorrectableReadWordAddress : 0UL;
        public ulong LastUncorrectableReadAddress => Nvm != null ? Nvm.LastUncorrectableReadAddress : 0UL;
        public ulong LastUncorrectableReadPC => Nvm != null ? Nvm.LastUncorrectableReadPC : 0UL;
        public bool IsWordUncorrectable(long offset) => Nvm != null && Nvm.IsWordUncorrectable(offset);
        public bool IsAddressUncorrectable(ulong busAddress) => Nvm != null && Nvm.IsAddressUncorrectable(busAddress);
        public void MarkWordUncorrectable(long offset) { Nvm?.MarkWordUncorrectable(offset); }
        public void ClearUncorrectableWord(long offset) { Nvm?.ClearUncorrectableWord(offset); }
        public void ClearUncorrectableWords() { Nvm?.ClearUncorrectableWords(); }
        public string UncorrectableWordsToString() => Nvm != null ? Nvm.UncorrectableWordsToString() : string.Empty;
        public string FaultUncorrectableWordsToString() => Nvm != null ? Nvm.FaultUncorrectableWordsToString() : string.Empty;
        public string UncorrectableReadsToString() => Nvm != null ? Nvm.UncorrectableReadsToString() : string.Empty;
        public void ClearUncorrectableReadLog() { Nvm?.ClearUncorrectableReadLog(); }

        public bool PreserveCountersAcrossReset
        {
            get { return Nvm != null && Nvm.PreserveCountersAcrossReset; }
            set { if(Nvm != null) { Nvm.PreserveCountersAcrossReset = value; } }
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
        public bool EraseTraceEnabled
        {
            get { return Nvm != null && Nvm.EraseTraceEnabled; }
            set { if(Nvm != null) { Nvm.EraseTraceEnabled = value; } }
        }
        public int EraseTraceCount { get { return Nvm != null ? Nvm.EraseTraceCount : 0; } }
        public string EraseTraceToString() { return Nvm != null ? Nvm.EraseTraceToString() : string.Empty; }
        public void EraseTraceClear() { Nvm?.EraseTraceClear(); }

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

            Registers.NvmEraseSize.Define(this)
                .WithValueField(0, 32,
                    valueProviderCallback: _ => nvmEraseSizeValue,
                    writeCallback: (_, value) => nvmEraseSizeValue = (uint)value);

            Registers.NvmEraseAddr.Define(this)
                .WithValueField(0, 32, FieldMode.Write, writeCallback: (_, value) =>
                {
                    if(Nvm == null)
                    {
                        illegalOperation = true;
                        return;
                    }
                    // Gated by NvmCtrl ERASE_EN[2:1]:
                    //   bit 1 (0x2) = word erase, bit 2 (0x4) = sector erase.
                    var eraseBits = (nvmCtrlWriteableBits >> 1) & 0x3U;
                    if(eraseBits == 0U)
                    {
                        illegalOperation = true;
                        return;
                    }
                    if(!TryNormalizeAddress((long)value, out var normalized))
                    {
                        illegalOperation = true;
                        return;
                    }
                    if(Nvm.ProgramAddressBase == 0UL && NvmBaseAddress > 0)
                    {
                        Nvm.ProgramAddressBase = (ulong)NvmBaseAddress;
                    }
                    if((eraseBits & 0x2U) != 0U)
                    {
                        var sectorLen = nvmEraseSizeValue != 0U
                            ? checked((int)nvmEraseSizeValue)
                            : (PageSize > 0 ? PageSize : 0x1000);
                        Nvm.EraseSector(normalized, sectorLen);
                    }
                    else
                    {
                        Nvm.EraseWord(normalized);
                    }
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
                status |= Nvm.EraseInProgress ? (1U << 10) : (1U << 9);
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

            if(Nvm == null || !Nvm.IsWriteInProgress())
            {
                ctrl |= (1U << 8); // RDY_FOR_ERASE
                ctrl |= (1U << 9); // RDY_FOR_PROG
            }

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
        private uint nvmEraseSizeValue;
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
            NvmEraseSize = 0x34,
            NvmEraseAddr = 0x38,
            NvmEc0 = 0x40,
            NvmEc1 = 0x44,
            NvmEc2 = 0x48,
            NvmEc3 = 0x4C,
            NvmUe = 0x50,
            NvmEcUeRst = 0x54,
        }
    }
}
