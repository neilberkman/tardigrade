// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Shared tracking state, trace buffers, and utility methods composed into
// each flash controller.  Does NOT own flash mutation, shadow management,
// or fault application — those stay per-controller.

using System;
using System.Collections.Generic;
using System.Text;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class FaultTracker
    {
        // --- Tracking state (public fields, forwarded by controller properties) ---
        public ulong TotalWordWrites;
        public ulong FaultAtWordWrite = ulong.MaxValue;
        public bool FaultFired;
        public bool DriverErrorFired;

        public ulong TotalPageErases;
        public ulong FaultAtPageErase = ulong.MaxValue;
        public bool EraseFaultFired;

        public uint LastFaultAddress;
        public ulong LastFaultPC;
        public ulong PendingPC;
        public byte[] FaultFlashSnapshot;

        public int WriteFaultMode;
        public int EraseFaultMode;
        public uint CorruptionSeed;
        public string MramTornWordMode = "half";
        public uint MramTornWordSeed;
        // Backend-neutral interrupted-operation outcome.  "fixed" preserves
        // each flash controller's historical power-loss result.  Keep this
        // separate from the MRAM compatibility properties: existing profiles
        // may use MramTornWordMode to control erase cuts on flash while program
        // cuts retain their historical result.
        public string TornWordMode = "fixed";
        public uint TornWordSeed;
        public bool PreserveCountersAcrossReset;

        public bool WriteTraceEnabled;
        public bool EraseTraceEnabled;

        public bool WriteFaultRequiresImmediateStop => FaultFired && WriteFaultMode == 0;
        public bool FaultRequiresImmediateStop => EraseFaultFired || WriteFaultRequiresImmediateStop;
        public bool AnyFaultFired => FaultRequiresImmediateStop;

        // --- Write counting ---

        // Full write record: increment counter, add trace entry if enabled,
        // check fault arm.  The trace records the byte offset and the value
        // written by this event in little-endian integer form, together with
        // the event width.  Caller is responsible for ALL fault application.
        // Returns true if TotalWordWrites == FaultAtWordWrite.
        public bool RecordWriteAndCheckFault(int byteOffset, ulong eventValue, int width)
        {
            var pc = PendingPC;
            PendingPC = 0;
            return RecordWriteAndCheckFault(byteOffset, eventValue, width, pc);
        }

        public bool RecordWriteAndCheckFault(int byteOffset, ulong eventValue, int width, ulong pc)
        {
            if(width != 1 && width != 2 && width != 4 && width != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(width),
                    "Write trace width must be 1, 2, 4, or 8 bytes");
            }
            var effectivePc = pc != 0 ? pc : PendingPC;
            PendingPC = 0;
            TotalWordWrites++;
            if(WriteTraceEnabled)
            {
                writeTrace.Add(Tuple.Create(TotalWordWrites, byteOffset, eventValue, width));
                if(effectivePc != 0)
                {
                    writeTracePcs[TotalWordWrites] = effectivePc;
                }
            }
            var faultHit = TotalWordWrites == FaultAtWordWrite;
            if(faultHit)
            {
                LastFaultPC = effectivePc;
            }
            return faultHit;
        }

        // Counter-only increment (NRF52 fast path outside diff window).
        // No trace entry emitted.  Returns true if fault arm hit.
        public bool IncrementWriteCount(ulong pc = 0)
        {
            var effectivePc = pc != 0 ? pc : PendingPC;
            PendingPC = 0;
            TotalWordWrites++;
            var faultHit = TotalWordWrites == FaultAtWordWrite;
            if(faultHit)
            {
                LastFaultPC = effectivePc;
            }
            return faultHit;
        }

        // --- Erase counting ---

        // Increment erase counter, add trace entry if enabled, check fault arm.
        // Returns true if TotalPageErases == FaultAtPageErase.
        // Caller is responsible for ALL erase application (partial or full).
        public bool RecordEraseAndCheckFault(long offset, int eraseSize, ulong pc = 0)
        {
            var effectivePc = pc != 0 ? pc : PendingPC;
            PendingPC = 0;
            TotalPageErases++;
            if(EraseTraceEnabled)
            {
                eraseTrace.Add(Tuple.Create(TotalPageErases, offset, TotalWordWrites, eraseSize, effectivePc));
            }
            var faultHit = TotalPageErases == FaultAtPageErase;
            if(faultHit)
            {
                LastFaultPC = effectivePc;
            }
            return faultHit;
        }

        // --- Trace access ---

        public int WriteTraceCount => writeTrace.Count;

        public string WriteTraceToString()
        {
            var sb = new StringBuilder(writeTrace.Count * 40);
            foreach(var entry in writeTrace)
            {
                sb.Append(entry.Item1);
                sb.Append(':');
                sb.Append(entry.Item2);
                sb.Append(':');
                sb.Append(entry.Item3);
                sb.Append(':');
                sb.Append(entry.Item4);
                ulong tracePc;
                if(writeTracePcs.TryGetValue(entry.Item1, out tracePc) && tracePc != 0)
                {
                    sb.Append(":0x");
                    sb.Append(tracePc.ToString("X8"));
                }
                sb.Append('\n');
            }
            return sb.ToString();
        }

        public void WriteTraceClear()
        {
            writeTrace.Clear();
            writeTracePcs.Clear();
        }

        public int EraseTraceCount => eraseTrace.Count;

        public string EraseTraceToString()
        {
            var sb = new StringBuilder(eraseTrace.Count * 40);
            foreach(var entry in eraseTrace)
            {
                sb.Append(entry.Item1);
                sb.Append(':');
                sb.Append(entry.Item2);
                sb.Append(':');
                sb.Append(entry.Item3);
                sb.Append(':');
                sb.Append(entry.Item4);
                if(entry.Item5 != 0)
                {
                    sb.Append(":0x");
                    sb.Append(entry.Item5.ToString("X8"));
                }
                sb.Append('\n');
            }
            return sb.ToString();
        }

        public void EraseTraceClear()
        {
            eraseTrace.Clear();
        }

        // --- Reset ---

        public void Reset()
        {
            if(!PreserveCountersAcrossReset && !FaultFired && !EraseFaultFired)
            {
                TotalWordWrites = 0;
                TotalPageErases = 0;
                FaultFired = false;
                DriverErrorFired = false;
                EraseFaultFired = false;
                LastFaultAddress = 0;
                LastFaultPC = 0;
                PendingPC = 0;
                FaultFlashSnapshot = null;
                writeTrace.Clear();
                writeTracePcs.Clear();
                eraseTrace.Clear();
            }
            if(WritebackDomains != null)
            {
                foreach(var d in WritebackDomains)
                {
                    d.Discard();
                    if(!PreserveCountersAcrossReset)
                    {
                        d.CommittedCount = 0;
                    }
                }
            }
        }

        // --- Static utilities ---

        public static uint NextLcg(ref uint seed)
        {
            seed = seed * 1103515245 + 12345;
            return seed;
        }

        public uint BuildFaultSeed(int offset)
        {
            var seed = CorruptionSeed != 0 ? CorruptionSeed : (uint)TotalWordWrites;
            seed ^= (uint)offset;
            seed ^= (uint)(TotalPageErases * 2654435761UL);
            return seed;
        }

        public static ulong BuildFlashTornProgramValue(ulong previousValue,
            ulong requestedValue, int width, byte eraseFill, string mode,
            uint seed, ulong operationIndex, long offset)
        {
            if(width < 1 || width > 8)
            {
                throw new ArgumentOutOfRangeException(nameof(width),
                    "Flash torn-program width must be between 1 and 8 bytes");
            }
            var normalized = (mode ?? "fixed").Trim().ToLowerInvariant();
            var valueMask = width == 8 ? ulong.MaxValue : ((1UL << (width * 8)) - 1UL);
            previousValue &= valueMask;
            requestedValue &= valueMask;
            if(normalized == "fixed" || normalized == "untouched")
            {
                return previousValue;
            }
            var fill = 0UL;
            for(var byteIndex = 0; byteIndex < width; byteIndex++)
            {
                fill |= (ulong)eraseFill << (byteIndex * 8);
            }
            // Programming may only move a bit away from its erased value.
            var programmed = ((fill & previousValue & requestedValue)
                | (~fill & (previousValue | requestedValue))) & valueMask;
            if(normalized == "programmed")
            {
                return programmed;
            }
            if(normalized == "partial_bits")
            {
                return SelectPartialBits(previousValue, programmed, width,
                    seed, operationIndex, offset, 0x50524F47U);
            }
            throw new ArgumentException(
                "Flash torn-word mode must be fixed, untouched, programmed, or partial_bits",
                nameof(mode));
        }

        public static byte[] BuildFlashTornEraseSpan(byte[] previousBytes,
            long offset, byte eraseFill, int programUnit, string mode,
            uint seed, ulong operationIndex)
        {
            if(previousBytes == null)
            {
                throw new ArgumentNullException(nameof(previousBytes));
            }
            var normalized = (mode ?? "fixed").Trim().ToLowerInvariant();
            var result = (byte[])previousBytes.Clone();
            if(normalized == "untouched")
            {
                return result;
            }
            if(normalized == "programmed" || normalized == "erased")
            {
                for(var index = 0; index < result.Length; index++)
                {
                    result[index] = eraseFill;
                }
                return result;
            }
            if(normalized != "partial_bits")
            {
                throw new ArgumentException(
                    "Flash torn-word erase mode must be untouched, programmed, erased, or partial_bits",
                    nameof(mode));
            }

            var unit = Math.Max(1, Math.Min(8, programUnit));
            for(var relative = 0; relative < result.Length; relative += unit)
            {
                var width = Math.Min(unit, result.Length - relative);
                ulong previous = 0;
                ulong erased = 0;
                for(var byteIndex = 0; byteIndex < width; byteIndex++)
                {
                    previous |= (ulong)previousBytes[relative + byteIndex] << (byteIndex * 8);
                    erased |= (ulong)eraseFill << (byteIndex * 8);
                }
                var partial = SelectPartialBits(previous, erased, width, seed,
                    operationIndex, offset + relative, 0x45524153U);
                for(var byteIndex = 0; byteIndex < width; byteIndex++)
                {
                    result[relative + byteIndex] = (byte)(partial >> (byteIndex * 8));
                }
            }
            return result;
        }

        private static ulong SelectPartialBits(ulong previousValue, ulong targetValue,
            int width, uint seed, ulong operationIndex, long offset, uint domain)
        {
            var changed = new List<int>();
            var totalBits = width * 8;
            for(var bit = 0; bit < totalBits; bit++)
            {
                if(((previousValue ^ targetValue) & (1UL << bit)) != 0)
                {
                    changed.Add(bit);
                }
            }
            if(changed.Count == 0)
            {
                return previousValue;
            }

            var state = seed != 0 ? seed : 0x5A3C96A5U;
            state ^= (uint)(operationIndex * 2654435761UL);
            state ^= (uint)((ulong)offset * 2246822519UL);
            state ^= domain;
            if(state == 0)
            {
                state = 0x9E3779B9U;
            }
            state = NextLcg(ref state);
            // With two or more changing bits, keep both an old and a target
            // bit.  A one-bit program has no physically distinct midpoint.
            var selectedCount = changed.Count == 1
                ? 1
                : 1 + (int)(state % (uint)(changed.Count - 1));
            var result = previousValue;
            for(var index = 0; index < selectedCount; index++)
            {
                state = NextLcg(ref state);
                var swapIndex = index + (int)(state % (uint)(changed.Count - index));
                var selectedBit = changed[swapIndex];
                changed[swapIndex] = changed[index];
                changed[index] = selectedBit;
                var mask = 1UL << selectedBit;
                result = (result & ~mask) | (targetValue & mask);
            }
            return result;
        }

        public byte[] BuildCorruptedErasedSpan(long offset, int spanSize, byte eraseFill, int wordUnitBytes = 4)
        {
            var corrupted = new byte[Math.Max(0, spanSize)];
            if(spanSize <= 0)
            {
                return corrupted;
            }
            if(eraseFill != 0)
            {
                for(var i = 0; i < spanSize; i++)
                {
                    corrupted[i] = eraseFill;
                }
            }
            var unitBytes = Math.Max(1, wordUnitBytes);
            var seed = MramTornWordSeed != 0
                ? (MramTornWordSeed ^ (uint)offset ^ (uint)(TotalPageErases * 2654435761UL))
                : BuildFaultSeed((int)offset);
            for(var wordPos = 0; wordPos < spanSize; wordPos += unitBytes)
            {
                var wordLen = Math.Min(unitBytes, spanSize - wordPos);
                var totalBits = wordLen * 8;
                var flips = Math.Min(totalBits, 3 + (int)(NextLcg(ref seed) % 3U));
                var used = new HashSet<int>();
                var attempts = 0;
                while(used.Count < flips && attempts < totalBits * 4)
                {
                    attempts++;
                    var bit = (int)(NextLcg(ref seed) % (uint)totalBits);
                    if(used.Add(bit))
                    {
                        corrupted[wordPos + (bit / 8)] ^= (byte)(1 << (bit % 8));
                    }
                }
            }
            return corrupted;
        }

        public static byte[] WordToBytes(uint value)
        {
            return new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
            };
        }

        public static uint ReadU32(byte[] data, int offset)
        {
            return (uint)(data[offset]
                | (data[offset + 1] << 8)
                | (data[offset + 2] << 16)
                | (data[offset + 3] << 24));
        }

        public static void WriteU32(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value);
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        // --- Writeback domain support ---
        public List<WritebackDomain> WritebackDomains;
        public bool WritebackEnabled;

        public WritebackDomain FindDomain(long address)
        {
            if(WritebackDomains == null) return null;
            foreach(var d in WritebackDomains)
            {
                if(address >= d.BaseAddress && address < d.BaseAddress + d.Size)
                    return d;
            }
            return null;
        }

        // --- Private trace storage ---
        private readonly List<Tuple<ulong, int, ulong, int>> writeTrace = new List<Tuple<ulong, int, ulong, int>>();
        private readonly Dictionary<ulong, ulong> writeTracePcs = new Dictionary<ulong, ulong>();
        private readonly List<Tuple<ulong, long, ulong, int, ulong>> eraseTrace = new List<Tuple<ulong, long, ulong, int, ulong>>();
    }

    public class WritebackDomain
    {
        public long BaseAddress;
        public long Size;
        public int Capacity;
        public bool EraseFlushesDomain;
        public Dictionary<long, uint> Overlay = new Dictionary<long, uint>();
        public bool Dirty;
        public int WriteCount;
        public int CommittedCount;
        public bool AutoCommitFired;

        public WritebackDomain(long baseAddr, long size, int capacity, bool eraseFlushesDomain = false)
        {
            BaseAddress = baseAddr;
            Size = size;
            Capacity = capacity;
            EraseFlushesDomain = eraseFlushesDomain;
        }

        public bool Write(long offset, uint value)
        {
            if(offset < 0 || offset >= Size) return false;
            Overlay[offset] = value;
            Dirty = true;
            WriteCount++;
            if(Capacity > 0 && WriteCount >= Capacity)
            {
                Commit("buffer_full");
                AutoCommitFired = true;
            }
            return true;
        }

        public uint Read(long offset, uint flashValue)
        {
            if(Overlay.TryGetValue(offset, out uint val)) return val;
            return flashValue;
        }

        public Dictionary<long, uint> Commit(string reason)
        {
            var committed = new Dictionary<long, uint>(Overlay);
            CommittedCount += Overlay.Count;
            Overlay.Clear();
            Dirty = false;
            WriteCount = 0;
            return committed;
        }

        public int Discard()
        {
            int lost = Overlay.Count;
            Overlay.Clear();
            Dirty = false;
            WriteCount = 0;
            return lost;
        }

        /// <summary>
        /// Clear overlay entries in the erased address range.
        /// Called when erase_flushes_domain is false — the erase hits
        /// flash directly but stale overlay entries must be removed
        /// so reads don't return pre-erase data.
        ///
        /// Note: WriteCount is intentionally NOT decremented here.
        /// WriteCount tracks "writes since last commit" (bus transactions),
        /// not "live overlay entries." An erased-then-cleared write still
        /// counts toward the buffer-full threshold, making the model
        /// slightly conservative (commits sooner than hardware might).
        /// </summary>
        public int ClearEraseRange(long eraseOffset, long eraseSize)
        {
            var toRemove = new List<long>();
            foreach(var key in Overlay.Keys)
            {
                if(key >= eraseOffset && key < eraseOffset + eraseSize)
                    toRemove.Add(key);
            }
            foreach(var key in toRemove)
            {
                Overlay.Remove(key);
            }
            if(Overlay.Count == 0)
            {
                Dirty = false;
            }
            return toRemove.Count;
        }

        public int Pending => Overlay.Count;
    }
}
