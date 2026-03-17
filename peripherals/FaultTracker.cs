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

        public ulong TotalPageErases;
        public ulong FaultAtPageErase = ulong.MaxValue;
        public bool EraseFaultFired;

        public uint LastFaultAddress;
        public byte[] FaultFlashSnapshot;

        public int WriteFaultMode;
        public int EraseFaultMode;
        public uint CorruptionSeed;

        public bool WriteTraceEnabled;
        public bool EraseTraceEnabled;

        public bool AnyFaultFired => FaultFired || EraseFaultFired;

        // --- Write counting ---

        // Full write record: increment counter, add trace entry if enabled,
        // check fault arm.  Returns true if TotalWordWrites == FaultAtWordWrite.
        // Caller is responsible for ALL fault application.
        public bool RecordWriteAndCheckFault(int alignedOffset, uint wordValue)
        {
            TotalWordWrites++;
            if(WriteTraceEnabled)
            {
                writeTrace.Add(Tuple.Create(TotalWordWrites, alignedOffset, wordValue));
            }
            return TotalWordWrites == FaultAtWordWrite;
        }

        // Counter-only increment (NRF52 fast path outside diff window).
        // No trace entry emitted.  Returns true if fault arm hit.
        public bool IncrementWriteCount()
        {
            TotalWordWrites++;
            return TotalWordWrites == FaultAtWordWrite;
        }

        // --- Erase counting ---

        // Increment erase counter, add trace entry if enabled, check fault arm.
        // Returns true if TotalPageErases == FaultAtPageErase.
        // Caller is responsible for ALL erase application (partial or full).
        public bool RecordEraseAndCheckFault(long offset, int eraseSize)
        {
            TotalPageErases++;
            if(EraseTraceEnabled)
            {
                eraseTrace.Add(Tuple.Create(TotalPageErases, offset, TotalWordWrites, eraseSize));
            }
            return TotalPageErases == FaultAtPageErase;
        }

        // --- Trace access ---

        public int WriteTraceCount => writeTrace.Count;

        public string WriteTraceToString()
        {
            var sb = new StringBuilder(writeTrace.Count * 24);
            foreach(var entry in writeTrace)
            {
                sb.Append(entry.Item1);
                sb.Append(':');
                sb.Append(entry.Item2);
                sb.Append(':');
                sb.Append(entry.Item3);
                sb.Append('\n');
            }
            return sb.ToString();
        }

        public void WriteTraceClear()
        {
            writeTrace.Clear();
        }

        public int EraseTraceCount => eraseTrace.Count;

        public string EraseTraceToString()
        {
            var sb = new StringBuilder(eraseTrace.Count * 32);
            foreach(var entry in eraseTrace)
            {
                sb.Append(entry.Item1);
                sb.Append(':');
                sb.Append(entry.Item2);
                sb.Append(':');
                sb.Append(entry.Item3);
                sb.Append(':');
                sb.Append(entry.Item4);
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
            TotalWordWrites = 0;
            TotalPageErases = 0;
            FaultFired = false;
            EraseFaultFired = false;
            LastFaultAddress = 0;
            FaultFlashSnapshot = null;
            writeTrace.Clear();
            eraseTrace.Clear();
            if(WritebackDomains != null)
            {
                foreach(var d in WritebackDomains)
                {
                    d.Discard();
                    d.CommittedCount = 0;
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
        private readonly List<Tuple<ulong, int, uint>> writeTrace = new List<Tuple<ulong, int, uint>>();
        private readonly List<Tuple<ulong, long, ulong, int>> eraseTrace = new List<Tuple<ulong, long, ulong, int>>();
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
