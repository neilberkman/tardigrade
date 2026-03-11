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

        // --- Private trace storage ---
        private readonly List<Tuple<ulong, int, uint>> writeTrace = new List<Tuple<ulong, int, uint>>();
        private readonly List<Tuple<ulong, long, ulong, int>> eraseTrace = new List<Tuple<ulong, long, ulong, int>>();
    }
}
