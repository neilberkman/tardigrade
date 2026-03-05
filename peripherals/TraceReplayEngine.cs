// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;

using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Memory
{
    /// <summary>
    /// High-throughput native trace replay engine for runtime fault sweeps.
    ///
    /// Write trace binary format (12 bytes/entry, little-endian):
    ///   [uint32 write_index][uint32 flash_offset][uint32 value]
    ///
    /// Optional erase trace format (12 bytes/entry, little-endian):
    ///   [uint32 writes_at_this_point][uint32 flash_offset][uint32 erase_size]
    ///
    /// Replay semantics:
    ///   - Applies writes with write_index &lt; faultAtExclusive.
    ///   - Does not apply write_index == faultAtExclusive (fault point).
    /// </summary>
    public class TraceReplayEngine : BasicDoubleWordPeripheral, IKnownSize
    {
        public TraceReplayEngine(IMachine machine) : base(machine)
        {
            Reset();
        }

        public override void Reset()
        {
            base.Reset();
            LastFaultEncountered = false;
            LastFaultAddress = 0;
            LastWritesApplied = 0;
            LastEntriesScanned = 0;
        }

        public override uint ReadDoubleWord(long offset)
        {
            return 0;
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            // No register interface; replay is monitor/API-driven.
        }

        public long Size => 0x4;

        // Target flash/NVM object (MappedMemory, NVMemory, etc.).
        public IPeripheral Target { get; set; }

        // Optional base address used for LastFaultAddress reporting.
        public uint TargetBaseAddress { get; set; }

        public bool LastFaultEncountered { get; private set; }

        public uint LastFaultAddress { get; private set; }

        public ulong LastWritesApplied { get; private set; }

        public ulong LastEntriesScanned { get; private set; }

        public ulong Replay(string writeTracePath, ulong faultAtExclusive)
        {
            var writes = LoadWriteTrace(writeTracePath);
            return ReplayCore(
                writes,
                Array.Empty<EraseEntry>(),
                faultAtExclusive,
                pageSize: 0,
                eraseFill: 0xFF,
                useEraseTrace: false
            );
        }

        public ulong ReplayWithErases(
            string writeTracePath,
            string eraseTracePath,
            ulong faultAtExclusive,
            uint pageSize,
            byte eraseFill)
        {
            if(pageSize == 0)
            {
                throw new ArgumentException("pageSize must be > 0", nameof(pageSize));
            }

            var writes = LoadWriteTrace(writeTracePath);
            var erases = LoadEraseTrace(eraseTracePath);
            return ReplayCore(
                writes,
                erases,
                faultAtExclusive,
                pageSize,
                eraseFill,
                useEraseTrace: true
            );
        }

        private ulong ReplayCore(
            WriteEntry[] writes,
            EraseEntry[] erases,
            ulong faultAtExclusive,
            uint pageSize,
            byte eraseFill,
            bool useEraseTrace)
        {
            if(faultAtExclusive == 0)
            {
                throw new ArgumentException("faultAtExclusive must be >= 1", nameof(faultAtExclusive));
            }

            ResolveTargetAccessors();

            LastFaultEncountered = false;
            LastFaultAddress = 0;
            LastWritesApplied = 0;
            LastEntriesScanned = 0;

            var eraseIdx = 0;
            for(var i = 0; i < writes.Length; i++)
            {
                var w = writes[i];

                if(useEraseTrace)
                {
                    while(eraseIdx < erases.Length && erases[eraseIdx].WritesAt < w.WriteIndex)
                    {
                        var es = erases[eraseIdx].EraseSize > 0 ? erases[eraseIdx].EraseSize : pageSize;
                        ErasePage(erases[eraseIdx].Offset, es, eraseFill);
                        eraseIdx++;
                    }
                }

                if(w.WriteIndex >= faultAtExclusive)
                {
                    LastFaultEncountered = (w.WriteIndex == faultAtExclusive);
                    LastFaultAddress = LastFaultEncountered
                        ? TargetBaseAddress + w.Offset
                        : 0;
                    break;
                }

                WriteWord(w.Offset, w.Value);
                LastWritesApplied++;
                LastEntriesScanned++;
            }

            if(useEraseTrace)
            {
                while(eraseIdx < erases.Length && erases[eraseIdx].WritesAt < faultAtExclusive)
                {
                    var es = erases[eraseIdx].EraseSize > 0 ? erases[eraseIdx].EraseSize : pageSize;
                    ErasePage(erases[eraseIdx].Offset, es, eraseFill);
                    eraseIdx++;
                }
            }

            return LastWritesApplied;
        }

        private void ResolveTargetAccessors()
        {
            if(Target == null)
            {
                throw new InvalidOperationException("TraceReplayEngine.Target is not set");
            }

            targetAsDoubleWord = Target as IDoubleWordPeripheral;
            targetAsMemory = Target as IMemory;

            if(targetAsDoubleWord == null && targetAsMemory == null)
            {
                throw new InvalidOperationException(
                    "TraceReplayEngine.Target must implement IDoubleWordPeripheral or IMemory");
            }
        }

        private void WriteWord(uint offset, uint value)
        {
            if(targetAsDoubleWord != null)
            {
                targetAsDoubleWord.WriteDoubleWord(offset, value);
                return;
            }

            wordScratch[0] = (byte)(value & 0xFF);
            wordScratch[1] = (byte)((value >> 8) & 0xFF);
            wordScratch[2] = (byte)((value >> 16) & 0xFF);
            wordScratch[3] = (byte)((value >> 24) & 0xFF);
            targetAsMemory.WriteBytes(offset, wordScratch, 0, 4, this);
        }

        private void ErasePage(uint offset, uint pageSize, byte eraseFill)
        {
            EnsureEraseScratch(pageSize, eraseFill);

            if(targetAsMemory != null)
            {
                targetAsMemory.WriteBytes(offset, eraseScratch, 0, eraseScratch.Length, this);
                return;
            }

            // Fallback for targets that expose only dword writes.
            var fillWord = (uint)(eraseFill
                | (eraseFill << 8)
                | (eraseFill << 16)
                | (eraseFill << 24));
            for(uint i = 0; i < pageSize; i += 4)
            {
                targetAsDoubleWord.WriteDoubleWord(offset + i, fillWord);
            }
        }

        private void EnsureEraseScratch(uint pageSize, byte eraseFill)
        {
            if(eraseScratch == null || eraseScratch.Length != pageSize || eraseScratchFill != eraseFill)
            {
                eraseScratch = new byte[pageSize];
                for(var i = 0; i < eraseScratch.Length; i++)
                {
                    eraseScratch[i] = eraseFill;
                }
                eraseScratchFill = eraseFill;
            }
        }

        private WriteEntry[] LoadWriteTrace(string path)
        {
            if(string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Trace path is empty", nameof(path));
            }

            var fullPath = Path.GetFullPath(path);
            var mtime = File.GetLastWriteTimeUtc(fullPath);

            CachedWriteTrace cached;
            if(writeTraceCache.TryGetValue(fullPath, out cached) && cached.MtimeUtc == mtime)
            {
                return cached.Entries;
            }

            using(var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if(fs.Length % WriteEntrySizeBytes != 0)
                {
                    throw new InvalidDataException(
                        $"Write trace '{fullPath}' has invalid length {fs.Length}; expected multiple of {WriteEntrySizeBytes}");
                }

                var count = checked((int)(fs.Length / WriteEntrySizeBytes));
                var entries = new WriteEntry[count];
                using(var br = new BinaryReader(fs))
                {
                    for(var i = 0; i < count; i++)
                    {
                        entries[i] = new WriteEntry
                        {
                            WriteIndex = br.ReadUInt32(),
                            Offset = br.ReadUInt32(),
                            Value = br.ReadUInt32(),
                        };
                    }
                }

                writeTraceCache[fullPath] = new CachedWriteTrace
                {
                    MtimeUtc = mtime,
                    Entries = entries,
                };

                this.Log(LogLevel.Info, "trace_replay: loaded {0} write entries from {1}", count, fullPath);
                return entries;
            }
        }

        private EraseEntry[] LoadEraseTrace(string path)
        {
            if(string.IsNullOrWhiteSpace(path))
            {
                return Array.Empty<EraseEntry>();
            }

            var fullPath = Path.GetFullPath(path);
            var mtime = File.GetLastWriteTimeUtc(fullPath);

            CachedEraseTrace cached;
            if(eraseTraceCache.TryGetValue(fullPath, out cached) && cached.MtimeUtc == mtime)
            {
                return cached.Entries;
            }

            using(var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if(fs.Length % EraseEntrySizeBytes != 0)
                {
                    throw new InvalidDataException(
                        $"Erase trace '{fullPath}' has invalid length {fs.Length}; expected multiple of {EraseEntrySizeBytes}");
                }

                var count = checked((int)(fs.Length / EraseEntrySizeBytes));
                var entries = new EraseEntry[count];
                using(var br = new BinaryReader(fs))
                {
                    for(var i = 0; i < count; i++)
                    {
                        entries[i] = new EraseEntry
                        {
                            WritesAt = br.ReadUInt32(),
                            Offset = br.ReadUInt32(),
                            EraseSize = br.ReadUInt32(),
                        };
                    }
                }

                eraseTraceCache[fullPath] = new CachedEraseTrace
                {
                    MtimeUtc = mtime,
                    Entries = entries,
                };

                this.Log(LogLevel.Info, "trace_replay: loaded {0} erase entries from {1}", count, fullPath);
                return entries;
            }
        }

        private sealed class CachedWriteTrace
        {
            public DateTime MtimeUtc;
            public WriteEntry[] Entries;
        }

        private sealed class CachedEraseTrace
        {
            public DateTime MtimeUtc;
            public EraseEntry[] Entries;
        }

        private struct WriteEntry
        {
            public uint WriteIndex;
            public uint Offset;
            public uint Value;
        }

        private struct EraseEntry
        {
            public uint WritesAt;
            public uint Offset;
            public uint EraseSize;
        }

        private IDoubleWordPeripheral targetAsDoubleWord;
        private IMemory targetAsMemory;

        private byte[] eraseScratch;
        private byte eraseScratchFill;
        private readonly byte[] wordScratch = new byte[4];

        private readonly Dictionary<string, CachedWriteTrace> writeTraceCache =
            new Dictionary<string, CachedWriteTrace>(StringComparer.Ordinal);
        private readonly Dictionary<string, CachedEraseTrace> eraseTraceCache =
            new Dictionary<string, CachedEraseTrace>(StringComparer.Ordinal);

        private const int WriteEntrySizeBytes = 12;
        private const int EraseEntrySizeBytes = 12;
    }
}
