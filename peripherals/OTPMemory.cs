// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Generic OTP (One-Time Programmable) / eFuse memory peripheral.
//
// Models write-once storage where bits can only transition from 0 to 1
// (fuse blow). Once a bit is blown, it is permanent and survives reset.
// This is the fundamental behavior of eFuse arrays, antifuse OTP, and
// similar technologies used for anti-rollback counters, security config
// bits, device identity, and key storage.
//
// Write granularity is configurable:
//   1  = single-bit blow (bit-addressable OTP)
//   8  = byte-granularity (byte-addressable eFuse)
//   32 = word-granularity (word-addressable eFuse, most common)
//
// Fault injection modes:
//   0 = partial_program  — not all requested bits flip (some stay 0)
//   1 = stuck_bit        — a specific bit fails to program permanently
//   2 = read_disturb     — adjacent bits get unintended 0->1 flips on blow
//   3 = overblow         — target bits flip plus extra neighboring bits
//
// Write tracking:
//   TotalBlows           — total fuse blow operations attempted
//   FaultAtBlow          — inject fault at the Nth blow operation
//   BlowFaultFired       — sticky flag set when a fault fires
//   BlownBitCount        — number of bits currently set to 1
//   RemainingLife         — total programmable bits minus blown bits
//
// Integration with tardigrade sweep:
//   The sweep engine treats each fuse blow as one "write" operation.
//   FaultAtBlow corresponds to FaultAtWordWrite in flash backends.
//   BlowFaultFired corresponds to FaultFired/FaultEverFired.

using System;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Memory
{
    public class OTPMemory : IMemory, IBytePeripheral, IWordPeripheral,
                             IDoubleWordPeripheral, IQuadWordPeripheral, IKnownSize
    {
        public OTPMemory(long size = DefaultSize, int writeGranularity = DefaultGranularity)
        {
            if(size <= 0 || size > int.MaxValue)
            {
                throw new ArgumentException("OTP size must be between 1 and Int32.MaxValue");
            }

            this.size = size;
            this.writeGranularity = writeGranularity;
            storage = new byte[size];
            stuckBitMask = new byte[size];
            // Storage starts all-zero: no fuses blown.
        }

        public void Reset()
        {
            // OTP memory is non-volatile and one-time-programmable.
            // Storage intentionally survives reset — fuses cannot be unblown.
            // Only transient tracking state is reset.
            BlowFaultFired = false;
        }

        // --- Read interface ---

        public byte ReadByte(long offset)
        {
            ValidateRange(offset, 1);
            return storage[offset];
        }

        public ushort ReadWord(long offset)
        {
            ValidateRange(offset, 2);
            return (ushort)(storage[offset]
                | (storage[offset + 1] << 8));
        }

        public uint ReadDoubleWord(long offset)
        {
            ValidateRange(offset, 4);
            return (uint)(storage[offset]
                | (storage[offset + 1] << 8)
                | (storage[offset + 2] << 16)
                | (storage[offset + 3] << 24));
        }

        public ulong ReadQuadWord(long offset)
        {
            ValidateRange(offset, 8);
            var lo = (uint)(storage[offset]
                | (storage[offset + 1] << 8)
                | (storage[offset + 2] << 16)
                | (storage[offset + 3] << 24));
            var hi = (uint)(storage[offset + 4]
                | (storage[offset + 5] << 8)
                | (storage[offset + 6] << 16)
                | (storage[offset + 7] << 24));
            return (ulong)lo | ((ulong)hi << 32);
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context)
        {
            ValidateRange(offset, count);
            var result = new byte[count];
            Array.Copy(storage, offset, result, 0, count);
            return result;
        }

        // --- Write interface (OTP semantics: bits only go 0 -> 1) ---

        public void WriteByte(long offset, byte value)
        {
            BlowBits(offset, new[] { value });
        }

        public void WriteWord(long offset, ushort value)
        {
            BlowBits(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
            });
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            BlowBits(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
            });
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            BlowBits(offset, new[]
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

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count, IPeripheral context)
        {
            if(array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if(startingIndex < 0 || count < 0 || startingIndex + count > array.Length)
            {
                throw new ArgumentOutOfRangeException(
                    $"Invalid write window start={startingIndex}, count={count}, arrayLength={array.Length}");
            }

            var data = new byte[count];
            Array.Copy(array, startingIndex, data, 0, count);
            BlowBits(offset, data);
        }

        // --- Properties ---

        public long Size
        {
            get { return size; }
            set
            {
                if(value <= 0 || value > int.MaxValue)
                {
                    throw new ArgumentException("OTP size must be between 1 and Int32.MaxValue");
                }

                if(value == size)
                {
                    return;
                }

                var newStorage = new byte[value];
                var newMask = new byte[value];
                var bytesToCopy = Math.Min(size, value);
                Array.Copy(storage, newStorage, bytesToCopy);
                Array.Copy(stuckBitMask, newMask, bytesToCopy);
                storage = newStorage;
                stuckBitMask = newMask;
                size = value;
            }
        }

        /// <summary>
        /// Write granularity in bits: 1 = bit-addressable, 8 = byte, 32 = word.
        /// Controls how many bits constitute one "blow" operation for tracking.
        /// </summary>
        public int WriteGranularity
        {
            get { return writeGranularity; }
            set
            {
                if(value != 1 && value != 8 && value != 32)
                {
                    throw new ArgumentException("WriteGranularity must be 1, 8, or 32");
                }
                writeGranularity = value;
            }
        }

        /// <summary>
        /// Total fuse blow operations performed since last counter reset.
        /// Each write (at the configured granularity) increments this counter.
        /// </summary>
        public ulong TotalBlows { get; set; }

        /// <summary>
        /// Inject a fault at the Nth blow operation.
        /// Set to ulong.MaxValue to disable fault injection.
        /// </summary>
        public ulong FaultAtBlow { get; set; } = ulong.MaxValue;

        /// <summary>
        /// Sticky flag: set when a blow fault fires, survives subsequent blows.
        /// Cleared only by Reset() or explicit assignment.
        /// </summary>
        public bool BlowFaultFired { get; set; }

        /// <summary>
        /// Fault mode for blow operations:
        ///   0 = partial_program (not all bits flip)
        ///   1 = stuck_bit (specific bits never program, mask via StuckBitMask)
        ///   2 = read_disturb (adjacent byte gets unintended bit flips)
        ///   3 = overblow (extra neighboring bits get blown)
        /// </summary>
        public int BlowFaultMode { get; set; }

        /// <summary>
        /// Deterministic PRNG seed for fault bit selection.
        /// </summary>
        public uint FaultSeed { get; set; }

        /// <summary>
        /// Count of bits currently blown (set to 1) across the entire OTP region.
        /// </summary>
        public int BlownBitCount
        {
            get
            {
                int count = 0;
                for(var i = 0L; i < size; i++)
                {
                    count += PopCount(storage[i]);
                }
                return count;
            }
        }

        /// <summary>
        /// Total programmable bits minus currently blown bits.
        /// </summary>
        public long RemainingLife
        {
            get { return (size * 8) - BlownBitCount; }
        }

        /// <summary>
        /// Address of the last blow that triggered a fault.
        /// </summary>
        public long LastFaultAddress { get; set; }

        /// <summary>
        /// Snapshot of OTP state captured at the moment a fault fires.
        /// </summary>
        public byte[] FaultSnapshot { get; set; }

        // --- Tardigrade sweep compatibility aliases ---
        // These let the sweep engine use the same property names
        // as flash backends where possible.

        /// <summary>Alias for TotalBlows (sweep compatibility).</summary>
        public ulong TotalWordWrites
        {
            get { return TotalBlows; }
            set { TotalBlows = value; }
        }

        /// <summary>Alias for FaultAtBlow (sweep compatibility).</summary>
        public ulong FaultAtWordWrite
        {
            get { return FaultAtBlow; }
            set { FaultAtBlow = value; }
        }

        /// <summary>Alias for BlowFaultFired (sweep compatibility).</summary>
        public bool FaultEverFired
        {
            get { return BlowFaultFired; }
            set { BlowFaultFired = value; }
        }

        /// <summary>
        /// Per-byte stuck-bit mask. Bits set to 1 in this mask will NEVER
        /// be programmed regardless of write value. Models manufacturing
        /// defects in the eFuse array. Applied when BlowFaultMode = 1
        /// and the blow index matches FaultAtBlow, OR applied permanently
        /// if PermanentStuckBits is true.
        /// </summary>
        public bool PermanentStuckBits { get; set; }

        /// <summary>
        /// Set a stuck-bit mask for a specific byte offset.
        /// Bits set to 1 in the mask will never program (stay 0).
        /// </summary>
        public void SetStuckBitMask(long offset, byte mask)
        {
            if(offset < 0 || offset >= size)
            {
                throw new ArgumentOutOfRangeException(
                    $"Stuck bit mask offset {offset} is outside OTP range [0, {size})");
            }
            stuckBitMask[offset] = mask;
        }

        /// <summary>
        /// Get the stuck-bit mask for a specific byte offset.
        /// </summary>
        public byte GetStuckBitMask(long offset)
        {
            if(offset < 0 || offset >= size)
            {
                return 0;
            }
            return stuckBitMask[offset];
        }

        /// <summary>
        /// Directly preset OTP bits without tracking (for test setup).
        /// Bypasses fault injection. Used to initialize anti-rollback
        /// counters or security fuse state before a test run.
        /// </summary>
        public void PresetByte(long offset, byte value)
        {
            ValidateRange(offset, 1);
            // OTP semantics: can only add 1-bits, never clear.
            storage[offset] |= value;
        }

        /// <summary>
        /// Directly preset a 32-bit word without tracking (for test setup).
        /// </summary>
        public void PresetWord(long offset, uint value)
        {
            ValidateRange(offset, 4);
            storage[offset] |= (byte)(value & 0xFF);
            storage[offset + 1] |= (byte)((value >> 8) & 0xFF);
            storage[offset + 2] |= (byte)((value >> 16) & 0xFF);
            storage[offset + 3] |= (byte)((value >> 24) & 0xFF);
        }

        /// <summary>
        /// Clear all OTP storage and stuck-bit masks. This is a TEST-ONLY
        /// operation that violates OTP semantics — real hardware cannot do this.
        /// Used between test iterations to reset the fuse array to a known state.
        /// </summary>
        public void TestClearAll()
        {
            Array.Clear(storage, 0, (int)size);
            Array.Clear(stuckBitMask, 0, (int)size);
            TotalBlows = 0;
            BlowFaultFired = false;
            LastFaultAddress = 0;
            FaultSnapshot = null;
        }

        // --- Core blow logic ---

        private void BlowBits(long offset, byte[] data)
        {
            if(data.Length == 0)
            {
                return;
            }

            ValidateRange(offset, data.Length);

            // Determine how many blow operations this write represents.
            // Granularity: 1 bit = each changed bit is a blow,
            //              8 bits = each byte is a blow,
            //              32 bits = each 4-byte word is a blow.
            int blowsInThisWrite;
            switch(writeGranularity)
            {
                case 1:
                    blowsInThisWrite = CountNewBits(offset, data);
                    break;
                case 8:
                    blowsInThisWrite = data.Length;
                    break;
                case 32:
                    blowsInThisWrite = Math.Max(1, (data.Length + 3) / 4);
                    break;
                default:
                    blowsInThisWrite = data.Length;
                    break;
            }

            if(blowsInThisWrite == 0)
            {
                // No new bits to blow — idempotent write.
                return;
            }

            for(int blowIdx = 0; blowIdx < blowsInThisWrite; blowIdx++)
            {
                TotalBlows++;

                if(TotalBlows == FaultAtBlow && !BlowFaultFired)
                {
                    BlowFaultFired = true;
                    LastFaultAddress = offset;

                    // Apply partial blow based on fault mode.
                    int blowByteStart;
                    int blowByteEnd;
                    ComputeBlowWindow(offset, data.Length, blowIdx, out blowByteStart, out blowByteEnd);

                    // Apply all blows BEFORE the faulted one normally.
                    for(int prior = 0; prior < blowIdx; prior++)
                    {
                        int priorStart;
                        int priorEnd;
                        ComputeBlowWindow(offset, data.Length, prior, out priorStart, out priorEnd);
                        ApplyNormalBlow(offset, data, priorStart, priorEnd);
                    }

                    // Apply the faulted blow.
                    ApplyFaultedBlow(offset, data, blowByteStart, blowByteEnd);

                    // Snapshot OTP state at fault moment.
                    FaultSnapshot = new byte[size];
                    Array.Copy(storage, FaultSnapshot, (int)size);
                    return; // Stop — power died.
                }
            }

            // No fault fired: apply all bits normally.
            if(!BlowFaultFired)
            {
                ApplyNormalBlow(offset, data, 0, data.Length);
            }
        }

        private void ApplyNormalBlow(long offset, byte[] data, int startByte, int endByte)
        {
            for(int i = startByte; i < endByte && i < data.Length; i++)
            {
                byte incoming = data[i];
                byte stuckMask = PermanentStuckBits ? stuckBitMask[offset + i] : (byte)0;
                // OTP: bits only go 0->1. Stuck bits (mask=1) are prevented.
                byte newBits = (byte)(incoming & ~stuckMask);
                storage[offset + i] |= newBits;
            }
        }

        private void ApplyFaultedBlow(long offset, byte[] data, int startByte, int endByte)
        {
            var seed = FaultSeed != 0 ? FaultSeed : (uint)(TotalBlows ^ 0xCAFE);
            if(seed == 0)
            {
                seed = 0xDEAD;
            }

            switch(BlowFaultMode)
            {
                case 0:
                    // Partial program: only some of the requested bits flip.
                    for(int i = startByte; i < endByte && i < data.Length; i++)
                    {
                        byte incoming = data[i];
                        byte newBits = (byte)(incoming & ~storage[offset + i]);
                        // Generate a mask that randomly drops some new bits.
                        seed = AdvanceLcg(seed);
                        byte keepMask = (byte)(seed >> 16);
                        byte partialBits = (byte)(newBits & keepMask);
                        storage[offset + i] |= partialBits;
                    }
                    break;

                case 1:
                    // Stuck bit: apply stuck-bit mask to prevent specific bits.
                    for(int i = startByte; i < endByte && i < data.Length; i++)
                    {
                        byte incoming = data[i];
                        byte stuckMask = stuckBitMask[offset + i];
                        byte allowed = (byte)(incoming & ~stuckMask);
                        storage[offset + i] |= allowed;
                    }
                    break;

                case 2:
                    // Read disturb: target bits blow normally, but an adjacent
                    // byte gets unintended 0->1 bit flips.
                    for(int i = startByte; i < endByte && i < data.Length; i++)
                    {
                        storage[offset + i] |= data[i];
                    }
                    // Disturb a neighboring byte.
                    seed = AdvanceLcg(seed);
                    int direction = (seed & 1) == 0 ? -1 : 1;
                    long neighborOffset = offset + endByte + direction;
                    if(neighborOffset >= 0 && neighborOffset < size)
                    {
                        seed = AdvanceLcg(seed);
                        byte disturbBits = (byte)((seed >> 16) & 0x03);
                        if(disturbBits == 0)
                        {
                            disturbBits = 0x01;
                        }
                        storage[neighborOffset] |= disturbBits;
                    }
                    break;

                case 3:
                    // Overblow: target bits blow plus extra random neighbors.
                    for(int i = startByte; i < endByte && i < data.Length; i++)
                    {
                        storage[offset + i] |= data[i];
                    }
                    // Blow a few extra bits in the same region.
                    int extraCount = 1 + (int)(AdvanceLcg(seed) % 3);
                    for(int e = 0; e < extraCount; e++)
                    {
                        seed = AdvanceLcg(seed);
                        long extraOffset = offset + (int)(seed % (uint)Math.Max(1, endByte + 4));
                        if(extraOffset >= 0 && extraOffset < size)
                        {
                            seed = AdvanceLcg(seed);
                            byte extraBit = (byte)(1 << (int)(seed % 8));
                            storage[extraOffset] |= extraBit;
                        }
                    }
                    break;

                default:
                    // Unknown mode: treat as partial_program.
                    goto case 0;
            }
        }

        private void ComputeBlowWindow(long offset, int dataLength, int blowIdx,
                                        out int startByte, out int endByte)
        {
            switch(writeGranularity)
            {
                case 1:
                    // Bit-granularity: each blow is one bit. Map to containing byte.
                    startByte = 0;
                    endByte = dataLength;
                    break;
                case 8:
                    // Byte-granularity: each blow is one byte.
                    startByte = Math.Min(blowIdx, dataLength);
                    endByte = Math.Min(blowIdx + 1, dataLength);
                    break;
                case 32:
                    // Word-granularity: each blow is 4 bytes.
                    startByte = Math.Min(blowIdx * 4, dataLength);
                    endByte = Math.Min(startByte + 4, dataLength);
                    break;
                default:
                    startByte = 0;
                    endByte = dataLength;
                    break;
            }
        }

        private int CountNewBits(long offset, byte[] data)
        {
            int count = 0;
            for(int i = 0; i < data.Length; i++)
            {
                byte newBits = (byte)(data[i] & ~storage[offset + i]);
                count += PopCount(newBits);
            }
            return count;
        }

        private static int PopCount(byte b)
        {
            int count = 0;
            while(b != 0)
            {
                count += (b & 1);
                b >>= 1;
            }
            return count;
        }

        private static uint AdvanceLcg(uint seed)
        {
            return seed * 1103515245u + 12345u;
        }

        private void ValidateRange(long offset, long length)
        {
            if(offset < 0 || length < 0 || (offset + length) > size)
            {
                throw new ArgumentOutOfRangeException(
                    $"OTP access out of range: offset={offset}, length={length}, size={size}");
            }
        }

        private long size;
        private int writeGranularity;
        private byte[] storage;
        private byte[] stuckBitMask;

        private const long DefaultSize = 0x100;     // 256 bytes (2048 fuse bits)
        private const int DefaultGranularity = 32;   // Word-granularity blows
    }
}
