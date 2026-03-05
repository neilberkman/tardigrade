// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Transparent write-intercepting wrapper for STM32F4 flash.
//
// Registered on the sysbus at the canonical flash address (0x08000000)
// while the backing MappedMemory stays at the alias address (0x00000000).
// All reads forward to BackingMemory.  Writes forward to BackingMemory
// AND notify the STM32F4FlashController for O(1) per-write tracking
// when PG (programming) mode is active.
//
// Implements IMemory so Renode recognizes this region as executable
// memory for VTOR and PC validation.  CPU instruction fetches go
// through ReadDoubleWord (slower than mapped memory but correct).
//
// This replaces the old snapshot+diff approach which cost O(flash_size)
// per write — prohibitively expensive for 1 MB flash with 47K writes.

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32F4FlashInterceptor : IDoubleWordPeripheral, IWordPeripheral,
                                           IBytePeripheral, IKnownSize, IMemory
    {
        public STM32F4FlashInterceptor(IMachine machine)
        {
        }

        public MappedMemory BackingMemory { get; set; }
        public STM32F4FlashController Controller { get; set; }

        public long Size => BackingMemory != null ? BackingMemory.Size : 0;

        // --- Reads: straight through to backing memory ---

        public uint ReadDoubleWord(long offset)
        {
            return BackingMemory.ReadDoubleWord(offset);
        }

        public ushort ReadWord(long offset)
        {
            return BackingMemory.ReadWord(offset);
        }

        public byte ReadByte(long offset)
        {
            return BackingMemory.ReadByte(offset);
        }

        // --- Writes: intercept when PG is active ---

        public void WriteDoubleWord(long offset, uint value)
        {
            if(Controller != null && Controller.PgActive && !Controller.AnyFaultFired)
            {
                if(!Controller.OnDirectFlashWrite(offset, value))
                {
                    return; // Fault injected — suppress write.
                }
            }
            BackingMemory.WriteDoubleWord(offset, value);
        }

        public void WriteWord(long offset, ushort value)
        {
            if(Controller != null && Controller.PgActive && !Controller.AnyFaultFired)
            {
                if(!Controller.OnDirectFlashWriteHalf(offset, value))
                {
                    return;
                }
            }
            BackingMemory.WriteWord(offset, value);
        }

        public void WriteByte(long offset, byte value)
        {
            if(Controller != null && Controller.PgActive && !Controller.AnyFaultFired)
            {
                if(!Controller.OnDirectFlashWriteByte(offset, value))
                {
                    return;
                }
            }
            BackingMemory.WriteByte(offset, value);
        }

        // --- IMultibyteWritePeripheral (required by IMemory) ---

        public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
        {
            return BackingMemory.ReadBytes(offset, count);
        }

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count,
                               IPeripheral context = null)
        {
            BackingMemory.WriteBytes(offset, array, startingIndex, count);
        }

        // --- IQuadWordPeripheral (required by IMemory) ---

        public ulong ReadQuadWord(long offset)
        {
            uint lo = BackingMemory.ReadDoubleWord(offset);
            uint hi = BackingMemory.ReadDoubleWord(offset + 4);
            return (ulong)lo | ((ulong)hi << 32);
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            BackingMemory.WriteDoubleWord(offset, (uint)(value & 0xFFFFFFFF));
            BackingMemory.WriteDoubleWord(offset + 4, (uint)(value >> 32));
        }

        public void Reset()
        {
        }
    }
}
