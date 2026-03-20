// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Minimal QEMU fw_cfg MMIO stub for Renode bringup. This is intentionally
// small: enough for U-Boot's qfw probe and basic firmware queries on the
// qemu_arm64 "virt" target, without trying to model DMA or file-backed blobs.

using System;
using System.Collections.Generic;

using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public sealed class QEMUFwCfg : IDoubleWordPeripheral, IWordPeripheral, IBytePeripheral, IKnownSize
    {
        public QEMUFwCfg()
        {
            entries = BuildEntries();
            Reset();
        }

        public long Size => 0x18;

        public void Reset()
        {
            currentSelector = SignatureSelector;
            currentData = entries[currentSelector];
            currentOffset = 0;
            dmaAddress = 0;
        }

        public byte ReadByte(long offset)
        {
            switch(offset)
            {
                case DataOffset:
                    return ReadData(1)[0];
                case SelectorOffset:
                case SelectorOffset + 1:
                    return 0;
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg byte read at 0x{0:X}", offset);
                    return 0;
            }
        }

        public ushort ReadWord(long offset)
        {
            switch(offset)
            {
                case DataOffset:
                    return AssembleLittleEndianWord(ReadData(2));
                case SelectorOffset:
                    return 0;
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg word read at 0x{0:X}", offset);
                    return 0;
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case DataOffset:
                    return AssembleLittleEndianDoubleWord(ReadData(4));
                case SelectorOffset:
                    return 0;
                case DmaOffset:
                    return (uint)(dmaAddress & 0xFFFFFFFF);
                case DmaOffset + 4:
                    return (uint)(dmaAddress >> 32);
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg dword read at 0x{0:X}", offset);
                    return 0;
            }
        }

        public void WriteByte(long offset, byte value)
        {
            switch(offset)
            {
                case SelectorOffset:
                    selectorWriteLow = value;
                    break;
                case SelectorOffset + 1:
                    SelectEntry((ushort)((selectorWriteLow << 8) | value));
                    break;
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg byte write at 0x{0:X}: 0x{1:X2}", offset, value);
                    break;
            }
        }

        public void WriteWord(long offset, ushort value)
        {
            switch(offset)
            {
                case SelectorOffset:
                    SelectEntry(ReverseEndianness(value));
                    break;
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg word write at 0x{0:X}: 0x{1:X4}", offset, value);
                    break;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case SelectorOffset:
                    SelectEntry((ushort)((value >> 8) & 0xFFFF));
                    break;
                case DmaOffset:
                    dmaAddress = (dmaAddress & 0xFFFFFFFF00000000UL) | value;
                    break;
                case DmaOffset + 4:
                    dmaAddress = (dmaAddress & 0x00000000FFFFFFFFUL) | ((ulong)value << 32);
                    break;
                default:
                    this.Log(LogLevel.Noisy, "Unhandled fw_cfg dword write at 0x{0:X}: 0x{1:X8}", offset, value);
                    break;
            }
        }

        private void SelectEntry(ushort selector)
        {
            currentSelector = selector;
            currentOffset = 0;
            if(!entries.TryGetValue(selector, out currentData))
            {
                currentData = Array.Empty<byte>();
                this.Log(LogLevel.Noisy, "fw_cfg selector 0x{0:X} not implemented; returning zeros", selector);
            }
        }

        private byte[] ReadData(int count)
        {
            var result = new byte[count];
            if(currentData == null)
            {
                return result;
            }

            for(var i = 0; i < count; i++)
            {
                if(currentOffset < currentData.Length)
                {
                    result[i] = currentData[currentOffset];
                    currentOffset++;
                }
            }
            return result;
        }

        private static ushort AssembleLittleEndianWord(byte[] data)
        {
            return (ushort)(data[0] | (data[1] << 8));
        }

        private static uint AssembleLittleEndianDoubleWord(byte[] data)
        {
            return (uint)(data[0]
                | (data[1] << 8)
                | (data[2] << 16)
                | (data[3] << 24));
        }

        private static ushort ReverseEndianness(ushort value)
        {
            return (ushort)((value >> 8) | (value << 8));
        }

        private static Dictionary<ushort, byte[]> BuildEntries()
        {
            return new Dictionary<ushort, byte[]>
            {
                { SignatureSelector, new byte[] { (byte)'Q', (byte)'E', (byte)'M', (byte)'U' } },
                { IdSelector, new byte[] { 0x00 } },
                { RamSizeSelector, ToBigEndianBytes(0x08000000u) },
                { NoGraphicSelector, new byte[] { 0x01 } },
                { CpuCountSelector, ToBigEndianBytes(0x0001) },
                { MaxCpuCountSelector, ToBigEndianBytes(0x0001) },
                { FileDirectorySelector, ToBigEndianBytes(0u) },
            };
        }

        private static byte[] ToBigEndianBytes(uint value)
        {
            return new[]
            {
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF),
            };
        }

        private static byte[] ToBigEndianBytes(ushort value)
        {
            return new[]
            {
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF),
            };
        }

        private const long DataOffset = 0x0;
        private const long SelectorOffset = 0x8;
        private const long DmaOffset = 0x10;

        private const ushort SignatureSelector = 0x0000;
        private const ushort IdSelector = 0x0001;
        private const ushort RamSizeSelector = 0x0003;
        private const ushort NoGraphicSelector = 0x0004;
        private const ushort CpuCountSelector = 0x0005;
        private const ushort MaxCpuCountSelector = 0x000F;
        private const ushort FileDirectorySelector = 0x0019;

        private readonly Dictionary<ushort, byte[]> entries;

        private ushort currentSelector;
        private byte[] currentData;
        private int currentOffset;
        private byte selectorWriteLow;
        private ulong dmaAddress;
    }
}
