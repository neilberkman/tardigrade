// CFI (Common Flash Interface) NOR Flash peripheral for Renode
// Implements CFI Query protocol + read/write/erase + tardigrade write tracking
//
// Used for: barebox vexpress, U-Boot CFI flash testing
// Reference: JEDEC JESD68.01, Intel CFI spec

using System;
using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public class CFIFlash : IDoubleWordPeripheral, IBytePeripheral, IWordPeripheral, IKnownSize
    {
        public CFIFlash(int size)
        {
            this.size = (long)size;
            flash = new byte[size];
            // Initialize to erased state (all 0xFF)
            for (int i = 0; i < size; i++)
                flash[i] = 0xFF;

            sectorSize = 0x20000; // 128KB sectors (default for 64MB flash)
            mode = FlashMode.ReadArray;
            totalWrites = 0;
            totalErases = 0;

            // Build CFI query response table
            BuildCFITable();
        }

        public long Size => size;

        // --- Tardigrade write tracking ---
        public int TotalWrites => totalWrites;
        public int TotalPageErases => totalErases;
        public bool FaultFired { get; set; }
        public bool EraseFaultFired { get; set; }
        public int FaultAtWrite { get; set; } = -1;
        public int FaultAtPageErase { get; set; } = -1;
        public int WriteFaultMode { get; set; } = 0;
        public bool WriteTraceEnabled { get; set; }
        public bool EraseTraceEnabled { get; set; }
        public int CorruptionSeed { get; set; }
        public bool FaultEverFired { get; set; }

        private readonly List<string> writeTrace = new List<string>();
        private readonly List<string> eraseTrace = new List<string>();

        public string WriteTraceToString()
        {
            return string.Join("\n", writeTrace);
        }

        public string EraseTraceToString()
        {
            return string.Join("\n", eraseTrace);
        }

        public void WriteTraceClear()
        {
            writeTrace.Clear();
        }

        public void EraseTraceClear()
        {
            eraseTrace.Clear();
        }

        // --- IDoubleWordPeripheral ---
        public uint ReadDoubleWord(long offset)
        {
            if (mode == FlashMode.CFIQuery)
            {
                return ReadCFI(offset);
            }
            if (mode == FlashMode.ReadStatus)
            {
                return 0x80; // Ready
            }
            // Normal read from flash
            if (offset >= 0 && offset + 3 < size)
            {
                return (uint)(flash[offset] | (flash[offset + 1] << 8) |
                              (flash[offset + 2] << 16) | (flash[offset + 3] << 24));
            }
            return 0xFFFFFFFF;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            HandleCommand(offset, value);
        }

        // --- IBytePeripheral ---
        public byte ReadByte(long offset)
        {
            if (mode == FlashMode.CFIQuery)
            {
                return (byte)(ReadCFI(offset) & 0xFF);
            }
            if (mode == FlashMode.ReadStatus)
            {
                return 0x80;
            }
            if (offset >= 0 && offset < size)
                return flash[offset];
            return 0xFF;
        }

        public void WriteByte(long offset, byte value)
        {
            HandleCommand(offset, (uint)value);
        }

        // --- IWordPeripheral ---
        public ushort ReadWord(long offset)
        {
            if (mode == FlashMode.CFIQuery)
            {
                return (ushort)(ReadCFI(offset) & 0xFFFF);
            }
            if (mode == FlashMode.ReadStatus)
            {
                return 0x80;
            }
            if (offset >= 0 && offset + 1 < size)
            {
                return (ushort)(flash[offset] | (flash[offset + 1] << 8));
            }
            return 0xFFFF;
        }

        public void WriteWord(long offset, ushort value)
        {
            HandleCommand(offset, (uint)value);
        }

        public void Reset()
        {
            mode = FlashMode.ReadArray;
            totalWrites = 0;
            totalErases = 0;
            FaultFired = false;
            EraseFaultFired = false;
            FaultEverFired = false;
            writeTrace.Clear();
            eraseTrace.Clear();
        }

        // --- Flash read helpers ---
        public byte[] ReadBytes(long offset, int count)
        {
            var result = new byte[count];
            for (int i = 0; i < count && offset + i < size; i++)
                result[i] = flash[offset + i];
            return result;
        }

        public void WriteBytes(long offset, byte[] data)
        {
            for (int i = 0; i < data.Length && offset + i < size; i++)
                flash[offset + i] = data[i];
        }

        public void WriteBytes(long offset, byte[] data, int startIndex, int count)
        {
            for (int i = 0; i < count && offset + i < size; i++)
                flash[offset + i] = data[startIndex + i];
        }

        public long FlashSize => size;

        // --- Command handling ---
        private void HandleCommand(long offset, uint value)
        {
            byte cmd = (byte)(value & 0xFF);

            switch (cmd)
            {
                case 0xFF: // Read Array
                    mode = FlashMode.ReadArray;
                    break;
                case 0x98: // CFI Query
                    mode = FlashMode.CFIQuery;
                    break;
                case 0x70: // Read Status Register
                    mode = FlashMode.ReadStatus;
                    break;
                case 0x50: // Clear Status Register
                    mode = FlashMode.ReadArray;
                    break;
                case 0x40: // Word Program Setup
                case 0x10: // Alternate Word Program Setup
                    mode = FlashMode.WordProgram;
                    break;
                case 0x20: // Block Erase Setup
                    mode = FlashMode.BlockEraseSetup;
                    break;
                case 0xD0: // Block Erase Confirm (after 0x20)
                    if (mode == FlashMode.BlockEraseSetup)
                    {
                        EraseSector(offset);
                        mode = FlashMode.ReadStatus;
                    }
                    break;
                default:
                    if (mode == FlashMode.WordProgram)
                    {
                        // Program the word (NOR flash: can only clear bits, 1->0)
                        ProgramWord(offset, value);
                        mode = FlashMode.ReadStatus;
                    }
                    break;
            }
        }

        private void ProgramWord(long offset, uint value)
        {
            // Check fault injection
            if (FaultAtWrite >= 0 && totalWrites == FaultAtWrite && !FaultEverFired)
            {
                FaultFired = true;
                FaultEverFired = true;
                this.Log(LogLevel.Info, "CFIFlash: Fault injected at write #{0}, offset=0x{1:X}", totalWrites, offset);

                if (WriteFaultMode == 0) // power_loss: don't write, halt
                {
                    totalWrites++;
                    return;
                }
                // Other fault modes: write with corruption (handled by caller)
            }

            // NOR flash: can only clear bits (AND with existing data)
            if (offset >= 0 && offset + 3 < size)
            {
                flash[offset] &= (byte)(value & 0xFF);
                flash[offset + 1] &= (byte)((value >> 8) & 0xFF);
                flash[offset + 2] &= (byte)((value >> 16) & 0xFF);
                flash[offset + 3] &= (byte)((value >> 24) & 0xFF);
            }

            if (WriteTraceEnabled)
            {
                writeTrace.Add(string.Format("{0},{1},{2}", totalWrites, offset, value));
            }

            totalWrites++;
        }

        public void EraseSector(long offset)
        {
            long sectorStart = (offset / sectorSize) * sectorSize;

            // Check erase fault injection
            if (FaultAtPageErase >= 0 && totalErases == FaultAtPageErase && !FaultEverFired)
            {
                EraseFaultFired = true;
                FaultEverFired = true;
                this.Log(LogLevel.Info, "CFIFlash: Erase fault at erase #{0}, sector=0x{1:X}", totalErases, sectorStart);
                totalErases++;
                return;
            }

            // Erase sector to 0xFF
            for (long i = sectorStart; i < sectorStart + sectorSize && i < size; i++)
                flash[i] = 0xFF;

            if (EraseTraceEnabled)
            {
                eraseTrace.Add(string.Format("{0},{1},{2},{3}", totalErases, sectorStart, totalWrites, sectorSize));
            }

            totalErases++;
        }

        // --- CFI Query Response ---
        private uint ReadCFI(long offset)
        {
            // CFI query addresses are word-aligned: actual_offset = query_index * 2
            // But some implementations use byte addressing
            long queryIndex = offset / 2;
            if (queryIndex >= 0 && queryIndex < cfiTable.Length)
                return cfiTable[queryIndex];
            return 0;
        }

        private void BuildCFITable()
        {
            cfiTable = new byte[0x80];

            // QRY magic at offset 0x10
            cfiTable[0x10] = (byte)'Q';
            cfiTable[0x11] = (byte)'R';
            cfiTable[0x12] = (byte)'Y';

            // Primary command set: Intel/Sharp (0x0001)
            cfiTable[0x13] = 0x01;
            cfiTable[0x14] = 0x00;

            // Primary extended table address
            cfiTable[0x15] = 0x31;
            cfiTable[0x16] = 0x00;

            // Alternate command set: none
            cfiTable[0x17] = 0x00;
            cfiTable[0x18] = 0x00;

            // Alternate extended table: none
            cfiTable[0x19] = 0x00;
            cfiTable[0x1A] = 0x00;

            // Vcc min/max
            cfiTable[0x1B] = 0x27; // 2.7V
            cfiTable[0x1C] = 0x36; // 3.6V

            // Vpp min/max
            cfiTable[0x1D] = 0x00;
            cfiTable[0x1E] = 0x00;

            // Typical timeouts
            cfiTable[0x1F] = 0x04; // Word program: 2^4 = 16 us
            cfiTable[0x20] = 0x00; // Buffer write: N/A
            cfiTable[0x21] = 0x0A; // Block erase: 2^10 = 1024 ms
            cfiTable[0x22] = 0x00; // Chip erase: N/A

            // Max timeouts (multipliers)
            cfiTable[0x23] = 0x04;
            cfiTable[0x24] = 0x00;
            cfiTable[0x25] = 0x04;
            cfiTable[0x26] = 0x00;

            // Device size: 2^N bytes
            int sizeLog = 0;
            long s = size;
            while (s > 1) { s >>= 1; sizeLog++; }
            cfiTable[0x27] = (byte)sizeLog;

            // Flash device interface: x8/x16
            cfiTable[0x28] = 0x02;
            cfiTable[0x29] = 0x00;

            // Max buffer write size: 2^N
            cfiTable[0x2A] = 0x00;
            cfiTable[0x2B] = 0x00;

            // Number of erase block regions
            cfiTable[0x2C] = 0x01;

            // Erase block region 1
            int numBlocks = (int)(size / sectorSize) - 1;
            cfiTable[0x2D] = (byte)(numBlocks & 0xFF);
            cfiTable[0x2E] = (byte)((numBlocks >> 8) & 0xFF);
            int sectorSizeDiv256 = (int)(sectorSize / 256);
            cfiTable[0x2F] = (byte)(sectorSizeDiv256 & 0xFF);
            cfiTable[0x30] = (byte)((sectorSizeDiv256 >> 8) & 0xFF);

            // Extended query table at 0x31
            cfiTable[0x31] = (byte)'P';
            cfiTable[0x32] = (byte)'R';
            cfiTable[0x33] = (byte)'I';
            cfiTable[0x34] = 0x31; // Version 1.1
            cfiTable[0x35] = 0x31;

            // Features
            cfiTable[0x36] = 0x06; // Erase suspend supported
            cfiTable[0x37] = 0x01; // Block protect bits
            cfiTable[0x38] = 0x00; // Temporary block unprotect
            cfiTable[0x39] = 0x01; // Block protect/unprotect scheme
            cfiTable[0x3A] = 0x01; // Simultaneous operations
            cfiTable[0x3B] = 0x00; // Burst mode type
            cfiTable[0x3C] = 0x00; // Page mode type
        }

        private readonly long size;
        private readonly long sectorSize;
        private byte[] flash;
        private byte[] cfiTable;
        private FlashMode mode;
        private int totalWrites;
        private int totalErases;

        private enum FlashMode
        {
            ReadArray,
            CFIQuery,
            ReadStatus,
            WordProgram,
            BlockEraseSetup,
        }
    }
}
