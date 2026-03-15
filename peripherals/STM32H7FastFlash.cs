// SPDX-License-Identifier: Apache-2.0
//
// Minimal STM32H7 dual-bank FLASH peripheral for fast emulation.
//
// Registered at 0x52002000 (STM32H7 FLASH register base), size 0x200.
// Counts writes on PG 1->0 transitions for smoke/perf experiments.
// This is intentionally not fully faithful to H7's 32-byte programming
// granularity: a single PG deactivation may cover multiple changed words.
// Use STM32H7FlashController for hardware-faithful fault indexing.
//
// When WriteTraceEnabled or fault snapshot is needed, captures flash
// on PG 0->1 and diffs on PG 1->0 to find the changed address.
// Otherwise just increments the counter.
//
// STM32H743 uniform sector geometry:
//   Bank 1: 8 sectors × 128 KB at 0x08000000
//   Bank 2: 8 sectors × 128 KB at 0x08100000
//
// Bank 1 registers at offset 0x000, Bank 2 at offset 0x100.

using System;
using System.Collections.Generic;
using System.Text;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32H7FastFlash : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        private readonly FaultTracker tracker = new FaultTracker();

        public STM32H7FastFlash(IMachine machine) : base(machine)
        {
            bank1State = new BankState();
            bank2State = new BankState();
        }

        public long Size => 0x200;

        // --- MappedMemory references (wired from .repl) ---

        public MappedMemory Flash1 { get; set; }
        public MappedMemory Flash2 { get; set; }

        // --- DualBankFlashView for ITardigradeFaultInjectable ---

        private DualBankView dualView;

        private DualBankView GetDualView()
        {
            if(dualView == null && Flash1 != null && Flash2 != null)
            {
                dualView = new DualBankView(Flash1, Flash2);
            }
            return dualView;
        }

        public IMemory Flash => GetDualView();
        public long FlashBaseAddress { get; set; } = 0x08000000;
        public long FlashSize { get; set; } = 0x200000;
        public int PageSize { get; set; } = 0x20000;
        public byte EraseFill { get; set; } = 0xFF;

        // --- Write tracking ---

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }

        public bool PerWriteAccurate => false;

        public bool SkipShadowScan { get; set; } = true;
        public bool PassthroughMode { get; set; }
        public int DiffLookahead { get; set; } = 32;

        public void InvalidateShadow() { }

        // --- Erase tracking ---

        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }
        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }
        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }

        // --- Fault modes ---

        public int WriteFaultMode { get => tracker.WriteFaultMode; set => tracker.WriteFaultMode = value; }
        public uint CorruptionSeed { get => tracker.CorruptionSeed; set => tracker.CorruptionSeed = value; }
        public int EraseFaultMode { get => tracker.EraseFaultMode; set => tracker.EraseFaultMode = value; }

        public bool AnyFaultFired => tracker.AnyFaultFired;

        // --- Write trace ---

        public bool WriteTraceEnabled { get => tracker.WriteTraceEnabled; set => tracker.WriteTraceEnabled = value; }
        public int WriteTraceCount => tracker.WriteTraceCount;
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public void WriteTraceClear() => tracker.WriteTraceClear();

        // --- Erase trace ---

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;
        public string EraseTraceToString() => tracker.EraseTraceToString();
        public void EraseTraceClear() => tracker.EraseTraceClear();

        // --- Read-fault injection stubs ---

        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        // ---------------------------------------------------------------
        // Per-bank state.
        // ---------------------------------------------------------------

        private BankState bank1State;
        private BankState bank2State;

        private class BankState
        {
            public uint crValue = LOCK_BIT;
            public bool locked = true;
            public int keySequence;
            public bool pgActive;

            public void Reset()
            {
                crValue = LOCK_BIT;
                locked = true;
                keySequence = 0;
                pgActive = false;
            }
        }

        // Pre-fault snapshot: captured on PG 0->1 when the next write will
        // trigger a fault OR when write trace is enabled.
        private byte[] preFaultSnapshot;

        // H7 FLASH_CR bit definitions (per-bank).
        private const uint LOCK_BIT  = 1U << 0;
        private const uint PG_BIT    = 1U << 1;
        private const uint SER_BIT   = 1U << 2;
        private const uint SNB_SHIFT = 8;
        private const uint SNB_MASK  = 0x7U << 8;  // 3 bits for 8 sectors
        private const uint STRT_BIT  = 1U << 7;
        private const uint BER_BIT   = 1U << 3;
        private const uint FW_BIT    = 1U << 6;

        // FLASH unlock keys.
        private const uint KEY1 = 0x45670123U;
        private const uint KEY2 = 0xCDEF89ABU;

        // Bank geometry: 8 uniform 128 KB sectors per bank.
        private const int SectorsPerBank = 8;
        private const int SectorSize = 0x20000;  // 128 KB
        private const long Bank1BaseOffset = 0;
        private const long Bank2BaseOffset = 0x100000;  // 1 MB

        // Register offsets within each bank block.
        private const long REG_ACR     = 0x00;  // Access Control (shared, bank 1 block only)
        private const long REG_KEYR    = 0x04;
        private const long REG_OPTKEYR = 0x08;  // bank 1 block only
        private const long REG_CR      = 0x0C;
        private const long REG_SR      = 0x10;
        private const long REG_CCR     = 0x14;

        // Bank 2 registers are at offset 0x100 from bank 1.
        private const long BANK2_OFFSET = 0x100;

        // Shared register state.
        private uint acrValue;

        // ---------------------------------------------------------------
        // Read / Write overrides.
        // ---------------------------------------------------------------

        public override uint ReadDoubleWord(long offset)
        {
            if(offset >= BANK2_OFFSET)
            {
                return ReadBankRegister(bank2State, offset - BANK2_OFFSET);
            }
            return ReadBankRegister(bank1State, offset);
        }

        private uint ReadBankRegister(BankState bank, long bankOffset)
        {
            switch(bankOffset)
            {
                case REG_ACR:     return acrValue;
                case REG_KEYR:    return 0;           // write-only
                case REG_OPTKEYR: return 0;           // write-only
                case REG_CR:      return bank.crValue;
                case REG_SR:      return 0;           // BSY=0, no errors
                case REG_CCR:     return 0;           // clear control: write-only
                default:          return 0;
            }
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            if(offset >= BANK2_OFFSET)
            {
                WriteBankRegister(bank2State, offset - BANK2_OFFSET, value, Bank2BaseOffset);
                return;
            }
            WriteBankRegister(bank1State, offset, value, Bank1BaseOffset);
        }

        private void WriteBankRegister(BankState bank, long bankOffset, uint value, long flashBankOffset)
        {
            switch(bankOffset)
            {
                case REG_ACR:
                    acrValue = value;
                    break;
                case REG_KEYR:
                    HandleKeyr(bank, value);
                    break;
                case REG_OPTKEYR:
                    break;
                case REG_CR:
                    HandleCr(bank, value, flashBankOffset);
                    break;
                case REG_SR:
                    break;  // writes clear status flags (ignored)
                case REG_CCR:
                    break;  // clear control (ignored)
            }
        }

        public override void Reset()
        {
            base.Reset();
            tracker.Reset();
            acrValue = 0;
            bank1State.Reset();
            bank2State.Reset();
            preFaultSnapshot = null;
            dualView = null;
        }

        // ---------------------------------------------------------------
        // FLASH_KEYR unlock sequence.
        // ---------------------------------------------------------------

        private void HandleKeyr(BankState bank, uint key)
        {
            if(bank.keySequence == 0 && key == KEY1)
            {
                bank.keySequence = 1;
            }
            else if(bank.keySequence == 1 && key == KEY2)
            {
                bank.locked = false;
                bank.crValue &= ~LOCK_BIT;
                bank.keySequence = 0;
            }
            else
            {
                bank.keySequence = 0;
            }
        }

        // ---------------------------------------------------------------
        // FLASH_CR handler.
        // ---------------------------------------------------------------

        private void HandleCr(BankState bank, uint newCr, long flashBankOffset)
        {
            // Setting LOCK always works.
            if((newCr & LOCK_BIT) != 0)
            {
                bank.locked = true;
                bank.crValue |= LOCK_BIT;
                if(bank.pgActive)
                {
                    bank.pgActive = false;
                    HandlePgDeactivation();
                }
                return;
            }

            if(bank.locked)
            {
                return;
            }

            bool wasPgActive = bank.pgActive;
            bank.crValue = newCr;
            bank.pgActive = (newCr & PG_BIT) != 0;

            // PG 0->1: entering programming mode.
            if(!wasPgActive && bank.pgActive)
            {
                HandlePgActivation();
            }

            // PG 1->0: a write just completed.
            if(wasPgActive && !bank.pgActive)
            {
                HandlePgDeactivation();
            }

            // SER + START: sector erase.
            if((newCr & SER_BIT) != 0 && (newCr & STRT_BIT) != 0)
            {
                int sectorNum = (int)((newCr & SNB_MASK) >> (int)SNB_SHIFT);
                HandleErase(sectorNum, flashBankOffset);
                bank.crValue &= ~STRT_BIT;
            }

            // BER + START: bank erase (erase all sectors in the bank).
            if((newCr & BER_BIT) != 0 && (newCr & STRT_BIT) != 0)
            {
                for(int s = 0; s < SectorsPerBank; s++)
                {
                    HandleErase(s, flashBankOffset);
                }
                bank.crValue &= ~STRT_BIT;
            }
        }

        // ---------------------------------------------------------------
        // PG activation: snapshot if needed for trace or fault.
        // ---------------------------------------------------------------

        private void HandlePgActivation()
        {
            preFaultSnapshot = null;

            var flash = GetDualView();
            if(AnyFaultFired || flash == null || FlashSize <= 0)
            {
                return;
            }

            bool needSnapshot = WriteTraceEnabled
                || TotalWordWrites + 1 == FaultAtWordWrite;

            if(needSnapshot)
            {
                preFaultSnapshot = flash.ReadBytes(0, checked((int)FlashSize));
            }
        }

        // ---------------------------------------------------------------
        // PG deactivation: count write, handle trace/fault.
        // ---------------------------------------------------------------

        private void HandlePgDeactivation()
        {
            var flash = GetDualView();
            if(AnyFaultFired || flash == null || FlashSize <= 0)
            {
                return;
            }

            if(preFaultSnapshot != null)
            {
                int flashLen = checked((int)FlashSize);
                byte[] current = flash.ReadBytes(0, flashLen);
                int changedOffset = -1;

                for(int off = 0; off <= flashLen - 4; off += 4)
                {
                    if(current[off]     != preFaultSnapshot[off]
                    || current[off + 1] != preFaultSnapshot[off + 1]
                    || current[off + 2] != preFaultSnapshot[off + 2]
                    || current[off + 3] != preFaultSnapshot[off + 3])
                    {
                        changedOffset = off;
                        break;
                    }
                }

                if(changedOffset >= 0)
                {
                    uint wordValue = FaultTracker.ReadU32(current, changedOffset);

                    if(tracker.RecordWriteAndCheckFault(changedOffset, wordValue))
                    {
                        FaultFired = true;
                        LastFaultAddress = (uint)(FlashBaseAddress + changedOffset);

                        var snap = new byte[flashLen];
                        Array.Copy(preFaultSnapshot, snap, flashLen);

                        ApplyWriteFaultAtOffset(snap, preFaultSnapshot, current, changedOffset, flashLen);

                        FaultFlashSnapshot = snap;
                    }
                }
                else
                {
                    if(tracker.IncrementWriteCount())
                    {
                        FaultFired = true;
                        LastFaultAddress = 0;
                        FaultFlashSnapshot = flash.ReadBytes(0, flashLen);
                    }
                }

                preFaultSnapshot = null;
            }
            else
            {
                if(tracker.IncrementWriteCount())
                {
                    FaultFired = true;
                    LastFaultAddress = 0;
                    FaultFlashSnapshot = flash.ReadBytes(0, checked((int)FlashSize));
                }
            }
        }

        // ---------------------------------------------------------------
        // Write fault application at a specific offset.
        // ---------------------------------------------------------------

        private static uint KeepOneToZeroTransitions(uint oldWord, uint newWord, uint keepMask)
        {
            uint bitsToFlip = oldWord & ~newWord;
            uint actuallyFlipped = bitsToFlip & keepMask;
            return oldWord & ~actuallyFlipped;
        }

        private void ApplyWriteFaultAtOffset(byte[] snap, byte[] pre, byte[] post, int off, int len)
        {
            if(off > len - 4)
            {
                return;
            }

            uint oldWord = FaultTracker.ReadU32(pre, off);
            uint newWord = FaultTracker.ReadU32(post, off);

            switch(WriteFaultMode)
            {
                case 1: // Bit corruption: keep only some intended 1->0 transitions.
                {
                    uint seed = tracker.BuildFaultSeed(off);
                    uint keepMask = FaultTracker.NextLcg(ref seed);
                    uint corrupted = KeepOneToZeroTransitions(oldWord, newWord, keepMask);
                    FaultTracker.WriteU32(snap, off, corrupted);
                    break;
                }
                case 2: // Silent write failure.
                {
                    uint silentValue = ((TotalWordWrites & 1UL) == 0UL) ? 0xFFFFFFFFU : 0x00000000U;
                    FaultTracker.WriteU32(snap, off, silentValue);
                    break;
                }
                case 3: // Write rejection: drop the write (keep old word).
                {
                    FaultTracker.WriteU32(snap, off, oldWord);
                    break;
                }
                case 4: // Write-disturb: target commits, neighbors corrupted.
                {
                    FaultTracker.WriteU32(snap, off, newWord);
                    uint seed = tracker.BuildFaultSeed(off);
                    foreach(int nOff in new[] { off - 4, off + 4 })
                    {
                        if(nOff < 0 || nOff > len - 4)
                        {
                            continue;
                        }
                        uint neighborWord = FaultTracker.ReadU32(snap, nOff);
                        uint disturbMask = FaultTracker.NextLcg(ref seed) & 0x11111111U;
                        uint disturbed = neighborWord & ~disturbMask;
                        FaultTracker.WriteU32(snap, nOff, disturbed);
                    }
                    break;
                }
                case 5: // Wear-leveling corruption.
                {
                    FaultTracker.WriteU32(snap, off, newWord);
                    int pageSize = Math.Max(4, PageSize);
                    int pageStart = (off / pageSize) * pageSize;
                    int wordsPerPage = Math.Max(1, pageSize / 4);
                    int errorCount = 2 + (int)Math.Min(10UL, TotalPageErases / 8UL);
                    uint seed = tracker.BuildFaultSeed(off);
                    for(int i = 0; i < errorCount; i++)
                    {
                        int idx = (int)(FaultTracker.NextLcg(ref seed) % (uint)wordsPerPage);
                        int tOff = pageStart + idx * 4;
                        if(tOff < 0 || tOff > len - 4)
                        {
                            continue;
                        }
                        uint word = FaultTracker.ReadU32(snap, tOff);
                        uint mask = FaultTracker.NextLcg(ref seed) & 0x01010101U;
                        if(mask == 0)
                        {
                            mask = 1U << (int)(FaultTracker.NextLcg(ref seed) % 32U);
                        }
                        uint aged = word & ~mask;
                        FaultTracker.WriteU32(snap, tOff, aged);
                    }
                    break;
                }
                default: // Power-loss mode (0): faulted word stays pre-write.
                    break;
            }
        }

        // ---------------------------------------------------------------
        // Sector erase.
        // ---------------------------------------------------------------

        private void HandleErase(int sectorNum, long flashBankOffset)
        {
            if(AnyFaultFired)
            {
                return;
            }

            if(sectorNum < 0 || sectorNum >= SectorsPerBank)
            {
                return;
            }

            var flash = GetDualView();
            if(flash == null)
            {
                return;
            }

            long offset = flashBankOffset + (long)sectorNum * SectorSize;
            if(offset + SectorSize > FlashSize)
            {
                return;
            }

            if(tracker.RecordEraseAndCheckFault(offset, SectorSize))
            {
                EraseFaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + offset);
                int halfSize = SectorSize / 2;

                if(EraseFaultMode == 1)
                {
                    int quarterSize = Math.Max(1, SectorSize / 4);
                    EraseWithFill(flash, offset, halfSize);
                    // Neighbor sector bleed.
                    int nextSector = sectorNum + 1;
                    long nextOffset;
                    if(nextSector < SectorsPerBank)
                    {
                        nextOffset = flashBankOffset + (long)nextSector * SectorSize;
                    }
                    else
                    {
                        // Wrap to first sector of next bank (if exists).
                        nextOffset = flashBankOffset + (long)SectorsPerBank * SectorSize;
                    }
                    if(nextOffset + quarterSize <= FlashSize)
                    {
                        EraseWithFill(flash, nextOffset, quarterSize);
                    }
                }
                else
                {
                    EraseWithFill(flash, offset, halfSize);
                }

                FaultFlashSnapshot = flash.ReadBytes(0, checked((int)FlashSize));
            }
            else
            {
                EraseWithFill(flash, offset, SectorSize);
            }
        }

        // ---------------------------------------------------------------
        // Helpers.
        // ---------------------------------------------------------------

        private void EraseWithFill(IMemory flash, long offset, int size)
        {
            if(size <= 0)
            {
                return;
            }
            var fillData = new byte[size];
            for(int i = 0; i < size; i++)
            {
                fillData[i] = EraseFill;
            }
            flash.WriteBytes(offset, fillData, 0, fillData.Length);
        }

        // ---------------------------------------------------------------
        // Minimal IMemory wrapper over two MappedMemory banks.
        // ---------------------------------------------------------------

        private class DualBankView : IMemory
        {
            private readonly MappedMemory bank1;
            private readonly MappedMemory bank2;
            private readonly long bank1Size;

            public DualBankView(MappedMemory b1, MappedMemory b2)
            {
                bank1 = b1;
                bank2 = b2;
                bank1Size = b1.Size;
            }

            public long Size => bank1.Size + bank2.Size;

            public void Reset() { }

            public byte ReadByte(long offset)
            {
                if(offset < bank1Size)
                {
                    return bank1.ReadByte(offset);
                }
                return bank2.ReadByte(offset - bank1Size);
            }

            public ushort ReadWord(long offset)
            {
                var bytes = ReadBytes(offset, 2);
                return (ushort)(bytes[0] | (bytes[1] << 8));
            }

            public uint ReadDoubleWord(long offset)
            {
                var bytes = ReadBytes(offset, 4);
                return (uint)(bytes[0]
                    | (bytes[1] << 8)
                    | (bytes[2] << 16)
                    | (bytes[3] << 24));
            }

            public ulong ReadQuadWord(long offset)
            {
                var bytes = ReadBytes(offset, 8);
                ulong result = 0;
                for(var i = 0; i < bytes.Length; i++)
                {
                    result |= (ulong)bytes[i] << (8 * i);
                }
                return result;
            }

            public byte[] ReadBytes(long offset, int count)
            {
                if(offset >= bank1Size)
                {
                    return bank2.ReadBytes(offset - bank1Size, count);
                }
                if(offset + count <= bank1Size)
                {
                    return bank1.ReadBytes(offset, count);
                }
                // Straddles boundary.
                var result = new byte[count];
                int fromBank1 = (int)(bank1Size - offset);
                var part1 = bank1.ReadBytes(offset, fromBank1);
                var part2 = bank2.ReadBytes(0, count - fromBank1);
                Array.Copy(part1, 0, result, 0, fromBank1);
                Array.Copy(part2, 0, result, fromBank1, count - fromBank1);
                return result;
            }

            public void WriteByte(long offset, byte value)
            {
                if(offset < bank1Size)
                {
                    bank1.WriteByte(offset, value);
                }
                else
                {
                    bank2.WriteByte(offset - bank1Size, value);
                }
            }

            public void WriteWord(long offset, ushort value)
            {
                WriteBytes(offset, new[]
                {
                    (byte)(value & 0xFF),
                    (byte)((value >> 8) & 0xFF),
                }, 0, 2);
            }

            public void WriteDoubleWord(long offset, uint value)
            {
                WriteBytes(offset, new[]
                {
                    (byte)(value & 0xFF),
                    (byte)((value >> 8) & 0xFF),
                    (byte)((value >> 16) & 0xFF),
                    (byte)((value >> 24) & 0xFF),
                }, 0, 4);
            }

            public void WriteQuadWord(long offset, ulong value)
            {
                var bytes = new byte[8];
                for(var i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)((value >> (8 * i)) & 0xFF);
                }
                WriteBytes(offset, bytes, 0, bytes.Length);
            }

            public void WriteBytes(long offset, byte[] array)
            {
                WriteBytes(offset, array, 0, array.Length);
            }

            public void WriteBytes(long offset, byte[] array, int startingIndex, int count, IPeripheral context = null)
            {
                if(offset >= bank1Size)
                {
                    bank2.WriteBytes(offset - bank1Size, array, startingIndex, count);
                    return;
                }
                if(offset + count <= bank1Size)
                {
                    bank1.WriteBytes(offset, array, startingIndex, count);
                    return;
                }
                // Straddles boundary.
                int toBank1 = (int)(bank1Size - offset);
                bank1.WriteBytes(offset, array, startingIndex, toBank1);
                bank2.WriteBytes(0, array, startingIndex + toBank1, count - toBank1);
            }

            public void WriteBytes(long offset, byte[] array, int startingIndex, int count)
            {
                WriteBytes(offset, array, startingIndex, count, null);
            }
        }
    }
}
