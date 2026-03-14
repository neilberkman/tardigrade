// SPDX-License-Identifier: Apache-2.0
//
// Minimal STM32F4 FLASH-only peripheral for fast emulation.
//
// Registered at 0x40023C00 (STM32F4 FLASH register base), size 0x20.
// Counts writes on PG 1->0 transitions (per-word accurate).
// No shadow scanning — each PG deactivation = exactly 1 word write.
//
// When WriteTraceEnabled or fault snapshot is needed, captures flash
// on PG 0->1 and diffs on PG 1->0 to find the changed address.
// Otherwise just increments the counter.
//
// Non-uniform sector erase geometry for STM32F407/F4xx:
//   Sectors 0-3:  16 KB each
//   Sector  4:    64 KB
//   Sectors 5-11: 128 KB each

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
    public class STM32F4FastFlash : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        private readonly FaultTracker tracker = new FaultTracker();

        public STM32F4FastFlash(IMachine machine) : base(machine)
        {
        }

        public long Size => 0x20;

        // --- MappedMemory references ---

        public IMemory Flash { get; set; }
        public long FlashBaseAddress { get; set; } = 0x08000000;
        public long FlashSize { get; set; } = 0x100000;
        public int PageSize { get; set; } = 0x20000;
        public byte EraseFill { get; set; } = 0xFF;

        // --- Write tracking ---

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }

        public bool PerWriteAccurate => true;

        // Stored but always effectively true — no shadow scanning.
        public bool SkipShadowScan { get; set; } = true;
        // Stored, no-op.
        public bool PassthroughMode { get; set; }
        // Stored but ignored — always skip scan.
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
        // STM32F4FastFlash uses MappedMemory for CPU reads (fast path),
        // so read-time interception is not possible.

        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        // --- FLASH register state ---

        private uint acrValue;
        private uint crValue = LOCK_BIT;
        private bool locked = true;
        private int keySequence;
        private bool pgActive;

        // Pre-fault snapshot: captured on PG 0->1 when the next write will
        // trigger a fault OR when write trace is enabled.
        private byte[] preFaultSnapshot;

        // FLASH_CR bit definitions.
        private const uint PG_BIT    = 1U << 0;
        private const uint SER_BIT   = 1U << 1;
        private const uint SNB_SHIFT = 3;
        private const uint SNB_MASK  = 0xFU << 3;
        private const uint STRT_BIT  = 1U << 16;
        private const uint LOCK_BIT  = 1U << 31;

        // FLASH unlock keys.
        private const uint KEY1 = 0x45670123U;
        private const uint KEY2 = 0xCDEF89ABU;

        // STM32F4 sector geometry (offset from flash base, size).
        private static readonly (long offset, int size)[] Sectors = new[]
        {
            (0x00000L, 0x04000),   // Sector  0: 16 KB
            (0x04000L, 0x04000),   // Sector  1: 16 KB
            (0x08000L, 0x04000),   // Sector  2: 16 KB
            (0x0C000L, 0x04000),   // Sector  3: 16 KB
            (0x10000L, 0x10000),   // Sector  4: 64 KB
            (0x20000L, 0x20000),   // Sector  5: 128 KB
            (0x40000L, 0x20000),   // Sector  6: 128 KB
            (0x60000L, 0x20000),   // Sector  7: 128 KB
            (0x80000L, 0x20000),   // Sector  8: 128 KB
            (0xA0000L, 0x20000),   // Sector  9: 128 KB
            (0xC0000L, 0x20000),   // Sector 10: 128 KB
            (0xE0000L, 0x20000),   // Sector 11: 128 KB
        };

        // ---------------------------------------------------------------
        // Read / Write overrides.
        // ---------------------------------------------------------------

        public override uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case 0x00: return acrValue;      // ACR
                case 0x04: return 0;             // KEYR: write-only
                case 0x08: return 0;             // OPTKEYR: ignored
                case 0x0C: return 0;             // SR: BSY=0, no errors
                case 0x10: return crValue;       // CR
                case 0x14: return 0;             // OPTCR: ignored
                default:   return 0;
            }
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case 0x00: // ACR
                    acrValue = value;
                    break;
                case 0x04: // KEYR
                    HandleKeyr(value);
                    break;
                case 0x08: // OPTKEYR: ignored
                    break;
                case 0x0C: // SR: writes clear flags (ignored)
                    break;
                case 0x10: // CR
                    HandleCr(value);
                    break;
                case 0x14: // OPTCR: ignored
                    break;
            }
        }

        public override void Reset()
        {
            base.Reset();
            tracker.Reset();
            acrValue = 0;
            crValue = LOCK_BIT;
            locked = true;
            keySequence = 0;
            pgActive = false;
            preFaultSnapshot = null;
        }

        // ---------------------------------------------------------------
        // FLASH_KEYR unlock sequence.
        // ---------------------------------------------------------------

        private void HandleKeyr(uint key)
        {
            if(keySequence == 0 && key == KEY1)
            {
                keySequence = 1;
            }
            else if(keySequence == 1 && key == KEY2)
            {
                locked = false;
                crValue &= ~LOCK_BIT;
                keySequence = 0;
            }
            else
            {
                keySequence = 0;
            }
        }

        // ---------------------------------------------------------------
        // FLASH_CR handler.
        // ---------------------------------------------------------------

        private void HandleCr(uint newCr)
        {
            // Setting LOCK always works.
            if((newCr & LOCK_BIT) != 0)
            {
                locked = true;
                crValue |= LOCK_BIT;
                if(pgActive)
                {
                    pgActive = false;
                    HandlePgDeactivation();
                }
                return;
            }

            if(locked)
            {
                return;
            }

            bool wasPgActive = pgActive;
            crValue = newCr;
            pgActive = (newCr & PG_BIT) != 0;

            // PG 0->1: entering programming mode.
            if(!wasPgActive && pgActive)
            {
                HandlePgActivation();
            }

            // PG 1->0: a write just completed.
            if(wasPgActive && !pgActive)
            {
                HandlePgDeactivation();
            }

            // SER + STRT: sector erase.
            if((newCr & SER_BIT) != 0 && (newCr & STRT_BIT) != 0)
            {
                int sectorNum = (int)((newCr & SNB_MASK) >> (int)SNB_SHIFT);
                HandleErase(sectorNum);
                crValue &= ~STRT_BIT;
            }
        }

        // ---------------------------------------------------------------
        // PG activation: snapshot if needed for trace or fault.
        // ---------------------------------------------------------------

        private void HandlePgActivation()
        {
            preFaultSnapshot = null;

            if(AnyFaultFired || Flash == null || FlashSize <= 0)
            {
                return;
            }

            // Need snapshot if: (a) next write is the fault target, or
            // (b) write trace is enabled (need to find changed address).
            bool needSnapshot = WriteTraceEnabled
                || TotalWordWrites + 1 == FaultAtWordWrite;

            if(needSnapshot)
            {
                preFaultSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
            }
        }

        // ---------------------------------------------------------------
        // PG deactivation: count write, handle trace/fault.
        // ---------------------------------------------------------------

        private void HandlePgDeactivation()
        {
            if(AnyFaultFired || Flash == null || FlashSize <= 0)
            {
                return;
            }

            if(preFaultSnapshot != null)
            {
                // We have a pre-write snapshot — diff to find the changed word.
                int flashLen = checked((int)FlashSize);
                byte[] current = Flash.ReadBytes(0, flashLen);
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

                        // Build fault snapshot from the pre-write state.
                        var snap = new byte[flashLen];
                        Array.Copy(preFaultSnapshot, snap, flashLen);

                        ApplyWriteFaultAtOffset(snap, preFaultSnapshot, current, changedOffset, flashLen);

                        FaultFlashSnapshot = snap;
                    }
                }
                else
                {
                    // No change found — still count the PG transition.
                    if(tracker.IncrementWriteCount())
                    {
                        FaultFired = true;
                        LastFaultAddress = 0;
                        FaultFlashSnapshot = Flash.ReadBytes(0, flashLen);
                    }
                }

                preFaultSnapshot = null;
            }
            else
            {
                // Fast path: no snapshot, just count.
                if(tracker.IncrementWriteCount())
                {
                    FaultFired = true;
                    LastFaultAddress = 0;
                    FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
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

        private void HandleErase(int sectorNum)
        {
            if(AnyFaultFired)
            {
                return;
            }

            if(sectorNum < 0 || sectorNum >= Sectors.Length)
            {
                return;
            }

            var (offset, size) = Sectors[sectorNum];
            if(Flash == null || offset + size > FlashSize)
            {
                return;
            }

            if(tracker.RecordEraseAndCheckFault(offset, size))
            {
                EraseFaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + offset);
                int halfSize = size / 2;

                if(EraseFaultMode == 1)
                {
                    // Multi-sector atomicity: partial target + neighbor bleed.
                    int quarterSize = Math.Max(1, size / 4);
                    EraseWithFill(Flash, offset, halfSize);
                    if(sectorNum + 1 < Sectors.Length)
                    {
                        var (nOffset, nSize) = Sectors[sectorNum + 1];
                        int neighborChunk = Math.Min(quarterSize, nSize);
                        if(nOffset + neighborChunk <= FlashSize)
                        {
                            EraseWithFill(Flash, nOffset, neighborChunk);
                        }
                    }
                }
                else
                {
                    // Interrupted erase: first half erased, second half untouched.
                    EraseWithFill(Flash, offset, halfSize);
                }

                FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
            }
            else
            {
                EraseWithFill(Flash, offset, size);
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
    }
}
