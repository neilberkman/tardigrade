// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// STM32F4 RCC + FLASH peripheral with word-level write tracking and fault
// injection.  API-compatible with NRF52NVMC so the generic sweep script
// (run_runtime_fault_sweep.resc) can use it via `sysbus.faultFlash`.
//
// Covers two STM32F4 register blocks in one peripheral:
//   RCC   (base + 0x000): clock control with auto-ready bits
//   FLASH (base + 0x400): flash interface registers
//
// Register at sysbus 0x40023800, size 0x420.
//
// Write tracking (shadow-based PG-transition scanning):
//   MappedMemory is registered at both 0x00000000 and 0x08000000.
//   CPU writes go directly to MappedMemory (fast execution via
//   IMappedSegment).  On each PG 1→0 transition, the controller
//   scans a shadow copy against the live flash to find the changed
//   byte(s).  Locality-based search gives O(1) in the common case
//   (sequential writes) and O(flash_size) worst case (sector boundary
//   crossing, happens ~6 times per swap).
//
// Erase tracking:
//   When FLASH_CR is written with SER+STRT, extracts the sector number from
//   SNB bits, looks up the sector geometry, and erases that region in the
//   backing MappedMemory.  Increments TotalPageErases.
//
// Fault injection:
//   FaultAtWordWrite / FaultAtPageErase arm write/erase faults.
//   Write fault modes: power_loss, bit_corruption, silent_write_failure,
//   write_rejection, write_disturb, wear_leveling_corruption.
//   Erase fault modes: interrupted_erase, multi_sector_atomicity.

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
    public class STM32F4FlashController : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        private readonly FaultTracker tracker = new FaultTracker();

        public STM32F4FlashController(IMachine machine) : base(machine)
        {
            DefineRegisters();
        }

        // Peripheral spans RCC (0x000) through FLASH (0x410+).
        public long Size => 0x420;

        // --- MappedMemory references (NRF52NVMC-compatible) ---

        public IMemory Flash { get; set; }
        public long FlashBaseAddress { get; set; } = 0x00000000;
        public long FlashSize { get; set; } = 0;
        public int PageSize { get; set; } = 0x20000;
        public byte EraseFill { get; set; } = 0xFF;

        // --- Write tracking ---

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }

        // Kept for backward compatibility with .resc scripts (no-op).
        public int DiffLookahead { get; set; } = 32;

        public bool PerWriteAccurate => true;

        public bool SkipShadowScan { get; set; }

        // --- PG state ---

        public bool PgActive { get; private set; }

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

        public void InvalidateShadow()
        {
            flashShadow = null;
            Array.Clear(localityCache, 0, LocalityCacheSize);
            localityCacheIdx = 0;
        }

        // ---------------------------------------------------------------
        // Direct write interception (called by STM32F4FlashInterceptor).
        // O(1) per write — no shadow scan needed.
        // Returns true if write should proceed, false if fault suppressed it.
        // ---------------------------------------------------------------

        public bool OnDirectFlashWrite(long offset, uint value)
        {
            return HandleDirectWrite(offset, 4, value);
        }

        public bool OnDirectFlashWriteHalf(long offset, ushort value)
        {
            return HandleDirectWrite(offset, 2, value);
        }

        public bool OnDirectFlashWriteByte(long offset, byte value)
        {
            return HandleDirectWrite(offset, 1, value);
        }

        private bool HandleDirectWrite(long offset, int width, uint value)
        {
            hadDirectWrite = true;

            if(AnyFaultFired || Flash == null || FlashSize == 0)
            {
                return true;
            }

            // Word-align for trace and fault tracking.
            int aligned = (int)(offset & ~3L);

            // Compute the full word value for trace recording.
            var pre = Flash.ReadBytes(aligned, 4);
            uint wordValue = FaultTracker.ReadU32(pre, 0);
            if(width == 4)
            {
                wordValue = value;
            }
            else if(width == 2)
            {
                int shift = (int)((offset & 2) * 8);
                wordValue = (wordValue & ~(0xFFFFU << shift)) | ((value & 0xFFFF) << shift);
            }
            else
            {
                int shift = (int)((offset & 3) * 8);
                wordValue = (wordValue & ~(0xFFU << shift)) | ((value & 0xFF) << shift);
            }

            if(tracker.RecordWriteAndCheckFault(aligned, wordValue))
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + offset);

                int flashLen = checked((int)FlashSize);
                FaultFlashSnapshot = Flash.ReadBytes(0, flashLen);

                // Apply fault in snapshot and flash.
                if(WriteFaultMode == 0)
                {
                    // Power-loss: suppress the write entirely.
                    return false;
                }
                else if(WriteFaultMode == 1)
                {
                    // Bit corruption: partial write (NOR flash physics).
                    uint seed = tracker.BuildFaultSeed((int)offset);
                    for(int i = 0; i < width; i++)
                    {
                        int byteOff = (int)offset + i;
                        byte oldByte = Flash.ReadBytes(byteOff, 1)[0];
                        byte newByte = (byte)((value >> (i * 8)) & 0xFF);
                        byte keepMask = (byte)(FaultTracker.NextLcg(ref seed) & 0xFF);
                        byte bitsToFlip = (byte)(oldByte & ~newByte);
                        byte actuallyFlipped = (byte)(bitsToFlip & keepMask);
                        byte corrupted = (byte)(oldByte & ~actuallyFlipped);
                        Flash.WriteByte(byteOff, corrupted);
                        FaultFlashSnapshot[byteOff] = corrupted;
                    }
                    return false;
                }

                return false;
            }

            return true;
        }

        // --- Erase trace ---

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;

        public string EraseTraceToString() => tracker.EraseTraceToString();

        public void EraseTraceClear() => tracker.EraseTraceClear();

        // ---------------------------------------------------------------
        // Internals.
        // ---------------------------------------------------------------

        // FLASH CR state.
        private uint crValue = LOCK_BIT;
        private bool locked = true;
        private int keySequence = 0;

        // RCC register storage.
        private uint rccCr = RCC_CR_RESET;
        private uint rccPllCfgr;
        private uint rccCfgr;

        // Generic register storage for unhandled offsets.
        private readonly Dictionary<long, uint> genericStorage = new Dictionary<long, uint>();

        // Shadow copy for locality-based write detection.
        private byte[] flashShadow;

        // Multi-locality tracking: circular buffer of recent write offsets.
        // Handles swap-move which alternates writes between 2-3 distant regions.
        private const int LocalityCacheSize = 4;
        private readonly int[] localityCache = new int[LocalityCacheSize];
        private int localityCacheIdx;

        // Direct write tracking: set when interceptor handles a write during PG.
        private bool hadDirectWrite;

        // Pre-fault snapshot: captured on PG 0→1 when next write will be faulted.
        // Used in SkipShadowScan mode to find the changed byte at fault time.
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

        // RCC_CR: always-set ready bits (HSIRDY | HSERDY | PLLRDY).
        private const uint RCC_HSIRDY  = 1U << 1;
        private const uint RCC_HSERDY  = 1U << 17;
        private const uint RCC_PLLRDY  = 1U << 25;
        private const uint RCC_CR_READY_BITS = RCC_HSIRDY | RCC_HSERDY | RCC_PLLRDY;
        private const uint RCC_CR_RESET = RCC_CR_READY_BITS;

        // RCC_BDCR (offset 0x70): LSEON bit 0 → LSERDY bit 1.
        // RCC_CSR  (offset 0x74): LSION bit 0 → LSIRDY bit 1.
        private const uint RCC_LSEON  = 1U << 0;
        private const uint RCC_LSERDY = 1U << 1;
        private const uint RCC_LSION  = 1U << 0;
        private const uint RCC_LSIRDY = 1U << 1;

        // STM32F407 sector geometry (offset from flash base, size).
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
                // --- RCC registers ---
                case 0x000: return rccCr | RCC_CR_READY_BITS;
                case 0x004: return rccPllCfgr;
                case 0x008:
                    uint sw = rccCfgr & 0x3U;
                    return (rccCfgr & ~0xCU) | (sw << 2);
                case 0x070:
                {
                    uint bdcr;
                    genericStorage.TryGetValue(offset, out bdcr);
                    if((bdcr & RCC_LSEON) != 0)
                        bdcr |= RCC_LSERDY;
                    return bdcr;
                }
                case 0x074:
                {
                    uint csr;
                    genericStorage.TryGetValue(offset, out csr);
                    if((csr & RCC_LSION) != 0)
                        csr |= RCC_LSIRDY;
                    return csr;
                }

                // --- FLASH registers (base + 0x400) ---
                case 0x400:
                    uint acrVal;
                    genericStorage.TryGetValue(offset, out acrVal);
                    return acrVal;
                case 0x404: return 0;         // KEYR: write-only
                case 0x40C: return 0;         // SR: BSY=0, no errors
                case 0x410: return crValue;   // CR

                default:
                    uint val;
                    genericStorage.TryGetValue(offset, out val);
                    return val;
            }
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                // --- RCC registers ---
                case 0x000:
                    rccCr = value;
                    break;
                case 0x004:
                    rccPllCfgr = value;
                    break;
                case 0x008:
                    rccCfgr = value;
                    break;

                // --- FLASH registers ---
                case 0x400: // ACR
                    genericStorage[offset] = value;
                    break;
                case 0x404: // KEYR — unlock sequence
                    HandleKeyr(value);
                    break;
                case 0x40C: // SR — writes clear error flags (ignored)
                    break;
                case 0x410: // CR
                    HandleCr(value);
                    break;

                default:
                    genericStorage[offset] = value;
                    break;
            }
        }

        public override void Reset()
        {
            base.Reset();
            crValue = LOCK_BIT;
            locked = true;
            keySequence = 0;
            PgActive = false;
            rccCr = RCC_CR_RESET;
            rccPllCfgr = 0;
            rccCfgr = 0;
            genericStorage.Clear();
            flashShadow = null;
            preFaultSnapshot = null;
            Array.Clear(localityCache, 0, LocalityCacheSize);
            localityCacheIdx = 0;
        }

        // ---------------------------------------------------------------
        // FLASH register handlers.
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

        private void HandleCr(uint newCr)
        {
            // Setting LOCK always works.
            if((newCr & LOCK_BIT) != 0)
            {
                locked = true;
                crValue |= LOCK_BIT;
                if(PgActive)
                {
                    PgActive = false;
                    HandlePgDeactivation();
                    hadDirectWrite = false;
                }
                return;
            }

            if(locked)
            {
                return;
            }

            bool wasPgActive = PgActive;
            crValue = newCr;
            PgActive = (newCr & PG_BIT) != 0;

            // PG 0→1: entering programming mode.
            if(!wasPgActive && PgActive)
            {
                hadDirectWrite = false;

                // In SkipShadowScan mode, capture flash state before the
                // faulted write so we can diff to find the changed byte.
                if(SkipShadowScan && !AnyFaultFired
                   && Flash != null && FlashSize > 0
                   && TotalWordWrites + 1 == FaultAtWordWrite)
                {
                    preFaultSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                }
            }

            // PG 1→0: a write just completed — scan for it.
            if(wasPgActive && !PgActive)
            {
                HandlePgDeactivation();
            }

            // Detect SER + STRT for erase.
            if((newCr & SER_BIT) != 0 && (newCr & STRT_BIT) != 0)
            {
                int sectorNum = (int)((newCr & SNB_MASK) >> (int)SNB_SHIFT);
                HandleErase(sectorNum);
                crValue &= ~STRT_BIT;
            }
        }

        // ---------------------------------------------------------------
        // PG-transition write detection.
        // ---------------------------------------------------------------

        private void HandlePgDeactivation()
        {
            if(AnyFaultFired || Flash == null || FlashSize == 0)
            {
                return;
            }

            // If the interceptor already tracked this write directly, skip scan.
            if(hadDirectWrite)
            {
                hadDirectWrite = false;
                return;
            }

            // Fast path: just count PG transitions without scanning flash.
            // Each PG deactivation = exactly 1 word write on STM32F4.
            if(SkipShadowScan)
            {
                if(tracker.IncrementWriteCount())
                {
                    FaultFired = true;
                    HandleSkipScanFault();
                }

                return;
            }

            // Lazy-init shadow on first PG use.
            int flashLen = checked((int)FlashSize);
            if(flashShadow == null)
            {
                flashShadow = Flash.ReadBytes(0, flashLen);
            }

            // Find the changed byte using locality-based search.
            int changedOffset = FindChangedByte(flashLen);
            if(changedOffset < 0)
            {
                return;
            }

            byte newValue = Flash.ReadBytes(changedOffset, 1)[0];
            byte oldValue = flashShadow[changedOffset];

            // Promote to word-aligned for trace recording.
            int aligned = changedOffset & ~3;
            var wordBytes = Flash.ReadBytes(aligned, 4);
            uint wordValue = FaultTracker.ReadU32(wordBytes, 0);

            // Update shadow to reflect the write.
            flashShadow[changedOffset] = newValue;

            if(tracker.RecordWriteAndCheckFault(aligned, wordValue))
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + changedOffset);

                // Snapshot current flash (post-write).
                FaultFlashSnapshot = Flash.ReadBytes(0, flashLen);

                // Apply the fault.
                ApplyWriteFault(changedOffset, oldValue, newValue);
            }
        }

        // Fault handling for SkipShadowScan mode.  Extracted to its own
        // method to avoid C# local-variable shadowing errors.
        private void HandleSkipScanFault()
        {
            int len = checked((int)FlashSize);

            if(preFaultSnapshot != null)
            {
                byte[] preSnap = preFaultSnapshot;
                preFaultSnapshot = null;
                flashShadow = preSnap;
                int off = FindChangedByte(len);

                if(off >= 0)
                {
                    byte old = preSnap[off];
                    byte cur = Flash.ReadBytes(off, 1)[0];
                    LastFaultAddress = (uint)(FlashBaseAddress + off);
                    FaultFlashSnapshot = Flash.ReadBytes(0, len);
                    ApplyWriteFault(off, old, cur);
                    flashShadow = null;
                }
                else
                {
                    flashShadow = null;
                    LastFaultAddress = 0;
                    FaultFlashSnapshot = Flash.ReadBytes(0, len);
                }
            }
            else
            {
                LastFaultAddress = 0;
                FaultFlashSnapshot = Flash.ReadBytes(0, len);
            }
        }

        private int FindChangedByte(int flashLen)
        {
            const int window = 128;

            // Check all cached locality windows first.
            for(int c = 0; c < LocalityCacheSize; c++)
            {
                int start = Math.Max(0, Math.Min(localityCache[c], flashLen - 1));
                int lo = Math.Max(0, start - 4);
                int hi = Math.Min(flashLen, start + window);
                int chunkLen = hi - lo;
                if(chunkLen <= 0) continue;

                var chunk = Flash.ReadBytes(lo, chunkLen);
                for(int i = 0; i < chunkLen; i++)
                {
                    if(chunk[i] != flashShadow[lo + i])
                    {
                        int found = lo + i;
                        localityCache[localityCacheIdx] = found + 1;
                        localityCacheIdx = (localityCacheIdx + 1) % LocalityCacheSize;
                        return found;
                    }
                }
            }

            // Fall back to scanning the full flash in chunks.
            int chunkSize = 1024;
            for(int baseOff = 0; baseOff < flashLen; baseOff += chunkSize)
            {
                int len = Math.Min(chunkSize, flashLen - baseOff);
                var data = Flash.ReadBytes(baseOff, len);
                for(int i = 0; i < len; i++)
                {
                    if(data[i] != flashShadow[baseOff + i])
                    {
                        int found = baseOff + i;
                        localityCache[localityCacheIdx] = found + 1;
                        localityCacheIdx = (localityCacheIdx + 1) % LocalityCacheSize;
                        return found;
                    }
                }
            }

            return -1;
        }

        // ---------------------------------------------------------------
        // Write fault application (post-write, must undo or modify).
        // ---------------------------------------------------------------

        private void ApplyWriteFault(int offset, byte oldValue, byte newValue)
        {
            switch(WriteFaultMode)
            {
                case 0: // Power-loss: undo the write.
                {
                    Flash.WriteByte(offset, oldValue);
                    flashShadow[offset] = oldValue;
                    FaultFlashSnapshot[offset] = oldValue;
                    break;
                }
                case 1: // Bit corruption: partial write.
                {
                    uint seed = tracker.BuildFaultSeed(offset);
                    byte keepMask = (byte)(FaultTracker.NextLcg(ref seed) & 0xFF);
                    byte bitsToFlip = (byte)(oldValue & ~newValue);
                    byte actuallyFlipped = (byte)(bitsToFlip & keepMask);
                    byte corrupted = (byte)(oldValue & ~actuallyFlipped);
                    Flash.WriteByte(offset, corrupted);
                    flashShadow[offset] = corrupted;
                    FaultFlashSnapshot[offset] = corrupted;
                    break;
                }
                case 2: // Silent write failure.
                {
                    byte silentVal = ((TotalWordWrites & 1UL) == 0UL) ? (byte)0xFF : (byte)0x00;
                    Flash.WriteByte(offset, silentVal);
                    flashShadow[offset] = silentVal;
                    FaultFlashSnapshot[offset] = silentVal;
                    break;
                }
                case 3: // Write rejection: undo the write.
                {
                    Flash.WriteByte(offset, oldValue);
                    flashShadow[offset] = oldValue;
                    FaultFlashSnapshot[offset] = oldValue;
                    break;
                }
                case 4: // Write-disturb: keep write, corrupt neighbors.
                {
                    uint seed = tracker.BuildFaultSeed(offset);
                    foreach(int nOff in new[] { offset - 1, offset + 1 })
                    {
                        if(nOff < 0 || nOff >= FaultFlashSnapshot.Length)
                        {
                            continue;
                        }
                        byte nb = FaultFlashSnapshot[nOff];
                        byte disturbMask = (byte)(FaultTracker.NextLcg(ref seed) & 0x11);
                        byte disturbed = (byte)(nb & ~disturbMask);
                        Flash.WriteByte(nOff, disturbed);
                        flashShadow[nOff] = disturbed;
                        FaultFlashSnapshot[nOff] = disturbed;
                    }
                    break;
                }
                default: // Power-loss fallback.
                {
                    Flash.WriteByte(offset, oldValue);
                    flashShadow[offset] = oldValue;
                    FaultFlashSnapshot[offset] = oldValue;
                    break;
                }
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
                    EraseWithFill(Flash, offset, halfSize);
                }

                FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
            }
            else
            {
                EraseWithFill(Flash, offset, size);
            }

            // Update shadow after erase.
            if(flashShadow != null)
            {
                int eraseLen = (TotalPageErases == FaultAtPageErase) ? size / 2 : size;
                for(int i = 0; i < eraseLen && offset + i < flashShadow.Length; i++)
                {
                    flashShadow[offset + i] = EraseFill;
                }
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
        // Register definitions.
        // ---------------------------------------------------------------

        private void DefineRegisters()
        {
        }
    }
}
