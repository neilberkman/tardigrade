// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// nRF52840 NVMC (Non-Volatile Memory Controller) with word-level write tracking
// and page-erase fault injection.
// Handles CONFIG (write/erase enable), ERASEPAGE, READY.
//
// Write tracking: on each WEN(1)->REN(0) transition, diffs the MappedMemory
// against a snapshot taken when WEN was set to count individual 4-byte word
// writes.  This handles the nRFX driver writing multiple words under a single
// WEN window (e.g. 16-byte magic = 4 word writes).
//
// Erase tracking: each ERASEPAGE register write (while CONFIG=EEN) increments
// TotalPageErases.  Fault injection at the Nth erase produces a partial erase
// (first half of the page erased to 0xFF, second half untouched) to simulate
// power loss mid-erase.
//
// Performance: set DiffLookahead to int.MaxValue to always diff (required
// for accurate write counts — calibration and sweep must use the same mode).
// With a smaller DiffLookahead, diffing only starts when TotalWordWrites is
// within DiffLookahead of FaultAtWordWrite; outside that window each WEN->REN
// counts as 1 write.  Only use limited DiffLookahead when you know every
// WEN->REN writes exactly 1 word.
//
// Fault injection (writes): when TotalWordWrites reaches FaultAtWordWrite
// mid-window, FaultFlashSnapshot is built with only the words up to the fault
// applied.
//
// Fault injection (erases): when TotalPageErases reaches FaultAtPageErase,
// EraseFaultFired is set and the page is only half-erased.  The
// FaultFlashSnapshot captures flash state after the partial erase.

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
    public class NRF52NVMC : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        private readonly FaultTracker tracker = new FaultTracker();

        public NRF52NVMC(IMachine machine) : base(machine)
        {
            DefineRegisters();
        }

        public long Size => 0x1000;

        public NVMemory Nvm { get; set; }

        public long NvmBaseAddress { get; set; } = 0x00000000;

        public int PageSize { get; set; } = 4096;

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }

        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }
        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }
        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;
        public string EraseTraceToString() => tracker.EraseTraceToString();
        public void EraseTraceClear() => tracker.EraseTraceClear();

        public int DiffLookahead { get; set; } = 32;

        public IMemory Flash { get; set; }

        public long FlashBaseAddress { get; set; } = 0x00000000;

        public long FlashSize { get; set; } = 0;

        public int WriteFaultMode { get => tracker.WriteFaultMode; set => tracker.WriteFaultMode = value; }
        public uint CorruptionSeed { get => tracker.CorruptionSeed; set => tracker.CorruptionSeed = value; }
        public int EraseFaultMode { get => tracker.EraseFaultMode; set => tracker.EraseFaultMode = value; }

        public bool AnyFaultFired => tracker.AnyFaultFired;

        public byte EraseFill { get; set; } = 0xFF;

        public bool WriteTraceEnabled { get => tracker.WriteTraceEnabled; set => tracker.WriteTraceEnabled = value; }
        public int WriteTraceCount => tracker.WriteTraceCount;
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public void WriteTraceClear() => tracker.WriteTraceClear();

        // Missing interface members (NRF52 uses WEN->REN window counting).
        public bool PerWriteAccurate => false;
        public bool SkipShadowScan { get; set; }
        public void InvalidateShadow() { wenSnapshot = null; }

        private uint configValue = 0;

        private byte[] wenSnapshot;

        private static uint KeepOneToZeroTransitions(uint oldWord, uint newWord, uint keepMask)
        {
            // NOR programming transitions only 1->0.
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
                case 1:
                {
                    // Bit corruption: keep only some intended 1->0 transitions.
                    uint seed = tracker.BuildFaultSeed(off);
                    uint keepMask = FaultTracker.NextLcg(ref seed);
                    uint corrupted = KeepOneToZeroTransitions(oldWord, newWord, keepMask);
                    FaultTracker.WriteU32(snap, off, corrupted);
                    break;
                }
                case 2:
                {
                    // Silent write failure: deterministic all-FF or all-00.
                    uint silentValue = ((TotalWordWrites & 1UL) == 0UL) ? 0xFFFFFFFFU : 0x00000000U;
                    FaultTracker.WriteU32(snap, off, silentValue);
                    break;
                }
                case 3:
                {
                    // Write rejection: drop the target write (keep old word).
                    FaultTracker.WriteU32(snap, off, oldWord);
                    break;
                }
                case 4:
                {
                    // Write-disturb: target word commits, neighboring words get
                    // unintended 1->0 bit flips.
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
                case 5:
                {
                    // Wear-leveling corruption: target write commits, then
                    // deterministic age-dependent bit errors appear in page.
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
                default:
                    // Power-loss mode: faulted word stays pre-WEN.
                    break;
            }
        }

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

        private void DefineRegisters()
        {
            // READY at 0x400 — always ready (instant operations).
            Registers.Ready.Define(this, 1);

            // READYNEXT at 0x408 — always ready.
            Registers.ReadyNext.Define(this, 1);

            // CONFIG at 0x504 — write enable mode.
            // Values: 0=REN (read-only), 1=WEN (write), 2=EEN (erase).
            Registers.Config.Define(this)
                .WithValueField(0, 2, writeCallback: (_, val) =>
                {
                    var oldConfig = configValue;
                    configValue = (uint)val;

                    if(Flash == null || FlashSize <= 0)
                    {
                        // No MappedMemory — fall back to simple counting.
                        if(oldConfig == 1 && val == 0 && !AnyFaultFired)
                        {
                            if(tracker.IncrementWriteCount())
                            {
                                FaultFired = true;
                            }
                        }
                        return;
                    }

                    // Are we close enough to the fault target to need
                    // word-level precision?
                    // DiffLookahead == int.MaxValue forces always-diff mode
                    // (used during calibration to get accurate word counts).
                    bool needDiff = !AnyFaultFired
                        && (DiffLookahead == int.MaxValue
                            || (FaultAtWordWrite != ulong.MaxValue
                                && TotalWordWrites + (ulong)DiffLookahead >= FaultAtWordWrite));

                    // Entering WEN: snapshot flash if we need word-level diff.
                    if(val == 1 && oldConfig != 1)
                    {
                        if(needDiff)
                        {
                            wenSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                        }
                        else
                        {
                            wenSnapshot = null;
                        }
                    }

                    // Exiting WEN → REN.
                    if(oldConfig == 1 && val == 0)
                    {
                        if(wenSnapshot != null && !AnyFaultFired)
                        {
                            // Word-level diff mode: count each changed 4-byte word.
                            var current = Flash.ReadBytes(0, checked((int)FlashSize));
                            int len = checked((int)FlashSize);

                            for(int off = 0; off <= len - 4; off += 4)
                            {
                                bool changed = current[off]     != wenSnapshot[off]
                                            || current[off + 1] != wenSnapshot[off + 1]
                                            || current[off + 2] != wenSnapshot[off + 2]
                                            || current[off + 3] != wenSnapshot[off + 3];
                                if(!changed)
                                {
                                    continue;
                                }

                                uint val32 = (uint)(current[off]
                                    | (current[off + 1] << 8)
                                    | (current[off + 2] << 16)
                                    | (current[off + 3] << 24));

                                if(tracker.RecordWriteAndCheckFault(off, val32))
                                {
                                    FaultFired = true;
                                    LastFaultAddress = (uint)(FlashBaseAddress + off);

                                    // Build partial snapshot: pre-WEN state
                                    // with words before the fault fully applied.
                                    var snap = new byte[len];
                                    Array.Copy(wenSnapshot, snap, len);
                                    for(int j = 0; j < off; j += 4)
                                    {
                                        if(j > len - 4) break;
                                        if(current[j]     != wenSnapshot[j]
                                        || current[j + 1] != wenSnapshot[j + 1]
                                        || current[j + 2] != wenSnapshot[j + 2]
                                        || current[j + 3] != wenSnapshot[j + 3])
                                        {
                                            snap[j]     = current[j];
                                            snap[j + 1] = current[j + 1];
                                            snap[j + 2] = current[j + 2];
                                            snap[j + 3] = current[j + 3];
                                        }
                                    }

                                    // Handle faulted word according to the selected
                                    // write fault mode.
                                    ApplyWriteFaultAtOffset(snap, wenSnapshot, current, off, len);

                                    FaultFlashSnapshot = snap;
                                    break; // Stop counting further words.
                                }
                            }
                        }
                        else if(!AnyFaultFired)
                        {
                            // Fast path: assume 1 word write per WEN->REN.
                            if(tracker.IncrementWriteCount())
                            {
                                FaultFired = true;
                                LastFaultAddress = 0;
                                FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                            }
                        }

                        wenSnapshot = null;
                    }
                }, valueProviderCallback: _ => configValue, name: "WEN");

            // ERASEPAGE at 0x508 — write page address to erase.
            // Tracks TotalPageErases and supports fault injection at the
            // Nth erase.  On fault: partial erase (first half 0xFF, second
            // half untouched) simulating power loss mid-erase.
            Registers.ErasePage.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    if(configValue != 2)
                    {
                        return;
                    }

                    var pageAddr = (long)val;

                    if(AnyFaultFired)
                    {
                        // A fault (write or erase) already fired — power is
                        // dead, suppress all further operations.
                        return;
                    }

                    if(Nvm != null)
                    {
                        var offset = pageAddr - NvmBaseAddress;
                        if(offset >= 0 && offset + PageSize <= Nvm.Size)
                        {
                            if(tracker.RecordEraseAndCheckFault(offset, PageSize))
                            {
                                EraseFaultFired = true;
                                LastFaultAddress = (uint)pageAddr;
                                int halfPage = PageSize / 2;
                                if(EraseFaultMode == 1)
                                {
                                    int quarterPage = Math.Max(1, PageSize / 4);
                                    Nvm.EraseSector(offset, halfPage);
                                    long neighbor = offset + PageSize;
                                    if(neighbor + quarterPage <= Nvm.Size)
                                    {
                                        Nvm.EraseSector(neighbor, quarterPage);
                                    }
                                }
                                else
                                {
                                    Nvm.EraseSector(offset, halfPage);
                                }
                            }
                            else
                            {
                                Nvm.EraseSector(offset, PageSize);
                            }
                        }
                    }
                    else if(Flash != null)
                    {
                        var offset = pageAddr - FlashBaseAddress;
                        if(offset >= 0 && offset + PageSize <= FlashSize)
                        {
                            if(tracker.RecordEraseAndCheckFault(offset, PageSize))
                            {
                                EraseFaultFired = true;
                                LastFaultAddress = (uint)pageAddr;
                                int halfPage = PageSize / 2;
                                if(EraseFaultMode == 1)
                                {
                                    int quarterPage = Math.Max(1, PageSize / 4);
                                    EraseWithFill(Flash, offset, halfPage);
                                    long neighbor = offset + PageSize;
                                    if(neighbor + quarterPage <= FlashSize)
                                    {
                                        EraseWithFill(Flash, neighbor, quarterPage);
                                    }
                                }
                                else
                                {
                                    EraseWithFill(Flash, offset, halfPage);
                                }

                                FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                            }
                            else
                            {
                                EraseWithFill(Flash, offset, PageSize);
                            }
                        }
                    }
                }, name: "ERASEPAGE");

            // ERASEALL at 0x50C.
            Registers.EraseAll.Define(this)
                .WithValueField(0, 1, writeCallback: (_, val) =>
                {
                    if(val == 1 && configValue == 2)
                    {
                        if(Nvm != null)
                        {
                            for(long offset = 0; offset < Nvm.Size; offset += PageSize)
                            {
                                var remaining = (int)Math.Min(PageSize, Nvm.Size - offset);
                                Nvm.EraseSector(offset, remaining);
                            }
                        }
                        else if(Flash != null)
                        {
                            var fillData = new byte[PageSize];
                            for(int i = 0; i < PageSize; i++)
                            {
                                fillData[i] = EraseFill;
                            }
                            for(long offset = 0; offset < FlashSize; offset += PageSize)
                            {
                                var remaining = (int)Math.Min(PageSize, FlashSize - offset);
                                if(remaining < PageSize)
                                {
                                    fillData = new byte[remaining];
                                    for(int i = 0; i < remaining; i++)
                                    {
                                        fillData[i] = EraseFill;
                                    }
                                }
                                Flash.WriteBytes(offset, fillData, 0, fillData.Length);
                            }
                        }
                    }
                }, name: "ERASEALL");
        }

        private enum Registers
        {
            Ready = 0x400,
            ReadyNext = 0x408,
            Config = 0x504,
            ErasePage = 0x508,
            EraseAll = 0x50C,
        }
    }
}
