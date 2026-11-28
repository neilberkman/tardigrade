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
using System.Linq;
using System.Text;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging.Profiling;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Memory;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class NRF52NVMC : BasicDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        private FaultTracker tracker = new FaultTracker();

        public FaultTracker SharedTracker
        {
            get => tracker;
            set
            {
                if(value != null)
                {
                    tracker = value;
                    if(tracker.Machine == null)
                    {
                        tracker.Bind(machine, this);
                    }
                }
            }
        }

        public NRF52NVMC(IMachine machine) : base(machine)
        {
            tracker.Bind(machine, this);
            operation = new FlashOperationTimer(this);
            DefineRegisters();
        }

        public long Size => 0x1000;

        public FlashTiming OperationTiming
        {
            get => timing;
            set
            {
                if(value == timing)
                {
                    return;
                }
                if(operation.Busy || configValue != 0)
                {
                    throw new InvalidOperationException("Select NVMC timing in read mode while ready");
                }
                timing = value;
                programBuffer.Invalidate();
                UpdateMemoryAccessHook(false);
            }
        }

        private FlashTiming timing;
        private readonly FlashOperationTimer operation;
        private readonly FlashProgramBuffer programBuffer = new FlashProgramBuffer();
        private Action bufferedProgram;
        private bool eraseBusy;

        private void SubmitProgram(long offset, int width, Action write)
        {
            if(width != 4 || (offset & 3) != 0)
            {
                throw new ArgumentException("NVMC programming requires an aligned 32-bit word");
            }
            if(operation.Busy)
            {
                if(bufferedProgram == null)
                {
                    bufferedProgram = () => StartProgram(write);
                }
                return;
            }
            StartProgram(write);
        }

        private void StartProgram(Action write)
        {
            operation.Start(41, () =>
            {
                write();
                RunNextBufferedProgram();
            });
        }

        private void RunNextBufferedProgram()
        {
            var next = bufferedProgram;
            bufferedProgram = null;
            if(next != null)
            {
                next();
            }
        }

        private void SubmitTimedFlashProgram(long rel, int width, ulong value)
        {
            if(width != 4 || (rel & 3L) != 0)
            {
                throw new ArgumentException("NVMC programming requires an aligned 32-bit word");
            }
            if(operation.Busy)
            {
                if(bufferedProgram == null)
                {
                    bufferedProgram = () => StartTimedFlashProgram(rel, width, value);
                }
                return;
            }
            StartTimedFlashProgram(rel, width, value);
        }

        private void StartTimedFlashProgram(long rel, int width, ulong value)
        {
            if(AnyFaultFired && FaultRequiresImmediateStop)
            {
                return;
            }
            programBuffer.Prepare(Flash, FlashSize);
            int off = checked((int)rel);
            uint oldWord = programBuffer.ReadU32(off);
            uint newWord = (uint)value;
            bool directOperationTrace = OperationTraceFastMode
                && WriteTraceEnabled
                && FaultAtWordWrite == ulong.MaxValue
                && WriteFaultMode == 0;
            bool needDiff = !PassthroughMode && !AnyFaultFired
                && ((WriteTraceEnabled && !directOperationTrace)
                    || DiffLookahead == int.MaxValue
                    || (FaultAtWordWrite != ulong.MaxValue
                        && TotalWordWrites + (ulong)DiffLookahead >= FaultAtWordWrite));
            bool wantSnap = needDiff || (!PassthroughMode && WriteFaultMode != 0 && !AnyFaultFired);

            if(PassthroughMode)
            {
                if(!AnyFaultFired && newWord != oldWord)
                {
                    tracker.IncrementWriteCount();
                }
            }
            else if(directOperationTrace)
            {
                if(newWord != oldWord)
                {
                    tracker.RecordWriteAndCheckFault(off, newWord, 4);
                }
            }
            else if(wantSnap)
            {
                if(newWord != oldWord && tracker.RecordWriteAndCheckFault(off, newWord, 4))
                {
                    FaultFired = true;
                    LastFaultAddress = (uint)(FlashBaseAddress + off);
                    int len = checked((int)FlashSize);
                    var preBytes = Flash.ReadBytes(0, len);
                    var postBytes = (byte[])preBytes.Clone();
                    FaultTracker.WriteU32(postBytes, off, newWord);
                    if(WriteFaultMode == 0)
                    {
                        var snap = (byte[])preBytes.Clone();
                        ApplyTornProgramAtOffset(snap, preBytes, postBytes, off, len);
                        Flash.WriteBytes(0, snap, 0, len);
                        programBuffer.RefreshIfPrepared(Flash);
                        FaultFlashSnapshot = snap;
                        bufferedProgram = null;
                        return;
                    }
                    var faultedCurrent = (byte[])postBytes.Clone();
                    ApplyWriteFaultAtOffset(faultedCurrent, preBytes, postBytes, off, len);
                    FaultFlashSnapshot = faultedCurrent;
                    operation.Start(41, () =>
                    {
                        Flash.WriteBytes(0, faultedCurrent, 0, len);
                        programBuffer.RefreshIfPrepared(Flash);
                        RunNextBufferedProgram();
                    });
                    return;
                }
            }
            else if(!AnyFaultFired)
            {
                if(newWord != oldWord && tracker.IncrementWriteCount())
                {
                    FaultFired = true;
                    LastFaultAddress = (uint)(FlashBaseAddress + off);
                    FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                    bufferedProgram = null;
                    return;
                }
            }

            var data = FlashProgramBuffer.StoreBytes(value, width);
            operation.Start(41, () =>
            {
                programBuffer.Program(Flash, off, data);
                if(operationTraceShadow != null && off >= 0 && off <= operationTraceShadow.Length - 4)
                {
                    Array.Copy(data, 0, operationTraceShadow, off, 4);
                }
                RunNextBufferedProgram();
            });
        }

        public override void Reset()
        {
            base.Reset();
            tracker.Reset();
            operation.Reset();
            eraseBusy = false;
            programBuffer.Invalidate();
            bufferedProgram = null;
            if(Nvm != null)
            {
                Nvm.ProgramScheduler = null;
            }
            configValue = 0;
            wenSnapshot = null;
            operationTraceShadow = null;
            wenWriteOffsets.Clear();
            wenWritePcs.Clear();
            wenWriteContexts.Clear();
            OperationTraceFastMode = false;
            memoryAccessHookInstalled = false;
            UpdateMemoryAccessHook(false);
        }

        public NVMemory Nvm { get; set; }

        public long NvmBaseAddress { get; set; } = 0x00000000;

        public int PageSize { get; set; } = 4096;

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public ulong LastFaultPC { get => tracker.LastFaultPC; set => tracker.LastFaultPC = value; }
        public string LastFaultCallContext { get => tracker.LastFaultCallContext; set => tracker.LastFaultCallContext = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }
        public bool DriverErrorFired { get => tracker.DriverErrorFired; set => tracker.DriverErrorFired = value; }
        public bool DriverErrorRequiresReturnHook => true;

        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }
        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }
        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;
        public string EraseTraceToString() => tracker.EraseTraceToString();
        public string EraseCallContextToString() => tracker.EraseCallContextToString();
        public void EraseTraceClear() => tracker.EraseTraceClear();

        public int DiffLookahead { get; set; } = 32;

        public IMemory Flash { get; set; }

        public long FlashBaseAddress { get; set; } = 0x00000000;

        public long FlashSize { get; set; } = 0;

        public int WriteFaultMode { get => tracker.WriteFaultMode; set => tracker.WriteFaultMode = value; }
        public uint CorruptionSeed { get => tracker.CorruptionSeed; set => tracker.CorruptionSeed = value; }
        public int EraseFaultMode { get => tracker.EraseFaultMode; set => tracker.EraseFaultMode = value; }
        public string MramTornWordMode { get => tracker.MramTornWordMode; set => tracker.MramTornWordMode = value; }
        public uint MramTornWordSeed { get => tracker.MramTornWordSeed; set => tracker.MramTornWordSeed = value; }
        public string TornWordMode { get => tracker.TornWordMode; set => tracker.TornWordMode = value; }
        public uint TornWordSeed { get => tracker.TornWordSeed; set => tracker.TornWordSeed = value; }
        public bool PreserveCountersAcrossReset { get => tracker.PreserveCountersAcrossReset; set => tracker.PreserveCountersAcrossReset = value; }

        public bool AnyFaultFired => tracker.AnyFaultFired;
        public bool FaultRequiresImmediateStop => tracker.FaultRequiresImmediateStop;

        public byte EraseFill { get; set; } = 0xFF;

        public bool WriteTraceEnabled { get => tracker.WriteTraceEnabled; set => tracker.WriteTraceEnabled = value; }
        public int WriteTraceCount => tracker.WriteTraceCount;
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public RecoveryTraceTimes TraceTimes => tracker.TraceTimes;
        public string WriteCallContextToString() => tracker.WriteCallContextToString();
        public void WriteTraceClear() => tracker.WriteTraceClear();
        // WEN diffing reconstructs aligned four-byte word writes, so every
        // trace row has an explicit, replay-safe width.
        public bool WriteTraceWidthExplicit => true;

        // CPU memory-write hooks record the exact chronological word order
        // within each WEN window, with address-scan fallback for monitor writes.
        public bool PerWriteAccurate => true;
        private bool skipShadowScan;
        public bool SkipShadowScan
        {
            get => skipShadowScan;
            set
            {
                skipShadowScan = value;
                wenSnapshot = null;
            }
        }
        // Recovery boots already avoid the expensive full diff path via
        // SkipShadowScan, so this stays as a defined no-op.
        public bool PassthroughMode { get; set; }
        // State-search recovery boots arm no write fault and need only the
        // chronological operation trace. In that narrow mode, the CPU memory
        // hook can record each aligned word directly instead of copying and
        // comparing the entire flash at every WEN window.
        private bool operationTraceFastMode;
        private byte[] operationTraceShadow;
        public bool OperationTraceFastMode
        {
            get => operationTraceFastMode;
            set
            {
                operationTraceFastMode = value;
                operationTraceShadow = value && Flash != null && FlashSize > 0
                    ? Flash.ReadBytes(0, checked((int)FlashSize))
                    : null;
            }
        }
        public void InvalidateShadow()
        {
            wenSnapshot = null;
            programBuffer.RefreshIfPrepared(Flash);
        }

        // Read-fault injection stubs.  NRF52NVMC uses MappedMemory for CPU
        // reads (fast path), so read-time interception is not possible.
        // These properties exist to satisfy ITardigradeFaultInjectable; the
        // sweep engine uses them for state tracking but the fault is applied
        // via direct MappedMemory corruption (see run_runtime_fault_sweep.resc).
        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        private uint configValue = 0;

        private byte[] wenSnapshot;
        private readonly List<int> wenWriteOffsets = new List<int>();
        private readonly Dictionary<int, ulong> wenWritePcs = new Dictionary<int, ulong>();
        private readonly Dictionary<int, string> wenWriteContexts = new Dictionary<int, string>();
        private bool memoryAccessHookInstalled;

        private ulong CurrentCpuPc()
        {
            if(!machine.IsRegistered(this))
            {
                return 0UL;
            }
            ICPU cpu;
            var bus = machine.GetSystemBus(this);
            if(bus != null && bus.TryGetCurrentCPU(out cpu) && cpu != null)
            {
                return cpu.PC.RawValue;
            }
            return 0UL;
        }

        private ulong ResolveWritePc(int offset, ulong fallbackPc)
        {
            ulong hookPc;
            if(wenWritePcs.TryGetValue(offset, out hookPc) && hookPc != 0)
            {
                return hookPc;
            }
            return fallbackPc;
        }

        private string ResolveWriteContext(int offset)
        {
            string hookCtx;
            if(wenWriteContexts.TryGetValue(offset, out hookCtx) && !string.IsNullOrEmpty(hookCtx))
            {
                return hookCtx;
            }
            return null;
        }

        private void UpdateMemoryAccessHook(bool enabled)
        {
            if(timing != FlashTiming.Off && Flash != null && FlashSize > 0)
            {
                if(memoryAccessHookInstalled) return;
                enabled = true;
            }
            if(!machine.IsRegistered(this))
            {
                memoryAccessHookInstalled = false;
                return;
            }
            var cpus = machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithMemoryAccessHooks>();
            foreach(var cpu in cpus)
            {
                cpu.SetHookAtMemoryAccess(enabled ? (MemoryAccessHook)OnCpuMemoryWrite : null);
            }
            memoryAccessHookInstalled = enabled;
        }

        private void OnCpuMemoryWrite(ulong pc, MemoryOperation operation, ulong virtualAddress,
                                      ulong physicalAddress, uint width, ulong value)
        {
            if(configValue != 1 || operation != MemoryOperation.MemoryWrite || FlashSize <= 0)
            {
                return;
            }
            long addr = (long)physicalAddress;
            long rel = -1;
            if(addr >= FlashBaseAddress && addr < FlashBaseAddress + FlashSize)
            {
                rel = addr - FlashBaseAddress;
            }
            else if(addr >= 0 && addr < FlashSize)
            {
                rel = addr;
            }
            if(rel < 0)
            {
                return;
            }
            if(timing != FlashTiming.Off && rel <= FlashSize - width)
            {
                programBuffer.Prepare(Flash, FlashSize);
                programBuffer.UndoStore(Flash, rel, (int)width);
                if(AnyFaultFired && FaultRequiresImmediateStop)
                {
                    return;
                }
                SubmitTimedFlashProgram(rel, (int)width, value);
                return;
            }
            if(OperationTraceFastMode && WriteTraceEnabled)
            {
                if(width != 4 || (rel & 3L) != 0 || rel > FlashSize - 4)
                {
                    throw new InvalidOperationException(
                        "operation trace fast mode requires aligned 4-byte flash writes");
                }
                int off = (int)rel;
                wenWritePcs[off] = pc;
                var fastCtx = tracker.CaptureCallContext(pc);
                if(!string.IsNullOrEmpty(fastCtx))
                {
                    wenWriteContexts[off] = fastCtx;
                }
                if(wenWriteOffsets.Count == 0 || wenWriteOffsets[wenWriteOffsets.Count - 1] != off)
                {
                    wenWriteOffsets.Add(off);
                }
                return;
            }
            int startAligned = (int)(rel & ~3L);
            int endAligned = (int)((rel + Math.Max(1U, width) - 1) & ~3L);
            var hookCtx = tracker.CaptureCallContext(pc);
            for(int off = startAligned; off <= endAligned; off += 4)
            {
                if(off >= 0 && off <= FlashSize - 4)
                {
                    wenWritePcs[off] = pc;
                    if(!string.IsNullOrEmpty(hookCtx))
                    {
                        wenWriteContexts[off] = hookCtx;
                    }
                    if(wenWriteOffsets.Count == 0 || wenWriteOffsets[wenWriteOffsets.Count - 1] != off)
                    {
                        wenWriteOffsets.Add(off);
                    }
                }
            }
        }

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
                case 6:
                {
                    // Driver error: reject the write and raise an error flag.
                    DriverErrorFired = true;
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

        private void ApplyTornProgramAtOffset(byte[] snap, byte[] pre, byte[] post,
                                              int off, int len)
        {
            if(off < 0 || off > len - 4)
            {
                return;
            }
            var torn = FaultTracker.BuildFlashTornProgramValue(
                FaultTracker.ReadU32(pre, off), FaultTracker.ReadU32(post, off),
                4, EraseFill, TornWordMode, TornWordSeed, TotalWordWrites, off);
            FaultTracker.WriteU32(snap, off, (uint)torn);
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
            Registers.Ready.Define(this, 1)
                .WithFlag(0, FieldMode.Read, valueProviderCallback: _ => !operation.Busy);
            Registers.ReadyNext.Define(this, 1)
                .WithFlag(0, FieldMode.Read, valueProviderCallback: _ =>
                    !operation.Busy || (configValue == 1 && bufferedProgram == null));

            // ERRORSTATUS at 0x410 — sticky driver error flag.
            Registers.ErrorStatus.Define(this)
                .WithFlag(0, FieldMode.Read | FieldMode.Set, name: "ERROR",
                    valueProviderCallback: _ => DriverErrorFired,
                    writeCallback: (_, val) =>
                    {
                        if(val)
                        {
                            DriverErrorFired = false;
                        }
                    });

            // CONFIG at 0x504 — write enable mode.
            // Values: 0=REN (read-only), 1=WEN (write), 2=EEN (erase).
            Registers.Config.Define(this)
                .WithValueField(0, 2, writeCallback: (_, val) =>
                {
                    if(eraseBusy)
                    {
                        return;
                    }
                    if(timing != FlashTiming.Off)
                    {
                        if(Nvm != null)
                        {
                            if(operation.Busy)
                            {
                                return;
                            }
                            Nvm.ProgramScheduler = val == 1 ? (Action<long, int, Action>)SubmitProgram : null;
                        }
                        else if(Flash != null && FlashSize > 0)
                        {
                            configValue = (uint)val;
                            if(val == 1)
                            {
                                programBuffer.Prepare(Flash, FlashSize);
                                if(!memoryAccessHookInstalled)
                                {
                                    UpdateMemoryAccessHook(true);
                                }
                            }
                            return;
                        }
                    }
                    if(operation.Busy)
                    {
                        return;
                    }
                    var oldConfig = configValue;
                    configValue = (uint)val;

                    if(Flash == null || FlashSize <= 0)
                    {
                        // No MappedMemory — fall back to simple counting.
                        if(oldConfig == 1 && val == 0 && !AnyFaultFired)
                        {
                            if(tracker.IncrementWriteCount(CurrentCpuPc()))
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
                    bool directOperationTrace = OperationTraceFastMode
                        && WriteTraceEnabled
                        && FaultAtWordWrite == ulong.MaxValue
                        && WriteFaultMode == 0;
                    bool needDiff = !PassthroughMode && !AnyFaultFired
                        && ((WriteTraceEnabled && !directOperationTrace)
                            || DiffLookahead == int.MaxValue
                            || (FaultAtWordWrite != ulong.MaxValue
                                && TotalWordWrites + (ulong)DiffLookahead >= FaultAtWordWrite));

                    // Entering WEN: snapshot flash if we need word-level diff,
                    // or if WriteFaultMode requires pre/post comparison.
                    if(val == 1 && oldConfig != 1)
                    {
                        wenWriteOffsets.Clear();
                        wenWritePcs.Clear();
                        wenWriteContexts.Clear();
                        if(timing != FlashTiming.Off)
                        {
                            programBuffer.Prepare(Flash, FlashSize);
                        }
                        bool wantSnap = needDiff || (!PassthroughMode && WriteFaultMode != 0 && !AnyFaultFired);
                        if(wantSnap)
                        {
                            if(!memoryAccessHookInstalled)
                            {
                                UpdateMemoryAccessHook(true);
                            }
                            wenSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                        }
                        else
                        {
                            if((directOperationTrace || timing != FlashTiming.Off) && !memoryAccessHookInstalled)
                            {
                                UpdateMemoryAccessHook(true);
                            }
                            else if(!directOperationTrace && timing == FlashTiming.Off && memoryAccessHookInstalled)
                            {
                                UpdateMemoryAccessHook(false);
                            }
                            wenSnapshot = null;
                        }
                    }

                    // Exiting WEN → REN.
                    if(oldConfig == 1 && val == 0)
                    {
                        var configWritePc = CurrentCpuPc();
                        if(wenSnapshot != null && !AnyFaultFired)
                        {
                            // Word-level diff mode: count each changed 4-byte word.
                            var current = Flash.ReadBytes(0, checked((int)FlashSize));
                            int len = checked((int)FlashSize);

                            if(wenWriteOffsets.Count > 0)
                            {
                                for(int idx = 0; idx < wenWriteOffsets.Count; idx++)
                                {
                                    int off = wenWriteOffsets[idx];
                                    if(off < 0 || off > len - 4)
                                    {
                                        continue;
                                    }
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

                                    tracker.PendingPC = ResolveWritePc(off, configWritePc);
                                    tracker.PendingCallContext = ResolveWriteContext(off);
                                    if(tracker.RecordWriteAndCheckFault(off, val32, 4))
                                    {
                                        FaultFired = true;
                                        LastFaultAddress = (uint)(FlashBaseAddress + off);

                                        var snap = new byte[len];
                                        Array.Copy(wenSnapshot, snap, len);

                                        if(WriteFaultMode == 0)
                                        {
                                            ApplyTornProgramAtOffset(snap, wenSnapshot, current, off, len);
                                            Flash.WriteBytes(0, snap, 0, len);
                                            FaultFlashSnapshot = snap;
                                        }
                                        else
                                        {
                                            var faultedCurrent = new byte[len];
                                            Array.Copy(current, faultedCurrent, len);
                                            ApplyWriteFaultAtOffset(faultedCurrent, wenSnapshot, current, off, len);
                                            Flash.WriteBytes(0, faultedCurrent, 0, len);
                                            FaultFlashSnapshot = faultedCurrent;
                                        }
                                        break;
                                    }

                                    wenSnapshot[off]     = current[off];
                                    wenSnapshot[off + 1] = current[off + 1];
                                    wenSnapshot[off + 2] = current[off + 2];
                                    wenSnapshot[off + 3] = current[off + 3];
                                }
                            }
                            else
                            {
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

                                    tracker.PendingPC = ResolveWritePc(off, configWritePc);
                                    tracker.PendingCallContext = ResolveWriteContext(off);
                                    if(tracker.RecordWriteAndCheckFault(off, val32, 4))
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

                                        // Power-loss mode resumes from the partial
                                        // pre-WEN snapshot above.  Other write faults
                                        // continue executing, so their corruption must
                                        // be applied to the live mapped flash rather than
                                        // existing only in the diagnostic snapshot.
                                        if(WriteFaultMode == 0)
                                        {
                                            ApplyTornProgramAtOffset(snap, wenSnapshot, current, off, len);
                                            Flash.WriteBytes(0, snap, 0, len);
                                            FaultFlashSnapshot = snap;
                                        }
                                        else
                                        {
                                            var faultedCurrent = new byte[len];
                                            Array.Copy(current, faultedCurrent, len);
                                            ApplyWriteFaultAtOffset(faultedCurrent, wenSnapshot, current, off, len);
                                            Flash.WriteBytes(0, faultedCurrent, 0, len);
                                            FaultFlashSnapshot = faultedCurrent;
                                        }
                                        break; // Stop counting further words.
                                    }
                                }
                            }
                        }
                        else if(directOperationTrace)
                        {
                            if(operationTraceShadow == null || operationTraceShadow.Length != FlashSize)
                            {
                                throw new InvalidOperationException(
                                    "operation trace fast mode has no flash shadow");
                            }
                            for(int idx = 0; idx < wenWriteOffsets.Count; idx++)
                            {
                                int off = wenWriteOffsets[idx];
                                var currentWord = Flash.ReadBytes(off, 4);
                                bool changed = currentWord[0] != operationTraceShadow[off]
                                    || currentWord[1] != operationTraceShadow[off + 1]
                                    || currentWord[2] != operationTraceShadow[off + 2]
                                    || currentWord[3] != operationTraceShadow[off + 3];
                                if(!changed)
                                {
                                    continue;
                                }
                                uint val32 = (uint)(currentWord[0]
                                    | (currentWord[1] << 8)
                                    | (currentWord[2] << 16)
                                    | (currentWord[3] << 24));
                                tracker.PendingPC = ResolveWritePc(off, configWritePc);
                                tracker.PendingCallContext = ResolveWriteContext(off);
                                tracker.RecordWriteAndCheckFault(off, val32, 4);
                                operationTraceShadow[off] = currentWord[0];
                                operationTraceShadow[off + 1] = currentWord[1];
                                operationTraceShadow[off + 2] = currentWord[2];
                                operationTraceShadow[off + 3] = currentWord[3];
                            }
                        }
                        else if(!AnyFaultFired)
                        {
                            // Fast path: assume 1 word write per WEN->REN.
                            // Only reachable for power-loss mode (WriteFaultMode==0)
                            // because the WEN entry guard captures wenSnapshot for
                            // all non-power-loss modes, routing them through the
                            // slow diff path above which calls ApplyWriteFaultAtOffset.
                            if(tracker.IncrementWriteCount(configWritePc))
                            {
                                FaultFired = true;
                                LastFaultAddress = 0;
                                FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                            }
                        }

                        wenWriteOffsets.Clear();
                        wenWritePcs.Clear();
                        wenWriteContexts.Clear();
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

                    if(operation.Busy)
                    {
                        return;
                    }
                    if(timing == FlashTiming.Off)
                    {
                        CompletePageErase(pageAddr);
                        return;
                    }
                    long offset = pageAddr - (Nvm != null ? NvmBaseAddress : FlashBaseAddress);
                    if(offset >= 0 && offset + PageSize <= (Nvm != null ? Nvm.Size : FlashSize))
                    {
                        if(!PassthroughMode && !AnyFaultFired && TotalPageErases + 1 == FaultAtPageErase)
                        {
                            CompletePageErase(pageAddr);
                            programBuffer.RefreshIfPrepared(Flash);
                            return;
                        }
                        eraseBusy = true;
                        operation.Start(85000, () =>
                        {
                            eraseBusy = false;
                            CompletePageErase(pageAddr);
                            programBuffer.RefreshIfPrepared(Flash);
                        });
                    }
                }, name: "ERASEPAGE");

            // ERASEALL at 0x50C.
            Registers.EraseAll.Define(this)
                .WithValueField(0, 1, writeCallback: (_, val) =>
                {
                    if(val == 1 && configValue == 2)
                    {
                        if(operation.Busy)
                        {
                            return;
                        }
                        if(timing == FlashTiming.Off)
                        {
                            CompleteEraseAll();
                            return;
                        }
                        eraseBusy = true;
                        operation.Start(169000, () =>
                        {
                            eraseBusy = false;
                            CompleteEraseAll();
                            programBuffer.RefreshIfPrepared(Flash);
                        });
                    }
                }, name: "ERASEALL");
        }

        private void CompletePageErase(long pageAddr)
        {
            var erasePc = CurrentCpuPc();
            if(Nvm != null)
            {
                var offset = pageAddr - NvmBaseAddress;
                if(offset >= 0 && offset + PageSize <= Nvm.Size)
                {
                    if(tracker.RecordEraseAndCheckFault(offset, PageSize, erasePc))
                    {
                        EraseFaultFired = true;
                        LastFaultAddress = (uint)pageAddr;
                        int halfPage = PageSize / 2;
                        if(EraseFaultMode == 1)
                        {
                            int quarterPage = Math.Max(1, PageSize / 4);
                            Nvm.EraseSectorRaw(offset, halfPage);
                            long neighbor = offset + PageSize;
                            if(neighbor + quarterPage <= Nvm.Size)
                            {
                                Nvm.EraseSectorRaw(neighbor, quarterPage);
                            }
                        }
                        else
                        {
                            var neutralMode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                            if(neutralMode != "fixed")
                            {
                                var previous = Nvm.ReadBytes(offset, PageSize);
                                var torn = FaultTracker.BuildFlashTornEraseSpan(
                                    previous, offset, EraseFill, 4, neutralMode,
                                    TornWordSeed, TotalPageErases);
                                Nvm.WriteSpanRaw(offset, torn);
                            }
                            else
                            {
                            var tornMode = (MramTornWordMode ?? "half").Trim().ToLowerInvariant();
                            if(tornMode == "untouched")
                            {
                                // Power cut before erase took effect.
                            }
                            else if(tornMode == "erased" || tornMode == "programmed")
                            {
                                Nvm.EraseSectorRaw(offset, PageSize);
                            }
                            else if(tornMode == "corrupted")
                            {
                                var corrupted = tracker.BuildCorruptedErasedSpan(offset, PageSize, EraseFill, 4);
                                Nvm.WriteSpanRaw(offset, corrupted);
                            }
                            else
                            {
                                Nvm.EraseSectorRaw(offset, halfPage);
                            }
                            }
                        }
                        FaultFlashSnapshot = Nvm.ReadBytes(0, checked((int)Nvm.Size));
                    }
                    else
                    {
                        Nvm.EraseSectorRaw(offset, PageSize);
                    }
                }
            }
            else if(Flash != null)
            {
                var offset = pageAddr - FlashBaseAddress;
                if(offset >= 0 && offset + PageSize <= FlashSize)
                {
                    if(tracker.RecordEraseAndCheckFault(offset, PageSize, erasePc))
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
                            var neutralMode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                            if(neutralMode != "fixed")
                            {
                                var previous = Flash.ReadBytes(offset, PageSize);
                                var torn = FaultTracker.BuildFlashTornEraseSpan(
                                    previous, offset, EraseFill, 4, neutralMode,
                                    TornWordSeed, TotalPageErases);
                                Flash.WriteBytes(offset, torn, 0, torn.Length);
                            }
                            else
                            {
                            var tornMode = (MramTornWordMode ?? "half").Trim().ToLowerInvariant();
                            if(tornMode == "untouched")
                            {
                                // Power cut before erase took effect.
                            }
                            else if(tornMode == "erased" || tornMode == "programmed")
                            {
                                EraseWithFill(Flash, offset, PageSize);
                            }
                            else if(tornMode == "corrupted")
                            {
                                var corrupted = tracker.BuildCorruptedErasedSpan(offset, PageSize, EraseFill, 4);
                                Flash.WriteBytes(offset, corrupted, 0, corrupted.Length);
                            }
                            else
                            {
                                EraseWithFill(Flash, offset, halfPage);
                            }
                            }
                        }

                        FaultFlashSnapshot = Flash.ReadBytes(0, checked((int)FlashSize));
                    }
                    else
                    {
                        EraseWithFill(Flash, offset, PageSize);
                    }
                }
            }
            if(operationTraceShadow != null && Flash != null)
            {
                var offset = pageAddr - FlashBaseAddress;
                if(offset >= 0 && offset + PageSize <= FlashSize)
                {
                    var currentPage = Flash.ReadBytes(offset, PageSize);
                    Array.Copy(currentPage, 0, operationTraceShadow, offset, PageSize);
                }
            }
        }

        private void CompleteEraseAll()
        {
            if(Nvm != null)
            {
                for(long offset = 0; offset < Nvm.Size; offset += PageSize)
                {
                    var remaining = (int)Math.Min(PageSize, Nvm.Size - offset);
                    Nvm.EraseSectorRaw(offset, remaining);
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
                if(operationTraceShadow != null)
                {
                    operationTraceShadow = Flash.ReadBytes(0, checked((int)FlashSize));
                }
            }
        }

        private enum Registers
        {
            Ready = 0x400,
            ReadyNext = 0x408,
            ErrorStatus = 0x410,
            Config = 0x504,
            ErasePage = 0x508,
            EraseAll = 0x50C,
        }
    }
}
