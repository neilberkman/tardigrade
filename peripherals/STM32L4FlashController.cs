// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Logging.Profiling;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.IRQControllers;
using Antmicro.Renode.Peripherals.Memory;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    /// <summary>
    /// STM32L4 internal Flash controller at 0x40022000 modeled from RM0351
    /// with Tardigrade fault injection, operation-accurate double-word (64-bit)
    /// write and page/bank erase tracing, fast row-programming mode (FSTPG),
    /// and ECC double-error (FLASH_ECCR.ECCD + NMI) read faults on double-words
    /// whose programming was interrupted.
    /// </summary>
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public class STM32L4FlashController : IDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        public STM32L4FlashController(IMachine machine, MappedMemory flash = null,
                                      long flashBaseAddress = DefaultFlashBaseAddress,
                                      long flashSize = DefaultFlashSize,
                                      int pageSize = DefaultPageSize,
                                      byte eraseFill = 0xFF,
                                      bool dualBank = true)
        {
            this.machine = machine;
            tracker.Bind(machine, this);
            this.flash = flash;
            this.flashBaseAddress = flashBaseAddress;
            this.flashSize = flashSize;
            this.pageSize = pageSize > 0 ? pageSize : DefaultPageSize;
            this.eraseFill = eraseFill;
            this.dualBankEnabled = dualBank;
            this.operation = new FlashOperationTimer(this);
            IRQ = new GPIO();

            var regMap = new Dictionary<long, DoubleWordRegister>
            {
                {(long)Registers.Acr, new DoubleWordRegister(this, ResetAcr)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => acr,
                        writeCallback: (_, val) => WriteAcr((uint)val),
                        name: "ACR")
                },
                {(long)Registers.Pdkeyr, new DoubleWordRegister(this)
                    .WithValueField(0, 32, FieldMode.Write,
                        writeCallback: (_, val) => WritePdkeyr((uint)val),
                        name: "PDKEYR")
                },
                {(long)Registers.Keyr, new DoubleWordRegister(this)
                    .WithValueField(0, 32, FieldMode.Write,
                        writeCallback: (_, val) => WriteKeyr((uint)val),
                        name: "KEYR")
                },
                {(long)Registers.Optkeyr, new DoubleWordRegister(this)
                    .WithValueField(0, 32, FieldMode.Write,
                        writeCallback: (_, val) => WriteOptkeyr((uint)val),
                        name: "OPTKEYR")
                },
                {(long)Registers.Sr, new DoubleWordRegister(this)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => (sr & ~SrBsyBit) | (operation.Busy ? SrBsyBit : 0u),
                        writeCallback: (_, val) => WriteSr((uint)val),
                        name: "SR")
                },
                {(long)Registers.Cr, new DoubleWordRegister(this, ResetCr)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => cr,
                        writeCallback: (_, val) => WriteCr((uint)val),
                        name: "CR")
                },
                {(long)Registers.Eccr, new DoubleWordRegister(this)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => eccr,
                        writeCallback: (_, val) => WriteEccr((uint)val),
                        name: "ECCR")
                },
                {(long)Registers.Optr, new DoubleWordRegister(this, ResetOptr)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => optr,
                        writeCallback: (_, val) => WriteOptr((uint)val),
                        name: "OPTR")
                },
                {(long)Registers.Pcrop1Sr, new DoubleWordRegister(this, 0xFFFFFFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => pcrop1Sr, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) pcrop1Sr = (uint)val; }, name: "PCROP1SR")
                },
                {(long)Registers.Pcrop1Er, new DoubleWordRegister(this, 0x0FF00000)
                    .WithValueField(0, 32, valueProviderCallback: _ => pcrop1Er, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) pcrop1Er = (uint)val; }, name: "PCROP1ER")
                },
                {(long)Registers.Wrp1Ar, new DoubleWordRegister(this, 0xFF00FFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => wrp1Ar, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) wrp1Ar = (uint)val; }, name: "WRP1AR")
                },
                {(long)Registers.Wrp1Br, new DoubleWordRegister(this, 0xFF00FFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => wrp1Br, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) wrp1Br = (uint)val; }, name: "WRP1BR")
                },
                {(long)Registers.Pcrop2Sr, new DoubleWordRegister(this, 0xFFFFFFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => pcrop2Sr, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) pcrop2Sr = (uint)val; }, name: "PCROP2SR")
                },
                {(long)Registers.Pcrop2Er, new DoubleWordRegister(this, 0x0FF00000)
                    .WithValueField(0, 32, valueProviderCallback: _ => pcrop2Er, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) pcrop2Er = (uint)val; }, name: "PCROP2ER")
                },
                {(long)Registers.Wrp2Ar, new DoubleWordRegister(this, 0xFF00FFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => wrp2Ar, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) wrp2Ar = (uint)val; }, name: "WRP2AR")
                },
                {(long)Registers.Wrp2Br, new DoubleWordRegister(this, 0xFF00FFFF)
                    .WithValueField(0, 32, valueProviderCallback: _ => wrp2Br, writeCallback: (_, val) => { if((cr & CrOptlockBit) == 0) wrp2Br = (uint)val; }, name: "WRP2BR")
                },
            };

            registers = new DoubleWordRegisterCollection(this, regMap);
            Reset();
        }

        public uint ReadDoubleWord(long offset)
        {
            return registers.Read(offset);
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            registers.Write(offset, value);
        }

        public void Reset()
        {
            registers.Reset();
            operation.Reset();
            acr = ResetAcr;
            sr = 0;
            cr = ResetCr;
            eccr = 0;
            optr = dualBankEnabled ? ResetOptr : (ResetOptr & ~OptrDualBankBit);
            pcrop1Sr = 0xFFFFFFFF;
            pcrop1Er = 0x0FF00000;
            wrp1Ar = 0xFF00FFFF;
            wrp1Br = 0xFF00FFFF;
            pcrop2Sr = 0xFFFFFFFF;
            pcrop2Er = 0x0FF00000;
            wrp2Ar = 0xFF00FFFF;
            wrp2Br = 0xFF00FFFF;
            keyUnlockStep = 0;
            optKeyUnlockStep = 0;
            pdKeyUnlockStep = 0;
            keyLockedUntilReset = false;
            optKeyLockedUntilReset = false;
            ClearPendingProgramState();
            writePowerLossLatched = false;
            RemoveStartHook();
            RemoveStopHook();
            trackingStopHit = false;
            trackingStopWrites = 0;
            trackingStopErases = 0;
            ClearUncorrectableReadLog();
            if(!PreserveCountersAcrossReset)
            {
                ResetTrackerState();
                FaultFlashSnapshot = null;
                flashShadow = null;
                trackingStartAddress = configuredTrackingStartAddress;
                trackingStarted = trackingStartAddress == 0;
            }
            else if(trackingStarted)
            {
                trackingStartAddress = 0;
            }
            else
            {
                trackingStartAddress = configuredTrackingStartAddress;
            }
            UpdateMemoryHooks();
            IRQ.Unset();
        }

        private void ResetTrackerState()
        {
            tracker.TotalWordWrites = 0;
            tracker.TotalPageErases = 0;
            tracker.FaultFired = false;
            tracker.EraseFaultFired = false;
            tracker.DriverErrorFired = false;
            tracker.LastFaultAddress = 0;
            tracker.FaultFlashSnapshot = null;
            tracker.WriteTraceClear();
            tracker.EraseTraceClear();
            lastFaultInjected = false;
            faultEverFired = false;
            flashShadow = null;
        }

        public void InvalidateShadow()
        {
            flashShadow = null;
            if(memoryAccessHookInstalled)
            {
                EnsureShadow();
            }
        }

        public void SyncShadowFromFlash()
        {
            if(flash != null && flashSize > 0 && flashSize <= int.MaxValue)
            {
                flashShadow = flash.ReadBytes(0, (int)flashSize);
            }
        }

        public void MarkWordUncorrectable(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            MarkWordUncorrectableInternal(offset);
            UpdateMemoryHooks();
        }

        public void ClearUncorrectableWord(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                return;
            }
            if(uncorrectableWords.Remove(AlignDown(offset, DoubleWordSize))
               && uncorrectableWords.Count == 0 && correctableWords.Count == 0)
            {
                UpdateMemoryHooks();
            }
        }

        public void ClearUncorrectableWords()
        {
            var hadAny = uncorrectableWords.Count > 0 || correctableWords.Count > 0;
            uncorrectableWords.Clear();
            correctableWords.Clear();
            if(hadAny)
            {
                UpdateMemoryHooks();
            }
        }

        public bool IsWordUncorrectable(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                return false;
            }
            return uncorrectableWords.Contains(AlignDown(offset, DoubleWordSize));
        }

        public bool IsAddressUncorrectable(long address)
        {
            if(!TryResolveFlashOffset((ulong)address, out var offset))
            {
                offset = address;
            }
            return IsWordUncorrectable(offset);
        }

        public void MarkWordCorrectable(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            correctableWords.Add(AlignDown(offset, DoubleWordSize));
            UpdateMemoryHooks();
        }

        public void ClearCorrectableWord(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                return;
            }
            if(correctableWords.Remove(AlignDown(offset, DoubleWordSize))
               && correctableWords.Count == 0 && uncorrectableWords.Count == 0)
            {
                UpdateMemoryHooks();
            }
        }

        public void ClearCorrectableWords()
        {
            if(correctableWords.Count == 0)
            {
                return;
            }
            correctableWords.Clear();
            UpdateMemoryHooks();
        }

        public int CorrectableWordCount => correctableWords.Count;
        public bool IsWordCorrectable(long offset)
        {
            if(offset < 0 || offset >= flashSize)
            {
                return false;
            }
            return correctableWords.Contains(AlignDown(offset, DoubleWordSize));
        }

        public int UncorrectableWordCount => uncorrectableWords.Count;
        public bool LastFaultMarkedUncorrectable => lastFaultMarkedUncorrectable;

        public string UncorrectableWordsToString()
        {
            var sb = new StringBuilder();
            foreach(var wordOffset in uncorrectableWords.OrderBy(x => x))
            {
                var busAddr = (ulong)flashBaseAddress + (ulong)wordOffset;
                sb.AppendFormat("{0}:0x{1:X8}\n", wordOffset, busAddr);
            }
            return sb.ToString();
        }

        public string FaultUncorrectableWordsToString()
        {
            var sb = new StringBuilder();
            foreach(var wordOffset in faultUncorrectableWords.OrderBy(x => x))
            {
                var busAddr = (ulong)flashBaseAddress + (ulong)wordOffset;
                sb.AppendFormat("{0}:0x{1:X8}\n", wordOffset, busAddr);
            }
            return sb.ToString();
        }

        public void ClearUncorrectableReadLog()
        {
            uncorrectableReads.Clear();
            uncorrectableReadCount = 0;
            lastUncorrectableReadWordAddress = 0;
            lastUncorrectableReadAddress = 0;
            lastUncorrectableReadPC = 0;
        }

        public ulong UncorrectableReadCount => uncorrectableReadCount;
        public ulong LastUncorrectableReadWordAddress => lastUncorrectableReadWordAddress;
        public ulong LastUncorrectableReadAddress => lastUncorrectableReadAddress;
        public ulong LastUncorrectableReadPC => lastUncorrectableReadPC;

        public string UncorrectableReadsToString()
        {
            var sb = new StringBuilder();
            foreach(var entry in uncorrectableReads)
            {
                sb.AppendFormat("{0}:{1}:0x{2:X8}:0x{3:X8}:{4}:0x{5:X8}\n",
                    entry.Index, entry.WordOffset, entry.WordBusAddress,
                    entry.AccessBusAddress, entry.Width, entry.PC);
            }
            return sb.ToString();
        }

        public GPIO IRQ { get; }
        public long Size => 0x400;

        public FlashTiming OperationTiming
        {
            get => timing;
            set
            {
                if(timing == value)
                {
                    return;
                }
                if(operation.Busy)
                {
                    throw new InvalidOperationException("Change flash timing while the controller is idle");
                }
                timing = value;
                UpdateMemoryHooks();
            }
        }

        public IMemory Flash
        {
            get => flash;
            set
            {
                flash = value as MappedMemory;
                flashShadow = null;
                UpdateMemoryHooks();
            }
        }

        public long FlashBaseAddress
        {
            get => flashBaseAddress;
            set => flashBaseAddress = value;
        }

        public long FlashSize
        {
            get => flashSize;
            set
            {
                flashSize = value;
                flashShadow = null;
                if(memoryAccessHookInstalled)
                {
                    EnsureShadow();
                }
            }
        }

        public int PageSize
        {
            get => pageSize;
            set => pageSize = value > 0 ? value : DefaultPageSize;
        }

        public int ProgramUnitSize => DoubleWordSize;
        public int WordSize => DoubleWordSize;

        public byte EraseFill
        {
            get => eraseFill;
            set => eraseFill = value;
        }

        public bool DualBankEnabled
        {
            get => (optr & OptrDualBankBit) != 0;
            set
            {
                dualBankEnabled = value;
                if(value)
                {
                    optr |= OptrDualBankBit;
                }
                else
                {
                    optr &= ~OptrDualBankBit;
                }
            }
        }

        public long BankSize => DualBankEnabled ? (flashSize / 2) : flashSize;

        public bool EccDoubleErrorRaisesNmi { get; set; } = true;
        public bool EccDoubleErrorRaisesBusFault { get; set; } = false;

        public byte[] FaultFlashSnapshot { get; set; }
        public bool WriteTraceWidthExplicit => true;
        public bool PerWriteAccurate => true;

        public int DiffLookahead { get; set; } = 32;
        public bool SkipShadowScan { get; set; } = true;
        public bool OperationTraceFastMode { get; set; } = true;

        public ulong TotalWordWrites
        {
            get => tracker.TotalWordWrites;
            set => tracker.TotalWordWrites = value;
        }

        public ulong TotalPageErases
        {
            get => tracker.TotalPageErases;
            set => tracker.TotalPageErases = value;
        }

        public ulong FaultAtWordWrite
        {
            get => tracker.FaultAtWordWrite;
            set
            {
                tracker.FaultAtWordWrite = value;
                writePowerLossLatched = false;
                UpdateMemoryHooks();
            }
        }

        public ulong FaultAtPageErase
        {
            get => tracker.FaultAtPageErase;
            set
            {
                tracker.FaultAtPageErase = value;
                writePowerLossLatched = false;
                UpdateMemoryHooks();
            }
        }

        public int WriteFaultMode
        {
            get => tracker.WriteFaultMode;
            set => tracker.WriteFaultMode = value;
        }

        public int EraseFaultMode
        {
            get => tracker.EraseFaultMode;
            set => tracker.EraseFaultMode = value;
        }

        public uint CorruptionSeed
        {
            get => tracker.CorruptionSeed;
            set => tracker.CorruptionSeed = value;
        }

        public string TornWordMode
        {
            get => l4UncorrectableTornMode ? "uncorrectable" : tracker.TornWordMode;
            set
            {
                var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
                if(normalized == "uncorrectable")
                {
                    l4UncorrectableTornMode = true;
                    tracker.TornWordMode = "untouched";
                    return;
                }
                l4UncorrectableTornMode = false;
                if(string.Equals((tracker.MramTornWordMode ?? string.Empty).Trim(), "uncorrectable", StringComparison.OrdinalIgnoreCase))
                {
                    tracker.MramTornWordMode = "half";
                }
                tracker.TornWordMode = value;
            }
        }

        public uint TornWordSeed
        {
            get => tracker.TornWordSeed;
            set => tracker.TornWordSeed = value;
        }

        public string MramTornWordMode
        {
            get => tracker.MramTornWordMode;
            set => tracker.MramTornWordMode = value;
        }

        public uint MramTornWordSeed
        {
            get => tracker.MramTornWordSeed;
            set => tracker.MramTornWordSeed = value;
        }

        public bool FaultFired
        {
            get => tracker.FaultFired;
            set
            {
                tracker.FaultFired = value;
                if(!value)
                {
                    writePowerLossLatched = false;
                }
                UpdateMemoryHooks();
            }
        }

        public bool EraseFaultFired
        {
            get => tracker.EraseFaultFired;
            set
            {
                tracker.EraseFaultFired = value;
                if(!value)
                {
                    writePowerLossLatched = false;
                }
                UpdateMemoryHooks();
            }
        }

        public bool LastFaultInjected
        {
            get => lastFaultInjected;
            set => lastFaultInjected = value;
        }

        public bool FaultEverFired
        {
            get => faultEverFired;
            set => faultEverFired = value;
        }

        public bool DriverErrorFired
        {
            get => tracker.DriverErrorFired;
            set => tracker.DriverErrorFired = value;
        }

        public uint LastFaultAddress
        {
            get => tracker.LastFaultAddress;
            set => tracker.LastFaultAddress = value;
        }

        public ulong LastFaultPC
        {
            get => tracker.LastFaultPC;
            set => tracker.LastFaultPC = value;
        }

        public string LastFaultCallContext
        {
            get => tracker.LastFaultCallContext;
            set => tracker.LastFaultCallContext = value;
        }

        public RecoveryTraceTimes TraceTimes => tracker.TraceTimes;
        public string WriteCallContextToString() => tracker.WriteCallContextToString();
        public string EraseCallContextToString() => tracker.EraseCallContextToString();

        private ulong GetCurrentCpuPC()
        {
            if(machine != null && machine.GetSystemBus(this).TryGetCurrentCPU(out var currentCpu))
            {
                return currentCpu.PC.RawValue;
            }
            foreach(var cpu in machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>())
            {
                return cpu.PC.RawValue;
            }
            return 0;
        }

        public bool AnyFaultFired => tracker.AnyFaultFired || ReadFaultFired;
        public bool FaultRequiresImmediateStop => tracker.FaultRequiresImmediateStop;

        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        public bool PreserveCountersAcrossReset
        {
            get => tracker.PreserveCountersAcrossReset;
            set => tracker.PreserveCountersAcrossReset = value;
        }

        public bool PassthroughMode
        {
            get => passthroughMode;
            set
            {
                passthroughMode = value;
                if(!value)
                {
                    writePowerLossLatched = false;
                }
                UpdateMemoryHooks();
            }
        }

        public ulong TrackingStartAddress
        {
            get => trackingStartAddress;
            set
            {
                RemoveStartHook();
                configuredTrackingStartAddress = value & ~1UL;
                trackingStartAddress = configuredTrackingStartAddress;
                trackingStarted = trackingStartAddress == 0;
                UpdateMemoryHooks();
            }
        }

        public bool TrackingStarted => trackingStarted;
        public bool StartHookInstalled => startHookInstalled;
        public bool MemoryAccessHookInstalled => memoryAccessHookInstalled;
        public bool NativeTrackingStartReliable => true;

        public ulong TrackingStopAddress
        {
            get => trackingStopAddress;
            set
            {
                RemoveStopHook();
                trackingStopAddress = value & ~1UL;
                trackingStopHit = false;
                trackingStopWrites = 0;
                trackingStopErases = 0;
                UpdateMemoryHooks();
            }
        }

        public bool TrackingStopHit => trackingStopHit;
        public ulong TrackingStopWrites => trackingStopWrites;
        public ulong TrackingStopErases => trackingStopErases;
        public bool StopHookInstalled => stopHookInstalled;

        public bool WriteTraceEnabled
        {
            get => tracker.WriteTraceEnabled;
            set => tracker.WriteTraceEnabled = value;
        }

        public bool EraseTraceEnabled
        {
            get => tracker.EraseTraceEnabled;
            set => tracker.EraseTraceEnabled = value;
        }

        public int WriteTraceCount => tracker.WriteTraceCount;
        public int EraseTraceCount => tracker.EraseTraceCount;

        public void WriteTraceClear() => tracker.WriteTraceClear();
        public void EraseTraceClear() => tracker.EraseTraceClear();
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public string EraseTraceToString() => tracker.EraseTraceToString();

        private void WriteAcr(uint value)
        {
            var writableMask = AcrLatencyMask | AcrPrftenBit | AcrIcenBit | AcrDcenBit | AcrIcrstBit | AcrDcrstBit | AcrRunPdBit | AcrSleepPdBit;
            acr = value & writableMask;
        }

        private void WritePdkeyr(uint value)
        {
            if(value == PdKey1)
            {
                pdKeyUnlockStep = 1;
                return;
            }
            if(pdKeyUnlockStep == 1 && value == PdKey2)
            {
                pdKeyUnlockStep = 0;
                return;
            }
            pdKeyUnlockStep = 0;
        }

        private void WriteKeyr(uint value)
        {
            if(keyLockedUntilReset)
            {
                RaiseBusError();
                return;
            }
            if(keyUnlockStep == 0)
            {
                if(value == UnlockKey1)
                {
                    keyUnlockStep = 1;
                    return;
                }
                LockUntilResetWithBusError();
                return;
            }
            if(value == UnlockKey2)
            {
                if((cr & CrLockBit) != 0)
                {
                    flashShadow = null;
                }
                cr &= ~CrLockBit;
                keyUnlockStep = 0;
                UpdateMemoryHooks();
                return;
            }
            LockUntilResetWithBusError();
        }

        private void LockUntilResetWithBusError()
        {
            keyUnlockStep = 0;
            keyLockedUntilReset = true;
            ClearPendingProgramState();
            fstpgActive = false;
            cr = (cr & ~(CrPgBit | CrFstpgBit)) | CrLockBit | CrOptlockBit;
            UpdateMemoryHooks();
            RaiseBusError();
        }

        private void WriteOptkeyr(uint value)
        {
            if(optKeyLockedUntilReset)
            {
                RaiseBusError();
                return;
            }
            if(optKeyUnlockStep == 0)
            {
                if(value == OptUnlockKey1)
                {
                    optKeyUnlockStep = 1;
                    return;
                }
                optKeyUnlockStep = 0;
                optKeyLockedUntilReset = true;
                cr |= CrOptlockBit;
                RaiseBusError();
                return;
            }
            if(value == OptUnlockKey2)
            {
                if((cr & CrLockBit) == 0)
                {
                    cr &= ~CrOptlockBit;
                }
                optKeyUnlockStep = 0;
                return;
            }
            optKeyUnlockStep = 0;
            optKeyLockedUntilReset = true;
            cr |= CrOptlockBit;
            RaiseBusError();
        }

        private void WriteSr(uint value)
        {
            var clearMask = value & SrRcW1Mask;
            sr &= ~clearMask;
            UpdateInterrupts();
        }

        private void WriteCr(uint value)
        {
            if(operation.Busy)
            {
                return;
            }
            if((cr & CrLockBit) != 0 || keyLockedUntilReset)
            {
                this.Log(LogLevel.Warning, "STM32L4 FLASH_CR write ignored while LOCK=1 (value=0x{0:X8})", value);
                return;
            }

            var wasPg = (cr & CrPgBit) != 0;
            var wasFstpg = (cr & CrFstpgBit) != 0;
            var nextPg = (value & CrPgBit) != 0;
            var nextFstpg = (value & CrFstpgBit) != 0;

            if(wasPg && !nextPg && pendingWordValid)
            {
                // RM0351 §3.3.7: clearing PG while only one 32-bit word of a
                // double-word was latched aborts the sequence and sets PGSERR.
                ClearPendingProgramState();
                sr |= SrPgserrBit;
            }
            if(wasFstpg && !nextFstpg && fstpgActive && fstpgWordsInRow > 0 && fstpgWordsInRow < FastRowWords)
            {
                // RM0351 §3.3.7: clearing FSTPG before all 64 words (32 double-words)
                // of the row have been written raises FASTERR / PGSERR.
                ClearPendingProgramState();
                sr |= SrFasterrBit | SrPgserrBit;
            }

            // LOCK and OPTLOCK can only be set (not cleared) via FLASH_CR.
            // Setting LOCK=1 also sets OPTLOCK=1 per RM0351 §3.7.6.
            var lockBit = (value & CrLockBit) != 0 ? CrLockBit : 0u;
            var optlockBit = ((cr & CrOptlockBit) != 0 || (value & CrOptlockBit) != 0 || lockBit != 0)
                ? CrOptlockBit
                : 0u;

            var writableMask = CrPgBit | CrPerBit | CrMer1Bit | CrPnbMask | CrBkerBit | CrMer2Bit
                             | CrStrtBit | CrOptstrtBit | CrFstpgBit | CrEopieBit | CrErrieBit
                             | CrRderrieBit | CrOblLaunchBit;
            cr = (value & writableMask) | optlockBit | lockBit;

            if(nextFstpg && !wasFstpg)
            {
                if(nextPg || (cr & (CrPerBit | CrMer1Bit | CrMer2Bit)) != 0)
                {
                    sr |= SrPgserrBit;
                    cr &= ~CrFstpgBit;
                }
                else
                {
                    fstpgActive = true;
                    fstpgRowBase = -1;
                    fstpgWordsInRow = 0;
                }
            }
            else if(!nextFstpg)
            {
                fstpgActive = false;
                fstpgRowBase = -1;
                fstpgWordsInRow = 0;
            }

            if((cr & CrStrtBit) != 0 && (cr & CrLockBit) == 0)
            {
                if((sr & SrProgramEraseErrorMask) != 0 || (cr & (CrPgBit | CrFstpgBit)) != 0)
                {
                    sr |= SrPgserrBit;
                }
                else if((cr & CrMer1Bit) != 0 && (cr & CrMer2Bit) != 0)
                {
                    ExecuteEraseRange(0, (int)flashSize);
                }
                else if((cr & CrMer1Bit) != 0)
                {
                    ExecuteEraseRange(0, (int)BankSize);
                }
                else if((cr & CrMer2Bit) != 0)
                {
                    if(DualBankEnabled && BankSize < flashSize)
                    {
                        ExecuteEraseRange(BankSize, (int)(flashSize - BankSize));
                    }
                    else
                    {
                        ExecuteEraseRange(0, (int)flashSize);
                    }
                }
                else if((cr & CrPerBit) != 0)
                {
                    var pnb = (int)((cr & CrPnbMask) >> CrPnbShift);
                    var isBank2 = DualBankEnabled && (cr & CrBkerBit) != 0;
                    var bankBase = isBank2 ? BankSize : 0L;
                    var pageOffset = bankBase + (long)pnb * pageSize;
                    if(pageOffset >= 0 && pageOffset + pageSize <= flashSize && (pageOffset < bankBase + BankSize))
                    {
                        ExecuteEraseRange(pageOffset, pageSize);
                    }
                    else
                    {
                        this.Log(LogLevel.Warning,
                            "STM32L4 page erase out of range (BKER={0}, PNB={1}, offset=0x{2:X})",
                            isBank2 ? 1 : 0, pnb, pageOffset);
                        sr |= SrPgserrBit;
                    }
                }
                cr &= ~CrStrtBit;
            }

            if((cr & CrOptstrtBit) != 0)
            {
                if((cr & CrOptlockBit) == 0)
                {
                    SetEopIfEnabled();
                }
                cr &= ~CrOptstrtBit;
            }

            UpdateMemoryHooks();
            UpdateInterrupts();
        }

        private void WriteEccr(uint value)
        {
            var clearMask = value & (EccrEcccBit | EccrEccdBit);
            eccr &= ~clearMask;
            eccr = (eccr & ~EccrEccieBit) | (value & EccrEccieBit);
            if((eccr & (EccrEcccBit | EccrEccdBit)) == 0)
            {
                eccr &= ~(EccrAddrMask | EccrBkEccBit | EccrSysfEccBit);
            }
            UpdateInterrupts();
        }

        private void WriteOptr(uint value)
        {
            if((cr & CrOptlockBit) != 0)
            {
                this.Log(LogLevel.Warning, "STM32L4 FLASH_OPTR write ignored while OPTLOCK=1");
                return;
            }
            optr = value;
            dualBankEnabled = (optr & OptrDualBankBit) != 0;
        }

        private void ExecuteEraseRange(long regionBase, int regionLength)
        {
            if(flash == null || flashSize <= 0 || regionBase < 0 || regionLength <= 0 || regionBase + regionLength > flashSize)
            {
                return;
            }
            if(!passthroughMode && (tracker.EraseFaultFired || writePowerLossLatched))
            {
                return;
            }

            EnsureShadow();
            if(!trackingStarted)
            {
                if(OperationTiming != FlashTiming.Off)
                {
                    var untimedDelay = GetL4EraseDelayMicros(regionLength);
                    operation.Start(untimedDelay, () =>
                    {
                        FillFlashAndShadow(regionBase, regionLength, eraseFill);
                        ClearUncorrectableRange(regionBase, regionLength);
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    });
                    return;
                }
                FillFlashAndShadow(regionBase, regionLength, eraseFill);
                ClearUncorrectableRange(regionBase, regionLength);
                SetEopIfEnabled();
                return;
            }

            var shouldFault = tracker.RecordEraseAndCheckFault(regionBase, regionLength, GetCurrentCpuPC());
            var eraseIndex = tracker.TotalPageErases;

            if(!passthroughMode && shouldFault)
            {
                ApplyEraseFault(regionBase, regionLength, eraseIndex);
                return;
            }

            if(OperationTiming != FlashTiming.Off)
            {
                var delay = GetL4EraseDelayMicros(regionLength);
                operation.Start(delay, () =>
                {
                    FillFlashAndShadow(regionBase, regionLength, eraseFill);
                    ClearUncorrectableRange(regionBase, regionLength);
                    SetEopIfEnabled();
                    UpdateInterrupts();
                });
                return;
            }

            FillFlashAndShadow(regionBase, regionLength, eraseFill);
            ClearUncorrectableRange(regionBase, regionLength);
            SetEopIfEnabled();
        }

        private ulong GetL4EraseDelayMicros(int regionLength)
        {
            var isMassOrBank = regionLength > pageSize;
            if(isMassOrBank)
            {
                return OperationTiming == FlashTiming.Maximum ? L4MassEraseMaxMicros : L4MassEraseTypMicros;
            }
            return OperationTiming == FlashTiming.Maximum ? L4PageEraseMaxMicros : L4PageEraseTypMicros;
        }

        private void ApplyEraseFault(long regionBase, int regionLength, ulong eraseIndex)
        {
            var previousBytes = flash.ReadBytes(regionBase, regionLength);
            EnsureShadow();
            Array.Copy(previousBytes, 0, flashShadow, (int)regionBase, regionLength);
            lastFaultMarkedUncorrectable = false;
            faultUncorrectableWords.Clear();

            if(tracker.EraseFaultMode == 1)
            {
                var halfLen = Math.Max(1, regionLength / 2);
                FillFlashAndShadow(regionBase, halfLen, eraseFill);
                ClearUncorrectableRange(regionBase, halfLen);

                var neighborOffset = regionBase + regionLength;
                if(neighborOffset < flashSize)
                {
                    var neighborLen = (int)Math.Min(Math.Max(1, regionLength / 4), flashSize - neighborOffset);
                    FillFlashAndShadow(neighborOffset, neighborLen, eraseFill);
                    ClearUncorrectableRange(neighborOffset, neighborLen);
                }
            }
            else if(IsUncorrectableTornModeActive())
            {
                var firstUnit = AlignDown(regionBase, DoubleWordSize);
                var lastUnit = AlignDown(regionBase + regionLength - 1, DoubleWordSize);
                for(var unit = firstUnit; unit <= lastUnit; unit += DoubleWordSize)
                {
                    MarkWordUncorrectableInternal(unit);
                }
                lastFaultMarkedUncorrectable = true;
                faultUncorrectableWords.AddRange(uncorrectableWords.OrderBy(x => x));
                UpdateMemoryHooks();
            }
            else
            {
                var neutralMode = (tracker.TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                if(neutralMode != "fixed")
                {
                    var seed = tracker.TornWordSeed != 0 ? tracker.TornWordSeed : tracker.CorruptionSeed;
                    var tornBytes = FaultTracker.BuildFlashTornEraseSpan(
                        previousBytes,
                        regionBase,
                        eraseFill,
                        DoubleWordSize,
                        neutralMode,
                        seed,
                        eraseIndex);
                    WriteFlashAndShadow(regionBase, tornBytes);
                    ClearUncorrectableRange(regionBase, regionLength);
                }
                else
                {
                    var tornMode = (tracker.MramTornWordMode ?? "half").Trim().ToLowerInvariant();
                    if(tornMode == "untouched")
                    {
                        // Leave pre-erase bytes intact.
                    }
                    else if(tornMode == "erased" || tornMode == "programmed")
                    {
                        FillFlashAndShadow(regionBase, regionLength, eraseFill);
                        ClearUncorrectableRange(regionBase, regionLength);
                    }
                    else if(tornMode == "corrupted")
                    {
                        var corrupted = tracker.BuildCorruptedErasedSpan(regionBase, regionLength, eraseFill, DoubleWordSize);
                        WriteFlashAndShadow(regionBase, corrupted);
                        ClearUncorrectableRange(regionBase, regionLength);
                    }
                    else
                    {
                        var halfLen = Math.Max(1, regionLength / 2);
                        FillFlashAndShadow(regionBase, halfLen, eraseFill);
                        ClearUncorrectableRange(regionBase, halfLen);
                    }
                }
            }

            tracker.EraseFaultFired = true;
            lastFaultInjected = true;
            faultEverFired = true;
            tracker.LastFaultAddress = (uint)(flashBaseAddress + regionBase);
            FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
            writePowerLossLatched = true;
            UpdateMemoryHooks();
        }

        private void OnCpuMemoryAccess(ulong pc, MemoryOperation operation,
                                       ulong virtualAddress, ulong physicalAddress,
                                       uint width, ulong value)
        {
            if(flash == null)
            {
                return;
            }

            if(operation == MemoryOperation.MemoryRead
               || operation == MemoryOperation.MemoryIORead
               || operation == MemoryOperation.InsnFetch)
            {
                if(uncorrectableWords.Count == 0 && correctableWords.Count == 0)
                {
                    return;
                }
                long readOffset;
                if(!TryResolveFlashOffset(virtualAddress, out readOffset)
                   && !TryResolveFlashOffset(physicalAddress, out readOffset))
                {
                    return;
                }
                var accessWidth = Math.Max(1, (int)Math.Min(width == 0 ? 1u : width, (uint)DoubleWordSize));
                var firstUnit = AlignDown(readOffset, DoubleWordSize);
                var lastUnit = AlignDown(readOffset + accessWidth - 1, DoubleWordSize);

                for(var unit = firstUnit; unit <= lastUnit; unit += DoubleWordSize)
                {
                    if(uncorrectableWords.Contains(unit))
                    {
                        HandleEccDoubleErrorRead(unit, readOffset, accessWidth, pc);
                        return;
                    }
                    if(correctableWords.Contains(unit))
                    {
                        HandleEccSingleErrorRead(unit);
                    }
                }
                return;
            }

            if((operation != MemoryOperation.MemoryWrite && operation != MemoryOperation.MemoryIOWrite)
               || width == 0)
            {
                return;
            }

            long offset;
            if(!TryResolveFlashOffset(virtualAddress, out offset)
               && !TryResolveFlashOffset(physicalAddress, out offset))
            {
                return;
            }

            if(!passthroughMode && (tracker.EraseFaultFired || writePowerLossLatched))
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                return;
            }

            if(this.operation.Busy)
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                return;
            }

            var pgEnabled = (cr & CrPgBit) != 0;
            var fstpgEnabled = (cr & CrFstpgBit) != 0;
            if((cr & CrLockBit) != 0 || (!pgEnabled && !fstpgEnabled))
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                return;
            }

            // RM0351 §3.3.7: starting a program while error flags are still set
            // in FLASH_SR sets PGSERR and aborts the operation.
            if((sr & SrProgramEraseErrorMask) != 0)
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                ClearPendingProgramState();
                sr |= SrPgserrBit;
                UpdateInterrupts();
                return;
            }

            if(pgEnabled && fstpgEnabled)
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                sr |= SrPgserrBit;
                UpdateInterrupts();
                return;
            }

            // RM0351 §3.3.7: Flash programming writes must be 32-bit word aligned
            // and 32-bit wide (or a 64-bit bus store covering an aligned double-word).
            if(width != 4 && width != 8)
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                ClearPendingProgramState();
                sr |= SrSizerrBit;
                if(fstpgEnabled)
                {
                    sr |= SrFasterrBit;
                }
                UpdateInterrupts();
                return;
            }

            if((offset & 3) != 0 || (width == 8 && (offset & 7) != 0))
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                ClearPendingProgramState();
                sr |= SrPgaerrBit;
                if(fstpgEnabled)
                {
                    sr |= SrFasterrBit;
                }
                UpdateInterrupts();
                return;
            }

            if(fstpgEnabled)
            {
                tracker.PendingPC = pc != 0 ? pc : GetCurrentCpuPC();
                HandleFastRowWrite(offset, width, value);
                return;
            }

            if(width == 8)
            {
                if(pendingWordValid)
                {
                    RevertFromShadow(offset, 8);
                    ClearPendingProgramState();
                    sr |= SrPgaerrBit;
                    UpdateInterrupts();
                    return;
                }
                tracker.PendingPC = pc != 0 ? pc : GetCurrentCpuPC();
                CommitDoubleWordProgram(offset, value, isFastRow: false);
                return;
            }

            tracker.PendingPC = pc != 0 ? pc : GetCurrentCpuPC();
            HandleStandardWordWrite(offset, (uint)value, isFastRow: false);
        }

        private void HandleFastRowWrite(long offset, uint width, ulong value)
        {
            if(width == 8)
            {
                HandleFastRowWord(offset, (uint)(value & 0xFFFFFFFF));
                if(!writePowerLossLatched && !tracker.EraseFaultFired && (sr & SrProgramEraseErrorMask) == 0)
                {
                    HandleFastRowWord(offset + 4, (uint)((value >> 32) & 0xFFFFFFFF));
                }
                else
                {
                    RevertFromShadow(offset + 4, 4);
                }
                return;
            }
            HandleFastRowWord(offset, (uint)value);
        }

        private void HandleFastRowWord(long offset, uint wordValue)
        {
            if(fstpgWordsInRow == 0)
            {
                if((offset & (FastRowBytes - 1)) != 0)
                {
                    RevertFromShadow(offset, 4);
                    ClearPendingProgramState();
                    sr |= SrPgaerrBit | SrFasterrBit;
                    UpdateInterrupts();
                    return;
                }
                fstpgRowBase = offset;
            }
            else
            {
                var expectedOffset = fstpgRowBase + (long)fstpgWordsInRow * 4;
                if(offset != expectedOffset)
                {
                    RevertFromShadow(offset, 4);
                    ClearPendingProgramState();
                    sr |= SrPgaerrBit | SrFasterrBit;
                    UpdateInterrupts();
                    return;
                }
            }

            if(!HandleStandardWordWrite(offset, wordValue, isFastRow: true))
            {
                return;
            }

            fstpgWordsInRow++;
            if(fstpgWordsInRow >= FastRowWords)
            {
                fstpgWordsInRow = 0;
                fstpgRowBase = -1;
                if(OperationTiming != FlashTiming.Off)
                {
                    var staged = fstpgStagedDoubleWords.ToArray();
                    fstpgStagedDoubleWords.Clear();
                    var delay = OperationTiming == FlashTiming.Maximum ? L4FastRowProgMaxMicros : L4FastRowProgTypMicros;
                    operation.Start(delay, () =>
                    {
                        foreach(var entry in staged)
                        {
                            WriteFlashAndShadowDoubleWord(entry.Key, entry.Value);
                            ClearUncorrectableWord(entry.Key);
                            ClearCorrectableWord(entry.Key);
                        }
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    });
                    return;
                }
                SetEopIfEnabled();
                UpdateInterrupts();
            }
        }

        private void FlushStagedFastRowDoubleWords()
        {
            if(fstpgStagedDoubleWords.Count == 0)
            {
                return;
            }
            foreach(var entry in fstpgStagedDoubleWords)
            {
                WriteFlashAndShadowDoubleWord(entry.Key, entry.Value);
                ClearUncorrectableWord(entry.Key);
                ClearCorrectableWord(entry.Key);
            }
            fstpgStagedDoubleWords.Clear();
        }

        private bool HandleStandardWordWrite(long offset, uint wordValue, bool isFastRow)
        {
            var dwOffset = AlignDown(offset, DoubleWordSize);
            var isHighHalf = (offset - dwOffset) == 4;

            if(!pendingWordValid)
            {
                // First 32-bit word of the 64-bit double-word: hold it in the
                // controller latch and keep backing Flash at its pre-program
                // value until the second 32-bit word arrives.
                RevertFromShadow(offset, 4);
                pendingWordValid = true;
                pendingDoubleWordOffset = dwOffset;
                pendingIsHighHalf = isHighHalf;
                pendingWordValue = wordValue;
                return true;
            }

            if(dwOffset != pendingDoubleWordOffset || isHighHalf == pendingIsHighHalf)
            {
                // RM0351 §3.3.7 / §3.7.5: second word did not target the
                // complementary half of the same 64-bit double-word: raise
                // PGAERR and abort the double-word.
                RevertFromShadow(offset, 4);
                ClearPendingProgramState();
                sr |= SrPgaerrBit;
                if(isFastRow)
                {
                    sr |= SrFasterrBit;
                }
                UpdateInterrupts();
                return false;
            }

            var lowWord = isHighHalf ? pendingWordValue : wordValue;
            var highWord = isHighHalf ? wordValue : pendingWordValue;
            pendingWordValid = false;
            var intendedDoubleWord = ((ulong)highWord << 32) | lowWord;
            return CommitDoubleWordProgram(dwOffset, intendedDoubleWord, isFastRow);
        }

        private bool CommitDoubleWordProgram(long dwOffset, ulong intendedValue, bool isFastRow)
        {
            if(dwOffset < 0 || dwOffset + DoubleWordSize > flashSize)
            {
                return false;
            }

            var oldDoubleWord = ReadShadowDoubleWord(dwOffset);

            // RM0351 §3.3.7: programming a non-erased double-word (!= 0xFFFFFFFF_FFFFFFFF)
            // or a double-word left partially programmed by an interrupted write
            // (tracked in uncorrectableWords) fails with PROGERR in FLASH_SR,
            // except when programming all zeros (0x00000000_00000000).
            if((oldDoubleWord != ulong.MaxValue || uncorrectableWords.Contains(dwOffset)) && intendedValue != 0UL)
            {
                WriteFlashDoubleWord(dwOffset, oldDoubleWord);
                ClearPendingProgramState();
                sr |= SrProgerrBit;
                if(isFastRow)
                {
                    sr |= SrFasterrBit;
                }
                UpdateInterrupts();
                this.Log(LogLevel.Warning,
                    "STM32L4 PROGERR at offset 0x{0:X}: destination double-word 0x{1:X16} is not erased",
                    dwOffset, oldDoubleWord);
                return false;
            }

            if(!trackingStarted)
            {
                if(OperationTiming != FlashTiming.Off)
                {
                    WriteFlashDoubleWord(dwOffset, oldDoubleWord);
                    if(isFastRow)
                    {
                        fstpgStagedDoubleWords.Add(new KeyValuePair<long, ulong>(dwOffset, intendedValue));
                        return true;
                    }
                    var untimedDelay = OperationTiming == FlashTiming.Maximum ? L4ProgMaxMicros : L4ProgTypMicros;
                    operation.Start(untimedDelay, () =>
                    {
                        WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
                        ClearUncorrectableWord(dwOffset);
                        ClearCorrectableWord(dwOffset);
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    });
                    return true;
                }
                WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
                ClearUncorrectableWord(dwOffset);
                ClearCorrectableWord(dwOffset);
                if(!isFastRow)
                {
                    SetEopIfEnabled();
                    UpdateInterrupts();
                }
                return true;
            }

            var shouldFault = tracker.RecordWriteAndCheckFault((int)dwOffset, intendedValue, DoubleWordSize);
            var writeIndex = tracker.TotalWordWrites;

            if(!passthroughMode && shouldFault)
            {
                if(OperationTiming != FlashTiming.Off)
                {
                    WriteFlashDoubleWord(dwOffset, oldDoubleWord);
                    if(isFastRow)
                    {
                        FlushStagedFastRowDoubleWords();
                    }
                    else if(tracker.WriteFaultMode != 0
                        && tracker.WriteFaultMode != 3
                        && tracker.WriteFaultMode != 6)
                    {
                        var faultDelay = OperationTiming == FlashTiming.Maximum ? L4ProgMaxMicros : L4ProgTypMicros;
                        operation.Start(faultDelay, () =>
                        {
                            ApplyWriteFault(dwOffset, oldDoubleWord, intendedValue, writeIndex, isFastRow: false);
                        });
                        return true;
                    }
                }
                return ApplyWriteFault(dwOffset, oldDoubleWord, intendedValue, writeIndex, isFastRow);
            }

            if(OperationTiming != FlashTiming.Off)
            {
                WriteFlashDoubleWord(dwOffset, oldDoubleWord);
                if(isFastRow)
                {
                    fstpgStagedDoubleWords.Add(new KeyValuePair<long, ulong>(dwOffset, intendedValue));
                    return true;
                }
                var delay = OperationTiming == FlashTiming.Maximum ? L4ProgMaxMicros : L4ProgTypMicros;
                operation.Start(delay, () =>
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
                    ClearUncorrectableWord(dwOffset);
                    ClearCorrectableWord(dwOffset);
                    SetEopIfEnabled();
                    UpdateInterrupts();
                });
                return true;
            }

            WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
            ClearUncorrectableWord(dwOffset);
            ClearCorrectableWord(dwOffset);
            if(!isFastRow)
            {
                SetEopIfEnabled();
                UpdateInterrupts();
            }
            return true;
        }

        private bool ApplyWriteFault(long dwOffset, ulong oldDoubleWord, ulong intendedValue,
                                     ulong writeIndex, bool isFastRow)
        {
            tracker.FaultFired = true;
            lastFaultInjected = true;
            faultEverFired = true;
            tracker.LastFaultAddress = (uint)(flashBaseAddress + dwOffset);
            lastFaultMarkedUncorrectable = false;
            faultUncorrectableWords.Clear();
            var completed = false;

            switch(tracker.WriteFaultMode)
            {
                case 0: // power_loss
                {
                    if(IsUncorrectableTornModeActive())
                    {
                        WriteFlashAndShadowDoubleWord(dwOffset, oldDoubleWord);
                        MarkWordUncorrectableInternal(dwOffset);
                        lastFaultMarkedUncorrectable = true;
                        faultUncorrectableWords.AddRange(uncorrectableWords.OrderBy(x => x));
                    }
                    else
                    {
                        var seed = tracker.TornWordSeed != 0 ? tracker.TornWordSeed : tracker.CorruptionSeed;
                        var tornValue = FaultTracker.BuildFlashTornProgramValue(
                            oldDoubleWord,
                            intendedValue,
                            DoubleWordSize,
                            eraseFill,
                            tracker.TornWordMode,
                            seed,
                            writeIndex,
                            dwOffset);
                        WriteFlashAndShadowDoubleWord(dwOffset, tornValue);
                        ClearUncorrectableWord(dwOffset);
                        ClearCorrectableWord(dwOffset);
                        faultUncorrectableWords.AddRange(uncorrectableWords.OrderBy(x => x));
                    }
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    writePowerLossLatched = true;
                    UpdateMemoryHooks();
                    break;
                }
                case 1: // bit_corruption
                {
                    var seed = tracker.BuildFaultSeed((int)dwOffset);
                    var keepLow = FaultTracker.NextLcg(ref seed);
                    var keepHigh = FaultTracker.NextLcg(ref seed);
                    var keepMask = ((ulong)keepHigh << 32) | keepLow;
                    var bitsToFlip = oldDoubleWord & ~intendedValue;
                    var corrupted = oldDoubleWord & ~(bitsToFlip & keepMask);
                    WriteFlashAndShadowDoubleWord(dwOffset, corrupted);
                    ClearUncorrectableWord(dwOffset);
                    ClearCorrectableWord(dwOffset);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    if(!isFastRow)
                    {
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    }
                    completed = true;
                    break;
                }
                case 2: // silent_write_failure
                {
                    var silentValue = (writeIndex & 1) == 0 ? ulong.MaxValue : 0UL;
                    WriteFlashAndShadowDoubleWord(dwOffset, silentValue);
                    ClearUncorrectableWord(dwOffset);
                    ClearCorrectableWord(dwOffset);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    if(!isFastRow)
                    {
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    }
                    completed = true;
                    break;
                }
                case 3: // write_rejection
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, oldDoubleWord);
                    ClearPendingProgramState();
                    sr |= SrProgerrBit;
                    if(isFastRow)
                    {
                        sr |= SrFasterrBit;
                    }
                    UpdateInterrupts();
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
                case 4: // write_disturb
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
                    ClearUncorrectableWord(dwOffset);
                    ClearCorrectableWord(dwOffset);
                    var seed = tracker.BuildFaultSeed((int)dwOffset);
                    foreach(var neighborOff in new[] { dwOffset - DoubleWordSize, dwOffset + DoubleWordSize })
                    {
                        if(neighborOff < 0 || neighborOff + DoubleWordSize > flashSize)
                        {
                            continue;
                        }
                        var neighborWord = ReadShadowDoubleWord(neighborOff);
                        var dLow = FaultTracker.NextLcg(ref seed) & 0x11111111u;
                        var dHigh = FaultTracker.NextLcg(ref seed) & 0x11111111u;
                        var disturbMask = ((ulong)dHigh << 32) | dLow;
                        WriteFlashAndShadowDoubleWord(neighborOff, neighborWord & ~disturbMask);
                    }
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    if(!isFastRow)
                    {
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    }
                    completed = true;
                    break;
                }
                case 5: // wear_leveling_corruption
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, intendedValue);
                    ClearUncorrectableWord(dwOffset);
                    ClearCorrectableWord(dwOffset);
                    var pageStart = (dwOffset / pageSize) * pageSize;
                    var dwordsPerPage = Math.Max(1, pageSize / DoubleWordSize);
                    var errorCount = 2 + (int)Math.Min(10UL, tracker.TotalPageErases / 8);
                    var seed = tracker.BuildFaultSeed((int)dwOffset);
                    for(var i = 0; i < errorCount; i++)
                    {
                        var idx = (int)(FaultTracker.NextLcg(ref seed) % (uint)dwordsPerPage);
                        var targetOff = pageStart + (long)idx * DoubleWordSize;
                        if(targetOff < 0 || targetOff + DoubleWordSize > flashSize)
                        {
                            continue;
                        }
                        var word = ReadShadowDoubleWord(targetOff);
                        var mLow = FaultTracker.NextLcg(ref seed) & 0x01010101u;
                        var mHigh = FaultTracker.NextLcg(ref seed) & 0x01010101u;
                        var mask = ((ulong)mHigh << 32) | mLow;
                        if(mask == 0)
                        {
                            mask = 1UL << (int)(FaultTracker.NextLcg(ref seed) % 64u);
                        }
                        WriteFlashAndShadowDoubleWord(targetOff, word & ~mask);
                    }
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    if(!isFastRow)
                    {
                        SetEopIfEnabled();
                        UpdateInterrupts();
                    }
                    completed = true;
                    break;
                }
                case 6: // driver_error
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, oldDoubleWord);
                    ClearPendingProgramState();
                    tracker.DriverErrorFired = true;
                    sr |= SrProgerrBit;
                    if(isFastRow)
                    {
                        sr |= SrFasterrBit;
                    }
                    UpdateInterrupts();
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
                default:
                {
                    WriteFlashAndShadowDoubleWord(dwOffset, oldDoubleWord);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
            }
            faultUncorrectableWords.Clear();
            faultUncorrectableWords.AddRange(uncorrectableWords.OrderBy(x => x));
            return completed;
        }

        private void HandleEccSingleErrorRead(long unitOffset)
        {
            var isBank2 = DualBankEnabled && unitOffset >= BankSize;
            var offsetInBank = isBank2 ? (unitOffset - BankSize) : unitOffset;
            var addrEcc = (uint)(offsetInBank & EccrAddrMask);

            if((eccr & (EccrEcccBit | EccrEccdBit)) == 0)
            {
                eccr = (eccr & ~(EccrAddrMask | EccrBkEccBit | EccrSysfEccBit))
                     | addrEcc
                     | (isBank2 ? EccrBkEccBit : 0u);
            }
            eccr |= EccrEcccBit;
            UpdateInterrupts();
        }

        private void HandleEccDoubleErrorRead(long unitOffset, long accessOffset, int width, ulong pc)
        {
            RecordUncorrectableRead(unitOffset, accessOffset, width, pc);

            var isBank2 = DualBankEnabled && unitOffset >= BankSize;
            var offsetInBank = isBank2 ? (unitOffset - BankSize) : unitOffset;
            var addrEcc = (uint)(offsetInBank & EccrAddrMask);

            // RM0351 §3.3.10 / §3.7.7: double ECC error sets ECCD (bit 31) and
            // latches ADDR_ECC[18:0], BK_ECC (bit 19), SYSF_ECC = 0 (bit 20)
            // only if neither ECCC nor ECCD is already set.
            if((eccr & (EccrEcccBit | EccrEccdBit)) == 0)
            {
                eccr = (eccr & ~(EccrAddrMask | EccrBkEccBit | EccrSysfEccBit))
                     | addrEcc
                     | (isBank2 ? EccrBkEccBit : 0u);
            }
            eccr |= EccrEccdBit;

            if(machine == null)
            {
                return;
            }
            var bus = machine.GetSystemBus(this);
            if(!bus.TryGetCurrentCPU(out var cpu) || cpu == null)
            {
                cpu = bus.GetCPUs().FirstOrDefault();
            }
            RaiseEccDoubleErrorException(cpu);
        }

        private void RaiseEccDoubleErrorException(ICPU cpu)
        {
            if(cpu == null || machine == null)
            {
                return;
            }
            var cortexM = cpu as CortexM;
            if(cortexM != null)
            {
                var nvic = machine.GetPeripheralsOfType<NVIC>().FirstOrDefault();
                if(nvic != null)
                {
                    if(EccDoubleErrorRaisesBusFault)
                    {
                        cortexM.FaultStatus |= 0x00000200u; // PRECISERR
                        var shcsr = nvic.ReadDoubleWord(0xD24);
                        var exc = ((shcsr & (1u << 17)) != 0
                                   && cortexM.PRIMASK.RawValue == 0
                                   && cortexM.FAULTMASK.RawValue == 0) ? 5 : 3;
                        nvic.SetPendingIRQ(exc);
                        cortexM.RaiseException(5);
                        return;
                    }
                    if(EccDoubleErrorRaisesNmi)
                    {
                        // RM0351 §3.3.10 Table 9: double ECC error generates NMI (exception 2).
                        nvic.SetPendingIRQ(2);
                        cortexM.RaiseException(5);
                        return;
                    }
                }
            }
        }

        private void RecordUncorrectableRead(long wordOffset, long accessOffset, int width, ulong pc)
        {
            var wordBusAddr = (ulong)flashBaseAddress + (ulong)wordOffset;
            var accessBusAddr = (ulong)flashBaseAddress + (ulong)accessOffset;
            uncorrectableReadCount++;
            lastUncorrectableReadWordAddress = wordBusAddr;
            lastUncorrectableReadAddress = accessBusAddr;
            lastUncorrectableReadPC = pc;
            if(uncorrectableReads.Count < 256)
            {
                uncorrectableReads.Add(new UncorrectableReadEntry(
                    uncorrectableReadCount, wordOffset, wordBusAddr, accessBusAddr, width, pc));
            }
        }

        private bool IsUncorrectableTornModeActive()
        {
            if(l4UncorrectableTornMode)
            {
                return true;
            }
            var neutralMode = (tracker.TornWordMode ?? "fixed").Trim().ToLowerInvariant();
            if(neutralMode != "fixed")
            {
                return false;
            }
            var mramMode = (tracker.MramTornWordMode ?? string.Empty).Trim().ToLowerInvariant();
            return mramMode == "uncorrectable";
        }

        private void MarkWordUncorrectableInternal(long offset)
        {
            var aligned = AlignDown(offset, DoubleWordSize);
            uncorrectableWords.Add(aligned);
            correctableWords.Remove(aligned);
        }

        private void ClearUncorrectableRange(long offset, int count)
        {
            if((uncorrectableWords.Count == 0 && correctableWords.Count == 0) || count <= 0 || offset < 0)
            {
                return;
            }
            var firstUnit = AlignDown(offset, DoubleWordSize);
            var lastUnit = AlignDown(offset + count - 1, DoubleWordSize);
            var removed = false;
            for(var unit = firstUnit; unit <= lastUnit; unit += DoubleWordSize)
            {
                if(uncorrectableWords.Remove(unit))
                {
                    removed = true;
                }
                if(correctableWords.Remove(unit))
                {
                    removed = true;
                }
            }
            if(removed && uncorrectableWords.Count == 0 && correctableWords.Count == 0)
            {
                UpdateMemoryHooks();
            }
        }

        private void ClearPendingProgramState()
        {
            pendingWordValid = false;
            pendingDoubleWordOffset = -1;
            pendingIsHighHalf = false;
            pendingWordValue = 0;
            fstpgRowBase = -1;
            fstpgWordsInRow = 0;
            fstpgStagedDoubleWords.Clear();
        }

        private void SetEopIfEnabled()
        {
            if((cr & CrEopieBit) != 0)
            {
                sr |= SrEopBit;
            }
        }

        private void UpdateInterrupts()
        {
            var srErrorMask = SrOperrBit | SrProgerrBit | SrWrperrBit | SrPgaerrBit
                            | SrSizerrBit | SrPgserrBit | SrMiserrBit | SrFasterrBit | SrOptverrBit;
            var errPending = (cr & CrErrieBit) != 0 && (sr & srErrorMask) != 0;
            var rderrPending = (cr & CrRderrieBit) != 0 && (sr & SrRderrBit) != 0;
            var eopPending = (cr & CrEopieBit) != 0 && (sr & SrEopBit) != 0;
            var eccPending = (eccr & EccrEccieBit) != 0 && (eccr & EccrEcccBit) != 0;
            if(errPending || rderrPending || eopPending || eccPending)
            {
                IRQ.Set();
            }
            else
            {
                IRQ.Unset();
            }
        }

        private void RaiseBusError()
        {
            if(machine == null)
            {
                return;
            }
            var bus = machine.GetSystemBus(this);
            var inCpuContext = bus.TryGetCurrentCPU(out var cpu) && cpu != null;
            if(!inCpuContext)
            {
                cpu = bus.GetCPUs().FirstOrDefault();
            }
            var cortexM = cpu as CortexM;
            if(cortexM != null)
            {
                var nvic = machine.GetPeripheralsOfType<NVIC>().FirstOrDefault();
                if(nvic != null)
                {
                    cortexM.FaultStatus |= 0x00000200u; // PRECISERR
                    var shcsr = nvic.ReadDoubleWord(0xD24);
                    var exc = ((shcsr & (1u << 17)) != 0
                               && cortexM.PRIMASK.RawValue == 0
                               && cortexM.FAULTMASK.RawValue == 0) ? 5 : 3;
                    nvic.SetPendingIRQ(exc);
                    if(inCpuContext)
                    {
                        cortexM.RaiseException(5);
                    }
                }
            }
        }

        private bool NeedsMemoryAccessHook =>
            (cr & CrLockBit) == 0
            || uncorrectableWords.Count > 0
            || correctableWords.Count > 0
            || (!passthroughMode && (writePowerLossLatched || tracker.EraseFaultFired));

        private void OnTrackingStart(ICpuSupportingGdb cpu, ulong address)
        {
            RemoveStartHook();
            trackingStartAddress = 0;
            trackingStarted = true;
            ResetTrackerState();
            FaultFlashSnapshot = null;
            flashShadow = null;
            UpdateMemoryHooks();
        }

        private void OnTrackingStop(ICpuSupportingGdb cpu, ulong address)
        {
            if(trackingStopHit)
            {
                return;
            }
            trackingStopHit = true;
            trackingStopWrites = tracker.TotalWordWrites;
            trackingStopErases = tracker.TotalPageErases;
            RemoveStopHook();
        }

        private void UpdateMemoryHooks()
        {
            if(machine == null || !machine.IsRegistered(this))
            {
                memoryAccessHookInstalled = false;
                return;
            }
            var hookNeeded = NeedsMemoryAccessHook;
            if(hookNeeded)
            {
                EnsureShadow();
            }
            var cpus = machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithMemoryAccessHooks>();
            foreach(var cpu in cpus)
            {
                cpu.SetHookAtMemoryAccess(hookNeeded ? (MemoryAccessHook)OnCpuMemoryAccess : null);
                var hookCpu = cpu as ICPUWithHooks;
                if(hookCpu == null)
                {
                    continue;
                }
                if(trackingStartAddress != 0 && !trackingStarted && !startHookInstalled)
                {
                    hookCpu.AddHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart);
                    startHookInstalled = true;
                }
                if(trackingStopAddress != 0 && !trackingStopHit && !stopHookInstalled)
                {
                    hookCpu.AddHook(trackingStopAddress, (CpuAddressHook)OnTrackingStop);
                    stopHookInstalled = true;
                }
            }
            memoryAccessHookInstalled = hookNeeded;
        }

        private void RemoveStartHook()
        {
            if(!startHookInstalled || machine == null || !machine.IsRegistered(this))
            {
                startHookInstalled = false;
                return;
            }
            foreach(var cpu in machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>())
            {
                cpu.RemoveHook(trackingStartAddress, (CpuAddressHook)OnTrackingStart);
            }
            startHookInstalled = false;
        }

        private void RemoveStopHook()
        {
            if(!stopHookInstalled || machine == null || !machine.IsRegistered(this))
            {
                stopHookInstalled = false;
                return;
            }
            foreach(var cpu in machine.GetSystemBus(this).GetCPUs().OfType<ICPUWithHooks>())
            {
                cpu.RemoveHook(trackingStopAddress, (CpuAddressHook)OnTrackingStop);
            }
            stopHookInstalled = false;
        }

        private bool TryResolveFlashOffset(ulong address, out long offset)
        {
            if(address >= (ulong)flashBaseAddress && address < (ulong)(flashBaseAddress + flashSize))
            {
                offset = (long)(address - (ulong)flashBaseAddress);
                return true;
            }
            if(flashSize > 0 && address < (ulong)flashSize)
            {
                offset = (long)address;
                return true;
            }
            offset = 0;
            return false;
        }

        private void EnsureShadow()
        {
            if(flashShadow == null && flash != null && flashSize > 0 && flashSize <= int.MaxValue)
            {
                flashShadow = flash.ReadBytes(0, (int)flashSize);
            }
        }

        private ulong ReadShadowDoubleWord(long offset)
        {
            EnsureShadow();
            ulong result = 0;
            for(var i = 0; i < DoubleWordSize; i++)
            {
                result |= (ulong)flashShadow[offset + i] << (8 * i);
            }
            return result;
        }

        private void WriteFlashDoubleWord(long offset, ulong value)
        {
            var bytes = new byte[DoubleWordSize];
            for(var i = 0; i < DoubleWordSize; i++)
            {
                bytes[i] = (byte)((value >> (8 * i)) & 0xFF);
            }
            flash.WriteBytes(offset, bytes, 0, bytes.Length);
        }

        private void WriteFlashAndShadowDoubleWord(long offset, ulong value)
        {
            EnsureShadow();
            var bytes = new byte[DoubleWordSize];
            for(var i = 0; i < DoubleWordSize; i++)
            {
                var b = (byte)((value >> (8 * i)) & 0xFF);
                bytes[i] = b;
                flashShadow[offset + i] = b;
            }
            flash.WriteBytes(offset, bytes, 0, bytes.Length);
        }

        private void WriteFlashAndShadow(long offset, byte[] data)
        {
            EnsureShadow();
            Array.Copy(data, 0, flashShadow, (int)offset, data.Length);
            flash.WriteBytes(offset, data, 0, data.Length);
        }

        private void FillFlashAndShadow(long offset, int length, byte fill)
        {
            var buf = new byte[length];
            for(var i = 0; i < length; i++)
            {
                buf[i] = fill;
                if(flashShadow != null)
                {
                    flashShadow[offset + i] = fill;
                }
            }
            flash.WriteBytes(offset, buf, 0, buf.Length);
        }

        private void RevertFromShadow(long offset, int length)
        {
            if(flash == null || flashShadow == null || offset < 0)
            {
                return;
            }
            var count = (int)Math.Min(length, flashSize - offset);
            if(count <= 0)
            {
                return;
            }
            var restored = new byte[count];
            Array.Copy(flashShadow, (int)offset, restored, 0, count);
            flash.WriteBytes(offset, restored, 0, restored.Length);
        }

        private static long AlignDown(long value, int alignment)
        {
            return value & ~(alignment - 1L);
        }

        private readonly IMachine machine;
        private readonly DoubleWordRegisterCollection registers;
        private readonly FaultTracker tracker = new FaultTracker();
        private readonly FlashOperationTimer operation;
        private FlashTiming timing;
        private readonly List<KeyValuePair<long, ulong>> fstpgStagedDoubleWords = new List<KeyValuePair<long, ulong>>();

        // DS10198 Rev 8 §6.3.10 Table 63 (Flash memory characteristics):
        //   tprog (64-bit double-word programming time): Typ 81.69 us (82 us), Max 90.76 us (91 us)
        //   tprog_row (32 double-word fast row programming time, FSTPG): Typ 1.91 ms (1910 us), Max 2.12 ms (2120 us)
        //   tERASE (2 KB page erase time): Typ 22.02 ms (22020 us), Max 24.47 ms (24470 us)
        //   tME (mass or single-bank erase time): Typ 22.13 ms (22130 us), Max 24.59 ms (24590 us)
        private const ulong L4ProgTypMicros = 82UL;
        private const ulong L4ProgMaxMicros = 91UL;
        private const ulong L4FastRowProgTypMicros = 1910UL;
        private const ulong L4FastRowProgMaxMicros = 2120UL;
        private const ulong L4PageEraseTypMicros = 22020UL;
        private const ulong L4PageEraseMaxMicros = 24470UL;
        private const ulong L4MassEraseTypMicros = 22130UL;
        private const ulong L4MassEraseMaxMicros = 24590UL;
        private readonly HashSet<long> uncorrectableWords = new HashSet<long>();
        private readonly HashSet<long> correctableWords = new HashSet<long>();
        private readonly List<long> faultUncorrectableWords = new List<long>();
        private readonly List<UncorrectableReadEntry> uncorrectableReads = new List<UncorrectableReadEntry>();

        private MappedMemory flash;
        private long flashBaseAddress;
        private long flashSize;
        private int pageSize;
        private byte eraseFill;
        private bool dualBankEnabled;
        private byte[] flashShadow;

        private uint acr;
        private uint sr;
        private uint cr;
        private uint eccr;
        private uint optr;
        private uint pcrop1Sr;
        private uint pcrop1Er;
        private uint wrp1Ar;
        private uint wrp1Br;
        private uint pcrop2Sr;
        private uint pcrop2Er;
        private uint wrp2Ar;
        private uint wrp2Br;
        private int keyUnlockStep;
        private int optKeyUnlockStep;
        private int pdKeyUnlockStep;
        private bool keyLockedUntilReset;
        private bool optKeyLockedUntilReset;

        private bool pendingWordValid;
        private long pendingDoubleWordOffset = -1;
        private bool pendingIsHighHalf;
        private uint pendingWordValue;

        private bool fstpgActive;
        private long fstpgRowBase = -1;
        private int fstpgWordsInRow;

        private bool passthroughMode;
        private bool writePowerLossLatched;
        private bool l4UncorrectableTornMode;
        private bool lastFaultMarkedUncorrectable;
        private bool lastFaultInjected;
        private bool faultEverFired;

        private ulong uncorrectableReadCount;
        private ulong lastUncorrectableReadWordAddress;
        private ulong lastUncorrectableReadAddress;
        private ulong lastUncorrectableReadPC;

        private ulong configuredTrackingStartAddress;
        private ulong trackingStartAddress;
        private bool trackingStarted = true;
        private bool startHookInstalled;
        private bool memoryAccessHookInstalled;
        private ulong trackingStopAddress;
        private bool trackingStopHit;
        private ulong trackingStopWrites;
        private ulong trackingStopErases;
        private bool stopHookInstalled;

        private const long DefaultFlashBaseAddress = 0x08000000;
        private const long DefaultFlashSize = 0x100000;
        private const int DefaultPageSize = 0x800;
        private const int DoubleWordSize = 8;
        private const int FastRowDoubleWords = 32;
        private const int FastRowWords = FastRowDoubleWords * 2;
        private const int FastRowBytes = FastRowDoubleWords * DoubleWordSize;

        private const uint PdKey1 = 0x04152637;
        private const uint PdKey2 = 0xFAFBFCFD;
        private const uint UnlockKey1 = 0x45670123;
        private const uint UnlockKey2 = 0xCDEF89AB;
        private const uint OptUnlockKey1 = 0x08192A3B;
        private const uint OptUnlockKey2 = 0x4C5D6E7F;

        private const uint ResetAcr = 0x00000600;
        private const uint ResetCr = 0xC0000000;
        private const uint ResetOptr = 0xFFEFF8AA;

        private const uint AcrLatencyMask = 0x07;
        private const uint AcrPrftenBit = 1u << 8;
        private const uint AcrIcenBit = 1u << 9;
        private const uint AcrDcenBit = 1u << 10;
        private const uint AcrIcrstBit = 1u << 11;
        private const uint AcrDcrstBit = 1u << 12;
        private const uint AcrRunPdBit = 1u << 13;
        private const uint AcrSleepPdBit = 1u << 14;

        private const uint SrEopBit = 1u << 0;
        private const uint SrOperrBit = 1u << 1;
        private const uint SrProgerrBit = 1u << 3;
        private const uint SrWrperrBit = 1u << 4;
        private const uint SrPgaerrBit = 1u << 5;
        private const uint SrSizerrBit = 1u << 6;
        private const uint SrPgserrBit = 1u << 7;
        private const uint SrMiserrBit = 1u << 8;
        private const uint SrFasterrBit = 1u << 9;
        private const uint SrRderrBit = 1u << 14;
        private const uint SrOptverrBit = 1u << 15;
        private const uint SrBsyBit = 1u << 16;
        private const uint SrProgramEraseErrorMask = SrOperrBit | SrProgerrBit | SrWrperrBit
                                                   | SrPgaerrBit | SrSizerrBit | SrPgserrBit
                                                   | SrMiserrBit | SrFasterrBit;
        private const uint SrRcW1Mask = SrEopBit | SrOperrBit | SrProgerrBit | SrWrperrBit
                                      | SrPgaerrBit | SrSizerrBit | SrPgserrBit | SrMiserrBit
                                      | SrFasterrBit | SrRderrBit | SrOptverrBit;

        private const uint CrPgBit = 1u << 0;
        private const uint CrPerBit = 1u << 1;
        private const uint CrMer1Bit = 1u << 2;
        private const int CrPnbShift = 3;
        private const uint CrPnbMask = 0xFFu << CrPnbShift;
        private const uint CrBkerBit = 1u << 11;
        private const uint CrMer2Bit = 1u << 15;
        private const uint CrStrtBit = 1u << 16;
        private const uint CrOptstrtBit = 1u << 17;
        private const uint CrFstpgBit = 1u << 18;
        private const uint CrEopieBit = 1u << 24;
        private const uint CrErrieBit = 1u << 25;
        private const uint CrRderrieBit = 1u << 26;
        private const uint CrOblLaunchBit = 1u << 27;
        private const uint CrOptlockBit = 1u << 30;
        private const uint CrLockBit = 1u << 31;

        private const uint EccrAddrMask = 0x0007FFFFu;
        private const uint EccrBkEccBit = 1u << 19;
        private const uint EccrSysfEccBit = 1u << 20;
        private const uint EccrEccieBit = 1u << 24;
        private const uint EccrEcccBit = 1u << 30;
        private const uint EccrEccdBit = 1u << 31;

        private const uint OptrDualBankBit = 1u << 21;

        private sealed class UncorrectableReadEntry
        {
            public UncorrectableReadEntry(ulong index, long wordOffset, ulong wordBusAddress,
                                          ulong accessBusAddress, int width, ulong pc)
            {
                Index = index;
                WordOffset = wordOffset;
                WordBusAddress = wordBusAddress;
                AccessBusAddress = accessBusAddress;
                Width = width;
                PC = pc;
            }
            public readonly ulong Index;
            public readonly long WordOffset;
            public readonly ulong WordBusAddress;
            public readonly ulong AccessBusAddress;
            public readonly int Width;
            public readonly ulong PC;
        }

        private enum Registers : long
        {
            Acr = 0x00,
            Pdkeyr = 0x04,
            Keyr = 0x08,
            Optkeyr = 0x0C,
            Sr = 0x10,
            Cr = 0x14,
            Eccr = 0x18,
            Optr = 0x20,
            Pcrop1Sr = 0x24,
            Pcrop1Er = 0x28,
            Wrp1Ar = 0x2C,
            Wrp1Br = 0x30,
            Pcrop2Sr = 0x44,
            Pcrop2Er = 0x48,
            Wrp2Ar = 0x4C,
            Wrp2Br = 0x50,
        }
    }

    /// <summary>
    /// Minimal STM32L4 RCC stub at 0x40021000 that mirrors MSI/HSI/HSE/PLL/LSI/LSE
    /// enable bits to their ready status bits and SW[1:0] to SWS[1:0].
    /// </summary>
    public class STM32L4RCCStub : IDoubleWordPeripheral, IKnownSize
    {
        public STM32L4RCCStub()
        {
            Reset();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch(offset)
            {
                case 0x00: // RCC_CR
                {
                    uint val = cr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1;   // MSION -> MSIRDY
                    if((val & (1u << 8)) != 0) val |= 1u << 10;  // HSION -> HSIRDY
                    if((val & (1u << 16)) != 0) val |= 1u << 17; // HSEON -> HSERDY
                    if((val & (1u << 24)) != 0) val |= 1u << 25; // PLLON -> PLLRDY
                    if((val & (1u << 26)) != 0) val |= 1u << 27; // PLLSAI1ON -> PLLSAI1RDY
                    if((val & (1u << 28)) != 0) val |= 1u << 29; // PLLSAI2ON -> PLLSAI2RDY
                    return val;
                }
                case 0x08: // RCC_CFGR
                {
                    uint sw = cfgr & 0x3u;
                    return (cfgr & ~0xCu) | (sw << 2);
                }
                case 0x90: // RCC_BDCR
                {
                    uint val = bdcr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1;   // LSEON -> LSERDY
                    if((val & (1u << 11)) != 0) val |= 1u << 12; // LSESYSEN -> LSESYSRDY
                    return val;
                }
                case 0x94: // RCC_CSR
                {
                    uint val = csr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1; // LSION -> LSIRDY
                    return val;
                }
                case 0x98: // RCC_CRRCR
                {
                    uint val = crrcr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1; // HSI48ON -> HSI48RDY
                    return val;
                }
                default:
                    return regs.TryGetValue(offset, out var v) ? v : 0u;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch(offset)
            {
                case 0x00:
                    cr = value;
                    break;
                case 0x08:
                    cfgr = value;
                    break;
                case 0x90:
                    bdcr = value;
                    break;
                case 0x94:
                    csr = (value & (1u << 23)) != 0 ? (value & 0x00FFFFFFu) : value;
                    break;
                case 0x98:
                    crrcr = value;
                    break;
                default:
                    regs[offset] = value;
                    break;
            }
        }

        public void Reset()
        {
            cr = 0x00000063; // MSIRANGE=6 (4 MHz), MSIRDY=1, MSION=1
            cfgr = 0x00000000;
            bdcr = 0x00000000;
            csr = 0x0C000600;
            crrcr = 0x00000000;
            regs.Clear();
            regs[0x04] = 0x10000000; // ICSCR
            regs[0x0C] = 0x00001000; // PLLCFGR
            regs[0x48] = 0x00000100; // AHB1ENR: FLASHEN
        }

        public long Size => 0x400;

        private uint cr;
        private uint cfgr;
        private uint bdcr;
        private uint csr;
        private uint crrcr;
        private readonly Dictionary<long, uint> regs = new Dictionary<long, uint>();
    }

    public class STM32L4DeviceInfoStub : IDoubleWordPeripheral, IWordPeripheral, IKnownSize
    {
        public STM32L4DeviceInfoStub(uint flashSizeKiB = 1024)
        {
            this.flashSizeKiB = flashSizeKiB & 0xFFFFu;
        }

        public uint ReadDoubleWord(long offset)
        {
            return offset == 0xE0 ? flashSizeKiB : 0u;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
        }

        public ushort ReadWord(long offset)
        {
            return offset == 0xE0 ? (ushort)flashSizeKiB : (ushort)0;
        }

        public void WriteWord(long offset, ushort value)
        {
        }

        public void Reset()
        {
        }

        public long Size => 0x100;

        private readonly uint flashSizeKiB;
    }
}
