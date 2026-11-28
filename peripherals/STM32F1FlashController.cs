// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.Linq;
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
    /// STM32F1 internal Flash program/erase controller (FPEC) at 0x40022000
    /// modeled from RM0008 / PM0075 with Tardigrade fault injection and
    /// operation-accurate half-word (16-bit) write and page/mass erase tracing.
    ///
    /// Key hardware behaviors modeled from RM0008 / PM0075:
    /// - Half-word (16-bit) programming when unlocked (FLASH_CR.LOCK == 0) and
    ///   FLASH_CR.PG == 1.
    /// - Attempting to program a half-word that is not erased (!= 0xFFFF) fails
    ///   with FLASH_SR.PGERR (bit 2) and leaves the existing half-word intact
    ///   rather than ANDing bits.
    /// - Page erase (1 KiB or 2 KiB pages via PageSize) triggered by setting
    ///   FLASH_CR.PER = 1, writing the target address to FLASH_AR, and setting
    ///   FLASH_CR.STRT = 1.
    /// - Mass erase triggered by setting FLASH_CR.MER = 1 and FLASH_CR.STRT = 1.
    /// - Unlock sequence via FLASH_KEYR (KEY1 = 0x45670123, KEY2 = 0xCDEF89AB)
    ///   and option byte unlock via FLASH_OPTKEYR.
    /// </summary>
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public class STM32F1FlashController : IDoubleWordPeripheral, IKnownSize, ITardigradeFaultInjectable
    {
        public STM32F1FlashController(IMachine machine, MappedMemory flash = null,
                                      long flashBaseAddress = DefaultFlashBaseAddress,
                                      long flashSize = DefaultFlashSize,
                                      int pageSize = DefaultPageSize,
                                      byte eraseFill = 0xFF)
        {
            this.machine = machine;
            tracker.Bind(machine, this);
            this.flash = flash;
            this.flashBaseAddress = flashBaseAddress;
            this.flashSize = flashSize;
            this.pageSize = pageSize > 0 ? pageSize : DefaultPageSize;
            this.eraseFill = eraseFill;
            IRQ = new GPIO();

            var regMap = new Dictionary<long, DoubleWordRegister>
            {
                {(long)Registers.Acr, new DoubleWordRegister(this, ResetAcr)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => acr,
                        writeCallback: (_, val) => WriteAcr((uint)val),
                        name: "ACR")
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
                        valueProviderCallback: _ => sr & ~SrBsyBit,
                        writeCallback: (_, val) => WriteSr((uint)val),
                        name: "SR")
                },
                {(long)Registers.Cr, new DoubleWordRegister(this, ResetCr)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => cr,
                        writeCallback: (_, val) => WriteCr((uint)val),
                        name: "CR")
                },
                {(long)Registers.Ar, new DoubleWordRegister(this)
                    .WithValueField(0, 32,
                        valueProviderCallback: _ => ar,
                        writeCallback: (_, val) => WriteAr((uint)val),
                        name: "AR")
                },
                {(long)Registers.Obr, new DoubleWordRegister(this, ResetObr)
                    .WithValueField(0, 32, FieldMode.Read,
                        valueProviderCallback: _ => obr,
                        name: "OBR")
                },
                {(long)Registers.Wrpr, new DoubleWordRegister(this, ResetWrpr)
                    .WithValueField(0, 32, FieldMode.Read,
                        valueProviderCallback: _ => wrpr,
                        name: "WRPR")
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
            acr = ResetAcr;
            sr = 0;
            cr = ResetCr;
            ar = 0;
            obr = ResetObr;
            wrpr = ResetWrpr;
            keyUnlockStep = 0;
            optKeyUnlockStep = 0;
            keyLockedUntilReset = false;
            optKeyLockedUntilReset = false;
            writePowerLossLatched = false;
            RemoveStartHook();
            RemoveStopHook();
            trackingStopHit = false;
            trackingStopWrites = 0;
            trackingStopErases = 0;
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
            tracker.LastFaultPC = 0;
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

        public GPIO IRQ { get; }
        public long Size => 0x400;

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

        public int ProgramUnitSize => HalfWordSize;

        public byte EraseFill
        {
            get => eraseFill;
            set => eraseFill = value;
        }

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
            get => tracker.TornWordMode;
            set => tracker.TornWordMode = value;
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
            var writable = value & (AcrLatencyMask | AcrHlfcyaBit | AcrPrftbeBit);
            var prftbs = (writable & AcrPrftbeBit) != 0 ? AcrPrftbsBit : 0u;
            acr = writable | prftbs;
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
            cr = (cr & ~CrPgBit) | CrLockBit;
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
                if(value == UnlockKey1)
                {
                    optKeyUnlockStep = 1;
                    return;
                }
                optKeyUnlockStep = 0;
                optKeyLockedUntilReset = true;
                cr &= ~CrOptwreBit;
                RaiseBusError();
                return;
            }
            if(value == UnlockKey2)
            {
                if((cr & CrLockBit) == 0)
                {
                    cr |= CrOptwreBit;
                }
                optKeyUnlockStep = 0;
                return;
            }
            optKeyUnlockStep = 0;
            optKeyLockedUntilReset = true;
            cr &= ~CrOptwreBit;
            RaiseBusError();
        }

        private void WriteSr(uint value)
        {
            var clearMask = value & (SrPgerrBit | SrWrprterrBit | SrEopBit);
            sr &= ~clearMask;
            UpdateInterrupts();
        }

        private void WriteCr(uint value)
        {
            if((cr & CrLockBit) != 0 || keyLockedUntilReset)
            {
                this.Log(LogLevel.Warning, "STM32F1 FLASH_CR write ignored while LOCK=1 (value=0x{0:X8})", value);
                return;
            }

            var optwre = (cr & CrOptwreBit) != 0 && (value & CrOptwreBit) != 0
                ? CrOptwreBit
                : 0u;
            var lockBit = (value & CrLockBit) != 0 ? CrLockBit : 0u;
            var writableMask = CrPgBit | CrPerBit | CrMerBit | CrOptpgBit | CrOpterBit | CrStrtBit | CrErrieBit | CrEopieBit;
            cr = (value & writableMask) | optwre | lockBit;

            if((cr & CrStrtBit) != 0 && (cr & CrLockBit) == 0)
            {
                if((cr & CrPerBit) != 0)
                {
                    ExecutePageErase(ar);
                }
                else if((cr & CrMerBit) != 0)
                {
                    ExecuteMassErase();
                }
                else if((cr & CrOpterBit) != 0 && (cr & CrOptwreBit) != 0)
                {
                    sr |= SrEopBit;
                }
                cr &= ~CrStrtBit;
            }

            UpdateMemoryHooks();
            UpdateInterrupts();
        }

        private void WriteAr(uint value)
        {
            if((cr & CrLockBit) != 0)
            {
                return;
            }
            ar = value;
        }

        private void ExecutePageErase(uint pageAddress)
        {
            if(flash == null || flashSize <= 0)
            {
                return;
            }
            if(!passthroughMode && (tracker.EraseFaultFired || writePowerLossLatched))
            {
                return;
            }

            long offset;
            if(pageAddress >= (ulong)flashBaseAddress && pageAddress < (ulong)(flashBaseAddress + flashSize))
            {
                offset = (long)pageAddress - flashBaseAddress;
            }
            else if(pageAddress < (ulong)flashSize)
            {
                offset = pageAddress;
            }
            else
            {
                this.Log(LogLevel.Warning, "STM32F1 page erase address 0x{0:X8} is outside flash", pageAddress);
                return;
            }

            var pageBase = (offset / pageSize) * pageSize;
            var eraseLen = (int)Math.Min(pageSize, flashSize - pageBase);
            if(eraseLen <= 0)
            {
                return;
            }

            EnsureShadow();
            if(!trackingStarted)
            {
                FillFlashAndShadow(pageBase, eraseLen, eraseFill);
                sr |= SrEopBit;
                return;
            }

            var shouldFault = tracker.RecordEraseAndCheckFault(pageBase, eraseLen, GetCurrentCpuPC());
            var eraseIndex = tracker.TotalPageErases;

            if(!passthroughMode && shouldFault)
            {
                ApplyEraseFault(pageBase, eraseLen, eraseIndex);
                return;
            }

            FillFlashAndShadow(pageBase, eraseLen, eraseFill);
            sr |= SrEopBit;
        }

        private void ExecuteMassErase()
        {
            if(flash == null || flashSize <= 0)
            {
                return;
            }
            if(!passthroughMode && (tracker.EraseFaultFired || writePowerLossLatched))
            {
                return;
            }

            EnsureShadow();
            var totalLen = (int)flashSize;
            if(!trackingStarted)
            {
                FillFlashAndShadow(0, totalLen, eraseFill);
                sr |= SrEopBit;
                return;
            }

            var shouldFault = tracker.RecordEraseAndCheckFault(0, totalLen, GetCurrentCpuPC());
            var eraseIndex = tracker.TotalPageErases;

            if(!passthroughMode && shouldFault)
            {
                ApplyEraseFault(0, totalLen, eraseIndex);
                return;
            }

            FillFlashAndShadow(0, totalLen, eraseFill);
            sr |= SrEopBit;
        }

        private void ApplyEraseFault(long regionBase, int regionLength, ulong eraseIndex)
        {
            var previousBytes = flash.ReadBytes(regionBase, regionLength);
            EnsureShadow();
            Array.Copy(previousBytes, 0, flashShadow, (int)regionBase, regionLength);

            if(tracker.EraseFaultMode == 1)
            {
                var halfLen = Math.Max(1, regionLength / 2);
                FillFlashAndShadow(regionBase, halfLen, eraseFill);

                var neighborOffset = regionBase + regionLength;
                if(neighborOffset < flashSize)
                {
                    var neighborLen = (int)Math.Min(Math.Max(1, regionLength / 4), flashSize - neighborOffset);
                    FillFlashAndShadow(neighborOffset, neighborLen, eraseFill);
                }
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
                        HalfWordSize,
                        neutralMode,
                        seed,
                        eraseIndex);
                    WriteFlashAndShadow(regionBase, tornBytes);
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
                    }
                    else if(tornMode == "corrupted")
                    {
                        var corrupted = tracker.BuildCorruptedErasedSpan(regionBase, regionLength, eraseFill, HalfWordSize);
                        WriteFlashAndShadow(regionBase, corrupted);
                    }
                    else
                    {
                        FillFlashAndShadow(regionBase, Math.Max(1, regionLength / 2), eraseFill);
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
            if((operation != MemoryOperation.MemoryWrite && operation != MemoryOperation.MemoryIOWrite)
               || width == 0 || flash == null)
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

            if((cr & CrLockBit) != 0 || (cr & CrPgBit) == 0)
            {
                RevertFromShadow(offset, (int)Math.Min(width, 8u));
                this.Log(LogLevel.Warning,
                    "STM32F1 flash write at 0x{0:X8} rejected (LOCK={1}, PG={2})",
                    flashBaseAddress + offset,
                    (cr & CrLockBit) != 0 ? 1 : 0,
                    (cr & CrPgBit) != 0 ? 1 : 0);
                return;
            }

            if(width == 2 && (offset & 1) == 0)
            {
                tracker.PendingPC = pc != 0 ? pc : GetCurrentCpuPC();
                ProcessHalfWordProgram(offset, (ushort)(value & 0xFFFF));
                return;
            }

            // PM0075 §2.3.3: any attempt to write a byte or a word (or an
            // unaligned half-word) while PG=1 results in a bus error, not
            // half-word programming or PGERR.
            RevertFromShadow(offset, (int)Math.Min(width, 8u));
            RaiseBusError();
        }

        private void ProcessHalfWordProgram(long offset, ushort newHalfWord)
        {
            if(offset < 0 || offset + HalfWordSize > flashSize)
            {
                return;
            }

            var oldHalfWord = ReadShadowHalfWord(offset);

            // RM0008 / PM0075 §2.3.3: attempting to program a half-word that is not
            // erased (0xFFFF) fails with PGERR in FLASH_SR rather than ANDing bits,
            // except when programming 0x0000.
            if(oldHalfWord != 0xFFFF && newHalfWord != 0x0000)
            {
                WriteFlashHalfWord(offset, oldHalfWord);
                sr |= SrPgerrBit;
                UpdateInterrupts();
                this.Log(LogLevel.Warning,
                    "STM32F1 PGERR at offset 0x{0:X}: destination half-word 0x{1:X4} is not erased (0xFFFF)",
                    offset, oldHalfWord);
                return;
            }

            if(!trackingStarted)
            {
                WriteFlashAndShadowHalfWord(offset, newHalfWord);
                sr |= SrEopBit;
                UpdateInterrupts();
                return;
            }

            var shouldFault = tracker.RecordWriteAndCheckFault((int)offset, newHalfWord, HalfWordSize);
            var writeIndex = tracker.TotalWordWrites;

            if(!passthroughMode && shouldFault)
            {
                ApplyWriteFault(offset, oldHalfWord, newHalfWord, writeIndex);
                return;
            }

            WriteFlashAndShadowHalfWord(offset, newHalfWord);
            sr |= SrEopBit;
            UpdateInterrupts();
        }

        private void ApplyWriteFault(long offset, ushort oldHalfWord, ushort newHalfWord, ulong writeIndex)
        {
            tracker.FaultFired = true;
            lastFaultInjected = true;
            faultEverFired = true;
            tracker.LastFaultAddress = (uint)(flashBaseAddress + offset);

            switch(tracker.WriteFaultMode)
            {
                case 0: // power_loss
                {
                    var seed = tracker.TornWordSeed != 0 ? tracker.TornWordSeed : tracker.CorruptionSeed;
                    var tornValue = (ushort)FaultTracker.BuildFlashTornProgramValue(
                        oldHalfWord,
                        newHalfWord,
                        HalfWordSize,
                        eraseFill,
                        tracker.TornWordMode,
                        seed,
                        writeIndex,
                        offset);
                    WriteFlashAndShadowHalfWord(offset, tornValue);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    writePowerLossLatched = true;
                    UpdateMemoryHooks();
                    break;
                }
                case 1: // bit_corruption
                {
                    var seed = tracker.BuildFaultSeed((int)offset);
                    var keepMask = (ushort)FaultTracker.NextLcg(ref seed);
                    var bitsToFlip = (ushort)(oldHalfWord & ~newHalfWord);
                    var corrupted = (ushort)(oldHalfWord & ~(bitsToFlip & keepMask));
                    WriteFlashAndShadowHalfWord(offset, corrupted);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    sr |= SrEopBit;
                    UpdateInterrupts();
                    break;
                }
                case 2: // silent_write_failure
                {
                    var silentValue = (writeIndex & 1) == 0 ? (ushort)0xFFFF : (ushort)0x0000;
                    WriteFlashAndShadowHalfWord(offset, silentValue);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    sr |= SrEopBit;
                    UpdateInterrupts();
                    break;
                }
                case 3: // write_rejection
                {
                    WriteFlashAndShadowHalfWord(offset, oldHalfWord);
                    sr |= SrPgerrBit;
                    UpdateInterrupts();
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
                case 4: // write_disturb
                {
                    WriteFlashAndShadowHalfWord(offset, newHalfWord);
                    var seed = tracker.BuildFaultSeed((int)offset);
                    foreach(var neighborOff in new[] { offset - HalfWordSize, offset + HalfWordSize })
                    {
                        if(neighborOff < 0 || neighborOff + HalfWordSize > flashSize)
                        {
                            continue;
                        }
                        var neighborWord = ReadShadowHalfWord(neighborOff);
                        var disturbBits = (ushort)(FaultTracker.NextLcg(ref seed) & 0x1111u);
                        WriteFlashAndShadowHalfWord(neighborOff, (ushort)(neighborWord & ~disturbBits));
                    }
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    sr |= SrEopBit;
                    UpdateInterrupts();
                    break;
                }
                case 5: // wear_leveling_corruption
                {
                    WriteFlashAndShadowHalfWord(offset, newHalfWord);
                    var pageStart = (offset / pageSize) * pageSize;
                    var halfWordsPerPage = Math.Max(1, pageSize / HalfWordSize);
                    var errorCount = 2 + (int)Math.Min(10UL, tracker.TotalPageErases / 8);
                    var seed = tracker.BuildFaultSeed((int)offset);
                    for(var i = 0; i < errorCount; i++)
                    {
                        var idx = (int)(FaultTracker.NextLcg(ref seed) % (uint)halfWordsPerPage);
                        var targetOff = pageStart + (long)idx * HalfWordSize;
                        if(targetOff < 0 || targetOff + HalfWordSize > flashSize)
                        {
                            continue;
                        }
                        var word = ReadShadowHalfWord(targetOff);
                        var mask = (ushort)(FaultTracker.NextLcg(ref seed) & 0x0101u);
                        if(mask == 0)
                        {
                            mask = (ushort)(1u << (int)(FaultTracker.NextLcg(ref seed) % 16u));
                        }
                        WriteFlashAndShadowHalfWord(targetOff, (ushort)(word & ~mask));
                    }
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    sr |= SrEopBit;
                    UpdateInterrupts();
                    break;
                }
                case 6: // driver_error
                {
                    WriteFlashAndShadowHalfWord(offset, oldHalfWord);
                    tracker.DriverErrorFired = true;
                    sr |= SrPgerrBit;
                    UpdateInterrupts();
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
                default:
                {
                    WriteFlashAndShadowHalfWord(offset, oldHalfWord);
                    FaultFlashSnapshot = flash.ReadBytes(0, (int)flashSize);
                    break;
                }
            }
        }

        private void UpdateInterrupts()
        {
            var errPending = (cr & CrErrieBit) != 0 && (sr & (SrPgerrBit | SrWrprterrBit)) != 0;
            var eopPending = (cr & CrEopieBit) != 0 && (sr & SrEopBit) != 0;
            if(errPending || eopPending)
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

        private ushort ReadShadowHalfWord(long offset)
        {
            EnsureShadow();
            return (ushort)(flashShadow[offset] | (flashShadow[offset + 1] << 8));
        }

        private void WriteFlashHalfWord(long offset, ushort value)
        {
            var bytes = new[] { (byte)(value & 0xFF), (byte)((value >> 8) & 0xFF) };
            flash.WriteBytes(offset, bytes, 0, bytes.Length);
        }

        private void WriteFlashAndShadowHalfWord(long offset, ushort value)
        {
            EnsureShadow();
            var b0 = (byte)(value & 0xFF);
            var b1 = (byte)((value >> 8) & 0xFF);
            flashShadow[offset] = b0;
            flashShadow[offset + 1] = b1;
            var bytes = new[] { b0, b1 };
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

        private readonly IMachine machine;
        private readonly DoubleWordRegisterCollection registers;
        private readonly FaultTracker tracker = new FaultTracker();

        private MappedMemory flash;
        private long flashBaseAddress;
        private long flashSize;
        private int pageSize;
        private byte eraseFill;
        private byte[] flashShadow;

        private uint acr;
        private uint sr;
        private uint cr;
        private uint ar;
        private uint obr;
        private uint wrpr;
        private int keyUnlockStep;
        private int optKeyUnlockStep;
        private bool keyLockedUntilReset;
        private bool optKeyLockedUntilReset;
        private bool passthroughMode;
        private bool writePowerLossLatched;
        private bool lastFaultInjected;
        private bool faultEverFired;

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
        private const long DefaultFlashSize = 0x20000;
        private const int DefaultPageSize = 0x400;
        private const int HalfWordSize = 2;

        private const uint UnlockKey1 = 0x45670123;
        private const uint UnlockKey2 = 0xCDEF89AB;

        private const uint ResetAcr = 0x00000030;
        private const uint ResetCr = 0x00000080;
        private const uint ResetObr = 0x03FFFFFC;
        private const uint ResetWrpr = 0xFFFFFFFF;

        private const uint AcrLatencyMask = 0x07;
        private const uint AcrHlfcyaBit = 1u << 3;
        private const uint AcrPrftbeBit = 1u << 4;
        private const uint AcrPrftbsBit = 1u << 5;

        private const uint SrBsyBit = 1u << 0;
        private const uint SrPgerrBit = 1u << 2;
        private const uint SrWrprterrBit = 1u << 4;
        private const uint SrEopBit = 1u << 5;

        private const uint CrPgBit = 1u << 0;
        private const uint CrPerBit = 1u << 1;
        private const uint CrMerBit = 1u << 2;
        private const uint CrOptpgBit = 1u << 4;
        private const uint CrOpterBit = 1u << 5;
        private const uint CrStrtBit = 1u << 6;
        private const uint CrLockBit = 1u << 7;
        private const uint CrOptwreBit = 1u << 9;
        private const uint CrErrieBit = 1u << 10;
        private const uint CrEopieBit = 1u << 12;

        private enum Registers : long
        {
            Acr = 0x00,
            Keyr = 0x04,
            Optkeyr = 0x08,
            Sr = 0x0C,
            Cr = 0x10,
            Ar = 0x14,
            Obr = 0x1C,
            Wrpr = 0x20,
        }
    }

    /// <summary>
    /// Minimal STM32F1 RCC stub at 0x40021000 that mirrors oscillator enable
    /// bits to their ready status bits and SW[1:0] to SWS[1:0].
    /// </summary>
    public class STM32F1RCCStub : IDoubleWordPeripheral, IKnownSize
    {
        public STM32F1RCCStub()
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
                    if((val & (1u << 0)) != 0) val |= 1u << 1;   // HSION -> HSIRDY
                    if((val & (1u << 16)) != 0) val |= 1u << 17; // HSEON -> HSERDY
                    if((val & (1u << 24)) != 0) val |= 1u << 25; // PLLON -> PLLRDY
                    if((val & (1u << 26)) != 0) val |= 1u << 27; // PLL2ON -> PLL2RDY
                    if((val & (1u << 28)) != 0) val |= 1u << 29; // PLL3ON -> PLL3RDY
                    return val;
                }
                case 0x04: // RCC_CFGR
                {
                    uint sw = cfgr & 0x3u;
                    return (cfgr & ~0xCu) | (sw << 2);
                }
                case 0x20: // RCC_BDCR
                {
                    uint val = bdcr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1; // LSEON -> LSERDY
                    return val;
                }
                case 0x24: // RCC_CSR
                {
                    uint val = csr;
                    if((val & (1u << 0)) != 0) val |= 1u << 1; // LSION -> LSIRDY
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
                case 0x04:
                    cfgr = value;
                    break;
                case 0x20:
                    bdcr = value;
                    break;
                case 0x24:
                    csr = (value & (1u << 24)) != 0 ? (value & 0x00FFFFFFu) : value;
                    break;
                default:
                    regs[offset] = value;
                    break;
            }
        }

        public void Reset()
        {
            cr = 0x00000083;   // HSION=1, HSIRDY=1, HSITRIM=16
            cfgr = 0x00000000;
            bdcr = 0x00000000;
            csr = 0x0C000000;
            regs.Clear();
            regs[0x14] = 0x00000014; // AHBENR: FLITFEN | SRAMEN
        }

        public long Size => 0x400;

        private uint cr;
        private uint cfgr;
        private uint bdcr;
        private uint csr;
        private readonly Dictionary<long, uint> regs = new Dictionary<long, uint>();
    }

    public class STM32F1DeviceInfoStub : IDoubleWordPeripheral, IWordPeripheral, IKnownSize
    {
        public STM32F1DeviceInfoStub(uint flashSizeKiB = 128)
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
