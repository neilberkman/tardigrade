// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// STM32H7 FLASH controller for tardigrade fault injection.
//
// This controller keeps the STM32H7 register/lock/programming model close to
// Renode's built-in MTD.STM32H7_FlashController, but also exposes the same
// fault-injection API as the repo's other fast-path controllers:
//   - TotalWordWrites / FaultAtWordWrite / FaultFired
//   - TotalPageErases / FaultAtPageErase / EraseFaultFired
//   - WriteTrace / EraseTrace export
//   - Flash / FlashBaseAddress / FlashSize / PageSize / EraseFill
//
// Unlike STM32F4, H7 uses two flash banks and a 32-byte programming buffer.
// The CPU memory-access hook includes the written value, so we can track the
// actual programmed words directly without shadow diffing.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Logging.Profiling;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.MTD;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public class STM32H7FlashController : STM32_FlashController, IKnownSize, ITardigradeFaultInjectable
    {
        private readonly FaultTracker tracker = new FaultTracker();

        public STM32H7FlashController(IMachine machine, MappedMemory flash1, MappedMemory flash2) : base(machine)
        {
            this.flash1 = flash1;
            this.flash2 = flash2;
            flash1Size = flash1.Size;
            Flash = new DualBankFlashView(machine, flash1, flash2);

            banks = new Bank[NrOfBanks]
            {
                new Bank(this, 1, flash1, 0),
                new Bank(this, 2, flash2, flash1Size),
            };

            optionControlLock = new LockRegister(this, nameof(optionControlLock), OptionControlKey);

            FlashBaseAddress = 0x08000000;
            FlashSize = flash1.Size + flash2.Size;
            PageSize = Bank.SectorSize;
            EraseFill = 0xFF;

            DefineRegisters();
            Reset();
        }

        public override void Reset()
        {
            base.Reset();
            foreach(var bank in banks)
            {
                bank.Reset();
            }
            optionControlLock.Reset();
            optionStatusCurrentValue = 0;
            tracker.Reset();
            flashShadow = null;
            ProgramCurrentValues();
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            if(optionControlLock.IsLocked && IsOffsetToProgramRegister(offset))
            {
                this.Log(LogLevel.Warning, "Attempted to write to a program register ({0}) while OPTLOCK bit is set. Ignoring", Enum.GetName(typeof(Registers), (Registers)offset));
                return;
            }
            base.WriteDoubleWord(offset, value);
        }

        public GPIO IRQ { get; } = new GPIO();

        public long Size => 0x1000;

        public DualBankFlashView Flash { get; }

        IMemory ITardigradeFaultInjectable.Flash => Flash;

        public long FlashBaseAddress { get; set; }

        public long FlashSize { get; set; }

        public int PageSize { get; set; }

        public byte EraseFill { get; set; }

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }

        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }

        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }

        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }

        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }

        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }

        public bool AnyFaultFired => tracker.AnyFaultFired;

        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }

        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }

        public int DiffLookahead { get; set; } = 32;

        public bool PerWriteAccurate => true;

        public bool SkipShadowScan { get; set; }

        public int WriteFaultMode { get => tracker.WriteFaultMode; set => tracker.WriteFaultMode = value; }

        public int EraseFaultMode { get => tracker.EraseFaultMode; set => tracker.EraseFaultMode = value; }

        public uint CorruptionSeed { get => tracker.CorruptionSeed; set => tracker.CorruptionSeed = value; }

        public bool WriteTraceEnabled { get => tracker.WriteTraceEnabled; set => tracker.WriteTraceEnabled = value; }

        public int WriteTraceCount => tracker.WriteTraceCount;

        public string WriteTraceToString() => tracker.WriteTraceToString();

        public void WriteTraceClear() => tracker.WriteTraceClear();

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }

        public int EraseTraceCount => tracker.EraseTraceCount;

        public string EraseTraceToString() => tracker.EraseTraceToString();

        public void EraseTraceClear() => tracker.EraseTraceClear();

        public void InvalidateShadow()
        {
            flashShadow = null;
        }

        private void DefineRegisters()
        {
            Registers.AccessControl.Define(this, 0x37)
                .WithValueField(0, 4, name: "LATENCY")
                .WithValueField(4, 2, name: "WRHIGHFREQ")
                .WithReservedBits(6, 26);

            Registers.OptionKey.Define(this)
                .WithValueField(0, 32, FieldMode.Write, name: "FLASH_OPTKEYR",
                    writeCallback: (_, value) => optionControlLock.ConsumeValue((uint)value));

            Registers.OptionControl.Define(this, 0x1)
                .WithFlag(0, FieldMode.Read | FieldMode.Set, name: "OPTLOCK", valueProviderCallback: _ => optionControlLock.IsLocked,
                    changeCallback: (_, value) =>
                    {
                        if(value)
                        {
                            optionControlLock.Lock();
                        }
                    })
                .WithFlag(1, FieldMode.Write, name: "OPTSTART", writeCallback: (_, value) =>
                    {
                        if(!value)
                        {
                            return;
                        }

                        if(optionControlLock.IsLocked)
                        {
                            this.Log(LogLevel.Warning, "Trying to start option byte change operation while the controller is locked. Ignoring");
                            return;
                        }

                        ProgramCurrentValues();
                    })
                .WithReservedBits(2, 2)
                .WithFlag(4, name: "MER",
                        valueProviderCallback: _ => false,
                        writeCallback: (_, val) => { if(val) MassErase(); })
                .WithReservedBits(5, 25)
                .WithTaggedFlag("OPTCHANGEERRIE", 30)
                .WithTaggedFlag("SWAP_BANK", 31);

            Registers.OptionStatusCurrent.Define(this)
                .WithValueField(0, 32, FieldMode.Read, name: "FLASH_OPTSR_CUR", valueProviderCallback: _ => optionStatusCurrentValue);

            Registers.OptionStatusProgram.Define(this, 0x406AAF0, false)
                .WithValueField(0, 32, out optionStatusProgramRegister, name: "FLASH_OPTSR_PRG", softResettable: false);

            foreach(var bank in banks)
            {
                bank.DefineRegisters();
            }
        }

        private void TriggerError(int bankId, Error error)
        {
            if(bankId < 1 || bankId > NrOfBanks)
            {
                throw new RecoverableException($"Bank ID must be in range [1, {NrOfBanks}]. Ignoring operation.");
            }

            banks[bankId - 1].TriggerError(error);
        }

        private void UpdateInterrupts()
        {
            var irqStatus = banks.Any(bank => bank.IrqStatus);
            this.DebugLog("Set IRQ: {0}", irqStatus);
            IRQ.Set(irqStatus);
        }

        private void ProgramCurrentValues()
        {
            optionStatusCurrentValue = (uint)optionStatusProgramRegister.Value;
            foreach(var bank in banks)
            {
                bank.ProgramCurrentValues();
            }
        }

        private bool IsOffsetToProgramRegister(long offset)
        {
            switch((Registers)offset)
            {
            case Registers.ProtectionAddressProgramBank1:
            case Registers.ProtectionAddressProgramBank2:
            case Registers.BootAddressProgram:
            case Registers.OptionStatusProgram:
            case Registers.SecureAddressProgramBank1:
            case Registers.SecureAddressProgramBank2:
            case Registers.WriteSectorProtectionProgramBank1:
            case Registers.WriteSectorProtectionProgramBank2:
                return true;
            default:
                return false;
            }
        }

        private void MassErase()
        {
            foreach(var bank in banks)
            {
                bank.HandleMassErase();
            }
        }

        private void OnMemoryProgramWrite(ulong _, MemoryOperation operation, ulong __, ulong physicalAddress, uint width, ulong value)
        {
            if(operation != MemoryOperation.MemoryWrite)
            {
                return;
            }

            var writeTarget = machine.GetSystemBus(this).WhatIsAt(physicalAddress)?.Peripheral;
            foreach(var bank in banks)
            {
                bank.HandleMemoryProgramWrite(writeTarget, physicalAddress, width, value);
            }
        }

        private void HandleTrackedWrite(Bank bank, long localOffset, uint width, ulong value)
        {
            EnsureShadow();

            if(AnyFaultFired)
            {
                RestoreRangeFromShadow(bank.CombinedBaseOffset + localOffset, (int)width);
                return;
            }

            if(width == 0)
            {
                return;
            }

            var byteCount = (int)width;
            var combinedOffset = bank.CombinedBaseOffset + localOffset;
            var valueBytes = new byte[byteCount];
            for(var i = 0; i < byteCount; i++)
            {
                valueBytes[i] = (byte)((value >> (8 * i)) & 0xFF);
            }

            var cursor = 0;
            while(cursor < byteCount)
            {
                var chunkOffset = combinedOffset + cursor;
                var alignedOffset = chunkOffset & ~3L;
                var inWordOffset = (int)(chunkOffset - alignedOffset);
                var bytesInWord = Math.Min(4 - inWordOffset, byteCount - cursor);

                var oldWord = ReadWordFromShadow(alignedOffset);
                var newWord = oldWord;
                for(var i = 0; i < bytesInWord; i++)
                {
                    var shift = (inWordOffset + i) * 8;
                    newWord = (newWord & ~(0xFFu << shift))
                        | ((uint)valueBytes[cursor + i] << shift);
                }

                if(tracker.RecordWriteAndCheckFault((int)alignedOffset, newWord))
                {
                    FaultFired = true;
                    LastFaultAddress = (uint)(FlashBaseAddress + alignedOffset);
                    FaultFlashSnapshot = ReadFlashSnapshot();
                    ApplyWriteFault(alignedOffset, oldWord, newWord);

                    // Power loss after the fault point suppresses any remaining
                    // bytes from the same access as well.
                    cursor += bytesInWord;
                    while(cursor < byteCount)
                    {
                        var restOffset = (combinedOffset + cursor) & ~3L;
                        RestoreWordFromShadow(restOffset);
                        cursor += 4;
                    }
                    return;
                }

                UpdateShadowWord(alignedOffset);
                cursor += bytesInWord;
            }
        }

        private void HandleTrackedErase(Bank bank, long sectorOffset, int eraseSize)
        {
            EnsureShadow();

            if(tracker.RecordEraseAndCheckFault(bank.CombinedBaseOffset + sectorOffset, eraseSize))
            {
                EraseFaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + bank.CombinedBaseOffset + sectorOffset);

                if(EraseFaultMode == 1)
                {
                    var half = eraseSize / 2;
                    EraseRange(bank.CombinedBaseOffset + sectorOffset, half);
                    var nextStart = bank.CombinedBaseOffset + sectorOffset + eraseSize;
                    if(nextStart < FlashSize)
                    {
                        EraseRange(nextStart, Math.Min(eraseSize / 4, (int)(FlashSize - nextStart)));
                    }
                }
                else
                {
                    EraseRange(bank.CombinedBaseOffset + sectorOffset, eraseSize / 2);
                }
                FaultFlashSnapshot = ReadFlashSnapshot();
                return;
            }

            EraseRange(bank.CombinedBaseOffset + sectorOffset, eraseSize);
        }

        private void ApplyWriteFault(long alignedOffset, uint oldWord, uint newWord)
        {
            switch(WriteFaultMode)
            {
            case 1:
                WriteWordFault(alignedOffset, oldWord, ApplyBitCorruption(alignedOffset, oldWord, newWord));
                break;
            case 2:
            {
                var silentValue = ((TotalWordWrites & 1UL) == 0UL) ? 0xFFFFFFFFU : 0x00000000U;
                WriteWordFault(alignedOffset, oldWord, silentValue);
                break;
            }
            case 4:
                WriteWordFault(alignedOffset, oldWord, newWord);
                ApplyNeighborDisturb(alignedOffset);
                break;
            case 5:
                WriteWordFault(alignedOffset, oldWord, newWord);
                ApplyWearCorruption(alignedOffset);
                break;
            case 3:
            case 0:
            default:
                WriteWordFault(alignedOffset, oldWord, oldWord);
                break;
            }
        }

        private void WriteWordFault(long alignedOffset, uint shadowOldWord, uint value)
        {
            var bytes = FaultTracker.WordToBytes(value);
            Flash.WriteBytes(alignedOffset, bytes, 0, bytes.Length, this);
            WriteSnapshotBytes(alignedOffset, bytes);
            WriteShadowBytes(alignedOffset, bytes);
        }

        private void ApplyNeighborDisturb(long alignedOffset)
        {
            foreach(var offset in new[] { alignedOffset - 4, alignedOffset + 4 })
            {
                if(offset < 0 || offset + 4 > FlashSize)
                {
                    continue;
                }
                var oldWord = ReadWordFromShadow(offset);
                var disturbed = oldWord & 0xEEEEEEEEU;
                var bytes = FaultTracker.WordToBytes(disturbed);
                Flash.WriteBytes(offset, bytes, 0, bytes.Length, this);
                WriteSnapshotBytes(offset, bytes);
                WriteShadowBytes(offset, bytes);
            }
        }

        private void ApplyWearCorruption(long alignedOffset)
        {
            var pageStart = (alignedOffset / PageSize) * PageSize;
            var seed = tracker.BuildFaultSeed((int)alignedOffset);
            for(var i = 0; i < 4; i++)
            {
                var candidate = pageStart + ((long)(FaultTracker.NextLcg(ref seed) % (uint)PageSize) & ~3L);
                if(candidate < 0 || candidate + 4 > FlashSize)
                {
                    continue;
                }
                var oldWord = ReadWordFromShadow(candidate);
                var corrupted = oldWord & ~(1u << (int)(FaultTracker.NextLcg(ref seed) % 31));
                var bytes = FaultTracker.WordToBytes(corrupted);
                Flash.WriteBytes(candidate, bytes, 0, bytes.Length, this);
                WriteSnapshotBytes(candidate, bytes);
                WriteShadowBytes(candidate, bytes);
            }
        }

        private uint ApplyBitCorruption(long alignedOffset, uint oldWord, uint newWord)
        {
            var seed = tracker.BuildFaultSeed((int)alignedOffset);
            var keepMask = FaultTracker.NextLcg(ref seed);
            var bitsToFlip = oldWord & ~newWord;
            var actuallyFlipped = bitsToFlip & keepMask;
            return oldWord & ~actuallyFlipped;
        }

        private void EraseRange(long offset, int size)
        {
            if(size <= 0)
            {
                return;
            }
            var fill = new byte[size];
            for(var i = 0; i < size; i++)
            {
                fill[i] = EraseFill;
            }
            Flash.WriteBytes(offset, fill, 0, fill.Length, this);
            WriteShadowBytes(offset, fill);
        }

        private void RestoreRangeFromShadow(long offset, int size)
        {
            if(flashShadow == null || size <= 0)
            {
                return;
            }
            var start = Math.Max(0, (int)(offset & ~3L));
            var end = Math.Min((int)FlashSize, (int)(offset + size + 3) & ~3);
            if(end <= start)
            {
                return;
            }
            var len = end - start;
            var bytes = new byte[len];
            Array.Copy(flashShadow, start, bytes, 0, len);
            Flash.WriteBytes(start, bytes, 0, len, this);
        }

        private void RestoreWordFromShadow(long alignedOffset)
        {
            var oldWord = ReadWordFromShadow(alignedOffset);
            var bytes = FaultTracker.WordToBytes(oldWord);
            Flash.WriteBytes(alignedOffset, bytes, 0, bytes.Length, this);
        }

        private void EnsureShadow()
        {
            if(flashShadow == null)
            {
                flashShadow = ReadFlashSnapshot();
            }
        }

        private byte[] ReadFlashSnapshot()
        {
            return Flash.ReadBytes(0, checked((int)FlashSize));
        }

        private uint ReadWordFromShadow(long alignedOffset)
        {
            var off = (int)alignedOffset;
            return (uint)(flashShadow[off]
                | (flashShadow[off + 1] << 8)
                | (flashShadow[off + 2] << 16)
                | (flashShadow[off + 3] << 24));
        }

        private void UpdateShadowWord(long alignedOffset)
        {
            if(flashShadow == null)
            {
                return;
            }
            var bytes = Flash.ReadBytes(alignedOffset, 4);
            WriteShadowBytes(alignedOffset, bytes);
        }

        private void WriteShadowBytes(long offset, byte[] bytes)
        {
            if(flashShadow == null)
            {
                return;
            }
            Array.Copy(bytes, 0, flashShadow, (int)offset, bytes.Length);
        }

        private void WriteSnapshotBytes(long offset, byte[] bytes)
        {
            if(FaultFlashSnapshot == null)
            {
                return;
            }
            Array.Copy(bytes, 0, FaultFlashSnapshot, (int)offset, bytes.Length);
        }

        private uint optionStatusCurrentValue;
        private IValueRegisterField optionStatusProgramRegister;
        private readonly LockRegister optionControlLock;
        private readonly Bank[] banks;
        private readonly MappedMemory flash1;
        private readonly MappedMemory flash2;
        private readonly long flash1Size;
        private byte[] flashShadow;

        private static readonly uint[] ControlBankKey = { 0x45670123, 0xCDEF89AB };
        private static readonly uint[] OptionControlKey = { 0x08192A3B, 0x4C5D6E7F };
        private const int NrOfBanks = 2;

        public enum Error
        {
            ProgrammingSequence,
            Operation,
            SingleECC,
            DoubleECC,
            Inconsistency,
        }

        private class Bank
        {
            public Bank(STM32H7FlashController parent, int id, MappedMemory memory, long combinedBaseOffset)
            {
                this.parent = parent;
                this.Id = id;
                this.memory = memory;
                this.CombinedBaseOffset = combinedBaseOffset;

                controlBankLock = new LockRegister(parent, $"{nameof(controlBankLock)}{id}", ControlBankKey);
            }

            public void Reset()
            {
                controlBankLock.Reset();
                bankWriteBufferCounter = 0;
                bankWriteBufferAddress = 0;
            }

            public void ProgramCurrentValues()
            {
                bankWriteProtectionCurrentValue = (byte)bankWriteProtectionProgramRegister.Value;
            }

            public void HandleMassErase()
            {
                bankEraseRequest.Value = true;
                BankErase();
            }

            public void TriggerError(Error error)
            {
                switch(error)
                {
                case Error.ProgrammingSequence:
                    bankProgrammingErrorStatus.Value = true;
                    break;
                case Error.Operation:
                    bankOperationErrorStatus.Value = true;
                    break;
                case Error.SingleECC:
                    bankSingleEccErrorStatus.Value = true;
                    break;
                case Error.DoubleECC:
                    bankDoubleEccErrorStatus.Value = true;
                    break;
                case Error.Inconsistency:
                    bankInconsistencyErrorStatus.Value = true;
                    break;
                default:
                    parent.WarningLog("Invalid error type {0}. Ignoring operation.", error);
                    return;
                }
                parent.UpdateInterrupts();
            }

            public void HandleMemoryProgramWrite(IPeripheral writeTarget, ulong address, uint width, ulong value)
            {
                if(writeTarget != memory)
                {
                    return;
                }

                if(!bankWriteEnabled.Value || bankInconsistencyErrorStatus.Value)
                {
                    bankProgrammingErrorStatus.Value = true;
                    parent.UpdateInterrupts();
                    return;
                }

                var registration = parent.machine.GetSystemBus(parent).WhatIsAt(address);
                if(registration == null)
                {
                    return;
                }

                var localOffset = (long)(address - registration.RegistrationPoint.Range.StartAddress);

                if(bankWriteBufferCounter == 0)
                {
                    bankWriteBufferAddress = address;
                }
                else if(bankWriteBufferAddress + (ulong)bankWriteBufferCounter != address)
                {
                    bankInconsistencyErrorStatus.Value = true;
                    parent.UpdateInterrupts();
                    return;
                }

                parent.HandleTrackedWrite(this, localOffset, width, value);

                bankWriteBufferCounter += (int)width;
                if(bankWriteBufferCounter >= WriteBufferSize)
                {
                    if(bankWriteBufferCounter > WriteBufferSize)
                    {
                        parent.WarningLog("More than the required number of bytes (32 bytes) have been written to Flash Bank {0}", Id);
                    }
                    FinishProgramWrite();
                }
            }

            public void DefineRegisters()
            {
                var bankOffset = (Id - 1) * BanksOffset;

                (Registers.KeyBank1 + bankOffset).Define(parent)
                    .WithValueField(0, 32, FieldMode.Write, name: $"FLASH_KEYR{Id}",
                        writeCallback: (_, value) => controlBankLock.ConsumeValue((uint)value));

                (Registers.ControlBank1 + bankOffset).Define(parent, 0x31)
                    .WithFlag(0, FieldMode.Read | FieldMode.Set, name: $"LOCK{Id}",
                        valueProviderCallback: _ => controlBankLock.IsLocked,
                        changeCallback: (_, value) =>
                        {
                            if(value)
                            {
                                controlBankLock.Lock();
                            }
                        })
                    .WithFlag(1, out bankWriteEnabled, name: $"PG{Id}",
                        changeCallback: (_, val) => HandleProgramWriteEnableChange(val))
                    .WithFlag(2, out bankSectorEraseRequest, name: $"SER{Id}")
                    .WithFlag(3, out bankEraseRequest, name: $"BER{Id}")
                    .WithTag($"PSIZE{Id}", 4, 2)
                    .WithFlag(6, FieldMode.Set | FieldMode.Read, name: $"FW{Id}",
                        valueProviderCallback: _ => false,
                        writeCallback: (_, val) => { if(val) FinishProgramWrite(); })
                    .WithFlag(7, FieldMode.Set | FieldMode.Read, name: $"START{Id}",
                        valueProviderCallback: _ => false,
                        writeCallback: (_, val) => { if(val) BankErase(); })
                    .WithValueField(8, 3, out bankSectorEraseNumber, name: $"SNB{Id}")
                    .WithReservedBits(11, 4)
                    .WithTaggedFlag($"CRC_EN", 15)
                    .WithFlag(16, out bankEndOfProgramIrqEnabled, name: $"EOPIE{Id}")
                    .WithTaggedFlag($"WRPERRIE{Id}", 17)
                    .WithFlag(18, out bankProgrammingErrorIrqEnable, name: $"PGSERRIE{Id}")
                    .WithTaggedFlag($"STRBERRIE{Id}", 19)
                    .WithReservedBits(20, 1)
                    .WithFlag(21, out bankInconsistencyErrorIrqEnable, name: $"INCERRIE{Id}")
                    .WithFlag(22, out bankOperationErrorIrqEnable, name: $"OPERRIE{Id}")
                    .WithTaggedFlag($"RDPERRIE{Id}", 23)
                    .WithTaggedFlag($"RDSERRIE{Id}", 24)
                    .WithFlag(25, out bankSingleEccErrorIrqEnable, name: $"SNECCERRIE{Id}")
                    .WithFlag(26, out bankDoubleEccErrorIrqEnable, name: $"DBECCERRIE{Id}")
                    .WithTaggedFlag($"CRCENDIE{Id}", 27)
                    .WithTaggedFlag($"CRCRDERRIE{Id}", 28)
                    .WithReservedBits(29, 3);

                (Registers.StatusBank1 + bankOffset).Define(parent)
                    .WithTaggedFlag($"BSY{Id}", 0)
                    .WithFlag(1, FieldMode.Read, name: $"WBNE{Id}",
                        valueProviderCallback: _ => bankWriteEnabled.Value && bankWriteBufferCounter > 0)
                    .WithTaggedFlag($"QW{Id}", 2)
                    .WithTaggedFlag($"CRC_BUSY{Id}", 3)
                    .WithReservedBits(4, 12)
                    .WithFlag(16, out bankEndOfProgramIrqStatus, name: $"EOP{Id}")
                    .WithTaggedFlag($"WRPERR{Id}", 17)
                    .WithFlag(18, out bankProgrammingErrorStatus, FieldMode.Read, name: $"PGSERR{Id}")
                    .WithTaggedFlag($"STRBERR{Id}", 19)
                    .WithReservedBits(20, 1)
                    .WithFlag(21, out bankInconsistencyErrorStatus, FieldMode.Read, name: $"INCERR{Id}")
                    .WithFlag(22, out bankOperationErrorStatus, FieldMode.Read, name: $"OPERR{Id}")
                    .WithTaggedFlag($"RDPERR{Id}", 23)
                    .WithTaggedFlag($"RDSERR{Id}", 24)
                    .WithFlag(25, out bankSingleEccErrorStatus, FieldMode.Read, name: $"SNECCERR{Id}")
                    .WithFlag(26, out bankDoubleEccErrorStatus, FieldMode.Read, name: $"DBECCERR{Id}")
                    .WithTaggedFlag($"CRCEND{Id}", 27)
                    .WithReservedBits(28, 4);

                (Registers.ClearControlBank1 + bankOffset).Define(parent)
                    .WithReservedBits(0, 16)
                    .WithFlag(16, FieldMode.Set, name: $"CLR_EOP{Id}",
                        writeCallback: (_, val) => { if(val) bankEndOfProgramIrqStatus.Value = false; })
                    .WithTaggedFlag($"CLR_WRPERR{Id}", 17)
                    .WithFlag(18, FieldMode.Set, name: $"CLR_PGSERR{Id}",
                        writeCallback: (_, val) => { if(val) bankProgrammingErrorStatus.Value = false; })
                    .WithTaggedFlag($"CLR_STRBERR{Id}", 19)
                    .WithReservedBits(20, 1)
                    .WithFlag(21, FieldMode.Set, name: $"CLR_INCERR{Id}",
                        writeCallback: (_, val) => { if(val) bankInconsistencyErrorStatus.Value = false; })
                    .WithFlag(22, FieldMode.Set, name: $"CLR_OPERR{Id}",
                        writeCallback: (_, val) => { if(val) bankOperationErrorStatus.Value = false; })
                    .WithTaggedFlag($"CLR_RDPERR{Id}", 23)
                    .WithTaggedFlag($"CLR_RDSERR{Id}", 24)
                    .WithFlag(25, FieldMode.Set, name: $"CLR_SNECCERR{Id}",
                        writeCallback: (_, val) => { if(val) bankSingleEccErrorStatus.Value = false; })
                    .WithFlag(26, FieldMode.Set, name: $"CLR_DBECCERR{Id}",
                        writeCallback: (_, val) => { if(val) bankDoubleEccErrorStatus.Value = false; })
                    .WithTaggedFlag($"CLR_CRCEND{Id}", 27)
                    .WithReservedBits(28, 4)
                    .WithWriteCallback((_, __) => parent.UpdateInterrupts());

                (Registers.WriteSectorProtectionCurrentBank1 + bankOffset).Define(parent)
                    .WithValueField(0, 8, FieldMode.Read, name: $"WRPSn{Id}", valueProviderCallback: _ => bankWriteProtectionCurrentValue)
                    .WithReservedBits(8, 24);

                (Registers.WriteSectorProtectionProgramBank1 + bankOffset).Define(parent, 0xFF, false)
                    .WithValueField(0, 8, out bankWriteProtectionProgramRegister, name: $"WRPSn{Id}", softResettable: false)
                    .WithReservedBits(8, 24);
            }

            public int Id { get; }

            public long CombinedBaseOffset { get; }

            public bool IrqStatus => (bankEndOfProgramIrqEnabled.Value && bankEndOfProgramIrqStatus.Value)
                                     || (bankInconsistencyErrorIrqEnable.Value && bankInconsistencyErrorStatus.Value)
                                     || (bankProgrammingErrorIrqEnable.Value && bankProgrammingErrorStatus.Value)
                                     || (bankOperationErrorIrqEnable.Value && bankOperationErrorStatus.Value)
                                     || (bankSingleEccErrorIrqEnable.Value && bankSingleEccErrorStatus.Value)
                                     || (bankDoubleEccErrorIrqEnable.Value && bankDoubleEccErrorStatus.Value);

            public bool WriteEnabled => bankWriteEnabled.Value;

            private void BankErase()
            {
                if(bankEraseRequest.Value)
                {
                    parent.HandleTrackedErase(this, 0, (int)memory.Size);
                    bankEndOfProgramIrqStatus.Value = true;
                    parent.UpdateInterrupts();
                }
                else if(bankSectorEraseRequest.Value)
                {
                    var sectorIdx = bankSectorEraseNumber.Value;
                    var sectorStartAddr = (long)(sectorIdx * SectorSize);
                    parent.HandleTrackedErase(this, sectorStartAddr, SectorSize);
                    bankEndOfProgramIrqStatus.Value = true;
                    parent.UpdateInterrupts();
                }
                else
                {
                    parent.WarningLog("Trying to perform a bank erase operation but neither Bank Erase Request nor Sector Erase Request was selected.");
                }
            }

            private void HandleProgramWriteEnableChange(bool value)
            {
                var areOtherBanksInWriteState = parent.banks.Any(bank => bank.Id != Id && bank.WriteEnabled);
                if(!areOtherBanksInWriteState)
                {
                    var cpus = parent.machine.GetSystemBus(parent).GetCPUs().OfType<ICPUWithMemoryAccessHooks>();
                    foreach(var cpu in cpus)
                    {
                        cpu.SetHookAtMemoryAccess(value ? (MemoryAccessHook)parent.OnMemoryProgramWrite : null);
                    }
                }

                bankWriteBufferCounter = 0;
            }

            private void FinishProgramWrite()
            {
                bankWriteBufferCounter = 0;
                bankEndOfProgramIrqStatus.Value = true;
                parent.UpdateInterrupts();
            }

            private IValueRegisterField bankWriteProtectionProgramRegister;
            private IFlagRegisterField bankEraseRequest;
            private IFlagRegisterField bankSectorEraseRequest;
            private IValueRegisterField bankSectorEraseNumber;
            private IFlagRegisterField bankEndOfProgramIrqEnabled;
            private IFlagRegisterField bankEndOfProgramIrqStatus;
            private IFlagRegisterField bankWriteEnabled;
            private IFlagRegisterField bankInconsistencyErrorIrqEnable;
            private IFlagRegisterField bankInconsistencyErrorStatus;
            private IFlagRegisterField bankProgrammingErrorIrqEnable;
            private IFlagRegisterField bankProgrammingErrorStatus;
            private IFlagRegisterField bankOperationErrorIrqEnable;
            private IFlagRegisterField bankOperationErrorStatus;
            private IFlagRegisterField bankSingleEccErrorIrqEnable;
            private IFlagRegisterField bankSingleEccErrorStatus;
            private IFlagRegisterField bankDoubleEccErrorIrqEnable;
            private IFlagRegisterField bankDoubleEccErrorStatus;

            private byte bankWriteProtectionCurrentValue;
            private int bankWriteBufferCounter;
            private ulong bankWriteBufferAddress;

            private readonly STM32H7FlashController parent;
            private readonly MappedMemory memory;
            private readonly LockRegister controlBankLock;

            private const int BanksOffset = 0x100;
            public const int SectorSize = 0x20000;
            private const int WriteBufferSize = 32;
        }

        public class DualBankFlashView : IMemory
        {
            public DualBankFlashView(IMachine machine, MappedMemory bank1, MappedMemory bank2)
            {
                this.machine = machine;
                this.bank1 = bank1;
                this.bank2 = bank2;
                this.bank1Size = bank1.Size;
            }

            public long Size => bank1.Size + bank2.Size;

            public void Reset()
            {
            }

            public byte ReadByte(long offset)
            {
                return Resolve(offset).Memory.ReadByte(Resolve(offset).LocalOffset);
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
                return ReadBytes(offset, count, this);
            }

            public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
            {
                var result = new byte[count];
                var read = 0;
                while(read < count)
                {
                    var region = Resolve(offset + read);
                    var chunk = Math.Min(count - read, (int)(region.Memory.Size - region.LocalOffset));
                    var data = region.Memory.ReadBytes(region.LocalOffset, chunk);
                    Array.Copy(data, 0, result, read, chunk);
                    read += chunk;
                }
                return result;
            }

            public void WriteByte(long offset, byte value)
            {
                Resolve(offset).Memory.WriteByte(Resolve(offset).LocalOffset, value);
            }

            public void WriteWord(long offset, ushort value)
            {
                WriteBytes(offset, new[]
                {
                    (byte)(value & 0xFF),
                    (byte)((value >> 8) & 0xFF),
                }, 0, 2, this);
            }

            public void WriteDoubleWord(long offset, uint value)
            {
                WriteBytes(offset, new[]
                {
                    (byte)(value & 0xFF),
                    (byte)((value >> 8) & 0xFF),
                    (byte)((value >> 16) & 0xFF),
                    (byte)((value >> 24) & 0xFF),
                }, 0, 4, this);
            }

            public void WriteQuadWord(long offset, ulong value)
            {
                var bytes = new byte[8];
                for(var i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)((value >> (8 * i)) & 0xFF);
                }
                WriteBytes(offset, bytes, 0, bytes.Length, this);
            }

            public void WriteBytes(long offset, byte[] array)
            {
                WriteBytes(offset, array, 0, array.Length, this);
            }

            public void WriteBytes(long offset, byte[] array, int startingIndex, int count, IPeripheral context = null)
            {
                var written = 0;
                while(written < count)
                {
                    var region = Resolve(offset + written);
                    var chunk = Math.Min(count - written, (int)(region.Memory.Size - region.LocalOffset));
                    region.Memory.WriteBytes(region.LocalOffset, array, startingIndex + written, chunk, context);
                    written += chunk;
                }
            }

            private (MappedMemory Memory, long LocalOffset) Resolve(long offset)
            {
                if(offset < 0 || offset >= Size)
                {
                    throw new RecoverableException($"Offset 0x{offset:X} outside flash view");
                }
                if(offset < bank1Size)
                {
                    return (bank1, offset);
                }
                return (bank2, offset - bank1Size);
            }

            private readonly IMachine machine;
            private readonly MappedMemory bank1;
            private readonly MappedMemory bank2;
            private readonly long bank1Size;
        }

        private enum Registers
        {
            AccessControl = 0x000,
            KeyBank1 = 0x004,
            OptionKey = 0x008,
            ControlBank1 = 0x00C,
            StatusBank1 = 0x010,
            ClearControlBank1 = 0x014,
            OptionControl = 0x018,
            OptionStatusCurrent = 0x01C,
            OptionStatusProgram = 0x020,
            OptionClearControl = 0x024,
            ProtectionAddressCurrentBank1 = 0x028,
            ProtectionAddressProgramBank1 = 0x02C,
            SecureAddressCurrentBank1 = 0x030,
            SecureAddressProgramBank1 = 0x034,
            WriteSectorProtectionCurrentBank1 = 0x038,
            WriteSectorProtectionProgramBank1 = 0x03C,
            BootAddressCurrent = 0x040,
            BootAddressProgram = 0x044,
            CRCControlBank1 = 0x050,
            CRCStartAddressBank1 = 0x054,
            CRCEndAddressBank1 = 0x058,
            CRCData = 0x05C,
            ECCFailAddressBank1 = 0x060,
            KeyBank2 = 0x104,
            ControlBank2 = 0x10C,
            StatusBank2 = 0x110,
            ClearControlBank2 = 0x114,
            ProtectionAddressCurrentBank2 = 0x128,
            ProtectionAddressProgramBank2 = 0x12C,
            SecureAddressCurrentBank2 = 0x130,
            SecureAddressProgramBank2 = 0x134,
            WriteSectorProtectionCurrentBank2 = 0x138,
            WriteSectorProtectionProgramBank2 = 0x13C,
            CRCControlBank2 = 0x150,
            CRCStartAddressBank2 = 0x154,
            CRCEndAddressBank2 = 0x158,
            ECCFailAddressBank2 = 0x160,
        }
    }
}
