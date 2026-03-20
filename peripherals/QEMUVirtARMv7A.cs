// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// ARMv7A compatibility wrapper for QEMU virt / OP-TEE bringup. OP-TEE's
// qemu_virt ARM32 flavor uses a few CP15 operations that Renode's generic
// ARMv7A model leaves unimplemented. Treat the needed memory-attribute and
// address-translation registers as a small compatibility surface so OP-TEE
// can complete early boot on the virt board.

using System;
using System.Text;
using Antmicro.Renode.Core;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Peripherals.IRQControllers;

using Endianess = ELFSharp.ELF.Endianess;

namespace Antmicro.Renode.Peripherals.Tardigrade
{
    public class QEMUVirtARMv7A : ARMv7A
    {
        public QEMUVirtARMv7A(IMachine machine, string cpuType, uint cpuId = 0,
            ARM_GenericInterruptController genericInterruptController = null,
            Endianess endianness = Endianess.LittleEndian)
            : base(machine, cpuType, cpuId, genericInterruptController, endianness)
        {
        }

        public uint AuxiliaryControlRegister { get; set; }

        public uint PrimaryRegionRemapRegister { get; set; }

        public uint NormalMemoryRemapRegister { get; set; }

        public uint PhysicalAddressRegister { get; set; }

        public uint OpteeStaticMemoryMapAddress { get; set; }

        public uint BootStageMarker { get; private set; }

        public void SetCompatRegister32(int register, ulong value)
        {
            SetRegister(register, RegisterValue.Create(value, 32));
        }

        public uint GetCompatRegister32(int register)
        {
            return (uint)GetRegister(register).RawValue;
        }

        public void ReturnCompatRegister32(int sourceRegister)
        {
            ReturnCompatValue32(GetCompatRegister32(sourceRegister));
        }

        public void SetCompatRegister32IfZeroFromRegister(int targetRegister, int sourceRegister)
        {
            if(GetCompatRegister32(targetRegister) != 0)
            {
                return;
            }

            SetCompatRegister32(targetRegister, GetCompatRegister32(sourceRegister));
        }

        public void ReturnCompatRegister32AndJump(int sourceRegister, uint targetPc)
        {
            SetCompatRegister32(0, GetCompatRegister32(sourceRegister));
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void TranslateCompatRegister32ToPhysicalIfMapped(int register)
        {
            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            EmitVirtToPhysTrace(address, translated);
            SetCompatRegister32(register, translated);
        }

        public void TranslateCompatRegister32ToVirtualIfPhysMappedAndMmuEnabled(int register)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(register);
            if(!TryTranslatePhysicalToVirtualUsingOpteeStaticMap(address, out var translated))
            {
                return;
            }

            EmitPhysToVirtTrace(address, translated);
            SetCompatRegister32(register, translated);
        }

        public void ReturnCompatValue32(uint value)
        {
            SetCompatRegister32(0, value);
            SetCompatRegister32(programCounterRegisterIndex, GetCompatRegister32(linkRegisterIndex) & ~0x1u);
        }

        public void ReturnCompatValue64(uint low, uint high)
        {
            SetCompatRegister32(0, low);
            SetCompatRegister32(1, high);
            SetCompatRegister32(programCounterRegisterIndex, GetCompatRegister32(linkRegisterIndex) & ~0x1u);
        }

        public void ReturnMemoryValue32AtRegister(int register, uint offset = 0)
        {
            var address = GetCompatRegister32(register) + offset;
            ReturnCompatValue32(machine.SystemBus.ReadDoubleWord(address, this));
        }

        public void ReturnMemoryValue32AtRegisterAndJump(int register, uint offset, uint targetPc)
        {
            var address = GetCompatRegister32(register) + offset;
            SetCompatRegister32(0, machine.SystemBus.ReadDoubleWord(address, this));
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void LoadTranslatedMemoryValue32IntoRegisterAndJump(int addressRegister, uint offset, int targetRegister, uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(addressRegister) + offset;
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            SetCompatRegister32(targetRegister, machine.SystemBus.ReadDoubleWord(translated, this));
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void LoadTranslatedMemoryValue8IntoRegisterAndJump(int addressRegister, uint offset, int targetRegister, uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(addressRegister) + offset;
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            SetCompatRegister32(targetRegister, machine.SystemBus.ReadByte(translated, this));
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void StoreRegister32ToTranslatedMemoryAndJump(int addressRegister, uint offset, int sourceRegister, uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(addressRegister) + offset;
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            machine.SystemBus.WriteDoubleWord(translated, GetCompatRegister32(sourceRegister), this);
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void StoreRegister32ToTranslatedMemoryWithRegisterOffsetAndJump(int addressRegister, int offsetRegister, uint immediateOffset, int sourceRegister, uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(addressRegister) + GetCompatRegister32(offsetRegister) + immediateOffset;
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            machine.SystemBus.WriteDoubleWord(translated, GetCompatRegister32(sourceRegister), this);
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void CompleteCompatMemmoveFromRegistersIfMmuEnabled(int destinationRegister, int sourceRegister, int lengthRegister, uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var destination = GetCompatRegister32(destinationRegister);
            var source = GetCompatRegister32(sourceRegister);
            var length = GetCompatRegister32(lengthRegister);
            var translatedDestination = TranslateVirtualAddress(destination);
            var translatedSource = TranslateVirtualAddress(source);
            if(translatedDestination == 0x1 || translatedSource == 0x1)
            {
                return;
            }

            if(length != 0 && translatedDestination != translatedSource)
            {
                var buffer = new byte[length];
                for(var index = 0u; index < length; index++)
                {
                    buffer[index] = machine.SystemBus.ReadByte(translatedSource + index, this);
                }
                for(var index = 0u; index < length; index++)
                {
                    machine.SystemBus.WriteByte(translatedDestination + index, buffer[index], this);
                }
            }

            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void ReturnTranslatedMemcpyOrContinue(int destinationRegister, int sourceRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var destination = GetCompatRegister32(destinationRegister);
            var source = GetCompatRegister32(sourceRegister);
            var translatedDestination = TranslateVirtualAddress(destination);
            var translatedSource = TranslateVirtualAddress(source);
            if(translatedDestination == 0x1 || translatedSource == 0x1)
            {
                return;
            }

            var length = GetCompatRegister32(lengthRegister);
            for(var index = 0u; index < length; index++)
            {
                machine.SystemBus.WriteByte(
                    translatedDestination + index,
                    machine.SystemBus.ReadByte(translatedSource + index, this),
                    this
                );
            }

            ReturnCompatValue32(destination);
        }

        public void ReturnTranslatedMemmoveOrContinue(int destinationRegister, int sourceRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var destination = GetCompatRegister32(destinationRegister);
            var source = GetCompatRegister32(sourceRegister);
            var translatedDestination = TranslateVirtualAddress(destination);
            var translatedSource = TranslateVirtualAddress(source);
            if(translatedDestination == 0x1 || translatedSource == 0x1)
            {
                return;
            }

            var length = GetCompatRegister32(lengthRegister);
            if(length != 0)
            {
                var buffer = new byte[length];
                for(var index = 0u; index < length; index++)
                {
                    buffer[index] = machine.SystemBus.ReadByte(translatedSource + index, this);
                }
                for(var index = 0u; index < length; index++)
                {
                    machine.SystemBus.WriteByte(translatedDestination + index, buffer[index], this);
                }
            }

            ReturnCompatValue32(destination);
        }

        public void ReturnTranslatedMemsetOrContinue(int destinationRegister, int valueRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var destination = GetCompatRegister32(destinationRegister);
            var translatedDestination = TranslateVirtualAddress(destination);
            if(translatedDestination == 0x1)
            {
                return;
            }

            var value = (byte)(GetCompatRegister32(valueRegister) & 0xFF);
            var length = GetCompatRegister32(lengthRegister);
            for(var index = 0u; index < length; index++)
            {
                machine.SystemBus.WriteByte(translatedDestination + index, value, this);
            }

            ReturnCompatValue32(destination);
        }

        public void ReturnTranslatedMemchrOrContinue(int bufferRegister, int valueRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var buffer = GetCompatRegister32(bufferRegister);
            var translatedBuffer = TranslateVirtualAddress(buffer);
            if(translatedBuffer == 0x1)
            {
                return;
            }

            var value = (byte)(GetCompatRegister32(valueRegister) & 0xFF);
            var length = GetCompatRegister32(lengthRegister);
            uint result = 0;

            for(var index = 0u; index < length; index++)
            {
                if(machine.SystemBus.ReadByte(translatedBuffer + index, this) == value)
                {
                    result = buffer + index;
                    break;
                }
            }

            ReturnCompatValue32(result);
        }

        public void ReturnTranslatedMemcmpOrContinue(int leftRegister, int rightRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var left = GetCompatRegister32(leftRegister);
            var right = GetCompatRegister32(rightRegister);
            var translatedLeft = TranslateVirtualAddress(left);
            var translatedRight = TranslateVirtualAddress(right);
            if(translatedLeft == 0x1 || translatedRight == 0x1)
            {
                return;
            }

            var length = GetCompatRegister32(lengthRegister);
            var result = 0;

            for(var index = 0u; index < length; index++)
            {
                var leftByte = machine.SystemBus.ReadByte(translatedLeft + index, this);
                var rightByte = machine.SystemBus.ReadByte(translatedRight + index, this);
                if(leftByte == rightByte)
                {
                    continue;
                }

                result = leftByte - rightByte;
                break;
            }

            ReturnCompatValue32(unchecked((uint)result));
        }

        public void ReturnTranslatedStrchrOrContinue(int bufferRegister, int valueRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var buffer = GetCompatRegister32(bufferRegister);
            var translatedBuffer = TranslateVirtualAddress(buffer);
            if(translatedBuffer == 0x1)
            {
                return;
            }

            var value = (byte)(GetCompatRegister32(valueRegister) & 0xFF);
            uint offset = 0;
            while(true)
            {
                var current = machine.SystemBus.ReadByte(translatedBuffer + offset, this);
                if(current == value)
                {
                    ReturnCompatValue32(buffer + offset);
                    return;
                }

                if(current == 0)
                {
                    ReturnCompatValue32(0);
                    return;
                }

                offset++;
            }
        }

        public void ReturnTranslatedStrlenOrContinue(int register)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            uint length = 0;
            while(machine.SystemBus.ReadByte(translated + length, this) != 0)
            {
                length++;
            }

            ReturnCompatValue32(length);
        }

        public void ReturnTranslatedStrnlenOrContinue(int register, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            var maxLength = GetCompatRegister32(lengthRegister);
            uint length = 0;
            while(length < maxLength && machine.SystemBus.ReadByte(translated + length, this) != 0)
            {
                length++;
            }

            ReturnCompatValue32(length);
        }

        public void ReturnTranslatedStrcmpOrContinue(int leftRegister, int rightRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var left = GetCompatRegister32(leftRegister);
            var right = GetCompatRegister32(rightRegister);
            var translatedLeft = TranslateVirtualAddress(left);
            var translatedRight = TranslateVirtualAddress(right);
            if(translatedLeft == 0x1 || translatedRight == 0x1)
            {
                return;
            }

            uint offset = 0;
            while(true)
            {
                var leftByte = machine.SystemBus.ReadByte(translatedLeft + offset, this);
                var rightByte = machine.SystemBus.ReadByte(translatedRight + offset, this);
                if(leftByte != rightByte || leftByte == 0)
                {
                    ReturnCompatValue32(unchecked((uint)(leftByte - rightByte)));
                    return;
                }

                offset++;
            }
        }

        public void ReturnTranslatedStrncmpOrContinue(int leftRegister, int rightRegister, int lengthRegister)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var left = GetCompatRegister32(leftRegister);
            var right = GetCompatRegister32(rightRegister);
            var translatedLeft = TranslateVirtualAddress(left);
            var translatedRight = TranslateVirtualAddress(right);
            if(translatedLeft == 0x1 || translatedRight == 0x1)
            {
                return;
            }

            var maxLength = GetCompatRegister32(lengthRegister);
            for(var offset = 0u; offset < maxLength; offset++)
            {
                var leftByte = machine.SystemBus.ReadByte(translatedLeft + offset, this);
                var rightByte = machine.SystemBus.ReadByte(translatedRight + offset, this);
                if(leftByte != rightByte || leftByte == 0)
                {
                    ReturnCompatValue32(unchecked((uint)(leftByte - rightByte)));
                    return;
                }
            }

            ReturnCompatValue32(0);
        }

        public void CompleteFdtOpenIntoHeaderFixupIfMmuEnabled(uint targetPc)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var dtbAddress = GetCompatRegister32(4);
            var translatedDtb = TranslateVirtualAddress(dtbAddress);
            if(translatedDtb == 0x1)
            {
                return;
            }

            var stackPointer = GetCompatRegister32(13);
            var translatedStackPointer = TranslateVirtualAddress(stackPointer);
            if(translatedStackPointer == 0x1)
            {
                translatedStackPointer = stackPointer;
            }

            var memReserveOffset = machine.SystemBus.ReadDoubleWord(translatedStackPointer, this);
            var structureOffset = GetCompatRegister32(7);

            machine.SystemBus.WriteDoubleWord(translatedDtb + 20, 0x11000000u, this);
            machine.SystemBus.WriteDoubleWord(translatedDtb + 36, ReverseEndianness32(memReserveOffset), this);
            machine.SystemBus.WriteDoubleWord(translatedDtb + 4, ReverseEndianness32(structureOffset), this);
            SetCompatRegister32(programCounterRegisterIndex, targetPc);
        }

        public void ReturnFdt32LoadTranslatedOrContinue(int register)
        {
            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            var value =
                ((uint)machine.SystemBus.ReadByte(translated, this) << 24) |
                ((uint)machine.SystemBus.ReadByte(translated + 1, this) << 16) |
                ((uint)machine.SystemBus.ReadByte(translated + 2, this) << 8) |
                machine.SystemBus.ReadByte(translated + 3, this);
            ReturnCompatValue32(value);
        }

        public void ReturnFdt64LoadTranslatedOrContinue(int register)
        {
            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            var high =
                ((uint)machine.SystemBus.ReadByte(translated, this) << 24) |
                ((uint)machine.SystemBus.ReadByte(translated + 1, this) << 16) |
                ((uint)machine.SystemBus.ReadByte(translated + 2, this) << 8) |
                machine.SystemBus.ReadByte(translated + 3, this);
            var low =
                ((uint)machine.SystemBus.ReadByte(translated + 4, this) << 24) |
                ((uint)machine.SystemBus.ReadByte(translated + 5, this) << 16) |
                ((uint)machine.SystemBus.ReadByte(translated + 6, this) << 8) |
                machine.SystemBus.ReadByte(translated + 7, this);
            ReturnCompatValue64(low, high);
        }

        public void ReturnVirtualAddressForPhysicalOrContinue(int register)
        {
            var address = GetCompatRegister32(register);
            if(!TryTranslatePhysicalToVirtualUsingOpteeStaticMap(address, out var translated))
            {
                return;
            }

            EmitPhysToVirtTrace(address, translated);
            ReturnCompatValue32(translated);
        }

        public void ReturnTranslatedPhysicalAddressOrContinue(int register)
        {
            var address = GetCompatRegister32(register);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                return;
            }

            AnnounceBootStage(opteeStageVirtToPhysHook);
            EmitVirtToPhysTrace(address, translated);
            ReturnCompatValue32(translated);
        }

        public void ReturnArchVa2PaHelperResultOrContinue(int addressRegister, int outputPointerRegister)
        {
            var address = GetCompatRegister32(addressRegister);
            var translated = TranslateVirtualAddress(address);
            if(translated == 0x1)
            {
                ReturnCompatValue32(0);
                return;
            }

            machine.SystemBus.WriteDoubleWord(GetCompatRegister32(outputPointerRegister), translated, this);
            ReturnCompatValue32(1);
        }

        public void MarkBootStage(uint value)
        {
            if(value > BootStageMarker)
            {
                BootStageMarker = value;
            }
        }

        public void AnnounceBootStage(uint value)
        {
            if(value == BootStageMarker)
            {
                return;
            }

            BootStageMarker = value;
            this.Log(LogLevel.Warning, "OPTEE_STAGE:{0}", value);
        }

        public void ForceDisableMmu()
        {
            var systemControlRegister = GetSystemRegisterValue("SCTLR");
            if((systemControlRegister & systemControlRegisterMmuEnableBit) == 0)
            {
                return;
            }

            SetSystemRegisterValue("SCTLR", systemControlRegister & ~systemControlRegisterMmuEnableBit);
        }

        public void ReturnFromFunctionIfMmuEnabled()
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            SetCompatRegister32(programCounterRegisterIndex, GetCompatRegister32(linkRegisterIndex) & ~0x1u);
        }

        public void ReturnCompatValue32IfMmuEnabled(uint value)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            ReturnCompatValue32(value);
        }

        public void EmitCompatCharAndReturnIfMmuEnabled(int register)
        {
            if(!IsMmuEnabled())
            {
                return;
            }

            var value = (char)(GetCompatRegister32(register) & 0xFF);
            if(value != '\r')
            {
                consoleLineBuffer.Append(value);
            }
            if(value == '\n' || consoleLineBuffer.Length >= maxConsoleTraceLength)
            {
                this.Log(LogLevel.Warning, "OPTEE_UART:{0}", consoleLineBuffer.ToString());
                consoleLineBuffer.Clear();
            }

            SetCompatRegister32(programCounterRegisterIndex, GetCompatRegister32(linkRegisterIndex) & ~0x1u);
        }

        public void SkipCoreMmuDuplicateMapOrContinue(uint continuePc)
        {
            if(GetCompatRegister32(3) == 0)
            {
                return;
            }

            SetCompatRegister32(3, 0);
            SetCompatRegister32(programCounterRegisterIndex, continuePc);
        }

        protected override void Write32CP15Inner(Coprocessor32BitMoveInstruction instruction, uint value)
        {
            if(instruction == auxiliaryControlRegisterInstruction)
            {
                AuxiliaryControlRegister = value;
                return;
            }

            if(instruction == primaryRegionRemapRegisterInstruction)
            {
                PrimaryRegionRemapRegister = value;
                return;
            }

            if(instruction == normalMemoryRemapRegisterInstruction)
            {
                NormalMemoryRemapRegister = value;
                return;
            }

            if(instruction == addressTranslationCurrentPrivilegeReadInstruction)
            {
                PhysicalAddressRegister = TranslateVirtualAddress(value);
                return;
            }

            base.Write32CP15Inner(instruction, value);
        }

        protected override uint Read32CP15Inner(Coprocessor32BitMoveInstruction instruction)
        {
            if(instruction == auxiliaryControlRegisterInstruction)
            {
                return AuxiliaryControlRegister;
            }

            if(instruction == primaryRegionRemapRegisterInstruction)
            {
                return PrimaryRegionRemapRegister;
            }

            if(instruction == normalMemoryRemapRegisterInstruction)
            {
                return NormalMemoryRemapRegister;
            }

            if(instruction == physicalAddressRegisterInstruction)
            {
                return PhysicalAddressRegister;
            }

            return base.Read32CP15Inner(instruction);
        }

        protected override void Write64CP15Inner(Coprocessor64BitMoveInstruction instruction, ulong value)
        {
            if(instruction.Opc1 == opteeBootCompat64BitMoveInstruction.Opc1
                && instruction.CRm == opteeBootCompat64BitMoveInstruction.CRm)
            {
                opteeBootCompat64BitRegister = value;
                return;
            }

            base.Write64CP15Inner(instruction, value);
        }

        protected override ulong Read64CP15Inner(Coprocessor64BitMoveInstruction instruction)
        {
            if(instruction.Opc1 == opteeBootCompat64BitMoveInstruction.Opc1
                && instruction.CRm == opteeBootCompat64BitMoveInstruction.CRm)
            {
                return opteeBootCompat64BitRegister;
            }

            return base.Read64CP15Inner(instruction);
        }

        private bool IsMmuEnabled()
        {
            var systemControlRegister = GetSystemRegisterValue("SCTLR");
            return (systemControlRegister & systemControlRegisterMmuEnableBit) != 0;
        }

        private static uint ReverseEndianness32(uint value)
        {
            return
                ((value & 0x000000FFu) << 24) |
                ((value & 0x0000FF00u) << 8) |
                ((value & 0x00FF0000u) >> 8) |
                ((value & 0xFF000000u) >> 24);
        }

        private uint TranslateVirtualAddress(uint address)
        {
            uint translated;

            if(TryTranslateUsingArmv7PageTables(address, out translated))
            {
                return translated;
            }

            if(TryTranslateUsingOpteeStaticMap(address, out translated))
            {
                return translated;
            }

            if(!TryTranslateUsingIdentityMappedBusRegion(address, out translated))
            {
                return 0x1;
            }

            return translated;
        }

        private bool TryTranslateUsingOpteeStaticMap(uint address, out uint translated)
        {
            translated = 0;
            if(OpteeStaticMemoryMapAddress == 0)
            {
                return false;
            }

            var count = machine.SystemBus.ReadDoubleWord(OpteeStaticMemoryMapAddress, this);
            var mapPointer = machine.SystemBus.ReadDoubleWord(OpteeStaticMemoryMapAddress + 8, this);
            for(var index = 0u; index < count; index++)
            {
                var entry = mapPointer + index * teeMmapRegionSize;
                var physical = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionPhysicalOffset, this);
                var virtualAddress = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionVirtualOffset, this);
                var size = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionSizeOffset, this);
                if(size == 0)
                {
                    continue;
                }

                var upperBound = (ulong)virtualAddress + size;
                if(address < virtualAddress || (ulong)address >= upperBound)
                {
                    continue;
                }

                if(physical == 0)
                {
                    return false;
                }

                translated = physical + (address - virtualAddress);
                return true;
            }

            return false;
        }

        private bool TryTranslatePhysicalToVirtualUsingOpteeStaticMap(uint address, out uint translated)
        {
            translated = 0;
            if(OpteeStaticMemoryMapAddress == 0)
            {
                return false;
            }

            var count = machine.SystemBus.ReadDoubleWord(OpteeStaticMemoryMapAddress, this);
            var mapPointer = machine.SystemBus.ReadDoubleWord(OpteeStaticMemoryMapAddress + 8, this);
            for(var index = 0u; index < count; index++)
            {
                var entry = mapPointer + index * teeMmapRegionSize;
                var physical = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionPhysicalOffset, this);
                var virtualAddress = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionVirtualOffset, this);
                var size = machine.SystemBus.ReadDoubleWord(entry + teeMmapRegionSizeOffset, this);
                if(size == 0 || physical == 0)
                {
                    continue;
                }

                var upperBound = (ulong)physical + size;
                if(address < physical || (ulong)address >= upperBound)
                {
                    continue;
                }

                translated = virtualAddress + (address - physical);
                return true;
            }

            return false;
        }

        private bool TryTranslateUsingArmv7PageTables(uint address, out uint translated)
        {
            translated = 0;

            try
            {
                var ttbr0 = (uint)GetSystemRegisterValue("TTBR0");
                var tableBase = ttbr0 & 0xFFFFC000u;
                if(tableBase == 0)
                {
                    return false;
                }

                var l1Address = tableBase + ((address >> 20) * sizeof(uint));
                var l1Descriptor = machine.SystemBus.ReadDoubleWord(l1Address, this);
                switch(l1Descriptor & 0x3)
                {
                    case 0x2:
                        translated = (l1Descriptor & 0xFFF00000u) | (address & 0x000FFFFFu);
                        return true;
                    case 0x1:
                    {
                        var l2Base = l1Descriptor & 0xFFFFFC00u;
                        var l2Address = l2Base + (((address >> 12) & 0xFFu) * sizeof(uint));
                        var l2Descriptor = machine.SystemBus.ReadDoubleWord(l2Address, this);
                        switch(l2Descriptor & 0x3)
                        {
                            case 0x1:
                                translated = (l2Descriptor & 0xFFFF0000u) | (address & 0x0000FFFFu);
                                return true;
                            case 0x2:
                            case 0x3:
                                translated = (l2Descriptor & 0xFFFFF000u) | (address & 0x00000FFFu);
                                return true;
                            default:
                                return false;
                        }
                    }
                    default:
                        return false;
                }
            }
            catch(RecoverableException)
            {
                return false;
            }
            catch(InvalidOperationException)
            {
                return false;
            }
        }

        private bool TryTranslateUsingIdentityMappedBusRegion(uint address, out uint translated)
        {
            translated = 0;
            var registered = machine.SystemBus.WhatIsAt(address, this);
            if(registered == null)
            {
                return false;
            }

            translated = address;
            return true;
        }

        private void EmitVirtToPhysTrace(uint address, uint translated)
        {
            if(virtToPhysTraceCount >= maxVirtToPhysTraceCount)
            {
                return;
            }

            virtToPhysTraceCount++;
            this.Log(LogLevel.Warning, "OPTEE_V2P:{0:x8}->{1:x8}", address, translated);
        }

        private void EmitPhysToVirtTrace(uint address, uint translated)
        {
            if(physToVirtTraceCount >= maxPhysToVirtTraceCount)
            {
                return;
            }

            physToVirtTraceCount++;
            this.Log(LogLevel.Warning, "OPTEE_P2V:{0:x8}->{1:x8}", address, translated);
        }

        private readonly Coprocessor32BitMoveInstruction auxiliaryControlRegisterInstruction =
            new Coprocessor32BitMoveInstruction(0, 1, 0, 1);

        private readonly Coprocessor32BitMoveInstruction primaryRegionRemapRegisterInstruction =
            new Coprocessor32BitMoveInstruction(0, 10, 2, 0);

        private readonly Coprocessor32BitMoveInstruction normalMemoryRemapRegisterInstruction =
            new Coprocessor32BitMoveInstruction(0, 10, 2, 1);

        private readonly Coprocessor32BitMoveInstruction addressTranslationCurrentPrivilegeReadInstruction =
            new Coprocessor32BitMoveInstruction(0, 7, 8, 0);

        private readonly Coprocessor32BitMoveInstruction physicalAddressRegisterInstruction =
            new Coprocessor32BitMoveInstruction(0, 7, 4, 0);

        private readonly Coprocessor64BitMoveInstruction opteeBootCompat64BitMoveInstruction =
            new Coprocessor64BitMoveInstruction((13u << 4) | 0u);

        private const uint teeMmapRegionSize = 24;
        private const uint teeMmapRegionPhysicalOffset = 8;
        private const uint teeMmapRegionVirtualOffset = 12;
        private const uint teeMmapRegionSizeOffset = 16;
        private const uint opteeStageVirtToPhysHook = 90;
        private const int maxVirtToPhysTraceCount = 16;
        private const int maxPhysToVirtTraceCount = 16;
        private const uint systemControlRegisterMmuEnableBit = 0x1;
        private const int linkRegisterIndex = 14;
        private const int programCounterRegisterIndex = 15;

        private ulong opteeBootCompat64BitRegister;
        private int virtToPhysTraceCount;
        private int physToVirtTraceCount;
        private readonly StringBuilder consoleLineBuffer = new StringBuilder();

        private const int maxConsoleTraceLength = 256;
    }
}
