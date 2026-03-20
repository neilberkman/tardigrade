// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// ARMv7A compatibility wrapper for QEMU virt / OP-TEE bringup. OP-TEE's
// qemu_virt ARM32 flavor uses a few CP15 operations that Renode's generic
// ARMv7A model leaves unimplemented. Treat the needed memory-attribute and
// address-translation registers as a small compatibility surface so OP-TEE
// can complete early boot on the virt board.

using System;
using Antmicro.Renode.Core;
using Antmicro.Renode.Exceptions;
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

        public void SetCompatRegister32(int register, ulong value)
        {
            SetRegister(register, RegisterValue.Create(value, 32));
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

        private uint TranslateVirtualAddress(uint address)
        {
            var registered = machine.SystemBus.WhatIsAt(address, this);
            if(registered == null)
            {
                return 0x1;
            }

            return address & 0xFFFFF000u;
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
    }
}
