// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Memory
{
    // Generic register-mapped NVM controller.
    // Models the common command handshake:
    //   write Address register
    //   write Data register
    //   write WriteCommandValue to Command register
    //   poll Status register for SuccessStatusValue
    //
    // The controller delegates storage semantics and write-fault behavior to NVMemory.
    public class GenericNvmController : BasicDoubleWordPeripheral, IKnownSize
    {
        public GenericNvmController(IMachine machine) : base(machine)
        {
            Reset();
        }

        public override void Reset()
        {
            base.Reset();

            registers.Clear();
            commandRegisterValue = 0U;
            addressRegisterValue = 0U;
            dataRegisterValue = 0U;
            statusRegisterValue = SuccessStatusValue;
            illegalOperation = false;
            commandExecutions = 0UL;

            registers[StatusRegisterOffset] = statusRegisterValue;
        }

        public override uint ReadDoubleWord(long offset)
        {
            if(offset == CommandRegisterOffset)
            {
                return commandRegisterValue;
            }

            if(offset == StatusRegisterOffset)
            {
                return statusRegisterValue;
            }

            if(offset == AddressRegisterOffset)
            {
                return addressRegisterValue;
            }

            if(offset == DataRegisterOffset)
            {
                return dataRegisterValue;
            }

            uint value;
            return registers.TryGetValue(offset, out value) ? value : 0U;
        }

        public override void WriteDoubleWord(long offset, uint value)
        {
            registers[offset] = value;

            if(offset == AddressRegisterOffset)
            {
                addressRegisterValue = value;
                return;
            }

            if(offset == DataRegisterOffset)
            {
                dataRegisterValue = value;
                return;
            }

            if(offset == StatusRegisterOffset)
            {
                statusRegisterValue = value;
                return;
            }

            if(offset == CommandRegisterOffset)
            {
                commandRegisterValue = value;
                ExecuteIfWriteCommand();
            }
        }

        public void InjectFault(long address, long length)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            try
            {
                Nvm.InjectFault(NormalizeAddress(address), length);
            }
            catch(ArgumentOutOfRangeException)
            {
                illegalOperation = true;
            }
        }

        public void InjectPartialWrite(long address)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            try
            {
                Nvm.InjectPartialWrite(NormalizeAddress(address));
            }
            catch(ArgumentOutOfRangeException)
            {
                illegalOperation = true;
            }
        }

        public bool WriteInProgress
        {
            get { return Nvm != null && Nvm.IsWriteInProgress(); }
        }

        public ulong WordWriteCount
        {
            get { return Nvm == null ? 0UL : Nvm.GetWordWriteCount(); }
        }

        public List<long> GetWriteLog()
        {
            return Nvm != null ? Nvm.WriteLog : new List<long>();
        }

        public void ClearWriteLog()
        {
            Nvm?.ClearWriteLog();
        }

        public long Size
        {
            get
            {
                var maxOffset = Math.Max(
                    Math.Max(CommandRegisterOffset, StatusRegisterOffset),
                    Math.Max(AddressRegisterOffset, DataRegisterOffset)
                );
                return Math.Max(MinControllerWindowSize, maxOffset + 4L);
            }
        }

        // Backing NVM model.
        public NVMemory Nvm { get; set; }

        // Address windows used to normalize absolute bus addresses to Nvm offsets.
        public long NvmBaseAddress { get; set; } = 0x10000000;
        public long NvReadOffset { get; set; } = 0x80000;

        // Register-map configuration.
        public long CommandRegisterOffset { get; set; } = 0x14;
        public long StatusRegisterOffset { get; set; } = 0x18;
        public long AddressRegisterOffset { get; set; } = 0x1C;
        public long DataRegisterOffset { get; set; } = 0x20;

        // Handshake values.
        public uint WriteCommandValue { get; set; } = 0x2;
        public uint SuccessStatusValue { get; set; } = 0x4;

        // Observability.
        public bool IllegalOperation
        {
            get { return illegalOperation; }
        }

        public ulong CommandExecutions
        {
            get { return commandExecutions; }
        }

        private void ExecuteIfWriteCommand()
        {
            if(commandRegisterValue != WriteCommandValue)
            {
                return;
            }

            commandExecutions++;
            statusRegisterValue = 0U;
            registers[StatusRegisterOffset] = statusRegisterValue;

            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            try
            {
                var nvmOffset = NormalizeAddress((long)addressRegisterValue);
                Nvm.WriteDoubleWord(nvmOffset, dataRegisterValue);
                statusRegisterValue = SuccessStatusValue;
                illegalOperation = false;
            }
            catch(ArgumentOutOfRangeException)
            {
                illegalOperation = true;
            }

            registers[StatusRegisterOffset] = statusRegisterValue;
        }

        private long NormalizeAddress(long address)
        {
            if(Nvm == null)
            {
                return address;
            }

            if(address >= 0 && address < Nvm.Size)
            {
                return address;
            }

            if(address >= NvmBaseAddress && address < NvmBaseAddress + Nvm.Size)
            {
                return address - NvmBaseAddress;
            }

            var nvReadBase = NvmBaseAddress + NvReadOffset;
            if(address >= nvReadBase && address < nvReadBase + Nvm.Size)
            {
                return address - nvReadBase;
            }

            throw new ArgumentOutOfRangeException(
                $"Address 0x{address:X} is outside modeled NVM windows");
        }

        private readonly Dictionary<long, uint> registers = new Dictionary<long, uint>();

        private uint commandRegisterValue;
        private uint statusRegisterValue;
        private uint addressRegisterValue;
        private uint dataRegisterValue;

        private bool illegalOperation;
        private ulong commandExecutions;

        private const long MinControllerWindowSize = 0x24;
    }
}
