// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using Antmicro.Renode.Peripherals;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public interface ITardigradeFaultInjectable
    {
        IMemory Flash { get; }
        long FlashBaseAddress { get; set; }
        long FlashSize { get; set; }
        int PageSize { get; set; }
        byte EraseFill { get; set; }

        ulong TotalWordWrites { get; set; }
        ulong FaultAtWordWrite { get; set; }
        bool FaultFired { get; set; }
        bool PerWriteAccurate { get; }

        ulong TotalPageErases { get; set; }
        ulong FaultAtPageErase { get; set; }
        bool EraseFaultFired { get; set; }

        bool AnyFaultFired { get; }
        uint LastFaultAddress { get; set; }
        byte[] FaultFlashSnapshot { get; set; }

        int WriteFaultMode { get; set; }
        int EraseFaultMode { get; set; }
        uint CorruptionSeed { get; set; }

        int DiffLookahead { get; set; }
        bool SkipShadowScan { get; set; }
        bool PassthroughMode { get; set; }
        void InvalidateShadow();

        bool WriteTraceEnabled { get; set; }
        int WriteTraceCount { get; }
        string WriteTraceToString();
        void WriteTraceClear();
        bool EraseTraceEnabled { get; set; }
        int EraseTraceCount { get; }
        string EraseTraceToString();
        void EraseTraceClear();

        // Read-fault injection: one-shot transient read corruption.
        // NVM content is unchanged; only the value returned to the CPU
        // on the first matching read is corrupted.
        //
        // Important: this only works when CPU reads flow through the
        // fault-injectable peripheral itself (for example via
        // IDoubleWordPeripheral/IMemory interception). Fast-path targets that
        // expose flash through a backing MappedMemory can implement these
        // properties, but the engine should still skip read faults if the CPU
        // bypasses the peripheral on reads.
        bool ReadFaultEnabled { get; set; }
        long ReadFaultAddress { get; set; }
        uint ReadFaultSeed { get; set; }
        int ReadFaultBitFlips { get; set; }
        bool ReadFaultFired { get; set; }
        ulong ReadFaultSkipCount { get; set; }
        ulong ReadFaultTotalReads { get; set; }
    }
}
