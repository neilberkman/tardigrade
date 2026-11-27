// Copyright (c) 2026 Neil Berkman
// SPDX-License-Identifier: Apache-2.0
//
// 24-Series I2C Serial EEPROM peripheral model with Tardigrade fault injection.
//
// Modeled part and datasheet reference:
//   Microchip 24LC256 / 24AA256 / 24FC256 — "256K I2C CMOS Serial EEPROM",
//   Document DS20001203Y (also compatible with Atmel/Microchip AT24C256):
//   - Section 1.0 / 3.0 Device Organization:
//     * 32,768 x 8 bits (32 KiB default capacity, configurable size).
//     * 64-byte page write buffer (PageSize = 64, configurable power-of-two).
//     * 2-byte big-endian word address (AddressBytes = 2, MSB first; 15-bit
//       address 0x0000..0x7FFF for 24LC256).
//   - Section 6.1 Byte Write & Section 6.2 Page Write:
//     * After the 2-byte word address, the master transmits 1..64 data bytes into
//       the internal 64-byte page buffer before sending STOP (FinishTransmission).
//     * The lower 6 bits (PageSize - 1) of the internal address pointer increment
//       after each byte while the upper address bits (~(PageSize - 1)) remain fixed.
//     * If data transmitted exceeds the 64-byte page boundary, the internal address
//       counter rolls over (wraps around) to the start of the same 64-byte page
//       ((pageBase) | ((startOffset + i) & (PageSize - 1))) and overwrites earlier
//       bytes in that page buffer.
//     * Receipt of the STOP condition (FinishTransmission) initiates the internal
//       self-timed write cycle (t_WR, max 5 ms) to commit the latched page buffer
//       to non-volatile memory.
//   - Section 7.0 Acknowledge Polling:
//     * During the internal write cycle (t_WR), inputs are disabled and the EEPROM
//       does not acknowledge (NACKs) bus transactions.
//     * Masters perform ACK polling by issuing START + control byte; while
//       WriteInProgress (IsBusy) is true, the device NACKs (incrementing
//       AckPollCount and NackCount, and raising ERRORSRC.ANACK / EVENTS_ERROR
//       when wired to an NRF52840_I2C controller). Once t_WR completes, the
//       device responds with ACK.
//   - Section 8.1 Current Address Read, Section 8.2 Random Read,
//     Section 8.3 Sequential Read:
//     * A write of only the 2 address bytes latches CurrentAddress without starting
//       an internal write cycle.
//     * Subsequent Read(count) calls stream sequential bytes from CurrentAddress,
//       incrementing CurrentAddress modulo Size across page boundaries and wrapping
//       from the end of the array back to 0x0000.
//   - Fault Injection:
//     * Implements ITardigradeFaultInjectable and FaultTracker contract:
//       width-explicit write tracing, cut before a write (untouched), cut during
//       the internal write cycle leaving a documented partial page, non-power
//       write fault modes, read bit-flip faults, trace replay, and persistent state.

using System;
using System.Collections.Generic;
using System.Reflection;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Miscellaneous;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.I2C
{
    public class I2CEEPROM :
        II2CPeripheral,
        IMemory,
        IBytePeripheral,
        IWordPeripheral,
        IDoubleWordPeripheral,
        IQuadWordPeripheral,
        IKnownSize,
        ITardigradeFaultInjectable
    {
        public const int DefaultMemorySize = 32768; // 24LC256: 32 KiB (256 Kbit)
        public const int DefaultPageBufferSize = 64; // 24LC256: 64-byte page buffer

        private readonly IMachine machine;
        private readonly FaultTracker tracker = new FaultTracker();
        private readonly byte[] storage;

        // I2C transaction and address state.
        private bool transmissionPending;
        private int addressBytesReceived;
        private int latchedAddressAccumulator;
        private int currentAddress;
        private int pageWriteStartAddress;
        private int pageWriteDataCount;
        private byte[] pageLatch;
        private bool[] pageByteTouched;
        private readonly List<int> pageTouchOrder = new List<int>(DefaultPageBufferSize);

        // Internal write cycle (t_WR) and ACK polling state.
        private TimeInterval writeCycleUntilTime;
        private bool hasWriteCycleDeadline;
        private int busyPollsRemaining;
        private bool nackLatchedForCurrentControllerTx;

        // Optional hook into Renode's NRF52840_I2C controller so busy ACK polling
        // raises hardware ERRORSRC.ANACK + EVENTS_ERROR on the TWI peripheral.
        private IPeripheral attachedController;
        private int attachedSlaveAddress = 0x50;

        public I2CEEPROM(
            IMachine machine,
            long size = DefaultMemorySize,
            int pageSize = DefaultPageBufferSize,
            int addressBytes = 2,
            long flashBaseAddress = 0x0,
            byte eraseFill = 0xFF)
        {
            if(size <= 0)
            {
                throw new ConstructionException($"I2CEEPROM size must be positive (got {size})");
            }
            if(pageSize <= 0 || (pageSize & (pageSize - 1)) != 0)
            {
                throw new ConstructionException($"I2CEEPROM pageSize must be a positive power of two (got {pageSize})");
            }
            if(addressBytes != 1 && addressBytes != 2)
            {
                throw new ConstructionException($"I2CEEPROM addressBytes must be 1 or 2 (got {addressBytes})");
            }

            this.machine = machine;
            DeviceSize = size;
            PageSize = pageSize;
            AddressBytes = addressBytes;
            FlashBaseAddress = flashBaseAddress;
            FlashSize = size;
            EraseFill = eraseFill;

            storage = new byte[checked((int)size)];
            FillArray(storage, 0, storage.Length, eraseFill);
            pageLatch = new byte[pageSize];
            pageByteTouched = new bool[pageSize];
            ClearPageLatch();
        }

        public long Size => DeviceSize;
        public long DeviceSize { get; private set; }
        public int AddressBytes { get; private set; }

        public IMemory Flash
        {
            get => this;
            set { }
        }

        public long FlashBaseAddress { get; set; }
        public long FlashSize { get; set; }

        private int pageSize = DefaultPageBufferSize;
        public int PageSize
        {
            get => pageSize;
            set
            {
                if(value <= 0 || (value & (value - 1)) != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        "PageSize must be a positive power of two");
                }
                pageSize = value;
                pageLatch = new byte[pageSize];
                pageByteTouched = new bool[pageSize];
                ClearPageLatch();
            }
        }

        public byte EraseFill { get; set; } = 0xFF;

        // If true, the first byte of a new I2C Write() frame is treated as the
        // 8-bit I2C control byte ((slaveAddr << 1) | rw) rather than the first
        // memory address byte. Standard Renode I2C controllers (e.g. NRF52840_I2C)
        // strip the control byte and pass [addr_hi, addr_lo, data...], so this
        // defaults to false.
        public bool HasLeadingDeviceAddressByte { get; set; }

        public bool WriteProtected { get; set; }

        // Internal write cycle (t_WR) timing & ACK polling configuration.
        // 24LC256 t_WR max is 5 ms (5000 us).
        public ulong WriteCycleTimeUs { get; set; } = 0;
        public int BusyPollsPerWrite { get; set; } = 1;
        public bool ForceBusy { get; set; }

        public int BusyPollsRemaining
        {
            get => busyPollsRemaining;
            set => busyPollsRemaining = Math.Max(0, value);
        }

        // Write chunking and page-level fault options.
        // Default WriteChunkSize = 4 emits 4-byte (or 1/2-byte tail) write trace
        // records compatible with TraceReplayEngine and state_search.
        // Setting PageLevelWriteTracking = true counts each I2C Page Write
        // transaction as a single write event for page-atomic fault tests.
        private int writeChunkSize = 4;
        public int WriteChunkSize
        {
            get => writeChunkSize;
            set
            {
                if(value != 1 && value != 2 && value != 4 && value != 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        "WriteChunkSize must be 1, 2, 4, or 8 bytes");
                }
                writeChunkSize = value;
            }
        }

        public bool PageLevelWriteTracking { get; set; }

        public int CurrentAddress
        {
            get => currentAddress;
            set => currentAddress = NormalizeAddress(value);
        }

        public bool WriteInProgress => IsBusyNow();
        public bool LastTransactionNacked { get; private set; }
        public ulong AckPollCount { get; private set; }
        public ulong NackCount { get; private set; }
        public ulong AckCount { get; private set; }
        public ulong PageWriteCount { get; private set; }
        public ulong PageWrapCount { get; private set; }
        public ulong SequentialReadByteCount { get; private set; }

        // Optional link to Renode's NRF52840_I2C controller for hardware ANACK during t_WR.
        public IPeripheral Controller
        {
            get => attachedController;
            set => AttachToController(value, attachedSlaveAddress);
        }

        public int SlaveAddress
        {
            get => attachedSlaveAddress;
            set => attachedSlaveAddress = value & 0x7F;
        }

        // --- ITardigradeFaultInjectable implementation ---

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public byte[] FaultFlashSnapshot { get => tracker.FaultFlashSnapshot; set => tracker.FaultFlashSnapshot = value; }
        public bool DriverErrorFired { get => tracker.DriverErrorFired; set => tracker.DriverErrorFired = value; }
        public bool DriverErrorRequiresReturnHook => true;

        public ulong TotalPageErases { get => tracker.TotalPageErases; set => tracker.TotalPageErases = value; }
        public ulong FaultAtPageErase { get => tracker.FaultAtPageErase; set => tracker.FaultAtPageErase = value; }
        public bool EraseFaultFired { get => tracker.EraseFaultFired; set => tracker.EraseFaultFired = value; }

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

        public bool WriteTraceEnabled { get => tracker.WriteTraceEnabled; set => tracker.WriteTraceEnabled = value; }
        public int WriteTraceCount => tracker.WriteTraceCount;
        public string WriteTraceToString() => tracker.WriteTraceToString();
        public void WriteTraceClear() => tracker.WriteTraceClear();
        public bool WriteTraceWidthExplicit => true;
        public bool PerWriteAccurate => true;

        public bool EraseTraceEnabled { get => tracker.EraseTraceEnabled; set => tracker.EraseTraceEnabled = value; }
        public int EraseTraceCount => tracker.EraseTraceCount;
        public string EraseTraceToString() => tracker.EraseTraceToString();
        public void EraseTraceClear() => tracker.EraseTraceClear();

        // Fast-path compatibility properties expected by run_runtime_fault_sweep.py.
        public int DiffLookahead { get; set; } = 32;
        public bool SkipShadowScan { get; set; } = true;
        public bool PassthroughMode { get; set; }
        public bool OperationTraceFastMode { get; set; }
        public void InvalidateShadow() { }

        // Read-fault injection properties.
        public bool ReadFaultEnabled { get; set; }
        public long ReadFaultAddress { get; set; } = -1;
        public uint ReadFaultSeed { get; set; }
        public int ReadFaultBitFlips { get; set; } = 1;
        public bool ReadFaultFired { get; set; }
        public ulong ReadFaultSkipCount { get; set; }
        public ulong ReadFaultTotalReads { get; set; }

        // --- Reset ---

        public void Reset()
        {
            tracker.Reset();
            transmissionPending = false;
            addressBytesReceived = 0;
            latchedAddressAccumulator = 0;
            currentAddress = 0;
            pageWriteStartAddress = 0;
            ClearPageLatch();
            hasWriteCycleDeadline = false;
            busyPollsRemaining = 0;
            ForceBusy = false;
            nackLatchedForCurrentControllerTx = false;
            LastTransactionNacked = false;
            ReadFaultFired = false;
            ReadFaultTotalReads = 0;
            if(!PreserveCountersAcrossReset)
            {
                AckPollCount = 0;
                NackCount = 0;
                AckCount = 0;
                PageWriteCount = 0;
                PageWrapCount = 0;
                SequentialReadByteCount = 0;
            }
        }

        // --- Explicit ACK Polling API (and automatic bus ACK polling) ---

        /// <summary>
        /// Perform a 24-series I2C ACK poll (START + control byte).
        /// Returns false (NACK) if the internal write cycle (t_WR) is still in progress,
        /// or true (ACK) when the device is ready to accept a new command.
        /// </summary>
        public bool AckPoll()
        {
            if(EvaluateAndConsumeBusyPoll())
            {
                LastTransactionNacked = true;
                AckPollCount++;
                NackCount++;
                return false;
            }
            LastTransactionNacked = false;
            AckCount++;
            return true;
        }

        // --- II2CPeripheral ---

        public void Write(System.Collections.IList data)
        {
            if(data == null)
            {
                Write((byte[])null);
                return;
            }
            byte[] bytes = new byte[data.Count];
            for(int i = 0; i < data.Count; i++)
            {
                bytes[i] = Convert.ToByte(data[i]);
            }
            Write(bytes);
        }

        public void Write(byte[] data)
        {
            if(data == null || data.Length == 0)
            {
                // Address-only probe / ACK poll.
                AckPoll();
                return;
            }

            if(!transmissionPending)
            {
                // Starting a new I2C write frame: check internal write cycle (t_WR) busy state.
                if(!AckPoll())
                {
                    // NACKed during internal write cycle: inputs are disabled per 24LC256 Section 7.0.
                    return;
                }
                transmissionPending = true;
                addressBytesReceived = 0;
                latchedAddressAccumulator = 0;
                ClearPageLatch();
            }

            int index = 0;
            if(addressBytesReceived == 0 && HasLeadingDeviceAddressByte)
            {
                index = 1;
                if(index >= data.Length)
                {
                    return;
                }
            }

            while(index < data.Length && addressBytesReceived < AddressBytes)
            {
                latchedAddressAccumulator = (latchedAddressAccumulator << 8) | data[index];
                addressBytesReceived++;
                index++;
                if(addressBytesReceived == AddressBytes)
                {
                    currentAddress = NormalizeAddress(latchedAddressAccumulator);
                    pageWriteStartAddress = currentAddress;
                }
            }

            // Remaining bytes are page-write data bytes buffered in the 64-byte page latch.
            while(index < data.Length)
            {
                LatchPageWriteByte(data[index]);
                index++;
            }
        }

        public byte[] Read(int count = 1)
        {
            if(count <= 0)
            {
                return new byte[0];
            }

            if(transmissionPending)
            {
                // Repeated START after writing address bytes (Random Read).
                // If any data bytes were also buffered before Repeated START, commit them;
                // if only address bytes were written, CurrentAddress is already latched.
                if(pageWriteDataCount > 0)
                {
                    CommitPageWrite();
                }
                transmissionPending = false;
                addressBytesReceived = 0;
                ClearPageLatch();
            }
            else
            {
                // Current Address Read: check if busy in internal write cycle (t_WR).
                if(!AckPoll())
                {
                    return new byte[0];
                }
            }

            byte[] result = new byte[count];
            for(int i = 0; i < count; i++)
            {
                result[i] = ReadStorageByteWithFault(currentAddress);
                currentAddress = NormalizeAddress(currentAddress + 1);
                SequentialReadByteCount++;
            }
            return result;
        }

        public void FinishTransmission()
        {
            if(!transmissionPending)
            {
                return;
            }

            try
            {
                if(addressBytesReceived == AddressBytes && pageWriteDataCount > 0)
                {
                    CommitPageWrite();
                }
            }
            finally
            {
                transmissionPending = false;
                addressBytesReceived = 0;
                latchedAddressAccumulator = 0;
                ClearPageLatch();
            }
        }

        // --- Page Write Buffer & Internal Write Cycle (t_WR) ---

        private void LatchPageWriteByte(byte data)
        {
            // 24LC256 Section 6.2: The lower 6 bits (PageSize - 1) increment
            // inside the active page while the upper address bits remain fixed.
            // Transmitting past the page boundary wraps to the start of the same page.
            int pageMask = pageSize - 1;
            int pageBase = pageWriteStartAddress & ~pageMask;
            int startInPage = pageWriteStartAddress & pageMask;
            int rawOffset = startInPage + pageWriteDataCount;
            if(rawOffset >= pageSize && pageWriteDataCount == pageSize - startInPage)
            {
                PageWrapCount++;
            }
            int inPageOffset = rawOffset & pageMask;

            pageLatch[inPageOffset] = data;
            if(!pageByteTouched[inPageOffset])
            {
                pageByteTouched[inPageOffset] = true;
                pageTouchOrder.Add(inPageOffset);
            }
            else
            {
                pageTouchOrder.Remove(inPageOffset);
                pageTouchOrder.Add(inPageOffset);
            }
            pageWriteDataCount++;
            currentAddress = NormalizeAddress(pageBase | ((inPageOffset + 1) & pageMask));
        }

        private void CommitPageWrite()
        {
            if(WriteProtected || pageTouchOrder.Count == 0)
            {
                return;
            }

            PageWriteCount++;
            StartWriteCycle(WriteCycleTimeUs, BusyPollsPerWrite);

            if(AnyFaultFired)
            {
                return;
            }

            int pageMask = pageSize - 1;
            int pageBase = pageWriteStartAddress & ~pageMask;

            if(PageLevelWriteTracking)
            {
                ExecutePageLevelTrackedWrite(pageBase);
                return;
            }

            int idx = 0;
            while(idx < pageTouchOrder.Count)
            {
                int spanStart = pageTouchOrder[idx];
                int spanLen = 1;
                while(idx + spanLen < pageTouchOrder.Count
                    && pageTouchOrder[idx + spanLen] == spanStart + spanLen)
                {
                    spanLen++;
                }

                int rel = 0;
                while(rel < spanLen)
                {
                    int inPageOff = spanStart + rel;
                    int remaining = spanLen - rel;
                    int chunkWidth = ChooseChunkWidth(inPageOff, remaining, writeChunkSize);
                    int devOff = pageBase + inPageOff;
                    if(devOff >= 0 && devOff + chunkWidth <= DeviceSize)
                    {
                        if(!WriteChunkWithFault(devOff, inPageOff, chunkWidth))
                        {
                            // Power-loss fault during internal write cycle: abort remaining chunks.
                            return;
                        }
                    }
                    rel += chunkWidth;
                }

                idx += spanLen;
            }
        }

        private void ExecutePageLevelTrackedWrite(int pageBase)
        {
            int count = pageTouchOrder.Count;
            int firstInPage = pageTouchOrder[0];
            int firstDevOff = pageBase + firstInPage;
            int traceWidth = ChooseChunkWidth(firstInPage, count, Math.Min(8, writeChunkSize));

            ulong oldWord = ReadStorageValueRaw(firstDevOff, traceWidth);
            ulong intendedWord = 0;
            for(int b = 0; b < traceWidth; b++)
            {
                int pOff = (firstInPage + b) & (pageSize - 1);
                byte val = pageByteTouched[pOff] ? pageLatch[pOff] : storage[pageBase + pOff];
                intendedWord |= (ulong)val << (b * 8);
            }

            bool isFault = PassthroughMode
                ? tracker.IncrementWriteCount()
                : tracker.RecordWriteAndCheckFault(firstDevOff, intendedWord, traceWidth);

            if(isFault)
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + firstDevOff);
                if(WriteFaultMode == 0)
                {
                    string mode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                    if(mode == "untouched")
                    {
                        // Cut at the start of the internal write cycle before any bytes commit.
                    }
                    else if(mode == "programmed")
                    {
                        for(int i = 0; i < count; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            storage[pageBase + pOff] = pageLatch[pOff];
                        }
                    }
                    else if(mode == "partial_bits")
                    {
                        for(int i = 0; i < count; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            int dOff = pageBase + pOff;
                            byte cur = storage[dOff];
                            byte target = pageLatch[pOff];
                            ulong torn = FaultTracker.BuildFlashTornProgramValue(
                                cur, target, 1, EraseFill, "partial_bits",
                                TornWordSeed, TotalWordWrites, dOff);
                            storage[dOff] = (byte)(torn & 0xFF);
                        }
                    }
                    else
                    {
                        // "fixed" / "half" / "half_retain": cut during the internal write cycle,
                        // leaving the first half of the page write committed and the second half
                        // retaining its pre-write bytes.
                        int halfCount = count / 2;
                        for(int i = 0; i < halfCount; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            storage[pageBase + pOff] = pageLatch[pOff];
                        }
                    }
                    FaultFlashSnapshot = (byte[])storage.Clone();
                    return;
                }

                ApplyNonPowerWriteFault(firstDevOff, oldWord, intendedWord, traceWidth);
                for(int i = traceWidth; i < count; i++)
                {
                    int pOff = pageTouchOrder[i];
                    storage[pageBase + pOff] = pageLatch[pOff];
                }
                FaultFlashSnapshot = (byte[])storage.Clone();
                return;
            }

            for(int i = 0; i < count; i++)
            {
                int pOff = pageTouchOrder[i];
                storage[pageBase + pOff] = pageLatch[pOff];
            }
        }

        private bool WriteChunkWithFault(int devOff, int inPageOff, int width)
        {
            ulong oldVal = ReadStorageValueRaw(devOff, width);
            ulong intendedVal = 0;
            for(int b = 0; b < width; b++)
            {
                intendedVal |= (ulong)pageLatch[inPageOff + b] << (b * 8);
            }

            bool isFault = PassthroughMode
                ? tracker.IncrementWriteCount()
                : tracker.RecordWriteAndCheckFault(devOff, intendedVal, width);

            if(isFault)
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + devOff);

                if(WriteFaultMode == 0)
                {
                    string mode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                    if((mode == "half" || mode == "half_retain") && width >= 2)
                    {
                        int halfBytes = width / 2;
                        ulong mask = (1UL << (halfBytes * 8)) - 1UL;
                        ulong halfVal = (intendedVal & mask) | (oldVal & ~mask);
                        WriteStorageValueRaw(devOff, halfVal, width);
                    }
                    else
                    {
                        string flashMode = (mode == "half" || mode == "half_retain") ? "fixed" : mode;
                        ulong torn = FaultTracker.BuildFlashTornProgramValue(
                            oldVal, intendedVal, width, EraseFill, flashMode,
                            TornWordSeed, TotalWordWrites, devOff);
                        WriteStorageValueRaw(devOff, torn, width);
                    }
                    FaultFlashSnapshot = (byte[])storage.Clone();
                    return false;
                }

                ApplyNonPowerWriteFault(devOff, oldVal, intendedVal, width);
                FaultFlashSnapshot = (byte[])storage.Clone();
                return true;
            }

            WriteStorageValueRaw(devOff, intendedVal, width);
            return true;
        }

        private void ApplyNonPowerWriteFault(int devOff, ulong oldVal, ulong intendedVal, int width)
        {
            ulong valueMask = width == 8 ? ulong.MaxValue : ((1UL << (width * 8)) - 1UL);
            switch(WriteFaultMode)
            {
                case 1: // Bit corruption
                {
                    uint seed = tracker.BuildFaultSeed(devOff);
                    ulong keepMask = FaultTracker.NextLcg(ref seed);
                    if(width > 4)
                    {
                        keepMask |= (ulong)FaultTracker.NextLcg(ref seed) << 32;
                    }
                    ulong bitsToFlip = (oldVal & ~intendedVal) & valueMask;
                    ulong corrupted = (oldVal & ~(bitsToFlip & keepMask)) & valueMask;
                    WriteStorageValueRaw(devOff, corrupted, width);
                    break;
                }
                case 2: // Silent write failure
                {
                    ulong silentVal = ((TotalWordWrites & 1UL) == 0UL) ? valueMask : 0UL;
                    WriteStorageValueRaw(devOff, silentVal, width);
                    break;
                }
                case 3: // Write rejection
                {
                    WriteStorageValueRaw(devOff, oldVal, width);
                    break;
                }
                case 4: // Write disturb
                {
                    WriteStorageValueRaw(devOff, intendedVal, width);
                    uint seed = tracker.BuildFaultSeed(devOff);
                    ulong disturbPattern = 0;
                    for(int b = 0; b < width; b++)
                    {
                        disturbPattern |= 0x11UL << (b * 8);
                    }
                    foreach(int nOff in new[] { devOff - width, devOff + width })
                    {
                        if(nOff < 0 || nOff + width > DeviceSize)
                        {
                            continue;
                        }
                        ulong nVal = ReadStorageValueRaw(nOff, width);
                        ulong r = FaultTracker.NextLcg(ref seed);
                        ulong disturbed = (nVal & ~(r & disturbPattern)) & valueMask;
                        WriteStorageValueRaw(nOff, disturbed, width);
                    }
                    break;
                }
                case 5: // Wear-leveling corruption
                {
                    WriteStorageValueRaw(devOff, intendedVal, width);
                    int pSize = Math.Max(width, PageSize);
                    int pageStart = (devOff / pSize) * pSize;
                    int wordsPerPage = Math.Max(1, pSize / width);
                    int errorCount = 2 + (int)Math.Min(10UL, TotalPageErases / 8UL);
                    uint seed = tracker.BuildFaultSeed(devOff);
                    ulong byteBitMask = 0;
                    for(int b = 0; b < width; b++)
                    {
                        byteBitMask |= 0x01UL << (b * 8);
                    }
                    for(int i = 0; i < errorCount; i++)
                    {
                        int idx = (int)(FaultTracker.NextLcg(ref seed) % (uint)wordsPerPage);
                        int tOff = pageStart + idx * width;
                        if(tOff < 0 || tOff + width > DeviceSize)
                        {
                            continue;
                        }
                        ulong word = ReadStorageValueRaw(tOff, width);
                        ulong mask = FaultTracker.NextLcg(ref seed) & byteBitMask;
                        if(mask == 0)
                        {
                            mask = 1UL << (int)(FaultTracker.NextLcg(ref seed) % (uint)(width * 8));
                        }
                        WriteStorageValueRaw(tOff, (word & ~mask) & valueMask, width);
                    }
                    break;
                }
                case 6: // Driver error
                {
                    DriverErrorFired = true;
                    WriteStorageValueRaw(devOff, oldVal, width);
                    break;
                }
                default:
                    break;
            }
        }

        // --- Busy Timing & Hardware Controller ANACK Wiring ---

        private void StartWriteCycle(ulong durationUs, int pollCount)
        {
            if(durationUs > 0 && machine != null)
            {
                writeCycleUntilTime = machine.LocalTimeSource.ElapsedVirtualTime + TimeInterval.FromMicroseconds(durationUs);
                hasWriteCycleDeadline = true;
            }
            else
            {
                hasWriteCycleDeadline = false;
            }
            busyPollsRemaining = Math.Max(0, pollCount);
        }

        private bool IsWriteCycleTimeActive()
        {
            if(!hasWriteCycleDeadline || machine == null)
            {
                return false;
            }
            if(machine.LocalTimeSource.ElapsedVirtualTime < writeCycleUntilTime)
            {
                return true;
            }
            hasWriteCycleDeadline = false;
            return false;
        }

        private bool IsBusyNow()
        {
            return ForceBusy || busyPollsRemaining > 0 || IsWriteCycleTimeActive();
        }

        private bool EvaluateAndConsumeBusyPoll()
        {
            bool timeBusy = IsWriteCycleTimeActive();
            bool pollBusy = busyPollsRemaining > 0;
            bool busy = ForceBusy || timeBusy || pollBusy;
            if(busyPollsRemaining > 0)
            {
                busyPollsRemaining--;
            }
            return busy;
        }

        private void AttachToController(IPeripheral controller, int slaveAddr)
        {
            attachedController = controller;
            attachedSlaveAddress = slaveAddr & 0x7F;
            if(controller == null)
            {
                return;
            }

            var type = controller.GetType();
            DoubleWordRegisterCollection regs = (controller as IProvidesRegisterCollection<DoubleWordRegisterCollection>)?.RegistersCollection;
            if(regs == null)
            {
                var regsProp = type.GetProperty("RegistersCollection", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                regs = regsProp?.GetValue(controller) as DoubleWordRegisterCollection;
            }
            if(regs == null)
            {
                var regsField = type.GetField("<RegistersCollection>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)
                    ?? type.GetField("registers", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                regs = regsField?.GetValue(controller) as DoubleWordRegisterCollection;
            }
            if(regs == null || GetControllerField("selectedSlave") == null)
            {
                return;
            }

            IDictionary<long, Action<long, uint>> afterWriteHooks = null;
            for(var t = regs.GetType(); t != null && afterWriteHooks == null; t = t.BaseType)
            {
                foreach(var f in t.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
                {
                    if(typeof(IDictionary<long, Action<long, uint>>).IsAssignableFrom(f.FieldType))
                    {
                        afterWriteHooks = f.GetValue(regs) as IDictionary<long, Action<long, uint>>;
                        break;
                    }
                }
            }
            if(afterWriteHooks == null)
            {
                return;
            }

            // Hook TASKS_STARTTX (0x008), TASKS_STARTRX (0x000), and TASKS_STOP (0x014)
            // on NRF52840_I2C so starting a transaction while the EEPROM is in its
            // internal write cycle (t_WR) causes the controller to NACK with ERRORSRC.ANACK.
            afterWriteHooks[0x008] = OnControllerStartTxWrite;
            afterWriteHooks[0x000] = OnControllerStartRxWrite;
            afterWriteHooks[0x014] = OnControllerStopWrite;
        }

        private void OnControllerStartTxWrite(long _, uint val)
        {
            if(val == 0 || !IsControllerTargetingUs())
            {
                return;
            }
            var selectedSlaveField = GetControllerField("selectedSlave");
            if(selectedSlaveField == null)
            {
                return;
            }
            if(IsBusyNow())
            {
                AckPoll();
                nackLatchedForCurrentControllerTx = true;
                selectedSlaveField.SetValue(attachedController, null);
                RaiseControllerAddressNack();
            }
            else if(nackLatchedForCurrentControllerTx)
            {
                nackLatchedForCurrentControllerTx = false;
                selectedSlaveField.SetValue(attachedController, this);
            }
        }

        private void OnControllerStartRxWrite(long _, uint val)
        {
            if(val == 0 || !IsControllerTargetingUs())
            {
                return;
            }
            var selectedSlaveField = GetControllerField("selectedSlave");
            if(selectedSlaveField == null)
            {
                return;
            }
            if(!transmissionPending && IsBusyNow())
            {
                AckPoll();
                nackLatchedForCurrentControllerTx = true;
                selectedSlaveField.SetValue(attachedController, null);
                RaiseControllerAddressNack();
            }
            else if(nackLatchedForCurrentControllerTx)
            {
                nackLatchedForCurrentControllerTx = false;
                selectedSlaveField.SetValue(attachedController, this);
            }
        }

        private void OnControllerStopWrite(long _, uint val)
        {
            if(val != 0 && nackLatchedForCurrentControllerTx && IsControllerAddressMatchingUs())
            {
                nackLatchedForCurrentControllerTx = false;
                GetControllerField("selectedSlave")?.SetValue(attachedController, this);
            }
        }

        private FieldInfo GetControllerField(string name)
        {
            return attachedController?.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        }

        private bool IsControllerAddressMatchingUs()
        {
            var addressField = GetControllerField("address");
            if(attachedController == null || addressField == null)
            {
                return false;
            }
            var addrFieldObj = addressField.GetValue(attachedController) as IValueRegisterField;
            if(addrFieldObj == null)
            {
                return false;
            }
            return (int)(addrFieldObj.Value & 0x7FUL) == attachedSlaveAddress;
        }

        private bool IsControllerTargetingUs()
        {
            var selectedSlaveField = GetControllerField("selectedSlave");
            if(attachedController == null || selectedSlaveField == null)
            {
                return false;
            }
            var currentSlave = selectedSlaveField.GetValue(attachedController);
            if(ReferenceEquals(currentSlave, this))
            {
                return true;
            }
            return currentSlave == null && IsControllerAddressMatchingUs();
        }

        private void RaiseControllerAddressNack()
        {
            if(attachedController == null)
            {
                return;
            }
            var anack = GetControllerField("addressNackError")?.GetValue(attachedController) as IFlagRegisterField;
            var errPending = GetControllerField("errorInterruptPending")?.GetValue(attachedController) as IFlagRegisterField;
            if(anack != null)
            {
                anack.Value = true;
            }
            if(errPending != null)
            {
                errPending.Value = true;
            }
            var updateMethod = attachedController.GetType().GetMethod("UpdateInterrupts", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            updateMethod?.Invoke(attachedController, null);
        }

        // --- Storage Helpers & Read-Fault Injection ---

        private int NormalizeAddress(long address)
        {
            int size = checked((int)DeviceSize);
            int mod = (int)(address % size);
            return mod < 0 ? mod + size : mod;
        }

        private byte ReadStorageByteWithFault(long offset)
        {
            if(offset < 0 || offset >= DeviceSize)
            {
                return EraseFill;
            }
            byte val = storage[offset];
            if(!ReadFaultEnabled)
            {
                return val;
            }
            long globalAddr = FlashBaseAddress + offset;
            if(ReadFaultAddress >= 0 && globalAddr != ReadFaultAddress && offset != ReadFaultAddress)
            {
                return val;
            }
            ReadFaultTotalReads++;
            if(ReadFaultTotalReads <= ReadFaultSkipCount)
            {
                return val;
            }
            ReadFaultFired = true;
            uint seed = ReadFaultSeed != 0
                ? (ReadFaultSeed ^ (uint)offset ^ (uint)ReadFaultTotalReads)
                : ((uint)offset ^ (uint)(ReadFaultTotalReads * 2654435761U) ^ 0xA5A55A5AU);
            int flips = Math.Max(1, Math.Min(8, ReadFaultBitFlips));
            int usedMask = 0;
            for(int i = 0; i < flips; i++)
            {
                int bit = (int)(FaultTracker.NextLcg(ref seed) % 8U);
                while((usedMask & (1 << bit)) != 0)
                {
                    bit = (bit + 1) & 7;
                }
                usedMask |= 1 << bit;
                val ^= (byte)(1 << bit);
            }
            return val;
        }

        private ulong ReadStorageValueRaw(int offset, int width)
        {
            ulong value = 0;
            for(int b = 0; b < width; b++)
            {
                if(offset + b >= 0 && offset + b < storage.Length)
                {
                    value |= (ulong)storage[offset + b] << (b * 8);
                }
            }
            return value;
        }

        private void WriteStorageValueRaw(int offset, ulong value, int width)
        {
            for(int b = 0; b < width; b++)
            {
                if(offset + b >= 0 && offset + b < storage.Length)
                {
                    storage[offset + b] = (byte)((value >> (b * 8)) & 0xFF);
                }
            }
        }

        private static int ChooseChunkWidth(int offset, int remaining, int maxChunkSize)
        {
            int cap = Math.Min(maxChunkSize, remaining);
            if(cap >= 8 && (offset & 7) == 0) return 8;
            if(cap >= 4 && (offset & 3) == 0) return 4;
            if(cap >= 2 && (offset & 1) == 0) return 2;
            if(cap >= 8) return 8;
            if(cap >= 4) return 4;
            if(cap >= 2) return 2;
            return 1;
        }

        private void ClearPageLatch()
        {
            if(pageLatch != null)
            {
                FillArray(pageLatch, 0, pageLatch.Length, EraseFill);
            }
            if(pageByteTouched != null)
            {
                Array.Clear(pageByteTouched, 0, pageByteTouched.Length);
            }
            pageTouchOrder.Clear();
            pageWriteDataCount = 0;
        }

        private static void FillArray(byte[] arr, int start, int length, byte value)
        {
            for(int i = start; i < start + length; i++)
            {
                arr[i] = value;
            }
        }

        // --- IMemory / Direct Bus Access (for host probes, preloading, and TraceReplayEngine) ---

        public byte ReadByte(long offset)
        {
            return ReadStorageByteWithFault(offset);
        }

        public void WriteByte(long offset, byte value)
        {
            if(offset >= 0 && offset < storage.Length)
            {
                storage[offset] = value;
            }
        }

        public ushort ReadWord(long offset)
        {
            return (ushort)(ReadByte(offset) | (ReadByte(offset + 1) << 8));
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteStorageValueRaw(checked((int)offset), value, 2);
        }

        public uint ReadDoubleWord(long offset)
        {
            return (uint)(ReadByte(offset)
                | (ReadByte(offset + 1) << 8)
                | (ReadByte(offset + 2) << 16)
                | (ReadByte(offset + 3) << 24));
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteStorageValueRaw(checked((int)offset), value, 4);
        }

        public ulong ReadQuadWord(long offset)
        {
            return (ulong)ReadDoubleWord(offset) | ((ulong)ReadDoubleWord(offset + 4) << 32);
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            WriteStorageValueRaw(checked((int)offset), value, 8);
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
        {
            if(count <= 0)
            {
                return new byte[0];
            }
            byte[] result = new byte[count];
            int avail = (int)Math.Max(0L, Math.Min((long)count, DeviceSize - offset));
            if(avail > 0 && offset >= 0)
            {
                Array.Copy(storage, (int)offset, result, 0, avail);
            }
            for(int i = avail; i < count; i++)
            {
                result[i] = EraseFill;
            }
            return result;
        }

        public void WriteBytes(long offset, byte[] value, int startingIndex, int count, IPeripheral context = null)
        {
            if(value == null || count <= 0 || offset < 0 || offset >= DeviceSize)
            {
                return;
            }
            int avail = (int)Math.Min((long)count, DeviceSize - offset);
            Array.Copy(value, startingIndex, storage, (int)offset, avail);
        }

        public void WriteBytes(long offset, byte[] value)
        {
            if(value != null)
            {
                WriteBytes(offset, value, 0, value.Length);
            }
        }
    }
}

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class I2CEEPROM : I2C.I2CEEPROM
    {
        public I2CEEPROM(
            IMachine machine,
            long size = DefaultMemorySize,
            int pageSize = DefaultPageBufferSize,
            int addressBytes = 2,
            long flashBaseAddress = 0x0,
            byte eraseFill = 0xFF)
            : base(machine, size, pageSize, addressBytes, flashBaseAddress, eraseFill)
        {
        }
    }
}
