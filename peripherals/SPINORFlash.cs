// Copyright (c) 2026 Neil Berkman
// SPDX-License-Identifier: Apache-2.0
//
// JEDEC SPI NOR Flash peripheral model with Tardigrade fault injection.
//
// Modeled part and datasheet reference:
//   Winbond W25Q16JV — "3V 16M-Bit Serial Flash Memory with Dual/Quad SPI",
//      Revision F:
//      - Section 7.1 Status Registers:
//        * Status Register-1 (RDSR1 0x05, WRSR1 0x01):
//          bit 0 = BUSY / WIP (Write In Progress, read-only)
//          bit 1 = WEL (Write Enable Latch)
//          bits 2..4 = BP0..BP2, bit 5 = TB, bit 6 = SEC, bit 7 = SRP
//        * Status Register-2 (RDSR2 0x35, WRSR2 0x31)
//        * Status Register-3 (RDSR3 0x15, WRSR3 0x11)
//      - Section 8.2.1 Write Enable (WREN 0x06): sets WEL = 1.
//      - Section 8.2.3 Write Disable (WRDI 0x04): clears WEL = 0.
//      - Section 8.2.6 Read Data (READ 0x03) & Section 8.2.7 Fast Read
//        (FAST_READ 0x0B with 8 dummy clocks): sequential byte stream
//        wrapping at device boundary.
//      - Section 8.2.15 Page Program (PP 0x02): requires WEL = 1 and
//        WIP = 0; latches up to 256 bytes into the target 256-byte page buffer
//        [addr & ~0xFF .. (addr & ~0xFF) + 0xFF] with in-page address wrap
//        ((addr & ~0xFF) | ((addr + i) & 0xFF)); on CS# rising edge
//        (FinishTransmission), programs 1->0 bit transitions (old & data),
//        clears WEL = 0, and asserts WIP = 1 for t_PP (typ. 0.7 ms, max 3 ms).
//      - Section 8.2.17 Sector Erase (SE 0x20): 4 KiB (4096 B) aligned
//        to addr & ~0xFFF, erases to 0xFF, clears WEL = 0, asserts WIP = 1 for t_SE.
//      - Section 8.2.18 32KB Block Erase (BE32K 0x52): 32 KiB (32768 B) aligned
//        to addr & ~0x7FFF, erases to 0xFF, clears WEL = 0, asserts WIP = 1 for t_BE1.
//      - Section 8.2.19 64KB Block Erase (BE64K 0xD8): 64 KiB (65536 B)
//        aligned to addr & ~0xFFFF, erases to 0xFF, clears WEL = 0, asserts WIP = 1.
//      - Section 8.2.20 Chip Erase (CE 0xC7 / 0x60): erases entire array to 0xFF,
//        clears WEL = 0, asserts WIP = 1 for t_CE.
//      - Section 8.2.27 Read JEDEC ID (RDID 0x9F): returns 3-byte ID
//        (Winbond W25Q16JV: 0xEF, 0x40, 0x15).
//      - Section 8.2.29 Read SFDP Register (RDSFDP 0x5A): 24-bit address +
//        8 dummy clocks, returns JEDEC JESD216B SFDP header ("SFDP" 0x50444653)
//        and 16-DWORD Basic Flash Parameter Table (BFPT) describing 256-byte
//        page size, 4 KiB (0x20), 32 KiB (0x52), and 64 KiB (0xD8) erase types.
//      The model also accepts the standard 4-byte-address opcode variants so a
//      larger configured instance can use the same peripheral implementation.

using System;
using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Memory;
using Antmicro.Renode.Peripherals.Miscellaneous;
using Antmicro.Renode.Time;

namespace Antmicro.Renode.Peripherals.SPI
{
    public class SPINORFlash :
        ISPIPeripheral,
        IGPIOReceiver,
        IMemory,
        IBytePeripheral,
        IWordPeripheral,
        IDoubleWordPeripheral,
        IQuadWordPeripheral,
        IKnownSize,
        ITardigradeFaultInjectable
    {
        public const int PageBufferSize = 256;
        public const int SectorEraseSize = 4096;
        public const int Block32EraseSize = 32768;
        public const int Block64EraseSize = 65536;

        // JEDEC SPI NOR opcodes (W25Q16JV Section 8.1), plus standard 4-byte variants.
        private const byte CMD_WRSR1      = 0x01;
        private const byte CMD_PP         = 0x02;
        private const byte CMD_READ       = 0x03;
        private const byte CMD_WRDI       = 0x04;
        private const byte CMD_RDSR1      = 0x05;
        private const byte CMD_WREN       = 0x06;
        private const byte CMD_FAST_READ  = 0x0B;
        private const byte CMD_FAST_READ4 = 0x0C;
        private const byte CMD_WRSR3      = 0x11;
        private const byte CMD_PP4        = 0x12;
        private const byte CMD_READ4      = 0x13;
        private const byte CMD_RDSR3      = 0x15;
        private const byte CMD_SE         = 0x20;
        private const byte CMD_SE4        = 0x21;
        private const byte CMD_WRSR2      = 0x31;
        private const byte CMD_RDSR2      = 0x35;
        private const byte CMD_WREN_VSR   = 0x50;
        private const byte CMD_BE32K      = 0x52;
        private const byte CMD_RDSFDP     = 0x5A;
        private const byte CMD_CE_ALT     = 0x60;
        private const byte CMD_RSTEN      = 0x66;
        private const byte CMD_ULBPR      = 0x98;
        private const byte CMD_RST        = 0x99;
        private const byte CMD_RDID       = 0x9F;
        private const byte CMD_RDPD       = 0xAB;
        private const byte CMD_EN4B       = 0xB7;
        private const byte CMD_DPD        = 0xB9;
        private const byte CMD_CE         = 0xC7;
        private const byte CMD_BE64K      = 0xD8;
        private const byte CMD_BE64K4     = 0xDC;
        private const byte CMD_EX4B       = 0xE9;

        // Status Register-1 bits.
        private const byte SR1_WIP = 0x01;
        private const byte SR1_WEL = 0x02;
        private const byte SR1_WRITABLE_MASK = 0xFC;

        private readonly IMachine machine;
        private FaultTracker tracker = new FaultTracker();
        private byte[] internalStorage;
        private IMemory backingMemory;
        private NRF52NVMC companionNvmc;

        // Active SPI transaction state.
        private bool csConfigured;
        private bool csActive = true;
        private bool inTransaction;
        private byte activeCommand;
        private int commandByteIndex;
        private int addressBytesNeeded;
        private int dummyBytesNeeded;
        private uint commandAddress;
        private uint streamOffset;
        private bool fourByteAddressMode;
        private bool deepPowerDown;
        private bool resetEnabled;

        // Status registers.
        private byte statusReg1;
        private byte statusReg2;
        private byte statusReg3;
        private readonly List<byte> statusWriteBuffer = new List<byte>(3);

        // 256-byte page program latch and write-order tracking.
        private readonly byte[] pageLatch = new byte[PageBufferSize];
        private readonly bool[] pageByteTouched = new bool[PageBufferSize];
        private readonly List<int> pageTouchOrder = new List<int>(PageBufferSize);
        private int pageProgramDataCount;

        // Busy / WIP timing state.
        private TimeInterval busyUntilTime;
        private bool hasBusyDeadline;
        private int busyPollsRemaining;
        private byte[] sfdpTable;

        public SPINORFlash(
            IMachine machine,
            long size = 0x200000,
            long flashBaseAddress = 0x0,
            long storageBaseOffset = 0x0,
            byte eraseFill = 0xFF,
            byte jedecManufacturerId = 0xEF,
            byte jedecMemoryType = 0x40,
            byte jedecCapacityId = 0x15)
        {
            if(size <= 0 || (size % SectorEraseSize) != 0)
            {
                throw new ConstructionException(
                    $"SPINORFlash size must be a positive multiple of {SectorEraseSize} bytes (got {size})");
            }
            this.machine = machine;
            tracker.Bind(machine, this);
            DeviceSize = size;
            FlashBaseAddress = flashBaseAddress;
            FlashSize = size;
            StorageBaseOffset = storageBaseOffset;
            EraseFill = eraseFill;
            PageSize = SectorEraseSize;
            JedecManufacturerId = jedecManufacturerId;
            JedecMemoryType = jedecMemoryType;
            JedecCapacityId = jedecCapacityId;

            internalStorage = new byte[checked((int)size)];
            FillArray(internalStorage, 0, internalStorage.Length, eraseFill);
            RebuildSfdpTable();
        }

        public long Size => DeviceSize;

        public long DeviceSize { get; private set; }

        // Offset within BackingMemory where this SPI NOR flash's array resides.
        // 0 when standalone; e.g. 0x00100000 when sharing a 2 MiB MappedMemory
        // with 1 MiB internal flash at [0x00000000..0x000FFFFF].
        public long StorageBaseOffset { get; set; }

        public IMemory BackingMemory
        {
            get => backingMemory;
            set
            {
                backingMemory = value;
                if(backingMemory != null)
                {
                    internalStorage = null;
                }
            }
        }

        public IMemory Flash
        {
            get => backingMemory ?? (IMemory)this;
            set
            {
                if(value != null && !ReferenceEquals(value, this))
                {
                    BackingMemory = value;
                }
            }
        }

        public NRF52NVMC CompanionNvmc
        {
            get => companionNvmc;
            set
            {
                companionNvmc = value;
                if(companionNvmc != null)
                {
                    companionNvmc.SharedTracker = tracker;
                }
            }
        }

        public FaultTracker Tracker => tracker;

        public long FlashBaseAddress { get; set; }
        public long FlashSize { get; set; }
        public int PageSize { get; set; } = SectorEraseSize;
        public byte EraseFill { get; set; } = 0xFF;

        // JEDEC ID (0x9F). Defaults to Winbond W25Q16JV (EF 40 15).
        public byte JedecManufacturerId { get; set; }
        public byte JedecMemoryType { get; set; }
        public byte JedecCapacityId { get; set; }
        public byte ElectronicSignature { get; set; } = 0x14;

        // Program / erase busy time configuration.
        // Virtual time durations in microseconds (0 = rely on poll counter only)
        // and deterministic RDSR poll counts before WIP clears.
        public ulong ProgramBusyTimeUs { get; set; } = 0;
        public ulong SectorEraseBusyTimeUs { get; set; } = 0;
        public ulong Block32EraseBusyTimeUs { get; set; } = 0;
        public ulong Block64EraseBusyTimeUs { get; set; } = 0;
        public ulong ChipEraseBusyTimeUs { get; set; } = 0;
        public ulong StatusWriteBusyTimeUs { get; set; } = 0;

        public int BusyPollsPerProgram { get; set; } = 1;
        public int BusyPollsPerErase { get; set; } = 1;
        public int BusyPollsPerStatusWrite { get; set; } = 0;
        public bool ForceBusy { get; set; }

        public int BusyPollsRemaining
        {
            get => busyPollsRemaining;
            set => busyPollsRemaining = Math.Max(0, value);
        }

        // Write chunking and page-level fault options.
        // Default ProgramChunkSize = 4 emits 4-byte (or 1/2-byte tail) write trace
        // records compatible with TraceReplayEngine and state_search.
        // Setting PageLevelWriteTracking = true counts each Page Program (0x02)
        // command as a single write event for page-atomic fault tests.
        private int programChunkSize = 4;
        public int ProgramChunkSize
        {
            get => programChunkSize;
            set
            {
                if(value != 1 && value != 2 && value != 4 && value != 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        "ProgramChunkSize must be 1, 2, 4, or 8 bytes");
                }
                programChunkSize = value;
            }
        }

        public bool PageLevelWriteTracking { get; set; }

        // Diagnostic counters for command validation and tests.
        public ulong IgnoredWithoutWelCount { get; private set; }
        public ulong IgnoredWhileBusyCount { get; private set; }
        public ulong StatusPollBusyObservedCount { get; private set; }
        public ulong PageProgramCommandCount { get; private set; }
        public ulong PageProgramWrapCount { get; private set; }
        public ulong SectorEraseCommandCount { get; private set; }
        public ulong Block32EraseCommandCount { get; private set; }
        public ulong Block64EraseCommandCount { get; private set; }
        public ulong ChipEraseCommandCount { get; private set; }

        public bool WriteEnableLatch
        {
            get => (statusReg1 & SR1_WEL) != 0;
            set
            {
                if(value)
                {
                    statusReg1 |= SR1_WEL;
                }
                else
                {
                    statusReg1 = (byte)(statusReg1 & ~SR1_WEL);
                }
            }
        }

        public bool WriteInProgress => IsBusyNow();

        public byte StatusRegister1 => ComposeStatusRegister1(consumePoll: false);
        public byte StatusRegister2 { get => statusReg2; set => statusReg2 = value; }
        public byte StatusRegister3 { get => statusReg3; set => statusReg3 = value; }

        // --- ITardigradeFaultInjectable implementation ---

        public ulong TotalWordWrites { get => tracker.TotalWordWrites; set => tracker.TotalWordWrites = value; }
        public ulong FaultAtWordWrite { get => tracker.FaultAtWordWrite; set => tracker.FaultAtWordWrite = value; }
        public bool FaultFired { get => tracker.FaultFired; set => tracker.FaultFired = value; }
        public uint LastFaultAddress { get => tracker.LastFaultAddress; set => tracker.LastFaultAddress = value; }
        public ulong LastFaultPC { get => tracker.LastFaultPC; set => tracker.LastFaultPC = value; }
        public string LastFaultCallContext { get => tracker.LastFaultCallContext; set => tracker.LastFaultCallContext = value; }
        public string WriteCallContextToString() => tracker.WriteCallContextToString();
        public string EraseCallContextToString() => tracker.EraseCallContextToString();
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

        // Fast-path compatibility properties forwarded to CompanionNvmc when present.
        private int diffLookahead = 32;
        public int DiffLookahead
        {
            get => diffLookahead;
            set
            {
                diffLookahead = value;
                if(companionNvmc != null)
                {
                    companionNvmc.DiffLookahead = value;
                }
            }
        }

        private bool skipShadowScan = true;
        public bool SkipShadowScan
        {
            get => skipShadowScan;
            set
            {
                skipShadowScan = value;
                if(companionNvmc != null)
                {
                    companionNvmc.SkipShadowScan = value;
                }
            }
        }

        private bool passthroughMode;
        public bool PassthroughMode
        {
            get => passthroughMode;
            set
            {
                passthroughMode = value;
                if(companionNvmc != null)
                {
                    companionNvmc.PassthroughMode = value;
                }
            }
        }

        private bool operationTraceFastMode;
        public bool OperationTraceFastMode
        {
            get => operationTraceFastMode;
            set
            {
                operationTraceFastMode = value;
                if(companionNvmc != null)
                {
                    companionNvmc.OperationTraceFastMode = value;
                }
            }
        }

        public void InvalidateShadow()
        {
            if(companionNvmc != null)
            {
                companionNvmc.InvalidateShadow();
            }
        }

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
            inTransaction = false;
            activeCommand = 0;
            commandByteIndex = 0;
            addressBytesNeeded = 0;
            dummyBytesNeeded = 0;
            commandAddress = 0;
            streamOffset = 0;
            fourByteAddressMode = false;
            deepPowerDown = false;
            resetEnabled = false;
            statusReg1 = 0;
            statusReg2 = 0;
            statusReg3 = 0;
            statusWriteBuffer.Clear();
            ClearPageLatch();
            hasBusyDeadline = false;
            busyPollsRemaining = 0;
            ForceBusy = false;
            ReadFaultFired = false;
            ReadFaultTotalReads = 0;
            if(!PreserveCountersAcrossReset)
            {
                IgnoredWithoutWelCount = 0;
                IgnoredWhileBusyCount = 0;
                StatusPollBusyObservedCount = 0;
                PageProgramCommandCount = 0;
                PageProgramWrapCount = 0;
                SectorEraseCommandCount = 0;
                Block32EraseCommandCount = 0;
                Block64EraseCommandCount = 0;
                ChipEraseCommandCount = 0;
            }
        }

        // --- IGPIOReceiver (CS# active-low on GPIO input 0) ---

        public void OnGPIO(int number, bool value)
        {
            if(number != 0)
            {
                return;
            }
            csConfigured = true;
            bool nowActive = !value; // Active-low CS#
            if(csActive && !nowActive)
            {
                FinishTransmission();
            }
            csActive = nowActive;
        }

        // --- ISPIPeripheral ---

        public byte Transmit(byte data)
        {
            if(csConfigured && !csActive)
            {
                return 0xFF;
            }

            if(!inTransaction)
            {
                BeginCommand(data);
                return 0xFF;
            }

            commandByteIndex++;

            // Collect address bytes if required by the active command.
            if(addressBytesNeeded > 0)
            {
                commandAddress = (commandAddress << 8) | data;
                addressBytesNeeded--;
                if(addressBytesNeeded == 0)
                {
                    streamOffset = commandAddress;
                }
                return 0xFF;
            }

            // Consume dummy bytes (e.g. 0x0B FAST_READ, 0x5A RDSFDP, 0xAB RDPD).
            if(dummyBytesNeeded > 0)
            {
                dummyBytesNeeded--;
                return 0xFF;
            }

            switch(activeCommand)
            {
                case CMD_RDSR1:
                    return ComposeStatusRegister1(consumePoll: true);

                case CMD_RDSR2:
                    return statusReg2;

                case CMD_RDSR3:
                    return statusReg3;

                case CMD_RDID:
                {
                    int idIdx = commandByteIndex - 1;
                    if(idIdx == 0) return JedecManufacturerId;
                    if(idIdx == 1) return JedecMemoryType;
                    if(idIdx == 2) return JedecCapacityId;
                    return 0x00;
                }

                case CMD_RDPD:
                    return ElectronicSignature;

                case CMD_RDSFDP:
                {
                    if(sfdpTable == null)
                    {
                        RebuildSfdpTable();
                    }
                    uint idx = streamOffset;
                    streamOffset++;
                    return idx < (uint)sfdpTable.Length ? sfdpTable[idx] : (byte)0xFF;
                }

                case CMD_READ:
                case CMD_FAST_READ:
                case CMD_READ4:
                case CMD_FAST_READ4:
                {
                    long devOff = (long)(streamOffset % (uint)DeviceSize);
                    streamOffset = (uint)((devOff + 1) % DeviceSize);
                    return ReadStorageByteWithFault(devOff);
                }

                case CMD_PP:
                case CMD_PP4:
                {
                    LatchPageProgramByte(data);
                    return 0xFF;
                }

                case CMD_WRSR1:
                case CMD_WRSR2:
                case CMD_WRSR3:
                {
                    if(statusWriteBuffer.Count < 3)
                    {
                        statusWriteBuffer.Add(data);
                    }
                    return 0xFF;
                }

                default:
                    return 0xFF;
            }
        }

        public void FinishTransmission()
        {
            if(!inTransaction)
            {
                return;
            }

            try
            {
                CompleteCommandOnCsHigh();
            }
            finally
            {
                inTransaction = false;
                activeCommand = 0;
                commandByteIndex = 0;
                addressBytesNeeded = 0;
                dummyBytesNeeded = 0;
            }
        }

        // --- Command State Machine ---

        private void BeginCommand(byte opcode)
        {
            inTransaction = true;
            activeCommand = opcode;
            commandByteIndex = 0;
            addressBytesNeeded = 0;
            dummyBytesNeeded = 0;
            commandAddress = 0;
            streamOffset = 0;
            statusWriteBuffer.Clear();
            ClearPageLatch();

            if(deepPowerDown && opcode != CMD_RDPD && opcode != CMD_RDID && opcode != CMD_RSTEN && opcode != CMD_RST)
            {
                activeCommand = 0;
                return;
            }

            if(opcode != CMD_RST)
            {
                resetEnabled = false;
            }

            int defaultAddrBytes = fourByteAddressMode ? 4 : 3;

            switch(opcode)
            {
                case CMD_READ:
                case CMD_PP:
                case CMD_SE:
                case CMD_BE32K:
                case CMD_BE64K:
                    addressBytesNeeded = defaultAddrBytes;
                    break;

                case CMD_FAST_READ:
                    addressBytesNeeded = defaultAddrBytes;
                    dummyBytesNeeded = 1;
                    break;

                case CMD_READ4:
                case CMD_PP4:
                case CMD_SE4:
                case CMD_BE64K4:
                    addressBytesNeeded = 4;
                    break;

                case CMD_FAST_READ4:
                    addressBytesNeeded = 4;
                    dummyBytesNeeded = 1;
                    break;

                case CMD_RDSFDP:
                    addressBytesNeeded = 3;
                    dummyBytesNeeded = 1;
                    break;

                case CMD_RDPD:
                    dummyBytesNeeded = 3;
                    break;
            }
        }

        private void LatchPageProgramByte(byte data)
        {
            // W25Q16JV Section 8.2.15: The lower 8 bits of the address increment
            // inside the 256-byte page [pageBase .. pageBase + 0xFF]; if more bytes
            // are clocked than remain in the page, the address wraps to offset 0
            // of the same 256-byte page.
            int startInPage = (int)(commandAddress & (uint)(PageBufferSize - 1));
            int rawOffset = startInPage + pageProgramDataCount;
            if(rawOffset >= PageBufferSize && pageProgramDataCount == PageBufferSize - startInPage)
            {
                PageProgramWrapCount++;
            }
            int inPageOffset = rawOffset & (PageBufferSize - 1);
            pageLatch[inPageOffset] = data;
            if(!pageByteTouched[inPageOffset])
            {
                pageByteTouched[inPageOffset] = true;
                pageTouchOrder.Add(inPageOffset);
            }
            else
            {
                // Move to latest position in write order if overwritten via >256B wrap.
                pageTouchOrder.Remove(inPageOffset);
                pageTouchOrder.Add(inPageOffset);
            }
            pageProgramDataCount++;
        }

        private void CompleteCommandOnCsHigh()
        {
            switch(activeCommand)
            {
                case CMD_WREN:
                    if(IsBusyNow())
                    {
                        IgnoredWhileBusyCount++;
                        return;
                    }
                    statusReg1 |= SR1_WEL;
                    break;

                case CMD_WREN_VSR:
                    break;

                case CMD_WRDI:
                    statusReg1 = (byte)(statusReg1 & ~SR1_WEL);
                    break;

                case CMD_DPD:
                    if(!IsBusyNow())
                    {
                        deepPowerDown = true;
                    }
                    break;

                case CMD_RDPD:
                    deepPowerDown = false;
                    break;

                case CMD_EN4B:
                    fourByteAddressMode = true;
                    break;

                case CMD_EX4B:
                    fourByteAddressMode = false;
                    break;

                case CMD_ULBPR:
                    if(WriteEnableLatch && !IsBusyNow())
                    {
                        statusReg1 = (byte)(statusReg1 & ~(0x1C | SR1_WEL));
                    }
                    break;

                case CMD_RSTEN:
                    resetEnabled = true;
                    break;

                case CMD_RST:
                    if(resetEnabled)
                    {
                        resetEnabled = false;
                        fourByteAddressMode = false;
                        deepPowerDown = false;
                        statusReg1 = (byte)(statusReg1 & ~SR1_WEL);
                        hasBusyDeadline = false;
                        busyPollsRemaining = 0;
                        ForceBusy = false;
                    }
                    break;

                case CMD_WRSR1:
                case CMD_WRSR2:
                case CMD_WRSR3:
                    ExecuteWriteStatusRegister();
                    break;

                case CMD_PP:
                case CMD_PP4:
                    if(addressBytesNeeded == 0 && pageProgramDataCount > 0)
                    {
                        ExecutePageProgram();
                    }
                    break;

                case CMD_SE:
                case CMD_SE4:
                    if(addressBytesNeeded == 0)
                    {
                        SectorEraseCommandCount++;
                        ExecuteErase(commandAddress & ~(uint)(SectorEraseSize - 1), SectorEraseSize, SectorEraseBusyTimeUs);
                    }
                    break;

                case CMD_BE32K:
                    if(addressBytesNeeded == 0)
                    {
                        Block32EraseCommandCount++;
                        ExecuteErase(commandAddress & ~(uint)(Block32EraseSize - 1), Block32EraseSize, Block32EraseBusyTimeUs);
                    }
                    break;

                case CMD_BE64K:
                case CMD_BE64K4:
                    if(addressBytesNeeded == 0)
                    {
                        Block64EraseCommandCount++;
                        ExecuteErase(commandAddress & ~(uint)(Block64EraseSize - 1), Block64EraseSize, Block64EraseBusyTimeUs);
                    }
                    break;

                case CMD_CE:
                case CMD_CE_ALT:
                    ChipEraseCommandCount++;
                    ExecuteErase(0, checked((int)DeviceSize), ChipEraseBusyTimeUs);
                    break;
            }
        }

        private void ExecuteWriteStatusRegister()
        {
            if(IsBusyNow())
            {
                IgnoredWhileBusyCount++;
                return;
            }
            if(!WriteEnableLatch)
            {
                IgnoredWithoutWelCount++;
                return;
            }
            if(statusWriteBuffer.Count > 0)
            {
                if(activeCommand == CMD_WRSR1)
                {
                    statusReg1 = (byte)((statusWriteBuffer[0] & SR1_WRITABLE_MASK) | (statusReg1 & ~SR1_WRITABLE_MASK));
                    if(statusWriteBuffer.Count > 1)
                    {
                        statusReg2 = statusWriteBuffer[1];
                    }
                    if(statusWriteBuffer.Count > 2)
                    {
                        statusReg3 = statusWriteBuffer[2];
                    }
                }
                else if(activeCommand == CMD_WRSR2)
                {
                    statusReg2 = statusWriteBuffer[0];
                }
                else if(activeCommand == CMD_WRSR3)
                {
                    statusReg3 = statusWriteBuffer[0];
                }
            }
            WriteEnableLatch = false;
            StartBusyWindow(StatusWriteBusyTimeUs, BusyPollsPerStatusWrite);
        }

        private void ExecutePageProgram()
        {
            if(IsBusyNow())
            {
                IgnoredWhileBusyCount++;
                return;
            }
            if(!WriteEnableLatch)
            {
                IgnoredWithoutWelCount++;
                return;
            }

            PageProgramCommandCount++;
            WriteEnableLatch = false;
            StartBusyWindow(ProgramBusyTimeUs, BusyPollsPerProgram);

            if(AnyFaultFired)
            {
                return;
            }

            long pageBase = (long)(commandAddress % (uint)DeviceSize) & ~(long)(PageBufferSize - 1);
            if(pageTouchOrder.Count == 0)
            {
                return;
            }

            if(PageLevelWriteTracking)
            {
                ExecutePageLevelTrackedProgram(pageBase);
                return;
            }

            // Build contiguous spans in the order bytes were latched into the page buffer,
            // then split each span into power-of-two chunks (up to ProgramChunkSize).
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
                    int chunkWidth = ChooseChunkWidth(inPageOff, remaining, programChunkSize);
                    long devOff = pageBase + inPageOff;
                    if(devOff >= 0 && devOff + chunkWidth <= DeviceSize)
                    {
                        if(!ProgramChunkWithFault(devOff, inPageOff, chunkWidth))
                        {
                            // Power-loss fault fired mid-page: abort remaining chunks.
                            return;
                        }
                    }
                    rel += chunkWidth;
                }

                idx += spanLen;
            }
        }

        private void ExecutePageLevelTrackedProgram(long pageBase)
        {
            int count = pageTouchOrder.Count;
            int firstInPage = pageTouchOrder[0];
            long firstDevOff = pageBase + firstInPage;
            int globalFirstOff = checked((int)(StorageBaseOffset + firstDevOff));

            int traceWidth = ChooseChunkWidth(firstInPage, count, Math.Min(8, programChunkSize));
            ulong oldWord = ReadStorageValueRaw(firstDevOff, traceWidth);
            ulong reqWord = 0;
            for(int b = 0; b < traceWidth; b++)
            {
                int pOff = (firstInPage + b) & (PageBufferSize - 1);
                byte latched = pageByteTouched[pOff] ? pageLatch[pOff] : (byte)0xFF;
                reqWord |= (ulong)latched << (b * 8);
            }
            ulong intendedWord = oldWord & reqWord;

            bool isFault = PassthroughMode
                ? tracker.IncrementWriteCount()
                : tracker.RecordWriteAndCheckFault(globalFirstOff, intendedWord, traceWidth);

            if(isFault)
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + globalFirstOff);
                if(WriteFaultMode == 0)
                {
                    string mode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                    if(mode == "untouched")
                    {
                        // Cut before page program commits any bytes.
                    }
                    else if(mode == "programmed")
                    {
                        for(int i = 0; i < count; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            long dOff = pageBase + pOff;
                            byte cur = ReadStorageByteRaw(dOff);
                            WriteStorageByteRaw(dOff, (byte)(cur & pageLatch[pOff]));
                        }
                    }
                    else if(mode == "partial_bits")
                    {
                        for(int i = 0; i < count; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            long dOff = pageBase + pOff;
                            long gOff = StorageBaseOffset + dOff;
                            byte cur = ReadStorageByteRaw(dOff);
                            byte target = (byte)(cur & pageLatch[pOff]);
                            ulong torn = FaultTracker.BuildFlashTornProgramValue(
                                cur, target, 1, EraseFill, "partial_bits",
                                TornWordSeed, TotalWordWrites, gOff);
                            WriteStorageByteRaw(dOff, (byte)(torn & 0xFF));
                        }
                    }
                    else
                    {
                        // "fixed" / "half" / "half_retain": cut part-way through the
                        // page program, committing the first half of the latched bytes
                        // and leaving the second half untouched.
                        int halfCount = count / 2;
                        for(int i = 0; i < halfCount; i++)
                        {
                            int pOff = pageTouchOrder[i];
                            long dOff = pageBase + pOff;
                            byte cur = ReadStorageByteRaw(dOff);
                            WriteStorageByteRaw(dOff, (byte)(cur & pageLatch[pOff]));
                        }
                    }
                    FaultFlashSnapshot = ReadFullFlashSnapshot();
                    return;
                }

                // Non-power write fault on page-level operation: apply fault to first chunk
                // and commit remaining bytes of the page.
                ApplyNonPowerWriteFault(firstDevOff, globalFirstOff, oldWord, intendedWord, traceWidth);
                for(int i = traceWidth; i < count; i++)
                {
                    int pOff = pageTouchOrder[i];
                    long dOff = pageBase + pOff;
                    byte cur = ReadStorageByteRaw(dOff);
                    WriteStorageByteRaw(dOff, (byte)(cur & pageLatch[pOff]));
                }
                FaultFlashSnapshot = ReadFullFlashSnapshot();
                return;
            }

            for(int i = 0; i < count; i++)
            {
                int pOff = pageTouchOrder[i];
                long dOff = pageBase + pOff;
                byte cur = ReadStorageByteRaw(dOff);
                WriteStorageByteRaw(dOff, (byte)(cur & pageLatch[pOff]));
            }
        }

        private bool ProgramChunkWithFault(long devOff, int inPageOff, int width)
        {
            int globalOff = checked((int)(StorageBaseOffset + devOff));
            ulong oldVal = ReadStorageValueRaw(devOff, width);
            ulong rawVal = 0;
            for(int b = 0; b < width; b++)
            {
                rawVal |= (ulong)pageLatch[inPageOff + b] << (b * 8);
            }
            // NOR flash physics: Page Program can only clear bits from 1 to 0.
            ulong intendedVal = oldVal & rawVal;

            bool isFault = PassthroughMode
                ? tracker.IncrementWriteCount()
                : tracker.RecordWriteAndCheckFault(globalOff, intendedVal, width);

            if(isFault)
            {
                FaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + globalOff);

                if(WriteFaultMode == 0)
                {
                    string mode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                    if((mode == "half" || mode == "half_retain") && width >= 2)
                    {
                        int halfBytes = width / 2;
                        ulong mask = ((1UL << (halfBytes * 8)) - 1UL);
                        ulong halfVal = (intendedVal & mask) | (oldVal & ~mask);
                        WriteStorageValueRaw(devOff, halfVal, width);
                    }
                    else
                    {
                        string flashMode = (mode == "half" || mode == "half_retain") ? "fixed" : mode;
                        ulong torn = FaultTracker.BuildFlashTornProgramValue(
                            oldVal, intendedVal, width, EraseFill, flashMode,
                            TornWordSeed, TotalWordWrites, globalOff);
                        WriteStorageValueRaw(devOff, torn, width);
                    }
                    FaultFlashSnapshot = ReadFullFlashSnapshot();
                    return false;
                }

                ApplyNonPowerWriteFault(devOff, globalOff, oldVal, intendedVal, width);
                FaultFlashSnapshot = ReadFullFlashSnapshot();
                return true;
            }

            WriteStorageValueRaw(devOff, intendedVal, width);
            return true;
        }

        private void ApplyNonPowerWriteFault(long devOff, int globalOff, ulong oldVal, ulong intendedVal, int width)
        {
            ulong valueMask = width == 8 ? ulong.MaxValue : ((1UL << (width * 8)) - 1UL);
            switch(WriteFaultMode)
            {
                case 1: // Bit corruption: keep only a PRNG subset of 1->0 transitions.
                {
                    uint seed = tracker.BuildFaultSeed(globalOff);
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
                case 2: // Silent write failure: all-FF on even write index, all-00 on odd.
                {
                    ulong silentVal = ((TotalWordWrites & 1UL) == 0UL) ? valueMask : 0UL;
                    WriteStorageValueRaw(devOff, silentVal, width);
                    break;
                }
                case 3: // Write rejection: drop the write (keep old value).
                {
                    WriteStorageValueRaw(devOff, oldVal, width);
                    break;
                }
                case 4: // Write disturb: commit target, flip 1->0 bits in neighbors.
                {
                    WriteStorageValueRaw(devOff, intendedVal, width);
                    uint seed = tracker.BuildFaultSeed(globalOff);
                    ulong disturbPattern = 0;
                    for(int b = 0; b < width; b++)
                    {
                        disturbPattern |= 0x11UL << (b * 8);
                    }
                    foreach(long nOff in new[] { devOff - width, devOff + width })
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
                case 5: // Wear-leveling corruption: commit target, age words in sector.
                {
                    WriteStorageValueRaw(devOff, intendedVal, width);
                    int pageSize = Math.Max(width, PageSize);
                    long pageStart = (devOff / pageSize) * pageSize;
                    int wordsPerPage = Math.Max(1, pageSize / width);
                    int errorCount = 2 + (int)Math.Min(10UL, TotalPageErases / 8UL);
                    uint seed = tracker.BuildFaultSeed(globalOff);
                    ulong byteBitMask = 0;
                    for(int b = 0; b < width; b++)
                    {
                        byteBitMask |= 0x01UL << (b * 8);
                    }
                    for(int i = 0; i < errorCount; i++)
                    {
                        int idx = (int)(FaultTracker.NextLcg(ref seed) % (uint)wordsPerPage);
                        long tOff = pageStart + (long)idx * width;
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
                case 6: // Driver error: reject write and raise DriverErrorFired.
                {
                    DriverErrorFired = true;
                    WriteStorageValueRaw(devOff, oldVal, width);
                    break;
                }
                default:
                    break;
            }
        }

        private void ExecuteErase(long alignedDevOffset, int eraseSize, ulong busyTimeUs)
        {
            if(IsBusyNow())
            {
                IgnoredWhileBusyCount++;
                return;
            }
            if(!WriteEnableLatch)
            {
                IgnoredWithoutWelCount++;
                return;
            }

            WriteEnableLatch = false;
            StartBusyWindow(busyTimeUs, BusyPollsPerErase);

            if(AnyFaultFired)
            {
                return;
            }
            if(alignedDevOffset < 0 || alignedDevOffset >= DeviceSize)
            {
                return;
            }

            int actualEraseSize = (int)Math.Min((long)eraseSize, DeviceSize - alignedDevOffset);
            long globalOffset = StorageBaseOffset + alignedDevOffset;

            if(tracker.RecordEraseAndCheckFault(globalOffset, actualEraseSize))
            {
                EraseFaultFired = true;
                LastFaultAddress = (uint)(FlashBaseAddress + globalOffset);
                int halfSize = Math.Max(1, actualEraseSize / 2);

                if(EraseFaultMode == 1)
                {
                    // Multi-sector atomicity: erase first half of target + first quarter of neighbor.
                    int quarterSize = Math.Max(1, actualEraseSize / 4);
                    FillStorage(alignedDevOffset, halfSize, EraseFill);
                    long neighborOffset = alignedDevOffset + actualEraseSize;
                    if(neighborOffset < DeviceSize)
                    {
                        int neighborSize = (int)Math.Min((long)quarterSize, DeviceSize - neighborOffset);
                        if(neighborSize > 0)
                        {
                            FillStorage(neighborOffset, neighborSize, EraseFill);
                        }
                    }
                }
                else
                {
                    string neutralMode = (TornWordMode ?? "fixed").Trim().ToLowerInvariant();
                    if(neutralMode != "fixed")
                    {
                        if(neutralMode == "half" || neutralMode == "half_retain")
                        {
                            FillStorage(alignedDevOffset, halfSize, EraseFill);
                        }
                        else
                        {
                            byte[] previous = ReadStorageBytesRaw(alignedDevOffset, actualEraseSize);
                            byte[] torn = FaultTracker.BuildFlashTornEraseSpan(
                                previous, globalOffset, EraseFill, 4, neutralMode,
                                TornWordSeed, TotalPageErases);
                            WriteStorageBytesRaw(alignedDevOffset, torn, 0, torn.Length);
                        }
                    }
                    else
                    {
                        string tornMode = (MramTornWordMode ?? "half").Trim().ToLowerInvariant();
                        if(tornMode == "untouched")
                        {
                            // Cut before erase modified any bytes.
                        }
                        else if(tornMode == "erased" || tornMode == "programmed")
                        {
                            FillStorage(alignedDevOffset, actualEraseSize, EraseFill);
                        }
                        else if(tornMode == "corrupted")
                        {
                            byte[] corrupted = tracker.BuildCorruptedErasedSpan(
                                globalOffset, actualEraseSize, EraseFill, 4);
                            WriteStorageBytesRaw(alignedDevOffset, corrupted, 0, corrupted.Length);
                        }
                        else if(tornMode == "partial_bits")
                        {
                            byte[] previous = ReadStorageBytesRaw(alignedDevOffset, actualEraseSize);
                            byte[] torn = FaultTracker.BuildFlashTornEraseSpan(
                                previous, globalOffset, EraseFill, 4, "partial_bits",
                                MramTornWordSeed, TotalPageErases);
                            WriteStorageBytesRaw(alignedDevOffset, torn, 0, torn.Length);
                        }
                        else
                        {
                            // Default "half" / "half_retain": first half erased to 0xFF,
                            // second half retains pre-erase contents.
                            FillStorage(alignedDevOffset, halfSize, EraseFill);
                        }
                    }
                }

                FaultFlashSnapshot = ReadFullFlashSnapshot();
                return;
            }

            FillStorage(alignedDevOffset, actualEraseSize, EraseFill);
        }

        // --- Busy / WIP Status Handling ---

        private void StartBusyWindow(ulong durationUs, int pollCount)
        {
            if(durationUs > 0 && machine != null)
            {
                busyUntilTime = machine.LocalTimeSource.ElapsedVirtualTime + TimeInterval.FromMicroseconds(durationUs);
                hasBusyDeadline = true;
            }
            else
            {
                hasBusyDeadline = false;
            }
            busyPollsRemaining = Math.Max(0, pollCount);
        }

        private bool IsBusyTimeActive()
        {
            if(!hasBusyDeadline || machine == null)
            {
                return false;
            }
            if(machine.LocalTimeSource.ElapsedVirtualTime < busyUntilTime)
            {
                return true;
            }
            hasBusyDeadline = false;
            return false;
        }

        private bool IsBusyNow()
        {
            return ForceBusy || busyPollsRemaining > 0 || IsBusyTimeActive();
        }

        private byte ComposeStatusRegister1(bool consumePoll)
        {
            bool timeBusy = IsBusyTimeActive();
            bool pollBusy = busyPollsRemaining > 0;
            bool busy = ForceBusy || timeBusy || pollBusy;
            if(consumePoll)
            {
                if(busy)
                {
                    StatusPollBusyObservedCount++;
                }
                if(busyPollsRemaining > 0)
                {
                    busyPollsRemaining--;
                }
            }
            byte sr = (byte)(statusReg1 & ~SR1_WIP);
            if(busy)
            {
                sr |= SR1_WIP;
            }
            return sr;
        }

        // --- JEDEC JESD216B SFDP Table Builder (0x5A) ---

        private void RebuildSfdpTable()
        {
            // 128-byte SFDP space:
            //   0x00..0x07: SFDP Header ("SFDP" signature 0x50444653, JESD216B rev 1.6, NPH=0)
            //   0x08..0x0F: Parameter Header 0 (ID=0xFF00 BFPT, rev 1.6, 16 DWORDs @ 0x000030)
            //   0x30..0x6F: 16-DWORD Basic Flash Parameter Table (BFPT)
            sfdpTable = new byte[128];
            FillArray(sfdpTable, 0, sfdpTable.Length, 0xFF);

            // SFDP Header (0x00..0x07)
            sfdpTable[0x00] = (byte)'S';
            sfdpTable[0x01] = (byte)'F';
            sfdpTable[0x02] = (byte)'D';
            sfdpTable[0x03] = (byte)'P';
            sfdpTable[0x04] = 0x06; // Minor revision 6 (JESD216B)
            sfdpTable[0x05] = 0x01; // Major revision 1
            sfdpTable[0x06] = 0x00; // NPH = 0 (1 parameter header)
            sfdpTable[0x07] = 0xFF; // Access protocol

            // Parameter Header 0: Basic Flash Parameter Table (0x08..0x0F)
            sfdpTable[0x08] = 0x00; // Parameter ID LSB (BFPT)
            sfdpTable[0x09] = 0x06; // Minor revision 6
            sfdpTable[0x0A] = 0x01; // Major revision 1
            sfdpTable[0x0B] = 0x10; // Length = 16 DWORDs (64 bytes)
            sfdpTable[0x0C] = 0x30; // Parameter table pointer [7:0] = 0x000030
            sfdpTable[0x0D] = 0x00; // Parameter table pointer [15:8]
            sfdpTable[0x0E] = 0x00; // Parameter table pointer [23:16]
            sfdpTable[0x0F] = 0xFF; // Parameter ID MSB

            // BFPT DWORD 1 (0x30): 4 KiB erase supported (bits 1:0 = 01b),
            // write granularity >= 64B (bit 2 = 1), volatile SR WREN 0x06 (bits 4:3 = 00b),
            // 4 KiB erase opcode = 0x20 (bits 15:8), 3-byte addressing (bits 18:17 = 00b).
            FaultTracker.WriteU32(sfdpTable, 0x30, 0xFFF120E5U);

            // BFPT DWORD 2 (0x34): Flash memory density in bits minus 1.
            ulong densityBitsMinusOne = ((ulong)DeviceSize * 8UL) - 1UL;
            uint dword2 = densityBitsMinusOne <= 0x7FFFFFFFUL
                ? (uint)densityBitsMinusOne
                : (0x80000000U | (uint)Math.Log((double)DeviceSize * 8.0, 2.0));
            FaultTracker.WriteU32(sfdpTable, 0x34, dword2);

            // BFPT DWORD 3..7 (0x38..0x4B): standard fast-read capabilities.
            FaultTracker.WriteU32(sfdpTable, 0x38, 0x6B08EB44U);
            FaultTracker.WriteU32(sfdpTable, 0x3C, 0xBB043B08U);
            FaultTracker.WriteU32(sfdpTable, 0x40, 0xFFFFFFEEU);
            FaultTracker.WriteU32(sfdpTable, 0x44, 0xFF00FFFFU);
            FaultTracker.WriteU32(sfdpTable, 0x48, 0xFF00FFFFU);

            // BFPT DWORD 8 (0x4C): Erase Type 1 = 4 KiB (2^12, opcode 0x20),
            // Erase Type 2 = 32 KiB (2^15, opcode 0x52).
            sfdpTable[0x4C] = 0x0C; // 2^12 = 4096 B
            sfdpTable[0x4D] = CMD_SE;
            sfdpTable[0x4E] = 0x0F; // 2^15 = 32768 B
            sfdpTable[0x4F] = CMD_BE32K;

            // BFPT DWORD 9 (0x50): Erase Type 3 = 64 KiB (2^16, opcode 0xD8),
            // Erase Type 4 = not present (0x00, 0xFF).
            sfdpTable[0x50] = 0x10; // 2^16 = 65536 B
            sfdpTable[0x51] = CMD_BE64K;
            sfdpTable[0x52] = 0x00;
            sfdpTable[0x53] = 0xFF;

            // BFPT DWORD 10 (0x54): Erase timing multipliers.
            FaultTracker.WriteU32(sfdpTable, 0x54, 0x00F57223U);

            // BFPT DWORD 11 (0x58): Page size = 2^8 = 256 bytes (bits 7:4 = 8 -> 0x82 in byte 0).
            FaultTracker.WriteU32(sfdpTable, 0x58, 0xCC04ED82U);

            // BFPT DWORD 12..16 (0x5C..0x6F): suspend/resume, deep power-down, 4B modes.
            FaultTracker.WriteU32(sfdpTable, 0x5C, 0x44688344U);
            FaultTracker.WriteU32(sfdpTable, 0x60, 0xB030B030U);
            FaultTracker.WriteU32(sfdpTable, 0x64, 0x5CD5C4F7U);
            FaultTracker.WriteU32(sfdpTable, 0x68, 0xFF29BE00U);
            FaultTracker.WriteU32(sfdpTable, 0x6C, 0xFFFFD0F0U);
        }

        // --- Storage Access & Read-Fault Injection ---

        private byte ReadStorageByteWithFault(long devOffset)
        {
            byte val = ReadStorageByteRaw(devOffset);
            if(!ReadFaultEnabled)
            {
                return val;
            }
            long globalAddr = FlashBaseAddress + StorageBaseOffset + devOffset;
            if(ReadFaultAddress >= 0 && globalAddr != ReadFaultAddress && devOffset != ReadFaultAddress)
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
                ? (ReadFaultSeed ^ (uint)devOffset ^ (uint)ReadFaultTotalReads)
                : ((uint)devOffset ^ (uint)(ReadFaultTotalReads * 2654435761U) ^ 0xA5A55A5AU);
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

        private byte ReadStorageByteRaw(long devOffset)
        {
            if(devOffset < 0 || devOffset >= DeviceSize)
            {
                return 0xFF;
            }
            if(backingMemory != null)
            {
                byte[] b = backingMemory.ReadBytes(StorageBaseOffset + devOffset, 1);
                return b[0];
            }
            return internalStorage[devOffset];
        }

        private void WriteStorageByteRaw(long devOffset, byte value)
        {
            if(devOffset < 0 || devOffset >= DeviceSize)
            {
                return;
            }
            if(backingMemory != null)
            {
                backingMemory.WriteBytes(StorageBaseOffset + devOffset, new[] { value }, 0, 1);
                return;
            }
            internalStorage[devOffset] = value;
        }

        private byte[] ReadStorageBytesRaw(long devOffset, int count)
        {
            if(count <= 0)
            {
                return new byte[0];
            }
            if(backingMemory != null)
            {
                return backingMemory.ReadBytes(StorageBaseOffset + devOffset, count);
            }
            byte[] result = new byte[count];
            int avail = (int)Math.Max(0L, Math.Min((long)count, DeviceSize - devOffset));
            if(avail > 0)
            {
                Array.Copy(internalStorage, (int)devOffset, result, 0, avail);
            }
            for(int i = avail; i < count; i++)
            {
                result[i] = 0xFF;
            }
            return result;
        }

        private void WriteStorageBytesRaw(long devOffset, byte[] data, int index, int count)
        {
            if(data == null || count <= 0 || devOffset < 0 || devOffset >= DeviceSize)
            {
                return;
            }
            int avail = (int)Math.Min((long)count, DeviceSize - devOffset);
            if(backingMemory != null)
            {
                if(index == 0 && avail == data.Length)
                {
                    backingMemory.WriteBytes(StorageBaseOffset + devOffset, data, 0, avail);
                }
                else
                {
                    byte[] slice = new byte[avail];
                    Array.Copy(data, index, slice, 0, avail);
                    backingMemory.WriteBytes(StorageBaseOffset + devOffset, slice, 0, avail);
                }
                return;
            }
            Array.Copy(data, index, internalStorage, (int)devOffset, avail);
        }

        private ulong ReadStorageValueRaw(long devOffset, int width)
        {
            ulong value = 0;
            for(int b = 0; b < width; b++)
            {
                value |= (ulong)ReadStorageByteRaw(devOffset + b) << (b * 8);
            }
            return value;
        }

        private void WriteStorageValueRaw(long devOffset, ulong value, int width)
        {
            byte[] buf = new byte[width];
            for(int b = 0; b < width; b++)
            {
                buf[b] = (byte)((value >> (b * 8)) & 0xFF);
            }
            WriteStorageBytesRaw(devOffset, buf, 0, width);
        }

        private void FillStorage(long devOffset, int count, byte fill)
        {
            if(count <= 0 || devOffset < 0 || devOffset >= DeviceSize)
            {
                return;
            }
            int avail = (int)Math.Min((long)count, DeviceSize - devOffset);
            if(backingMemory != null)
            {
                byte[] buf = new byte[avail];
                FillArray(buf, 0, avail, fill);
                backingMemory.WriteBytes(StorageBaseOffset + devOffset, buf, 0, avail);
                return;
            }
            FillArray(internalStorage, (int)devOffset, avail, fill);
        }

        private byte[] ReadFullFlashSnapshot()
        {
            if(backingMemory != null)
            {
                return backingMemory.ReadBytes(0, checked((int)FlashSize));
            }
            return (byte[])internalStorage.Clone();
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
            FillArray(pageLatch, 0, PageBufferSize, 0xFF);
            Array.Clear(pageByteTouched, 0, PageBufferSize);
            pageTouchOrder.Clear();
            pageProgramDataCount = 0;
        }

        private static void FillArray(byte[] arr, int start, int length, byte value)
        {
            for(int i = start; i < start + length; i++)
            {
                arr[i] = value;
            }
        }

        // --- IMemory / Direct Bus Access (for host image loading, probes, and TraceReplayEngine) ---

        public byte ReadByte(long offset)
        {
            return ReadStorageByteWithFault(offset);
        }

        public void WriteByte(long offset, byte value)
        {
            WriteStorageByteRaw(offset, value);
        }

        public ushort ReadWord(long offset)
        {
            return (ushort)(ReadByte(offset) | (ReadByte(offset + 1) << 8));
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteStorageValueRaw(offset, value, 2);
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
            WriteStorageValueRaw(offset, value, 4);
        }

        public ulong ReadQuadWord(long offset)
        {
            return (ulong)ReadDoubleWord(offset) | ((ulong)ReadDoubleWord(offset + 4) << 32);
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            WriteStorageValueRaw(offset, value, 8);
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context = null)
        {
            return ReadStorageBytesRaw(offset, count);
        }

        public void WriteBytes(long offset, byte[] value, int startingIndex, int count, IPeripheral context = null)
        {
            WriteStorageBytesRaw(offset, value, startingIndex, count);
        }

        public void WriteBytes(long offset, byte[] value)
        {
            if(value != null)
            {
                WriteStorageBytesRaw(offset, value, 0, value.Length);
            }
        }
    }
}

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class SPINORFlash : SPI.SPINORFlash
    {
        public SPINORFlash(
            IMachine machine,
            long size = 0x200000,
            long flashBaseAddress = 0x0,
            long storageBaseOffset = 0x0,
            byte eraseFill = 0xFF,
            byte jedecManufacturerId = 0xEF,
            byte jedecMemoryType = 0x40,
            byte jedecCapacityId = 0x15)
            : base(machine, size, flashBaseAddress, storageBaseOffset, eraseFill,
                   jedecManufacturerId, jedecMemoryType, jedecCapacityId)
        {
        }
    }
}
