// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Threading;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Memory
{
    // Persistent non-volatile memory model with configurable write granularity and optional sector erase.
    // Supports MRAM (word-write, no sector erase), flash (sector erase + word program), FRAM, and other NVM.
    public class NVMemory : IMemory, IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IQuadWordPeripheral, IKnownSize
    {
        public NVMemory(long size = DefaultSize, long wordSize = DefaultWordSize)
        {
            if(size <= 0 || size > int.MaxValue)
            {
                throw new ArgumentException("NVM size must be between 1 and Int32.MaxValue");
            }

            this.size = size;
            WordSize = wordSize;
            storage = new byte[size];

            // Default: fill with EraseFill so fresh memory looks erased.
            for(var i = 0L; i < size; i++)
            {
                storage[i] = EraseFill;
            }
        }

        public void Reset()
        {
            // Intentionally do NOT clear storage: this models non-volatile memory.
            WriteInProgress = false;
            LastFaultInjected = false;
            FaultEverFired = false;
        }

        public byte ReadByte(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadByte(offset);
            }
            ValidateRange(offset, 1);
            return storage[offset];
        }

        public ushort ReadWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadWord(offset);
            }
            ValidateRange(offset, 2);
            return (ushort)(ReadByte(offset)
                | (ReadByte(offset + 1) << 8));
        }

        public uint ReadDoubleWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadDoubleWord(offset);
            }
            ValidateRange(offset, 4);
            return (uint)(ReadByte(offset)
                | (ReadByte(offset + 1) << 8)
                | (ReadByte(offset + 2) << 16)
                | (ReadByte(offset + 3) << 24));
        }

        public ulong ReadQuadWord(long offset)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadQuadWord(offset);
            }
            ValidateRange(offset, 8);
            return ReadDoubleWord(offset)
                | ((ulong)ReadDoubleWord(offset + 4) << 32);
        }

        public void WriteByte(long offset, byte value)
        {
            WriteBytesInternal(offset, new[] { value });
        }

        public void WriteWord(long offset, ushort value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
            });
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
            });
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            WriteBytesInternal(offset, new[]
            {
                (byte)(value & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 32) & 0xFF),
                (byte)((value >> 40) & 0xFF),
                (byte)((value >> 48) & 0xFF),
                (byte)((value >> 56) & 0xFF),
            });
        }

        public byte[] ReadBytes(long offset, int count, IPeripheral context)
        {
            if(AliasTarget != null)
            {
                return AliasTarget.ReadBytes(offset, count, context);
            }

            ValidateRange(offset, count);
            var result = new byte[count];
            Array.Copy(storage, offset, result, 0, count);
            return result;
        }

        public void WriteBytes(long offset, byte[] array, int startingIndex, int count, IPeripheral context)
        {
            if(array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if(startingIndex < 0 || count < 0 || startingIndex + count > array.Length)
            {
                throw new ArgumentOutOfRangeException($"Invalid write window start={startingIndex}, count={count}, arrayLength={array.Length}");
            }

            var data = new byte[count];
            Array.Copy(array, startingIndex, data, 0, count);
            WriteBytesInternal(offset, data);
        }

        public void InjectFault(long address, long length, byte pattern = 0x00)
        {
            if(AliasTarget != null)
            {
                AliasTarget.InjectFault(address, length, pattern);
                return;
            }

            if(length <= 0)
            {
                return;
            }

            ValidateRange(address, length);
            for(var i = 0L; i < length; i++)
            {
                storage[address + i] = pattern;
            }
            LastFaultInjected = true;
            FaultEverFired = true;
            LastFaultPattern = pattern;
        }

        public void InjectPartialWrite(long address)
        {
            if(AliasTarget != null)
            {
                AliasTarget.InjectPartialWrite(address);
                return;
            }

            var aligned = AlignDown(address, WordSize);
            ValidateRange(aligned, WordSize);

            var half = WordSize / 2;
            for(var i = half; i < WordSize; i++)
            {
                storage[aligned + i] = EraseFill;
            }

            LastFaultInjected = true;
            FaultEverFired = true;
            LastFaultPattern = EraseFill;
        }

        public ulong GetWordWriteCount()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.GetWordWriteCount();
            }
            return TotalWordWrites;
        }

        public bool IsWriteInProgress()
        {
            if(AliasTarget != null)
            {
                return AliasTarget.IsWriteInProgress();
            }
            return WriteInProgress;
        }

        public long Size
        {
            get { return size; }
            set
            {
                if(AliasTarget != null)
                {
                    // Aliases inherit target geometry.
                    return;
                }

                if(value <= 0)
                {
                    throw new ArgumentException("NVM size must be > 0");
                }

                if(value > int.MaxValue)
                {
                    throw new ArgumentException("NVM size exceeds max supported backing array size");
                }

                if(value == size)
                {
                    return;
                }

                var newStorage = new byte[value];
                var bytesToCopy = Math.Min(size, value);
                Array.Copy(storage, newStorage, bytesToCopy);
                storage = newStorage;
                size = value;
            }
        }

        public long WordSize
        {
            get { return wordSize; }
            set
            {
                if(value <= 0)
                {
                    throw new ArgumentException("WordSize must be > 0");
                }

                // Keep word boundaries power-of-two for efficient alignment logic.
                if((value & (value - 1)) != 0)
                {
                    throw new ArgumentException("WordSize must be a power-of-two");
                }

                wordSize = value;
            }
        }

        public byte EraseFill
        {
            get { return eraseFill; }
            set
            {
                if(value != eraseFill)
                {
                    var oldFill = eraseFill;
                    eraseFill = value;

                    // Re-fill storage bytes that still hold the old erase pattern.
                    // This handles the Renode construction order issue: the constructor
                    // fills storage with the default EraseFill (0x00), then the .repl
                    // property setter fires with the actual value (e.g. 0xFF for flash).
                    // Only touch bytes that match the old fill to avoid clobbering data
                    // loaded between construction and property-set (e.g. LoadBinary).
                    if(storage != null)
                    {
                        for(var i = 0L; i < storage.Length; i++)
                        {
                            if(storage[i] == oldFill)
                            {
                                storage[i] = value;
                            }
                        }
                    }
                }
            }
        }

        public bool EnforceWordWriteSemantics { get; set; } = true;

        public bool ReadOnly { get; set; }

        // Optional alias to expose NV_READ_OFFSET style mirrored view.
        public NVMemory AliasTarget { get; set; }

        public ulong FaultAtWordWrite { get; set; } = ulong.MaxValue;

        // Fault mode: 0 = power_loss (partial write), 1 = bit_corruption (random bit flips).
        public int WriteFaultMode { get; set; }

        // Deterministic PRNG seed for bit corruption. Advanced on each corrupted byte.
        public uint CorruptionSeed { get; set; }

        public uint WriteLatencyMicros { get; set; }

        public bool WriteInProgress { get; private set; }

        public bool LastFaultInjected { get; private set; }

        // Sticky fault flag: set when any fault fires, cleared only by Reset()
        // or explicit assignment. Unlike LastFaultInjected (which is cleared at
        // the start of each WriteBytesInternal), this survives subsequent writes.
        public bool FaultEverFired { get; set; }

        public byte LastFaultPattern { get; private set; }

        public ulong TotalWordWrites { get; set; }

        public long LastWriteAddress { get; private set; }

        public List<long> WriteLog { get { return writeLog; } }

        public void EraseSector(long offset, int sectorSize)
        {
            if(AliasTarget != null)
            {
                AliasTarget.EraseSector(offset, sectorSize);
                return;
            }

            ValidateRange(offset, sectorSize);
            for(var i = 0; i < sectorSize; i++)
            {
                storage[offset + i] = EraseFill;
            }
        }

        public void ClearWriteLog()
        {
            writeLog.Clear();
        }

        public void ResetWriteLog()
        {
            writeLog.Clear();
        }

        private void WriteBytesInternal(long offset, byte[] data)
        {
            if(AliasTarget != null)
            {
                if(ReadOnly)
                {
                    return;
                }

                AliasTarget.WriteBytesInternal(offset, data);
                return;
            }

            if(ReadOnly)
            {
                return;
            }

            if(data.Length == 0)
            {
                return;
            }

            ValidateRange(offset, data.Length);
            LastWriteAddress = offset;

            if(!EnforceWordWriteSemantics)
            {
                // Fast path: write all data first, then check for fault injection.
                // This ensures words before the faulted word are properly written.
                var fastFirst = AlignDown(offset, WordSize);
                var fastLast = AlignDown(offset + data.Length - 1, WordSize);

                // Write all data to storage unconditionally first.
                for(var i = 0; i < data.Length; i++)
                {
                    storage[offset + i] = data[i];
                }

                // Now count word writes and check for fault injection.
                for(var wordStart = fastFirst; wordStart <= fastLast; wordStart += WordSize)
                {
                    var currentWriteIndex = TotalWordWrites + 1;
                    if(currentWriteIndex == FaultAtWordWrite)
                    {
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: data already written above; flip random bits.
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                        }
                        else
                        {
                            // Power-loss: corrupt second half of faulted word with EraseFill.
                            var half = WordSize / 2;
                            for(var i = wordStart + half; i < wordStart + WordSize; i++)
                            {
                                if(i >= offset && i < offset + data.Length)
                                {
                                    storage[i] = EraseFill;
                                }
                            }
                        }
                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : EraseFill);
                        TotalWordWrites++;
                        LastWriteAddress = wordStart;
                        return;
                    }

                    TotalWordWrites++;
                }

                return;
            }

            var firstWordStart = AlignDown(offset, WordSize);
            var lastWordStart = AlignDown(offset + data.Length - 1, WordSize);

            WriteInProgress = true;
            LastFaultInjected = false;

            try
            {
                for(var wordStart = firstWordStart; wordStart <= lastWordStart; wordStart += WordSize)
                {
                    var mergedWord = new byte[WordSize];
                    for(var i = 0L; i < WordSize; i++)
                    {
                        mergedWord[i] = storage[wordStart + i];
                    }

                    for(var i = 0; i < data.Length; i++)
                    {
                        var absoluteAddress = offset + i;
                        if(absoluteAddress < wordStart || absoluteAddress >= wordStart + WordSize)
                        {
                            continue;
                        }

                        mergedWord[absoluteAddress - wordStart] = data[i];
                    }

                    EraseWord(wordStart);

                    var currentWriteIndex = TotalWordWrites + 1;
                    if(currentWriteIndex == FaultAtWordWrite)
                    {
                        if(WriteFaultMode == 1)
                        {
                            // Bit corruption: write full word, then flip random bits.
                            ProgramWord(wordStart, mergedWord);
                            corruptionSeed = CorruptionSeed;
                            ApplyBitCorruptionToWord(wordStart);
                        }
                        else
                        {
                            // Power-loss: partial write (first half only).
                            var partialBytes = WordSize / 2;
                            for(var i = 0L; i < partialBytes; i++)
                            {
                                storage[wordStart + i] = mergedWord[i];
                            }

                            for(var i = partialBytes; i < WordSize; i++)
                            {
                                storage[wordStart + i] = 0x00;
                            }
                        }

                        LastFaultInjected = true;
                        FaultEverFired = true;
                        LastFaultPattern = (byte)(WriteFaultMode == 1 ? 0xCC : 0x00);
                        TotalWordWrites++;
                        writeLog.Add(wordStart);
                        break;
                    }

                    ProgramWord(wordStart, mergedWord);
                    TotalWordWrites++;
                    writeLog.Add(wordStart);

                    if(WriteLatencyMicros > 0)
                    {
                        var milliseconds = (int)Math.Max(1, WriteLatencyMicros / 1000);
                        Thread.Sleep(milliseconds);
                    }
                }
            }
            finally
            {
                WriteInProgress = false;
            }
        }

        private uint AdvancePrng()
        {
            corruptionSeed = corruptionSeed * 1103515245u + 12345u;
            return corruptionSeed;
        }

        // Apply random bit flips to a word already in storage.
        // MRAM physics: bits can flip in either direction (unlike NOR flash 1->0 only).
        private void ApplyBitCorruptionToWord(long wordStart)
        {
            for(var i = 0L; i < WordSize && (wordStart + i) < size; i++)
            {
                var r = AdvancePrng();
                if((r & 0x7) == 0) // ~12.5% chance per byte
                {
                    var flipMask = (byte)(AdvancePrng() >> 16);
                    if(flipMask == 0)
                    {
                        flipMask = 1;
                    }
                    storage[wordStart + i] ^= flipMask;
                }
            }
        }

        private void EraseWord(long wordStart)
        {
            for(var i = 0L; i < WordSize; i++)
            {
                storage[wordStart + i] = EraseFill;
            }
        }

        private void ProgramWord(long wordStart, byte[] mergedWord)
        {
            for(var i = 0L; i < WordSize; i++)
            {
                storage[wordStart + i] = mergedWord[i];
            }
        }

        private long AlignDown(long value, long alignment)
        {
            return value & ~(alignment - 1);
        }

        private void ValidateRange(long offset, long length)
        {
            if(offset < 0 || length < 0 || (offset + length) > size)
            {
                throw new ArgumentOutOfRangeException($"NVM access out of range: offset={offset}, length={length}, size={size}");
            }
        }

        private byte eraseFill;
        private long size;
        private long wordSize;
        private byte[] storage;
        private uint corruptionSeed;
        private readonly List<long> writeLog = new List<long>();

        private const long DefaultSize = 0x80000;
        private const long DefaultWordSize = 8;
    }
}

namespace Antmicro.Renode.Peripherals
{
    // Control/register block companion for NVMemory.
    public class NVMemoryController : BasicDoubleWordPeripheral, IKnownSize
    {
        public NVMemoryController(Machine machine) : base(machine)
        {
            DefineRegisters();
            Reset();
        }

        public override void Reset()
        {
            base.Reset();

            efuseStrobeLen.Value = 0;
            efuseCtrl.Value = 0;
            efuseOp.Value = 0;
            nvmCfg.Value = 0;
            nvmOverride.Value = 0;
            nvmCtrlWriteableBits = 0;
            nvmUe.Value = 0;

            for(var i = 0; i < eccCounters.Length; i++)
            {
                eccCounters[i] = 0;
            }

            illegalOperation = false;

            // Intentionally do NOT clear efuseSpareValue: eFuse bits are OTP
            // and survive reset, just like real hardware.

            // Intentionally do not touch Nvm.Reset() here; memory persistence is critical.
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

        public void EraseSector(long address, int sectorSize = 0x1000)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            try
            {
                Nvm.EraseSector(NormalizeAddress(address), sectorSize);
            }
            catch(ArgumentOutOfRangeException)
            {
                illegalOperation = true;
            }
        }

        public void InjectPartialErase(long address, int sectorSize = 0x1000)
        {
            if(Nvm == null)
            {
                illegalOperation = true;
                return;
            }

            try
            {
                var normalized = NormalizeAddress(address);
                var half = sectorSize / 2;
                // Erase first half of sector, leave second half intact.
                Nvm.EraseSector(normalized, half);
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
            get { return ControllerWindowSize; }
        }

        public bool FullMode { get; set; } = true;

        // OTP eFuse spare bits. Test scripts can preset via this property.
        // Writes OR bits in (never clears). Survives Reset().
        public uint EfuseSpare
        {
            get { return efuseSpareValue; }
            set { efuseSpareValue = value; }
        }

        public Antmicro.Renode.Peripherals.Memory.NVMemory Nvm { get; set; }

        public long NvmBaseAddress { get; set; } = 0x10000000;

        public long NvReadOffset { get; set; } = 0x80000;

        private void DefineRegisters()
        {
            Registers.MiscStatus.Define(this)
                .WithValueField(0, 32, FieldMode.Read, valueProviderCallback: _ => ComposeMiscStatus());

            Registers.EfuseStrobeLen.Define(this)
                .WithValueField(0, 32, out efuseStrobeLen, FieldMode.Read | FieldMode.Write);

            Registers.EfuseCtrl.Define(this)
                .WithValueField(0, 32, out efuseCtrl, FieldMode.Read | FieldMode.Write);

            Registers.EfuseOp.Define(this)
                .WithValueField(0, 32, out efuseOp, FieldMode.Read | FieldMode.Write);

            Registers.EfuseSpare.Define(this)
                .WithValueField(0, 32,
                    valueProviderCallback: _ => efuseSpareValue,
                    writeCallback: (_, value) =>
                    {
                        // OTP semantics: bits can only be set, never cleared.
                        efuseSpareValue |= (uint)value;
                    });

            Registers.NvmCfg.Define(this)
                .WithValueField(0, 32, out nvmCfg, FieldMode.Read | FieldMode.Write);

            Registers.NvmOverride.Define(this)
                .WithValueField(0, 32, out nvmOverride, FieldMode.Read | FieldMode.Write);

            Registers.NvmCtrl.Define(this)
                .WithValueField(0, 32,
                    valueProviderCallback: _ => ComposeNvmCtrl(),
                    writeCallback: (_, value) =>
                    {
                        // Writable bits: ECC_BYPASS[0], ERASE_EN[2:1], PROG_EN[3].
                        nvmCtrlWriteableBits = (uint)(value & 0xF);
                    });

            Registers.NvmEc0.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[0], writeCallback: (_, value) => eccCounters[0] = (uint)value);
            Registers.NvmEc1.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[1], writeCallback: (_, value) => eccCounters[1] = (uint)value);
            Registers.NvmEc2.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[2], writeCallback: (_, value) => eccCounters[2] = (uint)value);
            Registers.NvmEc3.Define(this)
                .WithValueField(0, 32, valueProviderCallback: _ => eccCounters[3], writeCallback: (_, value) => eccCounters[3] = (uint)value);

            Registers.NvmUe.Define(this)
                .WithValueField(0, 32, out nvmUe, FieldMode.Read | FieldMode.Write);

            Registers.NvmEcUeRst.Define(this)
                .WithValueField(0, 32, FieldMode.Write, writeCallback: (_, value) =>
                {
                    if(value == 0)
                    {
                        return;
                    }

                    for(var i = 0; i < eccCounters.Length; i++)
                    {
                        eccCounters[i] = 0;
                    }
                    nvmUe.Value = 0;
                });
        }

        private uint ComposeMiscStatus()
        {
            // Keep ROM-useful flags set while emulating operational bits 8..11.
            var status = 0U;
            status |= (1U << 2); // TRIM_FUSED
            status |= (1U << 3); // NVM_PROGRAMMED

            if(Nvm != null && Nvm.IsWriteInProgress())
            {
                status |= (1U << 9);  // PROG_ACTIVE
                status |= (1U << 10); // ERASE_ACTIVE
            }

            if(illegalOperation)
            {
                status |= (1U << 11); // ILLEGAL_OPERATION
            }

            return status;
        }

        private uint ComposeNvmCtrl()
        {
            var ctrl = nvmCtrlWriteableBits;

            // Model immediate readiness in the simplified timing model.
            ctrl |= (1U << 8); // RDY_FOR_ERASE
            ctrl |= (1U << 9); // RDY_FOR_PROG

            return ctrl;
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

            throw new ArgumentOutOfRangeException($"Address 0x{address:X} is outside modeled NVM windows");
        }

        private uint efuseSpareValue;

        private IValueRegisterField efuseStrobeLen;
        private IValueRegisterField efuseCtrl;
        private IValueRegisterField efuseOp;
        private IValueRegisterField nvmCfg;
        private IValueRegisterField nvmOverride;
        private IValueRegisterField nvmUe;

        private uint nvmCtrlWriteableBits;
        private readonly uint[] eccCounters = new uint[4];
        private bool illegalOperation;

        private const long ControllerWindowSize = 0x58;

        private enum Registers : long
        {
            MiscStatus = 0x00,
            EfuseStrobeLen = 0x04,
            EfuseCtrl = 0x08,
            EfuseOp = 0x0C,
            EfuseSpare = 0x10,
            NvmCfg = 0x20,
            NvmOverride = 0x24,
            NvmCtrl = 0x30,
            NvmEc0 = 0x40,
            NvmEc1 = 0x44,
            NvmEc2 = 0x48,
            NvmEc3 = 0x4C,
            NvmUe = 0x50,
            NvmEcUeRst = 0x54,
        }
    }
}
