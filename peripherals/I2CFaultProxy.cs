// Copyright (c) 2026
// SPDX-License-Identifier: Apache-2.0
//
// Generic I2C bus fault injection proxy for OTA resilience testing.
//
// Sits between the CPU's I2C master controller and a downstream I2C slave
// device (e.g. a secure element used for signature verification during boot).
// Forwards transactions normally but injects configurable faults at a
// specified transaction index.
//
// Fault types (FaultType property):
//   0 = None (passthrough)
//   1 = NACK: respond with NACK instead of ACK
//   2 = Timeout: don't respond (simulate clock stretch timeout / bus hang)
//   3 = BitFlip: flip bits in response data using deterministic PRNG
//   4 = TruncatedResponse: return fewer bytes than requested
//   5 = WrongAddress: respond as if a different address was targeted
//
// Configurable via Renode monitor properties:
//   FaultAtTransaction  — which transaction index triggers the fault (1-based)
//   FaultType           — fault type code (0-5)
//   FaultSeed           — PRNG seed for deterministic bit-flip patterns
//   TargetAddress       — I2C address to intercept (0 = intercept all)
//
// Counters:
//   TotalTransactions   — number of completed I2C transactions observed
//   FaultFired          — sticky flag: true once the fault has been injected
//
// Usage in .repl:
//   i2cProxy: I2C.I2CFaultProxy @ sysbus <0x40003000, +0x100>
//       DownstreamDevice: secureElement
//       FaultAtTransaction: 3
//       FaultType: 1

using System;
using System.Collections.Generic;

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Peripherals.I2C;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Logging;

namespace Antmicro.Renode.Peripherals.I2C
{
    public class I2CFaultProxy : II2CPeripheral, IKnownSize
    {
        public I2CFaultProxy()
        {
            Reset();
        }

        public void Reset()
        {
            totalTransactions = 0;
            currentTransactionActive = false;
            faultFired = false;
            lastFaultType = 0;
            transactionLog.Clear();
        }

        // -------------------------------------------------------------------
        // II2CPeripheral: Write (master -> slave)
        // -------------------------------------------------------------------

        public void Write(byte[] data)
        {
            if(data == null || data.Length == 0)
            {
                return;
            }

            // First byte is the I2C address + R/W bit in Renode's convention.
            // Some implementations pass raw data without address byte — guard
            // against both.
            byte addressByte = data[0];

            // Check address filter: 0 means intercept all addresses.
            if(TargetAddress != 0 && (addressByte >> 1) != TargetAddress)
            {
                // Not our target — forward transparently.
                if(DownstreamDevice != null)
                {
                    DownstreamDevice.Write(data);
                }
                return;
            }

            // Mark that this transaction has activity (fault decision
            // deferred to FinishTransmission where the full transaction
            // boundary is known).
            currentTransactionActive = true;

            if(ShouldInjectFault())
            {
                ApplyWriteFault(data);
                return;
            }

            // Normal passthrough.
            if(DownstreamDevice != null)
            {
                DownstreamDevice.Write(data);
            }
        }

        // -------------------------------------------------------------------
        // II2CPeripheral: Read
        // -------------------------------------------------------------------

        public byte[] Read(int count = 1)
        {
            // Mark that this transaction has activity (fault decision
            // deferred to FinishTransmission where the full transaction
            // boundary is known).
            currentTransactionActive = true;

            if(ShouldInjectFault())
            {
                return ApplyReadFault(count);
            }

            // Normal passthrough.
            if(DownstreamDevice != null)
            {
                return DownstreamDevice.Read(count);
            }

            // No downstream device — return all-FF (NACK-equivalent on read).
            var empty = new byte[count];
            for(int i = 0; i < count; i++)
            {
                empty[i] = 0xFF;
            }
            return empty;
        }

        // -------------------------------------------------------------------
        // II2CPeripheral: FinishTransmission
        // -------------------------------------------------------------------

        public void FinishTransmission()
        {
            if(currentTransactionActive)
            {
                totalTransactions++;
                currentTransactionActive = false;
            }

            if(DownstreamDevice != null)
            {
                DownstreamDevice.FinishTransmission();
            }
        }

        // -------------------------------------------------------------------
        // IKnownSize
        // -------------------------------------------------------------------

        public long Size => 0x100;

        // -------------------------------------------------------------------
        // Downstream device reference
        // -------------------------------------------------------------------

        public II2CPeripheral DownstreamDevice { get; set; }

        // -------------------------------------------------------------------
        // Configuration properties (set from .repl or Renode monitor)
        // -------------------------------------------------------------------

        /// <summary>
        /// Transaction index (1-based) at which to inject the fault.
        /// 0 or ulong.MaxValue means "never fault".
        /// </summary>
        public ulong FaultAtTransaction
        {
            get { return faultAtTransaction; }
            set { faultAtTransaction = value; }
        }

        /// <summary>
        /// Fault type code:
        ///   0 = None, 1 = NACK, 2 = Timeout, 3 = BitFlip,
        ///   4 = TruncatedResponse, 5 = WrongAddress
        /// </summary>
        public int FaultType
        {
            get { return faultType; }
            set
            {
                if(value < 0 || value > 5)
                {
                    this.Log(LogLevel.Warning,
                        "I2CFaultProxy: invalid FaultType {0}, clamping to 0 (None)", value);
                    faultType = 0;
                }
                else
                {
                    faultType = value;
                }
            }
        }

        /// <summary>
        /// PRNG seed for deterministic fault patterns (bit-flip mode).
        /// </summary>
        public uint FaultSeed
        {
            get { return faultSeed; }
            set { faultSeed = value; }
        }

        /// <summary>
        /// I2C 7-bit address to intercept. 0 = intercept all addresses.
        /// </summary>
        public byte TargetAddress
        {
            get { return targetAddress; }
            set { targetAddress = value; }
        }

        // -------------------------------------------------------------------
        // Observability
        // -------------------------------------------------------------------

        /// <summary>Total I2C transactions (read + write) observed.</summary>
        public ulong TotalTransactions
        {
            get { return totalTransactions; }
            set { totalTransactions = value; }
        }

        /// <summary>Sticky flag: true once fault has been injected.</summary>
        public bool FaultFired
        {
            get { return faultFired; }
            set { faultFired = value; }
        }

        /// <summary>The fault type code that was actually applied (for diagnostics).</summary>
        public int LastFaultType
        {
            get { return lastFaultType; }
        }

        /// <summary>Number of logged transactions (for trace/debug).</summary>
        public int TransactionLogCount
        {
            get { return transactionLog.Count; }
        }

        /// <summary>
        /// Retrieve the transaction log as a newline-separated string.
        /// Format: "index:direction:bytes_hex" per entry.
        /// </summary>
        public string TransactionLogToString()
        {
            var sb = new System.Text.StringBuilder(transactionLog.Count * 32);
            foreach(var entry in transactionLog)
            {
                sb.Append(entry);
                sb.Append('\n');
            }
            return sb.ToString();
        }

        public void TransactionLogClear()
        {
            transactionLog.Clear();
        }

        /// <summary>Enable transaction logging (disabled by default for perf).</summary>
        public bool TransactionLogEnabled { get; set; }

        // -------------------------------------------------------------------
        // Internal fault logic
        // -------------------------------------------------------------------

        private bool ShouldInjectFault()
        {
            if(faultFired)
            {
                // Already fired — suppress all further transactions (simulates
                // bus stuck / device unresponsive after fault).
                if(faultType == 2)
                {
                    return true;
                }
                return false;
            }

            if(faultType == 0)
            {
                return false;
            }

            // totalTransactions counts completed transactions (incremented in
            // FinishTransmission).  During an active transaction the current
            // transaction number is totalTransactions + 1.
            ulong currentTransaction = totalTransactions + 1;
            if(currentTransaction == faultAtTransaction)
            {
                faultFired = true;
                lastFaultType = faultType;
                this.Log(LogLevel.Info,
                    "I2CFaultProxy: injecting fault type {0} at transaction {1}",
                    FaultTypeName(faultType), currentTransaction);
                return true;
            }

            return false;
        }

        private void ApplyWriteFault(byte[] data)
        {
            if(TransactionLogEnabled)
            {
                transactionLog.Add(string.Format("{0}:W:FAULT_{1}:{2}",
                    totalTransactions, FaultTypeName(faultType), BitConverter.ToString(data)));
            }

            switch(faultType)
            {
                case 1: // NACK — drop the write, don't forward to downstream.
                    break;

                case 2: // Timeout — don't forward, don't respond at all.
                    break;

                case 3: // BitFlip — corrupt data before forwarding.
                    if(DownstreamDevice != null)
                    {
                        var corrupted = CorruptBytes(data);
                        DownstreamDevice.Write(corrupted);
                    }
                    break;

                case 4: // TruncatedResponse — forward only partial data.
                    if(DownstreamDevice != null && data.Length > 1)
                    {
                        int truncLen = Math.Max(1, data.Length / 2);
                        var truncated = new byte[truncLen];
                        Array.Copy(data, truncated, truncLen);
                        DownstreamDevice.Write(truncated);
                    }
                    break;

                case 5: // WrongAddress — mangle the address byte.
                    if(DownstreamDevice != null)
                    {
                        var mangled = new byte[data.Length];
                        Array.Copy(data, mangled, data.Length);
                        // XOR address byte to produce a different address.
                        mangled[0] = (byte)(data[0] ^ 0x02);
                        DownstreamDevice.Write(mangled);
                    }
                    break;

                default:
                    // Passthrough on unknown fault type.
                    if(DownstreamDevice != null)
                    {
                        DownstreamDevice.Write(data);
                    }
                    break;
            }
        }

        private byte[] ApplyReadFault(int count)
        {
            if(TransactionLogEnabled)
            {
                transactionLog.Add(string.Format("{0}:R:FAULT_{1}:count={2}",
                    totalTransactions, FaultTypeName(faultType), count));
            }

            switch(faultType)
            {
                case 1: // NACK — return empty / all-FF.
                {
                    var nackData = new byte[count];
                    for(int i = 0; i < count; i++)
                    {
                        nackData[i] = 0xFF;
                    }
                    return nackData;
                }

                case 2: // Timeout — return empty array (no response).
                    return new byte[0];

                case 3: // BitFlip — read from downstream, corrupt response.
                {
                    byte[] realData;
                    if(DownstreamDevice != null)
                    {
                        realData = DownstreamDevice.Read(count);
                    }
                    else
                    {
                        realData = new byte[count];
                    }
                    return CorruptBytes(realData);
                }

                case 4: // TruncatedResponse — return fewer bytes.
                {
                    int truncCount = Math.Max(1, count / 2);
                    if(DownstreamDevice != null)
                    {
                        var fullData = DownstreamDevice.Read(count);
                        var truncData = new byte[truncCount];
                        Array.Copy(fullData, truncData, Math.Min(truncCount, fullData.Length));
                        return truncData;
                    }
                    return new byte[truncCount];
                }

                case 5: // WrongAddress — read from downstream but return
                        // data as if from a different device (just corrupt
                        // the first byte as a marker).
                {
                    byte[] realData;
                    if(DownstreamDevice != null)
                    {
                        realData = DownstreamDevice.Read(count);
                    }
                    else
                    {
                        realData = new byte[count];
                    }
                    if(realData.Length > 0)
                    {
                        realData[0] ^= 0xA5;
                    }
                    return realData;
                }

                default:
                {
                    // Passthrough.
                    if(DownstreamDevice != null)
                    {
                        return DownstreamDevice.Read(count);
                    }
                    return new byte[count];
                }
            }
        }

        private byte[] CorruptBytes(byte[] data)
        {
            if(data == null || data.Length == 0)
            {
                return data;
            }

            var corrupted = new byte[data.Length];
            Array.Copy(data, corrupted, data.Length);

            uint seed = faultSeed != 0 ? faultSeed : (uint)totalTransactions;
            seed ^= (uint)(data.Length * 2654435761UL);

            // Flip 1-4 bits across the data.
            int flips = 1 + (int)(NextLcg(ref seed) % 4U);
            for(int i = 0; i < flips; i++)
            {
                int byteIdx = (int)(NextLcg(ref seed) % (uint)corrupted.Length);
                int bitIdx = (int)(NextLcg(ref seed) % 8U);
                corrupted[byteIdx] ^= (byte)(1 << bitIdx);
            }

            return corrupted;
        }

        private static uint NextLcg(ref uint seed)
        {
            seed = seed * 1103515245 + 12345;
            return seed;
        }

        private static string FaultTypeName(int ft)
        {
            switch(ft)
            {
                case 0: return "None";
                case 1: return "NACK";
                case 2: return "Timeout";
                case 3: return "BitFlip";
                case 4: return "TruncatedResponse";
                case 5: return "WrongAddress";
                default: return "Unknown_" + ft.ToString();
            }
        }

        // -------------------------------------------------------------------
        // Private state
        // -------------------------------------------------------------------

        private ulong totalTransactions;
        private bool currentTransactionActive;
        private ulong faultAtTransaction = ulong.MaxValue;
        private int faultType;
        private uint faultSeed;
        private byte targetAddress;
        private bool faultFired;
        private int lastFaultType;
        private readonly List<string> transactionLog = new List<string>();
    }
}
