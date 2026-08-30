# I2C Bus Fault Injection Model

## Overview

Tardigrade can inject faults on the I2C bus between the CPU and external
peripherals. The primary use case is testing bootloaders that communicate
with a secure element (or other external co-processor) over I2C during
signature verification, key retrieval, or anti-rollback counter operations.

If the bootloader does not handle I2C communication failures gracefully, a
transient bus fault can cause the device to brick, accept an unsigned image,
or enter an undefined state.

## Architecture

```
  CPU (I2C master)
       |
  I2CFaultProxy          <-- Renode C# peripheral, injects faults
       |
  Downstream I2C device  <-- e.g. secure element model
```

The `I2CFaultProxy` implements Renode's `II2CPeripheral` interface. It sits
between the CPU's I2C controller and any downstream I2C slave device.
During normal operation it forwards all transactions transparently. When
armed, it injects a specific fault at a configured transaction index.

## Fault Types

| Code | Name                | Behavior                                          |
| ---- | ------------------- | ------------------------------------------------- |
| 1    | `i2c_nack`          | Respond with NACK (0xFF / dropped write)          |
| 2    | `i2c_timeout`       | No response at all (simulates clock stretch hang) |
| 3    | `i2c_bit_flip`      | Corrupt response data with deterministic PRNG     |
| 4    | `i2c_truncated`     | Return fewer bytes than requested                 |
| 5    | `i2c_wrong_address` | Respond as if targeting a different address       |

## Renode Peripheral Properties

The `I2CFaultProxy` peripheral exposes these monitor-configurable properties:

- **`FaultAtTransaction`** (ulong): 1-based transaction index at which to
  inject the fault. Default `ulong.MaxValue` (never fault).
- **`FaultType`** (int): Fault type code 0-5 (0 = passthrough).
- **`FaultSeed`** (uint): PRNG seed for deterministic bit-flip patterns.
- **`TargetAddress`** (byte): 7-bit I2C address to intercept. 0 = all.
- **`DownstreamDevice`** (II2CPeripheral): Reference to the downstream slave.

Observable counters:

- **`TotalTransactions`** (ulong): Running count of all I2C transactions.
- **`FaultFired`** (bool): Sticky flag, set once the fault fires.
- **`LastFaultType`** (int): The fault code that was actually applied.
- **`TransactionLogEnabled`** / **`TransactionLogToString()`**: Optional
  trace logging for debugging.

## Profile Schema

Add an `i2c_fault_config` block inside `fault_sweep`:

```yaml
fault_sweep:
  fault_types: [i2c_nack, i2c_timeout]
  evaluation_mode: execute
  i2c_fault_config:
    peripheral_name: i2cProxy # sysbus name of the I2CFaultProxy
    target_address: 0x50 # 7-bit I2C address (0 = all)
    fault_types: [i2c_nack, i2c_timeout]
    fault_at_transaction: 3 # arm at 3rd transaction
    fault_seed: 42 # deterministic PRNG seed
```

The five I2C fault types (`i2c_nack`, `i2c_timeout`, `i2c_bit_flip`,
`i2c_truncated`, `i2c_wrong_address`) are registered as first-class fault
types in `KNOWN_FAULT_TYPES` and `IMPLEMENTED_FAULT_TYPES`. They are
execute-only (require full CPU emulation, not state-mode).

## Robot Variables

When active, the profile loader emits:

- `I2C_FAULT_PERIPHERAL` -- sysbus peripheral name
- `I2C_FAULT_TARGET_ADDRESS` -- 7-bit address filter
- `I2C_FAULT_TYPES` -- comma-separated fault type names
- `I2C_FAULT_TYPE_CODES` -- comma-separated numeric codes
- `I2C_FAULT_AT_TRANSACTION` -- transaction index to fault at
- `I2C_FAULT_SEED` -- PRNG seed

## Wire Codes

Each I2C fault type has a two-character wire code for batch dispatch:

| Fault Type          | Wire Code |
| ------------------- | --------- |
| `i2c_nack`          | `in`      |
| `i2c_timeout`       | `it`      |
| `i2c_bit_flip`      | `ib`      |
| `i2c_truncated`     | `ic`      |
| `i2c_wrong_address` | `iw`      |

## Platform Setup Example

In a `.repl` file:

```
secureElement: I2C.GenericSecureElement @ sysbus 0x40004000

i2cProxy: I2C.I2CFaultProxy @ sysbus <0x40003000, +0x100>
    DownstreamDevice: secureElement
```

In a `.resc` file:

```
sysbus.i2cProxy FaultAtTransaction 5
sysbus.i2cProxy FaultType 1
sysbus.i2cProxy TargetAddress 0x50
```

## Sweep Integration

The I2C fault sweep iterates over transaction indices (analogous to how
write-fault sweeps iterate over write indices). Calibration determines the
total number of I2C transactions during a successful boot, then the sweep
arms `FaultAtTransaction` at each index from 1 to N, checking whether the
bootloader recovers correctly.

Different `FaultType` values can be swept independently or combined (the
profile's `fault_types` list controls which are exercised).

## Design Decisions

1. **Generic, not device-specific.** The proxy works with any
   `II2CPeripheral` -- it does not model any specific secure element's
   register protocol. The downstream device can be any Renode I2C model.

2. **Sticky timeout behavior.** When `FaultType=2` (Timeout) fires, all
   subsequent transactions also return empty responses, simulating a bus
   that remains hung after the initial fault. Other fault types fire once
   and then resume normal passthrough.

3. **Deterministic bit-flips.** The `BitFlip` mode uses an LCG PRNG seeded
   from `FaultSeed` XORed with the transaction count, producing identical
   corruption across repeated runs for reproducibility.

4. **Execute-only.** I2C faults require full CPU emulation because the
   bootloader must actually execute the I2C driver code. State-mode
   simulation cannot model bus-level interactions.
