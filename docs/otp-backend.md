# OTP (One-Time Programmable) / eFuse Memory Backend

Tardigrade supports fault injection testing on OTP/eFuse memory regions,
enabling verification of anti-rollback counters, security fuse bits, and
other one-time-write storage.

## Background

OTP memory (eFuse, antifuse, poly fuse) is used in embedded systems for:

- **Anti-rollback counters**: Monotonic counters that prevent firmware downgrade
- **Security configuration**: Debug disable, secure boot enable, JTAG lock
- **Device identity**: Unique IDs, MAC addresses, calibration data
- **Key storage**: Root-of-trust keys, certificate hashes

Unlike flash or MRAM, OTP bits can only transition from 0 to 1 (fuse blow).
Once blown, a fuse is permanent and survives reset. This creates unique
failure modes when programming is interrupted or defective.

## OTPMemory Peripheral

`peripherals/OTPMemory.cs` models a generic OTP/eFuse array with:

- **Write-once semantics**: Bits only transition 0 to 1, never 1 to 0
- **Reset persistence**: Blown fuses survive `machine Reset`
- **Configurable granularity**: `WriteGranularity` of 1 (bit), 8 (byte), or 32 (word)
- **Blow tracking**: `TotalBlows` counter increments per programming operation
- **Sweep compatibility**: `TotalWordWrites`/`FaultAtWordWrite`/`FaultEverFired` aliases

### Fault Injection Modes

Set `BlowFaultMode` to select the fault model when `FaultAtBlow` triggers:

| Mode | Name              | Behavior                                                   |
| ---- | ----------------- | ---------------------------------------------------------- |
| 0    | `partial_program` | Not all requested bits flip; random subset stays 0         |
| 1    | `stuck_bit`       | Specific bits (per `SetStuckBitMask`) never program        |
| 2    | `read_disturb`    | Target bits blow, but adjacent byte gets unintended 1-bits |
| 3    | `overblow`        | Target bits blow plus extra random neighboring bits        |

### Properties

| Property             | Type   | Description                                    |
| -------------------- | ------ | ---------------------------------------------- |
| `Size`               | long   | Total OTP region size in bytes                 |
| `WriteGranularity`   | int    | Bits per blow operation (1, 8, or 32)          |
| `TotalBlows`         | ulong  | Total blow operations performed                |
| `FaultAtBlow`        | ulong  | Inject fault at Nth blow (MaxValue = disabled) |
| `BlowFaultFired`     | bool   | Sticky: set when fault fires, survives blows   |
| `BlowFaultMode`      | int    | Fault mode (0-3, see table above)              |
| `FaultSeed`          | uint   | PRNG seed for deterministic fault patterns     |
| `BlownBitCount`      | int    | Count of 1-bits in the entire OTP region       |
| `RemainingLife`      | long   | Total bits minus blown bits                    |
| `PermanentStuckBits` | bool   | When true, stuck-bit mask applies to ALL blows |
| `FaultSnapshot`      | byte[] | OTP state captured at fault moment             |

### Test Setup Methods

- `PresetByte(offset, value)` / `PresetWord(offset, value)`: Set initial fuse
  state without tracking. Used to initialize anti-rollback counters before a test.
- `TestClearAll()`: Reset all fuses to 0 (violates OTP semantics, test-only).
- `SetStuckBitMask(offset, mask)`: Mark bits that can never be programmed.

## Profile Configuration

### Declaring the OTP peripheral

```yaml
platform: platforms/cortex_m0_otp.repl
flash_backend: nvm_ctrl # Main storage backend (unchanged)
otp_peripheral: otp # Sysbus name of OTPMemory peripheral
```

### OTP-specific fault types

Three fault types target OTP programming:

| Fault Type            | Wire Code | Description                                                  |
| --------------------- | --------- | ------------------------------------------------------------ |
| `otp_partial_program` | `op`      | Partial fuse blow (some bits stay 0)                         |
| `otp_stuck_bit`       | `os`      | Manufacturing defect prevents specific bits from programming |
| `otp_read_disturb`    | `od`      | Programming disturbs adjacent fuse bits                      |

These are execute-only fault types (require full CPU emulation, not state mode).

### Example profile

```yaml
schema_version: 1
name: anti_rollback_otp_test
platform: platforms/cortex_m0_otp.repl
flash_backend: nvm_ctrl
otp_peripheral: otp
bootloader:
  elf: my_bootloader.elf
  entry: 0x10000000
memory:
  sram: { start: 0x20000000, end: 0x20020000 }
  write_granularity: 8
  slots:
    exec: { base: 0x10000000, size: 0x38000 }
    staging: { base: 0x10038000, size: 0x38000 }
images:
  staging: new_firmware.bin
security_policy:
  anti_rollback: true
  minimum_version: 2
success_criteria:
  vtor_in_slot: exec
fault_sweep:
  mode: runtime
  fault_types:
    - power_loss
    - otp_partial_program
    - otp_stuck_bit
expect:
  should_find_issues: true
```

## Platform Definition

`platforms/cortex_m0_otp.repl` provides a reference platform combining
NVMemory (main firmware storage) with an OTPMemory region:

```
otp: Memory.OTPMemory @ sysbus 0x40002000
    Size: 0x100
    WriteGranularity: 32
```

## Sweep Integration

The sweep engine dispatches on `backend['kind'] == 'otp'`:

- `get_total_writes()` returns `TotalBlows`
- `arm_fault()` sets `FaultAtBlow` and `BlowFaultMode`
- `was_fault_injected()` checks `BlowFaultFired`
- Erase faults are no-ops (OTP has no erase operations)
- `_snapshot_current_flash()` reads the full OTP region

The OTP backend also exposes sweep-compatible aliases (`TotalWordWrites`,
`FaultAtWordWrite`, `FaultEverFired`) so existing sweep infrastructure
works without modification.

## What This Tests

1. **Anti-rollback counter corruption**: A partially programmed counter
   could read as a lower value than intended, allowing downgrade.

2. **Security fuse ambiguity**: A half-blown secure-boot-enable fuse
   could leave the device in a state where some code paths check it as
   enabled and others as disabled.

3. **Stuck-bit manufacturing defects**: A counter that cannot increment
   past a certain value due to stuck fuses.

4. **Read disturb attacks**: Repeated reads of adjacent fuses could
   unintentionally blow security-critical bits.
