# Zephyr Flash Circular Buffer (`subsys/fs/fcb`) and Settings-on-FCB (`subsys/settings/src/settings_fcb.c`) Targets

This document describes the pinned Zephyr Flash Circular Buffer (`fcb_raw`) and
Settings-on-FCB (`settings_fcb`) power-loss targets under
`targets/zephyr_fcb_settings/`, the `zephyr_fcb_durability` invariant in
`scripts/zephyr_fcb_oracle.py`, and the known open upstream Zephyr issues
(`#121749`, `#121748`, and `#122446`) that the profiles reproduce at both
Zephyr `36940db938a8f4a1e919496793ed439850a221c2` (`v3.7.0`) and current
upstream Zephyr head `06b50e7c66d27d519826a49e3c524ed762873cb6` (`v4.5.99`).

## 1. Known Upstream Zephyr Issues and Observation Mapping

The failures observed across the FCB and Settings-on-FCB power-loss profiles are
reproductions of known open upstream Zephyr issues, not newly discovered bugs:

### 1.1 Zephyr Issue `#121749` (and Referenced Issue `#121748`)

- **Upstream issue `#121749`** (`https://github.com/zephyrproject-rtos/zephyr/issues/121749`)
  covers power cuts during `fcb_sector_hdr_init()` when initializing an
  8-byte `struct fcb_disk_area` sector header (`fd_magic` at offset `+0..+3`,
  `fd_ver` at `+4`, `_pad` at `+5`, `fd_id` at `+6..+7`):
  - The base issue description in `#121749` (cross-referenced from `#121748`)
    notes that a byte-granularity power cut mid-`fd_magic` leaves `fd_magic`
    neither `0xFFFFFFFF` nor `fcb_flash_magic(fcbp)`, causing
    `fcb_sector_hdr_read()` to return `-ENOMSG` and `fcb_init()` to fail
    permanently with `-ENOMSG`.
  - A comment on `#121749` describes the exact word/half-header variant
    reproduced here (and `#121749` links a draft fix): when power is lost after
    `fd_magic` (bytes `0..3`) is programmed but before `fd_ver` and `fd_id`
    (bytes `4..7`) are programmed, `fcb_sector_hdr_read()` checks only
    `fd_magic` (ignoring `fd_ver == 0xFF` and `fd_id == 0xFFFF`) and accepts
    the half-written header. `FCB_ID_GT(a, b)` casts `fd_id = 0xFFFF` to
    `(int16_t)-1`, so `fcb_init()` classifies the brand-new empty sector as
    `f_oldest` and leaves the already-full sector as `f_active`. Because the
    new sector immediately follows `f_active` in the circular sector ring,
    `fcb_free_sector_cnt()` returns `0`, leaving no free sector (`-ENOSPC` in
    raw FCB), while in the settings FCB backend (`settings_fcb_src()`),
    `fcb_free_sector_cnt(&cf->cf_fcb) < 1` triggers `flash_area_flatten()` on
    `cf->cf_fcb.f_active.fe_sector` — erasing the committed active data sector
    instead of the scratch sector.
- **Referenced upstream issue `#121748`** (`https://github.com/zephyrproject-rtos/zephyr/issues/121748`,
  *"fcb: power cut during a 2-byte entry length write makes fcb_init() fail
  permanently (-EIO)"*):
  - Covers entries of 128 bytes or more, which use a 2-byte length header in
    `fcb_append()`. If power is lost after only the first length byte is
    programmed, `fcb_get_len()` decodes a large length (`> FCB_MAX_LEN`)
    instead of returning `-ENOTSUP`, causing `fcb_elem_crc8()` to read past the
    end of the sector and `fcb_init()` to fail permanently with `-EIO`.
  - Our targets use 24-byte `struct fcb_record` payloads (1-byte length header
    `0x18` in `fcb_raw`, or 32-byte `"nvm/k0<id>=" + struct fcb_record` with
    1-byte length header `0x20` in `settings_fcb`). Because all runtime writes
    are under 128 bytes, they use a 1-byte length header and do not exercise
    `#121748`.
- **Observations in our profiles covered by `#121749`**:
  - **Raw FCB (`post_recovery_write_failed` / `-ENOSPC`)**:
    `zephyr_fcb_raw_internal_rotation_sweep` and
    `zephyr_fcb_raw_internal_head_rotation_sweep` at `w[17]` (`0x0000E004`);
    `zephyr_fcb_raw_spi_nor_rotation_sweep` and
    `zephyr_fcb_raw_spi_nor_head_rotation_sweep` at `w[17]` (`0x60002004`);
    and the 1-cut (`rs:17`) and 2-cut (`rs:15 -> 0x...004`) paths in
    `zephyr_fcb_raw_{internal,spi_nor}{,_head}_state_search`.
  - **Settings-on-FCB (`acknowledged_record_lost_or_stale`,
    `deleted_key_reappeared`, `post_recovery_write_failed`)**:
    `zephyr_settings_fcb_internal_compaction_sweep` and
    `zephyr_settings_fcb_internal_head_compaction_sweep` at `w[15]`
    (`0x0000E004`); `zephyr_settings_fcb_spi_nor_compaction_sweep` and
    `zephyr_settings_fcb_spi_nor_head_compaction_sweep` at `w[19]`
    (`0x60002004`); and the 1-cut and 2-cut paths in
    `zephyr_settings_fcb_{internal,spi_nor}{,_head}_state_search`, where
    `settings_fcb_src()` erases active sector `S1`, rolling back `nvm/k01`
    (`seq 10 -> 2`), losing `nvm/k04` (`seq 21 -> 0`), and resurrecting
    deleted key `nvm/k02` (`seq=3` from `S0`).

### 1.2 Zephyr Issue `#122446`

- **Upstream issue `#122446`** (`https://github.com/zephyrproject-rtos/zephyr/issues/122446`)
  covers an uncommitted torn FCB entry being accepted as valid because its
  computed CRC-8 equals the erased flash value (`0xFF`):
  - `fcb_append()` writes `fe_data_len` first, the caller writes the entry
    payload, and `fcb_append_finish()` writes the 1-byte `crc8_ccitt` trailer.
    While the payload is being programmed, the trailing CRC slot in NOR flash is
    still `0xFF`. If power is lost at a partial payload prefix where
    `crc8_ccitt(0xFF, length_header || partial_payload || remaining_0xFF_bytes) == 0xFF`,
    `fcb_elem_crc8()` matches the computed `0xFF` against the unwritten `0xFF`
    byte in flash and accepts the torn entry.
- **Observations in our profiles covered by `#122446`**:
  - `zephyr_settings_fcb_spi_nor_ordinary_sweep` and
    `zephyr_settings_fcb_spi_nor_head_ordinary_sweep` at `w[37]` (`0x60000160`),
    and `zephyr_settings_fcb_spi_nor_compaction_sweep` at `w[59]`
    (`0x60002080`) / `zephyr_settings_fcb_spi_nor_head_compaction_sweep` at
    `w[61]` (`0x60002080`), where cutting the 32-byte `"nvm/k03="` +
    `struct fcb_record(seq=24)` entry on SPI NOR (`f_align = 1`) after 18 bytes
    produces a 33-byte buffer with `crc8_ccitt(0xFF, ...) == 0xFF`, causing
    `settings_load()` to deliver a torn value (`torn_record_value`,
    `acknowledged_record_lost_or_stale`).

### 1.3 Coverage Completeness Against `#121749` and `#122446`

Every failure observed across all 32 profiles (at both `36940db938a8` and
current head `06b50e7c66d2`) is completely covered by `#121749` and `#122446`.
No observation in our sweeps or two-cut recovery-state searches falls outside
these two upstream issues.

## 2. Pinned Target Builds (`36940db938a8` and `06b50e7c66d2`) and API Differences

`targets/zephyr_fcb_settings/build_public_targets.sh` builds all four target
configurations at both pinned upstream commits and records their SHA-256
digests, frozen West manifests (`west-manifest.freeze.yml` and
`west-manifest-head.freeze.yml`), and upstream issue citations in
`targets/zephyr_fcb_settings/build/provenance.json`:

1. **Zephyr `36940db938a8f4a1e919496793ed439850a221c2` (`v3.7.0`)**:
   - `zephyr_fcb_raw_internal.elf`
   - `zephyr_fcb_raw_spi_nor.elf`
   - `zephyr_settings_fcb_internal.elf`
   - `zephyr_settings_fcb_spi_nor.elf`
2. **Zephyr `06b50e7c66d27d519826a49e3c524ed762873cb6` (`v4.5.99` head)**:
   - `zephyr_fcb_raw_internal_head.elf`
   - `zephyr_fcb_raw_spi_nor_head.elf`
   - `zephyr_settings_fcb_internal_head.elf`
   - `zephyr_settings_fcb_spi_nor_head.elf`

### Application API and Subsystem Differences at Head (`06b50e7c66d2`)

- **Zero application source changes required**: `fcb_raw/src/main.c`,
  `settings_fcb/src/main.c`, `include/fcb_oracle_common.h`, `prj_*.conf`, and
  `app_*.overlay` compile unchanged against both `36940db938a8` and
  `06b50e7c66d2`.
- **`include/zephyr/fs/fcb.h`**: `struct fcb::f_sector_cnt` widened from
  `uint8_t` to `uint16_t` (assignment-compatible with `FCB_SECTOR_COUNT = 3`).
- **`include/zephyr/settings/settings.h`**: `struct settings_handler` added an
  `int cprio` commit-priority field (zero-initialized by designated
  initializers).
- **`subsys/fs/fcb/fcb.c` (`fcb_sector_hdr_init`)**: upstream commit
  `f15889378791` (for issue `#111886`) changed `fcb_sector_hdr_init()` from
  writing `sizeof(struct fcb_disk_area)` (`8` bytes = two 4-byte writes) to
  writing a `16`-byte `WRITE_ALIGNMENT_BUFFER_SIZE` union whose trailing `8`
  bytes are filled with `fcbp->f_erase_value` (`0xFF`). On internal nRF52840
  NVMC flash (`faultFlash`), the two trailing `0xFFFFFFFF` words at `+0x008`
  and `+0x00C` do not modify erased flash bits so calibrated write counts remain
  `50` (`fcb_raw` rotation) and `56` (`settings_fcb` compaction). On external
  SPI NOR flash (`spiNor`), the 16-byte SPI page program streams all four 4-byte
  words over `spi2`, increasing calibrated write counts on the SPI NOR
  rotation/compaction profiles by `+2` at head (`50 -> 52` on `fcb_raw` SPI NOR
  rotation and `65 -> 67` on `settings_fcb` SPI NOR compaction, shifting the
  SPI NOR compaction CRC-8 collision cut from `w[59]` to `w[61]`). Both
  `#121749` and `#122446` reproduce identically at head `06b50e7c66d2`.

## 3. Kind-Qualified Durability Oracle Configuration

Single-cut sweep profiles configure `ack_write_boundaries` using kind-qualified
program point labels (`"w[N]"`), and `scripts/zephyr_fcb_oracle.py` propagates
`operation_kind` (`"program"` or `"erase"`) and `point` (`"w[N]"` / `"e[N]"`)
into every `InvariantViolation` detail record:

```yaml
invariants:
  - zephyr_fcb_durability

invariant_config:
  zephyr_fcb_durability:
    ack_write_boundaries:
      "21": "w[8]"
      "22": "w[16]"
      "23": "w[28]"
      "24": "w[52]"
```
