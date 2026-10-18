# MCUboot PR #2214 swap-offset regression pair

The `mcuboot_pr2214_offset_broken` and `mcuboot_pr2214_offset_fixed`
profiles separate on an nRF52840 layout whose secondary slot is one 4 KiB
sector larger than the primary, with a staged image whose swap size is
exactly `0x74000`. Pre-fix `429e2fea` refuses the upgrade and boots the old
image. Post-fix `90fd59d2` swaps and boots the staged image. No staged image
size separates the pair when both slots have the same sector count, and the
STM32F429 layout the profiles used before never reaches `swap_run` at all.
This note records the derivation so the search in
[issue #18](https://github.com/neilberkman/tardigrade/issues/18) is not
repeated.

## The off-by-one

`find_last_idx` in `boot/bootutil/src/swap_offset.c` walks sectors of the
size of primary sector 0, `S`, until it covers `swap_size`. With
`n = ceil(swap_size / S)`:

- `429e2fea` increments before the bound check and returns `n`, the sector
  count.
- `90fd59d2` increments after the bound check and returns `n - 1`, the index
  of the last sector.

On a fresh upgrade `swap_run` computes the first primary sector that holds
trailer data as `first_trailer_idx = N_pri - k`, where `N_pri` is the
primary sector count and `k = ceil(trailer_sz / S)`. It aborts with
"Not enough free space to run swap upgrade" when
`last_idx >= first_trailer_idx`. So:

- pre-fix aborts when `n >= N_pri - k`
- post-fix aborts when `n >= N_pri - k + 1`
- the pair separates only for `n == N_pri - k`, that is
  `(N_pri - k - 1) * S < swap_size <= (N_pri - k) * S`

## The secondary-slot ceiling

Swap-offset stores the staged image starting at secondary sector 1, so the
image occupies secondary sectors `1..n`. Two checks bound it:

- `bootutil_img_validate` rejects the image when its TLV end, measured from
  the start of the secondary slot, exceeds `bootutil_max_image_size`. For
  swap-offset that limit is the offset of the sector holding the secondary
  trailer, `(N_sec - k) * S`.
- `swap_run` erases the secondary trailer sectors before moving any data.

Both require `n <= N_sec - k - 1`. Combined with `n == N_pri - k`, the pair
can separate only when `N_sec >= N_pri + 1`.

## Numbers for each layout

| Layout | Sectors pri/sec | `trailer_sz` | `first_trailer_idx` | Pre-fix abort | Validation limit for `swap_size` | Separates |
| --- | --- | --- | --- | --- | --- | --- |
| STM32F429, 0x76000 at 0xC000 and 0x82000 | 6 / 3 | 0x1A0 | not reached | not reached | not reached | no |
| nRF52840, 0x76000 at 0xC000 and 0x82000 | 118 / 118 | 0x3E0 | 117 | above 0x74000 | at most 0x74000 | no |
| nRF52840, 0x75000 at 0xC000 and 0x76000 at 0x81000 | 117 / 118 | 0x3E0 | 116 | above 0x73000 | at most 0x74000 | yes, `0x73000 < swap_size <= 0x74000` |

`trailer_sz` comes from the built ELFs. `boot_trailer_sz(w)` disassembles to
`256 * w + 160` in the STM32F429 build, from the 128-sector fallback and
`MCUBOOT_BOOT_MAX_ALIGN=32`, with write size 1. It disassembles to
`236 * w + 48` in both nRF52840 builds, from `MIN_SECTOR_COUNT=118` and the
default `BOOT_MAX_ALIGN` of 8, with write size 4. Building the nRF52840
bootloaders with `MCUBOOT_BOOT_MAX_ALIGN=32` gives `trailer_sz` 0x450, which
still fits in one sector and leaves every row unchanged.

### STM32F429

Zephyr's STM32F429 page layout has four 16 KiB sectors, one 64 KiB sector
and seven 128 KiB sectors per bank. The primary slot gets six sectors, the
last of which runs past the slot end. The secondary slot gets three 128 KiB
sectors, the first at slot offset 0x1E000. `boot_slots_compatible` rejects
6 against 3 with "Cannot upgrade: not a compatible amount of sectors" before
an upgrade starts. `find_last_idx` also assumes every sector
is the size of sector 0, 16 KiB here. The seeded resume state in the old
profiles did not change this: the control boot of the old fixed profile
stopped on the `Cannot upgrade:` console line in all three boot cycles,
before any flash write.

### nRF52840 with equal slots

This is the layout described in issue #18. The pre-fix abort needs
`swap_size > 0x74000`. The secondary validation limit is 0x75000 measured
from the slot start, which leaves at most 0x74000 for an image at offset
0x1000. Every image large enough to reach the abort fails validation first
and is erased. The images issue #18
records as booting on both revisions fall outside the reachable range:

- `zephyr_slot1_max.bin` has swap size 0x74350 and sits at slot offset 0.
  `429e2fea` rejects a header in the first secondary sector with
  "Secondary header magic detected in first sector, wrong upload address?"
  and erases the slot.
- `img_size` 0x74E00 and 0x75000 give swap sizes 0x75150 and 0x75350, past
  both the abort threshold and the validation limit.

A staged image with swap size 0x74800 at slot offset 0x1000 confirms the
validation limit on the historical nRF52840 builds of both commits: both
boot v1.0.0 without starting a swap, and the post-fix console shows
"Image in the secondary slot is not valid!".

### nRF52840 with a secondary slot one sector larger

`swap_size = 0x74000` is the ceiling: the largest size that passes the
secondary validation limit and the post-swap primary limit of 0x74000, and
it is inside the separating window. The 429e2fea console shows:

```
W: Not enough free space to run swap upgrade
W: required 479232 bytes but only 475136 are available
```

479232 is `(last_idx + 1) * S = 117 * 0x1000` and 475136 is
`first_trailer_idx * S = 116 * 0x1000`. The 90fd59d2 console shows the swap
completing and "Image version: v1.2.0".

## Assets

| Asset | Contents |
| --- | --- |
| `oss_mcuboot_pr2214_offset_nrf52_broken.elf` | MCUboot `v2.1.0-246-g429e2fea2451` |
| `oss_mcuboot_pr2214_offset_nrf52_fixed.elf` | MCUboot `v2.1.0-247-g90fd59d2f9e4` |
| `zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin` | one erased 4 KiB sector, then a signed v1.2.0 image with swap size 0x74000 |

Running `BOOTSTRAP_SCOPE=pr2214 bash scripts/bootstrap_mcuboot_matrix_assets.sh`
builds both ELFs, writes `oss_mcuboot_pr2214_offset_nrf52_{broken,fixed}_commit.txt`,
and signs `zephyr_slot1_pr2214_swap_0x74000_offsetslot.bin`. `build_pr_bootloader_variant`
builds each ELF for board `nrf52840dk/nrf52840` with
`CONFIG_BOOT_SWAP_USING_OFFSET=y`, `CONFIG_BOOT_PREFER_SWAP_OFFSET=y`,
`CONFIG_BOOT_SIGNATURE_TYPE_NONE=y`, no `MCUBOOT_BOOT_MAX_ALIGN` override,
`arm-none-eabi-strip -g`, and this partition overlay:

```dts
&flash0 {
    /delete-node/ partitions;

    partitions {
        compatible = "fixed-partitions";
        #address-cells = <1>;
        #size-cells = <1>;

        boot_partition: partition@0 {
            label = "mcuboot";
            reg = <0x0 0x0c000>;
        };
        slot0_partition: partition@c000 {
            label = "image-0";
            reg = <0x0c000 0x75000>;
        };
        slot1_partition: partition@81000 {
            label = "image-1";
            reg = <0x81000 0x76000>;
        };
        storage_partition: partition@f7000 {
            label = "storage";
            reg = <0xf7000 0x09000>;
        };
    };
};

/ {
    chosen {
        zephyr,code-partition = &boot_partition;
    };
};
```

`ensure_mcuboot_history` fetches tags from `https://github.com/mcu-tools/mcuboot.git`
including `v2.1.0` before checking out `429e2fea24518f178cd4d33928cb66fcb0205803`
and `90fd59d2f9e45c24d0833dd391dcdc932b3b1908`, so `git describe` produces the
boot banner above.

The staging image uses the payload of `zephyr_slot1_padded.bin`, the
hello_world body linked for 0xC200, padded with `0x3C` to `img_size`
0x73CB0. `imgtool sign --key root-rsa-2048.pem --align 4 --header-size 0x200
--slot-size 0x76000 --version 1.2.0+0` adds TLVs totalling 0x150, giving
`0x200 + 0x73CB0 + 0x150 = 0x74000`. `imgtool verify` accepts the signed
image. Padding an already signed image would not work because `ih_img_size`
and the SHA-256 TLV cover the payload.

## Profiles and recorded runs

Both profiles load the assets above on `platforms/cortex_m4_flash_fast.repl`
with an explicit `mcuboot_trailer_magic` trigger on the staging slot and the
success marker `0x00000201`, the v1.2.0 header version at 0xC014.
`mcuboot_pr2214_offset_broken` sets `fault_sweep.max_writes: 0`. 429e2fea
moves no image data; its only flash write is `copy_done` at 0x80FE0, and a
power loss there also boots v1.0.0. With fault points enabled the audit
verdict is "control checks failed", because the expected control issue is
accepted only when no fault point reports one.

Runs on `docker://tardigrade-oss-validation:latest` with `--workers 2`:

| Profile | Mode | Wall time | Result |
| --- | --- | --- | --- |
| `mcuboot_pr2214_offset_broken` | `--quick` and full | 36 s each | `PASS`, control exhibits expected `wrong_image`, marker 0x00000001 |
| `mcuboot_pr2214_offset_fixed` | `--quick` | 1027 s | `PASS`, control marker 0x00000201, 124196 calibrated writes, 3 power-loss points at writes 0, 62098 and 124195 all recover to v1.2.0 |

The fixed full sweep has not been run. Its quick run exceeds ten minutes
because calibration emulates the whole 116-sector swap.

`scripts/self_test.py` `check_verdict` does not accept the broken report
yet. It requires calibration coverage whenever `power_loss` is configured,
and a zero-point campaign skips calibration. Both profiles keep
`skip_self_test: true`, so the self-test matrix does not run them.

## Historical equal-slot `90fd59d2` diagnostic boot

The `Unable to find bootable image` failure in the 1-second diagnostic boot of
the historical equal-slot `90fd59d2` nRF52840 build comes from a modified
`boot_swap_tables` entry compiled into
`4295e59:results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf`,
not from the 1-second emulation budget or upstream swap-offset logic. In that
ELF, `boot_swap_tables` entry 2 at `.rodata` address `0x6298` has bytes
`01 04 03 04 04 04`, setting `magic_secondary_slot` and
`copy_done_primary_slot` to `BOOT_FLAG_ANY`, value `4`. Upstream `90fd59d2`
compiles entry 2 as `01 03 03 04 01 04`, where `magic_secondary_slot` is
`BOOT_FLAG_UNSET`, value `3`, and `copy_done_primary_slot` is `BOOT_FLAG_SET`,
value `1`. The initial `4295e59` ELFs for `pr2205` and `pr2206` carry the same
table modification; clean worktree builds in `58cc54b` and
`oss_mcuboot_pr2214_offset_nrf52_fixed.elf` carry the upstream bytes.

On a fresh upgrade in `4295e59:results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf`:

1. `context_boot_go` at `0x960` resets `bs.swap_type` to
   `BOOT_SWAP_TYPE_NONE`, value `1`, sets `state->swap_type[0]` to
   `BOOT_SWAP_TYPE_TEST`, value `2`, at `0xae2`, and calls `swap_run` at
   `0x10c0`.
2. Because `bs.idx` is `1` and `bs.source` is `0`, `swap_run` erases the
   primary trailer at `0x1154`, calls `swap_status_init` at `0x115e`, and
   erases the secondary trailer at `0x1166`.
3. `swap_status_init` at `0x4a0e` calls `boot_write_swap_info` only when
   `bs->swap_type != BOOT_SWAP_TYPE_NONE`. Because `bs.swap_type` is `1`,
   `swap_status_init` writes only `swap_size` and `magic = GOOD` to the
   primary trailer, leaving `swap_type`, `copy_done`, and `image_ok` as
   `UNSET`, value `3`, in flash.
4. At `0x119a..0x1264`, `swap_run` selects between the revert sector loop at
   `0x11a0`, which counts `idx` down from `last_idx` to `0`, and the forward
   upgrade loop at `0x1266`, which counts `idx` up from `0` to `last_idx`, by
   checking whether `bs->swap_type` or `boot_swap_type_multi` returns
   `BOOT_SWAP_TYPE_REVERT`, value `4`.
5. Because `bs->swap_type` is `1`, `swap_run` calls `boot_swap_type_multi` at
   `0x125e` with primary trailer state `magic = GOOD`, `copy_done = UNSET`,
   `image_ok = UNSET` and an erased secondary trailer. In the `4295e59` ELF,
   entry 2 matches `copy_done_primary_slot = BOOT_FLAG_ANY`, logs the first
   `I: Image index: 0, Swap type: revert` line, and returns
   `BOOT_SWAP_TYPE_REVERT`.
6. `swap_run` branches into the revert loop at `0x11a0` for `idx = 5` down to
   `0`, copying secondary sector `idx` to primary sector `idx` and primary
   sector `idx` to secondary sector `idx + 1`. Because `zephyr_slot1_padded.bin`
   was staged at `0x83000`, secondary sector `1`, while secondary sector `0`
   at `0x82000` is erased `0xFF`, the loop copies 4 KiB of `0xFF` from
   `0x82000` into primary sector `0` at `0xC000`, copies the first five
   sectors of `v1.0.1` from `0x83000..0x87FFF` into `0xD000..0x11FFF`, shifts
   `v1.0.0` from `0xC000..0x11FFF` into `0x83000..0x88FFF` over the last
   sector of `v1.0.1`, erases secondary sector `0` and the secondary trailer,
   and writes `copy_done = 1` to the primary trailer.
7. At `0xb5e`, `context_boot_go` calls `boot_read_image_headers`, which calls
   `boot_swap_type_multi` once per slot, logging the second and third
   `I: Image index: 0, Swap type: revert` lines, and reads the post-swap
   primary header at `0xC000`. Because `0xC000` is `0xFF`,
   `boot_read_image_header` fails to find `IMAGE_MAGIC`, `context_boot_go`
   returns failure, and `main` logs `E: Unable to find bootable image` at
   `0x44a` before spinning at `0x44e`.

Running `4295e59:results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf`
on `platforms/cortex_m4_flash_fast.repl` in
`docker://tardigrade-oss-validation:latest` with `zephyr_slot0_padded.bin` at
`0xC000`, `zephyr_slot1_padded.bin` at `0x83000`, and trailer magic
`0xF395C277 0x7FEFD260 0x0F505235 0x8079B62C` at `0xF7FF0..0xF7FFC` produces
identical UARTE0 output for 1.0 s and 10.0 s emulation durations:

```
*** Booting MCUboot v2.1.0-247-g90fd59d2f9e4 ***
*** Using Zephyr OS build v3.7.0 ***
I: Starting bootloader
I: Image index: 0, Swap type: test
I: Primary image: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Secondary image: magic=good, swap_type=0x1, copy_done=0x3, image_ok=0x3
I: Boot source: none
I: Image index: 0, Swap type: test
I: Image index: 0, Swap type: test
I: Image index: 0, Swap type: test
I: Starting swap using offset algorithm.
I: Image index: 0, Swap type: revert
I: Image index: 0, Swap type: revert
I: Image index: 0, Swap type: revert
E: Unable to find bootable image
```

Resetting the CPU for a second and third 1.0 s boot cycle after that first
boot logs `Primary image: magic=good, swap_type=0x2, copy_done=0x1, image_ok=0x3`
and `Secondary image: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3`,
then fails in `boot_prepare_for_swap` with `W: Failed reading image headers; Image=0`
and `E: Unable to find bootable image` because both `0xC000` and `0x82000`
are erased.

Restoring the two upstream bytes in `boot_swap_tables` entry 2 on the `4295e59`
ELF before boot with `sysbus WriteByte 0x6299 0x03` and
`sysbus WriteByte 0x629C 0x01`, or booting the clean equal-slot `90fd59d2`
build from `58cc54b:results/oss_validation/assets/oss_mcuboot_pr2214_offset_geom_fixed.elf`
with its 32-byte-align trailer magic `0xE12D0020 0x0B41295D 0x9C67778D 0x8A1F0F11`
at `0xF7FF0..0xF7FFC`, makes `boot_swap_type_multi` at `0x125e` return
`BOOT_SWAP_TYPE_NONE`. Both runs take the forward upgrade loop at `0x1266` and
boot `v1.0.1` within 1.0 s:

```
I: Starting swap using offset algorithm.
I: Image index: 0, Swap type: none
I: Image index: 0, Swap type: revert
I: Bootloader chainload address offset: 0xc000
I: Image version: v1.0.1
I: Jumping to the first image slot
*** Booting Zephyr OS build v3.7.0 ***
Hello World! nrf52840dk/nrf52840
```

## Provenance of the patched `boot_swap_tables` entry

The modified `boot_swap_tables` entry 2 in
`4295e59:results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf` was
an unrecorded modification in the initial binary import, not a recorded
diagnostic.

Running `git log --follow` on
`results/oss_validation/assets/oss_mcuboot_pr2214_offset_fixed.elf` lists three
commits before removal:

- Commit `4295e59` added `oss_mcuboot_pr2214_offset_broken.elf` and
  `oss_mcuboot_pr2214_offset_fixed.elf` as 76,816-byte nRF52840 ELFs with
  `boot_swap_tables` entry 2 set to `01 04 03 04 04 04` at `.rodata` offset
  `0x6298`. Those same `01 04 03 04 04 04` bytes appear in the `4295e59` builds
  of `oss_mcuboot_pr2205_scratch_{broken,fixed}.elf` and
  `oss_mcuboot_pr2206_scratch{,_geom}_{broken,fixed}.elf`. In `4295e59`,
  `scripts/bootstrap_mcuboot_matrix_assets.sh` only initialized the Zephyr
  workspace without building PR differential ELFs, and no commit message,
  profile, script, or document in `4295e59` recorded any change to
  `boot_swap_tables` or `bootutil_public.c`.
- Commit `5b2bf00` rebuilt `oss_mcuboot_pr2214_offset_broken.elf` and
  `oss_mcuboot_pr2214_offset_fixed.elf` as 77,024-byte STM32F4 ELFs from clean
  detached worktrees added to `scripts/bootstrap_mcuboot_matrix_assets.sh` in
  `3996b44` and `58cc54b`, replacing `boot_swap_tables` entry 2 at `0x8006225`
  with the upstream bytes `01 03 03 04 01 04`.
- Commit `d20be56` stripped debug sections from both STM32F4 ELFs to 74,836
  bytes while keeping the upstream `boot_swap_tables` bytes at `0x800621d`.

Running `git log --follow` and `git blame` on `docs/` shows that no commit or
document mentioned `boot_swap_tables` or `copy_done_primary_slot` before
`4687d75` created `docs/mcuboot-pr2214-swap-offset.md` and `ec470c5` diagnosed
the `4295e59` binary failure. Commit `4687d75` switched
`profiles/mcuboot_pr2214_offset_{broken,fixed}.yaml` to
`oss_mcuboot_pr2214_offset_nrf52_{broken,fixed}.elf`, while
`profiles/mcuboot_pr2214_offset_geom_{broken,fixed}.yaml` use
`oss_mcuboot_pr2214_offset_geom_{broken,fixed}.elf`, leaving
`results/oss_validation/assets/oss_mcuboot_pr2214_offset_{broken,fixed}.elf`
unreferenced and retired.

## STM32F4 geometry pair and `0x0800C000` slot images

The exploratory `mcuboot_pr2214_offset_geom_broken` and
`mcuboot_pr2214_offset_geom_fixed` profiles remain in the repository after the
nRF52840 rework because commit `4687d75` moved two STM32F4 non-uniform-sector
trigger-discovery tests in `tests/test_trigger_discovery.py` onto
`mcuboot_pr2214_offset_geom_fixed.yaml`, and `tests/test_self_test_profiles.py`
lists `pr2214_offset_geom` in `EXPLORATORY_MCUBOOT_DIFFERENTIALS`. The nRF52840
pair uses uniform 4 KiB sectors where `sector_geometry.status` is `match` and
the next erase boundary is `0x1000` bytes ahead of the secondary slot base. On
`mcuboot_pr2214_offset_geom_fixed.yaml`, `validate_compiled_flash_map` matches
the compiled `default_flash_map` slot addresses and sizes at `0x0800C000` and
`0x08082000` while reporting `sector_geometry.status == "mismatch"` for 6
primary sectors against 3 secondary sectors, and `_clone_for_strategy` resolves
the next 128 KiB erase boundary from `0x08082000` to `0x080A0000` at offset
`0x1E000`.

The provenance mismatch on `mcuboot_pr2214_offset_geom_{broken,fixed}.yaml`
came from stale application images linked for `0x08020000` rather than a stale
profile slot map. Commit `5b2bf00` built
`oss_mcuboot_pr2214_offset_geom_{broken,fixed}.elf` on `nucleo_f429zi` with
`offset_with_geom_partition.dts`, placing `slot0_partition` at `0x0800C000` with
size `0x76000`, matching `memory.slots.exec` in both profiles. That commit built
`zephyr_slot1_offset_geom_full.bin` and
`zephyr_slot1_offset_geom_full_offsetslot.bin` from
`zephyr_head_offset_stm32f4_slot1.bin` and pointed `images.exec` at
`zephyr_head_offset_stm32f4_slot0.bin`, both of which were linked for
`0x08020000`.

Running `MCUBOOT_BOOTSTRAP_SCOPE=pr2214_geom bash scripts/bootstrap_mcuboot_matrix_assets.sh`
builds `samples/hello_world` for `nucleo_f429zi` with `slot0_partition` at
`0x0800C000` from `offset_with_geom_partition.dts`, reads
`CONFIG_ROM_START_OFFSET=0x200` from the application `.config`, signs
`zephyr_slot1_offset_geom_full.bin` with `--header-size 0x200 --slot-size 0x76000 --align 32`
at reset vector `0x0800d131`, and prepends `0x1E000` bytes of `0xFF` to produce
`zephyr_slot1_offset_geom_full_offsetslot.bin`. Pointing `images.exec` in both
profiles at `zephyr_slot1_offset_geom_full.bin` aligns both slots with the
bootloader ELF `slot0_partition` base `0x0800C000`.

Quick audit runs under `docker://tardigrade-oss-validation:latest` with
`--quick --workers 2 --no-assert-verdict` before and after rebuilding the
`0x0800C000` images:

| Profile | State | Exit code | Calibrated writes | Control stop reason | Observed control outcome | Fault points | Issue points |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mcuboot_pr2214_offset_geom_broken` | before | 2 | 0 | `console_fatal(Cannot upgrade:)` | `hard_fault` | 0 | 0 |
| `mcuboot_pr2214_offset_geom_broken` | after | 2 | 0 | `console_fatal(Cannot upgrade:)` | `hard_fault` | 0 | 0 |
| `mcuboot_pr2214_offset_geom_fixed` | before | 2 | 0 | `console_fatal(Cannot upgrade:)` | `hard_fault` | 0 | 0 |
| `mcuboot_pr2214_offset_geom_fixed` | after | 2 | 0 | `console_fatal(Cannot upgrade:)` | `hard_fault` | 0 | 0 |

The Renode UART log from the control run prints the refusal line and then chainloads `slot0` at `0x0800C000`:

```
*** Booting MCUboot v2.1.0-247-g90fd59d2f9e4 ***
*** Using Zephyr OS build v3.7.0 ***
I: Starting bootloader
I: Image index: 0, Swap type: none
I: Image index: 0, Swap type: none
W: Cannot upgrade: not a compatible amount of sectors
I: Bootloader chainload address offset: 0xc000
I: Image version: v2.1.0
I: Jumping to the first image slot
*** Booting Zephyr OS build v3.7.0 ***
Hello World! nucleo_f429zi/stm32f429xx
```

In `third_party/zephyr_ws/bootloader/mcuboot/boot/bootutil/src/swap_offset.c` at both `429e2fea24518f178cd4d33928cb66fcb0205803` and `90fd59d2f9e45c24d0833dd391dcdc932b3b1908`, `boot_slots_compatible` at lines 337 to 357 logs `BOOT_LOG_WRN("Cannot upgrade: not a compatible amount of sectors")` at line 353 when the sector count check fails:

```c
num_sectors_pri = boot_img_num_sectors(state, BOOT_PRIMARY_SLOT);
num_sectors_sec = boot_img_num_sectors(state, BOOT_SECONDARY_SLOT);
num_usable_sectors_pri = app_max_sectors(state);

if ((num_sectors_pri != num_sectors_sec) &&
        ((num_sectors_pri + 1) != num_sectors_sec) &&
        ((num_usable_sectors_pri + 1) != (num_sectors_sec))) {
    BOOT_LOG_WRN("Cannot upgrade: not a compatible amount of sectors");
    return 0;
}
```

The failing check compares primary and secondary sector counts:
- `num_sectors_pri` is `6`.
- `num_sectors_sec` is `3`.
- `num_usable_sectors_pri` from `app_max_sectors` at `swap_offset.c:313-335` is `6`, because `app_max_sectors` starts with `first_trailer_idx = 6`, adds `sector_sz = boot_img_sector_size(state, BOOT_PRIMARY_SLOT, 0) = 0x4000` at `16,384` bytes, and breaks immediately when `0x4000 >= trailer_sz` at `0x1A0` or `416` bytes for `max_align = 32` before decrementing `first_trailer_idx`.
- The condition checks `6 != 3`, `6 + 1 != 3`, and `6 + 1 != 3`, then returns `0` to `boot_prepare_image_for_update` at `boot/bootutil/src/loader.c:2030`. `boot_prepare_image_for_update` jumps to `out` at lines 2153 to 2156 and sets `BOOT_SWAP_TYPE(state) = BOOT_SWAP_TYPE_NONE` before reaching `swap_read_status` or `swap_run`. In `scripts/run_runtime_fault_sweep.py`, `check_console_fatal` matches `Cannot upgrade:` in the UART stream at `0.02 s` and classifies the control run as `hard_fault`.

The inconsistency lies in `offset_with_geom_partition.dts` and the `0x1E000`-padded staging image `zephyr_slot1_offset_geom_full_offsetslot.bin` against the STM32F429 Bank 1 hardware erase geometry:
- `memory.slots` in `profiles/mcuboot_pr2214_offset_geom_{broken,fixed}.yaml`, `offset_with_geom_partition.dts` in `scripts/bootstrap_mcuboot_matrix_assets.sh:458-491`, and the compiled `default_flash_map` in `oss_mcuboot_pr2214_offset_geom_{broken,fixed}.elf` all agree on slot addresses and byte sizes: `slot0_partition` at offset `0x0C000` or `0x0800C000` with size `0x76000` or `483,328` bytes, and `slot1_partition` at offset `0x82000` or `0x08082000` with size `0x76000` or `483,328` bytes.
- STM32F429 Bank 1 in `drivers/flash/flash_stm32f4x.c:459-461` has four `16 KiB` sectors at `0x00000..0x0FFFF`, one `64 KiB` sector at `0x10000..0x1FFFF`, and seven `128 KiB` sectors at `0x20000..0xFFFFF`. In `subsys/storage/flash_map/flash_map_layout.c:43-59`, `flash_area_get_sectors` includes a hardware erase sector when `area_off <= info->start_offset < area_off + area_len`.
- `slot0_partition` covers `0x0C000..0x82000` and starts on the `0x0C000` `16 KiB` boundary, so `flash_area_get_sectors` records 6 sectors: `0x0C000` of `16 KiB`, `0x10000` of `64 KiB`, and `0x20000`, `0x40000`, `0x60000`, and `0x80000` of `128 KiB`, where the `0x80000` sector extends `0x1E000` bytes past the end of `slot0_partition` to `0xA0000`.
- `slot1_partition` covers `0x82000..0xF8000` and starts `0x2000` bytes inside the `0x80000..0xA0000` sector. Because `0x80000 < 0x82000`, `flash_area_get_sectors` skips `0x80000` and records 3 sectors of `128 KiB` at `0xA0000`, `0xC0000`, and `0xE0000` with `fs_off` values `0x1E000`, `0x3E000`, and `0x5E000`.
- `zephyr_slot1_offset_geom_full_offsetslot.bin` has size `385,872` bytes or `0x5E350`, formed by prepending `0x1E000` bytes of `0xFF` to the `262,992`-byte or `0x40350` signed image so the header sits at `0x080A0000`. In `swap_offset.c:101`, `boot_read_image_header` reads the secondary slot header at `off = boot_img_sector_size(state, BOOT_SECONDARY_SLOT, 0) = 0x20000` or `0x080A2000`, `0x2000` bytes past the `0x1E000` padding.
- `git log` shows that commit `4295e59` created `profiles/mcuboot_pr2214_offset_geom_{broken,fixed}.yaml` on `nrf52840dk/nrf52840` with uniform `4 KiB` sectors at `0x0000C000` and `0x00082000` of size `0x76000`. Commit `b772260` introduced `offset_with_geom_partition.dts` for `nucleo_f429zi` in `scripts/bootstrap_mcuboot_geometry_assets.sh` while retaining the nRF52840 `0x0C000`/`0x76000` and `0x82000`/`0x76000` partition offsets, and commit `5b2bf00` copied that overlay into `scripts/bootstrap_mcuboot_matrix_assets.sh` and switched both profiles to `platforms/stm32f4.repl`. The overlay and sector counts have been inconsistent with STM32F429 flash geometry since `b772260` and `5b2bf00` moved the pair from nRF52840 to `nucleo_f429zi`.

## Mirrored-bank STM32F429 layout for `pr2214_offset_geom`

Placing `slot0_partition` in STM32F429 Bank 1 at `0x08008000` with size `0x18000` and `slot1_partition` in Bank 2 at `0x08108000` with size `0x38000` satisfies `boot_slots_compatible` and separates `429e2fea24518f178cd4d33928cb66fcb0205803` from `90fd59d2f9e45c24d0833dd391dcdc932b3b1908` at `swap_size = 0x8000`:

- `slot0_partition` at `0x08008000..0x08020000` spans three Bank 1 hardware sectors: two `16 KiB` sectors at `0x08008000` and `0x0800C000` and one `64 KiB` trailer sector at `0x08010000`. Here `N_pri = 3`, `S = 0x4000`, `trailer_sz = 0x450` for `write-block-size = <4>` and `MCUBOOT_BOOT_MAX_ALIGN = 32`, `k = 1`, and `first_trailer_idx = 2`.
- `slot1_partition` at `0x08108000..0x08140000` spans four Bank 2 hardware sectors: two `16 KiB` sectors at `0x08108000` and `0x0810C000`, one `64 KiB` sector at `0x08110000`, and one `128 KiB` trailer sector at `0x08120000`. Here `N_sec = 4 = N_pri + 1`, and secondary sectors `0..2` match primary sector sizes `16 KiB`, `16 KiB`, and `64 KiB`, so `boot_slots_compatible` succeeds.
- `zephyr_slot1_offset_geom_full.bin` is a `32,768`-byte or `0x8000` signed `v2.1.0` image built for `slot0_partition` at `0x08008000` with reset vector `0x08009131`, `0x200` header, `0x7CB0` payload, and `0x150` TLVs. `zephyr_slot1_offset_geom_full_offsetslot.bin` prepends `0x4000` bytes of `0xFF` for secondary sector `0` at `0x08108000`, placing the staged image at `0x0810C000..0x08114000` across secondary sector `1` of `16 KiB` and the first `16 KiB` of secondary sector `2` of `64 KiB`.
- Setting `write-block-size = <4>` in `offset_with_geom_partition.dts` matches `memory.write_granularity: 4` on `platforms/stm32f4.repl` so each STM32F4 flash write increments `FaultInjectableFlash.writeCount` by one 32-bit word during trace replay.
- At `swap_size = 0x8000`, pre-fix `429e2fea` computes `last_idx = 2 >= first_trailer_idx = 2`, logs `W: Not enough free space to run swap upgrade` and `W: required 49152 bytes but only 32768 are available`, writes only `copy_done` at `0x0801FFE0`, and boots `v1.0.0` at `0x08008000`. Post-fix `90fd59d2` computes `last_idx = 1 < first_trailer_idx = 2`, swaps sectors `0` and `1`, and boots `v2.1.0` at `0x08008000`.

Quick audit runs on the mirrored-bank layout with `--quick --workers 2 --no-assert-verdict`:

| Profile | Exit code | Wall time | Calibrated writes | Observed control outcome | Fault points | Recoveries | Issue points |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mcuboot_pr2214_offset_geom_broken` | 0 | 19.6 s | 0 | `wrong_image`, marker `0x00000001` | 0 | 0 | 0 |
| `mcuboot_pr2214_offset_geom_fixed` | 0 | 104.4 s | 12330 | `success`, marker `0x00000102` | 3 | 3 | 0 |

