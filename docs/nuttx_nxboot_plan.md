# NuttX nxboot target plan

This repo now includes a real `targets/nuttx_nxboot/` adapter scaffold based on
the public upstream `apache/nuttx-apps/boot/nxboot` semantics. The missing part
is no longer "what should we test?" but "what real upstream board/config can we
run under Renode with the three-slot nxboot model?"

## What already exists

- `targets/nuttx_nxboot/probe.py`
  - models public `nxboot_get_state()`-style slot roles
  - exports `update_slot`, `recovery_slot`, `primary_confirmed`,
    `recovery_valid`, `recovery_present`, and `next_boot`
- `targets/nuttx_nxboot/invariants.py`
  - `nuttx_nxboot_roles_distinct`
  - `nuttx_nxboot_confirmed_has_recovery`
  - `nuttx_nxboot_duplicate_update_consumed`
- unit coverage in `tests/test_nuttx_nxboot_target_package.py`

## Why this is the next real OSS target

- upstream has real public bugs in this state machine:
  - `#2824` incorrect confirm state for directly flashed image
  - `#3169` unwanted confirm on double update
- those bugs are closer to the semantic discovery story than the synthetic
  `nxboot_style` model
- `nxboot` is a better "second OSS target" story than adding more synthetic
  public examples

## Current gap

What does not exist yet:

- a real runnable public profile/workflow
- actual NuttX-built ELFs/images in this repo
- a public Renode platform/layout for an upstream-supported nxboot board

The main technical blocker is that nxboot needs three image partitions
(`primary`, `secondary`, `tertiary`), while the easiest upstream Renode-capable
board path we found is currently MCUboot-oriented and only exposes two OTA
slots plus scratch.

## Candidate board scan

### `nucleo-h743zi` (current first choice)

Why it is attractive:

- NuttX already documents it as Renode-capable in
  `Documentation/guides/renode.rst`
- it already has upstream board logic for:
  - `board_boot_image()` in `boards/arm/stm32h7/nucleo-h743zi/src/stm32_boot_image.c`
  - progmem OTA partition registration in
    `boards/arm/stm32h7/nucleo-h743zi/src/stm32_progmem.c`
- upstream already carries bootloader-oriented public configs:
  - `boards/arm/stm32h7/nucleo-h743zi/configs/mcuboot-loader/defconfig`
  - `boards/arm/stm32h7/nucleo-h743zi/configs/mcuboot-app/defconfig`

Why it is not yet a drop-in nxboot target:

- `stm32_progmem.c` currently registers:
  - `/dev/ota0`
  - `/dev/ota1`
  - `/dev/otascratch`
- nxboot requires:
  - `/dev/ota0`
  - `/dev/ota1`
  - `/dev/ota2`
- so the current board support is structurally closer to MCUboot than nxboot

Current verdict:

- best public candidate so far
- not runnable for real nxboot until a third slot is exposed

### `stm32f4discovery`

Pros:

- explicitly documented as Renode-tested
- simpler Cortex-M4 board

Cons:

- no obvious upstream OTA partition support
- no existing bootloader-style board configs to piggyback on
- likely more custom board/storage work than `nucleo-h743zi`

Current verdict:

- good fallback if `nucleo-h743zi` stalls
- not the fastest first path

### `nrf52840-dk`

Pros:

- explicitly documented as Renode-tested

Cons:

- Renode guide already calls out QSPI as not implemented
- external-flash-backed update/recovery storage is therefore a weak fit

Current verdict:

- poor first target for nxboot under Renode

## Concrete next implementation step

Use `nucleo-h743zi` as the first real target and derive an nxboot configuration
from the existing public MCUboot configs, but only after solving the third-slot
problem.

That means:

1. derive a public `nucleo-h743zi:nxboot-loader` config from
   `mcuboot-loader`
2. derive a public `nucleo-h743zi:nxboot-app` config from `mcuboot-app`
3. replace MCUboot-specific format/loader settings with:
   - `CONFIG_BOOT_NXBOOT`
   - `CONFIG_NXBOOT_BOOTLOADER`
   - `CONFIG_NXBOOT_HEADER_SIZE`
   - `CONFIG_NXBOOT_PLATFORM_IDENTIFIER`
   - `CONFIG_NXBOOT_PRIMARY_SLOT_PATH`
   - `CONFIG_NXBOOT_SECONDARY_SLOT_PATH`
   - `CONFIG_NXBOOT_TERTIARY_SLOT_PATH`
4. expose a real third slot on the board side or in a public Renode-backed
   storage layout

## Required config and board delta

The existing public `mcuboot-*` configs on `nucleo-h743zi` are useful mainly
as a map of what must change.

### Loader-side delta

Starting point:

- `boards/arm/stm32h7/nucleo-h743zi/configs/mcuboot-loader/defconfig`

Replace:

- `CONFIG_BOOT_MCUBOOT=y`
- `CONFIG_MCUBOOT_BOOTLOADER=y`
- `CONFIG_STM32_APP_FORMAT_MCUBOOT=y`

With nxboot-oriented settings:

- `CONFIG_BOOT_NXBOOT=y`
- `CONFIG_NXBOOT_BOOTLOADER=y`
- `CONFIG_NXBOOT_HEADER_SIZE=0x200`
- `CONFIG_NXBOOT_PLATFORM_IDENTIFIER=<public test id>`
- `CONFIG_NXBOOT_PRIMARY_SLOT_PATH="/dev/ota0"`
- `CONFIG_NXBOOT_SECONDARY_SLOT_PATH="/dev/ota1"`
- `CONFIG_NXBOOT_TERTIARY_SLOT_PATH="/dev/ota2"`

Keep if possible:

- `CONFIG_BOARDCTL_RESET=y`
- `CONFIG_STM32H7_FLASH_OVERRIDE_I=y`
- `CONFIG_STM32_PROGMEM_OTA_PARTITION=y` or successor
- `CONFIG_BOARDCTL_BOOT_IMAGE=y` (pulled in by `CONFIG_NXBOOT_BOOTLOADER`)

### App-side delta

Starting point:

- `boards/arm/stm32h7/nucleo-h743zi/configs/mcuboot-app/defconfig`

Remove MCUboot app helpers:

- `CONFIG_EXAMPLES_MCUBOOT_SLOT_CONFIRM=y`
- `CONFIG_EXAMPLES_MCUBOOT_SWAP_TEST=y`
- `CONFIG_EXAMPLES_MCUBOOT_UPDATE_AGENT=y`
- `CONFIG_STM32_APP_FORMAT_MCUBOOT=y`

Replace with nxboot-compatible application pieces:

- `CONFIG_BOOT_NXBOOT=y`
- some minimal app path that can:
  - call `nxboot_get_state()`
  - write an update through `nxboot_open_update_partition()`
  - call `nxboot_confirm()`

The existing `apps/examples/shv-nxboot-updater/` example is a likely public
source for the update-side behavior, but not necessarily the final CI payload.

### Board/linker delta

This is the part that currently prevents a quick public workflow.

- `boards/arm/stm32h7/nucleo-h743zi/src/CMakeLists.txt` currently switches
  linker scripts only for `CONFIG_STM32_APP_FORMAT_MCUBOOT`
- `boards/arm/stm32h7/nucleo-h743zi/src/stm32_progmem.c` currently registers
  only `ota0`, `ota1`, and `otascratch`

So a real public nxboot target likely needs:

1. an nxboot-specific linker-script path or a generic image-header-capable
   path for primary firmware
2. a three-slot board storage layout (`ota0`, `ota1`, `ota2`)
3. a public Renode board/platform setup that reflects that layout

## Public backlog

Short term:

1. document the required config delta from `mcuboot-*` to `nxboot-*`
2. identify the cleanest public way to expose `/dev/ota2` for
   `nucleo-h743zi`
3. build the first real upstream artifacts outside CI
4. only then add `profiles/nuttx_nxboot_*.yaml`

Medium term:

1. wire a public exploratory scenario using `targets/nuttx_nxboot/*`
2. focus the first upstream-facing scenario on the duplicate-update /
   confirm / revert class
3. pitch a narrow scheduled/manual validation surface upstream only after the
   local/public run is stable
