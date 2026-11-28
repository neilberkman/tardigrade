# wolfBoot on STM32F4

These profiles exercise an interrupted update and recovery using wolfBoot’s
shipped STM32F407 configuration. wolfBoot and OpenBLT use GPL-3.0-or-later.
Their source and build products stay in local build directories outside the
tracked tree.

## Tested revisions

| Target | Revision | Selected upstream configuration | Result |
| --- | --- | --- | --- |
| wolfBoot | `ad8dc62131fc0067a3ab25edc1b7e731397712d4` | `config/examples/stm32f407-discovery.config` | Built and tested on the modeled STM32F4 flash controller |
| OpenBLT | `64beeee6f24490f7ca3373185bfcd3188a6d3b15` | `Target/Demo/ARMCM4_STM32F4_Nucleo_F429ZI_GCC` | Buildable, but update testing stops because the unmodified public tree cannot provide the required self-contained A/B flow |

The selected wolfBoot configuration enables Ed25519 signatures, SHA-256
hashing, vector-table relocation, and custom partition trailers. It places
a 384 KiB boot partition at `0x08020000`, a 384 KiB update partition at
`0x08080000`, and a 128 KiB scratch partition at `0x080E0000`. The Tardigrade
profiles do not add or override wolfBoot build options.

STM32F4 was selected because the repository models its flash programming and
sector erasure protocol, including the boot alias used by wolfBoot. The
upstream test application is signed twice with wolfBoot's own tools to create
version 1 and version 2 inputs.

The selected OpenBLT demo builds without source edits, but it does
not expose an autonomous internal-flash A/B or swap update. Its public update
paths require an external XCP controller or removable storage, and its rollback
extension is not included in the public repository. The selected demo also
initializes peripherals that this Tardigrade platform does not model. Testing
it as requested would therefore require upstream source or configuration
changes, so the build driver reports those blockers and creates no OpenBLT
profiles.

## Build

The driver requires the `arm-none-eabi-gcc` toolchain on `PATH`.

```console
python3 scripts/build_wolfboot.py --target wolfboot \
  --json-out build/wolfboot/build_manifest.json
```

The driver clones and verifies the pinned revisions under the ignored
`build/wolfboot/` directory. An explicit `--work-dir` is accepted only
when it is outside the repository or covered by `.gitignore`. It copies the
shipped wolfBoot configuration to the location expected by wolfBoot's build,
generates a local test key and signs through the upstream tools, and refuses
unexpected changes to tracked upstream files.

## Run

```console
python3 scripts/audit_bootloader.py \
  --profile profiles/wolfboot_stm32f4_control.yaml \
  --output results/wolfboot/wolfboot_control.json

python3 scripts/audit_bootloader.py \
  --profile profiles/wolfboot_stm32f4_power_loss_erase.yaml \
  --output results/wolfboot/wolfboot_power_loss_erase.json

python3 scripts/audit_bootloader.py \
  --profile profiles/wolfboot_stm32f4_state_search.yaml \
  --output results/wolfboot/wolfboot_state_search.json
```

The uninterrupted control requires the signed v2 image and its version marker.
The sweep samples programming cuts and includes every erase cut. The state
search explores recovery after an interrupted trailer-sector erase and checks
each generated two-cut state against live execution.

Both fault campaigns require application handoff in the execution slot and
check that slot against the hashes of the two signed inputs. A recorded
match for `staging` identifies the new v2 image, and a match for `exec`
identifies the original v1 image. If power fails after wolfBoot marks v2 as
testing and before its first boot, wolfBoot can restore v1 through rollback.
