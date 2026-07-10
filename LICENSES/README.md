# Bundled third-party license material

These files accompany the public third-party object artifacts tracked under
`results/oss_validation/assets/`.

- `MCUBOOT-NOTICE.txt`: required MCUboot/Apache Mynewt attribution
- `TINYCRYPT-BSD-3-Clause.txt`: TinyCrypt linked by MCUboot
- `NRFX-BSD-3-Clause.txt` and `NRFX-v3.6-BSD-3-Clause.txt`: Nordic nrfx
  HAL linked by nRF52840 builds from the Zephyr 3.7 and 3.6 manifests
- `STM32CUBE-F4-BSD-3-Clause.txt`: STM32Cube F4 LL/HAL source linked by
  STM32F4 builds
- `SEGGER-RTT.txt`: SEGGER RTT source linked by Zephyr console support
- `PICOLIBC-COPYING.txt` and `PICOLIBC-NEWLIB-COPYING.txt`: picolibc and
  inherited newlib notices for Zephyr builds that link picolibc
- `GPL-3.0-only.txt` and `GCC-Runtime-Library-Exception-3.1.txt`: GNU Arm
  `libgcc` runtime linked by the firmware ELFs
- `NUTTX-NOTICE.txt`: Apache NuttX attribution for the local nxboot model
- `RUSTBOOT-MIT.txt`: rustBoot protocol reference used by the clean-room
  adapter; no rustBoot binary is retained

The complete Apache-2.0 text used by Tardigrade, MCUboot, Zephyr, and CMSIS is
at the repository root in `LICENSE`.

## Source links

Every legal text above preserves the wording and line wrapping from the cited
immutable public source. Repository text-file normalization may convert CRLF
to LF or add a final newline; no legal wording is paraphrased.

| File | Public source and immutable revision |
| --- | --- |
| `MCUBOOT-NOTICE.txt` | `https://github.com/mcu-tools/mcuboot/blob/f84b9d3fd019fb1945e532924bee7a9c03c77373/NOTICE` |
| `TINYCRYPT-BSD-3-Clause.txt` | `README.zephyr` is byte-identical at Zephyr TinyCrypt module revisions `3e9a49d2672ec01435ffbf0d788db6d95ef28de0` and `1012a3ebee18c15ede5efc8332ee2fc37817670f`; the latter is `https://github.com/zephyrproject-rtos/tinycrypt/blob/1012a3ebee18c15ede5efc8332ee2fc37817670f/README.zephyr` |
| `NRFX-BSD-3-Clause.txt` | `https://github.com/zephyrproject-rtos/hal_nordic/blob/ab5cb2e2faeb1edfad7a25286dcb513929ae55da/nrfx/hal/nrf_nvmc.h` (leading license block) |
| `NRFX-v3.6-BSD-3-Clause.txt` | `https://github.com/zephyrproject-rtos/hal_nordic/blob/dce8519f7da37b0a745237679fd3f88250b495ff/nrfx/hal/nrf_nvmc.h` (leading license block) |
| `STM32CUBE-F4-BSD-3-Clause.txt` | `https://github.com/zephyrproject-rtos/hal_stm32/blob/f1317150eac951fdd8259337a47cbbc4c2e6d335/stm32cube/stm32f4xx/LICENSE.md` |
| `SEGGER-RTT.txt` | `https://github.com/zephyrproject-rtos/segger/blob/b011c45b585e097d95d9cf93edf4f2e01588d3cd/SEGGER/SEGGER_RTT.c` (leading license block) |
| `PICOLIBC-COPYING.txt` | `https://github.com/zephyrproject-rtos/picolibc/blob/764ef4e401a8f4c6a86ab723533841f072885a5b/COPYING.picolibc` |
| `PICOLIBC-NEWLIB-COPYING.txt` | `https://github.com/zephyrproject-rtos/picolibc/blob/764ef4e401a8f4c6a86ab723533841f072885a5b/COPYING.NEWLIB` |
| `GPL-3.0-only.txt` | `COPYING3` is byte-identical at GCC 8.2.0 `ddeb81e76461fc0075542d436dc962f3cf6fac92` and GCC 13.2.0 `c891d8dc23e1a46ad9f3e757d09e57b500d40044` |
| `GCC-Runtime-Library-Exception-3.1.txt` | `COPYING.RUNTIME` is byte-identical at GCC 8.2.0 `ddeb81e76461fc0075542d436dc962f3cf6fac92` and GCC 13.2.0 `c891d8dc23e1a46ad9f3e757d09e57b500d40044` |
| `NUTTX-NOTICE.txt` | `https://github.com/apache/nuttx-apps/blob/45d4c7098bb3a7a6d9b5642efc47df5998c048d5/NOTICE` |
| `RUSTBOOT-MIT.txt` | `https://github.com/nihalpasham/rustBoot/blob/d4394d383ba3758574159c6630e4c3261a6b47f1/LICENSE` |

The GCC 8 release identifier `gcc-8-branch revision 267074` maps to public
mirror commit `401069dab8cadc29e34f968bbf360ef93c340ce6`.
