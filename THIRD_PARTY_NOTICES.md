# Third-Party Notices

Tardigrade is licensed under Apache-2.0; see [`LICENSE`](LICENSE). Bundled
third-party notices and license texts are listed below.

## MCUboot

- Project: https://github.com/mcu-tools/mcuboot
- License: Apache-2.0

The Apache-2.0 text is reproduced in this repository's `LICENSE`. MCUboot's
upstream `NOTICE` reads:

> Apache Mynewt  
> Copyright 2015-2017 The Apache Software Foundation
>
> This product includes software developed at  
> The Apache Software Foundation (http://www.apache.org/).
>
> Portions of this software were developed at  
> Runtime Inc, copyright 2015.
>
> Portions of this software were developed at  
> Arm Limited, copyright 2019-2021.

## Zephyr

- Project: https://github.com/zephyrproject-rtos/zephyr
- License: Apache-2.0
- Source revisions:
  - `468eb56cf242eedba62006ee758700ee6148763f` (v3.6.0)
  - `36940db938a8f4a1e919496793ed439850a221c2` (v3.7.0)

The Zephyr build manifests at those revisions pin their public module
dependencies, including MCUboot, CMSIS, and vendor HAL repositories. The
Apache-2.0 text is reproduced in this repository's `LICENSE`.

The retained MCUboot/Zephyr ELFs also link the following public open-source
components. Their verbatim binary-redistribution terms and immutable source
ledger are in [`LICENSES/README.md`](LICENSES/README.md):

- TinyCrypt (`1012a3ebee18c15ede5efc8332ee2fc37817670f`), BSD-3-Clause;
- Nordic nrfx (`ab5cb2e2faeb1edfad7a25286dcb513929ae55da` for
  Zephyr 3.7 and `dce8519f7da37b0a745237679fd3f88250b495ff` for
  Zephyr 3.6), BSD-3-Clause;
- STM32Cube F4 source
  (`f1317150eac951fdd8259337a47cbbc4c2e6d335`), BSD-3-Clause;
- SEGGER RTT (`b011c45b585e097d95d9cf93edf4f2e01588d3cd`), its
  permissive source license;
- picolibc (`764ef4e401a8f4c6a86ab723533841f072885a5b`) and inherited
  newlib sources, under the terms reproduced from the two upstream COPYING
  files; and
- GNU Arm `libgcc`, GPL-3.0 with GCC Runtime Library Exception 3.1.

No STM32 proprietary blob is fetched, linked, or distributed. In particular,
the optional `hal_stm32` SLA0044 blob directory is outside every build used by
the retained STM32F4 assets.

## NuttX nxboot model

- Project: https://github.com/apache/nuttx-apps
- License: Apache-2.0
- Immutable protocol/content baseline:
  `45d4c7098bb3a7a6d9b5642efc47df5998c048d5`

The local bare-metal model carries prominent modification notices in its
source. Apache NuttX's required attribution is reproduced verbatim in
`LICENSES/NUTTX-NOTICE.txt`.

## ESP-IDF OTA model

- Project: https://github.com/espressif/esp-idf
- License: Apache-2.0
- Immutable protocol/content baseline:
  `b8c527a87c1930a2446a5148ec16892b14f99c8e`

The local implementation is a materially independent, simplified model. The
upstream repository has no root NOTICE at that revision; its Apache-2.0 terms
are reproduced in `LICENSE`.

## rustBoot protocol reference

- Project: https://github.com/nihalpasham/rustBoot
- License: MIT
- Source revision: `d4394d383ba3758574159c6630e4c3261a6b47f1`

Tardigrade retains only a clean-room protocol adapter and documentation based
on this public revision. No rustBoot object artifact is distributed.

The rustBoot license text follows:

> MIT License
>
> Copyright (c) 2021 nihalpasham
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Downloaded build and test dependencies

The repository does not vendor these archives. CI and the public validation
container download only checksum-verified releases from public projects:

- Renode 1.16.1 portable .NET archive from
  https://github.com/renode/renode, licensed under MIT. The archive includes
  its complete `licenses/` directory for bundled components.
- xPack GNU Arm Embedded GCC 13.2.1-1.1 from
  https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack. GCC and its
  bundled runtime libraries are open source and the archive carries their
  license files.
- Ubuntu 22.04 from the official public Ubuntu container image, pinned by
  digest in `docker/oss-validation.Dockerfile`.
- Public PyPI packages pinned in `requirements*.txt`. Their licenses are
  OSI-approved permissive, PSF, MPL-2.0, or LGPL-3.0 licenses; no proprietary
  package index or private dependency is used.
