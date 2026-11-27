// SPDX-License-Identifier: Apache-2.0

using Antmicro.Renode.Core;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public sealed class TardigradeH7RNG : STM32F4_RNG
    {
    }

    public sealed class TardigradeH7DMAMUX : STM32_DMAMUX
    {
        public TardigradeH7DMAMUX(Machine machine) : base(machine,
            numberOfOutputRequestChannels: 16, numberOfRequestGeneratorChannels: 8)
        {
        }
    }
}
