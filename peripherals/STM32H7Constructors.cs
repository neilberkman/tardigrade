// SPDX-License-Identifier: Apache-2.0

using Antmicro.Renode.Core;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public sealed class TardigradeH7RNG : STM32_RNG
    {
        // The original H7 platform exposes the F4 register interface.
        public TardigradeH7RNG() : base(STM32Series.F4)
        {
        }
    }

    public sealed class TardigradeH7DMAMUX : STM32_DMAMUX
    {
        public TardigradeH7DMAMUX(Machine machine) : base(machine,
            numberOfInputRequestChannels: 115,
            numberOfOutputRequestChannels: 16, numberOfRequestGeneratorChannels: 8)
        {
        }
    }
}
