// SPDX-License-Identifier: Apache-2.0
using Antmicro.Renode.Peripherals.Miscellaneous;

namespace Antmicro.Renode.Peripherals
{
    public sealed class PowerResetWitness : IPowerLossAware
    {
        public string Events { get; private set; } = "";

        public void PowerLost(bool vbatPresent) { Events += vbatPresent ? "battery " : "off "; }
        public void Reset() { Events += "reset "; }
        public void PowerRestored() { Events += "on "; }
    }
}
