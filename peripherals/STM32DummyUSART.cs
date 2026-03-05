// Minimal USART stub: always returns TXE=1 (bit 7) and TC=1 (bit 6)
// in the SR register so firmware UART output doesn't hang.
// All writes are silently ignored.

using System.Text;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32DummyUSART : IDoubleWordPeripheral, IKnownSize
    {
        public long Size => 0x400;

        public uint ReadDoubleWord(long offset)
        {
            // SR at offset 0x00: TXE | TC = 0xC0.
            if(offset == 0)
                return 0xC0;
            return 0;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            // DR at offset 0x04: capture output characters.
            if(offset == 0x04)
            {
                char c = (char)(value & 0xFF);
                if(c == '\n' || lineBuffer.Length > 200)
                {
                    if(lineBuffer.Length > 0)
                    {
                        this.Log(LogLevel.Info, "UART: {0}", lineBuffer.ToString());
                    }
                    lineBuffer.Clear();
                }
                else if(c != '\r')
                {
                    lineBuffer.Append(c);
                }
            }
        }

        public void Reset()
        {
            lineBuffer.Clear();
        }

        private readonly StringBuilder lineBuffer = new StringBuilder();
    }
}
