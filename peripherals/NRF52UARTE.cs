// Minimal nRF52840 UARTE stub.
// Auto-fires EVENTS_ENDTX and EVENTS_TXSTOPPED when TASKS_STARTTX is written.
// This prevents MCUboot/Zephyr from spinning forever on UART TX completion.

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.UART
{
    public class NRF52UARTE : BasicDoubleWordPeripheral, IKnownSize
    {
        public NRF52UARTE(IMachine machine) : base(machine)
        {
            DefineRegisters();
        }

        public long Size => 0x1000;

        private uint eventsEndTx = 0;
        private uint eventsTxStopped = 0;
        private uint eventsTxStarted = 0;
        private uint eventsRxDReady = 0;
        private uint eventsEndRx = 0;

        private void DefineRegisters()
        {
            // TASKS_STARTRX (0x000)
            Registers.TasksStartRx.Define(this)
                .WithValueField(0, 1, writeCallback: (_, val) =>
                {
                    if(val == 1)
                    {
                        // Auto-complete RX (nothing to receive)
                        eventsEndRx = 1;
                    }
                }, name: "STARTRX");

            // TASKS_STOPRX (0x004)
            Registers.TasksStopRx.Define(this);

            // TASKS_STARTTX (0x008)
            Registers.TasksStartTx.Define(this)
                .WithValueField(0, 1, writeCallback: (_, val) =>
                {
                    if(val == 1)
                    {
                        // Auto-complete: TX is "instant".
                        eventsTxStarted = 1;
                        eventsEndTx = 1;
                        eventsTxStopped = 1;
                    }
                }, name: "STARTTX");

            // TASKS_STOPTX (0x00C)
            Registers.TasksStopTx.Define(this)
                .WithValueField(0, 1, writeCallback: (_, val) =>
                {
                    if(val == 1)
                    {
                        eventsTxStopped = 1;
                    }
                }, name: "STOPTX");

            // EVENTS_ENDRX (0x110)
            Registers.EventsEndRx.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    eventsEndRx = (uint)val;
                }, valueProviderCallback: _ => eventsEndRx, name: "ENDRX");

            // EVENTS_ENDTX (0x120)
            Registers.EventsEndTx.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    eventsEndTx = (uint)val;
                }, valueProviderCallback: _ => eventsEndTx, name: "ENDTX");

            // EVENTS_RXDRDY (0x108)
            Registers.EventsRxDReady.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    eventsRxDReady = (uint)val;
                }, valueProviderCallback: _ => eventsRxDReady, name: "RXDRDY");

            // EVENTS_TXSTARTED (0x150)
            Registers.EventsTxStarted.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    eventsTxStarted = (uint)val;
                }, valueProviderCallback: _ => eventsTxStarted, name: "TXSTARTED");

            // EVENTS_TXSTOPPED (0x158)
            Registers.EventsTxStopped.Define(this)
                .WithValueField(0, 32, writeCallback: (_, val) =>
                {
                    eventsTxStopped = (uint)val;
                }, valueProviderCallback: _ => eventsTxStopped, name: "TXSTOPPED");

            // ERRORSRC (0x480) — no errors.
            Registers.ErrorSrc.Define(this, 0);

            // ENABLE (0x500)
            Registers.Enable.Define(this)
                .WithValueField(0, 4, name: "ENABLE");

            // RXD.AMOUNT (0x538)
            Registers.RxdAmount.Define(this, 0);

            // TXD.AMOUNT (0x548) — report amount = max
            Registers.TxdAmount.Define(this)
                .WithValueField(0, 32, name: "TXDAMOUNT");
        }

        private enum Registers
        {
            TasksStartRx = 0x000,
            TasksStopRx = 0x004,
            TasksStartTx = 0x008,
            TasksStopTx = 0x00C,
            EventsRxDReady = 0x108,
            EventsEndRx = 0x110,
            EventsEndTx = 0x120,
            EventsTxStarted = 0x150,
            EventsTxStopped = 0x158,
            ErrorSrc = 0x480,
            Enable = 0x500,
            RxdAmount = 0x538,
            TxdAmount = 0x548,
        }
    }
}
