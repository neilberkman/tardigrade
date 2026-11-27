# Phase-two MRAM parity example

This Cortex-M0+ fixture performs a two-word MRAM update. A cut at the first
word leaves recovery responsible for repairing the update, and a second cut
interrupts the repair's progress word.

`profile_uncorrectable.yaml` uses an uncorrectable first word. Its minimal
HardFault handler skips each rejected load, allowing recovery to rewrite the
word and reach the second cut. The result's `recovery_boot_signals` contain the
uncorrectable-read address and PC.

`profile_followup.yaml` uses `boot_cycles: 2`. Its Python hook persists an MRAM
marker between cycles, and the state probe reports both the persistent marker
and the firmware's observation of it on cycle 1.

`profile_deferred_gate_not_reached.yaml` uses a three-cut search and checks
every deeper state live. A fully completed recovery state takes a success path
before the deferred tracking address, so the search records that the gate was
not reached and produces no candidates from that boot.

Set the toolchain prefix and `renode-test` executable for your installation,
then build and run from the repository root:

```sh
TOOLCHAIN_PREFIX=/path/to/arm-none-eabi-
RENODE_TEST=/path/to/renode-test

make -C examples/phase2_mram_parity \
  TOOLCHAIN_PREFIX="$TOOLCHAIN_PREFIX"
python3 scripts/audit_bootloader.py \
  --profile examples/phase2_mram_parity/profile_uncorrectable.yaml \
  --renode-test "$RENODE_TEST" \
  --workers 1 --no-assert-verdict --output /tmp/phase2-uncorrectable.json
python3 scripts/audit_bootloader.py \
  --profile examples/phase2_mram_parity/profile_followup.yaml \
  --renode-test "$RENODE_TEST" \
  --workers 1 --no-assert-verdict --output /tmp/phase2-followup.json
python3 scripts/audit_bootloader.py \
  --profile examples/phase2_mram_parity/profile_deferred_gate_not_reached.yaml \
  --renode-test "$RENODE_TEST" \
  --workers 1 --no-assert-verdict --output /tmp/deferred-gate-not-reached.json
```
