# SPDX-License-Identifier: Apache-2.0
CC = arm-none-eabi-gcc
CFLAGS = -mcpu=cortex-m4 -mthumb -Os -ffreestanding -nostdlib
LDFLAGS = -T link.ld -Wl,--build-id=none

all: nrf52840.elf stm32f4.elf

nrf52840.elf: firmware.c link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym,ORIGIN_FLASH=0 -DNRF52840 $< -o $@

stm32f4.elf: firmware.c link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym,ORIGIN_FLASH=0x08000000 -DSTM32F4 $< -o $@

clean:
	rm -f nrf52840.elf stm32f4.elf
