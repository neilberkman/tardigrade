TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -nostdlib
LDFLAGS := -T firmware.ld -Wl,--build-id=none

.PHONY: all clean
all: boot.elf old.elf update.elf old.bin update.bin

boot.elf: boot.c firmware.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym=FLASH_BASE=0,--defsym=LIVENESS_ADDRESS=0 -o $@ $<

old.elf: app.c firmware.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym=FLASH_BASE=0x10100000,--defsym=LIVENESS_ADDRESS=0x20000200 -DIMAGE_VERSION=1 -o $@ $<

update.elf: app.c firmware.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--defsym=FLASH_BASE=0x10100000,--defsym=LIVENESS_ADDRESS=0x20000300 -DIMAGE_VERSION=2 -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f boot.elf old.elf update.elf old.bin update.bin
