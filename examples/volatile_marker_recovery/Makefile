TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
LDFLAGS := -nostdlib -Wl,--gc-sections -T linker.ld

.PHONY: all clean

all: firmware.elf firmware.bin

firmware.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ firmware.c

firmware.bin: firmware.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f firmware.elf firmware.bin
