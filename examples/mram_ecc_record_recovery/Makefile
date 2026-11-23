TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
PYTHON ?= python3

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
LDFLAGS := -nostdlib -Wl,--gc-sections -T linker.ld

.PHONY: all clean

all: firmware_unhandled.elf firmware_handled.elf initial_mram.bin

firmware_unhandled.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -DHANDLE_READ_FAULT=0 -o $@ firmware.c

firmware_handled.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -DHANDLE_READ_FAULT=1 -o $@ firmware.c

initial_mram.bin: gen_initial_mram.py
	$(PYTHON) gen_initial_mram.py $@

clean:
	rm -f firmware_unhandled.elf firmware_handled.elf initial_mram.bin
