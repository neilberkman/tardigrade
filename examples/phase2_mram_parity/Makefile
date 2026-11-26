TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
TOOLCHAIN_ROOT = $(abspath $(dir $(shell $(CC) -print-libgcc-file-name))/../../../..)

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections \
	-ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. \
	-ffile-prefix-map=$(TOOLCHAIN_ROOT)=/opt/arm-none-eabi \
	-fdebug-prefix-map=$(TOOLCHAIN_ROOT)=/opt/arm-none-eabi
LDFLAGS := -nostdlib -Wl,--gc-sections -T linker.ld

.PHONY: all clean

all: firmware.elf slot.bin

firmware.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ firmware.c

slot.elf: slot.c slot.ld
	$(CC) $(CFLAGS) -nostdlib -Wl,--gc-sections -T slot.ld -o $@ slot.c

slot.bin: slot.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f firmware.elf slot.elf slot.bin
