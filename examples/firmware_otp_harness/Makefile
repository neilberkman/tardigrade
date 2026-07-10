TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
TOOLCHAIN_ROOT = $(abspath $(dir $(shell $(CC) -print-libgcc-file-name))/../../../..)

CFLAGS = -mcpu=cortex-m0plus -mthumb -O2 -g -ffreestanding -fno-builtin -fdata-sections -ffunction-sections \
	-ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=. \
	-ffile-prefix-map=$(TOOLCHAIN_ROOT)=/opt/arm-none-eabi \
	-fdebug-prefix-map=$(TOOLCHAIN_ROOT)=/opt/arm-none-eabi
LDFLAGS := -nostdlib -Wl,--gc-sections -T linker.ld

.PHONY: all clean

all: harness.elf harness.bin

harness.elf: harness.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ harness.c

harness.bin: harness.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f harness.elf harness.bin
