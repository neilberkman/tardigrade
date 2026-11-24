TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
LDFLAGS := -nostdlib -Wl,--gc-sections -T linker.ld

ERASED_LDFLAGS := -nostdlib -Wl,--gc-sections -T erased_vector.ld

.PHONY: all clean

all: firmware.elf firmware.bin erased_vector.elf erased_vector.bin

firmware.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ firmware.c

firmware.bin: firmware.elf
	$(OBJCOPY) -O binary $< $@

erased_vector.elf: erased_vector.c erased_vector.ld
	$(CC) $(CFLAGS) $(ERASED_LDFLAGS) -o $@ erased_vector.c

erased_vector.bin: erased_vector.elf
	$(OBJCOPY) -O binary --gap-fill 0xFF $< $@

clean:
	rm -f firmware.elf firmware.bin erased_vector.elf erased_vector.bin
