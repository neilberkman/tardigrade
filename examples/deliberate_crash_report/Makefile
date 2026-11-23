TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
BOOT_LDFLAGS := -nostdlib -Wl,--gc-sections -T boot.ld
APP_LDFLAGS := -nostdlib -Wl,--gc-sections -T app.ld
APP_PAD_TO := 0x10101000

.PHONY: all clean

all: boot.elf app.bin fault_before_checks.bin fault_forges_checks.bin

boot.elf: boot.c boot.ld
	$(CC) $(CFLAGS) $(BOOT_LDFLAGS) -o $@ boot.c

app.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -o $@ app.c

fault_before_checks.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DFAULT_BEFORE_CHECKS=1 -o $@ app.c

fault_forges_checks.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DFAULT_BEFORE_CHECKS=1 -DFAULT_HANDLER_FORGES_CHECKS=1 -o $@ app.c

%.bin: %.elf
	$(OBJCOPY) -O binary --gap-fill 0xFF --pad-to $(APP_PAD_TO) $< $@

clean:
	rm -f boot.elf app.elf fault_before_checks.elf fault_forges_checks.elf \
		app.bin fault_before_checks.bin fault_forges_checks.bin
