TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
BOOT_LDFLAGS := -nostdlib -Wl,--gc-sections -T boot.ld
APP_LDFLAGS := -nostdlib -Wl,--gc-sections -T app.ld
APP_PAD_TO := 0x10101000

.PHONY: all clean

all: boot.elf app.bin oscillating.bin fail_second_boot.bin unmet_checks_second_boot.bin

boot.elf: boot.c boot.ld
	$(CC) $(CFLAGS) $(BOOT_LDFLAGS) -o $@ boot.c

app.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -o $@ app.c

oscillating.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DOSCILLATE_ON_TORN=1 -o $@ app.c

fail_second_boot.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DFAIL_ON_SECOND_BOOT=1 -o $@ app.c

unmet_checks_second_boot.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DUNMET_CHECKS_ON_SECOND_BOOT=1 -o $@ app.c

%.bin: %.elf
	$(OBJCOPY) -O binary --gap-fill 0xFF --pad-to $(APP_PAD_TO) $< $@

clean:
	rm -f boot.elf app.elf oscillating.elf fail_second_boot.elf unmet_checks_second_boot.elf \
		app.bin oscillating.bin fail_second_boot.bin unmet_checks_second_boot.bin
