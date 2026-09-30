TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -Os -g -ffreestanding -fno-builtin \
	-ffunction-sections -fdata-sections
BOOT_LDFLAGS := -nostdlib -Wl,--gc-sections -T boot.ld
APP_LDFLAGS := -nostdlib -Wl,--gc-sections -T app.ld
APP_PAD_TO := 0x10101000

.PHONY: all clean

all: boot.elf old.bin update.bin no_reset.bin hung_update.bin

boot.elf: boot.c boot.ld
	$(CC) $(CFLAGS) $(BOOT_LDFLAGS) -o $@ boot.c

old.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DAPP_VERSION=0 -o $@ app.c

update.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DAPP_VERSION=1 -o $@ app.c

no_reset.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DAPP_VERSION=0 -DREQUEST_RESET=0 -o $@ app.c

hung_update.elf: app.c app.ld
	$(CC) $(CFLAGS) $(APP_LDFLAGS) -DAPP_VERSION=1 -DHANG_BEFORE_SCHEDULER=1 -o $@ app.c

%.bin: %.elf
	$(OBJCOPY) -O binary --gap-fill 0xFF --pad-to $(APP_PAD_TO) $< $@

clean:
	rm -f boot.elf old.elf update.elf no_reset.elf hung_update.elf \
		old.bin update.bin no_reset.bin hung_update.bin
