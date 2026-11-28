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

all: firmware.elf firmware_two_unit.elf firmware_deferred.elf \
	firmware_deferred_early_success.elf slot.bin

firmware.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ firmware.c

firmware_two_unit.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-DTARGET_ADDRESS_VALUE=0x10100108u \
		-DPROGRESS_ADDRESS_VALUE=0x10100118u \
		-DHOOK_ADDRESS_VALUE=0x10100128u \
		-o $@ firmware.c

firmware_deferred.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-DTARGET_ADDRESS_VALUE=0x10100108u \
		-DPROGRESS_ADDRESS_VALUE=0x10100118u \
		-DHOOK_ADDRESS_VALUE=0x10100128u \
		-DDEFERRED_TRACKING_FIXTURE=1 \
		-o $@ firmware.c

firmware_deferred_early_success.elf: firmware.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-DTARGET_ADDRESS_VALUE=0x10100108u \
		-DPROGRESS_ADDRESS_VALUE=0x10100118u \
		-DHOOK_ADDRESS_VALUE=0x10100128u \
		-DDEFERRED_TRACKING_FIXTURE=1 \
		-DDEFERRED_EARLY_SUCCESS_FIXTURE=1 \
		-o $@ firmware.c

slot.elf: slot.c slot.ld
	$(CC) $(CFLAGS) -nostdlib -Wl,--gc-sections -T slot.ld -o $@ slot.c

slot.bin: slot.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f firmware.elf firmware_two_unit.elf firmware_deferred.elf \
		firmware_deferred_early_success.elf counter.elf slot.elf slot.bin

counter.elf: counter.c linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ counter.c
