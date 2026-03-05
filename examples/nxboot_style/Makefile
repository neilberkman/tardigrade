TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -O2 -ffreestanding -fno-builtin -fdata-sections -ffunction-sections
LDFLAGS := -nostdlib -Wl,--gc-sections

LINKER := linker_boot.ld
SRC := bootloader_nxboot.c

VARIANTS := \
	bootloader_nxboot_none \
	bootloader_nxboot_no_recovery \
	bootloader_nxboot_no_revert \
	bootloader_nxboot_no_crc

ELF_TARGETS := $(addsuffix .elf,$(VARIANTS))
BIN_TARGETS := $(addsuffix .bin,$(VARIANTS))

.PHONY: all clean

all: $(ELF_TARGETS) $(BIN_TARGETS)

bootloader_nxboot_none.elf: $(SRC) nxboot_standalone.h $(LINKER)
	$(CC) $(CFLAGS) -DNXBOOT_DEFECT=0 $(LDFLAGS) -T $(LINKER) -o $@ $<

bootloader_nxboot_no_recovery.elf: $(SRC) nxboot_standalone.h $(LINKER)
	$(CC) $(CFLAGS) -DNXBOOT_DEFECT=1 $(LDFLAGS) -T $(LINKER) -o $@ $<

bootloader_nxboot_no_revert.elf: $(SRC) nxboot_standalone.h $(LINKER)
	$(CC) $(CFLAGS) -DNXBOOT_DEFECT=2 $(LDFLAGS) -T $(LINKER) -o $@ $<

bootloader_nxboot_no_crc.elf: $(SRC) nxboot_standalone.h $(LINKER)
	$(CC) $(CFLAGS) -DNXBOOT_DEFECT=3 $(LDFLAGS) -T $(LINKER) -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(ELF_TARGETS) $(BIN_TARGETS)
