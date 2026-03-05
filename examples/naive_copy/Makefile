TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy

CFLAGS := -mcpu=cortex-m0plus -mthumb -O2 -ffreestanding -fno-builtin -fdata-sections -ffunction-sections
LDFLAGS := -nostdlib -Wl,--gc-sections

LINKER := linker_boot.ld
SRC := bootloader_naive_copy.c

VARIANTS := \
	bootloader_bare_copy \
	bootloader_crc_pre_copy \
	bootloader_crc_post_copy

ELF_TARGETS := $(addsuffix .elf,$(VARIANTS))
BIN_TARGETS := $(addsuffix .bin,$(VARIANTS))

.PHONY: all clean

all: $(ELF_TARGETS) $(BIN_TARGETS)

bootloader_bare_copy.elf: $(SRC) $(LINKER)
	$(CC) $(CFLAGS) -DNAIVE_MODE=0 $(LDFLAGS) -T $(LINKER) -o $@ $<

bootloader_crc_pre_copy.elf: $(SRC) $(LINKER)
	$(CC) $(CFLAGS) -DNAIVE_MODE=1 $(LDFLAGS) -T $(LINKER) -o $@ $<

bootloader_crc_post_copy.elf: $(SRC) $(LINKER)
	$(CC) $(CFLAGS) -DNAIVE_MODE=2 $(LDFLAGS) -T $(LINKER) -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(ELF_TARGETS) $(BIN_TARGETS)
