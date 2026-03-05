TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC = $(TOOLCHAIN_PREFIX)gcc
OBJCOPY = $(TOOLCHAIN_PREFIX)objcopy
SIZE = $(TOOLCHAIN_PREFIX)size

CFLAGS  = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
CFLAGS += -Os -Wall -Wextra -Wno-unused-parameter
CFLAGS += -ffunction-sections -fdata-sections -fno-common
CFLAGS += -nostdlib -nostartfiles

LDFLAGS = -T riotboot.ld -Wl,--gc-sections -Wl,-Map=riotboot.map

SRCS = startup.c riotboot.c
OBJS = $(SRCS:.c=.o)

all: riotboot.elf riotboot.bin
	$(SIZE) riotboot.elf

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

riotboot.elf: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lgcc

riotboot.bin: riotboot.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.o *.elf *.bin *.map

.PHONY: all clean
