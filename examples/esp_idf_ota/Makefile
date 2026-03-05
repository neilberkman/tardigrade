TOOLCHAIN_PREFIX ?= arm-none-eabi-
CC = $(TOOLCHAIN_PREFIX)gcc
OBJCOPY = $(TOOLCHAIN_PREFIX)objcopy
STRIP = $(TOOLCHAIN_PREFIX)strip
SIZE = $(TOOLCHAIN_PREFIX)size

CFLAGS  = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
CFLAGS += -Os -Wall -Wextra -Wno-unused-parameter
CFLAGS += -ffunction-sections -fdata-sections -fno-common
CFLAGS += -nostdlib -nostartfiles

LDFLAGS = -T esp_idf_ota.ld -Wl,--gc-sections -Wl,-Map=esp_idf_ota.map

# Defect variants: ESP_DEFECT=0 (none), 1 (no_crc), 2 (single_sector),
#   3 (no_abort), 4 (no_fallback), 5 (crc_covers_state)
DEFECTS = no_crc single_sector no_abort no_fallback crc_covers_state
DEFECT_ELFS = $(foreach d,$(DEFECTS),esp_idf_fault_$(d).elf)
DEFECT_BINS = $(foreach d,$(DEFECTS),esp_idf_fault_$(d).bin)

all: esp_idf_ota.elf esp_idf_ota.bin esp_idf_ota_no_rollback.elf esp_idf_ota_no_rollback.bin $(DEFECT_ELFS) $(DEFECT_BINS)
	$(SIZE) esp_idf_ota.elf $(DEFECT_ELFS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

# --- Correct baseline ---
esp_idf_ota.elf: startup.o esp_idf_ota.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lgcc

# --- No rollback variant ---
esp_idf_ota_no_rollback.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DROLLBACK_ENABLED=0 -c $< -o $@

esp_idf_ota_no_rollback.elf: startup.o esp_idf_ota_no_rollback.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lgcc

# --- Defect variants ---
esp_idf_fault_no_crc.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DESP_DEFECT=1 -c $< -o $@

esp_idf_fault_single_sector.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DESP_DEFECT=2 -c $< -o $@

esp_idf_fault_no_abort.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DESP_DEFECT=3 -c $< -o $@

esp_idf_fault_no_fallback.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DESP_DEFECT=4 -c $< -o $@

esp_idf_fault_crc_covers_state.o: esp_idf_ota.c
	$(CC) $(CFLAGS) -DESP_DEFECT=5 -c $< -o $@

esp_idf_fault_%.elf: startup.o esp_idf_fault_%.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lgcc

strip: esp_idf_ota.elf esp_idf_ota_no_rollback.elf $(DEFECT_ELFS)
	for f in $^; do $(STRIP) --strip-debug $$f; done

clean:
	rm -f *.o *.elf *.bin *.map

.PHONY: all strip clean
