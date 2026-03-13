#include <stddef.h>
#include <stdint.h>

/*
 * Replace this with the real parser under test.
 * The stub keeps the example self-contained.
 */
int parse_ota_header(const uint8_t *data, size_t len) {
    if (len < 32) {
        return -1;
    }
    return data[0] == 0xE9 ? 0 : -2;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) {
        return 0;
    }
    (void)parse_ota_header(data, size);
    return 0;
}
