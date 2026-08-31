#include <stddef.h>
#include <stdint.h>

#ifdef TARDIGRADE_PREFLIGHT
#include <stdio.h>
#include <stdlib.h>
#endif

/*
 * Replace this with the real parser under test.
 * The stub keeps the example self-contained.
 */
int parse_ota_header(const uint8_t *data, size_t len) {
    if (len < 32) {
        return -1;
    }
    return data[0] == 'V' ? 0 : -2;
}

#ifndef TARDIGRADE_PREFLIGHT
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) {
        return 0;
    }
    (void)parse_ota_header(data, size);
    return 0;
}
#else
int main(int argc, char **argv) {
    FILE *stream;
    long length;
    uint8_t *data;
    size_t read_length;
    int accepted;

    if (argc != 2) {
        fputs("usage: preflight_adapter.bin INPUT\n", stderr);
        return 2;
    }
    stream = fopen(argv[1], "rb");
    if (stream == NULL || fseek(stream, 0, SEEK_END) != 0) {
        if (stream != NULL) {
            fclose(stream);
        }
        return 2;
    }
    length = ftell(stream);
    if (length < 0 || fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return 2;
    }
    data = malloc(length > 0 ? (size_t)length : 1U);
    if (data == NULL) {
        fclose(stream);
        return 2;
    }
    read_length = fread(data, 1, (size_t)length, stream);
    if (fclose(stream) != 0 || read_length != (size_t)length) {
        free(data);
        return 2;
    }
    accepted = parse_ota_header(data, read_length) == 0;
    free(data);
    printf("{\"accepted\":%s}\n", accepted ? "true" : "false");
    return 0;
}
#endif
