ifeq ($(origin CC), default)
CC := clang
endif
CFLAGS ?= -g -O1 -fsanitize=fuzzer,address
PREFLIGHT_CFLAGS ?= -g -O1 -Wall -Wextra -Werror

all: fuzz_header_parser preflight_adapter.bin

fuzz_header_parser: example_header_parser_harness.c
	$(CC) $(CFLAGS) $< -o $@

preflight_adapter.bin: example_header_parser_harness.c
	$(CC) $(PREFLIGHT_CFLAGS) -DTARDIGRADE_PREFLIGHT $< -o $@

clean:
	rm -f fuzz_header_parser preflight_adapter.bin
	rm -rf fuzz_header_parser.dSYM preflight_adapter.bin.dSYM
