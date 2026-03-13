CC ?= clang
CFLAGS ?= -g -O1 -fsanitize=fuzzer,address

all: fuzz_header_parser

fuzz_header_parser: example_header_parser_harness.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f fuzz_header_parser
