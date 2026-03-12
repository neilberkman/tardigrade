/*
 * fuzz_ota_header_template.c -- Generic libFuzzer harness for OTA image
 * header parsing.
 *
 * PURPOSE
 * -------
 * This is a template you adapt for YOUR bootloader's header parser.
 * The idea: libFuzzer generates random byte sequences, this harness
 * feeds them into your header-parsing function, and we check that the
 * parser either rejects invalid input gracefully or produces a
 * consistent result.  Crashes and sanitizer violations become crash
 * inputs that can be converted into tardigrade regression profiles via
 * scripts/fuzz_crash_to_profile.py.
 *
 * HOW TO ADAPT
 * ------------
 * 1. Replace the #include and struct definitions with your bootloader's
 *    actual header types.
 * 2. Replace parse_image_header() with a call to your real parser.
 * 3. Adjust HEADER_MAX_SIZE to match your header's maximum length.
 * 4. Add any sanitizer annotations or post-parse invariant checks in
 *    the marked section.
 *
 * BUILD (example with clang + libFuzzer)
 * ---------------------------------------
 *   clang -g -O1 -fsanitize=fuzzer,address \
 *       -DFUZZ_TARGET \
 *       -I/path/to/your/bootloader/include \
 *       fuzz_ota_header_template.c \
 *       /path/to/your/header_parser.c \
 *       -o fuzz_ota_header
 *
 *   # Run:
 *   mkdir -p corpus
 *   ./fuzz_ota_header corpus/ -max_len=512
 *
 *   # Seed corpus with a known-good header:
 *   cp known_good_header.bin corpus/seed_0
 *
 * CRASH-TO-PROFILE PIPELINE
 * -------------------------
 *   # After a crash:
 *   python3 scripts/fuzz_crash_to_profile.py \
 *       --crash-input crash-abc123 \
 *       --base-profile profiles/my_bootloader.yaml \
 *       --address-map address_map.yaml \
 *       --output profiles/regression/fuzz_crash_abc123.yaml
 *
 *   # Run the regression profile:
 *   python3 scripts/audit_bootloader.py \
 *       --profile profiles/regression/fuzz_crash_abc123.yaml
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ======================================================================
 * ADAPT THIS SECTION: Replace with your bootloader's header definitions.
 * ====================================================================== */

/* Maximum header size your parser accepts.  Fuzzer inputs are clamped
 * to this length.  Set it to your header's maximum possible size. */
#define HEADER_MAX_SIZE  512

/* Example header structure -- replace with your actual type. */
struct image_header {
    uint32_t magic;
    uint32_t image_size;
    uint32_t version;
    uint32_t flags;
    uint8_t  hash[32];
    /* ... add your fields ... */
};

/* Example return codes -- replace with your parser's actual codes. */
#define PARSE_OK            0
#define PARSE_BAD_MAGIC    -1
#define PARSE_BAD_SIZE     -2
#define PARSE_BAD_HASH     -3
#define PARSE_TOO_SHORT    -4

/*
 * ADAPT: Replace this stub with a call to your real header parser.
 *
 * The function should:
 *   - Return 0 (PARSE_OK) if the header is valid
 *   - Return a negative error code if the header is malformed
 *   - NEVER crash, NEVER access out of bounds, NEVER invoke UB
 *
 * That last point is exactly what we're testing.
 */
static int parse_image_header(const uint8_t *data, size_t len,
                              struct image_header *out)
{
    if (len < sizeof(struct image_header))
        return PARSE_TOO_SHORT;

    memcpy(out, data, sizeof(*out));

    /* Example validation -- replace with your real checks. */
    if (out->magic != 0x96F3B83D)
        return PARSE_BAD_MAGIC;
    if (out->image_size == 0 || out->image_size > 0x100000)
        return PARSE_BAD_SIZE;

    return PARSE_OK;
}

/* ======================================================================
 * END OF ADAPTATION SECTION -- below is generic fuzzer infrastructure.
 * ====================================================================== */

/*
 * libFuzzer entry point.  Called once per fuzzer iteration with a
 * buffer of random bytes.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Clamp input to maximum header size. */
    if (size > HEADER_MAX_SIZE)
        size = HEADER_MAX_SIZE;

    struct image_header parsed;
    memset(&parsed, 0, sizeof(parsed));

    int rc = parse_image_header(data, size, &parsed);

    /* ================================================================
     * POST-PARSE INVARIANT CHECKS
     *
     * Add assertions here that must hold regardless of whether the
     * parse succeeded or failed.  ASan/UBSan catch memory errors
     * automatically; these checks catch logical invariant violations.
     *
     * Examples:
     *   - If parse succeeds, image_size must be within slot bounds
     *   - Parsed version number must not exceed a reasonable maximum
     *   - A "secure boot" flag must not be set without a valid hash
     * ================================================================ */

    if (rc == PARSE_OK) {
        /* Example: image_size was validated, so it should be in range. */
        if (parsed.image_size == 0 || parsed.image_size > 0x100000) {
            /* If this fires, the parser accepted an invalid size.
             * ASan will report this as a crash -> fuzzer saves the input. */
            __builtin_trap();
        }

        /* ADAPT: Add your own post-parse invariant checks here.
         *
         * Example for a bootloader with version anti-rollback:
         *   if (parsed.version < minimum_allowed_version)
         *       __builtin_trap();
         *
         * Example for checking header-body size consistency:
         *   if (parsed.image_size + sizeof(struct image_header) > SLOT_SIZE)
         *       __builtin_trap();
         */
    }

    return 0;  /* Always return 0 -- nonzero means "don't add to corpus." */
}

/*
 * Optional: provide a seed corpus entry programmatically.  This gives
 * the fuzzer a valid header to start mutating from, which dramatically
 * improves coverage for magic-number-gated parsers.
 *
 * Uncomment and adapt if you don't have a file-based seed corpus.
 */
#if 0
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    /* One-time setup.  Use this to initialize global state your parser
     * needs (crypto contexts, flash simulator, etc.). */
    return 0;
}
#endif
