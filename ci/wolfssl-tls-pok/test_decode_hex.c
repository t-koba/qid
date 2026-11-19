/* Regression test for the interop helper's opaque-byte hex decoder. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int decode_hex(const char* hex, unsigned char** out, size_t* out_len);

static void expect_bytes(const char* hex, const unsigned char* want, size_t want_len)
{
    unsigned char* bytes = NULL;
    size_t length = 0;
    size_t i;

    if (decode_hex(hex, &bytes, &length) != 0 || length != want_len) {
        fprintf(stderr, "decode_hex failed for %s\n", hex);
        exit(1);
    }
    for (i = 0; i < length; ++i) {
        if (bytes[i] != want[i]) {
            fprintf(stderr, "decode_hex mismatch for %s at byte %zu\n", hex, i);
            free(bytes);
            exit(1);
        }
    }
    free(bytes);
}

static void expect_rejected(const char* hex)
{
    unsigned char* bytes = NULL;
    size_t length = 0;

    if (decode_hex(hex, &bytes, &length) == 0) {
        fprintf(stderr, "decode_hex accepted invalid input %s\n", hex);
        free(bytes);
        exit(1);
    }
}

int main(void)
{
    static const unsigned char a6[] = {0xa6};
    static const unsigned char a6b3[] = {0xa6, 0xb3};
    static const unsigned char mixed[] = {0x00, 0xff, 0x10};
    static const unsigned char header[] = {0x16, 0x03, 0x03, 0x00, 0x01};

    expect_bytes("a6", a6, sizeof(a6));
    expect_bytes("a6b3", a6b3, sizeof(a6b3));
    expect_bytes("00ff10", mixed, sizeof(mixed));
    expect_bytes("1603030001", header, sizeof(header));
    expect_rejected("");
    expect_rejected("abc");
    expect_rejected("zz");
    puts("decode_hex regression tests passed");
    return 0;
}
