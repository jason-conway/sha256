/**
 * @file validation.c
 * @author Jason Conway (jpc@jasonconway.dev)
 * @ref FIPS 180-4 examples
 * @ref NIST CAVP test vectors
 * @ref RFC 4634 test vectors
 * @version 2025.12
 *
 * @copyright This example is free and unencumbered software released into the public domain.
 *
 */

#include "sha256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define countof(a) (sizeof(a) / sizeof(*a))

typedef struct test_case_t {
    const char *name;
    const char *in;
    size_t in_len;
    const char *out;
} test_case_t;

static void to_hex(const uint8_t *hash, char *out)
{
    for (size_t i = 0; i < 32; i++) {
        sprintf(&out[2 * i], "%02x", hash[i]);
    }
    out[64] = '\0';
}

static bool run_test(const test_case_t *test)
{
    uint8_t hash[32] = { 0 };

    sha256_t ctx = { 0 };
    sha256_init(&ctx);
    sha256_append(&ctx, test->in, test->in_len);
    sha256_finish(&ctx, hash);

    char out[65] = { 0 };
    to_hex(hash, out);

    bool ok = !strcmp(out, test->out);

    printf("[%s] %s\n", ok ? "PASS" : "FAIL", test->name);
    if (!ok) {
        printf("  expected: %s\n", test->out);
        printf("  got:      %s\n", out);
    }

    return ok;
}

static bool test_incremental(const test_case_t *test)
{
    sha256_t ctx = { 0 };
    sha256_init(&ctx);

    // one byte at a time
    for (size_t i = 0; i < test->in_len; i++) {
        sha256_append(&ctx, &test->in[i], 1);
    }

    uint8_t hash[32] = { 0 };
    sha256_finish(&ctx, hash);

    char out[65] = { 0 };
    to_hex(hash, out);

    bool ok = !strcmp(out, test->out);

    printf("[%s] %s\n", ok ? "PASS" : "FAIL", test->name);
    if (!ok) {
        printf("  expected: %s\n", test->out);
        printf("  got:      %s\n", out);
    }

    return ok;
}

int main(void)
{
    int passed = 0;
    int total = 0;

    printf("FIPS 180-4 Test Vectors:\n");
    printf("------------------------\n");

    test_case_t fips_tests[] = {
        [0] = {
            .name = "FIPS 180-4: One-block message (\"abc\")",
            .in = "abc",
            .in_len = 3,
            .out = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        },
        [1] = {
            .name = "FIPS 180-4: Two-block message",
            .in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .in_len = 56,
            .out = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        }
    };

    for (size_t i = 0; i < countof(fips_tests); i++) {
        passed += run_test(&fips_tests[i]);
        total++;
    }

    printf("\n");
    printf("RFC 4634 Test Vectors:\n");
    printf("----------------------\n");

    test_case_t rfc_tests[] = {
        [0] = {
            .name = "RFC 4634: Empty string",
            .in = "",
            .in_len = 0,
            .out = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        [1] = {
            .name = "RFC 4634: \"a\"",
            .in = "a",
            .in_len = 1,
            .out = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        },
        [2] = {
            .name = "RFC 4634: \"message digest\"",
            .in = "message digest",
            .in_len = 14,
            .out = "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        },
        [3] = {
            .name = "RFC 4634: a-z",
            .in = "abcdefghijklmnopqrstuvwxyz",
            .in_len = 26,
            .out = "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
        },
        [4] = {
            .name = "RFC 4634: A-Za-z0-9",
            .in = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            .in_len = 62,
            .out = "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0"
        },
        [5] = {
            .name = "RFC 4634: 8x \"1234567890\"",
            .in = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            .in_len = 80,
            .out = "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
        }
    };

    for (size_t i = 0; i < countof(rfc_tests); i++) {
        passed += run_test(&rfc_tests[i]);
        total++;
    }

    printf("\n");
    printf("Boundary Condition Tests:\n");
    printf("-------------------------\n");

    char msg_55[55] = { 0 };
    memset(msg_55, 'a', 55);
    test_case_t boundary_55 = {
        .name = "55-byte message (padding boundary)",
        .in = msg_55,
        .in_len = 55,
        .out = "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
    };
    passed += run_test(&boundary_55);
    total++;

    char msg_56[56] = { 0 };
    memset(msg_56, 'a', 56);
    test_case_t boundary_56 = {
        .name = "56-byte message (padding overflow)",
        .in = msg_56,
        .in_len = 56,
        .out = "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    };
    passed += run_test(&boundary_56);
    total++;

    char msg_64[64] = { 0 };
    memset(msg_64, 'a', 64);
    test_case_t boundary_64 = {
        .name = "64-byte message (one full block)",
        .in = msg_64,
        .in_len = 64,
        .out = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    };
    passed += run_test(&boundary_64);
    total++;

    printf("\n");
    printf("Incremental Append Tests:\n");
    printf("-------------------------\n");

    test_case_t incremental_tests[] = {
        [0] = {
            .name = "Incremental: \"abc\" one byte at a time",
            .in = "abc",
            .in_len = 3,
            .out = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        },
        [1] = {
            .name = "Incremental: \"message digest\" one byte at a time",
            .in = "message digest",
            .in_len = 14,
            .out = "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        }
    };
    for (size_t i = 0; i < countof(incremental_tests); i++) {
        passed += test_incremental(&incremental_tests[i]);
        total++;
    }

    printf("\n");
    printf("Long Message Tests:\n");
    printf("-------------------\n");

    char long_msg[1000] = { 0 };
    memset(long_msg, 'a', 1000);
    test_case_t long_test = {
        .name = "1000 x 'a'",
        .in = long_msg,
        .in_len = 1000,
        .out = "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    };

    passed += run_test(&long_test);
    total++;

    printf("\n");
    printf("Context Reuse Test:\n");
    printf("-------------------\n");

    sha256_t ctx = { 0 };
    uint8_t hash[32] = { 0 };
    char out1[65] = { 0 };
    char out2[65] = { 0 };

    sha256_init(&ctx);
    sha256_append(&ctx, "abc", 3);
    sha256_finish(&ctx, hash);
    to_hex(hash, out1);

    sha256_init(&ctx);
    sha256_append(&ctx, "abc", 3);
    sha256_finish(&ctx, hash);
    to_hex(hash, out2);

    bool ok = !strcmp(out1, out2);
    printf("[%s] Context reinitialization works correctly\n", ok ? "PASS" : "FAIL");

    passed += ok;
    total++;

    printf("\n");
    printf("==================\n");
    printf("Test Results: %d/%d passed\n", passed, total);

    if (passed == total) {
        printf("\nAll tests passed!\n");
        return 0;
    }

    printf("\n%d test(s) failed!\n", total - passed);
    return 1;
}
