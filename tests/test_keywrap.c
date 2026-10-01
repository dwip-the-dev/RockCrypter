#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_keywrap_roundtrip(void) {
    printf("[KeyWrap] Testing SP-ARX Key Wrap and Unwrap Roundtrip (32-byte key)... ");

    uint8_t kek[32];
    uint8_t target_key[32];
    assert(cv_entropy_get(kek, 32) == 0);
    assert(cv_entropy_get(target_key, 32) == 0);

    uint8_t wrapped[40];
    assert(cv_key_wrap(kek, target_key, 32, wrapped) == 0);

    /* Wrapped key must not match target key */
    assert(cv_ct_memcmp(target_key, wrapped + 8, 32) != 0);

    uint8_t unwrapped[32];
    assert(cv_key_unwrap(kek, wrapped, 40, unwrapped) == 0);
    assert(cv_ct_memcmp(target_key, unwrapped, 32) == 0);

    /* Tamper detection: flip 1 bit in wrapped buffer */
    wrapped[10] ^= 0x01;
    uint8_t corrupted[32];
    assert(cv_key_unwrap(kek, wrapped, 40, corrupted) != 0);

    printf("PASSED\n");
}

static void test_keywrap_various_lengths(void) {
    printf("[KeyWrap] Testing Multiple Key Sizes (16B, 24B, 32B, 64B)... ");

    const size_t test_sizes[] = {16, 24, 32, 64, 128};

    uint8_t kek[32];
    assert(cv_entropy_get(kek, 32) == 0);

    for (size_t s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
        size_t key_len = test_sizes[s];
        uint8_t *orig = (uint8_t *)malloc(key_len);
        uint8_t *wrapped = (uint8_t *)malloc(key_len + 8);
        uint8_t *unwrapped = (uint8_t *)malloc(key_len);
        assert(orig && wrapped && unwrapped);

        assert(cv_entropy_get(orig, key_len) == 0);
        assert(cv_key_wrap(kek, orig, key_len, wrapped) == 0);
        assert(cv_key_unwrap(kek, wrapped, key_len + 8, unwrapped) == 0);
        assert(cv_ct_memcmp(orig, unwrapped, key_len) == 0);

        free(orig);
        free(wrapped);
        free(unwrapped);
    }

    printf("PASSED\n");
}

static void test_keywrap_alignment_errors(void) {
    printf("[KeyWrap] Testing Non-8-Byte Alignment Rejection... ");

    uint8_t kek[32];
    assert(cv_entropy_get(kek, 32) == 0);

    uint8_t unaligned_key[17] = {0};
    uint8_t wrapped[32];

    /* Unaligned key size (17 bytes) must be rejected */
    assert(cv_key_wrap(kek, unaligned_key, 17, wrapped) != 0);

    /* Length < 16 bytes must be rejected */
    uint8_t short_key[8] = {0};
    assert(cv_key_wrap(kek, short_key, 8, wrapped) != 0);

    /* Wrapped length < 24 bytes must be rejected during unwrap */
    uint8_t short_wrapped[16] = {0};
    uint8_t out_key[16];
    assert(cv_key_unwrap(kek, short_wrapped, 16, out_key) != 0);

    printf("PASSED\n");
}

static void test_keywrap_wrong_kek(void) {
    printf("[KeyWrap] Testing Unwrap Rejection with Incorrect KEK... ");

    uint8_t kek1[32];
    uint8_t kek2[32];
    uint8_t target_key[32];
    assert(cv_entropy_get(kek1, 32) == 0);
    assert(cv_entropy_get(kek2, 32) == 0);
    assert(cv_entropy_get(target_key, 32) == 0);

    uint8_t wrapped[40];
    assert(cv_key_wrap(kek1, target_key, 32, wrapped) == 0);

    uint8_t unwrapped[32];
    /* Attempt unwrap with kek2 */
    int ret = cv_key_unwrap(kek2, wrapped, 40, unwrapped);
    assert(ret != 0);

    printf("PASSED\n");
}

static void test_keywrap_boundary_tamper(void) {
    printf("[KeyWrap] Testing Comprehensive Bit-Flipping Fuzzing... ");

    uint8_t kek[32];
    uint8_t target_key[32];
    assert(cv_entropy_get(kek, 32) == 0);
    assert(cv_entropy_get(target_key, 32) == 0);

    uint8_t wrapped[40];
    assert(cv_key_wrap(kek, target_key, 32, wrapped) == 0);

    /* Flip every single byte in the wrapped key one by one; each must fail */
    for (size_t b = 0; b < 40; b++) {
        uint8_t tampered[40];
        memcpy(tampered, wrapped, 40);
        tampered[b] ^= 0x80;

        uint8_t unwrapped[32];
        assert(cv_key_unwrap(kek, tampered, 40, unwrapped) != 0);
    }

    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("          CryptoVault Key Wrap Test Suite           \n");
    printf("====================================================\n");
    test_keywrap_roundtrip();
    test_keywrap_various_lengths();
    test_keywrap_alignment_errors();
    test_keywrap_wrong_kek();
    test_keywrap_boundary_tamper();
    printf("All Key Wrap Tests PASSED!\n\n");
    return 0;
}
