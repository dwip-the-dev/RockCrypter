#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_hkdf_rfc5869(void) {
    printf("[HKDF] Testing RFC 5869 Extract & Expand Consistency... ");

    const char *ikm = "InputKeyingMaterialConstantVector";
    const char *salt = "CustomDomainSeparationSalt2026";
    const char *info = "CryptoVault-v1-Subkey-Expansion";

    uint8_t prk[32];
    assert(cv_hkdf_extract((const uint8_t *)salt, strlen(salt),
                           (const uint8_t *)ikm, strlen(ikm), prk) == 0);

    uint8_t okm1[64];
    uint8_t okm2[64];

    assert(cv_hkdf_expand(prk, (const uint8_t *)info, strlen(info), okm1, 64) == 0);
    assert(cv_hkdf_expand(prk, (const uint8_t *)info, strlen(info), okm2, 64) == 0);

    /* Determinism */
    assert(cv_ct_memcmp(okm1, okm2, 64) == 0);

    /* Context separation: different info must yield different OKM */
    uint8_t okm3[64];
    assert(cv_hkdf_expand(prk, (const uint8_t *)"DifferentContextInfo", 20, okm3, 64) == 0);
    assert(cv_ct_memcmp(okm1, okm3, 64) != 0);

    /* Direct one-shot HKDF check */
    uint8_t okm_direct[64];
    assert(cv_hkdf((const uint8_t *)salt, strlen(salt),
                   (const uint8_t *)ikm, strlen(ikm),
                   (const uint8_t *)info, strlen(info),
                   okm_direct, 64) == 0);
    assert(cv_ct_memcmp(okm1, okm_direct, 64) == 0);

    printf("PASSED\n");
}

static void test_hkdf_null_salt(void) {
    printf("[HKDF] Testing HKDF with NULL Salt (RFC 5869 Section 2.2)... ");

    const uint8_t ikm[32] = {0x42};
    uint8_t prk[32];

    /* NULL salt should default to 32 zero bytes */
    assert(cv_hkdf_extract(NULL, 0, ikm, sizeof(ikm), prk) == 0);

    uint8_t zero_salt[32];
    memset(zero_salt, 0, sizeof(zero_salt));
    uint8_t prk_zerosalt[32];
    assert(cv_hkdf_extract(zero_salt, sizeof(zero_salt), ikm, sizeof(ikm), prk_zerosalt) == 0);

    assert(cv_ct_memcmp(prk, prk_zerosalt, 32) == 0);

    printf("PASSED\n");
}

static void test_hkdf_long_expansion(void) {
    printf("[HKDF] Testing Multi-Block Long Expansion (1024 bytes)... ");

    uint8_t prk[32];
    for (int i = 0; i < 32; i++) prk[i] = (uint8_t)(i + 1);

    size_t long_len = 1024;
    uint8_t *okm = (uint8_t *)malloc(long_len);
    assert(okm != NULL);

    assert(cv_hkdf_expand(prk, (const uint8_t *)"LongExpandTest", 14, okm, long_len) == 0);

    /* Verify no repeating 32-byte blocks (cycles) */
    for (size_t b1 = 0; b1 < long_len; b1 += 32) {
        for (size_t b2 = b1 + 32; b2 < long_len; b2 += 32) {
            assert(cv_ct_memcmp(okm + b1, okm + b2, 32) != 0);
        }
    }

    free(okm);
    printf("PASSED\n");
}

static void test_hkdf_zero_length_info(void) {
    printf("[HKDF] Testing HKDF with Zero-Length / NULL Info Parameter... ");

    uint8_t prk[32];
    memset(prk, 0x77, 32);

    uint8_t okm1[32];
    uint8_t okm2[32];

    assert(cv_hkdf_expand(prk, NULL, 0, okm1, sizeof(okm1)) == 0);
    assert(cv_hkdf_expand(prk, (const uint8_t *)"", 0, okm2, sizeof(okm2)) == 0);

    assert(cv_ct_memcmp(okm1, okm2, sizeof(okm1)) == 0);

    printf("PASSED\n");
}

static void test_hkdf_boundary_limits(void) {
    printf("[HKDF] Testing Maximum Output Length Bounds Checking... ");

    uint8_t prk[32];
    memset(prk, 0xAA, 32);

    /* Output length exceeding 255 * 32 = 8160 must be rejected */
    uint8_t dummy[10];
    int ret = cv_hkdf_expand(prk, NULL, 0, dummy, 8161);
    assert(ret != 0);

    /* NULL parameters must be rejected */
    assert(cv_hkdf_extract(NULL, 0, NULL, 0, prk) != 0);
    assert(cv_hkdf_expand(NULL, NULL, 0, dummy, 10) != 0);

    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("            CryptoVault HKDF Test Suite             \n");
    printf("====================================================\n");
    test_hkdf_rfc5869();
    test_hkdf_null_salt();
    test_hkdf_long_expansion();
    test_hkdf_zero_length_info();
    test_hkdf_boundary_limits();
    printf("All HKDF Tests PASSED!\n\n");
    return 0;
}
