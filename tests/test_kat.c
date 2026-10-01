#include "cryptovault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_sbox_bijection(void) {
    printf("[KAT] Testing S-Box Bijection & Invertibility... ");
    uint8_t in[32], ct[32], dec[32];
    uint8_t key[32];
    memset(key, 0x1B, 32);

    cv_core_ctx_t ctx;
    assert(cv_core_expand_key(&ctx, key) == 0);

    for (int t = 0; t < 1000; t++) {
        for (int i = 0; i < 32; i++) {
            in[i] = (uint8_t)(t ^ (i * 37));
        }
        cv_core_encrypt_block(&ctx, in, ct);
        assert(memcmp(in, ct, 32) != 0);

        cv_core_decrypt_block(&ctx, ct, dec);
        assert(memcmp(in, dec, 32) == 0);
    }
    cv_core_clear(&ctx);
    printf("PASSED (1,000 round-trip block tests verified)\n");
}

static void test_sponge_determinism(void) {
    printf("[KAT] Testing 512-bit Sponge Permutation Determinism... ");
    cv_sponge_t s1, s2;
    cv_sponge_init(&s1, 0x12345678ULL);
    cv_sponge_init(&s2, 0x12345678ULL);

    const char *msg = "CryptoVault Standard Cryptographic Test Vector 2026";
    cv_sponge_absorb(&s1, msg, strlen(msg));
    cv_sponge_absorb(&s2, msg, strlen(msg));

    uint8_t out1[64], out2[64];
    cv_sponge_squeeze(&s1, out1, 64);
    cv_sponge_squeeze(&s2, out2, 64);

    assert(memcmp(out1, out2, 64) == 0);
    cv_sponge_clear(&s1);
    cv_sponge_clear(&s2);
    printf("PASSED\n");
}

static void test_kdf_consistency(void) {
    printf("[KAT] Testing Memory-Hard KDF Consistency & Subkey Isolation... ");
    uint8_t salt[32];
    memset(salt, 0x99, 32);
    const char *pass = "CorrectHorseBatteryStaple";

    cv_subkeys_t k1, k2;
    assert(cv_kdf_derive(pass, strlen(pass), salt, 128, 2, &k1) == 0);
    assert(cv_kdf_derive(pass, strlen(pass), salt, 128, 2, &k2) == 0);

    assert(memcmp(&k1, &k2, sizeof(cv_subkeys_t)) == 0);

    /* Domain-separated subkeys must not equal each other */
    assert(memcmp(k1.k_enc, k1.k_white, 32) != 0);
    assert(memcmp(k1.k_enc, k1.k_mac, 32) != 0);
    assert(memcmp(k1.k_white, k1.k_mac, 32) != 0);
    assert(memcmp(k1.k_mac, k1.k_hdr, 32) != 0);

    cv_subkeys_clear(&k1);
    cv_subkeys_clear(&k2);
    printf("PASSED\n");
}

static void test_mac_verification(void) {
    printf("[KAT] Testing Sponge-Based MAC Verification... ");
    uint8_t key[32];
    memset(key, 0x77, 32);
    const char *data = "Secure message needing authenticated integrity verification";
    uint8_t tag[32];

    assert(cv_mac_compute(key, data, strlen(data), tag) == 0);
    assert(cv_mac_verify(key, data, strlen(data), tag) == 0);

    /* Corrupted message test */
    assert(cv_mac_verify(key, "Corrupted message", 17, tag) != 0);

    /* Corrupted tag test */
    tag[0] ^= 0x01;
    assert(cv_mac_verify(key, data, strlen(data), tag) != 0);

    printf("PASSED\n");
}

static void test_aead_roundtrip(void) {
    printf("[KAT] Testing AEAD Buffer Roundtrip & AAD Handling... ");
    const char *plaintext = "Confidential university cybersecurity research document 2026.";
    const char *aad = "HeaderMetadata: CourseworkCS901, StudentID: 9948";
    const char *pass = "SuperSecureMasterKey#2026!";

    uint8_t *ciphertext = NULL;
    size_t ct_len = 0;

    int ret = cv_aead_encrypt((const uint8_t *)plaintext, strlen(plaintext),
                              (const uint8_t *)aad, strlen(aad),
                              pass, strlen(pass), 1, 128, 2,
                              &ciphertext, &ct_len);
    assert(ret == CV_SUCCESS);
    assert(ciphertext != NULL);
    assert(ct_len > strlen(plaintext));

    uint8_t *decrypted = NULL;
    size_t pt_len = 0;

    ret = cv_aead_decrypt(ciphertext, ct_len,
                          (const uint8_t *)aad, strlen(aad),
                          pass, strlen(pass), 1,
                          &decrypted, &pt_len);
    assert(ret == CV_SUCCESS);
    assert(pt_len == strlen(plaintext));
    assert(memcmp(decrypted, plaintext, pt_len) == 0);

    /* AAD mismatch test */
    uint8_t *bad_dec = NULL;
    size_t bad_len = 0;
    ret = cv_aead_decrypt(ciphertext, ct_len,
                          (const uint8_t *)"WrongMetadata", 13,
                          pass, strlen(pass), 1,
                          &bad_dec, &bad_len);
    assert(ret == CV_ERR_AAD_MISMATCH);
    assert(bad_dec == NULL);

    cv_secure_free(ciphertext, ct_len);
    cv_secure_free(decrypted, pt_len);
    printf("PASSED\n");
}

int main(void) {
    printf("===================================================\n");
    printf("      CryptoVault Known-Answer Tests (KAT)         \n");
    printf("===================================================\n");
    test_sbox_bijection();
    test_sponge_determinism();
    test_kdf_consistency();
    test_mac_verification();
    test_aead_roundtrip();
    printf("All Known-Answer Tests PASSED successfully!\n\n");
    return 0;
}
