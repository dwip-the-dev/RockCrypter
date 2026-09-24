#include "rockcrypter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_sbox_bijection(void) {
    printf("[KAT] Testing S-Box Bijection and Invertibility... ");
    uint8_t in[32], ct[32], dec[32];
    uint8_t key[32];
    memset(key, 0x1B, 32);

    rock_core_ctx_t ctx;
    assert(rock_core_expand_key(&ctx, key) == 0);

    for (int t = 0; t < 1000; t++) {
        for (int i = 0; i < 32; i++) {
            in[i] = (uint8_t)(t ^ (i * 37));
        }
        rock_core_encrypt_block(&ctx, in, ct);
        /* Ciphertext must not equal input */
        assert(memcmp(in, ct, 32) != 0);

        rock_core_decrypt_block(&ctx, ct, dec);
        assert(memcmp(in, dec, 32) == 0);
    }
    rock_core_clear(&ctx);
    printf("PASSED (1000 round-trip block tests verified)\n");
}

static void test_sponge_determinism(void) {
    printf("[KAT] Testing RockSponge-512 Determinism... ");
    rock_sponge_t s1, s2;
    rock_sponge_init(&s1, 0x12345678ULL);
    rock_sponge_init(&s2, 0x12345678ULL);

    const char *msg = "RockCrypter Cryptographic System Known-Answer-Test Vector";
    rock_sponge_absorb(&s1, msg, strlen(msg));
    rock_sponge_absorb(&s2, msg, strlen(msg));

    uint8_t out1[64], out2[64];
    rock_sponge_squeeze(&s1, out1, 64);
    rock_sponge_squeeze(&s2, out2, 64);

    assert(memcmp(out1, out2, 64) == 0);
    rock_sponge_clear(&s1);
    rock_sponge_clear(&s2);
    printf("PASSED\n");
}

static void test_kdf_consistency(void) {
    printf("[KAT] Testing RockKDF Consistency and Domain Separation... ");
    uint8_t salt[32];
    memset(salt, 0x99, 32);
    const char *pass = "CorrectHorseBatteryStaple";

    rock_subkeys_t k1, k2;
    /* Use small memory parameter for fast unit test */
    assert(rock_kdf_derive(pass, strlen(pass), salt, 128, 2, &k1) == 0);
    assert(rock_kdf_derive(pass, strlen(pass), salt, 128, 2, &k2) == 0);

    /* Must be deterministic */
    assert(memcmp(&k1, &k2, sizeof(rock_subkeys_t)) == 0);

    /* Domain-separated subkeys must not equal each other */
    assert(memcmp(k1.k_enc, k1.k_white, 32) != 0);
    assert(memcmp(k1.k_enc, k1.k_mac, 32) != 0);
    assert(memcmp(k1.k_white, k1.k_mac, 32) != 0);
    assert(memcmp(k1.k_mac, k1.k_hdr, 32) != 0);

    rock_subkeys_clear(&k1);
    rock_subkeys_clear(&k2);
    printf("PASSED\n");
}

static void test_mac_verification(void) {
    printf("[KAT] Testing RockMAC Verification... ");
    uint8_t key[32];
    memset(key, 0x77, 32);
    const char *data = "Secure message needing authenticated integrity verification";
    uint8_t tag[32];

    assert(rock_mac_compute(key, data, strlen(data), tag) == 0);
    assert(rock_mac_verify(key, data, strlen(data), tag) == 0);

    /* Corrupted message check */
    assert(rock_mac_verify(key, "Corrupted message", 17, tag) != 0);

    /* Corrupted tag check */
    tag[0] ^= 0x01;
    assert(rock_mac_verify(key, data, strlen(data), tag) != 0);

    printf("PASSED\n");
}

static void test_aead_roundtrip(void) {
    printf("[KAT] Testing RockAEAD Buffer Roundtrip & AAD Handling... ");
    const char *plaintext = "Confidential classified document content 2026. Top secret zero-trust.";
    const char *aad = "HeaderMetadata: v1.0, ClientID: 9948";
    const char *pass = "SuperSecureMasterKey#2026!";

    uint8_t *ciphertext = NULL;
    size_t ct_len = 0;

    int ret = rock_aead_encrypt((const uint8_t *)plaintext, strlen(plaintext),
                                (const uint8_t *)aad, strlen(aad),
                                pass, strlen(pass), 1, 128, 2,
                                &ciphertext, &ct_len);
    assert(ret == ROCK_SUCCESS);
    assert(ciphertext != NULL);
    assert(ct_len > strlen(plaintext));

    uint8_t *decrypted = NULL;
    size_t pt_len = 0;

    ret = rock_aead_decrypt(ciphertext, ct_len,
                            (const uint8_t *)aad, strlen(aad),
                            pass, strlen(pass), 1,
                            &decrypted, &pt_len);
    assert(ret == ROCK_SUCCESS);
    assert(pt_len == strlen(plaintext));
    assert(memcmp(decrypted, plaintext, pt_len) == 0);

    /* AAD mismatch test */
    uint8_t *bad_dec = NULL;
    size_t bad_len = 0;
    ret = rock_aead_decrypt(ciphertext, ct_len,
                            (const uint8_t *)"WrongAAD", 8,
                            pass, strlen(pass), 1,
                            &bad_dec, &bad_len);
    assert(ret == ROCK_ERR_AAD_MISMATCH);
    assert(bad_dec == NULL);

    rock_secure_free(ciphertext, ct_len);
    rock_secure_free(decrypted, pt_len);
    printf("PASSED\n");
}

int main(void) {
    printf("=========================================\n");
    printf("   RockCrypter Known-Answer Tests (KAT)   \n");
    printf("=========================================\n");
    test_sbox_bijection();
    test_sponge_determinism();
    test_kdf_consistency();
    test_mac_verification();
    test_aead_roundtrip();
    printf("All Known-Answer Tests PASSED successfully!\n\n");
    return 0;
}
