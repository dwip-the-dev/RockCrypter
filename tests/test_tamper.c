#include "cryptovault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_ciphertext_tampering(void) {
    printf("[Tamper] Exhaustive Bit-Flipping on Ciphertext Payload...\n");
    const char *msg = "This is high-assurance confidential data that must never be released on tampering.";
    size_t msg_len = strlen(msg);
    uint8_t key[32];
    cv_entropy_get(key, 32);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    assert(cv_aead_encrypt((const uint8_t *)msg, msg_len, NULL, 0, key, 32, 0, 0, 0, &ct, &ct_len) == CV_SUCCESS);

    size_t payload_offset = sizeof(cv_header_t);
    int detected_tamper = 0;

    for (size_t i = 0; i < msg_len; i++) {
        ct[payload_offset + i] ^= 0x01; /* Corrupt byte */

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int ret = cv_aead_decrypt(ct, ct_len, NULL, 0, key, 32, 0, &pt, &pt_len);

        /* Must fail and release zero plaintext */
        assert(ret == CV_ERR_AUTH_FAILED);
        assert(pt == NULL);
        assert(pt_len == 0);
        detected_tamper++;

        ct[payload_offset + i] ^= 0x01; /* Restore */
    }

    printf("  Verified %d/%d payload byte corruptions -> 100%% rejected (0 plaintext leaked)\n",
           detected_tamper, (int)msg_len);
    cv_secure_free(ct, ct_len);
}

static void test_header_tampering(void) {
    printf("[Tamper] Exhaustive Bit-Flipping on Header Envelope...\n");
    const char *msg = "TopSecretEnvelopeData";
    size_t msg_len = strlen(msg);
    uint8_t key[32];
    cv_entropy_get(key, 32);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    assert(cv_aead_encrypt((const uint8_t *)msg, msg_len, NULL, 0, key, 32, 0, 0, 0, &ct, &ct_len) == CV_SUCCESS);

    int detected_tamper = 0;
    for (size_t i = 0; i < sizeof(cv_header_t); i++) {
        ct[i] ^= 0x01; /* Corrupt header byte */

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int ret = cv_aead_decrypt(ct, ct_len, NULL, 0, key, 32, 0, &pt, &pt_len);

        assert(ret != CV_SUCCESS);
        assert(pt == NULL);
        assert(pt_len == 0);
        detected_tamper++;

        ct[i] ^= 0x01; /* Restore */
    }

    printf("  Verified %d/%d header corruptions -> 100%% rejected\n",
           detected_tamper, (int)sizeof(cv_header_t));
    cv_secure_free(ct, ct_len);
}

static void test_tag_tampering(void) {
    printf("[Tamper] Exhaustive Bit-Flipping on Authentication Tag...\n");
    const char *msg = "IntegrityVerificationPayload";
    uint8_t key[32];
    cv_entropy_get(key, 32);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    assert(cv_aead_encrypt((const uint8_t *)msg, strlen(msg), NULL, 0, key, 32, 0, 0, 0, &ct, &ct_len) == CV_SUCCESS);

    size_t tag_offset = ct_len - CV_TAG_SIZE;
    int detected_tamper = 0;

    for (size_t i = 0; i < CV_TAG_SIZE; i++) {
        ct[tag_offset + i] ^= 0x80; /* Flip MSB */

        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int ret = cv_aead_decrypt(ct, ct_len, NULL, 0, key, 32, 0, &pt, &pt_len);

        assert(ret == CV_ERR_AUTH_FAILED);
        assert(pt == NULL);
        detected_tamper++;

        ct[tag_offset + i] ^= 0x80; /* Restore */
    }

    printf("  Verified %d/%d tag byte corruptions -> 100%% rejected\n",
           detected_tamper, CV_TAG_SIZE);
    cv_secure_free(ct, ct_len);
}

static void test_truncation_and_extension(void) {
    printf("[Tamper] Testing Truncation and Extension Attacks...\n");
    const char *msg = "Payload to test length truncation";
    uint8_t key[32];
    cv_entropy_get(key, 32);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    assert(cv_aead_encrypt((const uint8_t *)msg, strlen(msg), NULL, 0, key, 32, 0, 0, 0, &ct, &ct_len) == CV_SUCCESS);

    /* 1. Truncate 1 byte */
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    assert(cv_aead_decrypt(ct, ct_len - 1, NULL, 0, key, 32, 0, &pt, &pt_len) != CV_SUCCESS);
    assert(pt == NULL);

    /* 2. Truncate 16 bytes */
    assert(cv_aead_decrypt(ct, ct_len - 16, NULL, 0, key, 32, 0, &pt, &pt_len) != CV_SUCCESS);
    assert(pt == NULL);

    /* 3. Extension: append 4 trailing bytes */
    uint8_t *extended = (uint8_t *)malloc(ct_len + 4);
    memcpy(extended, ct, ct_len);
    memset(extended + ct_len, 0xAA, 4);
    assert(cv_aead_decrypt(extended, ct_len + 4, NULL, 0, key, 32, 0, &pt, &pt_len) != CV_SUCCESS);
    assert(pt == NULL);
    free(extended);

    printf("  --> Truncation & Extension Attacks Rejected!\n");
    cv_secure_free(ct, ct_len);
}

static void test_file_stream_tampering(void) {
    printf("[Tamper] Testing Streaming File Chunk Tamper-Detection...\n");
    const char *in_file = "tmp_plain.txt";
    const char *enc_file = "tmp_enc.bin";
    const char *dec_file = "tmp_dec.txt";

    FILE *f = fopen(in_file, "wb");
    assert(f != NULL);
    for (int i = 0; i < 20000; i++) {
        fprintf(f, "Line %d: High assurance data security test payload.\n", i);
    }
    fclose(f);

    uint8_t key[32];
    cv_entropy_get(key, 32);

    /* Encrypt file */
    assert(cv_file_encrypt(in_file, enc_file, key, 32, 0, (const uint8_t *)"FILE_METADATA", 13, 0, 0) == CV_SUCCESS);

    /* Tamper with a chunk in the encrypted file (e.g. byte offset 500) */
    FILE *f_corrupt = fopen(enc_file, "r+b");
    assert(f_corrupt != NULL);
    fseek(f_corrupt, 500, SEEK_SET);
    int b = fgetc(f_corrupt);
    fseek(f_corrupt, 500, SEEK_SET);
    fputc(b ^ 0xFF, f_corrupt);
    fclose(f_corrupt);

    /* Attempt decryption: must detect corruption and delete partial output */
    int ret = cv_file_decrypt(enc_file, dec_file, key, 32, 0, (const uint8_t *)"FILE_METADATA", 13);
    assert(ret == CV_ERR_AUTH_FAILED || ret == CV_ERR_STREAM_CORRUPTED);

    /* Verify partial output was deleted (fail-secure) */
    assert(access(dec_file, F_OK) != 0);

    unlink(in_file);
    unlink(enc_file);
    printf("  --> Streaming Tamper Detection PASSED (Partial output safely deleted)\n");
}

int main(void) {
    printf("===================================================\n");
    printf("   CryptoVault Zero-Trust Tamper Detection Tests   \n");
    printf("===================================================\n");
    test_ciphertext_tampering();
    test_header_tampering();
    test_tag_tampering();
    test_truncation_and_extension();
    test_file_stream_tampering();
    printf("All Zero-Trust Tamper-Detection Tests PASSED!\n\n");
    return 0;
}
