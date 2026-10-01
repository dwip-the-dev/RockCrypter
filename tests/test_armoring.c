#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_armor_roundtrip(void) {
    printf("[Armoring] Testing RFC 4880 ASCII Armor Encode/Decode with CRC24... ");

    uint8_t original[128];
    assert(cv_entropy_get(original, sizeof(original)) == 0);

    char armored[1024];
    assert(cv_armor_encode(CV_ARMOR_MESSAGE, original, sizeof(original),
                           armored, sizeof(armored)) == 0);

    assert(strstr(armored, "-----BEGIN CRYPTOVAULT ENCRYPTED MESSAGE-----") != NULL);
    assert(strstr(armored, "-----END CRYPTOVAULT ENCRYPTED MESSAGE-----") != NULL);

    uint8_t decoded[128];
    size_t dec_len = sizeof(decoded);
    cv_armor_type_t type;
    assert(cv_armor_decode(armored, &type, decoded, &dec_len) == 0);
    assert(type == CV_ARMOR_MESSAGE);
    assert(dec_len == sizeof(original));
    assert(cv_ct_memcmp(original, decoded, sizeof(original)) == 0);

    printf("PASSED\n");
}

static void test_armor_all_types(void) {
    printf("[Armoring] Testing All Armor Header Types (Key, Share, PubKey)... ");

    uint8_t raw[32];
    assert(cv_entropy_get(raw, sizeof(raw)) == 0);

    const cv_armor_type_t types[] = {
        CV_ARMOR_KEY,
        CV_ARMOR_SHARE,
        CV_ARMOR_PUBKEY
    };

    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        char armored[512];
        assert(cv_armor_encode(types[i], raw, sizeof(raw), armored, sizeof(armored)) == 0);

        uint8_t decoded[64];
        size_t dec_len = sizeof(decoded);
        cv_armor_type_t out_type;
        assert(cv_armor_decode(armored, &out_type, decoded, &dec_len) == 0);
        assert(out_type == types[i]);
        assert(dec_len == sizeof(raw));
        assert(cv_ct_memcmp(raw, decoded, sizeof(raw)) == 0);
    }

    printf("PASSED\n");
}

static void test_crc24_corruption(void) {
    printf("[Armoring] Testing CRC-24 Error Detection on Single-Bit Corruption... ");

    uint8_t original[64];
    assert(cv_entropy_get(original, sizeof(original)) == 0);

    char armored[1024];
    assert(cv_armor_encode(CV_ARMOR_KEY, original, sizeof(original), armored, sizeof(armored)) == 0);

    /* Locate payload base64 and flip a single character */
    char *body_pos = strstr(armored, "\n\n");
    assert(body_pos != NULL);
    body_pos += 2;
    *body_pos = (*body_pos == 'A') ? 'B' : 'A';

    uint8_t decoded[64];
    size_t dec_len = sizeof(decoded);
    cv_armor_type_t type;
    int ret = cv_armor_decode(armored, &type, decoded, &dec_len);
    assert(ret != 0); /* CRC failure must be caught */

    printf("PASSED\n");
}

static void test_truncated_armor(void) {
    printf("[Armoring] Testing Truncated and Malformed Armored Envelopes... ");

    const char *malformed_headers[] = {
        "-----BEGIN INVALID HEADER-----\n\naaaa\n=1234\n-----END INVALID HEADER-----",
        "-----BEGIN CRYPTOVAULT KEY BLOCK-----\n\n",
        "-----BEGIN CRYPTOVAULT KEY BLOCK-----\n\naa\n-----END CRYPTOVAULT KEY BLOCK-----",
        ""
    };

    for (size_t i = 0; i < sizeof(malformed_headers)/sizeof(malformed_headers[0]); i++) {
        uint8_t decoded[64];
        size_t dec_len = sizeof(decoded);
        cv_armor_type_t type;
        assert(cv_armor_decode(malformed_headers[i], &type, decoded, &dec_len) != 0);
    }

    printf("PASSED\n");
}

static void test_large_payload_armoring(void) {
    printf("[Armoring] Testing Large Payload Multi-Line Armoring (4096 bytes)... ");

    size_t len = 4096;
    uint8_t *raw = (uint8_t *)malloc(len);
    assert(raw != NULL);
    assert(cv_entropy_get(raw, len) == 0);

    size_t armor_cap = len * 2 + 512;
    char *armored = (char *)malloc(armor_cap);
    assert(armored != NULL);

    assert(cv_armor_encode(CV_ARMOR_MESSAGE, raw, len, armored, armor_cap) == 0);

    uint8_t *decoded = (uint8_t *)malloc(len + 128);
    assert(decoded != NULL);
    size_t dec_len = len + 128;
    cv_armor_type_t type;

    assert(cv_armor_decode(armored, &type, decoded, &dec_len) == 0);
    assert(type == CV_ARMOR_MESSAGE);
    assert(dec_len == len);
    assert(cv_ct_memcmp(raw, decoded, len) == 0);

    free(raw);
    free(armored);
    free(decoded);

    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("        CryptoVault ASCII Armoring Test Suite       \n");
    printf("====================================================\n");
    test_armor_roundtrip();
    test_armor_all_types();
    test_crc24_corruption();
    test_truncated_armor();
    test_large_payload_armoring();
    printf("All ASCII Armoring Tests PASSED!\n\n");
    return 0;
}
