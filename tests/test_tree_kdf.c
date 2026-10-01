/**
 * @file test_tree_kdf.c
 * @brief Test Suite for Hierarchical Key Tree KDF, Ratcheting & Temporal Expiration.
 *
 * ============================================================================
 * CryptoVault Hierarchical Tree KDF Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Root -> Application -> File -> Epoch -> Chunk key isolation hierarchy.
 * 2. Strict orthogonal subkey separation across roles (Encryption, Authentication, Metadata, Header).
 * 3. Automatic epoch ratcheting and forward secrecy upon byte threshold.
 * 4. Temporal expiration enforcement against stale or expired keys.
 * 5. Deterministic derivation across independent instances with identical context.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "tree_kdf.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASS 0
#define TEST_FAIL 1

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define ASSERT_TEST(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "[-] FAILURE at %s:%d: %s\n", __FILE__, __LINE__, msg); \
        return TEST_FAIL; \
    } else { \
        g_tests_passed++; \
    } \
} while (0)

static int test_tree_kdf_hierarchy_and_determinism(void) {
    uint8_t master_key[CV_TREE_KEY_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    const char *app_id = "CryptoVault.SecureStorage";
    const char *file_id = "UUID-TEST-9876-54321";

    cv_key_tree_ctx_t ctx1, ctx2;
    ASSERT_TEST(cv_tree_kdf_init(&ctx1, master_key, app_id, file_id, 3600, 1024 * 1024) == CV_TREE_SUCCESS, "Init KDF 1");
    ASSERT_TEST(cv_tree_kdf_init(&ctx2, master_key, app_id, file_id, 3600, 1024 * 1024) == CV_TREE_SUCCESS, "Init KDF 2");

    /* Determinism check: Same inputs must yield identical subkeys */
    uint8_t enc1[32], enc2[32];
    uint8_t mac1[32], mac2[32];
    uint8_t meta1[32];

    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx1, 0, CV_KEY_ROLE_ENCRYPTION, 0, enc1) == CV_TREE_SUCCESS, "Derive enc1");
    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx2, 0, CV_KEY_ROLE_ENCRYPTION, 0, enc2) == CV_TREE_SUCCESS, "Derive enc2");
    ASSERT_TEST(cv_mem_equal(enc1, enc2, 32) == 1, "k_enc matches deterministically");

    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx1, 0, CV_KEY_ROLE_AUTHENTICATION, 0, mac1) == CV_TREE_SUCCESS, "Derive mac1");
    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx2, 0, CV_KEY_ROLE_AUTHENTICATION, 0, mac2) == CV_TREE_SUCCESS, "Derive mac2");
    ASSERT_TEST(cv_mem_equal(mac1, mac2, 32) == 1, "k_mac matches deterministically");

    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx1, 0, CV_KEY_ROLE_METADATA, 0, meta1) == CV_TREE_SUCCESS, "Derive meta1");

    /* Subkey separation: Roles within the same chunk must be mutually orthogonal */
    ASSERT_TEST(cv_mem_equal(enc1, mac1, 32) == 0, "enc != mac");
    ASSERT_TEST(cv_mem_equal(enc1, meta1, 32) == 0, "enc != meta");
    ASSERT_TEST(cv_mem_equal(mac1, meta1, 32) == 0, "mac != meta");

    cv_tree_kdf_clear(&ctx1);
    cv_tree_kdf_clear(&ctx2);
    return TEST_PASS;
}

static int test_tree_kdf_per_chunk_isolation(void) {
    uint8_t master[CV_TREE_KEY_SIZE];
    memset(master, 0x77, sizeof(master));

    cv_key_tree_ctx_t ctx;
    ASSERT_TEST(cv_tree_kdf_init(&ctx, master, "TestApp", "TestFile", 0, 0) == CV_TREE_SUCCESS, "Init");

    /* Derive encryption keys for 10 sequential chunks and ensure no collisions */
    uint8_t chunk_keys[10][32];
    for (uint64_t i = 0; i < 10; i++) {
        ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx, i, CV_KEY_ROLE_ENCRYPTION, 0, chunk_keys[i]) == CV_TREE_SUCCESS,
                    "Derive chunk key");
    }

    for (size_t i = 0; i < 10; i++) {
        for (size_t j = i + 1; j < 10; j++) {
            ASSERT_TEST(cv_mem_equal(chunk_keys[i], chunk_keys[j], 32) == 0,
                        "Different chunks must have distinct keys");
        }
    }

    cv_tree_kdf_clear(&ctx);
    return TEST_PASS;
}

static int test_tree_kdf_ratcheting(void) {
    uint8_t master[CV_TREE_KEY_SIZE];
    memset(master, 0x55, sizeof(master));

    cv_key_tree_ctx_t ctx;
    ASSERT_TEST(cv_tree_kdf_init(&ctx, master, "App", "File", 3600, 1024) == CV_TREE_SUCCESS, "Init");

    uint8_t epoch0_key[32], epoch1_key[32];
    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, 0, epoch0_key) == CV_TREE_SUCCESS, "Derive epoch 0");

    /* Advance epoch */
    ASSERT_TEST(cv_tree_rotate_epoch(&ctx) == CV_TREE_SUCCESS, "Rotate epoch");
    ASSERT_TEST(ctx.current_epoch == 1, "Epoch index incremented to 1");

    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, 0, epoch1_key) == CV_TREE_SUCCESS, "Derive epoch 1");

    /* Subkeys for chunk 0 in epoch 1 must differ completely from epoch 0 */
    ASSERT_TEST(cv_mem_equal(epoch0_key, epoch1_key, 32) == 0,
                "Ratcheted epoch changes derived chunk keys");

    cv_tree_kdf_clear(&ctx);
    return TEST_PASS;
}

static int test_tree_kdf_expiration(void) {
    uint8_t master[CV_TREE_KEY_SIZE] = {0xAA};

    cv_key_tree_ctx_t ctx;
    /* Initialize with 10 second lifetime */
    ASSERT_TEST(cv_tree_kdf_init(&ctx, master, "App", "File", 10, 0) == CV_TREE_SUCCESS, "Init with lifetime");

    uint8_t out[32];
    /* Check at valid timestamp: not expired */
    uint64_t valid_time = ctx.valid_from + 5;
    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, valid_time, out) == CV_TREE_SUCCESS,
                "Key valid within expiration window");

    /* Check beyond lifetime: expired */
    uint64_t expired_time = ctx.valid_from + 20;
    ASSERT_TEST(cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, expired_time, out) == CV_TREE_ERR_EXPIRED,
                "Expired key returns CV_TREE_ERR_EXPIRED");

    cv_tree_kdf_clear(&ctx);
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Hierarchical Key Tree KDF Test Suite...\n");

    if (cv_tree_kdf_self_test() != CV_TREE_SUCCESS) {
        fprintf(stderr, "[-] cv_tree_kdf_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_tree_kdf_hierarchy_and_determinism() != TEST_PASS) return 1;
    if (test_tree_kdf_per_chunk_isolation() != TEST_PASS) return 1;
    if (test_tree_kdf_ratcheting() != TEST_PASS) return 1;
    if (test_tree_kdf_expiration() != TEST_PASS) return 1;

    printf("[+] Hierarchical Key Tree KDF Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
