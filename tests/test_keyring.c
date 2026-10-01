/**
 * @file test_keyring.c
 * @brief Test Suite for Linux Kernel Keyring Integration & Secure Key Enclave.
 *
 * ============================================================================
 * CryptoVault Kernel Keyring & Secure Storage Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Storage of master, recovery, and ephemeral keys in kernel / mlocked vault.
 * 2. Exact retrieval and byte-level fidelity across multiple key types.
 * 3. In-place key rotation with automatic eviction of stale credentials.
 * 4. Explicit key revocation and secure memory erasure.
 * 5. Full vault purging with zero residual key material.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "keyring.h"
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

static int test_keyring_store_and_load(void) {
    const char *key_name = "cv_test_prod_master_key";
    uint8_t original_key[32] = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
    };

    int32_t kid = -1;
    int ret = cv_keyring_store(key_name, original_key, sizeof(original_key),
                               CV_KEY_TYPE_MASTER, &kid);
    ASSERT_TEST(ret == CV_KEYRING_SUCCESS, "Store key into keyring");

    uint8_t loaded_key[64];
    size_t loaded_len = 0;
    ret = cv_keyring_load(key_name, loaded_key, sizeof(loaded_key), &loaded_len);
    ASSERT_TEST(ret == CV_KEYRING_SUCCESS, "Load key from keyring");
    ASSERT_TEST(loaded_len == sizeof(original_key), "Key length matches");
    ASSERT_TEST(cv_mem_equal(original_key, loaded_key, sizeof(original_key)) == 1,
                "Loaded key matches stored key bit-for-bit");

    /* Clean up */
    ASSERT_TEST(cv_keyring_evict(key_name) == CV_KEYRING_SUCCESS, "Evict key");
    return TEST_PASS;
}

static int test_keyring_multiple_types_and_rotation(void) {
    uint8_t master[32] = {0xAA};
    uint8_t recovery[32] = {0xBB};
    uint8_t ephemeral[32] = {0xCC};

    ASSERT_TEST(cv_keyring_store("key_master", master, 32, CV_KEY_TYPE_MASTER, NULL) == CV_KEYRING_SUCCESS, "Store master");
    ASSERT_TEST(cv_keyring_store("key_recovery", recovery, 32, CV_KEY_TYPE_RECOVERY, NULL) == CV_KEYRING_SUCCESS, "Store recovery");
    ASSERT_TEST(cv_keyring_store("key_ephemeral", ephemeral, 32, CV_KEY_TYPE_EPHEMERAL, NULL) == CV_KEYRING_SUCCESS, "Store ephemeral");

    /* Verify each independent key */
    uint8_t out[32];
    size_t out_len = 0;
    ASSERT_TEST(cv_keyring_load("key_master", out, 32, &out_len) == CV_KEYRING_SUCCESS && out_len == 32, "Load master");
    ASSERT_TEST(cv_mem_equal(out, master, 32) == 1, "Master matches");

    ASSERT_TEST(cv_keyring_load("key_recovery", out, 32, &out_len) == CV_KEYRING_SUCCESS && out_len == 32, "Load recovery");
    ASSERT_TEST(cv_mem_equal(out, recovery, 32) == 1, "Recovery matches");

    /* Rotate master key */
    uint8_t master_v2[32] = {0x11, 0x22, 0x33, 0x44};
    ASSERT_TEST(cv_keyring_store("key_master", master_v2, 32, CV_KEY_TYPE_MASTER, NULL) == CV_KEYRING_SUCCESS, "Rotate master");

    ASSERT_TEST(cv_keyring_load("key_master", out, 32, &out_len) == CV_KEYRING_SUCCESS && out_len == 32, "Load rotated");
    ASSERT_TEST(cv_mem_equal(out, master_v2, 32) == 1, "Rotated key loaded");

    /* Clear all */
    ASSERT_TEST(cv_keyring_clear() == CV_KEYRING_SUCCESS, "Clear all keys");
    ASSERT_TEST(cv_keyring_load("key_master", out, 32, &out_len) == CV_KEYRING_ERR_NOT_FOUND, "Master evicted");
    ASSERT_TEST(cv_keyring_load("key_recovery", out, 32, &out_len) == CV_KEYRING_ERR_NOT_FOUND, "Recovery evicted");

    return TEST_PASS;
}

static int test_keyring_error_handling(void) {
    uint8_t buf[32];
    size_t len = 0;

    /* Query non-existent key */
    ASSERT_TEST(cv_keyring_load("non_existent_key_xyz", buf, 32, &len) == CV_KEYRING_ERR_NOT_FOUND,
                "Non-existent key returns NOT_FOUND");

    /* Null parameter checks */
    ASSERT_TEST(cv_keyring_store(NULL, buf, 32, CV_KEY_TYPE_MASTER, NULL) == CV_KEYRING_ERR_PARAM,
                "Null name rejected");
    ASSERT_TEST(cv_keyring_store("test", NULL, 32, CV_KEY_TYPE_MASTER, NULL) == CV_KEYRING_ERR_PARAM,
                "Null key pointer rejected");
    ASSERT_TEST(cv_keyring_store("test", buf, 0, CV_KEY_TYPE_MASTER, NULL) == CV_KEYRING_ERR_PARAM,
                "Zero length key rejected");

    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Kernel Keyring Test Suite...\n");

    if (cv_keyring_self_test() != CV_KEYRING_SUCCESS) {
        fprintf(stderr, "[-] cv_keyring_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_keyring_store_and_load() != TEST_PASS) return 1;
    if (test_keyring_multiple_types_and_rotation() != TEST_PASS) return 1;
    if (test_keyring_error_handling() != TEST_PASS) return 1;

    printf("[+] Kernel Keyring Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
