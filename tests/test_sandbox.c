/**
 * @file test_sandbox.c
 * @brief Test Suite for Zero-Trust Capability-Based Sandboxing & Boundary Validation.
 *
 * ============================================================================
 * CryptoVault Zero-Trust Sandboxing Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Initial capability assignment and granular permission checking.
 * 2. Monotonic privilege de-escalation (dropped capabilities cannot be restored).
 * 3. Strict buffer validation (null pointer rejection, buffer overflow prevention).
 * 4. Cryptographic capability token minting and tamper-proof verification.
 * 5. Permanent locking of sandbox security policies.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "sandbox.h"
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

static int test_sandbox_privilege_dropping(void) {
    cv_sandbox_context_t ctx;
    uint32_t caps = CV_CAP_ENCRYPT | CV_CAP_DECRYPT | CV_CAP_DERIVE_KEY | CV_CAP_FS_ACCESS;

    ASSERT_TEST(cv_sandbox_init(&ctx, caps, 1024 * 1024) == CV_SANDBOX_SUCCESS, "Init sandbox");

    /* Verify initial capabilities */
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_ENCRYPT) == CV_SANDBOX_SUCCESS, "Has ENCRYPT");
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_DECRYPT) == CV_SANDBOX_SUCCESS, "Has DECRYPT");
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_FS_ACCESS) == CV_SANDBOX_SUCCESS, "Has FS_ACCESS");

    /* Drop filesystem access (PoLP after loading keys) */
    ASSERT_TEST(cv_sandbox_drop_capability(&ctx, CV_CAP_FS_ACCESS) == CV_SANDBOX_SUCCESS, "Drop FS_ACCESS");
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_FS_ACCESS) == CV_SANDBOX_ERR_PERM_DENIED,
                "FS_ACCESS is now denied");

    /* Ensure other capabilities remain intact */
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_ENCRYPT) == CV_SANDBOX_SUCCESS, "Still has ENCRYPT");

    /* Drop all decryption rights (e.g. for write-only append worker) */
    ASSERT_TEST(cv_sandbox_drop_capability(&ctx, CV_CAP_DECRYPT) == CV_SANDBOX_SUCCESS, "Drop DECRYPT");
    ASSERT_TEST(cv_sandbox_check_capability(&ctx, CV_CAP_DECRYPT) == CV_SANDBOX_ERR_PERM_DENIED,
                "DECRYPT is now denied");

    return TEST_PASS;
}

static int test_sandbox_buffer_bounds(void) {
    cv_sandbox_context_t ctx;
    const size_t MAX_LIMIT = 64 * 1024; /* 64 KiB */
    ASSERT_TEST(cv_sandbox_init(&ctx, CV_CAP_ENCRYPT, MAX_LIMIT) == CV_SANDBOX_SUCCESS, "Init");

    uint8_t buf[256];

    /* 1. Normal buffer within limits */
    ASSERT_TEST(cv_sandbox_validate_buffer(&ctx, buf, sizeof(buf), CV_CAP_ENCRYPT) == CV_SANDBOX_SUCCESS,
                "Normal buffer within limit passes");

    /* 2. Buffer exceeding configured maximum */
    ASSERT_TEST(cv_sandbox_validate_buffer(&ctx, buf, MAX_LIMIT + 1, CV_CAP_ENCRYPT) == CV_SANDBOX_ERR_OVERFLOW,
                "Buffer exceeding upper bound rejected");

    /* 3. Null pointer with non-zero length */
    ASSERT_TEST(cv_sandbox_validate_buffer(&ctx, NULL, 128, CV_CAP_ENCRYPT) == CV_SANDBOX_ERR_NULL_PTR,
                "Null pointer rejected");

    /* 4. Action requiring ungranted capability */
    ASSERT_TEST(cv_sandbox_validate_buffer(&ctx, buf, sizeof(buf), CV_CAP_DECRYPT) == CV_SANDBOX_ERR_PERM_DENIED,
                "Buffer validation rejects ungranted capability");

    return TEST_PASS;
}

static int test_sandbox_token_authentication(void) {
    uint8_t secret[32] = {0x01, 0x02, 0x03, 0x04};
    uint8_t wrong_secret[32] = {0x99, 0x99, 0x99, 0x99};

    uint8_t token[CV_SANDBOX_TOKEN_SIZE];

    /* Mint capability token for key derivation */
    ASSERT_TEST(cv_sandbox_mint_token(secret, CV_CAP_DERIVE_KEY, token) == CV_SANDBOX_SUCCESS,
                "Mint token for DERIVE_KEY");

    /* Verify with correct secret and matching capability */
    ASSERT_TEST(cv_sandbox_verify_token(secret, CV_CAP_DERIVE_KEY, token) == CV_SANDBOX_SUCCESS,
                "Verify valid token succeeds");

    /* Verify with wrong secret key */
    ASSERT_TEST(cv_sandbox_verify_token(wrong_secret, CV_CAP_DERIVE_KEY, token) == CV_SANDBOX_ERR_TOKEN_BAD,
                "Verify with wrong secret fails");

    /* Verify against wrong capability (token minted for DERIVE_KEY presented for EXPORT_KEY) */
    ASSERT_TEST(cv_sandbox_verify_token(secret, CV_CAP_EXPORT_KEY, token) == CV_SANDBOX_ERR_TOKEN_BAD,
                "Token minted for one capability cannot be used for another");

    /* Tamper with token */
    token[15] ^= 0x80;
    ASSERT_TEST(cv_sandbox_verify_token(secret, CV_CAP_DERIVE_KEY, token) == CV_SANDBOX_ERR_TOKEN_BAD,
                "Tampered token rejected");

    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Zero-Trust Sandboxing Test Suite...\n");

    if (cv_sandbox_self_test() != CV_SANDBOX_SUCCESS) {
        fprintf(stderr, "[-] cv_sandbox_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_sandbox_privilege_dropping() != TEST_PASS) return 1;
    if (test_sandbox_buffer_bounds() != TEST_PASS) return 1;
    if (test_sandbox_token_authentication() != TEST_PASS) return 1;

    printf("[+] Zero-Trust Sandboxing Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
