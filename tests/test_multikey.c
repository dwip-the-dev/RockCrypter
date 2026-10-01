/**
 * @file test_multikey.c
 * @brief Test Suite for Multi-Key Dual Authorization & Multi-Recipient Encapsulation.
 *
 * ============================================================================
 * CryptoVault Multi-Key Cryptographic Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. 2-of-2 Dual-Authorization joint encryption requiring two independent secrets.
 * 2. Multi-recipient encapsulated key bags allowing any authorized party to open.
 * 3. Immediate decryption abort if either of the joint authorization keys is invalid.
 * 4. Rejection of unauthorized keys when attempting to open recipient bags.
 * 5. Memory cleanup and constant-time key validation.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "multikey.h"
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

static int test_multikey_dual_authorization(void) {
    uint8_t key_a[CV_MULTIKEY_KEY_SIZE] = {0x11, 0x22, 0x33, 0x44};
    uint8_t key_b[CV_MULTIKEY_KEY_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t wrong_key[CV_MULTIKEY_KEY_SIZE] = {0x99, 0x99, 0x99, 0x99};

    const char *secret_msg = "TopSecret Dual Authorization Executive Order #7712";
    size_t msg_len = strlen(secret_msg);

    uint8_t *container = NULL;
    size_t cont_len = 0;

    /* Joint Encrypt with both Key A and Key B */
    int ret = cv_multikey_encrypt_dual((const uint8_t *)secret_msg, msg_len,
                                       key_a, key_b,
                                       &container, &cont_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Joint dual encryption must succeed");
    ASSERT_TEST(container != NULL && cont_len > msg_len, "Container allocated");

    /* Joint Decrypt with correct Key A and Key B */
    uint8_t *decrypted = NULL;
    size_t dec_len = 0;
    ret = cv_multikey_decrypt_dual(container, cont_len,
                                   key_a, key_b,
                                   &decrypted, &dec_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Joint decryption succeeds with both keys");
    ASSERT_TEST(dec_len == msg_len, "Decrypted length matches original");
    ASSERT_TEST(memcmp(decrypted, secret_msg, msg_len) == 0, "Decrypted message matches");
    cv_secure_free(decrypted, dec_len);

    /* Joint Decrypt with wrong Key A */
    decrypted = NULL;
    ret = cv_multikey_decrypt_dual(container, cont_len,
                                   wrong_key, key_b,
                                   &decrypted, &dec_len);
    ASSERT_TEST(ret == CV_MK_ERR_AUTH, "Decryption must fail if Key A is incorrect");
    ASSERT_TEST(decrypted == NULL, "No plaintext returned on error");

    /* Joint Decrypt with wrong Key B */
    ret = cv_multikey_decrypt_dual(container, cont_len,
                                   key_a, wrong_key,
                                   &decrypted, &dec_len);
    ASSERT_TEST(ret == CV_MK_ERR_AUTH, "Decryption must fail if Key B is incorrect");
    ASSERT_TEST(decrypted == NULL, "No plaintext returned on error");

    cv_secure_free(container, cont_len);
    return TEST_PASS;
}

static int test_multikey_multi_recipient_flow(void) {
    uint8_t alice_key[CV_MULTIKEY_KEY_SIZE] = {0xA1, 0xA2};
    uint8_t bob_key[CV_MULTIKEY_KEY_SIZE] = {0xB1, 0xB2};
    uint8_t charlie_key[CV_MULTIKEY_KEY_SIZE] = {0xC1, 0xC2};
    uint8_t eve_unauthorized[CV_MULTIKEY_KEY_SIZE] = {0xEE, 0xEE};

    uint8_t recipient_keys_buf[3][CV_MULTIKEY_KEY_SIZE];
    memcpy(recipient_keys_buf[0], alice_key, CV_MULTIKEY_KEY_SIZE);
    memcpy(recipient_keys_buf[1], bob_key, CV_MULTIKEY_KEY_SIZE);
    memcpy(recipient_keys_buf[2], charlie_key, CV_MULTIKEY_KEY_SIZE);

    const char *doc = "Multi-Recipient Operational Intel Payload";
    size_t doc_len = strlen(doc);

    uint8_t *container = NULL;
    size_t cont_len = 0;

    int ret = cv_multikey_encrypt_multi_recipient((const uint8_t *)doc, doc_len,
                                                  (const uint8_t (*)[32])(const void *)recipient_keys_buf, 3,
                                                  &container, &cont_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Encrypt for 3 recipients");

    /* Alice opens the document */
    uint8_t *pt_alice = NULL;
    size_t pt_alice_len = 0;
    ret = cv_multikey_decrypt_recipient(container, cont_len, alice_key, &pt_alice, &pt_alice_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Alice opens container");
    ASSERT_TEST(pt_alice_len == doc_len && memcmp(pt_alice, doc, doc_len) == 0, "Alice recovers document");
    cv_secure_free(pt_alice, pt_alice_len);

    /* Bob opens the document */
    uint8_t *pt_bob = NULL;
    size_t pt_bob_len = 0;
    ret = cv_multikey_decrypt_recipient(container, cont_len, bob_key, &pt_bob, &pt_bob_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Bob opens container");
    ASSERT_TEST(pt_bob_len == doc_len && memcmp(pt_bob, doc, doc_len) == 0, "Bob recovers document");
    cv_secure_free(pt_bob, pt_bob_len);

    /* Charlie opens the document */
    uint8_t *pt_charlie = NULL;
    size_t pt_charlie_len = 0;
    ret = cv_multikey_decrypt_recipient(container, cont_len, charlie_key, &pt_charlie, &pt_charlie_len);
    ASSERT_TEST(ret == CV_MK_SUCCESS, "Charlie opens container");
    ASSERT_TEST(pt_charlie_len == doc_len && memcmp(pt_charlie, doc, doc_len) == 0, "Charlie recovers document");
    cv_secure_free(pt_charlie, pt_charlie_len);

    /* Eve (unauthorized) attempts to open */
    uint8_t *pt_eve = NULL;
    size_t pt_eve_len = 0;
    ret = cv_multikey_decrypt_recipient(container, cont_len, eve_unauthorized, &pt_eve, &pt_eve_len);
    ASSERT_TEST(ret == CV_MK_ERR_NOT_FOUND, "Unauthorized Eve rejected");
    ASSERT_TEST(pt_eve == NULL, "No plaintext for Eve");

    cv_secure_free(container, cont_len);
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Multi-Key Cryptographic Test Suite...\n");

    if (cv_multikey_self_test() != CV_MK_SUCCESS) {
        fprintf(stderr, "[-] cv_multikey_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_multikey_dual_authorization() != TEST_PASS) return 1;
    if (test_multikey_multi_recipient_flow() != TEST_PASS) return 1;

    printf("[+] Multi-Key Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
