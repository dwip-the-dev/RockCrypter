/**
 * @file test_manifest.c
 * @brief Test Suite for Cryptographic Manifest (.cvman) Signing & Metadata Integrity.
 *
 * ============================================================================
 * CryptoVault Cryptographic Manifest Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Cryptographic manifest creation binding filename, MIME, POSIX mode, and Merkle root.
 * 2. Authenticated signing and signature verification with publisher signing keys.
 * 3. Immediate detection and rejection of metadata tampering (file size, permissions, name).
 * 4. Rejection of corrupted Merkle root hash or invalid signature tags.
 * 5. Binary serialization and file persistence fidelity via cv_manifest_save and load.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "manifest.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static int test_manifest_sign_and_verify(void) {
    const char *test_path = "/tmp/cv_test_manifest_source.bin";
    FILE *f = fopen(test_path, "wb");
    ASSERT_TEST(f != NULL, "Create test file");
    fputs("TOP_SECRET_CLASSIFIED_MANIFEST_PAYLOAD_TEST", f);
    fclose(f);

    uint8_t pubkey[32] = {0x11, 0x22, 0x33, 0x44};
    uint8_t privkey[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t wrong_pubkey[32] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t merkle_root[32] = {0x5A, 0x5A, 0x5A, 0x5A};

    cv_manifest_t manifest;
    int ret = cv_manifest_create(&manifest, test_path, "document.pdf", "application/pdf",
                                 pubkey, privkey, merkle_root, 1);
    ASSERT_TEST(ret == CV_MAN_SUCCESS, "Manifest creation succeeds");

    /* Verify with authentic publisher public key */
    ret = cv_manifest_verify(&manifest, pubkey);
    ASSERT_TEST(ret == CV_MAN_SUCCESS, "Verification with authentic public key succeeds");

    /* Verify with wrong public key */
    ret = cv_manifest_verify(&manifest, wrong_pubkey);
    ASSERT_TEST(ret == CV_MAN_ERR_AUTH, "Verification with wrong public key fails");

    unlink(test_path);
    return TEST_PASS;
}

static int test_manifest_metadata_tampering(void) {
    const char *test_path = "/tmp/cv_test_manifest_tamper.bin";
    FILE *f = fopen(test_path, "wb");
    ASSERT_TEST(f != NULL, "Create test file");
    fputs("AUDIT_REPORT_CONTENT_FOR_TAMPER_TEST", f);
    fclose(f);

    uint8_t pubkey[32] = {0x01, 0x02, 0x03, 0x04};
    uint8_t privkey[32] = {0x09, 0x08, 0x07, 0x06};
    uint8_t merkle_root[32] = {0xEE, 0xEE, 0xEE, 0xEE};

    cv_manifest_t manifest;
    ASSERT_TEST(cv_manifest_create(&manifest, test_path, "audit.bin", "application/octet-stream",
                                   pubkey, privkey, merkle_root, 1) == CV_MAN_SUCCESS,
                "Create manifest");

    /* 1. Tamper with file size */
    cv_manifest_t tampered_size = manifest;
    tampered_size.file_size_bytes += 1;
    ASSERT_TEST(cv_manifest_verify(&tampered_size, pubkey) == CV_MAN_ERR_AUTH,
                "Tampered file size rejected");

    /* 2. Tamper with POSIX permissions */
    cv_manifest_t tampered_mode = manifest;
    tampered_mode.posix_mode = 0777;
    ASSERT_TEST(cv_manifest_verify(&tampered_mode, pubkey) == CV_MAN_ERR_AUTH,
                "Tampered POSIX mode rejected");

    /* 3. Tamper with filename */
    cv_manifest_t tampered_name = manifest;
    tampered_name.orig_filename[0] ^= 'X';
    ASSERT_TEST(cv_manifest_verify(&tampered_name, pubkey) == CV_MAN_ERR_AUTH,
                "Tampered filename rejected");

    /* 4. Tamper with Merkle root */
    cv_manifest_t tampered_root = manifest;
    tampered_root.merkle_root[0] ^= 0x01;
    ASSERT_TEST(cv_manifest_verify(&tampered_root, pubkey) == CV_MAN_ERR_AUTH,
                "Tampered Merkle root rejected");

    unlink(test_path);
    return TEST_PASS;
}

static int test_manifest_file_io(void) {
    const char *test_path = "/tmp/cv_test_manifest_io.bin";
    const char *manifest_file = "/tmp/cv_test_saved.cvman";
    unlink(manifest_file);

    FILE *f = fopen(test_path, "wb");
    ASSERT_TEST(f != NULL, "Create test file");
    fputs("FIRMWARE_BINARY_IMAGE_DATA_V2", f);
    fclose(f);

    uint8_t pubkey[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t privkey[32] = {0x12, 0x34, 0x56, 0x78};
    uint8_t merkle_root[32] = {0x99, 0x88, 0x77, 0x66};

    cv_manifest_t orig;
    ASSERT_TEST(cv_manifest_create(&orig, test_path, "firmware.img", "application/x-binary",
                                   pubkey, privkey, merkle_root, 1) == CV_MAN_SUCCESS,
                "Create manifest");

    /* Save to disk */
    ASSERT_TEST(cv_manifest_save(manifest_file, &orig) == CV_MAN_SUCCESS, "Save manifest to disk");

    /* Load from disk */
    cv_manifest_t loaded;
    ASSERT_TEST(cv_manifest_load(manifest_file, &loaded) == CV_MAN_SUCCESS, "Load manifest from disk");

    /* Verify loaded manifest passes authenticity verification */
    ASSERT_TEST(cv_manifest_verify(&loaded, pubkey) == CV_MAN_SUCCESS, "Loaded manifest verifies");

    /* Verify fields match */
    ASSERT_TEST(strcmp(orig.orig_filename, loaded.orig_filename) == 0, "Filename matches");
    ASSERT_TEST(orig.file_size_bytes == loaded.file_size_bytes, "Size matches");
    ASSERT_TEST(cv_mem_equal(orig.merkle_root, loaded.merkle_root, 32) == 1, "Merkle root matches");

    unlink(test_path);
    unlink(manifest_file);
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Cryptographic Manifest Test Suite...\n");

    if (cv_manifest_self_test() != CV_MAN_SUCCESS) {
        fprintf(stderr, "[-] cv_manifest_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_manifest_sign_and_verify() != TEST_PASS) return 1;
    if (test_manifest_metadata_tampering() != TEST_PASS) return 1;
    if (test_manifest_file_io() != TEST_PASS) return 1;

    printf("[+] Cryptographic Manifest Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
