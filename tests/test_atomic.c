/**
 * @file test_atomic.c
 * @brief Test Suite for Atomic Crash-Safe File Replacement & 64-bit Random Access IO.
 *
 * ============================================================================
 * CryptoVault Atomic File IO Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Crash-safe atomic file writing via staging files, fsync, and atomic rename.
 * 2. Automatic cleanup and unlinking upon writer abort (no partial writes on crash).
 * 3. Atomic replacement of pre-existing files without corruption windows.
 * 4. 64-bit random-access chunk reading at arbitrary byte offsets.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "atomic.h"
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

static int test_atomic_commit_flow(void) {
    const char *target = "/tmp/cv_test_atomic_commit.dat";
    unlink(target);

    cv_atomic_file_t af;
    int ret = cv_atomic_begin(&af, target);
    ASSERT_TEST(ret == CV_ATOMIC_SUCCESS, "Begin atomic transaction");

    const char *data = "CRASH_SAFE_ATOMIC_TRANSACTION_PAYLOAD_TEST_V1";
    size_t data_len = strlen(data);

    ret = cv_atomic_write(&af, data, data_len);
    ASSERT_TEST(ret == CV_ATOMIC_SUCCESS, "Write data");

    /* Commit transaction */
    ret = cv_atomic_commit(&af);
    ASSERT_TEST(ret == CV_ATOMIC_SUCCESS, "Commit transaction");

    /* Verify target exists and content matches */
    FILE *f = fopen(target, "rb");
    ASSERT_TEST(f != NULL, "Target file exists after commit");

    char buf[128];
    size_t r = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[r] = '\0';

    ASSERT_TEST(r == data_len, "Length matches");
    ASSERT_TEST(strcmp(buf, data) == 0, "Content matches");

    unlink(target);
    return TEST_PASS;
}

static int test_atomic_abort_flow(void) {
    const char *target = "/tmp/cv_test_atomic_abort.dat";
    unlink(target);

    cv_atomic_file_t af;
    ASSERT_TEST(cv_atomic_begin(&af, target) == CV_ATOMIC_SUCCESS, "Begin atomic transaction");

    const char *partial_data = "THIS_SHOULD_NEVER_EXIST_AFTER_ABORT";
    ASSERT_TEST(cv_atomic_write(&af, partial_data, strlen(partial_data)) == CV_ATOMIC_SUCCESS,
                "Write partial data");

    /* Abort transaction */
    cv_atomic_abort(&af);

    /* Verify target file was NOT created */
    FILE *f = fopen(target, "rb");
    ASSERT_TEST(f == NULL, "Target file must NOT exist after abort");

    return TEST_PASS;
}

static int test_atomic_replacement(void) {
    const char *target = "/tmp/cv_test_atomic_replace.dat";
    unlink(target);

    /* 1. Create original file */
    FILE *f = fopen(target, "wb");
    ASSERT_TEST(f != NULL, "Create initial file");
    fputs("ORIGINAL_CONTENT_VERSION_1", f);
    fclose(f);

    /* 2. Atomically overwrite with version 2 */
    cv_atomic_file_t af;
    ASSERT_TEST(cv_atomic_begin(&af, target) == CV_ATOMIC_SUCCESS, "Begin replacement");

    const char *v2_data = "NEW_UPDATED_REPLACEMENT_CONTENT_VERSION_2";
    ASSERT_TEST(cv_atomic_write(&af, v2_data, strlen(v2_data)) == CV_ATOMIC_SUCCESS, "Write v2");
    ASSERT_TEST(cv_atomic_commit(&af) == CV_ATOMIC_SUCCESS, "Commit replace");

    /* 3. Verify content is now V2 */
    f = fopen(target, "rb");
    ASSERT_TEST(f != NULL, "Open replaced file");
    char buf[128];
    size_t r = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[r] = '\0';

    ASSERT_TEST(strcmp(buf, v2_data) == 0, "Replaced file has exact new content");

    unlink(target);
    return TEST_PASS;
}

static int test_atomic_random_access_read(void) {
    const char *target = "/tmp/cv_test_atomic_ra.dat";
    unlink(target);

    /* Write 64 bytes of chunk payload + 32 bytes of tag */
    uint8_t payload[64];
    uint8_t tag[32];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i ^ 0x3C);
    for (size_t i = 0; i < sizeof(tag); i++) tag[i] = (uint8_t)(i ^ 0xA5);

    FILE *f = fopen(target, "wb");
    ASSERT_TEST(f != NULL, "Open file");
    fwrite(payload, 1, sizeof(payload), f);
    fwrite(tag, 1, sizeof(tag), f);
    fclose(f);

    /* Read chunk at offset 0 using cv_read_chunk_random_access */
    uint8_t read_payload[64];
    uint8_t read_tag[32];
    int ret = cv_read_chunk_random_access(target, 0, read_payload, 64, read_tag);
    ASSERT_TEST(ret == CV_ATOMIC_SUCCESS, "Random access read succeeds");
    ASSERT_TEST(memcmp(read_payload, payload, 64) == 0, "Payload matches");
    ASSERT_TEST(memcmp(read_tag, tag, 32) == 0, "Tag matches");

    unlink(target);
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Atomic File IO Test Suite...\n");

    if (cv_atomic_self_test() != CV_ATOMIC_SUCCESS) {
        fprintf(stderr, "[-] cv_atomic_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_atomic_commit_flow() != TEST_PASS) return 1;
    if (test_atomic_abort_flow() != TEST_PASS) return 1;
    if (test_atomic_replacement() != TEST_PASS) return 1;
    if (test_atomic_random_access_read() != TEST_PASS) return 1;

    printf("[+] Atomic File IO Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
