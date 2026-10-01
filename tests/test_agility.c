/**
 * @file test_agility.c
 * @brief Test Suite for Algorithm Agility, Cipher Suite Registry & Anti-Downgrade Defense.
 *
 * ============================================================================
 * CryptoVault Algorithm Agility Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Cipher suite registry enumeration and descriptor retrieval.
 * 2. Default suite assignment and security parameter verification (256-bit classical).
 * 3. Post-quantum capability flag detection on hybrid suites.
 * 4. Anti-downgrade enforcement when minimum security bit threshold is violated.
 * 5. Rejection of unknown or invalid cipher suite identifiers.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "agility.h"
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

static int test_agility_registry_enumeration(void) {
    size_t count = cv_agility_get_suite_count();
    ASSERT_TEST(count >= 3, "Registry must contain at least 3 cipher suites");

    bool found_default = false;
    for (size_t i = 0; i < count; i++) {
        cv_cipher_suite_desc_t desc;
        int ret = cv_agility_get_at_index(i, &desc);
        ASSERT_TEST(ret == CV_AGILITY_SUCCESS, "Get suite at index");
        ASSERT_TEST(desc.security_bits >= 256, "All suites must provide at least 256-bit security");
        ASSERT_TEST(desc.name != NULL && strlen(desc.name) > 0, "Suite has valid name");

        if (desc.is_default) {
            found_default = true;
            ASSERT_TEST(desc.suite_id == CV_SUITE_SPARX256_SPONGE, "Default suite is SP-ARX-256");
        }
    }

    ASSERT_TEST(found_default == true, "Exactly one default suite exists in registry");
    return TEST_PASS;
}

static int test_agility_pqc_capability(void) {
    cv_cipher_suite_desc_t pq_desc;
    int ret = cv_agility_get_descriptor(CV_SUITE_HYBRID_PQC_SPARX, &pq_desc);
    ASSERT_TEST(ret == CV_AGILITY_SUCCESS, "Retrieve hybrid PQC suite descriptor");
    ASSERT_TEST(pq_desc.pq_security_bits >= 128, "PQC security level >= 128 bits");

    /* Capability checks */
    int has_pqc = cv_agility_has_capability(CV_SUITE_HYBRID_PQC_SPARX, CV_SUITE_CAP_PQC);
    ASSERT_TEST(has_pqc == 1, "Hybrid suite must have CV_SUITE_CAP_PQC flag");

    int default_has_pqc = cv_agility_has_capability(CV_SUITE_SPARX256_SPONGE, CV_SUITE_CAP_PQC);
    ASSERT_TEST(default_has_pqc == 0, "Classical suite does NOT have PQC capability flag");

    return TEST_PASS;
}

static int test_agility_anti_downgrade(void) {
    /* Validating standard 256-bit suite with 256-bit threshold: MUST PASS */
    int ret = cv_agility_validate_suite(CV_SUITE_SPARX256_SPONGE, 256);
    ASSERT_TEST(ret == CV_AGILITY_SUCCESS, "Valid suite meets 256-bit requirement");

    /* Validating 256-bit suite with unattainable 512-bit threshold: MUST REJECT */
    ret = cv_agility_validate_suite(CV_SUITE_SPARX256_SPONGE, 512);
    ASSERT_TEST(ret == CV_AGILITY_ERR_INSECURE, "Suite below required threshold rejected");

    /* Validating non-existent suite ID: MUST RETURN UNKNOWN */
    ret = cv_agility_validate_suite(0xCAFE, 128);
    ASSERT_TEST(ret == CV_AGILITY_ERR_UNKNOWN, "Unknown suite ID rejected with CV_AGILITY_ERR_UNKNOWN");

    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Algorithm Agility Test Suite...\n");

    if (cv_agility_self_test() != CV_AGILITY_SUCCESS) {
        fprintf(stderr, "[-] cv_agility_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_agility_registry_enumeration() != TEST_PASS) return 1;
    if (test_agility_pqc_capability() != TEST_PASS) return 1;
    if (test_agility_anti_downgrade() != TEST_PASS) return 1;

    printf("[+] Algorithm Agility Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
