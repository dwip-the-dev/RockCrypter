#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_shamir_3_of_5(void) {
    printf("[Shamir] Testing 3-of-5 Threshold Secret Sharing... ");

    uint8_t secret[32];
    assert(cv_entropy_get(secret, 32) == 0);

    cv_share_t shares[5];
    assert(cv_shamir_split(secret, 3, 5, shares) == 0);

    /* Test 1: Reconstruct using shares {0, 1, 2} */
    cv_share_t subset1[3] = { shares[0], shares[1], shares[2] };
    uint8_t recovered1[32];
    assert(cv_shamir_combine(subset1, 3, recovered1) == 0);
    assert(cv_ct_memcmp(secret, recovered1, 32) == 0);

    /* Test 2: Reconstruct using shares {1, 3, 4} */
    cv_share_t subset2[3] = { shares[1], shares[3], shares[4] };
    uint8_t recovered2[32];
    assert(cv_shamir_combine(subset2, 3, recovered2) == 0);
    assert(cv_ct_memcmp(secret, recovered2, 32) == 0);

    /* Test 3: Reconstruct using shares {0, 2, 4} */
    cv_share_t subset3[3] = { shares[0], shares[2], shares[4] };
    uint8_t recovered3[32];
    assert(cv_shamir_combine(subset3, 3, recovered3) == 0);
    assert(cv_ct_memcmp(secret, recovered3, 32) == 0);

    printf("PASSED (All 3-share subsets successfully reconstructed secret)\n");
}

static void test_shamir_string_serialization(void) {
    printf("[Shamir] Testing Human-Readable Share Serialization with CRC32... ");

    uint8_t secret[32];
    assert(cv_entropy_get(secret, 32) == 0);

    cv_share_t shares[3];
    assert(cv_shamir_split(secret, 2, 3, shares) == 0);

    char share_str[128];
    assert(cv_shamir_share_to_string(&shares[0], share_str, sizeof(share_str)) == 0);

    cv_share_t parsed;
    assert(cv_shamir_share_from_string(share_str, &parsed) == 0);
    assert(parsed.id == shares[0].id);
    assert(cv_ct_memcmp(parsed.data, shares[0].data, 32) == 0);

    /* Tamper with string: change one hex char */
    share_str[20] = (share_str[20] == 'a') ? 'b' : 'a';
    assert(cv_shamir_share_from_string(share_str, &parsed) != 0);

    printf("PASSED\n");
}

static void test_shamir_duplicate_coordinates(void) {
    printf("[Shamir] Testing Duplicate Share Coordinate Rejection... ");

    uint8_t secret[32];
    assert(cv_entropy_get(secret, 32) == 0);

    cv_share_t shares[4];
    assert(cv_shamir_split(secret, 3, 4, shares) == 0);

    /* Construct subset with duplicate share {shares[0], shares[0], shares[1]} */
    cv_share_t dupes[3];
    dupes[0] = shares[0];
    dupes[1] = shares[0];
    dupes[2] = shares[1];

    uint8_t recovered[32];
    /* Combining duplicate coordinates must be rejected */
    assert(cv_shamir_combine(dupes, 3, recovered) != 0);

    printf("PASSED\n");
}

static void test_shamir_high_threshold(void) {
    printf("[Shamir] Testing 5-of-8 High Threshold Multi-Party Quorum... ");

    uint8_t master_key[32];
    assert(cv_entropy_get(master_key, 32) == 0);

    cv_share_t shares[8];
    assert(cv_shamir_split(master_key, 5, 8, shares) == 0);

    /* Pick 5 distinct shares {1, 3, 4, 6, 7} */
    cv_share_t quorum[5];
    quorum[0] = shares[1];
    quorum[1] = shares[3];
    quorum[2] = shares[4];
    quorum[3] = shares[6];
    quorum[4] = shares[7];

    uint8_t recovered[32];
    assert(cv_shamir_combine(quorum, 5, recovered) == 0);
    assert(cv_ct_memcmp(master_key, recovered, 32) == 0);

    printf("PASSED\n");
}

static void test_shamir_boundary_checks(void) {
    printf("[Shamir] Testing Boundary Parameter Validations... ");

    uint8_t secret[32];
    memset(secret, 0x55, 32);
    cv_share_t shares[5];

    /* k < 2 must be rejected */
    assert(cv_shamir_split(secret, 1, 5, shares) != 0);

    /* k > n must be rejected */
    assert(cv_shamir_split(secret, 6, 5, shares) != 0);

    /* NULL pointers must be rejected */
    assert(cv_shamir_split(NULL, 3, 5, shares) != 0);
    assert(cv_shamir_split(secret, 3, 5, NULL) != 0);

    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("   CryptoVault Shamir's Secret Sharing Test Suite   \n");
    printf("====================================================\n");
    test_shamir_3_of_5();
    test_shamir_string_serialization();
    test_shamir_duplicate_coordinates();
    test_shamir_high_threshold();
    test_shamir_boundary_checks();
    printf("All Shamir Secret Sharing Tests PASSED!\n\n");
    return 0;
}
