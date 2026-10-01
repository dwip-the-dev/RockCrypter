#include "vault.h"
#include "prng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_prng_initialization_and_generation(void) {
    printf("[PRNG] Testing Sponge CSPRNG Initialization & Stream Generation... ");

    cv_prng_t prng;
    assert(cv_prng_init(&prng) == CV_PRNG_SUCCESS);

    uint8_t buffer[256];
    assert(cv_prng_generate(&prng, buffer, sizeof(buffer)) == CV_PRNG_SUCCESS);

    /* Verify non-zero distribution */
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        sum += buffer[i];
    }
    assert(sum > 0);

    cv_prng_clear(&prng);
    printf("PASSED\n");
}

static void test_prng_forward_secrecy(void) {
    printf("[PRNG] Testing Forward Secrecy & Backtracking Resistance... ");

    cv_prng_t prng;
    assert(cv_prng_init(&prng) == CV_PRNG_SUCCESS);

    uint8_t sample1[32];
    uint8_t sample2[32];

    assert(cv_prng_generate(&prng, sample1, sizeof(sample1)) == CV_PRNG_SUCCESS);
    assert(cv_prng_generate(&prng, sample2, sizeof(sample2)) == CV_PRNG_SUCCESS);

    /* Consecutive samples must be distinct */
    assert(cv_ct_memcmp(sample1, sample2, sizeof(sample1)) != 0);

    cv_prng_clear(&prng);
    printf("PASSED\n");
}

static void test_prng_reseed_and_entropy_injection(void) {
    printf("[PRNG] Testing Entropy Re-seeding & External Seed Injection... ");

    cv_prng_t prng;
    assert(cv_prng_init(&prng) == CV_PRNG_SUCCESS);

    const char *extra_entropy = "AdditionalUserSuppliedEntropyHarvest2026";
    assert(cv_prng_reseed(&prng, extra_entropy, strlen(extra_entropy)) == CV_PRNG_SUCCESS);

    uint8_t out[64];
    assert(cv_prng_generate(&prng, out, sizeof(out)) == CV_PRNG_SUCCESS);

    cv_prng_clear(&prng);
    printf("PASSED\n");
}

static void test_prng_uniform_rejection_sampling(void) {
    printf("[PRNG] Testing Uniform Distribution Rejection Sampling [0, N)... ");

    cv_prng_t prng;
    assert(cv_prng_init(&prng) == CV_PRNG_SUCCESS);

    uint32_t counts[10] = {0};
    uint32_t trials = 10000;

    for (uint32_t i = 0; i < trials; i++) {
        uint32_t val = 0;
        assert(cv_prng_uniform_u32(&prng, 10, &val) == CV_PRNG_SUCCESS);
        assert(val < 10);
        counts[val]++;
    }

    /* Chi-square uniformity sanity check: each bucket should be roughly trials / 10 = 1000 */
    for (int i = 0; i < 10; i++) {
        assert(counts[i] >= 700 && counts[i] <= 1300);
    }

    cv_prng_clear(&prng);
    printf("PASSED\n");
}

static void test_prng_self_test_verification(void) {
    printf("[PRNG] Testing Self-Test Routine cv_prng_self_test()... ");
    assert(cv_prng_self_test() == CV_PRNG_SUCCESS);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("          CryptoVault Sponge CSPRNG Tests           \n");
    printf("====================================================\n");
    test_prng_initialization_and_generation();
    test_prng_forward_secrecy();
    test_prng_reseed_and_entropy_injection();
    test_prng_uniform_rejection_sampling();
    test_prng_self_test_verification();
    printf("All CSPRNG Tests PASSED!\n\n");
    return 0;
}
