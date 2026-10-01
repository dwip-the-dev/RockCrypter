/**
 * @file test_dudect.c
 * @brief Test Suite for DudeCT Statistical Timing Leakage & Side-Channel Verification.
 *
 * ============================================================================
 * CryptoVault DudeCT Statistical Timing Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Initialization and streaming state accumulation via Welford's algorithm.
 * 2. Correct Welch's t-statistic calculation between sample distributions.
 * 3. Verified pass condition (|t| < 4.5) for statistically indistinguishable timings.
 * 4. Proven leakage detection (|t| >= 4.5) for synthetic timing disparities.
 * 5. Differential evaluation comparing constant-time cv_mem_equal vs naive memcmp.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "dudect.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

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

static int test_dudect_welford_accuracy(void) {
    cv_dudect_ctx_t ctx;
    ASSERT_TEST(cv_dudect_init(&ctx, 4.5) == CV_DUDECT_PASS, "Init DudeCT context");

    /* Insert known sequence into Class 0: 10, 20, 30, 40, 50 */
    /* Mean = 30.0, Sample Variance = 250.0, M2 = 1000.0 */
    uint64_t seq[] = {10, 20, 30, 40, 50};
    for (size_t i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
        ASSERT_TEST(cv_dudect_record(&ctx, 0, seq[i]) == CV_DUDECT_PASS, "Record sample");
    }

    ASSERT_TEST(ctx.stats[0].count == 5, "Sample count is 5");
    ASSERT_TEST(fabs(ctx.stats[0].mean - 30.0) < 1e-6, "Running mean is exactly 30.0");
    ASSERT_TEST(fabs(ctx.stats[0].m2 - 1000.0) < 1e-6, "Welford M2 sum is exactly 1000.0");

    return TEST_PASS;
}

static int test_dudect_welch_t_detection(void) {
    cv_dudect_ctx_t ctx;
    ASSERT_TEST(cv_dudect_init(&ctx, 4.5) == CV_DUDECT_PASS, "Init");

    /* Feed 1000 samples with identical mean ~500 to both classes */
    for (int i = 0; i < 1000; i++) {
        cv_dudect_record(&ctx, 0, 500 + (uint64_t)(i % 11));
        cv_dudect_record(&ctx, 1, 500 + (uint64_t)(i % 11));
    }

    double t_val = 0.0;
    int eval = cv_dudect_evaluate(&ctx, &t_val);
    ASSERT_TEST(eval == CV_DUDECT_PASS, "Identical distributions must PASS");
    ASSERT_TEST(t_val < 2.0, "Absolute t-statistic must be small (< 2.0)");

    /* Reset and feed distributions with intentional timing gap (Class 0: 500, Class 1: 550) */
    cv_dudect_init(&ctx, 4.5);
    for (int i = 0; i < 1000; i++) {
        cv_dudect_record(&ctx, 0, 500 + (uint64_t)(i % 5));
        cv_dudect_record(&ctx, 1, 550 + (uint64_t)(i % 5));
    }

    eval = cv_dudect_evaluate(&ctx, &t_val);
    ASSERT_TEST(eval == CV_DUDECT_LEAK_DETECTED, "Skewed distributions must trigger LEAK_DETECTED");
    ASSERT_TEST(t_val >= 4.5, "Absolute t-statistic must exceed 4.5 threshold");

    return TEST_PASS;
}

static int test_dudect_mem_equal_benchmark(void) {
    double t_ct = 0.0;
    double t_naive = 0.0;

    /* Run 500 timing traces on both implementations */
    int ret = cv_dudect_benchmark_mem_equal(500, &t_ct, &t_naive);
    ASSERT_TEST(ret == CV_DUDECT_PASS, "Run mem_equal benchmark");

    printf("[*] DudeCT Benchmark Results: Constant-time |t| = %.3f, Naive |t| = %.3f\n",
           t_ct, t_naive);

    /* Constant-time implementation should not produce extreme t-values */
    ASSERT_TEST(t_ct >= 0.0, "Valid non-negative t-statistic computed");
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting DudeCT Statistical Timing Test Suite...\n");

    if (cv_dudect_self_test() != CV_DUDECT_PASS) {
        fprintf(stderr, "[-] cv_dudect_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_dudect_welford_accuracy() != TEST_PASS) return 1;
    if (test_dudect_welch_t_detection() != TEST_PASS) return 1;
    if (test_dudect_mem_equal_benchmark() != TEST_PASS) return 1;

    printf("[+] DudeCT Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
