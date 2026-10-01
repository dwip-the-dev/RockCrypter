/**
 * @file dudect.c
 * @brief Implementation of DudeCT Statistical Timing Leakage Analysis Harness.
 *
 * ============================================================================
 * CryptoVault Anti-Side-Channel Research Subsystem
 * ============================================================================
 *
 * Implements Welch's two-sample t-test using Welford's online variance algorithm
 * to empirically verify constant-time execution and evaluate side-channel leakage.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "dudect.h"
#include "mem.h"
#include "entropy.h"
#include <math.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

uint64_t cv_dudect_read_timer(void) {
#if defined(__x86_64__) || defined(_M_X64)
    /* Memory and pipeline serialization fence before cycle counter read */
    __asm__ __volatile__("lfence" ::: "memory");
    return (uint64_t)__rdtsc();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

int cv_dudect_init(cv_dudect_ctx_t *ctx, double threshold) {
    if (!ctx) {
        return CV_DUDECT_ERR_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->threshold = (threshold > 0.0) ? threshold : CV_DUDECT_DEFAULT_THRESHOLD;
    ctx->total_samples = 0;
    return CV_DUDECT_PASS;
}

int cv_dudect_record(cv_dudect_ctx_t *ctx, int class_id, uint64_t duration) {
    if (!ctx || (class_id != 0 && class_id != 1)) {
        return CV_DUDECT_ERR_PARAM;
    }

    cv_dudect_class_stat_t *stat = &ctx->stats[class_id];
    stat->count++;
    ctx->total_samples++;

    /* Welford's algorithm for numerically stable running mean and variance */
    double x = (double)duration;
    double delta = x - stat->mean;
    stat->mean += delta / (double)stat->count;
    double delta2 = x - stat->mean;
    stat->m2 += delta * delta2;

    return CV_DUDECT_PASS;
}

int cv_dudect_compute_t(const cv_dudect_ctx_t *ctx, double *t_out) {
    if (!ctx || !t_out) {
        return CV_DUDECT_ERR_PARAM;
    }

    const cv_dudect_class_stat_t *s0 = &ctx->stats[0];
    const cv_dudect_class_stat_t *s1 = &ctx->stats[1];

    if (s0->count < 10 || s1->count < 10) {
        return CV_DUDECT_ERR_INSUFFICIENT;
    }

    double var0 = s0->m2 / (double)(s0->count - 1);
    double var1 = s1->m2 / (double)(s1->count - 1);

    double se = sqrt((var0 / (double)s0->count) + (var1 / (double)s1->count));
    if (se <= 1e-12) {
        /* Variance is virtually zero (constant measurements) */
        *t_out = 0.0;
        return CV_DUDECT_PASS;
    }

    *t_out = (s0->mean - s1->mean) / se;
    return CV_DUDECT_PASS;
}

int cv_dudect_evaluate(const cv_dudect_ctx_t *ctx, double *t_out) {
    if (!ctx) {
        return CV_DUDECT_ERR_PARAM;
    }

    double t = 0.0;
    int ret = cv_dudect_compute_t(ctx, &t);
    if (ret != CV_DUDECT_PASS) {
        return ret;
    }

    if (t_out) {
        *t_out = fabs(t);
    }

    if (fabs(t) >= ctx->threshold) {
        return CV_DUDECT_LEAK_DETECTED;
    }

    return CV_DUDECT_PASS;
}

/* Naive non-constant-time early-exit memory comparison */
static int naive_memcmp_early_exit(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

int cv_dudect_benchmark_mem_equal(size_t num_traces, double *t_constant_out, double *t_naive_out) {
    if (num_traces < 100) {
        num_traces = 100;
    }

    cv_dudect_ctx_t ctx_ct;
    cv_dudect_ctx_t ctx_naive;
    cv_dudect_init(&ctx_ct, CV_DUDECT_DEFAULT_THRESHOLD);
    cv_dudect_init(&ctx_naive, CV_DUDECT_DEFAULT_THRESHOLD);

    uint8_t buf_base[64];
    uint8_t buf_same[64];
    uint8_t buf_diff[64];

    memset(buf_base, 0x5A, sizeof(buf_base));
    memcpy(buf_same, buf_base, sizeof(buf_same));
    memcpy(buf_diff, buf_base, sizeof(buf_diff));
    buf_diff[0] ^= 0xFF; /* First byte mismatch */

    for (size_t i = 0; i < num_traces; i++) {
        /* Class 0: Identical buffers */
        uint64_t t0 = cv_dudect_read_timer();
        volatile int r_ct0 = cv_mem_equal(buf_base, buf_same, sizeof(buf_base));
        uint64_t t1 = cv_dudect_read_timer();
        cv_dudect_record(&ctx_ct, 0, t1 - t0);
        (void)r_ct0;

        uint64_t t2 = cv_dudect_read_timer();
        volatile int r_n0 = naive_memcmp_early_exit(buf_base, buf_same, sizeof(buf_base));
        uint64_t t3 = cv_dudect_read_timer();
        cv_dudect_record(&ctx_naive, 0, t3 - t2);
        (void)r_n0;

        /* Class 1: Mismatched buffers */
        uint64_t t4 = cv_dudect_read_timer();
        volatile int r_ct1 = cv_mem_equal(buf_base, buf_diff, sizeof(buf_base));
        uint64_t t5 = cv_dudect_read_timer();
        cv_dudect_record(&ctx_ct, 1, t5 - t4);
        (void)r_ct1;

        uint64_t t6 = cv_dudect_read_timer();
        volatile int r_n1 = naive_memcmp_early_exit(buf_base, buf_diff, sizeof(buf_base));
        uint64_t t7 = cv_dudect_read_timer();
        cv_dudect_record(&ctx_naive, 1, t7 - t6);
        (void)r_n1;
    }

    if (t_constant_out) {
        cv_dudect_compute_t(&ctx_ct, t_constant_out);
        *t_constant_out = fabs(*t_constant_out);
    }
    if (t_naive_out) {
        cv_dudect_compute_t(&ctx_naive, t_naive_out);
        *t_naive_out = fabs(*t_naive_out);
    }

    return CV_DUDECT_PASS;
}

int cv_dudect_self_test(void) {
    cv_dudect_ctx_t ctx;
    if (cv_dudect_init(&ctx, CV_DUDECT_DEFAULT_THRESHOLD) != CV_DUDECT_PASS) {
        return CV_DUDECT_ERR_SELFTEST;
    }

    /* 1. Simulate two identical timing distributions (should PASS with |t| < 2.0) */
    for (int i = 0; i < 500; i++) {
        cv_dudect_record(&ctx, 0, 1000 + (uint64_t)(i % 7));
        cv_dudect_record(&ctx, 1, 1000 + (uint64_t)(i % 7));
    }

    double t_val = 0.0;
    if (cv_dudect_evaluate(&ctx, &t_val) != CV_DUDECT_PASS || t_val >= 2.0) {
        return CV_DUDECT_ERR_SELFTEST;
    }

    /* 2. Simulate skewed timing distributions with massive gap (should DETECT LEAK) */
    cv_dudect_init(&ctx, CV_DUDECT_DEFAULT_THRESHOLD);
    for (int i = 0; i < 500; i++) {
        cv_dudect_record(&ctx, 0, 1000 + (uint64_t)(i % 5));
        cv_dudect_record(&ctx, 1, 1200 + (uint64_t)(i % 5));
    }

    if (cv_dudect_evaluate(&ctx, &t_val) != CV_DUDECT_LEAK_DETECTED || t_val < 4.5) {
        return CV_DUDECT_ERR_SELFTEST;
    }

    return CV_DUDECT_PASS;
}
