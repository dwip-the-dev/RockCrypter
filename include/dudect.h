/**
 * @file dudect.h
 * @brief Differential Timing Leakage & Side-Channel Statistical Verification Harness.
 *
 * ============================================================================
 * CryptoVault Anti-Side-Channel Research Subsystem (DudeCT Harness)
 * ============================================================================
 *
 * Implements statistical hypothesis testing based on Welch's t-test (as formalized
 * in the DudeCT framework by Reparaz et al.) to empirically verify constant-time
 * execution and detect timing side-channels in cryptographic primitives:
 *
 * 1. Two-Class Timing Distribution:
 *    - Class 0: Fixed secret input (or all-zero vector).
 *    - Class 1: Random secret input uniformly sampled across the domain.
 * 2. Welford's Numerically Stable Online Variance Algorithm:
 *    - Computes streaming mean, variance, and sample count for each class
 *      without accumulating individual measurements in memory.
 * 3. Welch's t-Statistic Evaluation:
 *         t = (Mean_0 - Mean_1) / sqrt( (Var_0 / N_0) + (Var_1 / N_1) )
 *    - Decision Rule:
 *      - |t| < 4.5: Pass (No statistically significant timing leakage detected,
 *        confidence > 99.999%).
 *      - |t| >= 4.5: Fail (Severe timing leakage discovered; violates constant-time
 *        execution guarantees).
 * 4. Microarchitectural CPU Cycle Counters:
 *    - High-resolution timestamp counter (RDTSC / POSIX CLOCK_MONOTONIC_RAW)
 *      with CPU serialization barriers to prevent out-of-order execution noise.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef DUDECT_H
#define DUDECT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standard Significance Thresholds */
#define CV_DUDECT_DEFAULT_THRESHOLD 4.5  /* Standard 99.999% confidence boundary */
#define CV_DUDECT_STRICT_THRESHOLD  3.2  /* 99.9% confidence boundary */

/* Return Status Codes */
#define CV_DUDECT_PASS              0    /* No timing leak detected (|t| < threshold) */
#define CV_DUDECT_LEAK_DETECTED     1    /* Timing side-channel found (|t| >= threshold) */
#define CV_DUDECT_ERR_PARAM        -1    /* Invalid parameters */
#define CV_DUDECT_ERR_INSUFFICIENT -2    /* Too few samples to compute valid t-statistic */
#define CV_DUDECT_ERR_SELFTEST     -3    /* Self-test failed */

/**
 * @brief Welford's streaming distribution state for each class.
 */
typedef struct {
    uint64_t count;                      /* Number of samples recorded */
    double   mean;                       /* Running sample mean */
    double   m2;                         /* Sum of squared differences from mean */
} cv_dudect_class_stat_t;

/**
 * @brief DudeCT timing analysis context.
 */
typedef struct {
    cv_dudect_class_stat_t stats[2];     /* Class 0 (fixed) and Class 1 (random) */
    double threshold;                    /* Critical t-value threshold */
    uint64_t total_samples;              /* Aggregate measurements taken */
} cv_dudect_ctx_t;

/**
 * @brief Read CPU cycle counter or monotonic nanoseconds with serialization fence.
 *
 * @return 64-bit cycle or nanosecond count.
 */
uint64_t cv_dudect_read_timer(void);

/**
 * @brief Initialize DudeCT statistical context.
 *
 * @param ctx       Context to initialize.
 * @param threshold Critical t-value threshold (e.g. 4.5). If <= 0, defaults to 4.5.
 * @return CV_DUDECT_PASS on success, CV_DUDECT_ERR_PARAM if ctx is NULL.
 */
int cv_dudect_init(cv_dudect_ctx_t *ctx, double threshold);

/**
 * @brief Record a single execution duration for a given class.
 *
 * @param ctx       Active context.
 * @param class_id  Distribution class (0 for fixed, 1 for random).
 * @param duration  Measured clock cycles or nanoseconds.
 * @return CV_DUDECT_PASS on success, negative code on error.
 */
int cv_dudect_record(cv_dudect_ctx_t *ctx, int class_id, uint64_t duration);

/**
 * @brief Compute the current Welch's t-statistic between Class 0 and Class 1.
 *
 * @param ctx   Context containing recorded measurements.
 * @param t_out Output pointer to receive calculated t-statistic.
 * @return CV_DUDECT_PASS on success, CV_DUDECT_ERR_INSUFFICIENT if count < 10.
 */
int cv_dudect_compute_t(const cv_dudect_ctx_t *ctx, double *t_out);

/**
 * @brief Evaluate whether the recorded distribution exhibits a timing side-channel.
 *
 * @param ctx   Context containing recorded measurements.
 * @param t_out Optional pointer to receive absolute t-value (can be NULL).
 * @return CV_DUDECT_PASS if constant-time, CV_DUDECT_LEAK_DETECTED if leak found.
 */
int cv_dudect_evaluate(const cv_dudect_ctx_t *ctx, double *t_out);

/**
 * @brief Benchmark constant-time cv_mem_equal vs. standard non-constant-time memcmp.
 *
 * Evaluates timing leakage when comparing identical buffers vs buffers differing
 * at byte 0.
 *
 * @param num_traces Number of timing trials to execute.
 * @param t_constant_out Pointer to receive t-statistic of cv_mem_equal.
 * @param t_naive_out    Pointer to receive t-statistic of naive memcmp.
 * @return CV_DUDECT_PASS on completion.
 */
int cv_dudect_benchmark_mem_equal(size_t num_traces, double *t_constant_out, double *t_naive_out);

/**
 * @brief Self-test verifying Welford variance calculation and synthetic distribution detection.
 *
 * @return CV_DUDECT_PASS on success, CV_DUDECT_ERR_SELFTEST on failure.
 */
int cv_dudect_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_H */
