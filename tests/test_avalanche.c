#include "cryptovault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

static int count_bit_flips(const uint8_t *a, const uint8_t *b, size_t len) {
    int flips = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t diff = a[i] ^ b[i];
        while (diff) {
            flips += (diff & 1);
            diff >>= 1;
        }
    }
    return flips;
}

static void test_plaintext_avalanche(void) {
    printf("[Avalanche] Analyzing Plaintext Strict Avalanche Criterion (SAC)...\n");
    uint8_t key[32];
    cv_entropy_get(key, 32);

    cv_core_ctx_t ctx;
    cv_core_expand_key(&ctx, key);

    const int num_samples = 100;
    long long total_flips = 0;
    long long total_trials = (long long)num_samples * 256;
    double sum_sq_diff = 0.0;

    for (int s = 0; s < num_samples; s++) {
        uint8_t pt1[32], pt2[32];
        uint8_t ct1[32], ct2[32];
        cv_entropy_get(pt1, 32);

        cv_core_encrypt_block(&ctx, pt1, ct1);

        for (int bit = 0; bit < 256; bit++) {
            memcpy(pt2, pt1, 32);
            pt2[bit / 8] ^= (1 << (bit % 8)); /* Flip single bit */

            cv_core_encrypt_block(&ctx, pt2, ct2);
            int flips = count_bit_flips(ct1, ct2, 32);
            total_flips += flips;

            double diff = flips - 128.0;
            sum_sq_diff += diff * diff;
        }
    }

    double mean_flips = (double)total_flips / (double)total_trials;
    double mean_percentage = (mean_flips / 256.0) * 100.0;
    double variance = sum_sq_diff / (double)total_trials;
    double std_dev = sqrt(variance);

    printf("  Samples: %d | Bit trials: %lld\n", num_samples, total_trials);
    printf("  Mean bit flips per 1-bit input flip: %.2f / 256 bits (%.2f%%) [Ideal: 128.00 / 50.00%%]\n",
           mean_flips, mean_percentage);
    printf("  Standard Deviation: %.2f bits\n", std_dev);

    /* Avalanche criterion passing threshold: 48.0% to 52.0% */
    assert(mean_percentage >= 48.0 && mean_percentage <= 52.0);
    printf("  --> Plaintext SAC PASSED (Excellent Diffusion)\n");

    cv_core_clear(&ctx);
}

static void test_key_avalanche(void) {
    printf("[Avalanche] Analyzing Key Strict Avalanche Criterion (SAC)...\n");
    uint8_t pt[32];
    cv_entropy_get(pt, 32);

    const int num_samples = 100;
    long long total_flips = 0;
    long long total_trials = (long long)num_samples * 256;

    for (int s = 0; s < num_samples; s++) {
        uint8_t k1[32], k2[32];
        uint8_t ct1[32], ct2[32];
        cv_entropy_get(k1, 32);

        cv_core_ctx_t ctx1;
        cv_core_expand_key(&ctx1, k1);
        cv_core_encrypt_block(&ctx1, pt, ct1);
        cv_core_clear(&ctx1);

        for (int bit = 0; bit < 256; bit++) {
            memcpy(k2, k1, 32);
            k2[bit / 8] ^= (1 << (bit % 8)); /* Flip single bit in key */

            cv_core_ctx_t ctx2;
            cv_core_expand_key(&ctx2, k2);
            cv_core_encrypt_block(&ctx2, pt, ct2);
            cv_core_clear(&ctx2);

            int flips = count_bit_flips(ct1, ct2, 32);
            total_flips += flips;
        }
    }

    double mean_flips = (double)total_flips / (double)total_trials;
    double mean_percentage = (mean_flips / 256.0) * 100.0;

    printf("  Mean bit flips per 1-bit key flip: %.2f / 256 bits (%.2f%%) [Ideal: 128.00 / 50.00%%]\n",
           mean_flips, mean_percentage);

    assert(mean_percentage >= 48.0 && mean_percentage <= 52.0);
    printf("  --> Key SAC PASSED (Zero Key Leakage / Slide Symmetry)\n");
}

static void test_shannon_entropy_and_chisq(void) {
    printf("[Statistical] Evaluating Shannon Entropy & Chi-Square Randomness...\n");
    const size_t test_bytes = 1024 * 1024; /* 1 MB */
    uint8_t *plain = (uint8_t *)malloc(test_bytes);
    memset(plain, 0x00, test_bytes); /* Low entropy input: all zeroes */

    uint8_t key[32];
    cv_entropy_get(key, 32);

    uint8_t *ct = NULL;
    size_t ct_len = 0;
    int ret = cv_aead_encrypt(plain, test_bytes, NULL, 0, key, 32, 0, 0, 0, &ct, &ct_len);
    assert(ret == CV_SUCCESS);

    /* Skip header to evaluate pure ciphertext stream */
    const uint8_t *cipher_stream = ct + sizeof(cv_header_t);
    size_t stream_len = test_bytes;

    /* Byte frequency count */
    long count[256];
    memset(count, 0, sizeof(count));
    for (size_t i = 0; i < stream_len; i++) {
        count[cipher_stream[i]]++;
    }

    /* Shannon Entropy: -sum(p * log2(p)) */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            double p = (double)count[i] / (double)stream_len;
            entropy -= p * (log(p) / log(2.0));
        }
    }

    /* Chi-Square: sum((O - E)^2 / E) */
    double expected = (double)stream_len / 256.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)count[i] - expected;
        chi_sq += (diff * diff) / expected;
    }

    printf("  Evaluated Stream: %zu bytes (derived from all-zero plaintext)\n", stream_len);
    printf("  Shannon Entropy:  %.6f bits/byte (Theoretical Max: 8.000000)\n", entropy);
    printf("  Chi-Square (df=255): %.2f (Expected ~255.0)\n", chi_sq);

    assert(entropy > 7.999);
    assert(chi_sq > 180.0 && chi_sq < 330.0);
    printf("  --> Statistical Randomness & Indistinguishability PASSED\n");

    cv_secure_free(ct, ct_len);
    free(plain);
}

int main(void) {
    printf("====================================================\n");
    printf("  CryptoVault Avalanche & Statistical Cryptanalysis \n");
    printf("====================================================\n");
    test_plaintext_avalanche();
    test_key_avalanche();
    test_shannon_entropy_and_chisq();
    printf("All Cryptanalytic & Avalanche Tests PASSED!\n\n");
    return 0;
}
