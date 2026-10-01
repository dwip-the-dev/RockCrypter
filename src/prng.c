#define _GNU_SOURCE
#include "prng.h"
#include "entropy.h"
#include "mem.h"
#include <unistd.h>
#include <string.h>

#define CV_PRNG_DOMAIN_SEED 0x50524E4753454544ULL /* "PRNGSEED" */
#define CV_PRNG_DOMAIN_STEP 0x50524E4753544550ULL /* "PRNGSTEP" */

int cv_prng_init(cv_prng_t *prng) {
    if (!prng) return CV_PRNG_ERR_PARAM;

    cv_memzero(prng, sizeof(*prng));
    cv_sponge_init(&prng->sponge, CV_PRNG_DOMAIN_SEED);

    uint8_t kernel_seed[CV_PRNG_SEED_BYTES];
    if (cv_entropy_get(kernel_seed, sizeof(kernel_seed)) != 0) {
        return CV_PRNG_ERR_ENTROPY;
    }

    cv_sponge_absorb(&prng->sponge, kernel_seed, sizeof(kernel_seed));
    cv_memzero(kernel_seed, sizeof(kernel_seed));

    prng->bytes_generated = 0;
    prng->reseed_counter = 1;
    prng->pid = (int32_t)getpid();
    prng->initialized = true;

    return CV_PRNG_SUCCESS;
}

int cv_prng_reseed(cv_prng_t *prng, const void *extra_seed, size_t seed_len) {
    if (!prng || !prng->initialized) return CV_PRNG_ERR_NOT_INIT;

    uint8_t kernel_seed[CV_PRNG_SEED_BYTES];
    if (cv_entropy_get(kernel_seed, sizeof(kernel_seed)) != 0) {
        return CV_PRNG_ERR_ENTROPY;
    }

    cv_sponge_absorb(&prng->sponge, kernel_seed, sizeof(kernel_seed));
    cv_memzero(kernel_seed, sizeof(kernel_seed));

    if (extra_seed && seed_len > 0) {
        cv_sponge_absorb(&prng->sponge, extra_seed, seed_len);
    }

    prng->bytes_generated = 0;
    prng->reseed_counter++;
    prng->pid = (int32_t)getpid();

    return CV_PRNG_SUCCESS;
}

int cv_prng_generate(cv_prng_t *prng, void *out_buf, size_t len) {
    if (!prng || !prng->initialized) return CV_PRNG_ERR_NOT_INIT;
    if (len == 0) return CV_PRNG_SUCCESS;
    if (!out_buf) return CV_PRNG_ERR_PARAM;

    /* Fork detection: if PID changed, reseed immediately */
    int32_t current_pid = (int32_t)getpid();
    if (current_pid != prng->pid) {
        cv_prng_reseed(prng, NULL, 0);
    }

    /* Auto-reseed threshold check */
    if (prng->bytes_generated + len > CV_PRNG_RESEED_INTERVAL_BYTES) {
        cv_prng_reseed(prng, NULL, 0);
    }

    cv_sponge_squeeze(&prng->sponge, out_buf, len);
    prng->bytes_generated += len;

    /* Forward Secrecy / Backtracking Resistance:
     * Erase previous state by permuting with forward secrecy step tag */
    uint64_t step_tag = CV_PRNG_DOMAIN_STEP ^ (uint64_t)prng->bytes_generated;
    cv_sponge_absorb(&prng->sponge, &step_tag, sizeof(step_tag));

    return CV_PRNG_SUCCESS;
}

int cv_prng_uniform_u32(cv_prng_t *prng, uint32_t upper_bound, uint32_t *out_val) {
    if (!prng || !out_val || upper_bound == 0) return CV_PRNG_ERR_PARAM;

    /* Rejection sampling to eliminate modulo bias */
    uint32_t min = (uint32_t)(-upper_bound) % upper_bound;
    uint32_t r;

    do {
        if (cv_prng_generate(prng, &r, sizeof(r)) != CV_PRNG_SUCCESS) {
            return CV_PRNG_ERR_ENTROPY;
        }
    } while (r < min);

    *out_val = r % upper_bound;
    return CV_PRNG_SUCCESS;
}

void cv_prng_clear(cv_prng_t *prng) {
    if (prng) {
        cv_sponge_clear(&prng->sponge);
        cv_memzero(prng, sizeof(*prng));
    }
}

int cv_prng_self_test(void) {
    cv_prng_t prng1, prng2;
    if (cv_prng_init(&prng1) != CV_PRNG_SUCCESS) return CV_PRNG_ERR_SELFTEST;
    if (cv_prng_init(&prng2) != CV_PRNG_SUCCESS) {
        cv_prng_clear(&prng1);
        return CV_PRNG_ERR_SELFTEST;
    }

    uint8_t buf1[64], buf2[64];
    if (cv_prng_generate(&prng1, buf1, sizeof(buf1)) != CV_PRNG_SUCCESS) {
        cv_prng_clear(&prng1);
        cv_prng_clear(&prng2);
        return CV_PRNG_ERR_SELFTEST;
    }

    if (cv_prng_generate(&prng2, buf2, sizeof(buf2)) != CV_PRNG_SUCCESS) {
        cv_prng_clear(&prng1);
        cv_prng_clear(&prng2);
        return CV_PRNG_ERR_SELFTEST;
    }

    /* Distinct instances initialized with distinct kernel entropy must not produce identical output */
    if (cv_ct_memcmp(buf1, buf2, sizeof(buf1)) == 0) {
        cv_prng_clear(&prng1);
        cv_prng_clear(&prng2);
        return CV_PRNG_ERR_SELFTEST;
    }

    /* Test uniform range */
    uint32_t val;
    for (int i = 0; i < 100; i++) {
        if (cv_prng_uniform_u32(&prng1, 50, &val) != CV_PRNG_SUCCESS || val >= 50) {
            cv_prng_clear(&prng1);
            cv_prng_clear(&prng2);
            return CV_PRNG_ERR_SELFTEST;
        }
    }

    cv_prng_clear(&prng1);
    cv_prng_clear(&prng2);
    cv_memzero(buf1, sizeof(buf1));
    cv_memzero(buf2, sizeof(buf2));

    return CV_PRNG_SUCCESS;
}
