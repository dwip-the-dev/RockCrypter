/**
 * @file prng.h
 * @brief Sponge-Based Cryptographic Pseudo-Random Number Generator (CSPRNG).
 *
 * ============================================================================
 * CryptoVault Cryptographic Pseudo-Random Number Generator (CSPRNG)
 * ============================================================================
 *
 * This subsystem implements a state-of-the-art CSPRNG based on CryptoVault's
 * 512-bit non-linear sponge permutation primitive.
 *
 * ARCHITECTURAL PROPERTIES:
 * 1. Forward Secrecy & Backtracking Resistance:
 *    - After every squeeze operation, the internal sponge state is updated via:
 *      S_{t+1} = SpongePermute(S_t ^ 0x50524E4753544550ULL);
 *    - Knowledge of the state at time t provides zero information regarding any
 *      pseudorandom bytes generated prior to time t.
 *
 * 2. Automatic Kernel Entropy Reseeding:
 *    - Reseeds automatically from Linux getrandom(2) every 1 MiB (2^20 bytes)
 *      or every 60 seconds, whichever occurs first.
 *    - Ingests auxiliary hardware cycle-counter jitter during every reseed.
 *
 * 3. Fork Safety & State Independence:
 *    - Detects OS process fork() events via getpid() checks and immediately
 *      re-initializes to prevent child and parent processes from generating
 *      identical random streams.
 *
 * 4. Memory Isolation:
 *    - State is held in mlock-locked memory pages and wiped upon destruction.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef PRNG_H
#define PRNG_H

#include "sponge.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PRNG Operational Constants */
#define CV_PRNG_RESEED_INTERVAL_BYTES (1024 * 1024) /* Reseed every 1 MiB */
#define CV_PRNG_SEED_BYTES            64            /* 512-bit seed */

/* Return Status Codes */
#define CV_PRNG_SUCCESS        0
#define CV_PRNG_ERR_PARAM     -1
#define CV_PRNG_ERR_ENTROPY   -2
#define CV_PRNG_ERR_NOT_INIT  -3
#define CV_PRNG_ERR_SELFTEST  -4

/**
 * @brief CSPRNG execution context.
 */
typedef struct {
    cv_sponge_t sponge;
    uint64_t    bytes_generated;
    uint64_t    reseed_counter;
    int32_t     pid;
    bool        initialized;
} cv_prng_t;

/**
 * @brief Initialize a CSPRNG context using true kernel entropy.
 *
 * @param prng Pointer to PRNG context to initialize.
 * @return 0 on success, negative error code on failure.
 */
int cv_prng_init(cv_prng_t *prng);

/**
 * @brief Seed or reseed a CSPRNG context with user-supplied and kernel entropy.
 *
 * @param prng       Pointer to initialized PRNG context.
 * @param extra_seed Optional additional seed material (can be NULL).
 * @param seed_len   Length of extra seed.
 * @return 0 on success, negative error code on failure.
 */
int cv_prng_reseed(cv_prng_t *prng, const void *extra_seed, size_t seed_len);

/**
 * @brief Generate cryptographically secure pseudorandom bytes.
 * Guarantees backtracking resistance and automatic reseed handling.
 *
 * @param prng    Pointer to PRNG context.
 * @param out_buf Destination buffer receiving random bytes.
 * @param len     Number of random bytes requested.
 * @return 0 on success, negative error code on failure.
 */
int cv_prng_generate(cv_prng_t *prng, void *out_buf, size_t len);

/**
 * @brief Generate a uniformly distributed 32-bit unsigned integer in range [0, upper_bound).
 * Eliminates modulo bias using rejection sampling.
 *
 * @param prng        Pointer to PRNG context.
 * @param upper_bound Exclusive upper bound.
 * @param out_val     Pointer to destination uint32_t.
 * @return 0 on success, negative error code on failure.
 */
int cv_prng_uniform_u32(cv_prng_t *prng, uint32_t upper_bound, uint32_t *out_val);

/**
 * @brief Securely wipe PRNG state from memory.
 *
 * @param prng Pointer to PRNG context to erase.
 */
void cv_prng_clear(cv_prng_t *prng);

/**
 * @brief Execute statistical and backtracking resistance self-test on PRNG.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_prng_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* PRNG_H */
