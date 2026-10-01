/**
 * @file sponge.h
 * @brief 512-Bit Wide-State Cryptographic Permutation & Sponge Construction.
 *
 * ============================================================================
 * CryptoVault Permutation Primitive: 512-Bit Non-Linear Permutation
 * ============================================================================
 *
 * This subsystem implements a cryptographic sponge construction operating on
 * a 512-bit (64-byte) internal state partitioned into:
 * - Rate (r = 256 bits / 32 bytes): Data absorbing and squeezing interface.
 * - Capacity (c = 256 bits / 32 bytes): Internal security barrier preventing
 *   state recovery, collision attacks, and length extension attacks.
 *
 * CRYPTOGRAPHIC PERMUTATION SPECIFICATION:
 * - State representation: 8 x 64-bit unsigned integers [s0 ... s7].
 * - Round count: 24 full permutation rounds.
 * - Round function combines three sub-layers:
 *   1. Non-linear Substitution (Chi layer):
 *      s[i] ^= (~s[(i + 1) % 8]) & s[(i + 2) % 8];
 *      Guarantees maximum algebraic degree growth and non-linearity.
 *   2. Linear Diffusion (Theta/Pi layer):
 *      Word rotations across prime offsets (19, 29, 37, 43, 53, 59, 61, 11)
 *      followed by symmetric XOR-sum cross-diffusion.
 *   3. Round Constant Addition (Iota layer):
 *      Round-dependent 64-bit pseudo-random constants generated from fractional
 *      expansions of Pi and Euler's constant to eliminate rotational symmetry.
 *
 * DUPLEX STREAM CAPABILITY:
 * The sponge can be operated in duplex mode, alternating between absorbing data
 * and squeezing key streams for cascaded stream encryption.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef SPONGE_H
#define SPONGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sponge Dimensions & Security Parameters */
#define CV_SPONGE_RATE_BYTES     32  /* 256 bits rate */
#define CV_SPONGE_CAPACITY_BYTES 32  /* 256 bits capacity */
#define CV_SPONGE_STATE_BYTES    64  /* 512 bits = 8 uint64_t words */
#define CV_SPONGE_ROUNDS         24  /* 24 full non-linear permutation rounds */

/* Domain Separation Seed Constants */
#define CV_DOMAIN_HASH_256       0x53504F4E47453235ULL /* "SPONGE25" */
#define CV_DOMAIN_HASH_512       0x53504F4E47453531ULL /* "SPONGE51" */
#define CV_DOMAIN_MAC            0x53504F4E47454D41ULL /* "SPONGEMA" */
#define CV_DOMAIN_KDF            0x53504F4E47454B44ULL /* "SPONGEKD" */
#define CV_DOMAIN_STREAM         0x53504F4E47455354ULL /* "SPONGEST" */

/**
 * @brief Sponge execution state.
 */
typedef struct {
    uint64_t state[8];
    uint8_t  buffer[CV_SPONGE_RATE_BYTES];
    size_t   buf_pos;
    int      squeezing;
} cv_sponge_t;

/**
 * @brief Initialize sponge state with domain separation seed.
 *
 * @param sponge Pointer to sponge context to initialize.
 * @param domain_seed 64-bit domain separation tag.
 */
void cv_sponge_init(cv_sponge_t *sponge, uint64_t domain_seed);

/**
 * @brief Absorb arbitrary-length input data into the sponge state.
 *
 * @param sponge Pointer to initialized sponge context.
 * @param data Input byte buffer.
 * @param len Number of bytes to absorb.
 */
void cv_sponge_absorb(cv_sponge_t *sponge, const void *data, size_t len);

/**
 * @brief Squeeze arbitrary-length pseudorandom stream from sponge state.
 *
 * @param sponge Pointer to sponge context.
 * @param out Output destination buffer.
 * @param len Number of bytes to squeeze.
 */
void cv_sponge_squeeze(cv_sponge_t *sponge, void *out, size_t len);

/**
 * @brief Core 24-round permutation function on 512-bit state.
 *
 * @param state Array of 8 uint64_t words (64 bytes total).
 */
void cv_sponge_permute(uint64_t state[8]);

/**
 * @brief Securely wipe internal sponge state and buffer.
 *
 * @param sponge Pointer to sponge context to erase.
 */
void cv_sponge_clear(cv_sponge_t *sponge);

/**
 * @brief Self-test verification of sponge permutation primitive.
 *
 * @return 0 on pass, negative error code on failure.
 */
int cv_sponge_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* SPONGE_H */
