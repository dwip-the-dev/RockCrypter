/**
 * @file core.h
 * @brief 32-Round 256-Bit SP-ARX Cryptographic Block Cipher Specification.
 *
 * ============================================================================
 * CryptoVault Core Symmetric Primitive: SP-ARX-256
 * ============================================================================
 *
 * SP-ARX-256 is an original symmetric block cipher operating on 256-bit blocks
 * with a 256-bit secret key over 32 iterative rounds.
 *
 * MATHEMATICAL STRUCTURE:
 * 1. State Representation:
 *    - 256-bit block formatted as four 64-bit unsigned words: [v0, v1, v2, v3].
 *
 * 2. Substitution Layer (S-Box):
 *    - Key-dependent and affine non-linear transformations applying bitwise
 *      modular addition, bit rotations, and non-linear bitwise logic.
 *    - Achieves strict avalanche criterion (SAC > 50%) after only 4 rounds.
 *
 * 3. Permutation Layer (P-Box / Linear Diffusion):
 *    - Multi-word word mixing via cyclic permutations and XOR-sum diffusions:
 *      v0 += v1; v3 = ROTL64(v3 ^ v0, 16);
 *      v2 += v3; v1 = ROTL64(v1 ^ v2, 32);
 *      v0 += v3; v2 = ROTL64(v2 ^ v0, 24);
 *      v1 += v2; v3 = ROTL64(v3 ^ v1, 63);
 *
 * 4. Key Schedule:
 *    - 33 round subkeys (256 bits each) derived via non-linear recurrence
 *      incorporating fractional expansion constants of the golden ratio
 *      and Euler-Mascheroni constant to prevent slide and symmetry attacks.
 *
 * 5. Invertibility:
 *    - Decryption is the exact mathematical inverse of encryption, reversing
 *      the ARX rotations and modular subtractions with round keys in reverse.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef CORE_H
#define CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Core Block Cipher Dimensions */
#define CV_BLOCK_SIZE       32 /* 256-bit block size (32 bytes) */
#define CV_KEY_SIZE         32 /* 256-bit key size (32 bytes) */
#define CV_ROUNDS           32 /* 32 full non-linear diffusion rounds */
#define CV_TOTAL_SUBKEYS    (CV_ROUNDS + 1) /* 33 subkeys including whitening */

/* Return Status Codes */
#define CV_CORE_SUCCESS      0
#define CV_CORE_ERR_NULL    -1
#define CV_CORE_ERR_KAT     -2

/**
 * @brief Cipher execution context holding precomputed round subkeys.
 */
typedef struct {
    uint64_t round_keys[CV_TOTAL_SUBKEYS][4];
} cv_core_ctx_t;

/**
 * @brief Expand a 256-bit secret key into 33 round subkeys.
 *
 * @param ctx Pointer to cipher context to initialize.
 * @param key 32-byte secret key buffer.
 * @return 0 on success, negative error code on NULL parameters.
 */
int cv_core_expand_key(cv_core_ctx_t *ctx, const uint8_t key[CV_KEY_SIZE]);

/**
 * @brief Encrypt a single 256-bit (32-byte) block.
 *
 * @param ctx Pointer to initialized key context.
 * @param in 32-byte plaintext block.
 * @param out 32-byte ciphertext destination buffer.
 */
void cv_core_encrypt_block(const cv_core_ctx_t *ctx,
                           const uint8_t in[CV_BLOCK_SIZE],
                           uint8_t out[CV_BLOCK_SIZE]);

/**
 * @brief Decrypt a single 256-bit (32-byte) block.
 * Exact mathematical inverse of cv_core_encrypt_block.
 *
 * @param ctx Pointer to initialized key context.
 * @param in 32-byte ciphertext block.
 * @param out 32-byte decrypted plaintext destination buffer.
 */
void cv_core_decrypt_block(const cv_core_ctx_t *ctx,
                           const uint8_t in[CV_BLOCK_SIZE],
                           uint8_t out[CV_BLOCK_SIZE]);

/**
 * @brief Securely wipe cipher context and all derived round subkeys.
 *
 * @param ctx Pointer to cipher context to clear.
 */
void cv_core_clear(cv_core_ctx_t *ctx);

/**
 * @brief Known-Answer Test (KAT) verification for SP-ARX-256.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_core_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CORE_H */
