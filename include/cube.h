/**
 * @file cube.h
 * @brief RockCrypter 256x256 Multi-Dimensional Cube & Heisenberg Tensor Diffusion Engine.
 *
 * ============================================================================
 * RockCrypter 256x256 Cube & Heisenberg Transformation Subsystem
 * ============================================================================
 *
 * This subsystem implements an experimental hyper-dimensional substitution,
 * permutation, and diffusion primitive operating across multi-axis tensor states:
 *
 * 1. 256x256 Hyper-State Matrix & Tensor Cube:
 *    - Operates on a 2D/3D state manifold (up to 65,536 bytes per macro-block or
 *      a 16x16x16 4096-byte hypercube tensor).
 *    - Provides high-diffusion macro-block whitening and non-linear mixing.
 *
 * 2. Heisenberg Non-Commutative Phase Transformations:
 *    - Models non-commuting position and momentum displacement operators over
 *      Galois Field GF(2^8):
 *          [X_pos, P_mom] = X_pos * P_mom ^ P_mom * X_pos != 0
 *    - Introduces key-dependent cyclic phase shifts and non-linear coordinate
 *      entanglement that defeats linear and differential cryptanalysis.
 *
 * 3. 3-Axis Rotational Permutation:
 *    - Executes multi-axis hypercube rotations across Row (X), Column (Y),
 *      and Depth (Z) planes with key-scheduled permutation offsets.
 *
 * 4. Guaranteed Bijective Invertibility:
 *    - Every forward transformation step possesses an exact, constant-time
 *      algebraic inverse for deterministic decryption.
 *
 * @version 2.4.0
 * @author RockCrypter Academic Security Group
 */

#ifndef CUBE_H
#define CUBE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dimension Definitions */
#define CV_CUBE_DIM               16
#define CV_CUBE_SIZE             (CV_CUBE_DIM * CV_CUBE_DIM * CV_CUBE_DIM) /* 4096 bytes */
#define CV_MATRIX_256_DIM         256
#define CV_MATRIX_256_SIZE       (CV_MATRIX_256_DIM * CV_MATRIX_256_DIM)   /* 65536 bytes */
#define CV_CUBE_ROUNDS            8
#define CV_CUBE_KEY_SIZE          32

/* Status Return Codes */
#define CV_CUBE_SUCCESS           0
#define CV_CUBE_ERR_PARAM        -1
#define CV_CUBE_ERR_ALLOC        -2
#define CV_CUBE_ERR_CORRUPT      -3
#define CV_CUBE_ERR_SELFTEST     -4

/**
 * @brief Heisenberg phase operator state.
 */
typedef struct {
    uint8_t phase_x[CV_CUBE_DIM];                /* Position coordinate shift */
    uint8_t phase_p[CV_CUBE_DIM];                /* Momentum conjugate shift */
    uint8_t commutator_seed[CV_CUBE_KEY_SIZE];   /* Non-commutative key seed */
} cv_heisenberg_state_t;

/**
 * @brief RockCrypter 256x256 / 16x16x16 Cube Transformation Context.
 */
typedef struct {
    uint8_t               state[CV_CUBE_SIZE];    /* 4096-byte working tensor */
    uint8_t               round_keys[CV_CUBE_ROUNDS][CV_CUBE_KEY_SIZE];
    cv_heisenberg_state_t heisenberg;
    int                   initialized;
} cv_cube_ctx_t;

/**
 * @brief Initialize the Cube transformation context with a 256-bit key.
 *
 * @param ctx Pointer to cube context.
 * @param key 32-byte key material.
 * @return CV_CUBE_SUCCESS on success, negative error code on failure.
 */
int cv_cube_init(cv_cube_ctx_t *ctx, const uint8_t key[CV_CUBE_KEY_SIZE]);

/**
 * @brief Apply forward Heisenberg Cube transformation on a 4096-byte block.
 *
 * @param ctx       Pointer to initialized cube context.
 * @param in_block  Input 4096-byte plaintext/ciphertext buffer.
 * @param out_block Output 4096-byte transformed buffer.
 * @return CV_CUBE_SUCCESS on success, negative error code on failure.
 */
int cv_cube_transform_block(cv_cube_ctx_t *ctx,
                            const uint8_t in_block[CV_CUBE_SIZE],
                            uint8_t out_block[CV_CUBE_SIZE]);

/**
 * @brief Apply inverse Heisenberg Cube transformation to reverse the block.
 *
 * @param ctx       Pointer to initialized cube context.
 * @param in_block  Input 4096-byte transformed block.
 * @param out_block Output 4096-byte restored buffer.
 * @return CV_CUBE_SUCCESS on success, negative error code on failure.
 */
int cv_cube_inv_transform_block(cv_cube_ctx_t *ctx,
                                const uint8_t in_block[CV_CUBE_SIZE],
                                uint8_t out_block[CV_CUBE_SIZE]);

/**
 * @brief Execute 256x256 (64 KiB) Macro-Matrix Heisenberg diffusion.
 *
 * Diffuses an entire 65,536-byte memory buffer in a single pass using
 * non-commutative phase modulation across all 256 rows and columns.
 *
 * @param data           Pointer to 65,536-byte data buffer (modified in place).
 * @param key            32-byte key seed for phase shifts.
 * @param is_decryption  0 for forward diffusion, 1 for inverse diffusion.
 * @return CV_CUBE_SUCCESS on success, negative code on failure.
 */
int cv_cube_matrix256_diffuse(uint8_t data[CV_MATRIX_256_SIZE],
                              const uint8_t key[CV_CUBE_KEY_SIZE],
                              int is_decryption);

/**
 * @brief Erase cube context from memory using non-optimizable memory barriers.
 *
 * @param ctx Pointer to cube context.
 */
void cv_cube_clear(cv_cube_ctx_t *ctx);

/**
 * @brief Comprehensive self-test verifying invertibility and Strict Avalanche Criterion.
 *
 * @return CV_CUBE_SUCCESS on success, negative code on failure.
 */
int cv_cube_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CUBE_H */
