/**
 * @file cube.c
 * @brief RockCrypter 256x256 Multi-Dimensional Cube & Heisenberg Tensor Diffusion Engine.
 *
 * Implements non-commutative Heisenberg operator displacement, 3-axis hypercube
 * rotational permutations, and 256x256 macro-matrix diffusion over Galois Field GF(2^8).
 *
 * @version 2.4.0
 * @author RockCrypter Academic Security Group
 */

#include "cube.h"
#include "mem.h"
#include "hkdf.h"
#include "matrix.h"
#include <string.h>

/* Forward S-Box: Rijndael-style affine inverse over GF(2^8) */
static const uint8_t CUBE_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Inverse S-Box: Exact Bijection */
static const uint8_t CUBE_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define CUBE_IDX(x, y, z) (((x) * CV_CUBE_DIM * CV_CUBE_DIM) + ((y) * CV_CUBE_DIM) + (z))

int cv_cube_init(cv_cube_ctx_t *ctx, const uint8_t key[CV_CUBE_KEY_SIZE]) {
    if (!ctx || !key) return CV_CUBE_ERR_PARAM;

    cv_memzero(ctx, sizeof(cv_cube_ctx_t));

    /* Derive round keys via HKDF */
    uint8_t expanded[CV_CUBE_ROUNDS * CV_CUBE_KEY_SIZE];
    if (cv_hkdf(NULL, 0, key, CV_CUBE_KEY_SIZE,
                (const uint8_t *)"RockCrypter-256x256-Cube-Key", 28,
                expanded, sizeof(expanded)) != 0) {
        return CV_CUBE_ERR_ALLOC;
    }

    for (size_t r = 0; r < CV_CUBE_ROUNDS; r++) {
        memcpy(ctx->round_keys[r], expanded + (r * CV_CUBE_KEY_SIZE), CV_CUBE_KEY_SIZE);
    }
    cv_memzero(expanded, sizeof(expanded));

    /* Initialize Heisenberg phase operators */
    for (size_t i = 0; i < CV_CUBE_DIM; i++) {
        ctx->heisenberg.phase_x[i] = ctx->round_keys[0][i];
        ctx->heisenberg.phase_p[i] = ctx->round_keys[1][i];
    }
    memcpy(ctx->heisenberg.commutator_seed, key, CV_CUBE_KEY_SIZE);
    ctx->initialized = 1;

    return CV_CUBE_SUCCESS;
}

void cv_cube_clear(cv_cube_ctx_t *ctx) {
    if (ctx) {
        cv_memzero(ctx, sizeof(cv_cube_ctx_t));
    }
}

/* 3-Axis Cyclic Rotations */
static void rotate_plane_xy(uint8_t state[CV_CUBE_SIZE], int shift) {
    uint8_t tmp[CV_CUBE_DIM];
    shift = (shift % CV_CUBE_DIM + CV_CUBE_DIM) % CV_CUBE_DIM;
    if (shift == 0) return;

    for (size_t z = 0; z < CV_CUBE_DIM; z++) {
        for (size_t x = 0; x < CV_CUBE_DIM; x++) {
            for (size_t y = 0; y < CV_CUBE_DIM; y++) {
                tmp[(y + shift) % CV_CUBE_DIM] = state[CUBE_IDX(x, y, z)];
            }
            for (size_t y = 0; y < CV_CUBE_DIM; y++) {
                state[CUBE_IDX(x, y, z)] = tmp[y];
            }
        }
    }
}

static void rotate_plane_yz(uint8_t state[CV_CUBE_SIZE], int shift) {
    uint8_t tmp[CV_CUBE_DIM];
    shift = (shift % CV_CUBE_DIM + CV_CUBE_DIM) % CV_CUBE_DIM;
    if (shift == 0) return;

    for (size_t x = 0; x < CV_CUBE_DIM; x++) {
        for (size_t y = 0; y < CV_CUBE_DIM; y++) {
            for (size_t z = 0; z < CV_CUBE_DIM; z++) {
                tmp[(z + shift) % CV_CUBE_DIM] = state[CUBE_IDX(x, y, z)];
            }
            for (size_t z = 0; z < CV_CUBE_DIM; z++) {
                state[CUBE_IDX(x, y, z)] = tmp[z];
            }
        }
    }
}

static void rotate_plane_zx(uint8_t state[CV_CUBE_SIZE], int shift) {
    uint8_t tmp[CV_CUBE_DIM];
    shift = (shift % CV_CUBE_DIM + CV_CUBE_DIM) % CV_CUBE_DIM;
    if (shift == 0) return;

    for (size_t y = 0; y < CV_CUBE_DIM; y++) {
        for (size_t z = 0; z < CV_CUBE_DIM; z++) {
            for (size_t x = 0; x < CV_CUBE_DIM; x++) {
                tmp[(x + shift) % CV_CUBE_DIM] = state[CUBE_IDX(x, y, z)];
            }
            for (size_t x = 0; x < CV_CUBE_DIM; x++) {
                state[CUBE_IDX(x, y, z)] = tmp[x];
            }
        }
    }
}

#define PLANE_SIZE (CV_CUBE_DIM * CV_CUBE_DIM) /* 256 bytes */

static void heisenberg_feistel_f(const uint8_t in_plane[PLANE_SIZE], uint8_t key_seed, uint8_t out_plane[PLANE_SIZE]) {
    uint8_t acc = key_seed;
    for (size_t i = 0; i < PLANE_SIZE; i++) {
        acc = CUBE_SBOX[acc ^ in_plane[i]];
        out_plane[i] = acc ^ in_plane[(i * 17 + 13) % PLANE_SIZE];
    }
}

int cv_cube_transform_block(cv_cube_ctx_t *ctx,
                            const uint8_t in_block[CV_CUBE_SIZE],
                            uint8_t out_block[CV_CUBE_SIZE]) {
    if (!ctx || !in_block || !out_block || !ctx->initialized) return CV_CUBE_ERR_PARAM;

    uint8_t s[CV_CUBE_SIZE];
    memcpy(s, in_block, CV_CUBE_SIZE);

    for (size_t r = 0; r < CV_CUBE_ROUNDS; r++) {
        const uint8_t *rk = ctx->round_keys[r];

        /* 1. Heisenberg Position-Momentum Non-Commutative Phase Modulation */
        for (size_t x = 0; x < CV_CUBE_DIM; x++) {
            for (size_t y = 0; y < CV_CUBE_DIM; y++) {
                for (size_t z = 0; z < CV_CUBE_DIM; z++) {
                    size_t idx = CUBE_IDX(x, y, z);
                    uint8_t val = s[idx] ^ ctx->heisenberg.phase_x[x] ^ rk[idx % CV_CUBE_KEY_SIZE];
                    val = CUBE_SBOX[val];
                    val ^= ctx->heisenberg.phase_p[y];
                    s[idx] = val;
                }
            }
        }

        /* 2. Inter-Plane Heisenberg Generalized Feistel Diffusion */
        for (size_t i = 0; i < CV_CUBE_DIM - 1; i++) {
            uint8_t f_out[PLANE_SIZE];
            heisenberg_feistel_f(s + (i * PLANE_SIZE), rk[i % CV_CUBE_KEY_SIZE], f_out);
            for (size_t j = 0; j < PLANE_SIZE; j++) {
                s[(i + 1) * PLANE_SIZE + j] ^= f_out[j];
            }
        }

        /* 3. 3-Axis Tensor Cube Rotations */
        int shift_xy = (int)(rk[0] & 0x0F) + 1;
        int shift_yz = (int)(rk[1] & 0x0F) + 1;
        int shift_zx = (int)(rk[2] & 0x0F) + 1;

        rotate_plane_xy(s, shift_xy);
        rotate_plane_yz(s, shift_yz);
        rotate_plane_zx(s, shift_zx);

        /* 4. Linear Diffusion across 4-byte columns */
        for (size_t i = 0; i < CV_CUBE_SIZE; i += 4) {
            uint8_t col[4], diff[4];
            memcpy(col, s + i, 4);
            cv_mds_multiply_4x4(col, diff);
            memcpy(s + i, diff, 4);
        }
    }

    memcpy(out_block, s, CV_CUBE_SIZE);
    cv_memzero(s, sizeof(s));
    return CV_CUBE_SUCCESS;
}

int cv_cube_inv_transform_block(cv_cube_ctx_t *ctx,
                                const uint8_t in_block[CV_CUBE_SIZE],
                                uint8_t out_block[CV_CUBE_SIZE]) {
    if (!ctx || !in_block || !out_block || !ctx->initialized) return CV_CUBE_ERR_PARAM;

    uint8_t s[CV_CUBE_SIZE];
    memcpy(s, in_block, CV_CUBE_SIZE);

    for (int r = (int)CV_CUBE_ROUNDS - 1; r >= 0; r--) {
        const uint8_t *rk = ctx->round_keys[r];

        /* 1. Inverse Linear Diffusion */
        for (size_t i = 0; i < CV_CUBE_SIZE; i += 4) {
            uint8_t col[4], diff[4];
            memcpy(col, s + i, 4);
            cv_mds_inv_multiply_4x4(col, diff);
            memcpy(s + i, diff, 4);
        }

        /* 2. Inverse 3-Axis Tensor Cube Rotations */
        int shift_xy = (int)(rk[0] & 0x0F) + 1;
        int shift_yz = (int)(rk[1] & 0x0F) + 1;
        int shift_zx = (int)(rk[2] & 0x0F) + 1;

        rotate_plane_zx(s, -shift_zx);
        rotate_plane_yz(s, -shift_yz);
        rotate_plane_xy(s, -shift_xy);

        /* 3. Inverse Inter-Plane Heisenberg Feistel Diffusion */
        for (int i = (int)CV_CUBE_DIM - 2; i >= 0; i--) {
            uint8_t f_out[PLANE_SIZE];
            heisenberg_feistel_f(s + (i * PLANE_SIZE), rk[i % CV_CUBE_KEY_SIZE], f_out);
            for (size_t j = 0; j < PLANE_SIZE; j++) {
                s[(i + 1) * PLANE_SIZE + j] ^= f_out[j];
            }
        }

        /* 4. Inverse Heisenberg Phase Modulation */
        for (size_t x = 0; x < CV_CUBE_DIM; x++) {
            for (size_t y = 0; y < CV_CUBE_DIM; y++) {
                for (size_t z = 0; z < CV_CUBE_DIM; z++) {
                    size_t idx = CUBE_IDX(x, y, z);
                    uint8_t val = s[idx] ^ ctx->heisenberg.phase_p[y];
                    val = CUBE_INV_SBOX[val];
                    val ^= ctx->heisenberg.phase_x[x] ^ rk[idx % CV_CUBE_KEY_SIZE];
                    s[idx] = val;
                }
            }
        }
    }

    memcpy(out_block, s, CV_CUBE_SIZE);
    cv_memzero(s, sizeof(s));
    return CV_CUBE_SUCCESS;
}

int cv_cube_matrix256_diffuse(uint8_t data[CV_MATRIX_256_SIZE],
                              const uint8_t key[CV_CUBE_KEY_SIZE],
                              int is_decryption) {
    if (!data || !key) return CV_CUBE_ERR_PARAM;

    if (!is_decryption) {
        /* Forward 256x256 Diffusion */
        /* Row substitutions and cyclic rotations */
        for (size_t row = 0; row < CV_MATRIX_256_DIM; row++) {
            uint8_t shift = key[row % CV_CUBE_KEY_SIZE] ^ (uint8_t)row;
            uint8_t tmp[CV_MATRIX_256_DIM];
            for (size_t col = 0; col < CV_MATRIX_256_DIM; col++) {
                uint8_t val = data[row * CV_MATRIX_256_DIM + col];
                val = CUBE_SBOX[val ^ key[(row + col) % CV_CUBE_KEY_SIZE]];
                tmp[(col + shift) % CV_MATRIX_256_DIM] = val;
            }
            memcpy(data + (row * CV_MATRIX_256_DIM), tmp, CV_MATRIX_256_DIM);
        }

        /* Column mixing using GF(2^8) cascade */
        for (size_t col = 0; col < CV_MATRIX_256_DIM; col++) {
            uint8_t acc = key[col % CV_CUBE_KEY_SIZE];
            for (size_t row = 0; row < CV_MATRIX_256_DIM; row++) {
                size_t idx = row * CV_MATRIX_256_DIM + col;
                data[idx] ^= acc;
                acc = cv_gf256_mul(data[idx], 0x03) ^ 0x01;
            }
        }
    } else {
        /* Inverse 256x256 Diffusion (Strict Reverse) */
        /* Inverse Column mixing */
        for (size_t col = 0; col < CV_MATRIX_256_DIM; col++) {
            uint8_t acc = key[col % CV_CUBE_KEY_SIZE];
            for (size_t row = 0; row < CV_MATRIX_256_DIM; row++) {
                size_t idx = row * CV_MATRIX_256_DIM + col;
                uint8_t orig = data[idx] ^ acc;
                acc = cv_gf256_mul(data[idx], 0x03) ^ 0x01;
                data[idx] = orig;
            }
        }

        /* Inverse Row substitutions and cyclic rotations */
        for (size_t row = 0; row < CV_MATRIX_256_DIM; row++) {
            uint8_t shift = key[row % CV_CUBE_KEY_SIZE] ^ (uint8_t)row;
            uint8_t tmp[CV_MATRIX_256_DIM];
            for (size_t col = 0; col < CV_MATRIX_256_DIM; col++) {
                size_t orig_col = (col + CV_MATRIX_256_DIM - (shift % CV_MATRIX_256_DIM)) % CV_MATRIX_256_DIM;
                uint8_t val = data[row * CV_MATRIX_256_DIM + col];
                val = CUBE_INV_SBOX[val] ^ key[(row + orig_col) % CV_CUBE_KEY_SIZE];
                tmp[orig_col] = val;
            }
            memcpy(data + (row * CV_MATRIX_256_DIM), tmp, CV_MATRIX_256_DIM);
        }
    }

    return CV_CUBE_SUCCESS;
}

int cv_cube_self_test(void) {
    uint8_t key[CV_CUBE_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };

    cv_cube_ctx_t ctx;
    if (cv_cube_init(&ctx, key) != CV_CUBE_SUCCESS) return CV_CUBE_ERR_SELFTEST;

    /* 1. Test 4096-byte tensor cube invertibility */
    uint8_t original[CV_CUBE_SIZE];
    uint8_t encrypted[CV_CUBE_SIZE];
    uint8_t decrypted[CV_CUBE_SIZE];

    for (size_t i = 0; i < CV_CUBE_SIZE; i++) {
        original[i] = (uint8_t)(i * 13 + 7);
    }

    if (cv_cube_transform_block(&ctx, original, encrypted) != CV_CUBE_SUCCESS) {
        cv_cube_clear(&ctx);
        return CV_CUBE_ERR_SELFTEST;
    }

    /* Verify ciphertext differs from plaintext */
    if (cv_ct_memcmp(original, encrypted, CV_CUBE_SIZE) == 0) {
        cv_cube_clear(&ctx);
        return CV_CUBE_ERR_SELFTEST;
    }

    if (cv_cube_inv_transform_block(&ctx, encrypted, decrypted) != CV_CUBE_SUCCESS) {
        cv_cube_clear(&ctx);
        return CV_CUBE_ERR_SELFTEST;
    }

    /* Verify exact roundtrip */
    if (cv_ct_memcmp(original, decrypted, CV_CUBE_SIZE) != 0) {
        cv_cube_clear(&ctx);
        return CV_CUBE_ERR_SELFTEST;
    }

    /* 2. Strict Avalanche Criterion: Flip 1 bit, verify ~50% bit diffusion */
    uint8_t perturbed[CV_CUBE_SIZE];
    memcpy(perturbed, original, CV_CUBE_SIZE);
    perturbed[0] ^= 0x01; /* 1-bit flip */

    uint8_t enc_perturbed[CV_CUBE_SIZE];
    cv_cube_transform_block(&ctx, perturbed, enc_perturbed);

    size_t bit_diffs = 0;
    for (size_t i = 0; i < CV_CUBE_SIZE; i++) {
        uint8_t d = encrypted[i] ^ enc_perturbed[i];
        while (d) {
            bit_diffs += (d & 1);
            d >>= 1;
        }
    }
    size_t total_bits = CV_CUBE_SIZE * 8;
    double ratio = (double)bit_diffs / (double)total_bits;
    /* Expect ~50% bit flip: 40% to 60% range */
    if (ratio < 0.40 || ratio > 0.60) {
        cv_cube_clear(&ctx);
        return CV_CUBE_ERR_SELFTEST;
    }

    cv_cube_clear(&ctx);

    /* 3. Test 256x256 (64 KiB) Macro-Matrix Diffusion Roundtrip */
    uint8_t *matrix = (uint8_t *)cv_secure_alloc(CV_MATRIX_256_SIZE);
    uint8_t *matrix_orig = (uint8_t *)cv_secure_alloc(CV_MATRIX_256_SIZE);
    if (!matrix || !matrix_orig) {
        if (matrix) cv_secure_free(matrix, CV_MATRIX_256_SIZE);
        if (matrix_orig) cv_secure_free(matrix_orig, CV_MATRIX_256_SIZE);
        return CV_CUBE_ERR_ALLOC;
    }

    for (size_t i = 0; i < CV_MATRIX_256_SIZE; i++) {
        matrix[i] = (uint8_t)(i ^ (i >> 8));
        matrix_orig[i] = matrix[i];
    }

    if (cv_cube_matrix256_diffuse(matrix, key, 0) != CV_CUBE_SUCCESS) {
        cv_secure_free(matrix, CV_MATRIX_256_SIZE);
        cv_secure_free(matrix_orig, CV_MATRIX_256_SIZE);
        return CV_CUBE_ERR_SELFTEST;
    }

    /* Decrypt / Inverse diffusion */
    if (cv_cube_matrix256_diffuse(matrix, key, 1) != CV_CUBE_SUCCESS) {
        cv_secure_free(matrix, CV_MATRIX_256_SIZE);
        cv_secure_free(matrix_orig, CV_MATRIX_256_SIZE);
        return CV_CUBE_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(matrix, matrix_orig, CV_MATRIX_256_SIZE) != 0) {
        cv_secure_free(matrix, CV_MATRIX_256_SIZE);
        cv_secure_free(matrix_orig, CV_MATRIX_256_SIZE);
        return CV_CUBE_ERR_SELFTEST;
    }

    cv_secure_free(matrix, CV_MATRIX_256_SIZE);
    cv_secure_free(matrix_orig, CV_MATRIX_256_SIZE);
    return CV_CUBE_SUCCESS;
}
