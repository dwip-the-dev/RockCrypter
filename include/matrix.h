/**
 * @file matrix.h
 * @brief Galois Field GF(2^8) Arithmetic & Maximum Distance Separable (MDS) Diffusion.
 *
 * ============================================================================
 * CryptoVault Finite Field & Linear Diffusion Architecture
 * ============================================================================
 *
 * This subsystem implements finite field arithmetic over GF(2^8) and optimal
 * Maximum Distance Separable (MDS) diffusion layers for linear cryptanalysis resistance:
 *
 * MATHEMATICAL FOUNDATIONS:
 * 1. Finite Field GF(2^8) Representation:
 *    - Polynomial basis modulo irreducible polynomial:
 *      P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
 *    - Addition and Subtraction: Bitwise XOR (a ^ b).
 *    - Multiplication: Russian Peasant multiplication implemented in constant
 *      time using bit-masking to eliminate conditional branch timing side-channels.
 *    - Inversion: Computed via Fermat's Little Theorem:
 *      For any non-zero a in GF(2^8): a^255 = 1 => a^-1 = a^254.
 *
 * 2. Optimal MDS Matrix Diffusion:
 *    - A matrix M is Maximum Distance Separable (MDS) if every square submatrix
 *      has a non-zero determinant.
 *    - For an n x n MDS matrix over GF(2^8), the branch number achieves the
 *      theoretical maximum: B(M) = n + 1.
 *      * 4x4 MDS Matrix: Branch number = 5 (active S-boxes >= 5 across 2 rounds).
 *      * 8x8 MDS Matrix: Branch number = 9 (active S-boxes >= 9 across 2 rounds).
 *
 * 3. Horner Polynomial Evaluation & Lagrange Interpolation:
 *    - Polynomials f(x) evaluated in O(deg) field operations via Horner's scheme.
 *    - Secret reconstruction f(0) computed in O(k^2) field operations via Lagrange
 *      basis polynomials, serving as the core engine for Shamir's Secret Sharing.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MATRIX_H
#define MATRIX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Field Constants */
#define CV_GF256_POLY       0x11B /* x^8 + x^4 + x^3 + x + 1 */
#define CV_GF256_ORDER      256

/* Return Status Codes */
#define CV_MATRIX_SUCCESS    0
#define CV_MATRIX_ERR_PARAM -1
#define CV_MATRIX_ERR_TEST  -2

/**
 * @brief Constant-time multiplication in Galois Field GF(2^8).
 * Modulo P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
 *
 * @param a First field element (8-bit).
 * @param b Second field element (8-bit).
 * @return Product (a * b) in GF(2^8).
 */
uint8_t cv_gf256_mul(uint8_t a, uint8_t b);

/**
 * @brief Multiplicative inverse in GF(2^8).
 * Returns x^-1 such that gf256_mul(x, x^-1) == 1, or 0 for x == 0.
 *
 * @param a Input field element.
 * @return Multiplicative inverse in GF(2^8).
 */
uint8_t cv_gf256_inv(uint8_t a);

/**
 * @brief Addition / Subtraction in GF(2^8) (equivalent to bitwise XOR).
 */
static inline uint8_t cv_gf256_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

/**
 * @brief 4x4 Maximum Distance Separable (MDS) matrix diffusion over GF(2^8).
 * Guarantees optimal branch number of 5.
 *
 * @param in  4-byte input vector.
 * @param out 4-byte output vector.
 */
void cv_mds_multiply_4x4(const uint8_t in[4], uint8_t out[4]);

/**
 * @brief Inverse 4x4 MDS matrix multiplication.
 *
 * @param in  4-byte transformed vector.
 * @param out 4-byte recovered vector.
 */
void cv_mds_inv_multiply_4x4(const uint8_t in[4], uint8_t out[4]);

/**
 * @brief 8x8 MDS matrix diffusion layer for 64-bit word diffusion.
 * Guarantees optimal branch number of 9.
 *
 * @param in  8-byte input vector.
 * @param out 8-byte output vector.
 */
void cv_mds_multiply_8x8(const uint8_t in[8], uint8_t out[8]);

/**
 * @brief Inverse 8x8 MDS matrix diffusion layer.
 *
 * @param in  8-byte transformed vector.
 * @param out 8-byte recovered vector.
 */
void cv_mds_inv_multiply_8x8(const uint8_t in[8], uint8_t out[8]);

/**
 * @brief Polynomial evaluation at point x in GF(2^8) using Horner's method.
 *
 * @param coeffs Array of polynomial coefficients [a_0, a_1, ..., a_{k-1}].
 * @param deg    Degree of polynomial (number of coeffs = deg + 1).
 * @param x      Evaluation coordinate (x != 0).
 * @return f(x) in GF(2^8).
 */
uint8_t cv_poly_eval_gf256(const uint8_t *coeffs, size_t deg, uint8_t x);

/**
 * @brief Lagrange polynomial interpolation at x = 0 in GF(2^8).
 *
 * @param xs Array of k distinct x-coordinates.
 * @param ys Array of k corresponding y-coordinates.
 * @param k  Threshold number of points.
 * @return Reconstructed secret f(0) in GF(2^8).
 */
uint8_t cv_lagrange_interpolate_zero(const uint8_t *xs, const uint8_t *ys, size_t k);

/**
 * @brief Execute algebraic field and MDS matrix invertible self-test.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_matrix_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* MATRIX_H */
