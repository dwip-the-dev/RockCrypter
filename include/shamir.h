/**
 * @file shamir.h
 * @brief Information-Theoretic (k, n) Threshold Secret Sharing over GF(2^8).
 *
 * ============================================================================
 * CryptoVault Shamir Secret Sharing Architecture
 * ============================================================================
 *
 * This subsystem implements Adi Shamir's (k, n) threshold secret sharing scheme
 * generalized over the finite Galois Field GF(2^8).
 *
 * MATHEMATICAL FORMALIZATION:
 * 1. Polynomial Formulation:
 *    - To share a 256-bit secret S = (s_0, s_1, ..., s_31) with threshold k and
 *      n total shares (2 <= k <= n <= 255):
 *    - For each byte position b in [0..31], a random polynomial f_b(x) of degree
 *      (k - 1) is constructed over GF(2^8):
 *          f_b(x) = s_b + a_1 * x + a_2 * x^2 + ... + a_{k-1} * x^{k-1}
 *      where s_b is the secret byte and coefficients a_1 ... a_{k-1} are sampled
 *      from the cryptographically secure entropy harvester.
 *
 * 2. Share Evaluation:
 *    - Share i receives coordinate x_i = i for i in [1..n].
 *    - The payload for share i consists of the vector:
 *      y_i = (f_0(x_i), f_1(x_i), ..., f_31(x_i)).
 *
 * 3. Exact Lagrange Interpolation at x = 0:
 *    - Any subset of k shares {(x_1, y_1), ..., (x_k, y_k)} recovers the secret:
 *          s_b = f_b(0) = SUM_{i=1}^k [ y_{i,b} * PROD_{j != i} (x_j / (x_j + x_i)) ]
 *      All additions and subtractions correspond to bitwise XOR in GF(2^8).
 *
 * 4. Information-Theoretic Security:
 *    - Any subset of (k - 1) or fewer shares provides zero mathematical advantage:
 *      all 256 possible byte values remain equally probable.
 *
 * 5. String Serialization with CRC32:
 *    - Shares are serialized as "CVSHARE-XX-<64-char hex>-<8-char CRC32>" for
 *      paper backup and split-channel distribution across trusted custodians.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef SHAMIR_H
#define SHAMIR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shamir Subsystem Bounds */
#define CV_SHAMIR_SECRET_SIZE 32  /* 256-bit secret size (32 bytes) */
#define CV_MAX_SHARES         255 /* Maximum evaluation points in GF(2^8) */
#define CV_MIN_THRESHOLD      2   /* Minimum threshold */

/* Return Status Codes */
#define CV_SHAMIR_SUCCESS        0
#define CV_SHAMIR_ERR_INVALID   -1
#define CV_SHAMIR_ERR_BOUNDS    -2
#define CV_SHAMIR_ERR_ALLOC     -3
#define CV_SHAMIR_ERR_ENTROPY   -4
#define CV_SHAMIR_ERR_DUPLICATE -5
#define CV_SHAMIR_ERR_CHECKSUM  -6
#define CV_SHAMIR_ERR_SELFTEST  -7

/**
 * @brief Discrete evaluation share coordinate and data vector.
 */
typedef struct {
    uint8_t id;                            /* Share coordinate x in [1, 255] */
    uint8_t data[CV_SHAMIR_SECRET_SIZE];   /* y coordinates for all 32 bytes */
} cv_share_t;

/**
 * @brief Split a 256-bit secret into n shares with threshold k.
 *
 * @param secret     Input 32-byte secret.
 * @param k          Threshold required to reconstruct (2 <= k <= n <= 255).
 * @param n          Total number of shares generated.
 * @param shares_out Pre-allocated array of n shares.
 * @return 0 on success, negative error code on failure.
 */
int cv_shamir_split(const uint8_t secret[CV_SHAMIR_SECRET_SIZE],
                    uint8_t k, uint8_t n,
                    cv_share_t *shares_out);

/**
 * @brief Reconstruct a 256-bit secret from k valid shares.
 *
 * @param shares     Array of k shares.
 * @param k          Number of shares provided (must be >= threshold).
 * @param secret_out Output buffer receiving reconstructed 32-byte secret.
 * @return 0 on success, negative error code on failure.
 */
int cv_shamir_combine(const cv_share_t *shares,
                      uint8_t k,
                      uint8_t secret_out[CV_SHAMIR_SECRET_SIZE]);

/**
 * @brief Serialize a share into a human-readable hex string with CRC32.
 * Format: "CVSHARE-XX-YYYYYYYY...-CRC32"
 *
 * @param share    Pointer to share structure.
 * @param str_out  Output text buffer (must be at least 80 bytes).
 * @param max_len  Capacity of str_out.
 * @return 0 on success, negative error code on failure.
 */
int cv_shamir_share_to_string(const cv_share_t *share, char *str_out, size_t max_len);

/**
 * @brief Parse a human-readable share string back into a cv_share_t.
 * Verifies format, hexadecimal decoding, and CRC32 checksum.
 *
 * @param str_in    Input null-terminated string.
 * @param share_out Destination share structure.
 * @return 0 on success, negative code on checksum mismatch or corrupt format.
 */
int cv_shamir_share_from_string(const char *str_in, cv_share_t *share_out);

/**
 * @brief Execute split, combine, and string serialization self-test.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_shamir_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* SHAMIR_H */
