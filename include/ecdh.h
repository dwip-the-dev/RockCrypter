/**
 * @file ecdh.h
 * @brief Curve25519 (X25519) Montgomery Scalar Multiplication & Diffie-Hellman Key Exchange.
 *
 * ============================================================================
 * CryptoVault Asymmetric Diffie-Hellman Primitive (X25519)
 * ============================================================================
 *
 * This subsystem implements Montgomery-curve Diffie-Hellman key exchange over
 * Curve25519, defined by the equation:
 *      y^2 = x^3 + 486662 * x^2 + x  (mod 2^255 - 19)
 *
 * MATHEMATICAL & SECURITY SPECIFICATION:
 * 1. Base Point & Montgomery Ladder:
 *    - Base point generator: G = (x = 9).
 *    - Scalarmult Q = [k] * P is computed using a 255-step constant-time
 *      Montgomery ladder requiring only x-coordinates (differential addition
 *      and point doubling), eliminating side-channel leakage.
 *
 * 2. Scalar Clamping & Small-Order Defense:
 *    - Private scalars are clamped according to RFC 7748:
 *      k[0] &= 248;   (Clear lowest 3 bits: clears cofactor of 8)
 *      k[31] &= 127;  (Clear bit 255: ensures scalar is in field range)
 *      k[31] |= 64;   (Set bit 254: guarantees constant ladder loop count)
 *    - Protects against small subgroup confinement attacks and timing attacks.
 *
 * 3. Twist Security & Contributory Behavior:
 *    - Curve25519 is twist-secure: points on the quadratic twist have orders
 *      with large prime factors, preventing twist attacks.
 *    - All-zero shared secrets resulting from low-order input points are
 *      explicitly detected and rejected with CV_ECDH_ERR_LOW_ORDER.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef ECDH_H
#define ECDH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key Dimension Constants */
#define CV_ECDH_KEY_SIZE        32 /* 256 bits (32 bytes) */
#define CV_ECDH_SHARED_SIZE     32 /* 256 bits (32 bytes) */

/* Return Status Codes */
#define CV_ECDH_SUCCESS          0
#define CV_ECDH_ERR_INVALID     -1
#define CV_ECDH_ERR_ENTROPY     -2
#define CV_ECDH_ERR_LOW_ORDER   -3
#define CV_ECDH_ERR_SELFTEST    -4

/**
 * @brief Public/private keypair container.
 */
typedef struct {
    uint8_t priv[CV_ECDH_KEY_SIZE];
    uint8_t pub[CV_ECDH_KEY_SIZE];
} cv_ecdh_keypair_t;

/**
 * @brief Generate a new cryptographically secure X25519 keypair.
 *
 * @param kp Output structure receiving private and public keys.
 * @return 0 on success, negative error code on failure.
 */
int cv_ecdh_keygen(cv_ecdh_keypair_t *kp);

/**
 * @brief Compute the public coordinate from a given 32-byte private key.
 *
 * @param priv    Input 32-byte private scalar.
 * @param pub_out Destination buffer receiving 32-byte public key.
 * @return 0 on success, negative error code on failure.
 */
int cv_ecdh_public_from_private(const uint8_t priv[CV_ECDH_KEY_SIZE],
                                uint8_t pub_out[CV_ECDH_KEY_SIZE]);

/**
 * @brief Perform Diffie-Hellman key exchange.
 * Computes shared secret S = my_priv * peer_pub in constant time.
 *
 * @param my_priv    Own 32-byte private scalar.
 * @param peer_pub   Peer's 32-byte public coordinate.
 * @param shared_out Output buffer receiving 32-byte raw shared secret.
 * @return 0 on success, CV_ECDH_ERR_LOW_ORDER if peer point is invalid.
 */
int cv_ecdh_compute_shared(const uint8_t my_priv[CV_ECDH_KEY_SIZE],
                           const uint8_t peer_pub[CV_ECDH_KEY_SIZE],
                           uint8_t shared_out[CV_ECDH_KEY_SIZE]);

/**
 * @brief Securely wipe and zeroize an ECDH keypair.
 *
 * @param kp Pointer to keypair structure to clear.
 */
void cv_ecdh_keypair_clear(cv_ecdh_keypair_t *kp);

/**
 * @brief Execute RFC 7748 Known-Answer Test and Diffie-Hellman exchange sanity check.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_ecdh_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* ECDH_H */
