/**
 * @file pqc.h
 * @brief Post-Quantum Cryptography (PQC) & Hybrid Key Encapsulation Mechanism.
 *
 * ============================================================================
 * CryptoVault Post-Quantum & Hybrid Cryptography Subsystem
 * ============================================================================
 *
 * This module implements experimental lattice-based post-quantum cryptography
 * over the polynomial ring R_q = Z_q[x]/(x^256 + 1) with modulus q = 3329:
 * 1. Learning With Errors (LWE / Ring-LWE) formulation inspired by NIST FIPS 203.
 * 2. Constant-time polynomial reduction, negacyclic polynomial multiplication,
 *    and Gaussian noise sampling.
 * 3. Key Encapsulation Mechanism (KEM):
 *    - `cv_pqc_keygen`: Generates public/secret keypair.
 *    - `cv_pqc_encapsulate`: Encapsulates a 256-bit symmetric secret.
 *    - `cv_pqc_decapsulate`: Decapsulates secret key using recipient private key.
 * 4. Hybrid Combiner (Dual-PRK HKDF):
 *    - Merges classical ephemeral Diffie-Hellman (X25519) with post-quantum
 *      lattice shared secret:
 *        K_session = HKDF-Extract-and-Expand(SS_classical || SS_pqc, salt, info)
 *    - Guarantees security as long as AT LEAST ONE of the classical or quantum-
 *      resistant primitives remains unbroken ("dual-security guarantee").
 *
 * Threat Model:
 * - "Harvest Now, Decrypt Later" (HNDL): Protects recorded ciphertexts from future
 *   large-scale quantum computers running Shor's algorithm.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef PQC_H
#define PQC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ring Parameters: R_q = Z_q[x]/(x^n + 1) */
#define CV_PQC_POLY_DEGREE        256     /* Degree n = 256 */
#define CV_PQC_PRIME_Q            3329    /* Modulus q = 3329 (FIPS 203 standard) */

/* Key & Ciphertext Byte Lengths */
#define CV_PQC_PUBLIC_KEY_SIZE    512     /* 256 16-bit coefficients encoded */
#define CV_PQC_SECRET_KEY_SIZE    512     /* 256 16-bit private polynomial */
#define CV_PQC_CIPHERTEXT_SIZE    544     /* 256 16-bit poly (512B) + 256-bit hint (32B) */
#define CV_PQC_SHARED_SECRET_SIZE 32      /* 256-bit derived shared secret */
#define CV_PQC_HYBRID_SECRET_SIZE 32      /* 256-bit combined session secret */

/* Return Status Codes */
#define CV_PQC_SUCCESS             0
#define CV_PQC_ERR_PARAM          -1
#define CV_PQC_ERR_ENTROPY        -2
#define CV_PQC_ERR_DECAPSULATE    -3
#define CV_PQC_ERR_SELFTEST       -4

/**
 * @brief Representation of a polynomial in R_q = Z_q[x]/(x^256 + 1).
 */
typedef struct {
    int16_t coeffs[CV_PQC_POLY_DEGREE];
} cv_pqc_poly_t;

/**
 * @brief Public/private keypair for post-quantum KEM.
 */
typedef struct {
    uint8_t pk[CV_PQC_PUBLIC_KEY_SIZE];
    uint8_t sk[CV_PQC_SECRET_KEY_SIZE];
} cv_pqc_keypair_t;

/**
 * @brief Encapsulated ciphertext payload.
 */
typedef struct {
    uint8_t data[CV_PQC_CIPHERTEXT_SIZE];
} cv_pqc_ciphertext_t;

/**
 * @brief Perform negacyclic polynomial multiplication: c(x) = a(x) * b(x) mod (x^256 + 1) mod q.
 *
 * @param a First input polynomial.
 * @param b Second input polynomial.
 * @param c Output product polynomial.
 */
void cv_pqc_poly_mul(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c);

/**
 * @brief Perform polynomial addition: c(x) = a(x) + b(x) mod q.
 *
 * @param a First input polynomial.
 * @param b Second input polynomial.
 * @param c Output sum polynomial.
 */
void cv_pqc_poly_add(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c);

/**
 * @brief Perform polynomial subtraction: c(x) = a(x) - b(x) mod q.
 *
 * @param a First input polynomial.
 * @param b Second input polynomial.
 * @param c Output difference polynomial.
 */
void cv_pqc_poly_sub(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c);

/**
 * @brief Generate a post-quantum public/private keypair.
 *
 * @param kp Pointer to keypair structure to populate.
 * @return CV_PQC_SUCCESS on success, negative code on failure.
 */
int cv_pqc_keygen(cv_pqc_keypair_t *kp);

/**
 * @brief Encapsulate a random 256-bit shared secret against recipient public key.
 *
 * @param pk_bytes Recipient public key (512 bytes).
 * @param ct_out   Encapsulated ciphertext output (512 bytes).
 * @param ss_out   Derived 32-byte post-quantum shared secret.
 * @return CV_PQC_SUCCESS on success, negative code on failure.
 */
int cv_pqc_encapsulate(const uint8_t *pk_bytes, cv_pqc_ciphertext_t *ct_out, uint8_t *ss_out);

/**
 * @brief Decapsulate shared secret using private key.
 *
 * @param sk_bytes Recipient secret key (512 bytes).
 * @param ct       Ciphertext received from sender (512 bytes).
 * @param ss_out   Recovered 32-byte post-quantum shared secret.
 * @return CV_PQC_SUCCESS on success, negative code on failure.
 */
int cv_pqc_decapsulate(const uint8_t *sk_bytes, const cv_pqc_ciphertext_t *ct, uint8_t *ss_out);

/**
 * @brief Hybrid Key Combiner combining classical DH and Post-Quantum secrets.
 *
 * Performs:
 *   IKM = SS_classical || SS_pqc
 *   HybridKey = HKDF-Expand(HKDF-Extract(salt, IKM), context_info, out_len)
 *
 * @param classical_ss Classical shared secret (e.g. from X25519).
 * @param classical_len Length of classical shared secret in bytes.
 * @param pqc_ss        PQC shared secret.
 * @param pqc_len       Length of PQC shared secret in bytes.
 * @param context_info  Context/domain separation string.
 * @param info_len      Length of context string.
 * @param hybrid_out    Output buffer for combined key.
 * @param out_len       Requested output length (e.g. 32 bytes).
 * @return CV_PQC_SUCCESS on success, negative code on error.
 */
int cv_pqc_hybrid_combine(const uint8_t *classical_ss, size_t classical_len,
                          const uint8_t *pqc_ss, size_t pqc_len,
                          const uint8_t *context_info, size_t info_len,
                          uint8_t *hybrid_out, size_t out_len);

/**
 * @brief Self-test verifying polynomial arithmetic, keygen, encap, decap, and hybrid combiner.
 *
 * @return CV_PQC_SUCCESS on success, negative code on failure.
 */
int cv_pqc_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* PQC_H */
