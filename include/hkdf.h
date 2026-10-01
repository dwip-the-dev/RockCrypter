/**
 * @file hkdf.h
 * @brief HMAC/Sponge-Based Extract-and-Expand Key Derivation (RFC 5869).
 *
 * ============================================================================
 * CryptoVault HKDF Architecture (RFC 5869 Formalization)
 * ============================================================================
 *
 * This subsystem implements the two-step Extract-and-Expand key derivation
 * construction specified in RFC 5869, instantiated using CryptoVault's keyed
 * sponge PRF:
 *
 * 1. Step 1: HKDF-Extract(salt, IKM) -> PRK
 *    - Extracts a uniform pseudorandom key (PRK) of fixed length (256 bits)
 *      from input keying material (IKM) that may not be uniformly distributed.
 *    - If salt is not provided, an all-zero salt of HashLen bytes is used.
 *    - Concentrates the physical entropy of the input material.
 *
 * 2. Step 2: HKDF-Expand(PRK, info, L) -> OKM
 *    - Expands the uniform PRK into Output Keying Material (OKM) of arbitrary
 *      length L (up to 255 * HashLen = 8160 bytes).
 *    - Iterative feedback chain:
 *      T(0) = empty string
 *      T(1) = PRF(PRK, T(0) || info || 0x01)
 *      T(2) = PRF(PRK, T(1) || info || 0x02)
 *      ...
 *      T(N) = PRF(PRK, T(N-1) || info || N)
 *      OKM = first L bytes of T(1) || T(2) || ... || T(N)
 *
 * 3. Application Context (info parameter):
 *    - Cryptographically binds derived keys to specific protocols, cipher suites,
 *      and recipient identities, preventing cross-protocol key reuse.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HKDF Constants & Bounds */
#define CV_HKDF_HASH_LEN    32   /* 256-bit PRK length */
#define CV_HKDF_MAX_OKM_LEN (255 * CV_HKDF_HASH_LEN) /* 8160 bytes max */

/* Return Status Codes */
#define CV_HKDF_SUCCESS      0
#define CV_HKDF_ERR_INVALID -1
#define CV_HKDF_ERR_TOO_BIG -2
#define CV_HKDF_ERR_SELFTEST -3

/**
 * @brief HKDF-Extract: Extracts a pseudorandom key (PRK) from input keying material.
 *
 * @param salt     Optional salt buffer (can be NULL).
 * @param salt_len Length of salt buffer.
 * @param ikm      Input keying material.
 * @param ikm_len  Length of input keying material.
 * @param prk_out  Destination array of 32 bytes receiving PRK.
 * @return 0 on success, negative error code on failure.
 */
int cv_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk_out[CV_HKDF_HASH_LEN]);

/**
 * @brief HKDF-Expand: Expands a pseudorandom key into arbitrary length key material.
 *
 * @param prk      32-byte pseudorandom key.
 * @param info     Optional application context string/bytes (can be NULL).
 * @param info_len Length of info.
 * @param okm_out  Destination buffer receiving OKM.
 * @param okm_len  Requested length of OKM in bytes (<= 8160).
 * @return 0 on success, negative error code on failure.
 */
int cv_hkdf_expand(const uint8_t prk[CV_HKDF_HASH_LEN],
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm_out, size_t okm_len);

/**
 * @brief Complete HKDF: Executes Extract and Expand in a single unified call.
 *
 * @param salt     Optional salt (can be NULL).
 * @param salt_len Length of salt.
 * @param ikm      Input keying material.
 * @param ikm_len  Length of IKM.
 * @param info     Optional context info.
 * @param info_len Length of info.
 * @param okm_out  Output key material buffer.
 * @param okm_len  Requested OKM length.
 * @return 0 on success, negative error code on failure.
 */
int cv_hkdf(const uint8_t *salt, size_t salt_len,
            const uint8_t *ikm, size_t ikm_len,
            const uint8_t *info, size_t info_len,
            uint8_t *okm_out, size_t okm_len);

/**
 * @brief Known-Answer Test and sanity check for HKDF subsystem.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_hkdf_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_H */
