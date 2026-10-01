/**
 * @file keywrap.h
 * @brief NIST SP 800-38F / RFC 3394 Symmetric Key Wrap & Key Unwrap Engine.
 *
 * ============================================================================
 * CryptoVault Key Encapsulation Architecture
 * ============================================================================
 *
 * This subsystem implements deterministic authenticated key encapsulation for
 * protecting target cryptographic keys (such as ephemeral file encryption keys)
 * under a master Key-Encrypting Key (KEK).
 *
 * ALGORITHM SPECIFICATION:
 * 1. Semiblock Construction:
 *    - Operates on 64-bit (8-byte) semiblocks using the underlying SP-ARX-256
 *      symmetric primitive.
 *    - Input plaintext key of length n * 8 bytes (e.g. 32 bytes for 4 semiblocks).
 *    - Output wrapped key of length (n + 1) * 8 bytes (32-byte key -> 40-byte wrapped key).
 *
 * 2. 6-Round Permutation Feedback:
 *    - Performs 6 full passes over all n payload semiblocks.
 *    - For round j in [0..5] and semiblock i in [1..n]:
 *      t = (n * j) + i
 *      B = CipherEncrypt(KEK, (A || R[i]))
 *      A = MSB_64(B) ^ t
 *      R[i] = LSB_64(B)
 *
 * 3. Default Initial Value (Integrity Check Vector):
 *    - Uses RFC 3394 default IV: 0xA6A6A6A6A6A6A6A6ULL.
 *    - Upon unwrapping, constant-time verification guarantees that tampering
 *      with even a single bit of the wrapped key results in an integrity
 *      failure, triggering fail-secure zeroization.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef KEYWRAP_H
#define KEYWRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key Wrap Constants */
#define CV_KW_IV_LEN        8
#define CV_KW_SEMIBLOCK     8
#define CV_KW_TAG_LEN       8
#define CV_KW_OVERHEAD_BYTES 8 /* Wrapped key is plaintext key len + 8 */

/* Return Status Codes */
#define CV_KW_SUCCESS        0
#define CV_KW_ERR_INVALID   -1
#define CV_KW_ERR_ALIGNMENT -2
#define CV_KW_ERR_ALLOC     -3
#define CV_KW_ERR_INTEGRITY -4
#define CV_KW_ERR_SELFTEST  -5

/**
 * @brief Wrapped key size calculation helper macro.
 * Plaintext key length + 8 bytes of authentication overhead.
 */
#define CV_KW_WRAPPED_SIZE(plain_len) ((plain_len) + CV_KW_OVERHEAD_BYTES)

/**
 * @brief Unwrapped key size calculation helper macro.
 * Wrapped key length - 8 bytes of authentication overhead.
 */
#define CV_KW_UNWRAPPED_SIZE(wrap_len) ((wrap_len) - CV_KW_OVERHEAD_BYTES)

/**
 * @brief Wrap (encapsulate and authenticate) a target key using a 256-bit KEK.
 *
 * Implements deterministic authenticated key encapsulation over 6 outer passes
 * (6n semiblock iterations). Guarantees that any corruption of the ciphertext
 * results in an authenticated integrity reject with zero plaintext leakage.
 *
 * @param kek          32-byte Key-Encrypting Key.
 * @param in_key       Input plaintext key (must be multiple of 8 bytes, >= 16 bytes).
 * @param in_len       Length of input key in bytes (e.g. 32 for 256-bit key).
 * @param out_wrapped  Destination buffer of size (in_len + 8) bytes.
 * @return 0 on success, negative error code on failure.
 */
int cv_key_wrap(const uint8_t kek[32],
                const uint8_t *in_key, size_t in_len,
                uint8_t *out_wrapped);

/**
 * @brief Unwrap (authenticate and decapsulate) a wrapped key using a 256-bit KEK.
 *
 * Reverses the 6 outer passes in descending order and performs constant-time
 * comparison against DEFAULT_IV. If the reconstructed IV does not match, all
 * intermediate buffers are securely zeroized and CV_KW_ERR_INTEGRITY is returned.
 *
 * @param kek          32-byte Key-Encrypting Key.
 * @param in_wrapped   Input wrapped buffer of length in_len.
 * @param in_len       Length of wrapped buffer (must be >= 24 bytes).
 * @param out_key      Destination buffer of size (in_len - 8) bytes.
 * @return 0 on success, CV_KW_ERR_INTEGRITY on authentication failure.
 */
int cv_key_unwrap(const uint8_t kek[32],
                  const uint8_t *in_wrapped, size_t in_len,
                  uint8_t *out_key);

/**
 * @brief Known-Answer Test and round-trip verification for Key Wrap.
 *
 * Executes self-tests against known vectors, confirms bit-level tamper
 * detection, and validates error paths.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_keywrap_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYWRAP_H */

