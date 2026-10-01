/**
 * @file aead.h
 * @brief Cascaded Dual-Layer Authenticated Encryption with Associated Data (AEAD).
 *
 * ============================================================================
 * CryptoVault Cascaded Authenticated Envelope Architecture (.cvlt)
 * ============================================================================
 *
 * This subsystem implements CryptoVault's core zero-trust envelope container format:
 *
 * CRYPTOGRAPHIC DEFENSE-IN-DEPTH SPECIFICATION:
 * 1. Cascaded Dual-Layer Symmetric Encryption:
 *    - Layer 1 (Inner): 32-round 256-bit SP-ARX block cipher in CTR mode.
 *      Keyed by subkey k_enc with pre- and post-whitening via k_white.
 *    - Layer 2 (Outer): 512-bit wide-state sponge duplex stream cipher.
 *      Keyed by subkey k_cascade.
 *    - Rationale: Even if an unprecedented cryptanalytic breakthrough were to
 *      compromise one cipher family, the orthogonal construction of the other
 *      guarantees confidentiality and indistinguishability under chosen-ciphertext
 *      attacks (IND-CCA2).
 *
 * 2. Two-Tier Defensive Header Parsing:
 *    - Tier 1 (Header Integrity):
 *      The container header contains an authenticated MAC (header_mac) computed
 *      over all configuration fields (magic, version, suite, flags, mem_cost, salt, nonce,
 *      payload_len, aad_len).
 *      Defense against Resource Exhaustion: An adversary tampering with mem_cost_kb
 *      to force a multi-gigabyte memory exhaustion attack is rejected immediately
 *      before any KDF scratchpad memory is allocated!
 *    - Tier 2 (Payload & AAD Integrity):
 *      A 256-bit authentication tag computed over AAD and ciphertext.
 *
 * 3. Fail-Secure Zeroization Invariant:
 *    - If authentication fails at either tier, all allocated buffers are wiped
 *      with zeroes before returning.
 *
 * ENVELOPE MEMORY LAYOUT:
 * +------------------------+----------------+----------------+----------------+
 * | cv_header_t (120 bytes)| AAD (optional) |   Ciphertext   | Tag (32 bytes) |
 * +------------------------+----------------+----------------+----------------+
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef AEAD_H
#define AEAD_H

#include "kdf.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic & Container Versioning */
#define CV_MAGIC_BYTES     "CVLTv100"
#define CV_MAGIC_LEN       8
#define CV_VERSION_1       0x0100
#define CV_SUITE_STANDARD  0x0001

/* Dimensions & Defaults */
#define CV_TAG_SIZE        32
#define CV_BASE_1MIB_BYTES (1024 * 1024) /* 1 MiB Base Encryption Unit */

/* Status and Error Codes */
#define CV_SUCCESS                  0
#define CV_ERR_NULL_PARAM          -1
#define CV_ERR_INVALID_LENGTH      -2
#define CV_ERR_OUT_OF_MEMORY       -3
#define CV_ERR_ENTROPY_FAILED      -4
#define CV_ERR_INVALID_MAGIC       -10
#define CV_ERR_UNSUPPORTED_VERSION -11
#define CV_ERR_UNSUPPORTED_SUITE   -12
#define CV_ERR_HEADER_CORRUPTED    -13
#define CV_ERR_AUTH_FAILED         -14
#define CV_ERR_AAD_MISMATCH        -15
#define CV_ERR_IO                  -20
#define CV_ERR_STREAM_CORRUPTED    -21

/**
 * @brief Binary container header structure (120 bytes packed).
 */
typedef struct __attribute__((packed)) {
    uint8_t  magic[8];        /* "CVLTv100" */
    uint16_t version;         /* 0x0100 */
    uint16_t cipher_suite;    /* 0x0001 */
    uint32_t flags;           /* 0x0000 = single frame, 0x0001 = streaming chunks */
    uint32_t mem_cost_kb;     /* KDF memory parameter (default: 1024 KB = 1 MiB) */
    uint32_t time_cost;       /* KDF iteration count */
    uint8_t  salt[32];        /* 256-bit KDF salt */
    uint8_t  nonce[24];       /* 192-bit Nonce */
    uint64_t payload_len;     /* Ciphertext payload length in bytes */
    uint32_t aad_len;         /* Associated Authenticated Data length */
    uint8_t  header_mac[32];  /* 256-bit Tier 1 integrity MAC of header metadata */
} cv_header_t;

#define CV_HEADER_SIZE (sizeof(cv_header_t))

/**
 * @brief Returns human-readable explanation of error code.
 *
 * @param err Error code returned from any CryptoVault API function.
 * @return Constant string description.
 */
const char *cv_strerror(int err);

/**
 * @brief Encrypt plaintext buffer with zero-trust authenticated envelope.
 * Uses cascaded dual-layer encryption and two-tiered MAC verification.
 * Output format: [ cv_header_t ] [ AAD ] [ Ciphertext ] [ Tag (32 bytes) ]
 *
 * @param plaintext     Input plaintext buffer.
 * @param pt_len        Length of plaintext in bytes.
 * @param aad           Optional Associated Authenticated Data (can be NULL).
 * @param aad_len       Length of AAD.
 * @param secret        Password string or raw 32-byte key.
 * @param secret_len    Length of password or key.
 * @param is_passphrase 1 if human passphrase, 0 if raw 256-bit key.
 * @param mem_cost_kb   KDF memory parameter (default: 1024 for 1 MiB base).
 * @param time_cost     KDF iteration count (default: 4).
 * @param out_buf       Output pointer receiving dynamically allocated envelope buffer.
 * @param out_len       Output variable receiving total envelope length.
 * @return 0 on success, negative error code on failure.
 */
int cv_aead_encrypt(const uint8_t *plaintext, size_t pt_len,
                    const uint8_t *aad, size_t aad_len,
                    const void *secret, size_t secret_len,
                    int is_passphrase,
                    uint32_t mem_cost_kb, uint32_t time_cost,
                    uint8_t **out_buf, size_t *out_len);

/**
 * @brief Authenticate and decrypt envelope buffer.
 * Fails securely without releasing partial plaintext on any tamper or error.
 *
 * @param envelope      Input encrypted envelope buffer.
 * @param env_len       Total length of envelope.
 * @param expected_aad  Expected AAD to verify against.
 * @param aad_len       Length of expected AAD.
 * @param secret        Password string or raw 32-byte key.
 * @param secret_len    Length of password or key.
 * @param is_passphrase 1 if human passphrase, 0 if raw 256-bit key.
 * @param out_plaintext Output pointer receiving allocated decrypted plaintext.
 * @param out_pt_len    Output variable receiving decrypted length.
 * @return 0 on success, negative error code on forgery or corrupted header.
 */
int cv_aead_decrypt(const uint8_t *envelope, size_t env_len,
                    const uint8_t *expected_aad, size_t aad_len,
                    const void *secret, size_t secret_len,
                    int is_passphrase,
                    uint8_t **out_plaintext, size_t *out_pt_len);

#ifdef __cplusplus
}
#endif

#endif /* AEAD_H */
