/**
 * @file armoring.h
 * @brief RFC 4880 OpenPGP-Style ASCII Armoring Engine with 24-Bit CRC Verification.
 *
 * ============================================================================
 * CryptoVault ASCII Armoring & Text Serialization Architecture
 * ============================================================================
 *
 * This subsystem converts binary keys, encrypted envelopes, public key certificates,
 * and Shamir shares into human-readable, email-safe, copy-pasteable ASCII text:
 *
 * FORMAT SPECIFICATION:
 * 1. Header & Footer Framing:
 *    -----BEGIN CRYPTOVAULT KEY BLOCK-----
 *    Version: CryptoVault 2.4.0
 *    Comment: High-Assurance End-to-End Cryptographic Envelope
 *
 *    <Radix-64 Encoded Body (folded at 64 columns)>
 *    =<4-character Base64 24-bit CRC Checksum>
 *    -----END CRYPTOVAULT KEY BLOCK-----
 *
 * 2. 24-Bit Radix-64 CRC Checksum:
 *    - Polynomial: CRC-24-OpenPGP:
 *      P(x) = x^24 + x^23 + x^18 + x^17 + x^14 + x^11 + x^10 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
 *      Generator polynomial constant: 0x864CFB
 *      Initialization vector: 0xB704CE
 *    - Detects single-bit transmission corruption, truncated copy-pastes, and
 *      accidental newline alterations in text transport channels.
 *
 * 3. Constant-Time Decryption Guard:
 *    - If CRC fails upon decoding, destination buffers are immediately wiped
 *      with zeroes to prevent unauthenticated plaintext leakage.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef ARMORING_H
#define ARMORING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Supported Armor Types */
typedef enum {
    CV_ARMOR_MESSAGE = 1,
    CV_ARMOR_KEY     = 2,
    CV_ARMOR_SHARE   = 3,
    CV_ARMOR_PUBKEY  = 4
} cv_armor_type_t;

/* Return Status Codes */
#define CV_ARMOR_SUCCESS        0
#define CV_ARMOR_ERR_INVALID   -1
#define CV_ARMOR_ERR_OVERFLOW  -2
#define CV_ARMOR_ERR_CORRUPT   -3
#define CV_ARMOR_ERR_CRC_FAIL  -4
#define CV_ARMOR_ERR_SELFTEST  -5

/**
 * @brief Encode binary buffer into RFC 4880-style ASCII Armor.
 * Appends 24-bit radix-64 Radix CRC checksum.
 *
 * @param type     Armor type (Message, Key, Share, PublicKey).
 * @param in_bin   Raw binary input buffer.
 * @param in_len   Length of raw binary input.
 * @param out_str  Output buffer receiving null-terminated armored ASCII text.
 * @param max_len  Capacity of out_str buffer.
 * @return 0 on success, negative error code on failure.
 */
int cv_armor_encode(cv_armor_type_t type,
                    const uint8_t *in_bin, size_t in_len,
                    char *out_str, size_t max_len);

/**
 * @brief Decode ASCII Armored string back into binary buffer.
 * Verifies header, footer, base64 payload, and 24-bit CRC checksum.
 *
 * @param in_str    Input armored ASCII text.
 * @param type_out  Receives detected armor type (can be NULL).
 * @param out_bin   Output binary buffer.
 * @param out_len   In/Out: capacity of out_bin; on return, actual decoded byte length.
 * @return 0 on success, negative code on checksum mismatch or corrupt base64.
 */
int cv_armor_decode(const char *in_str,
                    cv_armor_type_t *type_out,
                    uint8_t *out_bin, size_t *out_len);

/**
 * @brief Execute roundtrip encoding and CRC corruption self-test.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_armor_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* ARMORING_H */
