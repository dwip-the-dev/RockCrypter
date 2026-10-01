/**
 * @file cert.h
 * @brief Public Key Identity Certificate & Authenticity Verification Subsystem.
 *
 * ============================================================================
 * CryptoVault Cryptographic Identity Certificate Architecture (.cvcert)
 * ============================================================================
 *
 * This subsystem implements self-contained, authenticated identity certificates
 * binding an entity's name/email to their X25519 public key, along with expiration
 * timestamps and key usage flags.
 *
 * CERTIFICATE STRUCTURE:
 * 1. Metadata Fields:
 *    - Magic header: "CVCERT10" (8 bytes).
 *    - Certificate version: 0x0100.
 *    - Valid from timestamp: uint64_t UTC seconds.
 *    - Valid until timestamp: uint64_t UTC seconds.
 *    - Key usage flags (e.g. CV_KEY_USAGE_ENCRYPT, CV_KEY_USAGE_SIGN).
 *    - Subject identity string (UTF-8, up to 64 bytes).
 *    - Subject X25519 public key (32 bytes).
 *
 * 2. Authenticity Verification:
 *    - Sponge-based authentication tag computed across all certificate fields.
 *    - Supports self-signing by the keyholder as well as organizational signing.
 *
 * 3. Human-Readable Fingerprinting:
 *    - Calculates a 256-bit SHA3/Sponge digest formatted as colon-separated hex:
 *      "AA:BB:CC:DD:..." for out-of-band visual verification over phone or secure chat.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef CERT_H
#define CERT_H

#include "ecdh.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_CERT_MAGIC         "CVCERT10"
#define CV_CERT_MAGIC_LEN     8
#define CV_CERT_MAX_SUBJECT   64
#define CV_CERT_TAG_SIZE      32

/* Key Usage Flags */
#define CV_KEY_USAGE_ENCRYPT  (1 << 0)
#define CV_KEY_USAGE_SIGN     (1 << 1)
#define CV_KEY_USAGE_BACKUP   (1 << 2)

/* Certificate Status Codes */
#define CV_CERT_SUCCESS        0
#define CV_CERT_ERR_PARAM     -1
#define CV_CERT_ERR_MAGIC     -2
#define CV_CERT_ERR_EXPIRED   -3
#define CV_CERT_ERR_NOT_YET   -4
#define CV_CERT_ERR_AUTH      -5
#define CV_CERT_ERR_IO        -6
#define CV_CERT_ERR_SELFTEST  -7

/**
 * @brief Packed cryptographic certificate structure.
 */
typedef struct __attribute__((packed)) {
    uint8_t  magic[CV_CERT_MAGIC_LEN];       /* "CVCERT10" */
    uint16_t version;                        /* 0x0100 */
    uint16_t usage_flags;                    /* Key usage bitmask */
    uint64_t valid_from;                     /* Unix epoch UTC seconds */
    uint64_t valid_until;                    /* Unix epoch UTC seconds */
    char     subject[CV_CERT_MAX_SUBJECT];   /* Entity name/email (null-padded) */
    uint8_t  pubkey[CV_ECDH_KEY_SIZE];       /* 32-byte public key */
    uint8_t  auth_tag[CV_CERT_TAG_SIZE];     /* 32-byte authenticity tag */
} cv_cert_t;

/**
 * @brief Create a self-signed identity certificate for an X25519 public key.
 *
 * @param cert        Output certificate structure.
 * @param subject     Identity string (e.g. "alice@example.com").
 * @param pubkey      32-byte public key.
 * @param privkey     32-byte corresponding private key (used for authentication).
 * @param valid_secs  Validity period in seconds from now.
 * @param usage_flags Bitmask of CV_KEY_USAGE_* flags.
 * @return 0 on success, negative error code on failure.
 */
int cv_cert_create_self_signed(cv_cert_t *cert,
                               const char *subject,
                               const uint8_t pubkey[CV_ECDH_KEY_SIZE],
                               const uint8_t privkey[CV_ECDH_KEY_SIZE],
                               uint64_t valid_secs,
                               uint16_t usage_flags);

/**
 * @brief Verify validity and authenticity of an identity certificate.
 *
 * @param cert        Pointer to certificate to verify.
 * @param current_time Unix timestamp (0 for current system time).
 * @return 0 on valid certificate, negative code on expiry or tamper.
 */
int cv_cert_verify(const cv_cert_t *cert, uint64_t current_time);

/**
 * @brief Compute the visual hexadecimal fingerprint of a public key.
 * Format: "XX:XX:XX:...:XX" (32 bytes = 95 characters).
 *
 * @param pubkey   32-byte public key coordinate.
 * @param fp_out   Output string buffer (must be at least 96 bytes).
 * @param max_len  Capacity of fp_out.
 * @return 0 on success, negative error code on failure.
 */
int cv_cert_compute_fingerprint(const uint8_t pubkey[CV_ECDH_KEY_SIZE],
                                char *fp_out, size_t max_len);

/**
 * @brief Save certificate to an ASCII armored file.
 *
 * @param path File system destination path.
 * @param cert Pointer to certificate structure.
 * @return 0 on success, negative code on failure.
 */
int cv_cert_save_armored(const char *path, const cv_cert_t *cert);

/**
 * @brief Load certificate from an ASCII armored file.
 *
 * @param path     File system source path.
 * @param cert_out Destination certificate structure.
 * @return 0 on success, negative code on failure.
 */
int cv_cert_load_armored(const char *path, cv_cert_t *cert_out);

/**
 * @brief Execute self-test on certificate creation and verification.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_cert_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CERT_H */
