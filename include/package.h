/**
 * @file package.h
 * @brief Secure Self-Contained Cryptographic Transport Container (.cvpkg).
 *
 * ============================================================================
 * CryptoVault Transmission Container Architecture (.cvpkg)
 * ============================================================================
 *
 * This subsystem implements self-contained, tamper-proof cryptographic packages
 * designed for secure sharing of encrypted files and confidential keys across
 * untrusted public networks (Email, Cloud Drives, Messaging Apps, USB):
 *
 * CONTAINER PACKAGE LAYOUT:
 * 1. Package Header:
 *    - Magic identifier: "CVPKG200" (8 bytes).
 *    - Mode flag:
 *      * CV_PKG_MODE_PASSWORD: Encrypted with memory-hard password.
 *      * CV_PKG_MODE_HYBRID:   Encrypted for recipient's X25519 public key.
 *      * CV_PKG_MODE_SHAMIR:   Key split into k-of-n Shamir shares.
 *    - Creation timestamp (UTC).
 *    - Embedded original filename (up to 128 bytes).
 *    - File size descriptors.
 *
 * 2. Key Envelope Section:
 *    - For Hybrid: 32-byte ephemeral public key + 40-byte wrapped session key.
 *    - For Password: Salt + Nonce + KDF parameters (1 MiB base).
 *    - For Shamir: Quorum threshold metadata.
 *
 * 3. Ciphertext Section:
 *    - 1 MiB chunked streaming AEAD payload with ratcheted sponge authentication.
 *
 * 4. Package Integrity Seal:
 *    - 256-bit sponge cryptographic digest over the entire container.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef PACKAGE_H
#define PACKAGE_H

#include "ecdh.h"
#include "shamir.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_PKG_MAGIC         "CVPKG200"
#define CV_PKG_MAGIC_LEN     8
#define CV_PKG_MAX_FILENAME  128

/* Package Delivery Modes */
typedef enum {
    CV_PKG_MODE_PASSWORD = 1,
    CV_PKG_MODE_HYBRID   = 2,
    CV_PKG_MODE_SHAMIR   = 3
} cv_pkg_mode_t;

/* Status Return Codes */
#define CV_PKG_SUCCESS        0
#define CV_PKG_ERR_PARAM     -1
#define CV_PKG_ERR_IO        -2
#define CV_PKG_ERR_MAGIC     -3
#define CV_PKG_ERR_AUTH      -4
#define CV_PKG_ERR_DECRYPT   -5
#define CV_PKG_ERR_CORRUPT   -6
#define CV_PKG_ERR_SELFTEST  -7

/**
 * @brief Manifest metadata inspection structure.
 */
typedef struct {
    char          orig_filename[CV_PKG_MAX_FILENAME];
    cv_pkg_mode_t mode;
    uint64_t      created_timestamp;
    uint64_t      payload_size;
    uint8_t       recipient_pubkey[CV_ECDH_KEY_SIZE];
    uint8_t       package_seal[32];
} cv_pkg_manifest_t;

/**
 * @brief Create a hybrid public-key package (.cvpkg) for a recipient.
 *
 * @param src_file       Path to plaintext file to package.
 * @param out_pkg_path   Destination package path (e.g. "document.cvpkg").
 * @param recipient_pub  Recipient's 32-byte X25519 public key.
 * @return 0 on success, negative error code on failure.
 */
int cv_package_create_hybrid(const char *src_file,
                             const char *out_pkg_path,
                             const uint8_t recipient_pub[CV_ECDH_KEY_SIZE]);

/**
 * @brief Extract and decrypt a hybrid package (.cvpkg) using recipient's private key.
 *
 * @param pkg_path       Path to .cvpkg file.
 * @param dest_file      Destination path for restored plaintext file.
 * @param recipient_priv Recipient's 32-byte X25519 private key.
 * @return 0 on success, negative code on authentication or decryption failure.
 */
int cv_package_extract_hybrid(const char *pkg_path,
                              const char *dest_file,
                              const uint8_t recipient_priv[CV_ECDH_KEY_SIZE]);

/**
 * @brief Create a password-protected package (.cvpkg) using 1 MiB memory-hard KDF.
 *
 * @param src_file     Path to plaintext file.
 * @param out_pkg_path Destination package path.
 * @param password     Secret passphrase.
 * @return 0 on success, negative error code on failure.
 */
int cv_package_create_password(const char *src_file,
                               const char *out_pkg_path,
                               const char *password);

/**
 * @brief Extract and decrypt a password-protected package (.cvpkg).
 *
 * @param pkg_path  Path to .cvpkg file.
 * @param dest_file Destination path for restored plaintext file.
 * @param password  Secret passphrase.
 * @return 0 on success, negative error code on wrong password or tamper.
 */
int cv_package_extract_password(const char *pkg_path,
                                const char *dest_file,
                                const char *password);

/**
 * @brief Inspect container manifest and metadata without decrypting payload.
 *
 * @param pkg_path     Path to .cvpkg file.
 * @param manifest_out Destination manifest structure.
 * @return 0 on success, negative code on invalid container.
 */
int cv_package_inspect(const char *pkg_path, cv_pkg_manifest_t *manifest_out);

/**
 * @brief Self-test verification of package creation and unpacking.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_package_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKAGE_H */
