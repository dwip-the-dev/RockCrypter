/**
 * @file keyfile.h
 * @brief Armored Encrypted Keyfile Storage & Asymmetric Identity Keybag.
 *
 * ============================================================================
 * CryptoVault Armored Keybag & Secure Key File Architecture
 * ============================================================================
 *
 * This subsystem manages persistent, encrypted, and ASCII-armored key storage
 * for both symmetric file keys and asymmetric X25519 identity keypairs.
 *
 * DESIGN & SECURITY PROPERTIES:
 * 1. Password Protection via 1 MiB Base Memory-Hard KDF:
 *    - Private keys and backup keys are never stored on disk in plaintext.
 *    - Keys are wrapped in an authenticated AEAD envelope (.cvlt) protected by
 *      a human passphrase processed through CryptoVault's 1 MiB memory-hard KDF.
 *    - Brute-force attacks against stolen key files on laptops or cloud backups
 *      are economically penalized by high memory bandwidth requirements.
 *
 * 2. Dual-Layer ASCII Armoring:
 *    - Encrypted keybags are wrapped in OpenPGP-style Radix-64 ASCII frames
 *      with 24-bit CRC checksums.
 *    - Allows safe copy-pasting into emails, secure chat apps (Signal, Matrix),
 *      or printing as paper recovery keys.
 *
 * 3. Public Key Fingerprinting & Export:
 *    - Public identity keys can be freely exported and imported in armored
 *      format for sharing with communication peers.
 *
 * 4. Constant-Time Decryption & Fail-Secure Erasure:
 *    - Incorrect passphrase attempts fail tag authentication immediately.
 *    - Temporary buffers are wiped with volatile memory fences before returning.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef KEYFILE_H
#define KEYFILE_H

#include "ecdh.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return Status Codes */
#define CV_KEYFILE_SUCCESS        0
#define CV_KEYFILE_ERR_INVALID   -1
#define CV_KEYFILE_ERR_IO        -2
#define CV_KEYFILE_ERR_DECRYPT   -3
#define CV_KEYFILE_ERR_CHECKSUM  -4
#define CV_KEYFILE_ERR_SELFTEST  -5

/**
 * @brief Save a 256-bit symmetric key encrypted with a passphrase to an armored file.
 *
 * @param path        Destination file path (e.g. "backup.key.asc").
 * @param key         Raw 32-byte secret key.
 * @param passphrase  Human password to protect the keyfile.
 * @param mem_cost_kb KDF memory cost (default: 1024 for 1 MiB base).
 * @return 0 on success, negative error code on failure.
 */
int cv_keyfile_save_encrypted(const char *path,
                              const uint8_t key[32],
                              const char *passphrase,
                              uint32_t mem_cost_kb);

/**
 * @brief Load and decrypt a 256-bit symmetric key from an encrypted armored file.
 *
 * @param path        Path to encrypted keyfile.
 * @param passphrase  Passphrase used during encryption.
 * @param key_out     Destination buffer receiving decrypted 32-byte key.
 * @return 0 on success, negative code on decryption or integrity failure.
 */
int cv_keyfile_load_encrypted(const char *path,
                              const char *passphrase,
                              uint8_t key_out[32]);

/**
 * @brief Export an ECDH Public Key to an ASCII armored file.
 *
 * @param path Path to output public key file (e.g. "alice.pub.asc").
 * @param pub  Raw 32-byte public key coordinate.
 * @return 0 on success, negative code on I/O error.
 */
int cv_pubkey_export_armored(const char *path, const uint8_t pub[CV_ECDH_KEY_SIZE]);

/**
 * @brief Import an ECDH Public Key from an ASCII armored file.
 *
 * @param path    Path to public key file.
 * @param pub_out Destination buffer receiving 32-byte public key.
 * @return 0 on success, negative code on parse failure.
 */
int cv_pubkey_import_armored(const char *path, uint8_t pub_out[CV_ECDH_KEY_SIZE]);

/**
 * @brief Export an ECDH Private Key encrypted with a passphrase.
 *
 * @param path       Path to destination file (e.g. "alice.priv.asc").
 * @param priv       Raw 32-byte private key.
 * @param passphrase Passphrase to protect private key.
 * @return 0 on success, negative error code on failure.
 */
int cv_privkey_export_encrypted(const char *path,
                                const uint8_t priv[CV_ECDH_KEY_SIZE],
                                const char *passphrase);

/**
 * @brief Import an ECDH Private Key from an encrypted armored file.
 *
 * @param path       Path to encrypted private key file.
 * @param passphrase Passphrase used during export.
 * @param priv_out   Destination buffer receiving decrypted private key.
 * @return 0 on success, negative code on authentication failure.
 */
int cv_privkey_import_encrypted(const char *path,
                                const char *passphrase,
                                uint8_t priv_out[CV_ECDH_KEY_SIZE]);

/**
 * @brief Execute round-trip keyfile encryption and ASCII armoring self-test.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_keyfile_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYFILE_H */
