/**
 * @file keyring.h
 * @brief OS Kernel Keyring Integration & Hardware-Backed Key Storage Subsystem.
 *
 * ============================================================================
 * CryptoVault Extreme Key Management & Kernel Keyring Subsystem
 * ============================================================================
 *
 * Integrates directly with the Linux Kernel Key Management Facility (`keyctl`
 * and `add_key` syscalls) to protect root master keys and recovery secrets from
 * user-space memory dumps, cold-boot attacks, and unauthorized process snooping:
 *
 * 1. Kernel Keyring Enclaves:
 *    - Keys are stored in the kernel space (`KEY_SPEC_USER_KEYRING` or
 *      `KEY_SPEC_SESSION_KEYRING`) where they are immune to user-space `ptrace`
 *      inspections and unprivileged process dumping.
 * 2. Automatic Secure Eviction & Revocation:
 *    - Zeroizes and revokes kernel key descriptors (`KEYCTL_REVOKE`, `KEYCTL_UNLINK`)
 *      upon completion of cryptographic operations or timeout expiration.
 * 3. Graceful Memory-Locked (`mlock`) Fallback:
 *    - Detects container environments (e.g. Docker, unprivileged namespaces) where
 *      kernel keyring syscalls may be restricted by seccomp profiles, seamlessly
 *      falling back to non-swappable `mlock(2)` memory segments protected by
 *      memory wiping fences.
 * 4. Key Tagging & Metadata Association:
 *    - Cryptographically binds key types (Master, Recovery, Ephemeral) and
 *      timestamps with the stored kernel key payloads.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef KEYRING_H
#define KEYRING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key Classification Types */
#define CV_KEY_TYPE_MASTER       0x0001 /* Root Master Key (Argon2id/KDF derived) */
#define CV_KEY_TYPE_RECOVERY     0x0002 /* Break-glass Emergency Recovery Secret */
#define CV_KEY_TYPE_EPHEMERAL    0x0003 /* Short-lived session key */
#define CV_KEY_TYPE_THRESHOLD    0x0004 /* Multi-party Shamir threshold share */

/* Return Status Codes */
#define CV_KEYRING_SUCCESS        0
#define CV_KEYRING_ERR_PARAM     -1
#define CV_KEYRING_ERR_NOT_FOUND -2
#define CV_KEYRING_ERR_ACCESS    -3
#define CV_KEYRING_ERR_STORAGE   -4
#define CV_KEYRING_ERR_SELFTEST  -5

/* Maximum sizes */
#define CV_KEYRING_MAX_NAME_LEN  64
#define CV_KEYRING_MAX_KEY_LEN   256

/**
 * @brief Descriptor for a kernel-stored cryptographic key.
 */
typedef struct {
    int32_t  key_id;                             /* Kernel key identifier or handle */
    char     name[CV_KEYRING_MAX_NAME_LEN];      /* Key description/identifier */
    uint32_t key_type;                           /* Key classification type */
    size_t   key_len;                            /* Key length in bytes */
    uint64_t created_at;                         /* Creation epoch timestamp */
    bool     is_kernel_backed;                   /* 1 if stored in kernel, 0 if mlocked */
} cv_keyring_entry_t;

/**
 * @brief Store a cryptographic key into the kernel keyring or mlocked vault.
 *
 * @param name       Unique name/identifier for the key.
 * @param key_data   Pointer to secret key bytes.
 * @param key_len    Length of key in bytes.
 * @param key_type   Key type flag (e.g. CV_KEY_TYPE_MASTER).
 * @param key_id_out Pointer to receive assigned key identifier (optional, can be NULL).
 * @return CV_KEYRING_SUCCESS on success, negative error code on failure.
 */
int cv_keyring_store(const char *name, const uint8_t *key_data, size_t key_len,
                     uint32_t key_type, int32_t *key_id_out);

/**
 * @brief Retrieve a cryptographic key by name.
 *
 * @param name        Key name to look up.
 * @param key_out     Buffer to receive key material.
 * @param max_len     Size of key_out buffer.
 * @param key_len_out Pointer to receive actual retrieved key length.
 * @return CV_KEYRING_SUCCESS on success, CV_KEYRING_ERR_NOT_FOUND if not found.
 */
int cv_keyring_load(const char *name, uint8_t *key_out, size_t max_len, size_t *key_len_out);

/**
 * @brief Revoke, unmap, and evict a specific key from the keyring.
 *
 * @param name Key name to evict.
 * @return CV_KEYRING_SUCCESS on success, CV_KEYRING_ERR_NOT_FOUND if not found.
 */
int cv_keyring_evict(const char *name);

/**
 * @brief Clear and wipe all managed keys in the active keyring.
 *
 * @return CV_KEYRING_SUCCESS on success.
 */
int cv_keyring_clear(void);

/**
 * @brief Self-test verifying key storage, retrieval, secure eviction, and boundary checks.
 *
 * @return CV_KEYRING_SUCCESS on success, CV_KEYRING_ERR_SELFTEST on failure.
 */
int cv_keyring_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYRING_H */
