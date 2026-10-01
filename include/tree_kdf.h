/**
 * @file tree_kdf.h
 * @brief Hierarchical Key Tree, Per-Block Derivation, Key Rotation & Expiration Engine.
 *
 * ============================================================================
 * CryptoVault Hierarchical Tree Key Architecture (HKDF-Tree)
 * ============================================================================
 *
 * This subsystem implements a complete cryptographic key tree hierarchy providing:
 * 1. Multi-Level Key Isolation: Root -> Application -> File Context -> Epoch -> Chunk.
 *    Compromise of a single chunk key reveals ZERO information about previous chunks,
 *    subsequent chunks, or higher-level keys.
 * 2. Per-Block / Per-Chunk Key Derivation: Every 1 MiB chunk is encrypted and
 *    authenticated with fresh, mathematically distinct keys.
 * 3. Automatic Ratcheted Rotation: Advances epoch keys automatically after a configured
 *    byte threshold or chunk interval to enforce forward secrecy.
 * 4. Expiring Keys: Cryptographically enforces validity time windows (valid_from,
 *    valid_until) with strict epoch bound checking.
 * 5. Strict Key Separation: Separate keys for Encryption, Authentication, Metadata,
 *    and Header protection.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef TREE_KDF_H
#define TREE_KDF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_TREE_KEY_SIZE        32
#define CV_TREE_MAX_APP_ID      64
#define CV_TREE_MAX_FILE_ID     64

/* Return Status Codes */
#define CV_TREE_SUCCESS          0
#define CV_TREE_ERR_PARAM       -1
#define CV_TREE_ERR_EXPIRED     -2
#define CV_TREE_ERR_NOT_YET     -3
#define CV_TREE_ERR_LIMIT       -4
#define CV_TREE_ERR_SELFTEST    -5

/**
 * @brief Domain separation tags for orthogonal key roles.
 */
typedef enum {
    CV_KEY_ROLE_ENCRYPTION = 1,
    CV_KEY_ROLE_AUTHENTICATION = 2,
    CV_KEY_ROLE_METADATA = 3,
    CV_KEY_ROLE_HEADER = 4,
    CV_KEY_ROLE_RATCHET = 5
} cv_key_role_t;

/**
 * @brief Hierarchical Key Context Node representing active encryption state.
 */
typedef struct {
    uint8_t  master_key[CV_TREE_KEY_SIZE];       /* Root key */
    uint8_t  app_key[CV_TREE_KEY_SIZE];          /* Application-level subkey */
    uint8_t  file_key[CV_TREE_KEY_SIZE];         /* File-level subkey */
    uint8_t  epoch_key[CV_TREE_KEY_SIZE];        /* Active ratcheted epoch key */
    uint64_t current_epoch;                      /* Monotonic epoch counter */
    uint64_t valid_from;                         /* Unix epoch UTC seconds */
    uint64_t valid_until;                        /* Unix epoch UTC seconds (0 = never) */
    uint64_t bytes_processed;                    /* Total bytes encrypted under active epoch */
    uint64_t rotation_threshold_bytes;           /* Max bytes before auto-rotation */
    char     app_id[CV_TREE_MAX_APP_ID];         /* Application context string */
    char     file_id[CV_TREE_MAX_FILE_ID];       /* Unique file UUID or identifier */
} cv_key_tree_ctx_t;

/**
 * @brief Initialize a hierarchical key tree from a 256-bit master secret.
 *
 * @param ctx           Pointer to tree context structure.
 * @param master_secret 32-byte root secret.
 * @param app_id        Application identifier string (e.g. "CryptoVault.SecureStorage").
 * @param file_id       File context string (e.g. "UUID-9876-54321").
 * @param valid_secs    Validity duration in seconds (0 = unlimited).
 * @param rotate_bytes  Bytes processed before automatic key rotation (default: 1 GiB).
 * @return CV_TREE_SUCCESS on success, negative error code on failure.
 */
int cv_tree_kdf_init(cv_key_tree_ctx_t *ctx,
                     const uint8_t master_secret[CV_TREE_KEY_SIZE],
                     const char *app_id,
                     const char *file_id,
                     uint64_t valid_secs,
                     uint64_t rotate_bytes);

/**
 * @brief Derive a dedicated, role-separated key for a specific 1 MiB chunk index.
 *
 * @param ctx          Pointer to valid key tree context.
 * @param chunk_index  Index of target file chunk.
 * @param role         Key role (Encryption, Authentication, Metadata, Header).
 * @param current_time Current Unix timestamp for expiration bounds checking (0 = now).
 * @param subkey_out   Destination buffer receiving 32-byte derived subkey.
 * @return CV_TREE_SUCCESS on success, CV_TREE_ERR_EXPIRED if expired.
 */
int cv_tree_kdf_derive_chunk_key(cv_key_tree_ctx_t *ctx,
                                 uint64_t chunk_index,
                                 cv_key_role_t role,
                                 uint64_t current_time,
                                 uint8_t subkey_out[CV_TREE_KEY_SIZE]);

/**
 * @brief Explicitly advance the tree to the next ratcheted epoch.
 * Overwrites previous epoch key using volatile write barriers.
 *
 * @param ctx Pointer to key tree context.
 * @return CV_TREE_SUCCESS on success, negative error code on failure.
 */
int cv_tree_rotate_epoch(cv_key_tree_ctx_t *ctx);

/**
 * @brief Update byte counters and trigger automatic key rotation if threshold reached.
 *
 * @param ctx            Pointer to key tree context.
 * @param bytes_written  Number of bytes just encrypted or processed.
 * @return CV_TREE_SUCCESS on success, negative error code on failure.
 */
int cv_tree_account_bytes(cv_key_tree_ctx_t *ctx, size_t bytes_written);

/**
 * @brief Securely erase and destroy all keys in the tree context.
 *
 * @param ctx Pointer to key tree context.
 */
void cv_tree_kdf_clear(cv_key_tree_ctx_t *ctx);

/**
 * @brief Self-test verifying hierarchical derivation, domain separation, and rotation.
 *
 * @return CV_TREE_SUCCESS on success, negative error code on failure.
 */
int cv_tree_kdf_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* TREE_KDF_H */
