/**
 * @file manifest.h
 * @brief Cryptographic File Manifests, Metadata Authentication & Permission Binding.
 *
 * ============================================================================
 * CryptoVault Cryptographic File Manifest Architecture (.cvman)
 * ============================================================================
 *
 * This subsystem creates and authenticates cryptographic file manifests that bind:
 * 1. File Metadata: Original filename, MIME type, and POSIX permissions.
 * 2. Integrity Commitments: Full-file 256-bit hash, Merkle root, chunk count, and size.
 * 3. Publisher Identity: Origin public key and 256-bit authenticity seal.
 * 4. Anti-Downgrade Defense: Prevents attackers from modifying file attributes,
 *    substituting extension types, or resetting permission bits upon decryption.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MANIFEST_H
#define MANIFEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_MANIFEST_MAGIC        "CVMAN100"
#define CV_MANIFEST_MAGIC_LEN    8
#define CV_MANIFEST_MAX_NAME     128
#define CV_MANIFEST_MAX_MIME     32
#define CV_MANIFEST_SIG_SIZE     32

/* Return Status Codes */
#define CV_MAN_SUCCESS           0
#define CV_MAN_ERR_PARAM        -1
#define CV_MAN_ERR_MAGIC        -2
#define CV_MAN_ERR_AUTH         -3
#define CV_MAN_ERR_IO           -4
#define CV_MAN_ERR_SELFTEST     -5

/**
 * @brief Packed cryptographic file manifest structure.
 */
typedef struct __attribute__((packed)) {
    uint8_t  magic[CV_MANIFEST_MAGIC_LEN];       /* "CVMAN100" */
    uint16_t version;                            /* 0x0100 */
    uint16_t flags;                              /* Reserved flags */
    uint32_t posix_mode;                         /* POSIX file mode (e.g. 0644, 0755) */
    uint64_t file_size_bytes;                    /* Exact unencrypted file size */
    uint64_t chunk_count;                        /* Total 1 MiB chunk count */
    uint64_t created_timestamp;                  /* UTC seconds */
    char     orig_filename[CV_MANIFEST_MAX_NAME];/* Canonical filename (null-terminated) */
    char     mime_type[CV_MANIFEST_MAX_MIME];    /* MIME type string (e.g. "application/pdf") */
    uint8_t  publisher_pubkey[32];               /* X25519 public key of publisher */
    uint8_t  full_file_hash[32];                 /* 256-bit Sponge digest of entire plaintext */
    uint8_t  merkle_root[32];                    /* Merkle root digest over chunk tags */
    uint8_t  manifest_seal[CV_MANIFEST_SIG_SIZE];/* Sponge MAC over all manifest fields */
} cv_manifest_t;

/**
 * @brief Create and authenticate a cryptographic manifest for a target file.
 *
 * @param manifest_out     Pointer to manifest destination.
 * @param source_file_path Path to file on disk.
 * @param orig_name        Canonical name (or NULL to deduce from path).
 * @param mime             MIME type string (e.g. "application/octet-stream").
 * @param publisher_pub    32-byte publisher public key.
 * @param publisher_priv   32-byte publisher private key used to seal manifest.
 * @param merkle_root      32-byte Merkle root over chunk tags.
 * @param total_chunks     Total chunk count.
 * @return CV_MAN_SUCCESS on success, negative error code on failure.
 */
int cv_manifest_create(cv_manifest_t *manifest_out,
                       const char *source_file_path,
                       const char *orig_name,
                       const char *mime,
                       const uint8_t publisher_pub[32],
                       const uint8_t publisher_priv[32],
                       const uint8_t merkle_root[32],
                       uint64_t total_chunks);

/**
 * @brief Authenticate a manifest against a publisher's public key.
 *
 * @param manifest  Pointer to manifest to verify.
 * @param pubkey    32-byte expected publisher public key.
 * @return CV_MAN_SUCCESS if authentic, CV_MAN_ERR_AUTH on forgery or corruption.
 */
int cv_manifest_verify(const cv_manifest_t *manifest, const uint8_t pubkey[32]);

/**
 * @brief Write manifest structure to disk as a binary file (.cvman).
 *
 * @param path     Destination file path.
 * @param manifest Pointer to manifest.
 * @return CV_MAN_SUCCESS on success, CV_MAN_ERR_IO on failure.
 */
int cv_manifest_save(const char *path, const cv_manifest_t *manifest);

/**
 * @brief Read and parse manifest structure from disk.
 *
 * @param path         Source file path.
 * @param manifest_out Output structure populated from disk.
 * @return CV_MAN_SUCCESS on success, negative error code on failure.
 */
int cv_manifest_load(const char *path, cv_manifest_t *manifest_out);

/**
 * @brief Self-test verifying manifest generation, seal verification, and anti-tamper.
 *
 * @return CV_MAN_SUCCESS on success, negative code on failure.
 */
int cv_manifest_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* MANIFEST_H */
