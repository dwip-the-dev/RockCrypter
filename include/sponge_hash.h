/**
 * @file sponge_hash.h
 * @brief Cryptographic Sponge Hash Function (256-Bit and 512-Bit Modes).
 *
 * ============================================================================
 * CryptoVault Sponge Cryptographic Hashing Architecture
 * ============================================================================
 *
 * This subsystem implements unkeyed cryptographic hashing directly on top of
 * the 512-bit permutation primitive.
 *
 * MATHEMATICAL & SECURITY SPECIFICATION:
 * 1. Dual Digest Modes:
 *    - CV_HASH256 (32 bytes / 256 bits):
 *      Collision resistance: 2^128 operations.
 *      Preimage resistance: 2^256 operations.
 *      Domain separation: 0x4841534832353631ULL ("HASH2561").
 *    - CV_HASH512 (64 bytes / 512 bits):
 *      Collision resistance: 2^256 operations.
 *      Preimage resistance: 2^512 operations.
 *      Domain separation: 0x4841534835313231ULL ("HASH5121").
 *
 * 2. Unambiguous Length Padding:
 *    - Once all message bytes are absorbed, an 8-byte little-endian length
 *      descriptor is absorbed to prevent prefix-suffix collision ambiguities.
 *
 * 3. Streaming File Hashing:
 *    - cv_hash_file() computes SHA-3 style file digests in 64 KiB buffered
 *      chunks, enabling cryptographic integrity checks on multi-gigabyte files.
 *
 * 4. Constant-Time Verification:
 *    - All digest comparisons should use cv_ct_memcmp() to prevent timing leaks.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef SPONGE_HASH_H
#define SPONGE_HASH_H

#include "sponge.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hash Digest Sizes */
#define CV_HASH256_SIZE     32 /* 256 bits (32 bytes) */
#define CV_HASH512_SIZE     64 /* 512 bits (64 bytes) */

/* Return Status Codes */
#define CV_HASH_SUCCESS      0
#define CV_HASH_ERR_INVALID -1
#define CV_HASH_ERR_MODE    -2
#define CV_HASH_ERR_IO      -3
#define CV_HASH_ERR_SELFTEST -4

/**
 * @brief Streaming cryptographic hash context.
 */
typedef struct {
    cv_sponge_t sponge;
    uint64_t    total_bytes;
    size_t      digest_len;
} cv_hash_ctx_t;

/**
 * @brief Initialize a 256-bit or 512-bit cryptographic hash stream.
 *
 * @param ctx Pointer to hash context to initialize.
 * @param digest_len Requested output size (CV_HASH256_SIZE or CV_HASH512_SIZE).
 * @return 0 on success, negative error code on failure.
 */
int cv_hash_init(cv_hash_ctx_t *ctx, size_t digest_len);

/**
 * @brief Update hash state with incoming chunk data.
 *
 * @param ctx Pointer to initialized hash context.
 * @param data Input byte buffer.
 * @param len Number of bytes.
 * @return 0 on success, negative error code on failure.
 */
int cv_hash_update(cv_hash_ctx_t *ctx, const void *data, size_t len);

/**
 * @brief Finalize and squeeze the cryptographic digest.
 *
 * @param ctx Pointer to hash context.
 * @param digest_out Destination buffer receiving the digest.
 * @return 0 on success, negative error code on failure.
 */
int cv_hash_final(cv_hash_ctx_t *ctx, uint8_t *digest_out);

/**
 * @brief One-shot 256-bit cryptographic hash.
 *
 * @param data Input byte buffer.
 * @param len Number of bytes.
 * @param digest Output array receiving 32-byte digest.
 * @return 0 on success, negative error code on failure.
 */
int cv_hash256(const void *data, size_t len, uint8_t digest[CV_HASH256_SIZE]);

/**
 * @brief One-shot 512-bit cryptographic hash.
 *
 * @param data Input byte buffer.
 * @param len Number of bytes.
 * @param digest Output array receiving 64-byte digest.
 * @return 0 on success, negative error code on failure.
 */
int cv_hash512(const void *data, size_t len, uint8_t digest[CV_HASH512_SIZE]);

/**
 * @brief Compute cryptographic hash of a file on disk.
 *
 * @param path File system path to target file.
 * @param digest Output array receiving 32-byte hash.
 * @return 0 on success, negative error code on I/O error.
 */
int cv_hash_file(const char *path, uint8_t digest[CV_HASH256_SIZE]);

/**
 * @brief Execute Known-Answer Test and sanity check on hash subsystem.
 *
 * @return 0 on success, negative error code on failure.
 */
int cv_hash_self_test(void);

/**
 * @brief General sponge hash helper for variable digest lengths.
 *
 * @param data Input byte buffer.
 * @param len Input length.
 * @param digest Output digest buffer.
 * @param digest_len Requested output digest size.
 * @return 0 on success, negative code on error.
 */
static inline int cv_sponge_hash(const void *data, size_t len, uint8_t *digest, size_t digest_len) {
    if (digest_len == CV_HASH256_SIZE) {
        return cv_hash256(data, len, digest);
    } else if (digest_len == CV_HASH512_SIZE) {
        return cv_hash512(data, len, digest);
    } else {
        cv_hash_ctx_t ctx;
        if (cv_hash_init(&ctx, digest_len > 32 ? CV_HASH512_SIZE : CV_HASH256_SIZE) != 0) {
            return -1;
        }
        cv_hash_update(&ctx, data, len);
        uint8_t full_digest[CV_HASH512_SIZE];
        int ret = cv_hash_final(&ctx, full_digest);
        if (ret == 0) {
            size_t copy_len = (digest_len < CV_HASH512_SIZE) ? digest_len : CV_HASH512_SIZE;
            for (size_t i = 0; i < copy_len; i++) {
                digest[i] = full_digest[i];
            }
        }
        return ret;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SPONGE_HASH_H */
