/**
 * @file atomic.h
 * @brief Crash-Safe Writes, Atomic File Replacement & Huge-File Random-Access.
 *
 * ============================================================================
 * CryptoVault Crash-Safe Storage & Atomic Transaction Subsystem
 * ============================================================================
 *
 * This subsystem guarantees data integrity under sudden power loss, OS crashes,
 * and concurrent read access:
 * 1. ACID-Like Atomic File Replacement: Encrypted outputs are staged in an
 *    ephemeral scratch file on the same filesystem, flushed to physical disk
 *    via fsync(2), and atomically swapped using POSIX rename(2).
 * 2. Automatic Crash Rollback: If an interruption or authentication failure occurs,
 *    temporary staging files are unlinked immediately; existing authentic files
 *    are NEVER partially overwritten or truncated.
 * 3. 64-Bit Huge File Support: Uses 64-bit stream offsets (off_t / fseeko) to
 *    seamlessly navigate multi-gigabyte and multi-terabyte datasets.
 * 4. Random-Access Chunk Decryption: Decrypts an individual 1 MiB chunk at arbitrary
 *    64-bit file offsets in O(1) time without processing preceding chunks.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef ATOMIC_H
#define ATOMIC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return Status Codes */
#define CV_ATOMIC_SUCCESS        0
#define CV_ATOMIC_ERR_PARAM     -1
#define CV_ATOMIC_ERR_IO        -2
#define CV_ATOMIC_ERR_SYNC      -3
#define CV_ATOMIC_ERR_RENAME    -4
#define CV_ATOMIC_ERR_SEEK      -5
#define CV_ATOMIC_ERR_SELFTEST  -6

/**
 * @brief Atomic transaction descriptor for staged file writes.
 */
typedef struct {
    char   target_path[512];                     /* Final destination path */
    char   temp_path[540];                       /* Staged temporary path */
    FILE  *file_handle;                          /* Open file stream */
    int    is_open;                              /* 1 if active, 0 otherwise */
} cv_atomic_file_t;

/**
 * @brief Begin an atomic write transaction for destination file.
 * Staging file is created in the same directory to ensure same-filesystem rename.
 *
 * @param af          Pointer to atomic file descriptor.
 * @param destination Final destination path.
 * @return CV_ATOMIC_SUCCESS on success, negative error code on failure.
 */
int cv_atomic_begin(cv_atomic_file_t *af, const char *destination);

/**
 * @brief Write data buffer to staged atomic transaction stream.
 *
 * @param af   Pointer to active atomic file.
 * @param buf  Data buffer to write.
 * @param len  Length of data buffer.
 * @return CV_ATOMIC_SUCCESS on success, CV_ATOMIC_ERR_IO on failure.
 */
int cv_atomic_write(cv_atomic_file_t *af, const void *buf, size_t len);

/**
 * @brief Flush file buffers to physical storage media (fsync) and atomically rename.
 * Guarantees that either the complete new file is visible or the original is untouched.
 *
 * @param af Pointer to active atomic file.
 * @return CV_ATOMIC_SUCCESS on success, negative error code on failure.
 */
int cv_atomic_commit(cv_atomic_file_t *af);

/**
 * @brief Abort atomic transaction, close stream, and unlink temporary staging file.
 *
 * @param af Pointer to atomic file.
 */
void cv_atomic_abort(cv_atomic_file_t *af);

/**
 * @brief Calculate exact 64-bit file byte offset for a specific chunk index.
 *
 * @param chunk_index       Zero-based chunk index.
 * @param header_size_bytes Total bytes in envelope header.
 * @param chunk_size_bytes  Payload bytes per chunk (e.g. 1048576).
 * @param tag_size_bytes    Tag overhead bytes per chunk (e.g. 32).
 * @return Exact 64-bit file offset.
 */
uint64_t cv_calc_chunk_offset(uint64_t chunk_index,
                              size_t header_size_bytes,
                              size_t chunk_size_bytes,
                              size_t tag_size_bytes);

/**
 * @brief Random-access chunk reader: reads exactly one encrypted chunk and its tag
 * at arbitrary 64-bit offset without sequential iteration.
 *
 * @param file_path         Path to encrypted .cvlt file.
 * @param chunk_offset      64-bit byte offset calculated via cv_calc_chunk_offset.
 * @param chunk_buf         Buffer receiving raw encrypted chunk payload.
 * @param chunk_size        Expected payload size.
 * @param tag_out           Buffer receiving 32-byte chunk MAC tag.
 * @return CV_ATOMIC_SUCCESS on success, negative error code on failure.
 */
int cv_read_chunk_random_access(const char *file_path,
                                uint64_t chunk_offset,
                                uint8_t *chunk_buf,
                                size_t chunk_size,
                                uint8_t tag_out[32]);

/**
 * @brief Self-test verifying atomic write rollback, commit, and 64-bit chunk offsets.
 *
 * @return CV_ATOMIC_SUCCESS on success, negative code on failure.
 */
int cv_atomic_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* ATOMIC_H */
