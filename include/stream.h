/**
 * @file stream.h
 * @brief 1 MiB Base Chunked Streaming & Ratcheted Sponge Tamper-Proofing Engine.
 *
 * ============================================================================
 * CryptoVault High-Throughput 1 MiB Chunked Streaming Architecture
 * ============================================================================
 *
 * This subsystem performs secure authenticated streaming encryption of arbitrarily
 * large documents and multimedia files using a constant-memory 1 MiB chunked pipeline.
 *
 * ARCHITECTURAL SPECIFICATION:
 * 1. 1 MiB Base Processing Window:
 *    - Chunk payload size: CV_CHUNK_SIZE = 1,048,576 bytes (1 MiB).
 *    - Memory ceiling: At no point is the entire file held in memory. Both encryption
 *      and decryption stream through a strictly bounded ~2 MiB working buffer,
 *      supporting multi-terabyte datasets on embedded or low-RAM environments.
 *
 * 2. Cascaded Dual-Layer Symmetric Cipher:
 *    - Layer 1 (Inner): 32-round SP-ARX-256 in CTR mode with per-chunk counter offset.
 *    - Layer 2 (Outer): 512-bit wide sponge duplex stream cipher.
 *    - Both layers utilize independent keys (k_enc and k_cascade) derived from the
 *      1 MiB base memory-hard KDF.
 *
 * 3. Ratcheted Chained Sponge Authentication:
 *    - Each chunk authentication tag incorporates the preceding chunk's tag:
 *          T_0 = MAC(k_mac, "STREAM_INIT" || Salt || Nonce || AAD)
 *          T_i = MAC(k_mac, T_{i-1} || Chunk_Index_i || Is_Last_Flag || Ciphertext_i)
 *    - This ratchet structure forms an unforgeable cryptographic hash chain:
 *      * Insertion of rogue chunks breaks the chain.
 *      * Deletion or truncation of chunks causes the final tag verification to fail.
 *      * Reordering or swapping chunks invalidates both the chunk index and predecessor tag.
 *
 * 4. Fail-Secure Atomic Abort:
 *    - If any chunk fails authentication during decryption:
 *      a) The destination output file is immediately closed.
 *      b) The file on disk is deleted via unlink(2).
 *      c) All in-memory plaintext buffers and keys are securely zeroized.
 *      No partial or unauthenticated plaintext is ever left on disk!
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef STREAM_H
#define STREAM_H

#include "aead.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 1 MiB Base Chunk Dimension */
#define CV_CHUNK_SIZE           (1024 * 1024) /* 1,048,576 bytes (1 MiB) */
#define CV_STREAM_TAG_SIZE      32            /* 256-bit authentication tag */

/* Return Status Codes */
#define CV_STREAM_SUCCESS        0
#define CV_STREAM_ERR_INVALID   -1
#define CV_STREAM_ERR_IO        -2
#define CV_STREAM_ERR_HEADER    -3
#define CV_STREAM_ERR_CORRUPT   -4
#define CV_STREAM_ERR_MEMORY    -5

/**
 * @brief Streaming diagnostic callback structure for tracking progress.
 */
typedef struct {
    uint64_t total_bytes_processed;
    uint32_t current_chunk_index;
    uint32_t total_estimated_chunks;
    double   throughput_mbps;
} cv_stream_progress_t;

/**
 * @brief Encrypt a document or file using 1 MiB chunked streaming AEAD
 * with a ratcheted sponge tamper-proof authentication chain.
 *
 * @param in_path         Source file path (e.g. document.pdf).
 * @param out_path        Destination encrypted path (e.g. document.pdf.cvlt).
 * @param secret          Password string or 32-byte key.
 * @param secret_len      Length of password or key.
 * @param is_passphrase   1 if human password, 0 if raw 256-bit key.
 * @param aad             Optional associated metadata to authenticate.
 * @param aad_len         Length of AAD.
 * @param mem_cost_kb     KDF memory parameter (default: 1024 for 1 MiB base).
 * @param time_cost       KDF iterations (default: 4).
 * @return 0 on success, negative error code on failure.
 */
int cv_file_encrypt(const char *in_path, const char *out_path,
                    const void *secret, size_t secret_len, int is_passphrase,
                    const uint8_t *aad, size_t aad_len,
                    uint32_t mem_cost_kb, uint32_t time_cost);

/**
 * @brief Decrypt and authenticate a document or file using 1 MiB chunked streaming AEAD.
 * Enforces fail-secure automatic file deletion if any chunk tampering or truncation is detected.
 *
 * @param in_path         Encrypted file path (e.g. document.pdf.cvlt).
 * @param out_path        Destination restored file path (e.g. document_dec.pdf).
 * @param secret          Password string or 32-byte key.
 * @param secret_len      Length of password or key.
 * @param is_passphrase   1 if human password, 0 if raw 256-bit key.
 * @param expected_aad    Expected associated metadata.
 * @param aad_len         Length of expected AAD.
 * @return 0 on success, negative error code on failure.
 */
int cv_file_decrypt(const char *in_path, const char *out_path,
                    const void *secret, size_t secret_len, int is_passphrase,
                    const uint8_t *expected_aad, size_t aad_len);

/**
 * @brief Inspect container headers and metadata of an encrypted .cvlt file.
 *
 * @param path    Path to encrypted .cvlt file.
 * @param hdr_out Destination structure receiving validated header metadata.
 * @return 0 on success, negative code on invalid header magic or checksum.
 */
int cv_file_inspect(const char *path, cv_header_t *hdr_out);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_H */
