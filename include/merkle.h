/**
 * @file merkle.h
 * @brief Binary Merkle Tree Integrity Verification & Random-Access Block Authentication.
 *
 * ============================================================================
 * CryptoVault Merkle Tree Verification Subsystem
 * ============================================================================
 *
 * This subsystem implements cryptographic Merkle tree structures over chunked
 * file streams, providing:
 * 1. O(log N) Authentication Paths: Allows arbitrary 1 MiB chunks to be verified
 *    and decrypted in constant memory without reading the entire multi-gigabyte file.
 * 2. Corruption Localization: Instantly pinpoints the exact chunk index that
 *    suffered bit rot or adversarial tampering.
 * 3. Domain Separation: Prevents second-preimage attacks via distinct domain prefixes
 *    for leaf nodes (0x00) and interior nodes (0x01).
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MERKLE_H
#define MERKLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_MERKLE_HASH_SIZE    32
#define CV_MERKLE_MAX_DEPTH    32 /* Supports up to 2^32 chunks (4 Petabytes at 1 MiB/chunk) */

/* Return Status Codes */
#define CV_MERKLE_SUCCESS       0
#define CV_MERKLE_ERR_PARAM    -1
#define CV_MERKLE_ERR_ALLOC    -2
#define CV_MERKLE_ERR_CORRUPT  -3
#define CV_MERKLE_ERR_DEPTH    -4
#define CV_MERKLE_ERR_EMPTY    -5

/**
 * @brief Complete in-memory binary Merkle tree descriptor.
 */
typedef struct {
    size_t   num_leaves;                         /* Number of chunk leaf hashes */
    size_t   total_nodes;                        /* Total nodes in binary tree */
    uint8_t *nodes;                              /* Contiguous array of 32-byte digests */
    uint8_t  root[CV_MERKLE_HASH_SIZE];          /* Top-level Merkle root */
} cv_merkle_tree_t;

/**
 * @brief Logarithmic authentication path (Merkle proof) for an individual chunk.
 */
typedef struct {
    uint64_t chunk_index;                        /* Target chunk index */
    size_t   depth;                              /* Number of sibling hashes */
    uint8_t  siblings[CV_MERKLE_MAX_DEPTH][CV_MERKLE_HASH_SIZE];
} cv_merkle_proof_t;

/**
 * @brief Construct a complete Merkle tree over an array of chunk tags/digests.
 *
 * @param chunk_tags  Array of 32-byte chunk authentication tags or digests.
 * @param num_chunks  Total number of chunks (must be >= 1).
 * @param tree_out    Pointer to allocated tree structure.
 * @return CV_MERKLE_SUCCESS on success, negative error code on failure.
 */
int cv_merkle_build(const uint8_t *chunk_tags, size_t num_chunks, cv_merkle_tree_t *tree_out);

/**
 * @brief Release all resources allocated for a Merkle tree.
 *
 * @param tree Pointer to tree structure.
 */
void cv_merkle_free(cv_merkle_tree_t *tree);

/**
 * @brief Retrieve the 32-byte Merkle root digest.
 *
 * @param tree      Pointer to valid tree.
 * @param root_out  Destination buffer receiving 32-byte root hash.
 * @return CV_MERKLE_SUCCESS on success, negative error code on failure.
 */
int cv_merkle_get_root(const cv_merkle_tree_t *tree, uint8_t root_out[CV_MERKLE_HASH_SIZE]);

/**
 * @brief Generate an O(log N) Merkle authentication proof for a specific chunk.
 *
 * @param tree         Pointer to valid tree.
 * @param chunk_index  Index of target chunk [0, num_leaves - 1].
 * @param proof_out    Output structure populated with sibling hashes.
 * @return CV_MERKLE_SUCCESS on success, negative error code on failure.
 */
int cv_merkle_gen_proof(const cv_merkle_tree_t *tree, uint64_t chunk_index, cv_merkle_proof_t *proof_out);

/**
 * @brief Verify a chunk against a known Merkle root using only its logarithmic proof.
 * Does NOT require having the rest of the tree or other chunks in memory.
 *
 * @param expected_root  32-byte authentic Merkle root.
 * @param chunk_tag      32-byte authentication tag of the chunk.
 * @param proof          Merkle authentication proof for this chunk.
 * @return CV_MERKLE_SUCCESS if authentic, CV_MERKLE_ERR_CORRUPT on forgery.
 */
int cv_merkle_verify_proof(const uint8_t expected_root[CV_MERKLE_HASH_SIZE],
                           const uint8_t chunk_tag[CV_MERKLE_HASH_SIZE],
                           const cv_merkle_proof_t *proof);

/**
 * @brief Pinpoint the exact chunk indices that fail verification against an authentic root.
 *
 * @param tree           Computed tree from current (potentially corrupted) file.
 * @param expected_root  Authentic root stored in manifest or header.
 * @param bad_indices    Array receiving indices of corrupted chunks.
 * @param max_bad        Capacity of bad_indices array.
 * @param num_bad_out    Receives count of detected corrupted chunks.
 * @return CV_MERKLE_SUCCESS on success, negative error code on failure.
 */
int cv_merkle_locate_corruption(const cv_merkle_tree_t *tree,
                                const uint8_t expected_root[CV_MERKLE_HASH_SIZE],
                                uint64_t *bad_indices, size_t max_bad, size_t *num_bad_out);

/**
 * @brief Self-test routine verifying Merkle construction, proofs, and corruption detection.
 *
 * @return CV_MERKLE_SUCCESS on success, negative error code on failure.
 */
int cv_merkle_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* MERKLE_H */
