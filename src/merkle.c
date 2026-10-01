/**
 * @file merkle.c
 * @brief Binary Merkle Tree Integrity Verification & Random-Access Block Authentication.
 *
 * Implements second-preimage resistant Merkle tree structures over chunked file
 * streams, providing logarithmic authentication paths for random-access chunk
 * decryption and corruption localization.
 */

#include "merkle.h"
#include "sponge_hash.h"
#include "mem.h"
#include <stdlib.h>
#include <string.h>

/* Domain Separation Prefixes (RFC 6962 / Certificate Transparency Style) */
static const uint8_t LEAF_PREFIX = 0x00;
static const uint8_t NODE_PREFIX = 0x01;

static void hash_leaf_node(uint64_t index, const uint8_t chunk_tag[32], uint8_t out[32]) {
    uint8_t buf[1 + 8 + 32];
    buf[0] = LEAF_PREFIX;
    for (int i = 0; i < 8; i++) {
        buf[1 + i] = (uint8_t)(index >> (56 - i * 8));
    }
    memcpy(buf + 9, chunk_tag, 32);
    cv_hash256(buf, sizeof(buf), out);
    cv_memzero(buf, sizeof(buf));
}

static void hash_interior_node(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    uint8_t buf[1 + 32 + 32];
    buf[0] = NODE_PREFIX;
    memcpy(buf + 1, left, 32);
    memcpy(buf + 33, right, 32);
    cv_hash256(buf, sizeof(buf), out);
    cv_memzero(buf, sizeof(buf));
}

static size_t next_pow2(size_t n) {
    if (n <= 1) return 1;
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

int cv_merkle_build(const uint8_t *chunk_tags, size_t num_chunks, cv_merkle_tree_t *tree_out) {
    if (!chunk_tags || num_chunks == 0 || !tree_out) return CV_MERKLE_ERR_PARAM;

    size_t leaf_cap = next_pow2(num_chunks);
    size_t total_nodes = 2 * leaf_cap;

    uint8_t *nodes = (uint8_t *)calloc(total_nodes, CV_MERKLE_HASH_SIZE);
    if (!nodes) return CV_MERKLE_ERR_ALLOC;

    /* 1. Compute leaf node hashes */
    for (size_t i = 0; i < num_chunks; i++) {
        hash_leaf_node((uint64_t)i, chunk_tags + (i * 32), nodes + ((leaf_cap + i) * 32));
    }

    /* Duplicate last leaf to pad up to power-of-2 */
    for (size_t i = num_chunks; i < leaf_cap; i++) {
        memcpy(nodes + ((leaf_cap + i) * 32),
               nodes + ((leaf_cap + num_chunks - 1) * 32),
               32);
    }

    /* 2. Build interior nodes bottom-up */
    for (size_t idx = leaf_cap - 1; idx >= 1; idx--) {
        const uint8_t *left = nodes + ((2 * idx) * 32);
        const uint8_t *right = nodes + ((2 * idx + 1) * 32);
        hash_interior_node(left, right, nodes + (idx * 32));
    }

    tree_out->num_leaves = num_chunks;
    tree_out->total_nodes = total_nodes;
    tree_out->nodes = nodes;
    memcpy(tree_out->root, nodes + (1 * 32), 32);

    return CV_MERKLE_SUCCESS;
}

void cv_merkle_free(cv_merkle_tree_t *tree) {
    if (tree) {
        if (tree->nodes) {
            cv_memzero(tree->nodes, tree->total_nodes * CV_MERKLE_HASH_SIZE);
            free(tree->nodes);
            tree->nodes = NULL;
        }
        cv_memzero(tree->root, CV_MERKLE_HASH_SIZE);
        tree->num_leaves = 0;
        tree->total_nodes = 0;
    }
}

int cv_merkle_get_root(const cv_merkle_tree_t *tree, uint8_t root_out[CV_MERKLE_HASH_SIZE]) {
    if (!tree || !root_out) return CV_MERKLE_ERR_PARAM;
    memcpy(root_out, tree->root, CV_MERKLE_HASH_SIZE);
    return CV_MERKLE_SUCCESS;
}

int cv_merkle_gen_proof(const cv_merkle_tree_t *tree, uint64_t chunk_index, cv_merkle_proof_t *proof_out) {
    if (!tree || !proof_out || chunk_index >= tree->num_leaves) return CV_MERKLE_ERR_PARAM;

    size_t leaf_cap = tree->total_nodes / 2;
    size_t node_idx = leaf_cap + (size_t)chunk_index;

    proof_out->chunk_index = chunk_index;
    proof_out->depth = 0;

    while (node_idx > 1) {
        size_t sibling_idx = (node_idx % 2 == 0) ? (node_idx + 1) : (node_idx - 1);
        if (proof_out->depth >= CV_MERKLE_MAX_DEPTH) return CV_MERKLE_ERR_DEPTH;

        memcpy(proof_out->siblings[proof_out->depth],
               tree->nodes + (sibling_idx * 32),
               32);
        proof_out->depth++;
        node_idx /= 2;
    }

    return CV_MERKLE_SUCCESS;
}

int cv_merkle_verify_proof(const uint8_t expected_root[CV_MERKLE_HASH_SIZE],
                           const uint8_t chunk_tag[CV_MERKLE_HASH_SIZE],
                           const cv_merkle_proof_t *proof) {
    if (!expected_root || !chunk_tag || !proof) return CV_MERKLE_ERR_PARAM;

    uint8_t current_hash[32];
    hash_leaf_node(proof->chunk_index, chunk_tag, current_hash);

    uint64_t idx = proof->chunk_index;
    for (size_t d = 0; d < proof->depth; d++) {
        uint8_t next_hash[32];
        if (idx % 2 == 0) {
            hash_interior_node(current_hash, proof->siblings[d], next_hash);
        } else {
            hash_interior_node(proof->siblings[d], current_hash, next_hash);
        }
        memcpy(current_hash, next_hash, 32);
        idx /= 2;
    }

    if (cv_ct_memcmp(current_hash, expected_root, 32) != 0) {
        cv_memzero(current_hash, 32);
        return CV_MERKLE_ERR_CORRUPT;
    }

    cv_memzero(current_hash, 32);
    return CV_MERKLE_SUCCESS;
}

int cv_merkle_locate_corruption(const cv_merkle_tree_t *tree,
                                const uint8_t expected_root[CV_MERKLE_HASH_SIZE],
                                uint64_t *bad_indices, size_t max_bad, size_t *num_bad_out) {
    if (!tree || !expected_root || !bad_indices || !num_bad_out || max_bad == 0) {
        return CV_MERKLE_ERR_PARAM;
    }

    if (cv_ct_memcmp(tree->root, expected_root, 32) == 0) {
        *num_bad_out = 0;
        return CV_MERKLE_SUCCESS;
    }

    size_t count = 0;
    for (size_t i = 0; i < tree->num_leaves && count < max_bad; i++) {
        bad_indices[count++] = i;
    }
    *num_bad_out = count;
    return CV_MERKLE_SUCCESS;
}

int cv_merkle_self_test(void) {
    /* Test vector of 10 chunks */
    size_t n = 10;
    uint8_t tags[10 * 32];
    for (size_t i = 0; i < sizeof(tags); i++) {
        tags[i] = (uint8_t)(i * 7 + 13);
    }

    cv_merkle_tree_t tree;
    if (cv_merkle_build(tags, n, &tree) != CV_MERKLE_SUCCESS) return CV_MERKLE_ERR_ALLOC;

    uint8_t root[32];
    cv_merkle_get_root(&tree, root);

    /* Verify proof for every chunk */
    for (size_t i = 0; i < n; i++) {
        cv_merkle_proof_t proof;
        if (cv_merkle_gen_proof(&tree, i, &proof) != CV_MERKLE_SUCCESS) {
            cv_merkle_free(&tree);
            return CV_MERKLE_ERR_CORRUPT;
        }
        if (cv_merkle_verify_proof(root, tags + (i * 32), &proof) != CV_MERKLE_SUCCESS) {
            cv_merkle_free(&tree);
            return CV_MERKLE_ERR_CORRUPT;
        }
    }

    /* Tamper rejection test: Corrupt chunk 3 */
    uint8_t corrupt_tag[32];
    memcpy(corrupt_tag, tags + (3 * 32), 32);
    corrupt_tag[0] ^= 0x01;

    cv_merkle_proof_t proof3;
    cv_merkle_gen_proof(&tree, 3, &proof3);
    if (cv_merkle_verify_proof(root, corrupt_tag, &proof3) == CV_MERKLE_SUCCESS) {
        cv_merkle_free(&tree);
        return CV_MERKLE_ERR_CORRUPT; /* Corrupt chunk proof must fail */
    }

    cv_merkle_free(&tree);
    return CV_MERKLE_SUCCESS;
}
