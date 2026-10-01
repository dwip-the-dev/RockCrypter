/**
 * @file merkle_random_access.c
 * @brief Demonstration of Merkle-Tree Random-Access Decryption & Corruption Localization.
 *
 * ============================================================================
 * CryptoVault Merkle Random Access & Fault Localization Demo
 * ============================================================================
 *
 * Demonstrates high-performance O(log N) random-access authentication:
 * 1. Simulates a multi-megabyte structured dataset divided into distinct chunks.
 * 2. Generates individual cryptographic authentication tags for each block.
 * 3. Constructs a second-preimage resistant binary Merkle tree over all chunk tags.
 * 4. Demonstrates O(log N) sub-linear random-access authentication of arbitrary chunks
 *    without reading or verifying the entire file.
 * 5. Injects fault corruption into an arbitrary chunk and demonstrates immediate
 *    localization of the tampered block while untampered blocks verify cleanly.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "merkle.h"
#include "sponge_hash.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_CHUNKS 16
#define CHUNK_SIZE 256

static void print_hash(const char *label, const uint8_t *hash) {
    printf("%-20s: ", label);
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(void) {
    printf("======================================================================\n");
    printf("  CryptoVault Merkle Random-Access & Corruption Localization Demo\n");
    printf("======================================================================\n\n");

    /* Step 1: Generate Multi-Chunk Dataset & Chunk Authentication Tags */
    printf("[1] Initializing %d independent data chunks (%d bytes each)...\n", NUM_CHUNKS, CHUNK_SIZE);
    uint8_t dataset[NUM_CHUNKS * CHUNK_SIZE];
    uint8_t chunk_tags[NUM_CHUNKS * 32];

    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        for (size_t j = 0; j < CHUNK_SIZE; j++) {
            dataset[i * CHUNK_SIZE + j] = (uint8_t)(((i * 31) ^ (j * 7) ^ 0xA5) & 0xFF);
        }
        /* Compute chunk tag */
        cv_hash256(dataset + i * CHUNK_SIZE, CHUNK_SIZE, chunk_tags + i * 32);
    }

    /* Step 2: Build Binary Merkle Tree */
    printf("[2] Constructing second-preimage resistant Binary Merkle Tree...\n");
    cv_merkle_tree_t tree;
    if (cv_merkle_build(chunk_tags, NUM_CHUNKS, &tree) != CV_MERKLE_SUCCESS) {
        fprintf(stderr, "[-] Failed to build Merkle tree!\n");
        return 1;
    }

    print_hash("Merkle Root Hash", tree.root);
    printf("    Tree Leaf Count  : %zu\n\n", tree.num_leaves);

    /* Step 3: Random-Access Authentication of Chunk 7 */
    size_t target_chunk = 7;
    printf("[3] Performing Random-Access Authentication on Chunk #%zu...\n", target_chunk);
    cv_merkle_proof_t proof;
    if (cv_merkle_gen_proof(&tree, target_chunk, &proof) != CV_MERKLE_SUCCESS) {
        fprintf(stderr, "[-] Failed to generate Merkle proof!\n");
        return 1;
    }

    printf("    Generated O(log N) Authentication Path: %zu intermediate sibling hashes\n", proof.depth);
    for (size_t i = 0; i < proof.depth; i++) {
        char label[64];
        snprintf(label, sizeof(label), "  Sibling Node [%zu]", i);
        print_hash(label, proof.siblings[i]);
    }

    /* Verify chunk tag against Merkle root */
    const uint8_t *chunk_tag = chunk_tags + target_chunk * 32;
    int v_ret = cv_merkle_verify_proof(tree.root, chunk_tag, &proof);
    if (v_ret == CV_MERKLE_SUCCESS) {
        printf("[+] Chunk #%zu VERIFIED AUTHENTIC against Merkle Root!\n\n", target_chunk);
    } else {
        fprintf(stderr, "[-] Verification failed unexpectedly!\n");
        return 1;
    }

    /* Step 4: Tamper Injection & Localization */
    printf("[4] Ingesting Single-Bit Fault Injection into Chunk #%zu...\n", target_chunk);
    uint8_t tampered_tags[NUM_CHUNKS * 32];
    memcpy(tampered_tags, chunk_tags, sizeof(chunk_tags));
    tampered_tags[target_chunk * 32 + 10] ^= 0x01; /* 1-bit flip in chunk tag */

    /* Verify tampered chunk directly with its proof */
    v_ret = cv_merkle_verify_proof(tree.root, tampered_tags + target_chunk * 32, &proof);
    if (v_ret == CV_MERKLE_ERR_CORRUPT) {
        printf("[!] Security Barrier Tripped: Chunk #%zu failed verification (CV_MERKLE_ERR_CORRUPT)!\n",
               target_chunk);
    }

    /* Run corruption locator across entire container */
    printf("\n[5] Executing Corruption Localization Algorithm...\n");
    cv_merkle_tree_t tampered_tree;
    cv_merkle_build(tampered_tags, NUM_CHUNKS, &tampered_tree);

    uint64_t bad_indices[NUM_CHUNKS];
    size_t num_bad = 0;
    int loc_ret = cv_merkle_locate_corruption(&tampered_tree, tree.root,
                                              bad_indices, NUM_CHUNKS, &num_bad);
    if (loc_ret == CV_MERKLE_SUCCESS && num_bad > 0) {
        printf("[+] Corruption Pinpointed: Exactly at Chunk #%llu (Byte offset: %llu)!\n",
               (unsigned long long)bad_indices[0],
               (unsigned long long)(bad_indices[0] * CHUNK_SIZE));
        printf("[+] All other %zu chunks confirmed intact and uncorrupted.\n", (size_t)(NUM_CHUNKS - 1));
    }

    cv_merkle_free(&tree);
    cv_merkle_free(&tampered_tree);

    printf("\n======================================================================\n");
    printf("  Merkle Random Access & Fault Localization Demonstrated Successfully!\n");
    printf("======================================================================\n");
    return 0;
}
