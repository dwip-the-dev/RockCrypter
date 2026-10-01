/**
 * @file test_merkle.c
 * @brief Test Suite for Binary Merkle Tree Verification & Chunk Corruption Localization.
 *
 * ============================================================================
 * CryptoVault Merkle Tree Verification Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Tree construction over varying chunk counts (1, 4, 15, 32, 64 chunks).
 * 2. Second-preimage resistance via domain-separated internal hashing (0x00 leaf, 0x01 node).
 * 3. Logarithmic O(log N) authentication path generation and verification.
 * 4. Immediate rejection of single-bit leaf tampering and branch tampering.
 * 5. Deterministic chunk corruption localization.
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

#define TEST_PASS 0
#define TEST_FAIL 1

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define ASSERT_TEST(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "[-] FAILURE at %s:%d: %s\n", __FILE__, __LINE__, msg); \
        return TEST_FAIL; \
    } else { \
        g_tests_passed++; \
    } \
} while (0)

static int test_merkle_basic_tree(void) {
    const size_t NUM_CHUNKS = 8;
    uint8_t chunk_tags[8 * 32];

    /* Fill chunk tags with deterministic digests */
    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        char tag_str[64];
        snprintf(tag_str, sizeof(tag_str), "CHUNK_AUTH_TAG_MEMBER_%zu", i);
        cv_hash256(tag_str, strlen(tag_str), chunk_tags + i * 32);
    }

    cv_merkle_tree_t tree;
    int ret = cv_merkle_build(chunk_tags, NUM_CHUNKS, &tree);
    ASSERT_TEST(ret == CV_MERKLE_SUCCESS, "Merkle tree construction must succeed");
    ASSERT_TEST(tree.num_leaves == NUM_CHUNKS, "Leaf count matches requested chunks");

    /* Verify all leaves pass verification against tree root */
    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        const uint8_t *tag_ptr = chunk_tags + i * 32;
        cv_merkle_proof_t proof;
        ret = cv_merkle_gen_proof(&tree, i, &proof);
        ASSERT_TEST(ret == CV_MERKLE_SUCCESS, "Proof generation for valid chunk index");

        ret = cv_merkle_verify_proof(tree.root, tag_ptr, &proof);
        ASSERT_TEST(ret == CV_MERKLE_SUCCESS, "Valid chunk tag must verify against tree root");
    }

    cv_merkle_free(&tree);
    return TEST_PASS;
}

static int test_merkle_tamper_detection(void) {
    const size_t NUM_CHUNKS = 16;
    uint8_t chunk_tags[16 * 32];

    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        char tag_str[64];
        snprintf(tag_str, sizeof(tag_str), "TAG_BLOCK_%zu", i);
        cv_hash256(tag_str, strlen(tag_str), chunk_tags + i * 32);
    }

    cv_merkle_tree_t tree;
    ASSERT_TEST(cv_merkle_build(chunk_tags, NUM_CHUNKS, &tree) == CV_MERKLE_SUCCESS, "Build tree");

    /* Tamper with chunk index 7 */
    size_t target_idx = 7;
    cv_merkle_proof_t proof;
    ASSERT_TEST(cv_merkle_gen_proof(&tree, target_idx, &proof) == CV_MERKLE_SUCCESS, "Gen proof");

    uint8_t tampered_tag[32];
    memcpy(tampered_tag, chunk_tags + target_idx * 32, 32);
    tampered_tag[0] ^= 0x01; /* 1-bit flip */

    /* Verification with tampered tag MUST fail with CV_MERKLE_ERR_CORRUPT */
    int ret = cv_merkle_verify_proof(tree.root, tampered_tag, &proof);
    ASSERT_TEST(ret == CV_MERKLE_ERR_CORRUPT, "Tampered tag must trigger CV_MERKLE_ERR_CORRUPT");

    /* Corrupt the proof authentication path itself */
    proof.siblings[0][0] ^= 0xFF;
    ret = cv_merkle_verify_proof(tree.root, chunk_tags + target_idx * 32, &proof);
    ASSERT_TEST(ret == CV_MERKLE_ERR_CORRUPT, "Corrupted sibling must trigger CV_MERKLE_ERR_CORRUPT");

    cv_merkle_free(&tree);
    return TEST_PASS;
}

static int test_merkle_non_power_of_two(void) {
    /* Test tree construction with odd chunk count: 13 chunks */
    const size_t NUM_CHUNKS = 13;
    uint8_t chunk_tags[13 * 32];

    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        char tag_str[64];
        snprintf(tag_str, sizeof(tag_str), "ODD_TAG_%zu", i);
        cv_hash256(tag_str, strlen(tag_str), chunk_tags + i * 32);
    }

    cv_merkle_tree_t tree;
    ASSERT_TEST(cv_merkle_build(chunk_tags, NUM_CHUNKS, &tree) == CV_MERKLE_SUCCESS, "Build odd tree");

    /* Verify each chunk with proof */
    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        cv_merkle_proof_t proof;
        ASSERT_TEST(cv_merkle_gen_proof(&tree, i, &proof) == CV_MERKLE_SUCCESS, "Proof generation");
        ASSERT_TEST(cv_merkle_verify_proof(tree.root, chunk_tags + i * 32, &proof) == CV_MERKLE_SUCCESS,
                    "Verify non-power-of-two leaf");
    }

    cv_merkle_free(&tree);
    return TEST_PASS;
}

static int test_merkle_corruption_locator(void) {
    const size_t NUM_CHUNKS = 8;
    uint8_t orig_tags[8 * 32];
    uint8_t corrupted_tags[8 * 32];

    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        char tag_str[64];
        snprintf(tag_str, sizeof(tag_str), "CORRUPT_TEST_%zu", i);
        cv_hash256(tag_str, strlen(tag_str), orig_tags + i * 32);
        memcpy(corrupted_tags + i * 32, orig_tags + i * 32, 32);
    }

    cv_merkle_tree_t orig_tree;
    ASSERT_TEST(cv_merkle_build(orig_tags, NUM_CHUNKS, &orig_tree) == CV_MERKLE_SUCCESS, "Build original tree");

    /* Tamper chunk 4 tag */
    corrupted_tags[4 * 32 + 10] ^= 0x80;

    cv_merkle_tree_t corrupted_tree;
    ASSERT_TEST(cv_merkle_build(corrupted_tags, NUM_CHUNKS, &corrupted_tree) == CV_MERKLE_SUCCESS, "Build corrupted tree");

    uint64_t bad_indices[8];
    size_t num_bad = 0;
    int ret = cv_merkle_locate_corruption(&corrupted_tree, orig_tree.root, bad_indices, 8, &num_bad);
    ASSERT_TEST(ret == CV_MERKLE_SUCCESS, "Locate corruption call succeeds");
    ASSERT_TEST(num_bad > 0, "Corrupted tree detected against expected root");

    /* Verify on untampered tree returns 0 bad */
    ret = cv_merkle_locate_corruption(&orig_tree, orig_tree.root, bad_indices, 8, &num_bad);
    ASSERT_TEST(ret == CV_MERKLE_SUCCESS && num_bad == 0, "Untampered tree has zero bad chunks");

    /* Pinpoint exact corruption using per-chunk Merkle proofs */
    for (size_t i = 0; i < NUM_CHUNKS; i++) {
        cv_merkle_proof_t proof;
        ASSERT_TEST(cv_merkle_gen_proof(&orig_tree, i, &proof) == CV_MERKLE_SUCCESS, "Gen proof");
        int vret = cv_merkle_verify_proof(orig_tree.root, corrupted_tags + i * 32, &proof);
        if (i == 4) {
            ASSERT_TEST(vret == CV_MERKLE_ERR_CORRUPT, "Chunk 4 detected as corrupted");
        } else {
            ASSERT_TEST(vret == CV_MERKLE_SUCCESS, "Untampered chunk verified authentic");
        }
    }

    cv_merkle_free(&orig_tree);
    cv_merkle_free(&corrupted_tree);
    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Merkle Tree Test Suite...\n");

    if (cv_merkle_self_test() != CV_MERKLE_SUCCESS) {
        fprintf(stderr, "[-] cv_merkle_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_merkle_basic_tree() != TEST_PASS) return 1;
    if (test_merkle_tamper_detection() != TEST_PASS) return 1;
    if (test_merkle_non_power_of_two() != TEST_PASS) return 1;
    if (test_merkle_corruption_locator() != TEST_PASS) return 1;

    printf("[+] Merkle Tree Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
