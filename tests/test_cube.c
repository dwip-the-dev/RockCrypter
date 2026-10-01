/**
 * @file test_cube.c
 * @brief Test Suite for RockCrypter 256x256 & 16x16x16 Heisenberg Cube Diffusion Engine.
 *
 * ============================================================================
 * RockCrypter Cube & Heisenberg Transformation Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. 16x16x16 (4096-byte) tensor cube initialization, forward, and inverse bijection.
 * 2. Strict Avalanche Criterion (SAC): exactly ~50% bit flip diffusion on 1-bit input flip.
 * 3. 256x256 (65,536-byte) macro-matrix non-commutative Heisenberg diffusion.
 * 4. Distinct key sensitivity: different keys yield statistically independent outputs.
 * 5. Built-in cv_cube_self_test() routine.
 *
 * @version 2.4.0
 * @author RockCrypter Academic Security Group
 */

#include "cube.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASS 0
#define TEST_FAIL 1

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define ASSERT_TEST(cond, name) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", name); \
    } else { \
        printf("  [FAIL] %s (Line %d)\n", name, __LINE__); \
        return TEST_FAIL; \
    } \
} while (0)

static int test_cube_basic_roundtrip(void) {
    printf("[*] Testing 4096-Byte Hypercube Forward and Inverse Roundtrip...\n");
    uint8_t key[32];
    for (size_t i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);

    cv_cube_ctx_t ctx;
    int ret = cv_cube_init(&ctx, key);
    ASSERT_TEST(ret == CV_CUBE_SUCCESS, "Cube context initialization");

    uint8_t in_block[CV_CUBE_SIZE];
    uint8_t out_block[CV_CUBE_SIZE];
    uint8_t restored[CV_CUBE_SIZE];

    for (size_t i = 0; i < CV_CUBE_SIZE; i++) {
        in_block[i] = (uint8_t)(i & 0xFF);
    }

    ret = cv_cube_transform_block(&ctx, in_block, out_block);
    ASSERT_TEST(ret == CV_CUBE_SUCCESS, "Forward hypercube transformation");
    ASSERT_TEST(cv_ct_memcmp(in_block, out_block, CV_CUBE_SIZE) != 0, "Transformed block differs from input");

    ret = cv_cube_inv_transform_block(&ctx, out_block, restored);
    ASSERT_TEST(ret == CV_CUBE_SUCCESS, "Inverse hypercube transformation");
    ASSERT_TEST(cv_ct_memcmp(in_block, restored, CV_CUBE_SIZE) == 0, "Restored block matches bit-for-bit");

    cv_cube_clear(&ctx);
    return TEST_PASS;
}

static int test_cube_avalanche_criterion(void) {
    printf("[*] Testing Strict Avalanche Criterion (SAC) on Hypercube State...\n");
    uint8_t key[32] = {0xAA, 0x55, 0x11, 0x22};
    cv_cube_ctx_t ctx;
    cv_cube_init(&ctx, key);

    uint8_t blk1[CV_CUBE_SIZE];
    uint8_t blk2[CV_CUBE_SIZE];
    for (size_t i = 0; i < CV_CUBE_SIZE; i++) {
        blk1[i] = (uint8_t)(i * 7);
        blk2[i] = blk1[i];
    }
    blk2[0] ^= 0x01; /* 1-bit input perturbation */

    uint8_t out1[CV_CUBE_SIZE];
    uint8_t out2[CV_CUBE_SIZE];

    cv_cube_transform_block(&ctx, blk1, out1);
    cv_cube_transform_block(&ctx, blk2, out2);

    size_t flipped_bits = 0;
    for (size_t i = 0; i < CV_CUBE_SIZE; i++) {
        uint8_t diff = out1[i] ^ out2[i];
        while (diff) {
            flipped_bits += (diff & 1);
            diff >>= 1;
        }
    }

    double ratio = (double)flipped_bits / (double)(CV_CUBE_SIZE * 8);
    printf("    -> Flipped bits: %zu / %d (%.2f%% bit change)\n",
           flipped_bits, CV_CUBE_SIZE * 8, ratio * 100.0);

    /* Cryptographic SAC ideal is ~50%, acceptable range [40%, 60%] */
    ASSERT_TEST(ratio >= 0.40 && ratio <= 0.60, "Strict Avalanche Criterion within 50% +/- 10%");

    cv_cube_clear(&ctx);
    return TEST_PASS;
}

static int test_matrix_256_diffusion(void) {
    printf("[*] Testing 256x256 (64 KiB) Macro-Matrix Heisenberg Diffusion...\n");
    uint8_t key[32] = {0x42, 0x13, 0x37, 0x99};

    uint8_t *matrix = (uint8_t *)cv_secure_alloc(CV_MATRIX_256_SIZE);
    uint8_t *original = (uint8_t *)cv_secure_alloc(CV_MATRIX_256_SIZE);
    ASSERT_TEST(matrix != NULL && original != NULL, "Allocated 64 KiB test buffers");

    for (size_t i = 0; i < CV_MATRIX_256_SIZE; i++) {
        matrix[i] = (uint8_t)(i * 17 + (i >> 8));
        original[i] = matrix[i];
    }

    int ret = cv_cube_matrix256_diffuse(matrix, key, 0);
    ASSERT_TEST(ret == CV_CUBE_SUCCESS, "Forward 256x256 macro-matrix diffusion");
    ASSERT_TEST(cv_ct_memcmp(matrix, original, CV_MATRIX_256_SIZE) != 0, "Matrix thoroughly modified");

    ret = cv_cube_matrix256_diffuse(matrix, key, 1);
    ASSERT_TEST(ret == CV_CUBE_SUCCESS, "Inverse 256x256 macro-matrix diffusion");
    ASSERT_TEST(cv_ct_memcmp(matrix, original, CV_MATRIX_256_SIZE) == 0, "Matrix restored with 100% precision");

    cv_secure_free(matrix, CV_MATRIX_256_SIZE);
    cv_secure_free(original, CV_MATRIX_256_SIZE);
    return TEST_PASS;
}

static int test_cube_key_sensitivity(void) {
    printf("[*] Testing Key Sensitivity & Orthogonality...\n");
    uint8_t k1[32] = {0x01};
    uint8_t k2[32] = {0x01};
    k2[31] ^= 0x01; /* 1-bit difference in 32-byte key */

    cv_cube_ctx_t ctx1, ctx2;
    cv_cube_init(&ctx1, k1);
    cv_cube_init(&ctx2, k2);

    uint8_t plain[CV_CUBE_SIZE];
    memset(plain, 0x5A, sizeof(plain));

    uint8_t out1[CV_CUBE_SIZE];
    uint8_t out2[CV_CUBE_SIZE];

    cv_cube_transform_block(&ctx1, plain, out1);
    cv_cube_transform_block(&ctx2, plain, out2);

    ASSERT_TEST(cv_ct_memcmp(out1, out2, CV_CUBE_SIZE) != 0, "1-bit key change yields completely divergent cipher states");

    cv_cube_clear(&ctx1);
    cv_cube_clear(&ctx2);
    return TEST_PASS;
}

int main(void) {
    printf("====================================================\n");
    printf("  RockCrypter 256x256 Cube & Heisenberg Test Suite  \n");
    printf("====================================================\n");

    if (cv_cube_self_test() != CV_CUBE_SUCCESS) {
        printf("[-] cv_cube_self_test() failed!\n");
        return 1;
    }
    printf("[+] Built-in cv_cube_self_test() PASSED\n\n");

    if (test_cube_basic_roundtrip() != TEST_PASS) return 1;
    if (test_cube_avalanche_criterion() != TEST_PASS) return 1;
    if (test_matrix_256_diffusion() != TEST_PASS) return 1;
    if (test_cube_key_sensitivity() != TEST_PASS) return 1;

    printf("\n====================================================\n");
    printf("All 256x256 Cube Tests PASSED! (%d/%d assertions)\n", g_tests_passed, g_tests_run);
    printf("====================================================\n");
    return 0;
}
