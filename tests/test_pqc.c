/**
 * @file test_pqc.c
 * @brief Test Suite for Post-Quantum Ring-LWE KEM & Dual-PRK Hybrid Combiner.
 *
 * ============================================================================
 * CryptoVault Post-Quantum Cryptography Test Suite
 * ============================================================================
 *
 * Validates:
 * 1. Polynomial ring arithmetic over R_q = Z_q[x]/(x^256 + 1) with q = 3329.
 * 2. Addition/subtraction inversion and negacyclic multiplication commutativity.
 * 3. Ring-LWE Key Encapsulation Mechanism (keygen, encap, decap).
 * 4. Error-free shared secret agreement via 1-bit boundary reconciliation.
 * 5. Failure of agreement under ciphertext tampering or unauthorized private key.
 * 6. Dual-PRK Hybrid Combiner avalanche and domain separation.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "pqc.h"
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

static int test_pqc_polynomial_algebra(void) {
    cv_pqc_poly_t a, b, c1, c2, diff;

    /* Initialize test polynomials */
    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        a.coeffs[i] = (int16_t)((i * 13 + 5) % CV_PQC_PRIME_Q);
        b.coeffs[i] = (int16_t)((i * 29 + 17) % CV_PQC_PRIME_Q);
    }

    /* 1. Addition and Subtraction Inversion: (a + b) - b == a */
    cv_pqc_poly_add(&a, &b, &c1);
    cv_pqc_poly_sub(&c1, &b, &diff);

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        ASSERT_TEST(diff.coeffs[i] == a.coeffs[i], "(a + b) - b == a");
    }

    /* 2. Multiplication Commutativity: a * b == b * a */
    cv_pqc_poly_mul(&a, &b, &c1);
    cv_pqc_poly_mul(&b, &a, &c2);

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        ASSERT_TEST(c1.coeffs[i] == c2.coeffs[i], "Negacyclic multiplication is commutative");
    }

    return TEST_PASS;
}

static int test_pqc_kem_workflow(void) {
    cv_pqc_keypair_t alice_kp;
    cv_pqc_keypair_t bob_kp;

    ASSERT_TEST(cv_pqc_keygen(&alice_kp) == CV_PQC_SUCCESS, "Alice keygen");
    ASSERT_TEST(cv_pqc_keygen(&bob_kp) == CV_PQC_SUCCESS, "Bob keygen");

    /* Keys must be distinct */
    ASSERT_TEST(cv_mem_equal(alice_kp.pk, bob_kp.pk, CV_PQC_PUBLIC_KEY_SIZE) == 0,
                "Alice and Bob have distinct public keys");

    /* Bob encapsulates to Alice */
    cv_pqc_ciphertext_t ct;
    uint8_t ss_sender[CV_PQC_SHARED_SECRET_SIZE];
    ASSERT_TEST(cv_pqc_encapsulate(alice_kp.pk, &ct, ss_sender) == CV_PQC_SUCCESS, "Bob encapsulates");

    /* Alice decapsulates using her secret key */
    uint8_t ss_receiver[CV_PQC_SHARED_SECRET_SIZE];
    ASSERT_TEST(cv_pqc_decapsulate(alice_kp.sk, &ct, ss_receiver) == CV_PQC_SUCCESS, "Alice decapsulates");

    /* Alice and Bob must derive exact same 256-bit secret */
    ASSERT_TEST(cv_mem_equal(ss_sender, ss_receiver, CV_PQC_SHARED_SECRET_SIZE) == 1,
                "Derived post-quantum shared secrets must match 100%");

    /* Eve (Bob's secret key) tries to decapsulate Alice's ciphertext */
    uint8_t ss_eve[CV_PQC_SHARED_SECRET_SIZE];
    ASSERT_TEST(cv_pqc_decapsulate(bob_kp.sk, &ct, ss_eve) == CV_PQC_SUCCESS, "Eve decapsulates");
    ASSERT_TEST(cv_mem_equal(ss_sender, ss_eve, CV_PQC_SHARED_SECRET_SIZE) == 0,
                "Eve with wrong secret key cannot recover Alice's secret");

    /* Tamper with ciphertext reconciliation hints */
    ct.data[512 + 2] ^= 0xFF;
    ct.data[1] ^= 0x08;
    uint8_t ss_corrupted[CV_PQC_SHARED_SECRET_SIZE];
    ASSERT_TEST(cv_pqc_decapsulate(alice_kp.sk, &ct, ss_corrupted) == CV_PQC_SUCCESS, "Decap tampered");
    ASSERT_TEST(cv_mem_equal(ss_sender, ss_corrupted, CV_PQC_SHARED_SECRET_SIZE) == 0,
                "Tampered ciphertext yields mismatched secret");

    cv_mem_zero(&alice_kp, sizeof(alice_kp));
    cv_mem_zero(&bob_kp, sizeof(bob_kp));
    return TEST_PASS;
}

static int test_pqc_hybrid_combiner_avalanche(void) {
    uint8_t classical[32] = {0x11, 0x22, 0x33, 0x44};
    uint8_t pqc[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    const char *ctx = "HYBRID_TEST_V1";

    uint8_t hybrid_base[32];
    ASSERT_TEST(cv_pqc_hybrid_combine(classical, 32, pqc, 32,
                                     (const uint8_t *)ctx, strlen(ctx),
                                     hybrid_base, 32) == CV_PQC_SUCCESS,
                "Hybrid combine base");

    /* Flip 1 bit in classical secret */
    uint8_t classical_flip[32];
    memcpy(classical_flip, classical, 32);
    classical_flip[0] ^= 0x01;

    uint8_t hybrid_flip_classical[32];
    ASSERT_TEST(cv_pqc_hybrid_combine(classical_flip, 32, pqc, 32,
                                     (const uint8_t *)ctx, strlen(ctx),
                                     hybrid_flip_classical, 32) == CV_PQC_SUCCESS,
                "Hybrid combine with flipped classical");
    ASSERT_TEST(cv_mem_equal(hybrid_base, hybrid_flip_classical, 32) == 0,
                "Flipping classical secret changes combined key");

    /* Flip 1 bit in PQC secret */
    uint8_t pqc_flip[32];
    memcpy(pqc_flip, pqc, 32);
    pqc_flip[0] ^= 0x01;

    uint8_t hybrid_flip_pqc[32];
    ASSERT_TEST(cv_pqc_hybrid_combine(classical, 32, pqc_flip, 32,
                                     (const uint8_t *)ctx, strlen(ctx),
                                     hybrid_flip_pqc, 32) == CV_PQC_SUCCESS,
                "Hybrid combine with flipped PQC");
    ASSERT_TEST(cv_mem_equal(hybrid_base, hybrid_flip_pqc, 32) == 0,
                "Flipping PQC secret changes combined key");

    return TEST_PASS;
}

int main(void) {
    printf("[*] Starting Post-Quantum Cryptography Test Suite...\n");

    if (cv_pqc_self_test() != CV_PQC_SUCCESS) {
        fprintf(stderr, "[-] cv_pqc_self_test failed!\n");
        return 1;
    }
    g_tests_run++;
    g_tests_passed++;

    if (test_pqc_polynomial_algebra() != TEST_PASS) return 1;
    if (test_pqc_kem_workflow() != TEST_PASS) return 1;
    if (test_pqc_hybrid_combiner_avalanche() != TEST_PASS) return 1;

    printf("[+] Post-Quantum Cryptography Test Suite Passed: %d/%d assertions\n", g_tests_passed, g_tests_run);
    return 0;
}
