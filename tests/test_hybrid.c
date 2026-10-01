#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_x25519_key_exchange(void) {
    printf("[Hybrid] Testing X25519 Elliptic Curve Key Exchange... ");

    cv_ecdh_keypair_t alice;
    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&alice) == 0);
    assert(cv_ecdh_keygen(&bob) == 0);

    uint8_t shared_alice[32];
    uint8_t shared_bob[32];

    assert(cv_ecdh_compute_shared(alice.priv, bob.pub, shared_alice) == 0);
    assert(cv_ecdh_compute_shared(bob.priv, alice.pub, shared_bob) == 0);

    /* Diffie-Hellman Property: shared secret must match identically */
    assert(cv_ct_memcmp(shared_alice, shared_bob, 32) == 0);

    cv_ecdh_keypair_clear(&alice);
    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

static void test_hybrid_pke_buffer_roundtrip(void) {
    printf("[Hybrid] Testing Hybrid PKE Buffer Encryption & Decryption... ");

    cv_ecdh_keypair_t recipient;
    assert(cv_ecdh_keygen(&recipient) == 0);

    const char *msg = "Confidential report for academic coursework evaluation 2026";
    size_t msg_len = strlen(msg);

    uint8_t *enc_buf = NULL;
    size_t enc_len = 0;

    /* Alice encrypts using Bob's public key */
    assert(cv_hybrid_encrypt(recipient.pub, (const uint8_t *)msg, msg_len,
                             (const uint8_t *)"Metadata:v1", 11,
                             &enc_buf, &enc_len) == 0);
    assert(enc_buf != NULL);

    /* Bob decrypts using his private key */
    uint8_t *dec_buf = NULL;
    size_t dec_len = 0;
    assert(cv_hybrid_decrypt(recipient.priv, enc_buf, enc_len,
                             (const uint8_t *)"Metadata:v1", 11,
                             &dec_buf, &dec_len) == 0);

    assert(dec_len == msg_len);
    assert(cv_ct_memcmp(dec_buf, msg, msg_len) == 0);

    /* Tamper test: Corrupt byte in envelope */
    enc_buf[15] ^= 0x01;
    uint8_t *tamper_pt = NULL;
    size_t tamper_len = 0;
    assert(cv_hybrid_decrypt(recipient.priv, enc_buf, enc_len,
                             (const uint8_t *)"Metadata:v1", 11,
                             &tamper_pt, &tamper_len) != 0);
    assert(tamper_pt == NULL);

    cv_secure_free(dec_buf, dec_len);
    free(enc_buf);
    cv_ecdh_keypair_clear(&recipient);
    printf("PASSED\n");
}

static void test_hybrid_aad_mismatch(void) {
    printf("[Hybrid] Testing Hybrid Decryption AAD Tamper Rejection... ");

    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&bob) == 0);

    const char *msg = "Top secret university transcript";
    uint8_t *enc_buf = NULL;
    size_t enc_len = 0;

    assert(cv_hybrid_encrypt(bob.pub, (const uint8_t *)msg, strlen(msg),
                             (const uint8_t *)"Sender:Alice", 12,
                             &enc_buf, &enc_len) == 0);

    /* Decrypt with altered AAD must fail */
    uint8_t *dec_buf = NULL;
    size_t dec_len = 0;
    int ret = cv_hybrid_decrypt(bob.priv, enc_buf, enc_len,
                                (const uint8_t *)"Sender:Eve", 10,
                                &dec_buf, &dec_len);
    assert(ret != 0);
    assert(dec_buf == NULL);

    free(enc_buf);
    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

static void test_hybrid_wrong_private_key(void) {
    printf("[Hybrid] Testing Decryption with Wrong Recipient Private Key... ");

    cv_ecdh_keypair_t bob;
    cv_ecdh_keypair_t charlie;
    assert(cv_ecdh_keygen(&bob) == 0);
    assert(cv_ecdh_keygen(&charlie) == 0);

    const char *msg = "Only Bob should be able to read this";
    uint8_t *enc_buf = NULL;
    size_t enc_len = 0;

    assert(cv_hybrid_encrypt(bob.pub, (const uint8_t *)msg, strlen(msg),
                             NULL, 0, &enc_buf, &enc_len) == 0);

    /* Charlie attempts to decrypt with his own private key */
    uint8_t *dec_buf = NULL;
    size_t dec_len = 0;
    int ret = cv_hybrid_decrypt(charlie.priv, enc_buf, enc_len, NULL, 0,
                                &dec_buf, &dec_len);
    assert(ret != 0);
    assert(dec_buf == NULL);

    free(enc_buf);
    cv_ecdh_keypair_clear(&bob);
    cv_ecdh_keypair_clear(&charlie);
    printf("PASSED\n");
}

static void test_hybrid_file_streaming(void) {
    printf("[Hybrid] Testing Hybrid File Encryption and Decryption... ");

    const char *orig_file = "/tmp/cv_test_hybrid_orig.txt";
    const char *enc_file = "/tmp/cv_test_hybrid.cvlt";
    const char *dec_file = "/tmp/cv_test_hybrid_dec.txt";

    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&bob) == 0);

    FILE *f = fopen(orig_file, "w");
    assert(f != NULL);
    fprintf(f, "Testing Hybrid File Streaming Encryption Architecture 2026\n");
    for (int i = 0; i < 1000; i++) {
        fprintf(f, "Line %04d: Cryptographic engineering capstone grade 5.0\n", i);
    }
    fclose(f);

    /* Alice encrypts for Bob */
    assert(cv_hybrid_file_encrypt(orig_file, enc_file, bob.pub,
                                  (const uint8_t *)"FileAAD", 7) == 0);

    /* Bob decrypts */
    assert(cv_hybrid_file_decrypt(enc_file, dec_file, bob.priv,
                                  (const uint8_t *)"FileAAD", 7) == 0);

    /* Compare contents */
    uint8_t h1[32], h2[32];
    assert(cv_hash_file(orig_file, h1) == 0);
    assert(cv_hash_file(dec_file, h2) == 0);
    assert(cv_ct_memcmp(h1, h2, 32) == 0);

    unlink(orig_file);
    unlink(enc_file);
    unlink(dec_file);
    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("     CryptoVault Hybrid PKE Cryptographic Tests     \n");
    printf("====================================================\n");
    test_x25519_key_exchange();
    test_hybrid_pke_buffer_roundtrip();
    test_hybrid_aad_mismatch();
    test_hybrid_wrong_private_key();
    test_hybrid_file_streaming();
    printf("All Hybrid PKE Tests PASSED!\n\n");
    return 0;
}
