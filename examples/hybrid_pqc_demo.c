/**
 * @file hybrid_pqc_demo.c
 * @brief Demonstration of Hybrid Classical + Post-Quantum Key Exchange & Storage.
 *
 * ============================================================================
 * CryptoVault Post-Quantum Hybrid Cryptography Demonstration
 * ============================================================================
 *
 * Demonstrates a defense-in-depth hybrid key establishment protocol combining:
 * 1. Classical Ephemeral Diffie-Hellman Key Exchange (X25519 Curve25519).
 * 2. Post-Quantum Lattice Ring-LWE Key Encapsulation (FIPS 203 Kyber-style).
 * 3. Dual-PRF HKDF Combiner: K_session = HKDF(SS_classical || SS_pqc, salt, info).
 * 4. Symmetric AEAD payload encryption using the hybrid session key.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "pqc.h"
#include "ecdh.h"
#include "aead.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-24s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("======================================================================\n");
    printf("  CryptoVault Post-Quantum Hybrid Key Exchange & Storage Demonstration\n");
    printf("======================================================================\n\n");

    /* Step 1: Classical Diffie-Hellman Handshake */
    printf("[1] Initializing Classical Diffie-Hellman (X25519) Key Exchange...\n");
    cv_ecdh_keypair_t alice_classical_kp;
    cv_ecdh_keypair_t bob_classical_kp;

    if (cv_ecdh_keygen(&alice_classical_kp) != 0 ||
        cv_ecdh_keygen(&bob_classical_kp) != 0) {
        fprintf(stderr, "[-] Classical key generation failed!\n");
        return 1;
    }

    uint8_t alice_classical_ss[32];
    uint8_t bob_classical_ss[32];

    if (cv_ecdh_compute_shared(alice_classical_kp.priv, bob_classical_kp.pub, alice_classical_ss) != 0 ||
        cv_ecdh_compute_shared(bob_classical_kp.priv, alice_classical_kp.pub, bob_classical_ss) != 0) {
        fprintf(stderr, "[-] Classical shared secret derivation failed!\n");
        return 1;
    }

    print_hex("Alice Classical SS", alice_classical_ss, 16);
    print_hex("Bob Classical SS", bob_classical_ss, 16);

    /* Step 2: Post-Quantum Lattice Ring-LWE Key Encapsulation */
    printf("\n[2] Initializing Post-Quantum Lattice KEM (R_q = Z_3329[x]/(x^256 + 1))...\n");
    cv_pqc_keypair_t alice_pqc_kp;
    if (cv_pqc_keygen(&alice_pqc_kp) != CV_PQC_SUCCESS) {
        fprintf(stderr, "[-] PQC keygen failed!\n");
        return 1;
    }

    cv_pqc_ciphertext_t pqc_ct;
    uint8_t bob_pqc_ss[CV_PQC_SHARED_SECRET_SIZE];
    uint8_t alice_pqc_ss[CV_PQC_SHARED_SECRET_SIZE];

    /* Bob encapsulates to Alice's PQC public key */
    if (cv_pqc_encapsulate(alice_pqc_kp.pk, &pqc_ct, bob_pqc_ss) != CV_PQC_SUCCESS) {
        fprintf(stderr, "[-] PQC encapsulation failed!\n");
        return 1;
    }

    /* Alice decapsulates using her secret key */
    if (cv_pqc_decapsulate(alice_pqc_kp.sk, &pqc_ct, alice_pqc_ss) != CV_PQC_SUCCESS) {
        fprintf(stderr, "[-] PQC decapsulation failed!\n");
        return 1;
    }

    print_hex("Alice Post-Quantum SS", alice_pqc_ss, 16);
    print_hex("Bob Post-Quantum SS", bob_pqc_ss, 16);

    /* Step 3: Dual-PRK Hybrid Key Combiner */
    printf("\n[3] Executing Dual-PRK Hybrid Combiner (Classical || Post-Quantum)...\n");
    const char *domain_info = "CryptoVault-Hybrid-Session-v2";
    uint8_t alice_hybrid_key[32];
    uint8_t bob_hybrid_key[32];

    cv_pqc_hybrid_combine(alice_classical_ss, 32, alice_pqc_ss, 32,
                          (const uint8_t *)domain_info, strlen(domain_info),
                          alice_hybrid_key, 32);

    cv_pqc_hybrid_combine(bob_classical_ss, 32, bob_pqc_ss, 32,
                          (const uint8_t *)domain_info, strlen(domain_info),
                          bob_hybrid_key, 32);

    print_hex("Alice Hybrid Key", alice_hybrid_key, 32);
    print_hex("Bob Hybrid Key", bob_hybrid_key, 32);

    if (cv_mem_equal(alice_hybrid_key, bob_hybrid_key, 32) != 1) {
        fprintf(stderr, "[-] FATAL: Hybrid key mismatch between Alice and Bob!\n");
        return 1;
    }
    printf("[+] Hybrid Key Establishment Successful! Both parties agree on 256-bit key.\n");

    /* Step 4: Encrypt Sample Document using AEAD Envelope */
    printf("\n[4] Encrypting Classified Document using Hybrid Session Key...\n");
    const char *plaintext = "Top-Secret Quantum Resistant Operational Order #8829";
    size_t pt_len = strlen(plaintext);
    const char *aad = "AUTHENTICATED_DOCUMENT_METADATA_HEADER_V1";

    uint8_t *envelope = NULL;
    size_t env_len = 0;

    int enc_ret = cv_aead_encrypt((const uint8_t *)plaintext, pt_len,
                                  (const uint8_t *)aad, strlen(aad),
                                  alice_hybrid_key, 32, 0,
                                  1024, 2,
                                  &envelope, &env_len);
    if (enc_ret != 0) {
        fprintf(stderr, "[-] AEAD encryption failed!\n");
        return 1;
    }

    printf("    Generated AEAD Envelope Size: %zu bytes (Header + Ciphertext + Tag)\n", env_len);
    print_hex("Envelope Sample Prefix", envelope, 32);

    /* Step 5: Decrypt and Authenticate */
    printf("\n[5] Bob Decrypts and Verifies Document Authentication Tag...\n");
    uint8_t *decrypted = NULL;
    size_t dec_len = 0;

    int dec_ret = cv_aead_decrypt(envelope, env_len,
                                  (const uint8_t *)aad, strlen(aad),
                                  bob_hybrid_key, 32, 0,
                                  &decrypted, &dec_len);
    if (dec_ret != 0) {
        fprintf(stderr, "[-] AEAD authentication failed!\n");
        return 1;
    }

    char *pt_str = (char *)malloc(dec_len + 1);
    if (pt_str) {
        memcpy(pt_str, decrypted, dec_len);
        pt_str[dec_len] = '\0';
        printf("[+] Decrypted Plaintext: \"%s\"\n\n", pt_str);
        free(pt_str);
    }

    cv_secure_free(decrypted, dec_len);
    free(envelope);

    /* Secure cleanup */
    cv_memzero(alice_classical_ss, sizeof(alice_classical_ss));
    cv_memzero(bob_classical_ss, sizeof(bob_classical_ss));
    cv_memzero(alice_pqc_ss, sizeof(alice_pqc_ss));
    cv_memzero(bob_pqc_ss, sizeof(bob_pqc_ss));
    cv_memzero(alice_hybrid_key, sizeof(alice_hybrid_key));
    cv_memzero(bob_hybrid_key, sizeof(bob_hybrid_key));

    printf("======================================================================\n");
    printf("  Hybrid Post-Quantum Security Protocol Verified Successfully!\n");
    printf("======================================================================\n");
    return 0;
}
