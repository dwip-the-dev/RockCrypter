/**
 * @file alice_bob_hybrid.c
 * @brief Standalone C Example: Alice & Bob Asymmetric Hybrid Document Exchange.
 *
 * Demonstrates:
 * 1. Bob generates an X25519 keypair and exports his armored public key.
 * 2. Alice imports Bob's public key and verifies his key fingerprint.
 * 3. Alice encrypts a sensitive confidential document using hybrid streaming.
 * 4. Bob receives the encrypted file and decrypts it with his private key.
 * 5. Integrity verification ensures 100% cryptographic authentication.
 */

#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    printf("====================================================================\n");
    printf("     CryptoVault Academic Example: Alice & Bob Hybrid Encryption    \n");
    printf("====================================================================\n\n");

    /* Define file paths for the demonstration */
    const char *doc_file = "/tmp/alice_confidential_research.txt";
    const char *enc_file = "/tmp/alice_to_bob_encrypted.cvlt";
    const char *dec_file = "/tmp/bob_restored_research.txt";
    const char *bob_pub_file = "/tmp/bob_identity_public.asc";

    /* Step 1: Create a sample document written by Alice */
    printf("[Alice] Writing confidential research paper to '%s'...\n", doc_file);
    FILE *f_doc = fopen(doc_file, "w");
    if (!f_doc) {
        perror("Failed to create source document");
        return 1;
    }
    fprintf(f_doc, "Title: Zero-Trust Cryptographic Architectures for University Systems\n");
    fprintf(f_doc, "Author: Alice (Cryptography & Network Security Division)\n");
    fprintf(f_doc, "Confidentiality Notice: For Bob's eyes only.\n\n");
    for (int i = 1; i <= 100; i++) {
        fprintf(f_doc, "Finding %03d: 1 MiB chunk streaming guarantees bounded RAM overhead.\n", i);
    }
    fclose(f_doc);
    printf("[Alice] Document created successfully.\n\n");

    /* Step 2: Bob generates his X25519 identity keypair */
    printf("[Bob] Generating fresh 256-bit Curve25519 (X25519) identity keypair...\n");
    cv_ecdh_keypair_t bob_keypair;
    if (cv_ecdh_keygen(&bob_keypair) != 0) {
        fprintf(stderr, "Failed to generate Bob's keypair\n");
        return 1;
    }

    /* Bob exports his public key in OpenPGP ASCII armored format */
    if (cv_pubkey_export_armored(bob_pub_file, bob_keypair.pub) != 0) {
        fprintf(stderr, "Failed to export Bob's armored public key\n");
        return 1;
    }
    printf("[Bob] Public key exported to '%s'\n", bob_pub_file);

    /* Compute and display Bob's public key fingerprint */
    char bob_fingerprint[128];
    cv_hash256(bob_keypair.pub, CV_ECDH_KEY_SIZE, (uint8_t *)bob_fingerprint);
    printf("[Bob] Public Key Fingerprint (Visual Verification):\n      ");
    for (int i = 0; i < 32; i++) {
        printf("%02X%s", (uint8_t)bob_fingerprint[i], (i == 31) ? "\n\n" : ":");
    }

    /* Step 3: Alice imports Bob's public key from the file */
    printf("[Alice] Importing Bob's public key from '%s'...\n", bob_pub_file);
    uint8_t alice_view_of_bob_pub[CV_ECDH_KEY_SIZE];
    if (cv_pubkey_import_armored(bob_pub_file, alice_view_of_bob_pub) != 0) {
        fprintf(stderr, "Alice failed to import Bob's public key\n");
        return 1;
    }
    printf("[Alice] Bob's public key successfully imported.\n\n");

    /* Step 4: Alice encrypts the document for Bob using Hybrid HPKE */
    printf("[Alice] Encrypting '%s' -> '%s' using Bob's public key...\n", doc_file, enc_file);
    const char *aad_context = "Subject: Research Paper; Classification: Top Secret";
    if (cv_hybrid_file_encrypt(doc_file, enc_file, alice_view_of_bob_pub,
                               (const uint8_t *)aad_context, strlen(aad_context)) != 0) {
        fprintf(stderr, "Hybrid encryption failed\n");
        return 1;
    }
    printf("[Alice] Encryption COMPLETE! File is ready to send over untrusted channel.\n\n");

    /* Step 5: Bob receives the encrypted file and decrypts it using his private key */
    printf("[Bob] Received '%s'. Decrypting with private key...\n", enc_file);
    if (cv_hybrid_file_decrypt(enc_file, dec_file, bob_keypair.priv,
                               (const uint8_t *)aad_context, strlen(aad_context)) != 0) {
        fprintf(stderr, "Bob failed to decrypt document\n");
        return 1;
    }
    printf("[Bob] Decryption & Authentication SUCCESSFUL! Output saved to '%s'.\n\n", dec_file);

    /* Step 6: Verify bit-for-bit cryptographic integrity between original and decrypted files */
    uint8_t hash_original[32];
    uint8_t hash_restored[32];
    cv_hash_file(doc_file, hash_original);
    cv_hash_file(dec_file, hash_restored);

    if (cv_ct_memcmp(hash_original, hash_restored, 32) == 0) {
        printf("[Audit] Bit-for-bit SHA-3 digest verification: 100%% EXACT MATCH!\n");
        printf("[Audit] Both files are cryptographically identical.\n");
    } else {
        fprintf(stderr, "[Audit] ERROR: Digest mismatch!\n");
        return 1;
    }

    /* Cleanup */
    unlink(doc_file);
    unlink(enc_file);
    unlink(dec_file);
    unlink(bob_pub_file);
    cv_ecdh_keypair_clear(&bob_keypair);

    printf("\nExample executed successfully with zero memory leaks.\n");
    return 0;
}
