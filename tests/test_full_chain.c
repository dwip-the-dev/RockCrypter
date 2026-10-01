#include "vault.h"
#include "cert.h"
#include "package.h"
#include "diffie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_end_to_end_alice_bob_life_cycle(void) {
    printf("[FullChain] Simulating End-to-End Alice & Bob Cryptographic Pipeline...\n");

    /* Step 1: Alice creates an X25519 identity keypair and self-signed certificate */
    printf("  [1/6] Alice creates identity keypair & armored certificate... ");
    cv_ecdh_keypair_t alice_id;
    assert(cv_ecdh_keygen(&alice_id) == 0);

    cv_cert_t alice_cert;
    assert(cv_cert_create_self_signed(&alice_cert, "alice@university.edu",
                                      alice_id.pub, alice_id.priv,
                                      86400, CV_KEY_USAGE_ENCRYPT) == CV_CERT_SUCCESS);

    const char *cert_file = "/tmp/cv_pipeline_alice.cert.asc";
    assert(cv_cert_save_armored(cert_file, &alice_cert) == CV_CERT_SUCCESS);
    printf("DONE\n");

    /* Step 2: Bob receives Alice's certificate and verifies visual fingerprint */
    printf("  [2/6] Bob verifies Alice's certificate and visual fingerprint... ");
    cv_cert_t bob_view_of_alice_cert;
    assert(cv_cert_load_armored(cert_file, &bob_view_of_alice_cert) == CV_CERT_SUCCESS);
    assert(cv_cert_verify(&bob_view_of_alice_cert, 0) == CV_CERT_SUCCESS);

    char alice_fingerprint[128];
    assert(cv_cert_compute_fingerprint(bob_view_of_alice_cert.pubkey,
                                       alice_fingerprint, sizeof(alice_fingerprint)) == CV_CERT_SUCCESS);
    assert(strlen(alice_fingerprint) == 95);
    printf("DONE (Fingerprint: %.23s...)\n", alice_fingerprint);

    /* Step 3: Bob encrypts a confidential document into a .cvpkg container for Alice */
    printf("  [3/6] Bob packages document into a .cvpkg container for Alice... ");
    const char *doc_file = "/tmp/cv_pipeline_secret_document.pdf";
    const char *pkg_file = "/tmp/cv_pipeline_transfer.cvpkg";
    const char *restored_file = "/tmp/cv_pipeline_decrypted_document.pdf";

    FILE *f_doc = fopen(doc_file, "wb");
    assert(f_doc != NULL);
    for (int i = 0; i < 2000; i++) {
        fprintf(f_doc, "Row %05d: Academic Term Paper Evaluation - 5.0 CGPA Final Deliverable\n", i);
    }
    fclose(f_doc);

    assert(cv_package_create_hybrid(doc_file, pkg_file, bob_view_of_alice_cert.pubkey) == CV_PKG_SUCCESS);
    printf("DONE\n");

    /* Step 4: Alice receives package, verifies seal, and decrypts with her private key */
    printf("  [4/6] Alice unpacks .cvpkg and decrypts document... ");
    cv_pkg_manifest_t manifest;
    assert(cv_package_inspect(pkg_file, &manifest) == CV_PKG_SUCCESS);
    assert(manifest.mode == CV_PKG_MODE_HYBRID);

    assert(cv_package_extract_hybrid(pkg_file, restored_file, alice_id.priv) == CV_PKG_SUCCESS);

    uint8_t h_orig[32], h_restored[32];
    assert(cv_hash_file(doc_file, h_orig) == 0);
    assert(cv_hash_file(restored_file, h_restored) == 0);
    assert(cv_ct_memcmp(h_orig, h_restored, 32) == 0);
    printf("DONE (Bit-for-bit SHA-3 digest match verified)\n");

    /* Step 5: Alice backs up her private key using 3-of-5 Shamir Secret Sharing */
    printf("  [5/6] Alice splits private key into 3-of-5 Shamir shares... ");
    cv_share_t shares[5];
    assert(cv_shamir_split(alice_id.priv, 3, 5, shares) == CV_SHAMIR_SUCCESS);

    char share_strings[5][128];
    for (int i = 0; i < 5; i++) {
        assert(cv_shamir_share_to_string(&shares[i], share_strings[i], sizeof(share_strings[i])) == 0);
    }
    printf("DONE (5 armored paper shares created)\n");

    /* Step 6: Disaster Recovery Simulation: Alice reconstructs key from 3 custodians */
    printf("  [6/6] Disaster recovery: Custodians {1, 3, 4} combine shares... ");
    cv_share_t recovery_subset[3];
    assert(cv_shamir_share_from_string(share_strings[1], &recovery_subset[0]) == 0);
    assert(cv_shamir_share_from_string(share_strings[3], &recovery_subset[1]) == 0);
    assert(cv_shamir_share_from_string(share_strings[4], &recovery_subset[2]) == 0);

    uint8_t recovered_priv[32];
    assert(cv_shamir_combine(recovery_subset, 3, recovered_priv) == CV_SHAMIR_SUCCESS);
    assert(cv_ct_memcmp(alice_id.priv, recovered_priv, 32) == 0);
    printf("DONE (Private key restored with zero error)\n");

    /* Cleanup temporary files */
    unlink(cert_file);
    unlink(doc_file);
    unlink(pkg_file);
    unlink(restored_file);
    cv_ecdh_keypair_clear(&alice_id);
    cv_memzero(recovered_priv, sizeof(recovered_priv));

    printf("[FullChain] End-to-End Life-Cycle PASSED!\n");
}

int main(void) {
    printf("====================================================\n");
    printf("    CryptoVault Full End-to-End Life-Cycle Test     \n");
    printf("====================================================\n");
    test_end_to_end_alice_bob_life_cycle();
    printf("All Life-Cycle Tests PASSED!\n\n");
    return 0;
}
