#include "vault.h"
#include "cert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_cert_creation_and_fingerprint(void) {
    printf("[Cert] Testing Identity Certificate Creation & Hex Fingerprinting... ");

    cv_ecdh_keypair_t alice;
    assert(cv_ecdh_keygen(&alice) == 0);

    cv_cert_t cert;
    assert(cv_cert_create_self_signed(&cert, "alice@cryptovault.academic",
                                      alice.pub, alice.priv,
                                      3600, CV_KEY_USAGE_ENCRYPT | CV_KEY_USAGE_SIGN) == CV_CERT_SUCCESS);

    assert(strcmp(cert.subject, "alice@cryptovault.academic") == 0);
    assert(cert.valid_until > cert.valid_from);

    char fp[128];
    assert(cv_cert_compute_fingerprint(alice.pub, fp, sizeof(fp)) == CV_CERT_SUCCESS);
    assert(strlen(fp) == 95); /* 32 bytes * 2 hex + 31 colons = 95 chars */

    cv_ecdh_keypair_clear(&alice);
    printf("PASSED\n");
}

static void test_cert_expiration_verification(void) {
    printf("[Cert] Testing Expiration and Time-Window Bounds Verification... ");

    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&bob) == 0);

    cv_cert_t cert;
    uint64_t one_hour = 3600;
    assert(cv_cert_create_self_signed(&cert, "bob@cryptovault.academic",
                                      bob.pub, bob.priv,
                                      one_hour, CV_KEY_USAGE_ENCRYPT) == CV_CERT_SUCCESS);

    /* Verify currently valid */
    assert(cv_cert_verify(&cert, cert.valid_from + 10) == CV_CERT_SUCCESS);

    /* Verify expired in future */
    assert(cv_cert_verify(&cert, cert.valid_until + 100) == CV_CERT_ERR_EXPIRED);

    /* Verify before valid_from */
    assert(cv_cert_verify(&cert, cert.valid_from - 100) == CV_CERT_ERR_NOT_YET);

    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

static void test_cert_armored_persistence(void) {
    printf("[Cert] Testing Armored File Export and Import Roundtrip... ");

    const char *path = "/tmp/cv_test_cert_storage.asc";
    cv_ecdh_keypair_t kp;
    assert(cv_ecdh_keygen(&kp) == 0);

    cv_cert_t original;
    assert(cv_cert_create_self_signed(&original, "custodian@cryptovault.academic",
                                      kp.pub, kp.priv, 7200, CV_KEY_USAGE_BACKUP) == CV_CERT_SUCCESS);

    assert(cv_cert_save_armored(path, &original) == CV_CERT_SUCCESS);

    cv_cert_t loaded;
    assert(cv_cert_load_armored(path, &loaded) == CV_CERT_SUCCESS);

    assert(cv_ct_memcmp(&original, &loaded, sizeof(cv_cert_t)) == 0);
    unlink(path);

    cv_ecdh_keypair_clear(&kp);
    printf("PASSED\n");
}

static void test_cert_tamper_rejection(void) {
    printf("[Cert] Testing Tamper Rejection on Modified Subject Field... ");

    cv_ecdh_keypair_t kp;
    assert(cv_ecdh_keygen(&kp) == 0);

    cv_cert_t cert;
    assert(cv_cert_create_self_signed(&cert, "original@cryptovault.academic",
                                      kp.pub, kp.priv, 7200, CV_KEY_USAGE_ENCRYPT) == CV_CERT_SUCCESS);

    /* Tamper with subject */
    cert.subject[0] = 'X';
    /* Tampered certificate magic or auth tag must be rejected */
    assert(cv_cert_verify(&cert, cert.valid_from + 10) != CV_CERT_SUCCESS);

    cv_ecdh_keypair_clear(&kp);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("       CryptoVault Identity Certificate Tests       \n");
    printf("====================================================\n");
    test_cert_creation_and_fingerprint();
    test_cert_expiration_verification();
    test_cert_armored_persistence();
    test_cert_tamper_rejection();
    printf("All Certificate Tests PASSED!\n\n");
    return 0;
}
