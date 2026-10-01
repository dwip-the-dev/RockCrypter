#include "vault.h"
#include "package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_package_hybrid_workflow(void) {
    printf("[Package] Testing Hybrid Public-Key Packaging & Restoration... ");

    const char *src = "/tmp/cv_pkg_test_source.txt";
    const char *pkg = "/tmp/cv_pkg_test_bundle.cvpkg";
    const char *dec = "/tmp/cv_pkg_test_restored.txt";

    FILE *f = fopen(src, "w");
    assert(f != NULL);
    for (int i = 0; i < 500; i++) {
        fprintf(f, "Packaging Test Row %04d: Secure file and key transmission\n", i);
    }
    fclose(f);

    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&bob) == 0);

    /* Alice packages file for Bob */
    assert(cv_package_create_hybrid(src, pkg, bob.pub) == CV_PKG_SUCCESS);

    /* Inspect package manifest */
    cv_pkg_manifest_t manifest;
    assert(cv_package_inspect(pkg, &manifest) == CV_PKG_SUCCESS);
    assert(manifest.mode == CV_PKG_MODE_HYBRID);
    assert(manifest.payload_size > 0);
    assert(cv_ct_memcmp(manifest.recipient_pubkey, bob.pub, CV_ECDH_KEY_SIZE) == 0);

    /* Bob extracts package */
    assert(cv_package_extract_hybrid(pkg, dec, bob.priv) == CV_PKG_SUCCESS);

    /* Verify bit-for-bit hash identity */
    uint8_t h1[32], h2[32];
    assert(cv_hash_file(src, h1) == 0);
    assert(cv_hash_file(dec, h2) == 0);
    assert(cv_ct_memcmp(h1, h2, 32) == 0);

    unlink(src);
    unlink(pkg);
    unlink(dec);
    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

static void test_package_password_workflow(void) {
    printf("[Package] Testing Password-Protected 1 MiB Hardened Packaging... ");

    const char *src = "/tmp/cv_pw_test_source.txt";
    const char *pkg = "/tmp/cv_pw_test_bundle.cvpkg";
    const char *dec = "/tmp/cv_pw_test_restored.txt";

    FILE *f = fopen(src, "w");
    assert(f != NULL);
    fprintf(f, "Testing Password Packaging with 1 MiB Base KDF Hardness\n");
    fclose(f);

    const char *pass = "CorrectAcademicPassword2026";

    assert(cv_package_create_password(src, pkg, pass) == CV_PKG_SUCCESS);

    /* Inspect manifest */
    cv_pkg_manifest_t manifest;
    assert(cv_package_inspect(pkg, &manifest) == CV_PKG_SUCCESS);
    assert(manifest.mode == CV_PKG_MODE_PASSWORD);

    /* Attempt extraction with incorrect password */
    assert(cv_package_extract_password(pkg, dec, "WrongPasswordAttempt") != CV_PKG_SUCCESS);

    /* Extract with correct password */
    assert(cv_package_extract_password(pkg, dec, pass) == CV_PKG_SUCCESS);

    uint8_t h1[32], h2[32];
    assert(cv_hash_file(src, h1) == 0);
    assert(cv_hash_file(dec, h2) == 0);
    assert(cv_ct_memcmp(h1, h2, 32) == 0);

    unlink(src);
    unlink(pkg);
    unlink(dec);
    printf("PASSED\n");
}

static void test_package_tamper_detection(void) {
    printf("[Package] Testing Package Seal Integrity Tamper Rejection... ");

    const char *src = "/tmp/cv_tamper_test_src.txt";
    const char *pkg = "/tmp/cv_tamper_test.cvpkg";
    const char *dec = "/tmp/cv_tamper_test_dec.txt";

    FILE *f = fopen(src, "w");
    assert(f != NULL);
    fprintf(f, "Tamper evaluation file payload\n");
    fclose(f);

    cv_ecdh_keypair_t bob;
    assert(cv_ecdh_keygen(&bob) == 0);

    assert(cv_package_create_hybrid(src, pkg, bob.pub) == CV_PKG_SUCCESS);

    /* Tamper with file: flip 1 byte at payload offset */
    FILE *f_pkg = fopen(pkg, "r+b");
    assert(f_pkg != NULL);
    fseek(f_pkg, 300, SEEK_SET);
    int c = fgetc(f_pkg);
    fseek(f_pkg, 300, SEEK_SET);
    fputc(c ^ 0x01, f_pkg);
    fclose(f_pkg);

    /* Extraction must detect seal corruption and fail */
    assert(cv_package_extract_hybrid(pkg, dec, bob.priv) != CV_PKG_SUCCESS);

    unlink(src);
    unlink(pkg);
    cv_ecdh_keypair_clear(&bob);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("      CryptoVault Secure Package Container Tests    \n");
    printf("====================================================\n");
    test_package_hybrid_workflow();
    test_package_password_workflow();
    test_package_tamper_detection();
    printf("All Packaging Tests PASSED!\n\n");
    return 0;
}
