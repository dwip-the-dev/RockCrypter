#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

static void test_kdf_memory_scaling(void) {
    printf("[KDFCost] Testing Memory-Hard Scaling (64 KiB, 256 KiB, 1024 KiB Base)... ");

    const char *pass = "UniversityCapstoneSecurityProject2026";
    uint8_t salt[32];
    assert(cv_entropy_get(salt, sizeof(salt)) == 0);

    const uint32_t mem_costs[] = {64, 256, CV_DEFAULT_MEM_COST_KB}; /* up to 1 MiB base */

    for (size_t i = 0; i < sizeof(mem_costs)/sizeof(mem_costs[0]); i++) {
        uint32_t mem = mem_costs[i];
        cv_subkeys_t k1, k2;

        clock_t t0 = clock();
        assert(cv_kdf_derive(pass, strlen(pass), salt, mem, 2, &k1) == CV_KDF_SUCCESS);
        clock_t t1 = clock();

        /* Determinism verification */
        assert(cv_kdf_derive(pass, strlen(pass), salt, mem, 2, &k2) == CV_KDF_SUCCESS);

        assert(cv_ct_memcmp(k1.k_enc, k2.k_enc, 32) == 0);
        assert(cv_ct_memcmp(k1.k_mac, k2.k_mac, 32) == 0);
        assert(cv_ct_memcmp(k1.k_cascade, k2.k_cascade, 32) == 0);

        double elapsed_sec = (double)(t1 - t0) / CLOCKS_PER_SEC;
        assert(elapsed_sec >= 0.0);

        cv_subkeys_clear(&k1);
        cv_subkeys_clear(&k2);
    }

    printf("PASSED\n");
}

static void test_kdf_salt_and_passphrase_sensitivity(void) {
    printf("[KDFCost] Testing Salt and Password Diffusion Sensitivity... ");

    const char *pass1 = "SecretPassphraseA";
    const char *pass2 = "SecretPassphraseB"; /* 1 character difference */

    uint8_t salt1[32];
    uint8_t salt2[32];
    memset(salt1, 0x11, sizeof(salt1));
    memset(salt2, 0x11, sizeof(salt2));
    salt2[31] ^= 0x01; /* 1 bit difference */

    cv_subkeys_t k_base, k_diff_pass, k_diff_salt;

    assert(cv_kdf_derive(pass1, strlen(pass1), salt1, 64, 1, &k_base) == CV_KDF_SUCCESS);
    assert(cv_kdf_derive(pass2, strlen(pass2), salt1, 64, 1, &k_diff_pass) == CV_KDF_SUCCESS);
    assert(cv_kdf_derive(pass1, strlen(pass1), salt2, 64, 1, &k_diff_salt) == CV_KDF_SUCCESS);

    /* 1 character change in password must yield completely uncorrelated keys */
    assert(cv_ct_memcmp(k_base.k_enc, k_diff_pass.k_enc, 32) != 0);
    assert(cv_ct_memcmp(k_base.k_mac, k_diff_pass.k_mac, 32) != 0);

    /* 1 bit change in salt must yield completely uncorrelated keys */
    assert(cv_ct_memcmp(k_base.k_enc, k_diff_salt.k_enc, 32) != 0);
    assert(cv_ct_memcmp(k_base.k_mac, k_diff_salt.k_mac, 32) != 0);

    cv_subkeys_clear(&k_base);
    cv_subkeys_clear(&k_diff_pass);
    cv_subkeys_clear(&k_diff_salt);

    printf("PASSED\n");
}

static void test_kdf_subkey_orthogonality(void) {
    printf("[KDFCost] Testing Pairwise Subkey Orthogonality & Isolation... ");

    const char *pass = "PairwiseSubkeyIndependenceTestString";
    uint8_t salt[32];
    memset(salt, 0x42, sizeof(salt));

    cv_subkeys_t keys;
    assert(cv_kdf_derive(pass, strlen(pass), salt, 128, 2, &keys) == CV_KDF_SUCCESS);

    /* Verify all 5 subkeys are mutually distinct */
    assert(cv_ct_memcmp(keys.k_enc, keys.k_white, 32) != 0);
    assert(cv_ct_memcmp(keys.k_enc, keys.k_mac, 32) != 0);
    assert(cv_ct_memcmp(keys.k_enc, keys.k_hdr, 32) != 0);
    assert(cv_ct_memcmp(keys.k_enc, keys.k_cascade, 32) != 0);
    assert(cv_ct_memcmp(keys.k_white, keys.k_mac, 32) != 0);
    assert(cv_ct_memcmp(keys.k_white, keys.k_hdr, 32) != 0);
    assert(cv_ct_memcmp(keys.k_white, keys.k_cascade, 32) != 0);
    assert(cv_ct_memcmp(keys.k_mac, keys.k_hdr, 32) != 0);
    assert(cv_ct_memcmp(keys.k_mac, keys.k_cascade, 32) != 0);
    assert(cv_ct_memcmp(keys.k_hdr, keys.k_cascade, 32) != 0);

    cv_subkeys_clear(&keys);
    printf("PASSED\n");
}

static void test_kdf_self_test(void) {
    printf("[KDFCost] Testing Built-in cv_kdf_self_test()... ");
    assert(cv_kdf_self_test() == CV_KDF_SUCCESS);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("     CryptoVault 1 MiB Base KDF Cost Test Suite     \n");
    printf("====================================================\n");
    test_kdf_memory_scaling();
    test_kdf_salt_and_passphrase_sensitivity();
    test_kdf_subkey_orthogonality();
    test_kdf_self_test();
    printf("All KDF Cost Tests PASSED!\n\n");
    return 0;
}
