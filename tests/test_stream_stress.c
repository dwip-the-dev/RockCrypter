#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

static void test_stream_boundary_conditions(void) {
    printf("[StreamStress] Testing Exact 1 MiB, 1 MiB + 1B, and Multi-Chunk Boundaries... ");

    const size_t test_sizes[] = {
        0,                      /* Empty file */
        1,                      /* Single byte */
        1024,                   /* 1 KiB */
        CV_CHUNK_SIZE - 1,      /* 1 MiB - 1 byte */
        CV_CHUNK_SIZE,          /* Exactly 1 MiB (single chunk boundary) */
        CV_CHUNK_SIZE + 1,      /* 1 MiB + 1 byte (spills into chunk 2) */
        CV_CHUNK_SIZE * 2 + 77  /* Multiple chunks */
    };

    const char *pass = "BoundaryStressPassphrase2026!";
    char in_file[256];
    char enc_file[256];
    char dec_file[256];

    for (size_t s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
        size_t size = test_sizes[s];
        snprintf(in_file, sizeof(in_file), "/tmp/cv_stress_in_%zu.dat", size);
        snprintf(enc_file, sizeof(enc_file), "/tmp/cv_stress_enc_%zu.cvlt", size);
        snprintf(dec_file, sizeof(dec_file), "/tmp/cv_stress_dec_%zu.dat", size);

        FILE *f = fopen(in_file, "wb");
        assert(f != NULL);

        /* Write deterministic patterned data */
        uint8_t pattern[4096];
        for (size_t p = 0; p < sizeof(pattern); p++) {
            pattern[p] = (uint8_t)((p + size) ^ 0xAA);
        }

        size_t written = 0;
        while (written < size) {
            size_t to_write = (size - written < sizeof(pattern)) ? (size - written) : sizeof(pattern);
            fwrite(pattern, 1, to_write, f);
            written += to_write;
        }
        fclose(f);

        /* Encrypt using 1 MiB base streaming with light KDF for fast testing */
        assert(cv_file_encrypt(in_file, enc_file, pass, strlen(pass), 1,
                               (const uint8_t *)"AAD_Boundary", 12, 64, 1) == 0);

        /* Decrypt */
        assert(cv_file_decrypt(enc_file, dec_file, pass, strlen(pass), 1,
                               (const uint8_t *)"AAD_Boundary", 12) == 0);

        /* Verify digest match */
        uint8_t h_orig[32], h_dec[32];
        assert(cv_hash_file(in_file, h_orig) == 0);
        assert(cv_hash_file(dec_file, h_dec) == 0);
        assert(cv_ct_memcmp(h_orig, h_dec, 32) == 0);

        unlink(in_file);
        unlink(enc_file);
        unlink(dec_file);
    }

    printf("PASSED\n");
}

static void test_stream_multi_megabyte_throughput(void) {
    printf("[StreamStress] Testing 10 MiB High-Throughput Streaming Pipeline... ");

    const char *in_file = "/tmp/cv_stream_10mb_in.dat";
    const char *enc_file = "/tmp/cv_stream_10mb_enc.cvlt";
    const char *dec_file = "/tmp/cv_stream_10mb_dec.dat";

    size_t total_bytes = 10 * 1024 * 1024; /* 10 MiB */

    FILE *f = fopen(in_file, "wb");
    assert(f != NULL);

    uint8_t block[65536];
    for (size_t i = 0; i < sizeof(block); i++) block[i] = (uint8_t)(i * 3 + 19);

    size_t written = 0;
    while (written < total_bytes) {
        size_t to_write = (total_bytes - written < sizeof(block)) ? (total_bytes - written) : sizeof(block);
        fwrite(block, 1, to_write, f);
        written += to_write;
    }
    fclose(f);

    const char *pass = "TenMegabyteStressTestPassword";

    /* Encrypt across 10 distinct 1 MiB chunks with ratcheted sponge chaining */
    assert(cv_file_encrypt(in_file, enc_file, pass, strlen(pass), 1, NULL, 0, 64, 1) == 0);

    /* Decrypt */
    assert(cv_file_decrypt(enc_file, dec_file, pass, strlen(pass), 1, NULL, 0) == 0);

    /* Verify full file hash */
    uint8_t h_orig[32], h_dec[32];
    assert(cv_hash_file(in_file, h_orig) == 0);
    assert(cv_hash_file(dec_file, h_dec) == 0);
    assert(cv_ct_memcmp(h_orig, h_dec, 32) == 0);

    unlink(in_file);
    unlink(enc_file);
    unlink(dec_file);

    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("     CryptoVault 1 MiB Stream Stress Test Suite     \n");
    printf("====================================================\n");
    test_stream_boundary_conditions();
    test_stream_multi_megabyte_throughput();
    printf("All Stream Stress Tests PASSED!\n\n");
    return 0;
}
