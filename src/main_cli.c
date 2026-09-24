#include "rockcrypter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog) {
    printf("RockCrypter CLI - Experimental High-Assurance Cryptographic System\n");
    printf("Usage:\n");
    printf("  %s keygen -o <keyfile>\n", prog);
    printf("  %s enc -i <infile> -o <outfile> (-p <passphrase> | -k <keyfile>) [--aad <aad_string>]\n", prog);
    printf("  %s dec -i <infile> -o <outfile> (-p <passphrase> | -k <keyfile>) [--aad <aad_string>]\n", prog);
    printf("  %s bench\n", prog);
    printf("  %s version\n", prog);
}

static int cmd_keygen(const char *outfile) {
    if (!outfile) {
        fprintf(stderr, "Error: missing output file (-o <keyfile>)\n");
        return 1;
    }
    uint8_t key[32];
    if (rock_entropy_get(key, sizeof(key)) != 0) {
        fprintf(stderr, "Error: entropy generation failed\n");
        return 1;
    }
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        perror("Error opening keyfile for writing");
        rock_memzero(key, sizeof(key));
        return 1;
    }
    if (fwrite(key, 1, sizeof(key), f) != sizeof(key)) {
        perror("Error writing keyfile");
        fclose(f);
        rock_memzero(key, sizeof(key));
        return 1;
    }
    fclose(f);
    rock_memzero(key, sizeof(key));
    printf("[+] Generated 256-bit cryptographically secure key -> %s\n", outfile);
    return 0;
}

static int read_key_file(const char *path, uint8_t key[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("Error reading key file");
        return -1;
    }
    if (fread(key, 1, 32, f) != 32) {
        fprintf(stderr, "Error: keyfile must be at least 32 bytes\n");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int cmd_bench(void) {
    printf("=== RockCrypter Cryptographic Benchmark ===\n");

    /* 1. Core Cipher Block Encryption Benchmark */
    uint8_t key[32];
    uint8_t block[32];
    rock_entropy_get(key, 32);
    rock_entropy_get(block, 32);

    rock_core_ctx_t core_ctx;
    rock_core_expand_key(&core_ctx, key);

    const int core_iters = 500000;
    clock_t start = clock();
    for (int i = 0; i < core_iters; i++) {
        rock_core_encrypt_block(&core_ctx, block, block);
    }
    clock_t end = clock();
    double sec = (double)(end - start) / CLOCKS_PER_SEC;
    double mb = (double)(core_iters * 32) / (1024.0 * 1024.0);
    printf("RockCore-256 (32 rounds): %.2f MB/s (%d blocks in %.3f s)\n", mb / sec, core_iters, sec);
    rock_core_clear(&core_ctx);

    /* 2. Sponge Absorb/Squeeze Benchmark */
    rock_sponge_t sponge;
    rock_sponge_init(&sponge, 0);
    uint8_t sponge_buf[1024];
    memset(sponge_buf, 0x42, sizeof(sponge_buf));

    const int sponge_iters = 50000;
    start = clock();
    for (int i = 0; i < sponge_iters; i++) {
        rock_sponge_absorb(&sponge, sponge_buf, sizeof(sponge_buf));
    }
    end = clock();
    sec = (double)(end - start) / CLOCKS_PER_SEC;
    mb = (double)(sponge_iters * sizeof(sponge_buf)) / (1024.0 * 1024.0);
    printf("RockSponge-512 Absorb:   %.2f MB/s (%.1f MB in %.3f s)\n", mb / sec, mb, sec);
    rock_sponge_clear(&sponge);

    /* 3. RockKDF Derivation Time */
    rock_subkeys_t subkeys;
    start = clock();
    rock_kdf_derive("benchmark_password", 18, key, 16384, 4, &subkeys);
    end = clock();
    sec = (double)(end - start) / CLOCKS_PER_SEC;
    printf("RockKDF (16 MB memory, 4 passes): %.3f s per derivation\n", sec);
    rock_subkeys_clear(&subkeys);

    /* 4. Full AEAD Encryption / Decryption Pipeline */
    size_t test_size = 10 * 1024 * 1024; /* 10 MB */
    uint8_t *data = (uint8_t *)malloc(test_size);
    if (data) {
        memset(data, 0x5A, test_size);
        uint8_t *ct = NULL;
        size_t ct_len = 0;

        start = clock();
        int ret = rock_aead_encrypt(data, test_size, (const uint8_t *)"AAD_BENCH", 9,
                                    key, 32, 0, 0, 0, &ct, &ct_len);
        end = clock();
        sec = (double)(end - start) / CLOCKS_PER_SEC;
        if (ret == 0) {
            printf("RockAEAD Encryption:     %.2f MB/s (10 MB in %.3f s)\n", 10.0 / sec, sec);

            uint8_t *pt = NULL;
            size_t pt_len = 0;
            start = clock();
            ret = rock_aead_decrypt(ct, ct_len, (const uint8_t *)"AAD_BENCH", 9,
                                    key, 32, 0, &pt, &pt_len);
            end = clock();
            sec = (double)(end - start) / CLOCKS_PER_SEC;
            if (ret == 0) {
                printf("RockAEAD Decryption:     %.2f MB/s (10 MB in %.3f s)\n", 10.0 / sec, sec);
                rock_secure_free(pt, pt_len);
            }
            rock_secure_free(ct, ct_len);
        }
        free(data);
    }
    rock_memzero(key, sizeof(key));
    rock_memzero(block, sizeof(block));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];

    if (strcmp(action, "version") == 0 || strcmp(action, "-v") == 0) {
        printf("RockCrypter v%s (C Core Engine)\n", ROCKCRYPTER_VERSION_STRING);
        return 0;
    }

    if (strcmp(action, "bench") == 0) {
        return cmd_bench();
    }

    if (strcmp(action, "keygen") == 0) {
        const char *outfile = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                outfile = argv[++i];
            }
        }
        return cmd_keygen(outfile);
    }

    if (strcmp(action, "enc") == 0 || strcmp(action, "dec") == 0) {
        int is_enc = (strcmp(action, "enc") == 0);
        const char *infile = NULL;
        const char *outfile = NULL;
        const char *pass = NULL;
        const char *keyfile = NULL;
        const char *aad_str = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) infile = argv[++i];
            else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outfile = argv[++i];
            else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) pass = argv[++i];
            else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) keyfile = argv[++i];
            else if (strcmp(argv[i], "--aad") == 0 && i + 1 < argc) aad_str = argv[++i];
        }

        if (!infile || !outfile || (!pass && !keyfile)) {
            print_usage(argv[0]);
            return 1;
        }

        uint8_t raw_key[32];
        const void *secret = NULL;
        size_t secret_len = 0;
        int is_passphrase = 0;

        if (pass) {
            secret = pass;
            secret_len = strlen(pass);
            is_passphrase = 1;
        } else {
            if (read_key_file(keyfile, raw_key) != 0) return 1;
            secret = raw_key;
            secret_len = 32;
            is_passphrase = 0;
        }

        const uint8_t *aad = (const uint8_t *)aad_str;
        size_t aad_len = aad_str ? strlen(aad_str) : 0;

        int ret = 0;
        if (is_enc) {
            printf("[*] Encrypting '%s' -> '%s' (Streaming chunks + RockMAC AEAD)...\n", infile, outfile);
            ret = rock_file_encrypt(infile, outfile, secret, secret_len, is_passphrase,
                                    aad, aad_len, 16384, 4);
            if (ret == ROCK_SUCCESS) {
                printf("[+] Encryption complete successfully!\n");
            } else {
                fprintf(stderr, "[-] Encryption failed: %s (%d)\n", rock_strerror(ret), ret);
            }
        } else {
            printf("[*] Decrypting and authenticating '%s' -> '%s'...\n", infile, outfile);
            ret = rock_file_decrypt(infile, outfile, secret, secret_len, is_passphrase,
                                    aad, aad_len);
            if (ret == ROCK_SUCCESS) {
                printf("[+] Decryption and authentication verified successfully!\n");
            } else {
                fprintf(stderr, "[-] Decryption failed: %s (%d)\n", rock_strerror(ret), ret);
            }
        }

        rock_memzero(raw_key, sizeof(raw_key));
        return (ret == ROCK_SUCCESS) ? 0 : 2;
    }

    print_usage(argv[0]);
    return 1;
}
