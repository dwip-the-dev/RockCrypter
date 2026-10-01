#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog) {
    printf("RockCrypter CLI - High-Assurance Zero-Trust Cryptographic Engine\n");
    printf("Usage:\n");
    printf("  %s keygen -o <keyfile> [--hex]\n", prog);
    printf("  %s encrypt -i <infile> -o <outfile.rck> (-p <passphrase> | -k <keyfile>) [--aad <metadata>]\n", prog);
    printf("  %s decrypt -i <infile.rck> -o <outfile> (-p <passphrase> | -k <keyfile>) [--aad <metadata>]\n", prog);
    printf("  %s inspect -i <infile.rck>\n", prog);
    printf("  %s benchmark\n", prog);
    printf("  %s version\n", prog);
}

static int cmd_keygen(const char *outfile, int show_hex) {
    if (!outfile) {
        fprintf(stderr, "Error: missing output file (-o <keyfile>)\n");
        return 1;
    }
    uint8_t key[32];
    if (cv_entropy_get(key, sizeof(key)) != 0) {
        fprintf(stderr, "Error: OS entropy harvesting failed\n");
        return 1;
    }
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        perror("Error opening keyfile for writing");
        cv_memzero(key, sizeof(key));
        return 1;
    }
    if (fwrite(key, 1, sizeof(key), f) != sizeof(key)) {
        perror("Error writing keyfile");
        fclose(f);
        cv_memzero(key, sizeof(key));
        return 1;
    }
    fclose(f);

    printf("[+] Generated 256-bit cryptographically secure key -> %s\n", outfile);
    if (show_hex) {
        printf("[+] Key Hex: ");
        for (size_t i = 0; i < sizeof(key); i++) printf("%02x", key[i]);
        printf("\n");
    }
    cv_memzero(key, sizeof(key));
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

static int cmd_inspect(const char *filepath) {
    if (!filepath) {
        fprintf(stderr, "Error: missing input file (-i <file.cvlt>)\n");
        return 1;
    }
    cv_header_t hdr;
    int ret = cv_file_inspect(filepath, &hdr);
    if (ret != CV_SUCCESS) {
        fprintf(stderr, "[-] File inspection error: %s (%d)\n", cv_strerror(ret), ret);
        return 1;
    }

    printf("\n=== RockCrypter Container Header Inspection ===\n");
    printf("  Magic:               %.8s\n", hdr.magic);
    printf("  Version:             0x%04X\n", hdr.version);
    printf("  Cipher Suite:        0x%04X (SP-ARX-256 + Duplex-MAC-256)\n", hdr.cipher_suite);
    printf("  Flags:               0x%08X (%s)\n", hdr.flags, (hdr.flags & 1) ? "1 MiB Streaming Chunks" : "Single Buffer");
    printf("  KDF Memory Cost:     %u KB (%.2f MB)\n", hdr.mem_cost_kb, (double)hdr.mem_cost_kb / 1024.0);
    printf("  KDF Time Cost:       %u passes\n", hdr.time_cost);
    printf("  Salt (256-bit):      ");
    for (int i = 0; i < 16; i++) printf("%02x", hdr.salt[i]);
    printf("...\n");
    printf("  Nonce (192-bit):     ");
    for (int i = 0; i < 12; i++) printf("%02x", hdr.nonce[i]);
    printf("...\n");
    printf("  AAD Length:          %u bytes\n", hdr.aad_len);
    printf("  Header MAC:          ");
    for (int i = 0; i < 16; i++) printf("%02x", hdr.header_mac[i]);
    printf("...\n");
    printf("================================================\n\n");
    return 0;
}

static int cmd_benchmark(void) {
    printf("=== RockCrypter Cryptographic Benchmark ===\n");

    /* 1. Core Cipher Block Encryption Benchmark */
    uint8_t key[32];
    uint8_t block[32];
    cv_entropy_get(key, 32);
    cv_entropy_get(block, 32);

    cv_core_ctx_t core_ctx;
    cv_core_expand_key(&core_ctx, key);

    const int core_iters = 500000;
    clock_t start = clock();
    for (int i = 0; i < core_iters; i++) {
        cv_core_encrypt_block(&core_ctx, block, block);
    }
    clock_t end = clock();
    double sec = (double)(end - start) / CLOCKS_PER_SEC;
    double mb = (double)(core_iters * 32) / (1024.0 * 1024.0);
    printf("Core SP-ARX (32 rounds): %.2f MB/s (%d blocks in %.3f s)\n", mb / sec, core_iters, sec);
    cv_core_clear(&core_ctx);

    /* 2. Sponge Absorb/Squeeze Benchmark */
    cv_sponge_t sponge;
    cv_sponge_init(&sponge, 0);
    uint8_t sponge_buf[1024];
    memset(sponge_buf, 0x42, sizeof(sponge_buf));

    const int sponge_iters = 50000;
    start = clock();
    for (int i = 0; i < sponge_iters; i++) {
        cv_sponge_absorb(&sponge, sponge_buf, sizeof(sponge_buf));
    }
    end = clock();
    sec = (double)(end - start) / CLOCKS_PER_SEC;
    mb = (double)(sponge_iters * sizeof(sponge_buf)) / (1024.0 * 1024.0);
    printf("Sponge-512 Permutation:  %.2f MB/s (%.1f MB in %.3f s)\n", mb / sec, mb, sec);
    cv_sponge_clear(&sponge);

    /* 3. KDF Derivation Benchmark (1 MiB base) */
    cv_subkeys_t subkeys;
    start = clock();
    cv_kdf_derive("benchmark_password", 18, key, 1024, 4, &subkeys);
    end = clock();
    sec = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Memory-Hard KDF (1 MiB base, 4 passes): %.3f s per derivation\n", sec);
    cv_subkeys_clear(&subkeys);

    /* 4. Full AEAD Encryption / Decryption Pipeline */
    size_t test_size = 10 * 1024 * 1024; /* 10 MB */
    uint8_t *data = (uint8_t *)malloc(test_size);
    if (data) {
        memset(data, 0x5A, test_size);
        uint8_t *ct = NULL;
        size_t ct_len = 0;

        start = clock();
        int ret = cv_aead_encrypt(data, test_size, (const uint8_t *)"AAD_BENCH", 9,
                                  key, 32, 0, 0, 0, &ct, &ct_len);
        end = clock();
        sec = (double)(end - start) / CLOCKS_PER_SEC;
        if (ret == 0) {
            printf("AEAD Buffer Encryption:  %.2f MB/s (10 MB in %.3f s)\n", 10.0 / sec, sec);

            uint8_t *pt = NULL;
            size_t pt_len = 0;
            start = clock();
            ret = cv_aead_decrypt(ct, ct_len, (const uint8_t *)"AAD_BENCH", 9,
                                  key, 32, 0, &pt, &pt_len);
            end = clock();
            sec = (double)(end - start) / CLOCKS_PER_SEC;
            if (ret == 0) {
                printf("AEAD Buffer Decryption:  %.2f MB/s (10 MB in %.3f s)\n", 10.0 / sec, sec);
                cv_secure_free(pt, pt_len);
            }
            cv_secure_free(ct, ct_len);
        }
        free(data);
    }
    cv_memzero(key, sizeof(key));
    cv_memzero(block, sizeof(block));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];

    if (strcmp(action, "version") == 0 || strcmp(action, "-v") == 0) {
        printf("RockCrypter v%s (Zero-Trust Cryptographic Engine)\n", CRYPTOVAULT_VERSION_STRING);
        return 0;
    }

    if (strcmp(action, "benchmark") == 0 || strcmp(action, "bench") == 0) {
        return cmd_benchmark();
    }

    if (strcmp(action, "inspect") == 0) {
        const char *filepath = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
                filepath = argv[++i];
            }
        }
        return cmd_inspect(filepath);
    }

    if (strcmp(action, "keygen") == 0) {
        const char *outfile = NULL;
        int show_hex = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outfile = argv[++i];
            else if (strcmp(argv[i], "--hex") == 0) show_hex = 1;
        }
        return cmd_keygen(outfile, show_hex);
    }

    if (strcmp(action, "encrypt") == 0 || strcmp(action, "enc") == 0 ||
        strcmp(action, "decrypt") == 0 || strcmp(action, "dec") == 0) {
        int is_enc = (strcmp(action, "encrypt") == 0 || strcmp(action, "enc") == 0);
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
            printf("[*] Encrypting '%s' -> '%s' (1 MiB Chunked Streaming AEAD)...\n", infile, outfile);
            ret = cv_file_encrypt(infile, outfile, secret, secret_len, is_passphrase,
                                  aad, aad_len, 1024, 4);
            if (ret == CV_SUCCESS) {
                printf("[+] Encryption complete successfully -> %s\n", outfile);
            } else {
                fprintf(stderr, "[-] Encryption failed: %s (%d)\n", cv_strerror(ret), ret);
            }
        } else {
            printf("[*] Authenticating and decrypting '%s' -> '%s'...\n", infile, outfile);
            ret = cv_file_decrypt(infile, outfile, secret, secret_len, is_passphrase,
                                  aad, aad_len);
            if (ret == CV_SUCCESS) {
                printf("[+] Decryption and verification PASSED -> %s\n", outfile);
            } else {
                fprintf(stderr, "[-] Decryption failed: %s (%d)\n", cv_strerror(ret), ret);
            }
        }

        cv_memzero(raw_key, sizeof(raw_key));
        return (ret == CV_SUCCESS) ? 0 : 2;
    }

    print_usage(argv[0]);
    return 1;
}
