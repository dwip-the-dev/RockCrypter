#include "kdf.h"
#include "sponge.h"
#include "mem.h"
#include <stdlib.h>
#include <string.h>

#define KDF_BLOCK_SIZE 64 /* 512 bits = 8 uint64_t */
#define CV_SUBKEY_SIZE 32

static inline uint64_t load64_le(const uint8_t *b) {
    return ((uint64_t)b[0]) |
           (((uint64_t)b[1]) << 8) |
           (((uint64_t)b[2]) << 16) |
           (((uint64_t)b[3]) << 24) |
           (((uint64_t)b[4]) << 32) |
           (((uint64_t)b[5]) << 40) |
           (((uint64_t)b[6]) << 48) |
           (((uint64_t)b[7]) << 56);
}

static inline void store64_le(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

int cv_kdf_derive(const void *password, size_t pass_len,
                  const uint8_t salt[32],
                  uint32_t mem_cost_kb, uint32_t time_cost,
                  cv_subkeys_t *keys_out) {
    if (!password || !salt || !keys_out) return -1;
    if (mem_cost_kb == 0) mem_cost_kb = CV_DEFAULT_MEM_COST_KB;
    if (mem_cost_kb < 64) mem_cost_kb = 64;
    if (mem_cost_kb > 1048576) return -2; /* 1 GB max */
    if (time_cost == 0) time_cost = CV_DEFAULT_TIME_COST;
    if (time_cost > 100) return -3;

    size_t total_bytes = (size_t)mem_cost_kb * 1024;
    size_t num_blocks = total_bytes / KDF_BLOCK_SIZE;

    uint8_t *mem_grid = (uint8_t *)cv_secure_alloc(total_bytes);
    if (!mem_grid) return -4;

    /* Phase 1: Initialize sponge and perform seed filling */
    cv_sponge_t sponge;
    cv_sponge_init(&sponge, 0x4B44465F494E4954ULL); /* "KDF_INIT" */

    uint32_t meta[2] = { mem_cost_kb, time_cost };
    cv_sponge_absorb(&sponge, meta, sizeof(meta));
    cv_sponge_absorb(&sponge, salt, 32);
    cv_sponge_absorb(&sponge, password, pass_len);

    for (size_t i = 0; i < num_blocks; i++) {
        cv_sponge_squeeze(&sponge, mem_grid + (i * KDF_BLOCK_SIZE), KDF_BLOCK_SIZE);
    }
    cv_sponge_clear(&sponge);

    /* Phase 2: Memory-hard mixing passes */
    uint64_t state[8];
    for (uint32_t t = 0; t < time_cost; t++) {
        for (size_t i = 0; i < num_blocks; i++) {
            size_t prev_idx = (i == 0) ? (num_blocks - 1) : (i - 1);
            const uint8_t *prev_block = mem_grid + (prev_idx * KDF_BLOCK_SIZE);
            uint8_t *curr_block = mem_grid + (i * KDF_BLOCK_SIZE);

            /* Non-linear pseudo-random indexing */
            uint64_t index_seed = load64_le(prev_block) ^ ((uint64_t)t << 32) ^ (uint64_t)i;
            size_t rand_idx = (size_t)(index_seed % num_blocks);
            const uint8_t *rand_block = mem_grid + (rand_idx * KDF_BLOCK_SIZE);

            for (int w = 0; w < 8; w++) {
                uint64_t c = load64_le(curr_block + (w * 8));
                uint64_t p = load64_le(prev_block + (w * 8));
                uint64_t r = load64_le(rand_block + (w * 8));
                state[w] = c ^ p ^ r ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(w + 1));
            }

            cv_sponge_permute(state);

            for (int w = 0; w < 8; w++) {
                store64_le(curr_block + (w * 8), state[w]);
            }
        }
    }
    cv_memzero(state, sizeof(state));

    /* Phase 3: Domain-separated subkey extraction */
    const uint8_t *last_block = mem_grid + ((num_blocks - 1) * KDF_BLOCK_SIZE);

    /* Derive K_enc (Domain Tag 0x01) */
    cv_sponge_init(&sponge, 0x5355424B45595F31ULL);
    cv_sponge_absorb(&sponge, last_block, KDF_BLOCK_SIZE);
    cv_sponge_absorb(&sponge, "ENC_KEY", 7);
    cv_sponge_squeeze(&sponge, keys_out->k_enc, CV_SUBKEY_SIZE);
    cv_sponge_clear(&sponge);

    /* Derive K_white (Domain Tag 0x02) */
    cv_sponge_init(&sponge, 0x5355424B45595F32ULL);
    cv_sponge_absorb(&sponge, last_block, KDF_BLOCK_SIZE);
    cv_sponge_absorb(&sponge, "WHITE_KEY", 9);
    cv_sponge_squeeze(&sponge, keys_out->k_white, CV_SUBKEY_SIZE);
    cv_sponge_clear(&sponge);

    /* Derive K_mac (Domain Tag 0x03) */
    cv_sponge_init(&sponge, 0x5355424B45595F33ULL);
    cv_sponge_absorb(&sponge, last_block, KDF_BLOCK_SIZE);
    cv_sponge_absorb(&sponge, "MAC_KEY", 7);
    cv_sponge_squeeze(&sponge, keys_out->k_mac, CV_SUBKEY_SIZE);
    cv_sponge_clear(&sponge);

    /* Derive K_hdr (Domain Tag 0x04) */
    cv_sponge_init(&sponge, 0x5355424B45595F34ULL);
    cv_sponge_absorb(&sponge, last_block, KDF_BLOCK_SIZE);
    cv_sponge_absorb(&sponge, "HDR_KEY", 7);
    cv_sponge_squeeze(&sponge, keys_out->k_hdr, CV_SUBKEY_SIZE);
    cv_sponge_clear(&sponge);

    /* Derive K_cascade (Domain Tag 0x05) */
    cv_sponge_init(&sponge, 0x5355424B45595F35ULL);
    cv_sponge_absorb(&sponge, last_block, KDF_BLOCK_SIZE);
    cv_sponge_absorb(&sponge, "CASCADE_KEY", 11);
    cv_sponge_squeeze(&sponge, keys_out->k_cascade, CV_SUBKEY_SIZE);
    cv_sponge_clear(&sponge);

    /* Phase 4: Secure Wipe & Free */
    cv_secure_free(mem_grid, total_bytes);
    return 0;
}

void cv_subkeys_clear(cv_subkeys_t *keys) {
    if (keys) {
        cv_memzero(keys, sizeof(*keys));
    }
}

int cv_kdf_self_test(void) {
    uint8_t salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (uint8_t)i;

    cv_subkeys_t k1, k2;
    /* Use 64 KiB scratchpad for rapid unit test verification */
    if (cv_kdf_derive("TestSecretPassphrase", 20, salt, 64, 1, &k1) != 0) {
        return CV_KDF_ERR_SELF_TEST;
    }
    if (cv_kdf_derive("TestSecretPassphrase", 20, salt, 64, 1, &k2) != 0) {
        cv_subkeys_clear(&k1);
        return CV_KDF_ERR_SELF_TEST;
    }

    int match_enc = cv_ct_memcmp(k1.k_enc, k2.k_enc, 32);
    int match_mac = cv_ct_memcmp(k1.k_mac, k2.k_mac, 32);
    int diff_subkeys = cv_ct_memcmp(k1.k_enc, k1.k_mac, 32);

    cv_subkeys_clear(&k1);
    cv_subkeys_clear(&k2);

    if (match_enc != 0 || match_mac != 0 || diff_subkeys == 0) {
        return CV_KDF_ERR_SELF_TEST;
    }
    return CV_KDF_SUCCESS;
}
