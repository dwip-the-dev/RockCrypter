#include "rock_kdf.h"
#include "rock_sponge.h"
#include "rock_mem.h"
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 64 /* 512 bits = 8 uint64_t */

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

int rock_kdf_derive(const void *password, size_t pass_len,
                    const uint8_t salt[32],
                    uint32_t mem_cost_kb, uint32_t time_cost,
                    rock_subkeys_t *keys_out) {
    if (!password || !salt || !keys_out) return -1;
    if (mem_cost_kb < 64) mem_cost_kb = 64;
    if (mem_cost_kb > 1048576) return -2; /* 1 GB limit */
    if (time_cost < 1) time_cost = 1;
    if (time_cost > 100) return -3;

    size_t total_bytes = (size_t)mem_cost_kb * 1024;
    size_t num_blocks = total_bytes / BLOCK_SIZE;

    uint8_t *mem_grid = (uint8_t *)rock_secure_alloc(total_bytes);
    if (!mem_grid) return -4;

    /* Phase 1: Initialize sponge and perform seed filling */
    rock_sponge_t sponge;
    rock_sponge_init(&sponge, 0x4B44465F494E4954ULL); /* "KDF_INIT" */

    /* Absorb metadata & secrets */
    uint32_t meta[2] = { mem_cost_kb, time_cost };
    rock_sponge_absorb(&sponge, meta, sizeof(meta));
    rock_sponge_absorb(&sponge, salt, 32);
    rock_sponge_absorb(&sponge, password, pass_len);

    /* Fill memory grid */
    for (size_t i = 0; i < num_blocks; i++) {
        rock_sponge_squeeze(&sponge, mem_grid + (i * BLOCK_SIZE), BLOCK_SIZE);
    }
    rock_sponge_clear(&sponge);

    /* Phase 2: Memory-hard mixing passes */
    uint64_t state[8];
    for (uint32_t t = 0; t < time_cost; t++) {
        for (size_t i = 0; i < num_blocks; i++) {
            size_t prev_idx = (i == 0) ? (num_blocks - 1) : (i - 1);
            const uint8_t *prev_block = mem_grid + (prev_idx * BLOCK_SIZE);
            uint8_t *curr_block = mem_grid + (i * BLOCK_SIZE);

            /* Non-linear pseudo-random indexing based on previous block content */
            uint64_t index_seed = load64_le(prev_block) ^ ((uint64_t)t << 32) ^ (uint64_t)i;
            size_t rand_idx = (size_t)(index_seed % num_blocks);
            const uint8_t *rand_block = mem_grid + (rand_idx * BLOCK_SIZE);

            /* Load and mix */
            for (int w = 0; w < 8; w++) {
                uint64_t c = load64_le(curr_block + (w * 8));
                uint64_t p = load64_le(prev_block + (w * 8));
                uint64_t r = load64_le(rand_block + (w * 8));
                state[w] = c ^ p ^ r ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(w + 1));
            }

            rock_sponge_permute(state);

            for (int w = 0; w < 8; w++) {
                store64_le(curr_block + (w * 8), state[w]);
            }
        }
    }
    rock_memzero(state, sizeof(state));

    /* Phase 3: Domain-separated subkey derivation */
    const uint8_t *last_block = mem_grid + ((num_blocks - 1) * BLOCK_SIZE);

    /* Derive K_enc (Domain Tag 0x01) */
    rock_sponge_init(&sponge, 0x5355424B45595F31ULL); /* "SUBKEY_1" */
    rock_sponge_absorb(&sponge, last_block, BLOCK_SIZE);
    rock_sponge_absorb(&sponge, "ENC_KEY", 7);
    rock_sponge_squeeze(&sponge, keys_out->k_enc, ROCK_SUBKEY_SIZE);
    rock_sponge_clear(&sponge);

    /* Derive K_white (Domain Tag 0x02) */
    rock_sponge_init(&sponge, 0x5355424B45595F32ULL); /* "SUBKEY_2" */
    rock_sponge_absorb(&sponge, last_block, BLOCK_SIZE);
    rock_sponge_absorb(&sponge, "WHITE_KEY", 9);
    rock_sponge_squeeze(&sponge, keys_out->k_white, ROCK_SUBKEY_SIZE);
    rock_sponge_clear(&sponge);

    /* Derive K_mac (Domain Tag 0x03) */
    rock_sponge_init(&sponge, 0x5355424B45595F33ULL); /* "SUBKEY_3" */
    rock_sponge_absorb(&sponge, last_block, BLOCK_SIZE);
    rock_sponge_absorb(&sponge, "MAC_KEY", 7);
    rock_sponge_squeeze(&sponge, keys_out->k_mac, ROCK_SUBKEY_SIZE);
    rock_sponge_clear(&sponge);

    /* Derive K_hdr (Domain Tag 0x04) */
    rock_sponge_init(&sponge, 0x5355424B45595F34ULL); /* "SUBKEY_4" */
    rock_sponge_absorb(&sponge, last_block, BLOCK_SIZE);
    rock_sponge_absorb(&sponge, "HDR_KEY", 7);
    rock_sponge_squeeze(&sponge, keys_out->k_hdr, ROCK_SUBKEY_SIZE);
    rock_sponge_clear(&sponge);

    /* Phase 4: Secure Wipe & Free */
    rock_secure_free(mem_grid, total_bytes);
    return 0;
}

void rock_subkeys_clear(rock_subkeys_t *keys) {
    if (keys) {
        rock_memzero(keys, sizeof(*keys));
    }
}
