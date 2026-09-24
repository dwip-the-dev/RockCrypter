#ifndef ROCK_MAC_H
#define ROCK_MAC_H

#include "rock_sponge.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_MAC_KEY_SIZE 32
#define ROCK_MAC_TAG_SIZE 32

typedef struct {
    rock_sponge_t sponge;
    uint64_t      total_bytes;
} rock_mac_ctx_t;

/**
 * Initialize RockMAC context with a 256-bit key.
 */
int rock_mac_init(rock_mac_ctx_t *ctx, const uint8_t key[ROCK_MAC_KEY_SIZE]);

/**
 * Update MAC with arbitrary data chunk.
 */
int rock_mac_update(rock_mac_ctx_t *ctx, const void *data, size_t len);

/**
 * Finalize and produce 256-bit authentication tag.
 * Automatically clears the context.
 */
int rock_mac_final(rock_mac_ctx_t *ctx, uint8_t tag[ROCK_MAC_TAG_SIZE]);

/**
 * Direct one-shot MAC calculation.
 */
int rock_mac_compute(const uint8_t key[ROCK_MAC_KEY_SIZE],
                     const void *data, size_t len,
                     uint8_t tag[ROCK_MAC_TAG_SIZE]);

/**
 * Constant-time MAC verification.
 * Returns 0 on valid match, negative on authentication failure.
 */
int rock_mac_verify(const uint8_t key[ROCK_MAC_KEY_SIZE],
                    const void *data, size_t len,
                    const uint8_t expected_tag[ROCK_MAC_TAG_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_MAC_H */
