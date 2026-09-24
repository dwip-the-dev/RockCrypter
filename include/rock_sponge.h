#ifndef ROCK_SPONGE_H
#define ROCK_SPONGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_SPONGE_STATE_WORDS 8
#define ROCK_SPONGE_STATE_BYTES 64
#define ROCK_SPONGE_RATE_BYTES  32
#define ROCK_SPONGE_ROUNDS      24

typedef struct {
    uint64_t state[ROCK_SPONGE_STATE_WORDS];
    uint8_t  buffer[ROCK_SPONGE_RATE_BYTES];
    size_t   buf_pos;
    int      squeezing;
} rock_sponge_t;

/**
 * Initialize sponge with a domain separation tag.
 */
void rock_sponge_init(rock_sponge_t *ctx, uint64_t domain_tag);

/**
 * Absorb arbitrary data into the sponge.
 */
void rock_sponge_absorb(rock_sponge_t *ctx, const void *data, size_t len);

/**
 * Squeeze arbitrary output bytes from the sponge.
 */
void rock_sponge_squeeze(rock_sponge_t *ctx, void *out, size_t len);

/**
 * Execute 24-round cryptographic permutation on the 512-bit state.
 */
void rock_sponge_permute(uint64_t state[ROCK_SPONGE_STATE_WORDS]);

/**
 * Securely clear the sponge state.
 */
void rock_sponge_clear(rock_sponge_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_SPONGE_H */
