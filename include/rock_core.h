#ifndef ROCK_CORE_H
#define ROCK_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_CORE_BLOCK_SIZE 32 /* 256 bits */
#define ROCK_CORE_KEY_SIZE   32 /* 256 bits */
#define ROCK_CORE_ROUNDS     32

typedef struct {
    /* 33 subkeys (pre-whitening + 32 rounds), each 4x 64-bit words */
    uint64_t round_keys[ROCK_CORE_ROUNDS + 1][4];
} rock_core_ctx_t;

/**
 * Initialize and expand 256-bit key into round keys.
 */
int rock_core_expand_key(rock_core_ctx_t *ctx, const uint8_t key[ROCK_CORE_KEY_SIZE]);

/**
 * Encrypt a single 256-bit (32-byte) block.
 */
void rock_core_encrypt_block(const rock_core_ctx_t *ctx, const uint8_t in[ROCK_CORE_BLOCK_SIZE], uint8_t out[ROCK_CORE_BLOCK_SIZE]);

/**
 * Decrypt a single 256-bit (32-byte) block.
 */
void rock_core_decrypt_block(const rock_core_ctx_t *ctx, const uint8_t in[ROCK_CORE_BLOCK_SIZE], uint8_t out[ROCK_CORE_BLOCK_SIZE]);

/**
 * Securely clear the core context and round keys.
 */
void rock_core_clear(rock_core_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_CORE_H */
