#include "rock_mac.h"
#include "rock_mem.h"
#include <string.h>

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

int rock_mac_init(rock_mac_ctx_t *ctx, const uint8_t key[ROCK_MAC_KEY_SIZE]) {
    if (!ctx || !key) return -1;
    rock_memzero(ctx, sizeof(*ctx));
    rock_sponge_init(&ctx->sponge, 0x524F434B4D414331ULL); /* "ROCKMAC1" */

    /* Key absorption and domain setup */
    rock_sponge_absorb(&ctx->sponge, key, ROCK_MAC_KEY_SIZE);
    ctx->total_bytes = 0;
    return 0;
}

int rock_mac_update(rock_mac_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || (!data && len > 0)) return -1;
    rock_sponge_absorb(&ctx->sponge, data, len);
    ctx->total_bytes += len;
    return 0;
}

int rock_mac_final(rock_mac_ctx_t *ctx, uint8_t tag[ROCK_MAC_TAG_SIZE]) {
    if (!ctx || !tag) return -1;

    /* Length encoding absorption to prevent extension attacks */
    uint8_t len_bytes[8];
    store64_le(len_bytes, ctx->total_bytes);
    rock_sponge_absorb(&ctx->sponge, len_bytes, 8);

    /* Squeeze authentication tag */
    rock_sponge_squeeze(&ctx->sponge, tag, ROCK_MAC_TAG_SIZE);

    /* Securely wipe state */
    rock_sponge_clear(&ctx->sponge);
    rock_memzero(ctx, sizeof(*ctx));
    return 0;
}

int rock_mac_compute(const uint8_t key[ROCK_MAC_KEY_SIZE],
                     const void *data, size_t len,
                     uint8_t tag[ROCK_MAC_TAG_SIZE]) {
    rock_mac_ctx_t ctx;
    int ret = rock_mac_init(&ctx, key);
    if (ret != 0) return ret;
    ret = rock_mac_update(&ctx, data, len);
    if (ret != 0) {
        rock_sponge_clear(&ctx.sponge);
        return ret;
    }
    return rock_mac_final(&ctx, tag);
}

int rock_mac_verify(const uint8_t key[ROCK_MAC_KEY_SIZE],
                    const void *data, size_t len,
                    const uint8_t expected_tag[ROCK_MAC_TAG_SIZE]) {
    uint8_t computed_tag[ROCK_MAC_TAG_SIZE];
    int ret = rock_mac_compute(key, data, len, computed_tag);
    if (ret != 0) return -1;

    int cmp = rock_ct_memcmp(computed_tag, expected_tag, ROCK_MAC_TAG_SIZE);
    rock_memzero(computed_tag, sizeof(computed_tag));
    return (cmp == 0) ? 0 : -2;
}
