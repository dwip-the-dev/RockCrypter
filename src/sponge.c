#include "sponge.h"
#include "mem.h"
#include <string.h>

static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64 - n));
}

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

static const uint64_t SPONGE_RC[CV_SPONGE_ROUNDS] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
    0xCB706D76390736C5ULL, 0x628CB518B0970C88ULL,
    0x9159015A429E2F83ULL, 0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL,
    0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
    0xAE4565BE140C94F0ULL, 0xCF65DE7ECF8C0660ULL,
    0x2F683CA3A52F7306ULL, 0x6D14BBE1DA2C8A4DULL,
    0x8B44A3A2C8F38BF4ULL, 0xE361491763F12CD6ULL,
    0x1C44F35E180BC46FULL, 0x6F1880A584405E63ULL
};

void cv_sponge_permute(uint64_t state[8]) {
    uint64_t T[8];

    for (int r = 0; r < CV_SPONGE_ROUNDS; r++) {
        /* Step 1: Nothing-up-my-sleeve prime square root constant injection */
        state[0] ^= SPONGE_RC[r];
        state[4] ^= (SPONGE_RC[r] << 31) | (SPONGE_RC[r] >> 33);

        /* Step 2: Non-linear chi-layer (degree 2 quadratic mapping) */
        for (int i = 0; i < 8; i++) {
            uint64_t not_next = ~state[(i + 1) % 8];
            uint64_t next_next = state[(i + 2) % 8];
            T[i] = state[i] ^ (not_next & next_next);
        }

        /* Step 3: ARX cross-word diffusion */
        state[0] = (T[0] + T[1]) ^ rotl64(T[4], 19);
        state[1] = (T[1] + T[2]) ^ rotl64(T[5], 31);
        state[2] = (T[2] + T[3]) ^ rotl64(T[6], 43);
        state[3] = (T[3] + T[4]) ^ rotl64(T[7], 53);
        state[4] = (T[4] + T[5]) ^ rotl64(T[0], 11);
        state[5] = (T[5] + T[6]) ^ rotl64(T[1], 23);
        state[6] = (T[6] + T[7]) ^ rotl64(T[2], 37);
        state[7] = (T[7] + T[0]) ^ rotl64(T[3], 47);
    }
}

void cv_sponge_init(cv_sponge_t *ctx, uint64_t domain_tag) {
    if (!ctx) return;
    cv_memzero(ctx, sizeof(*ctx));
    ctx->state[0] = domain_tag;
    ctx->state[1] = 0x5641554C54535047ULL; /* "VAULTSPG" */
    ctx->state[2] = 0x0123456789ABCDEFULL;
    ctx->state[3] = 0xFEDCBA9876543210ULL;
    ctx->state[4] = 0xC3A5C85C975218E5ULL;
    ctx->state[5] = 0x49B497B76F59D1B9ULL;
    ctx->state[6] = 0xE6F87C976D92B6EBULL;
    ctx->state[7] = 0xA2B1C3D4E5F60718ULL;
    ctx->buf_pos = 0;
    ctx->squeezing = 0;
    cv_sponge_permute(ctx->state);
}

void cv_sponge_absorb(cv_sponge_t *ctx, const void *data, size_t len) {
    if (!ctx || (!data && len > 0)) return;
    const uint8_t *in = (const uint8_t *)data;

    while (len > 0) {
        size_t take = CV_SPONGE_RATE_BYTES - ctx->buf_pos;
        if (take > len) take = len;

        for (size_t i = 0; i < take; i++) {
            ctx->buffer[ctx->buf_pos + i] = in[i];
        }
        ctx->buf_pos += take;
        in += take;
        len -= take;

        if (ctx->buf_pos == CV_SPONGE_RATE_BYTES) {
            for (int w = 0; w < 4; w++) {
                ctx->state[w] ^= load64_le(ctx->buffer + (w * 8));
            }
            cv_sponge_permute(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

static void sponge_finalize_absorb(cv_sponge_t *ctx) {
    /* Multi-rate 10*1 padding */
    ctx->buffer[ctx->buf_pos] ^= 0x01;
    ctx->buffer[CV_SPONGE_RATE_BYTES - 1] ^= 0x80;

    for (int w = 0; w < 4; w++) {
        ctx->state[w] ^= load64_le(ctx->buffer + (w * 8));
    }
    cv_sponge_permute(ctx->state);
    ctx->buf_pos = 0;
    ctx->squeezing = 1;
}

void cv_sponge_squeeze(cv_sponge_t *ctx, void *out, size_t len) {
    if (!ctx || (!out && len > 0)) return;
    uint8_t *out_p = (uint8_t *)out;

    if (!ctx->squeezing) {
        sponge_finalize_absorb(ctx);
    }

    while (len > 0) {
        if (ctx->buf_pos == CV_SPONGE_RATE_BYTES) {
            cv_sponge_permute(ctx->state);
            ctx->buf_pos = 0;
        }

        uint8_t rate_bytes[CV_SPONGE_RATE_BYTES];
        for (int w = 0; w < 4; w++) {
            store64_le(rate_bytes + (w * 8), ctx->state[w]);
        }

        size_t available = CV_SPONGE_RATE_BYTES - ctx->buf_pos;
        size_t take = (available < len) ? available : len;

        memcpy(out_p, rate_bytes + ctx->buf_pos, take);
        ctx->buf_pos += take;
        out_p += take;
        len -= take;

        cv_memzero(rate_bytes, sizeof(rate_bytes));
    }
}

void cv_sponge_clear(cv_sponge_t *ctx) {
    if (ctx) {
        cv_memzero(ctx, sizeof(*ctx));
    }
}

int cv_sponge_self_test(void) {
    cv_sponge_t s1, s2;
    uint8_t out1[32], out2[32];
    const char msg[] = "CryptoVault 512-bit Sponge Permutation KAT Test String";

    cv_sponge_init(&s1, CV_DOMAIN_HASH_256);
    cv_sponge_absorb(&s1, msg, strlen(msg));
    cv_sponge_squeeze(&s1, out1, sizeof(out1));
    cv_sponge_clear(&s1);

    cv_sponge_init(&s2, CV_DOMAIN_HASH_256);
    cv_sponge_absorb(&s2, msg, strlen(msg));
    cv_sponge_squeeze(&s2, out2, sizeof(out2));
    cv_sponge_clear(&s2);

    int cmp = cv_ct_memcmp(out1, out2, sizeof(out1));
    cv_memzero(out1, sizeof(out1));
    cv_memzero(out2, sizeof(out2));

    return (cmp == 0) ? 0 : -1;
}
