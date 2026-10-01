#include "sponge_hash.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
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

int cv_hash_init(cv_hash_ctx_t *ctx, size_t digest_len) {
    if (!ctx) return CV_HASH_ERR_INVALID;
    if (digest_len != CV_HASH256_SIZE && digest_len != CV_HASH512_SIZE) {
        return CV_HASH_ERR_MODE;
    }
    cv_memzero(ctx, sizeof(*ctx));

    /* Domain-separated hash seeds */
    uint64_t domain = (digest_len == 32) ? 0x4841534832353631ULL /* "HASH2561" */
                                         : 0x4841534835313231ULL;/* "HASH5121" */
    cv_sponge_init(&ctx->sponge, domain);
    ctx->total_bytes = 0;
    ctx->digest_len = digest_len;
    return CV_HASH_SUCCESS;
}

int cv_hash_update(cv_hash_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx) return CV_HASH_ERR_INVALID;
    if (len == 0) return CV_HASH_SUCCESS;
    if (!data) return CV_HASH_ERR_INVALID;

    cv_sponge_absorb(&ctx->sponge, data, len);
    ctx->total_bytes += len;
    return CV_HASH_SUCCESS;
}

int cv_hash_final(cv_hash_ctx_t *ctx, uint8_t *digest_out) {
    if (!ctx || !digest_out) return CV_HASH_ERR_INVALID;

    uint8_t len_bytes[8];
    store64_le(len_bytes, ctx->total_bytes);
    cv_sponge_absorb(&ctx->sponge, len_bytes, 8);

    cv_sponge_squeeze(&ctx->sponge, digest_out, ctx->digest_len);
    cv_sponge_clear(&ctx->sponge);
    cv_memzero(ctx, sizeof(*ctx));
    cv_memzero(len_bytes, sizeof(len_bytes));
    return CV_HASH_SUCCESS;
}

int cv_hash256(const void *data, size_t len, uint8_t digest[CV_HASH256_SIZE]) {
    cv_hash_ctx_t ctx;
    int ret = cv_hash_init(&ctx, CV_HASH256_SIZE);
    if (ret != CV_HASH_SUCCESS) return ret;

    ret = cv_hash_update(&ctx, data, len);
    if (ret != CV_HASH_SUCCESS) {
        cv_sponge_clear(&ctx.sponge);
        return ret;
    }
    return cv_hash_final(&ctx, digest);
}

int cv_hash512(const void *data, size_t len, uint8_t digest[CV_HASH512_SIZE]) {
    cv_hash_ctx_t ctx;
    int ret = cv_hash_init(&ctx, CV_HASH512_SIZE);
    if (ret != CV_HASH_SUCCESS) return ret;

    ret = cv_hash_update(&ctx, data, len);
    if (ret != CV_HASH_SUCCESS) {
        cv_sponge_clear(&ctx.sponge);
        return ret;
    }
    return cv_hash_final(&ctx, digest);
}

int cv_hash_file(const char *path, uint8_t digest[CV_HASH256_SIZE]) {
    if (!path || !digest) return CV_HASH_ERR_INVALID;
    FILE *f = fopen(path, "rb");
    if (!f) return CV_HASH_ERR_IO;

    cv_hash_ctx_t ctx;
    int ret = cv_hash_init(&ctx, CV_HASH256_SIZE);
    if (ret != CV_HASH_SUCCESS) {
        fclose(f);
        return ret;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        cv_hash_update(&ctx, buf, n);
    }
    fclose(f);
    cv_memzero(buf, sizeof(buf));
    return cv_hash_final(&ctx, digest);
}

int cv_hash_self_test(void) {
    const char msg[] = "The quick brown fox jumps over the lazy dog";
    uint8_t d1[CV_HASH256_SIZE];
    uint8_t d2[CV_HASH256_SIZE];
    uint8_t d512[CV_HASH512_SIZE];

    if (cv_hash256(msg, strlen(msg), d1) != CV_HASH_SUCCESS) return CV_HASH_ERR_SELFTEST;
    if (cv_hash256(msg, strlen(msg), d2) != CV_HASH_SUCCESS) return CV_HASH_ERR_SELFTEST;
    if (cv_hash512(msg, strlen(msg), d512) != CV_HASH_SUCCESS) return CV_HASH_ERR_SELFTEST;

    /* Digests must match for identical input */
    if (cv_ct_memcmp(d1, d2, CV_HASH256_SIZE) != 0) return CV_HASH_ERR_SELFTEST;

    /* Squeezed 256 and 512 must have distinct domain prefix */
    if (cv_ct_memcmp(d1, d512, CV_HASH256_SIZE) == 0) return CV_HASH_ERR_SELFTEST;

    cv_memzero(d1, sizeof(d1));
    cv_memzero(d2, sizeof(d2));
    cv_memzero(d512, sizeof(d512));
    return CV_HASH_SUCCESS;
}
