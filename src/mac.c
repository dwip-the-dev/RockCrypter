#include "mac.h"
#include "mem.h"
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

int cv_mac_init(cv_mac_ctx_t *ctx, const uint8_t key[CV_MAC_KEY_SIZE]) {
    if (!ctx || !key) return CV_MAC_ERR_INVALID;
    cv_memzero(ctx, sizeof(*ctx));
    cv_sponge_init(&ctx->sponge, 0x415554484D414331ULL); /* "AUTHMAC1" */

    cv_sponge_absorb(&ctx->sponge, key, CV_MAC_KEY_SIZE);
    ctx->total_bytes = 0;
    ctx->finalized = 0;
    return CV_MAC_SUCCESS;
}

int cv_mac_update(cv_mac_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || ctx->finalized) return CV_MAC_ERR_INVALID;
    if (len == 0) return CV_MAC_SUCCESS;
    if (!data) return CV_MAC_ERR_INVALID;

    cv_sponge_absorb(&ctx->sponge, data, len);
    ctx->total_bytes += len;
    return CV_MAC_SUCCESS;
}

int cv_mac_final(cv_mac_ctx_t *ctx, uint8_t tag[CV_MAC_TAG_SIZE]) {
    if (!ctx || ctx->finalized || !tag) return CV_MAC_ERR_INVALID;

    uint8_t len_bytes[8];
    store64_le(len_bytes, ctx->total_bytes);
    cv_sponge_absorb(&ctx->sponge, len_bytes, 8);

    cv_sponge_squeeze(&ctx->sponge, tag, CV_MAC_TAG_SIZE);

    cv_sponge_clear(&ctx->sponge);
    ctx->finalized = 1;
    cv_memzero(ctx, sizeof(*ctx));
    cv_memzero(len_bytes, sizeof(len_bytes));
    return CV_MAC_SUCCESS;
}

int cv_mac_compute(const uint8_t key[CV_MAC_KEY_SIZE],
                   const void *data, size_t len,
                   uint8_t tag[CV_MAC_TAG_SIZE]) {
    cv_mac_ctx_t ctx;
    int ret = cv_mac_init(&ctx, key);
    if (ret != CV_MAC_SUCCESS) return ret;

    ret = cv_mac_update(&ctx, data, len);
    if (ret != CV_MAC_SUCCESS) {
        cv_sponge_clear(&ctx.sponge);
        return ret;
    }
    return cv_mac_final(&ctx, tag);
}

int cv_mac_verify(const uint8_t key[CV_MAC_KEY_SIZE],
                  const void *data, size_t len,
                  const uint8_t expected_tag[CV_MAC_TAG_SIZE]) {
    uint8_t computed_tag[CV_MAC_TAG_SIZE];
    int ret = cv_mac_compute(key, data, len, computed_tag);
    if (ret != CV_MAC_SUCCESS) return ret;

    int cmp = cv_ct_memcmp(computed_tag, expected_tag, CV_MAC_TAG_SIZE);
    cv_memzero(computed_tag, sizeof(computed_tag));
    return (cmp == 0) ? CV_MAC_SUCCESS : CV_MAC_ERR_FORGERY;
}

int cv_mac_self_test(void) {
    uint8_t key[CV_MAC_KEY_SIZE];
    for (int i = 0; i < CV_MAC_KEY_SIZE; i++) key[i] = (uint8_t)(i + 1);

    const char msg1[] = "CryptoVault High Assurance MAC Test Message 1";
    const char msg2[] = "CryptoVault High Assurance MAC Test Message 2";

    uint8_t tag1[CV_MAC_TAG_SIZE];
    uint8_t tag2[CV_MAC_TAG_SIZE];
    uint8_t tag1_verify[CV_MAC_TAG_SIZE];

    if (cv_mac_compute(key, msg1, strlen(msg1), tag1) != CV_MAC_SUCCESS) {
        return CV_MAC_ERR_SELFTEST;
    }
    if (cv_mac_compute(key, msg2, strlen(msg2), tag2) != CV_MAC_SUCCESS) {
        return CV_MAC_ERR_SELFTEST;
    }
    if (cv_mac_compute(key, msg1, strlen(msg1), tag1_verify) != CV_MAC_SUCCESS) {
        return CV_MAC_ERR_SELFTEST;
    }

    /* Verification tests */
    if (cv_ct_memcmp(tag1, tag1_verify, CV_MAC_TAG_SIZE) != 0) {
        return CV_MAC_ERR_SELFTEST;
    }
    if (cv_ct_memcmp(tag1, tag2, CV_MAC_TAG_SIZE) == 0) {
        return CV_MAC_ERR_SELFTEST;
    }
    if (cv_mac_verify(key, msg1, strlen(msg1), tag1) != CV_MAC_SUCCESS) {
        return CV_MAC_ERR_SELFTEST;
    }
    if (cv_mac_verify(key, msg1, strlen(msg1), tag2) == CV_MAC_SUCCESS) {
        return CV_MAC_ERR_SELFTEST; /* Forged tag must fail */
    }

    cv_memzero(key, sizeof(key));
    cv_memzero(tag1, sizeof(tag1));
    cv_memzero(tag2, sizeof(tag2));
    cv_memzero(tag1_verify, sizeof(tag1_verify));

    return CV_MAC_SUCCESS;
}
