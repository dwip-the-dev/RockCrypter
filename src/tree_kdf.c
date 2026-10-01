/**
 * @file tree_kdf.c
 * @brief Hierarchical Key Tree, Per-Block Derivation, Key Rotation & Expiration Engine.
 *
 * Implements HKDF-based hierarchical key derivation trees providing multi-level
 * key isolation, per-chunk distinct keys, automatic ratcheted rotation, and
 * temporal expiration bounds.
 */

#include "tree_kdf.h"
#include "hkdf.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int cv_tree_kdf_init(cv_key_tree_ctx_t *ctx,
                     const uint8_t master_secret[CV_TREE_KEY_SIZE],
                     const char *app_id,
                     const char *file_id,
                     uint64_t valid_secs,
                     uint64_t rotate_bytes) {
    if (!ctx || !master_secret || !app_id || !file_id) return CV_TREE_ERR_PARAM;

    cv_memzero(ctx, sizeof(*ctx));
    memcpy(ctx->master_key, master_secret, CV_TREE_KEY_SIZE);

    strncpy(ctx->app_id, app_id, CV_TREE_MAX_APP_ID - 1);
    strncpy(ctx->file_id, file_id, CV_TREE_MAX_FILE_ID - 1);

    uint64_t now = (uint64_t)time(NULL);
    ctx->valid_from = now;
    ctx->valid_until = (valid_secs > 0) ? (now + valid_secs) : 0;
    ctx->current_epoch = 0;
    ctx->bytes_processed = 0;
    ctx->rotation_threshold_bytes = (rotate_bytes > 0) ? rotate_bytes : (1024ULL * 1024ULL * 1024ULL); /* 1 GiB */

    /* 1. Derive Application-Level Key: K_app = HKDF(K_master, app_id) */
    if (cv_hkdf(NULL, 0, ctx->master_key, CV_TREE_KEY_SIZE,
                (const uint8_t *)app_id, strlen(app_id),
                ctx->app_key, CV_TREE_KEY_SIZE) != 0) {
        cv_tree_kdf_clear(ctx);
        return CV_TREE_ERR_PARAM;
    }

    /* 2. Derive File-Level Key: K_file = HKDF(K_app, file_id) */
    if (cv_hkdf(NULL, 0, ctx->app_key, CV_TREE_KEY_SIZE,
                (const uint8_t *)file_id, strlen(file_id),
                ctx->file_key, CV_TREE_KEY_SIZE) != 0) {
        cv_tree_kdf_clear(ctx);
        return CV_TREE_ERR_PARAM;
    }

    /* 3. Derive Initial Epoch Key: K_epoch_0 = HKDF(K_file, "EPOCH:0") */
    const char *epoch0_info = "EPOCH_ROOT_V1:0";
    if (cv_hkdf(NULL, 0, ctx->file_key, CV_TREE_KEY_SIZE,
                (const uint8_t *)epoch0_info, strlen(epoch0_info),
                ctx->epoch_key, CV_TREE_KEY_SIZE) != 0) {
        cv_tree_kdf_clear(ctx);
        return CV_TREE_ERR_PARAM;
    }

    return CV_TREE_SUCCESS;
}

int cv_tree_kdf_derive_chunk_key(cv_key_tree_ctx_t *ctx,
                                 uint64_t chunk_index,
                                 cv_key_role_t role,
                                 uint64_t current_time,
                                 uint8_t subkey_out[CV_TREE_KEY_SIZE]) {
    if (!ctx || !subkey_out) return CV_TREE_ERR_PARAM;

    uint64_t now = (current_time > 0) ? current_time : (uint64_t)time(NULL);

    /* Temporal Expiration Verification */
    if (ctx->valid_from > 0 && now < ctx->valid_from) return CV_TREE_ERR_NOT_YET;
    if (ctx->valid_until > 0 && now > ctx->valid_until) return CV_TREE_ERR_EXPIRED;

    /* Build Domain-Separated Context Info: "ROLE:X;CHUNK:Y" */
    char info[96];
    const char *role_str = "UNKNOWN";
    switch (role) {
        case CV_KEY_ROLE_ENCRYPTION:     role_str = "ENC"; break;
        case CV_KEY_ROLE_AUTHENTICATION: role_str = "MAC"; break;
        case CV_KEY_ROLE_METADATA:       role_str = "META"; break;
        case CV_KEY_ROLE_HEADER:         role_str = "HDR"; break;
        case CV_KEY_ROLE_RATCHET:        role_str = "RATCHET"; break;
    }

    snprintf(info, sizeof(info), "CRYPTOVAULT_CHUNK;ROLE=%s;IDX=%llu;EPOCH=%llu",
             role_str, (unsigned long long)chunk_index,
             (unsigned long long)ctx->current_epoch);

    /* Derive per-chunk key from active epoch key */
    int ret = cv_hkdf(NULL, 0, ctx->epoch_key, CV_TREE_KEY_SIZE,
                      (const uint8_t *)info, strlen(info),
                      subkey_out, CV_TREE_KEY_SIZE);

    cv_memzero(info, sizeof(info));
    return (ret == 0) ? CV_TREE_SUCCESS : CV_TREE_ERR_PARAM;
}

int cv_tree_rotate_epoch(cv_key_tree_ctx_t *ctx) {
    if (!ctx) return CV_TREE_ERR_PARAM;

    uint64_t next_epoch = ctx->current_epoch + 1;
    char epoch_info[64];
    snprintf(epoch_info, sizeof(epoch_info), "EPOCH_ADVANCE;NEXT=%llu",
             (unsigned long long)next_epoch);

    uint8_t new_epoch_key[CV_TREE_KEY_SIZE];
    int ret = cv_hkdf(ctx->epoch_key, CV_TREE_KEY_SIZE,
                      ctx->file_key, CV_TREE_KEY_SIZE,
                      (const uint8_t *)epoch_info, strlen(epoch_info),
                      new_epoch_key, CV_TREE_KEY_SIZE);

    if (ret != 0) return CV_TREE_ERR_PARAM;

    /* Securely overwrite and rotate */
    cv_memzero(ctx->epoch_key, CV_TREE_KEY_SIZE);
    memcpy(ctx->epoch_key, new_epoch_key, CV_TREE_KEY_SIZE);
    cv_memzero(new_epoch_key, sizeof(new_epoch_key));
    cv_memzero(epoch_info, sizeof(epoch_info));

    ctx->current_epoch = next_epoch;
    ctx->bytes_processed = 0;

    return CV_TREE_SUCCESS;
}

int cv_tree_account_bytes(cv_key_tree_ctx_t *ctx, size_t bytes_written) {
    if (!ctx) return CV_TREE_ERR_PARAM;

    ctx->bytes_processed += bytes_written;
    if (ctx->rotation_threshold_bytes > 0 &&
        ctx->bytes_processed >= ctx->rotation_threshold_bytes) {
        return cv_tree_rotate_epoch(ctx);
    }

    return CV_TREE_SUCCESS;
}

void cv_tree_kdf_clear(cv_key_tree_ctx_t *ctx) {
    if (ctx) {
        cv_memzero(ctx, sizeof(*ctx));
    }
}

int cv_tree_kdf_self_test(void) {
    uint8_t master[32];
    for (int i = 0; i < 32; i++) master[i] = (uint8_t)(i * 3 + 1);

    cv_key_tree_ctx_t ctx;
    if (cv_tree_kdf_init(&ctx, master, "TestApp", "TestFile-1234", 3600, 1048576) != CV_TREE_SUCCESS) {
        return CV_TREE_ERR_SELFTEST;
    }

    /* Verify per-chunk key uniqueness */
    uint8_t k_enc_0[32], k_enc_1[32], k_mac_0[32];
    cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, 0, k_enc_0);
    cv_tree_kdf_derive_chunk_key(&ctx, 1, CV_KEY_ROLE_ENCRYPTION, 0, k_enc_1);
    cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_AUTHENTICATION, 0, k_mac_0);

    /* Keys for different chunks must be distinct */
    if (cv_ct_memcmp(k_enc_0, k_enc_1, 32) == 0) {
        cv_tree_kdf_clear(&ctx);
        return CV_TREE_ERR_SELFTEST;
    }

    /* Keys for different roles on same chunk must be distinct */
    if (cv_ct_memcmp(k_enc_0, k_mac_0, 32) == 0) {
        cv_tree_kdf_clear(&ctx);
        return CV_TREE_ERR_SELFTEST;
    }

    /* Test automatic rotation */
    cv_tree_account_bytes(&ctx, 1048576);
    if (ctx.current_epoch != 1) {
        cv_tree_kdf_clear(&ctx);
        return CV_TREE_ERR_SELFTEST;
    }

    /* Test expiration boundary */
    uint8_t k_expired[32];
    uint64_t future = ctx.valid_until + 100;
    if (cv_tree_kdf_derive_chunk_key(&ctx, 0, CV_KEY_ROLE_ENCRYPTION, future, k_expired) != CV_TREE_ERR_EXPIRED) {
        cv_tree_kdf_clear(&ctx);
        return CV_TREE_ERR_SELFTEST;
    }

    cv_tree_kdf_clear(&ctx);
    cv_memzero(master, sizeof(master));
    cv_memzero(k_enc_0, sizeof(k_enc_0));
    cv_memzero(k_enc_1, sizeof(k_enc_1));
    cv_memzero(k_mac_0, sizeof(k_mac_0));

    return CV_TREE_SUCCESS;
}
