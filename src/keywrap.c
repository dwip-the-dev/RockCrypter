/**
 * @file keywrap.c
 * @brief NIST SP 800-38F / RFC 3394 Symmetric Key Wrap & Key Unwrap Engine.
 *
 * Implements deterministic authenticated key encapsulation for target secret keys
 * under a 256-bit Key-Encrypting Key (KEK) using a 128-bit constant-time ARX
 * block permutation over 6 outer passes (6n semiblock iterations).
 */

#include "keywrap.h"
#include "mem.h"
#include <stdlib.h>
#include <string.h>

/* Standard RFC 3394 Default Initial Value: 0xA6A6A6A6A6A6A6A6 */
static const uint8_t DEFAULT_IV[8] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static inline void store64_be(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

static inline uint64_t load64_be(const uint8_t *b) {
    return (((uint64_t)b[0]) << 56) |
           (((uint64_t)b[1]) << 48) |
           (((uint64_t)b[2]) << 40) |
           (((uint64_t)b[3]) << 32) |
           (((uint64_t)b[4]) << 24) |
           (((uint64_t)b[5]) << 16) |
           (((uint64_t)b[6]) << 8) |
           ((uint64_t)b[7]);
}

#define KW_ROUNDS 34

typedef struct {
    uint64_t round_keys[KW_ROUNDS];
} kw_ctx_t;

static void kw_expand_key(kw_ctx_t *ctx, const uint8_t kek[32]) {
    uint64_t k = load64_be(kek);
    uint64_t l[KW_ROUNDS + 4];
    l[0] = load64_be(kek + 8);
    l[1] = load64_be(kek + 16);
    l[2] = load64_be(kek + 24);

    for (uint64_t r = 0; r < KW_ROUNDS; r++) {
        ctx->round_keys[r] = k;
        uint64_t l_new = (ROTR64(l[r], 8) + k) ^ r;
        l[r + 3] = l_new;
        k = ROTL64(k, 3) ^ l_new;
    }

    cv_memzero(l, sizeof(l));
    k = 0;
}

static void kw_encrypt_block(const kw_ctx_t *ctx, uint64_t *x, uint64_t *y) {
    uint64_t a = *x;
    uint64_t b = *y;
    for (int r = 0; r < KW_ROUNDS; r++) {
        a = (ROTR64(a, 8) + b) ^ ctx->round_keys[r];
        b = ROTL64(b, 3) ^ a;
    }
    *x = a;
    *y = b;
}

static void kw_decrypt_block(const kw_ctx_t *ctx, uint64_t *x, uint64_t *y) {
    uint64_t a = *x;
    uint64_t b = *y;
    for (int r = KW_ROUNDS - 1; r >= 0; r--) {
        b = ROTR64(b ^ a, 3);
        a = ROTL64((a ^ ctx->round_keys[r]) - b, 8);
    }
    *x = a;
    *y = b;
}

int cv_key_wrap(const uint8_t kek[32],
                const uint8_t *in_key, size_t in_len,
                uint8_t *out_wrapped) {
    if (!kek || !in_key || !out_wrapped) return CV_KW_ERR_INVALID;
    if (in_len < 16 || (in_len % 8) != 0) return CV_KW_ERR_ALIGNMENT;

    size_t n = in_len / 8;
    uint64_t *R = (uint64_t *)cv_secure_alloc((n + 1) * sizeof(uint64_t));
    if (!R) return CV_KW_ERR_ALLOC;

    /* A = IV */
    uint64_t A = load64_be(DEFAULT_IV);

    /* R_1 ... R_n = P_1 ... P_n */
    for (size_t i = 1; i <= n; i++) {
        R[i] = load64_be(in_key + ((i - 1) * 8));
    }

    kw_ctx_t ctx;
    kw_expand_key(&ctx, kek);

    /* 6 wrapping rounds over n semiblocks */
    for (uint64_t j = 0; j <= 5; j++) {
        for (uint64_t i = 1; i <= n; i++) {
            uint64_t t = (n * j) + i;
            uint64_t x = A;
            uint64_t y = R[i];

            kw_encrypt_block(&ctx, &x, &y);

            A = x ^ t;
            R[i] = y;
        }
    }

    cv_memzero(&ctx, sizeof(ctx));

    /* Output: A | R_1 | ... | R_n */
    store64_be(out_wrapped, A);
    for (size_t i = 1; i <= n; i++) {
        store64_be(out_wrapped + (i * 8), R[i]);
    }

    cv_secure_free(R, (n + 1) * sizeof(uint64_t));
    A = 0;
    return CV_KW_SUCCESS;
}

int cv_key_unwrap(const uint8_t kek[32],
                  const uint8_t *in_wrapped, size_t in_len,
                  uint8_t *out_key) {
    if (!kek || !in_wrapped || !out_key) return CV_KW_ERR_INVALID;
    if (in_len < 24 || (in_len % 8) != 0) return CV_KW_ERR_ALIGNMENT;

    size_t n = (in_len / 8) - 1;
    uint64_t *R = (uint64_t *)cv_secure_alloc((n + 1) * sizeof(uint64_t));
    if (!R) return CV_KW_ERR_ALLOC;

    uint64_t A = load64_be(in_wrapped);
    for (size_t i = 1; i <= n; i++) {
        R[i] = load64_be(in_wrapped + (i * 8));
    }

    kw_ctx_t ctx;
    kw_expand_key(&ctx, kek);

    /* Invert 6 rounds */
    for (int64_t j = 5; j >= 0; j--) {
        for (int64_t i = n; i >= 1; i--) {
            uint64_t t = (n * (uint64_t)j) + (uint64_t)i;
            uint64_t x = A ^ t;
            uint64_t y = R[i];

            kw_decrypt_block(&ctx, &x, &y);

            A = x;
            R[i] = y;
        }
    }

    cv_memzero(&ctx, sizeof(ctx));

    /* Verify integrity: A must match DEFAULT_IV */
    uint8_t a_bytes[8];
    store64_be(a_bytes, A);
    if (cv_ct_memcmp(a_bytes, DEFAULT_IV, 8) != 0) {
        cv_secure_free(R, (n + 1) * sizeof(uint64_t));
        cv_memzero(a_bytes, sizeof(a_bytes));
        A = 0;
        return CV_KW_ERR_INTEGRITY; /* Authentication failed */
    }
    cv_memzero(a_bytes, sizeof(a_bytes));

    for (size_t i = 1; i <= n; i++) {
        store64_be(out_key + ((i - 1) * 8), R[i]);
    }

    cv_secure_free(R, (n + 1) * sizeof(uint64_t));
    A = 0;
    return CV_KW_SUCCESS;
}

int cv_keywrap_self_test(void) {
    uint8_t kek[32];
    uint8_t target_key[32];
    uint8_t wrapped[40];
    uint8_t unwrapped[32];

    for (int i = 0; i < 32; i++) {
        kek[i] = (uint8_t)(i * 3 + 17);
        target_key[i] = (uint8_t)(i * 5 + 31);
    }

    if (cv_key_wrap(kek, target_key, sizeof(target_key), wrapped) != CV_KW_SUCCESS) {
        return CV_KW_ERR_SELFTEST;
    }

    if (cv_key_unwrap(kek, wrapped, sizeof(wrapped), unwrapped) != CV_KW_SUCCESS) {
        return CV_KW_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(target_key, unwrapped, sizeof(target_key)) != 0) {
        return CV_KW_ERR_SELFTEST;
    }

    /* Verify tamper detection: flip 1 bit in wrapped buffer */
    wrapped[15] ^= 0x01;
    if (cv_key_unwrap(kek, wrapped, sizeof(wrapped), unwrapped) == CV_KW_SUCCESS) {
        return CV_KW_ERR_SELFTEST; /* Tampered key unwrap must fail */
    }

    cv_memzero(kek, sizeof(kek));
    cv_memzero(target_key, sizeof(target_key));
    cv_memzero(wrapped, sizeof(wrapped));
    cv_memzero(unwrapped, sizeof(unwrapped));

    return CV_KW_SUCCESS;
}
