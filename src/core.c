#include "core.h"
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

/* 8x8 Bijective Affine-Inverted Galois S-Box (Non-linearity 112, 0 Fixed Points) */
static const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* Inverse Galois S-Box */
static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/* Fractional Golden-Ratio Round Constants */
static const uint64_t CORE_RC[33] = {
    0x9E3779B97F4A7C15ULL, 0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL, 0xA4093822299F31D0ULL,
    0x082EFA98EC4E6C89ULL, 0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL, 0xC0AC29B7C97C50DDULL,
    0x3F84D5B5B5470917ULL, 0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL, 0x2FFD72DBD01ADFB7ULL,
    0xB8E1AFED6A267E96ULL, 0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL, 0x0801F2E2858EFC16ULL,
    0x636920D871574E69ULL, 0xA458FEA3F4933D7EULL, 0x0D95748F728EB658ULL, 0x718BCD5882154AEEULL,
    0x7B54A41DC25A59B5ULL, 0x9C30D5392AF26013ULL, 0xC5D1B023286085F0ULL, 0xCA417918B8DB38EFULL,
    0x8E79DCB0603A180EULL, 0x6C9E0E8BB01E8A3EULL, 0xD71577C1BD314B27ULL, 0x78D32FEEC543C123ULL,
    0x9723D190B07FD6E7ULL, 0x42E670233D295257ULL, 0x5AC562B6C3F8A7E2ULL, 0xD34D62EB064E2440ULL,
    0x6E4FE697479B4895ULL
};

static uint64_t sbox_word(uint64_t w) {
    uint8_t b[8];
    store64_le(b, w);
    for (int i = 0; i < 8; i++) {
        b[i] = SBOX[b[i]];
    }
    return load64_le(b);
}

int cv_core_expand_key(cv_core_ctx_t *ctx, const uint8_t key[CV_KEY_SIZE]) {
    if (!ctx || !key) return -1;

    uint64_t W[132]; /* 33 rounds * 4 words */
    W[0] = load64_le(key);
    W[1] = load64_le(key + 8);
    W[2] = load64_le(key + 16);
    W[3] = load64_le(key + 24);

    for (int i = 4; i < 132; i++) {
        uint64_t temp = W[i - 1];
        if (i % 4 == 0) {
            temp = rotl64(sbox_word(temp), 19) ^ CORE_RC[i / 4];
        }
        W[i] = W[i - 4] ^ temp ^ (W[i - 2] * 0x9E3779B97F4A7C15ULL);
    }

    for (int r = 0; r <= CV_ROUNDS; r++) {
        for (int j = 0; j < 4; j++) {
            ctx->round_keys[r][j] = W[r * 4 + j];
        }
    }

    cv_memzero(W, sizeof(W));
    return 0;
}

static void shift_rows_forward(uint8_t state[32]) {
    uint8_t tmp[32];
    memcpy(tmp, state, 8);
    tmp[8]  = state[9];  tmp[9]  = state[10]; tmp[10] = state[11]; tmp[11] = state[12];
    tmp[12] = state[13]; tmp[13] = state[14]; tmp[14] = state[15]; tmp[15] = state[8];

    tmp[16] = state[19]; tmp[17] = state[20]; tmp[18] = state[21]; tmp[19] = state[22];
    tmp[20] = state[23]; tmp[21] = state[16]; tmp[22] = state[17]; tmp[23] = state[18];

    tmp[24] = state[29]; tmp[25] = state[30]; tmp[26] = state[31]; tmp[27] = state[24];
    tmp[28] = state[25]; tmp[29] = state[26]; tmp[30] = state[27]; tmp[31] = state[28];
    memcpy(state, tmp, 32);
    cv_memzero(tmp, sizeof(tmp));
}

static void shift_rows_inverse(uint8_t state[32]) {
    uint8_t tmp[32];
    memcpy(tmp, state, 8);
    tmp[8]  = state[15]; tmp[9]  = state[8];  tmp[10] = state[9];  tmp[11] = state[10];
    tmp[12] = state[11]; tmp[13] = state[12]; tmp[14] = state[13]; tmp[15] = state[14];

    tmp[16] = state[21]; tmp[17] = state[22]; tmp[18] = state[23]; tmp[19] = state[16];
    tmp[20] = state[17]; tmp[21] = state[18]; tmp[22] = state[19]; tmp[23] = state[20];

    tmp[24] = state[27]; tmp[25] = state[28]; tmp[26] = state[29]; tmp[27] = state[30];
    tmp[28] = state[31]; tmp[29] = state[24]; tmp[30] = state[25]; tmp[31] = state[26];
    memcpy(state, tmp, 32);
    cv_memzero(tmp, sizeof(tmp));
}

void cv_core_encrypt_block(const cv_core_ctx_t *ctx, const uint8_t in[CV_BLOCK_SIZE], uint8_t out[CV_BLOCK_SIZE]) {
    uint64_t A = load64_le(in);
    uint64_t B = load64_le(in + 8);
    uint64_t C = load64_le(in + 16);
    uint64_t D = load64_le(in + 24);

    A ^= ctx->round_keys[0][0];
    B ^= ctx->round_keys[0][1];
    C ^= ctx->round_keys[0][2];
    D ^= ctx->round_keys[0][3];

    uint8_t state[32];

    for (int r = 1; r <= CV_ROUNDS; r++) {
        store64_le(state, A);
        store64_le(state + 8, B);
        store64_le(state + 16, C);
        store64_le(state + 24, D);

        /* 1. S-Box Substitution */
        for (int i = 0; i < 32; i++) {
            state[i] = SBOX[state[i]];
        }

        /* 2. Linear ShiftRows */
        shift_rows_forward(state);

        A = load64_le(state);
        B = load64_le(state + 8);
        C = load64_le(state + 16);
        D = load64_le(state + 24);

        /* 3. Word-Level Feistel ARX step */
        A = (A + B) ^ rotl64(D, 17);
        C = (C + D) ^ rotl64(B, 31);
        B = (B + C) ^ rotl64(A, 43);
        D = (D + A) ^ rotl64(C, 25);

        /* 4. Round Key Injection */
        A ^= ctx->round_keys[r][0];
        B ^= ctx->round_keys[r][1];
        C ^= ctx->round_keys[r][2];
        D ^= ctx->round_keys[r][3];
    }

    store64_le(out, A);
    store64_le(out + 8, B);
    store64_le(out + 16, C);
    store64_le(out + 24, D);

    cv_memzero(state, sizeof(state));
}

void cv_core_decrypt_block(const cv_core_ctx_t *ctx, const uint8_t in[CV_BLOCK_SIZE], uint8_t out[CV_BLOCK_SIZE]) {
    uint64_t A = load64_le(in);
    uint64_t B = load64_le(in + 8);
    uint64_t C = load64_le(in + 16);
    uint64_t D = load64_le(in + 24);

    uint8_t state[32];

    for (int r = CV_ROUNDS; r >= 1; r--) {
        /* Invert 4. Key Injection */
        A ^= ctx->round_keys[r][0];
        B ^= ctx->round_keys[r][1];
        C ^= ctx->round_keys[r][2];
        D ^= ctx->round_keys[r][3];

        /* Invert 3. Feistel ARX */
        D = (D ^ rotl64(C, 25)) - A;
        B = (B ^ rotl64(A, 43)) - C;
        C = (C ^ rotl64(B, 31)) - D;
        A = (A ^ rotl64(D, 17)) - B;

        store64_le(state, A);
        store64_le(state + 8, B);
        store64_le(state + 16, C);
        store64_le(state + 24, D);

        /* Invert 2. Linear ShiftRows */
        shift_rows_inverse(state);

        /* Invert 1. S-Box Substitution */
        for (int i = 0; i < 32; i++) {
            state[i] = INV_SBOX[state[i]];
        }

        A = load64_le(state);
        B = load64_le(state + 8);
        C = load64_le(state + 16);
        D = load64_le(state + 24);
    }

    A ^= ctx->round_keys[0][0];
    B ^= ctx->round_keys[0][1];
    C ^= ctx->round_keys[0][2];
    D ^= ctx->round_keys[0][3];

    store64_le(out, A);
    store64_le(out + 8, B);
    store64_le(out + 16, C);
    store64_le(out + 24, D);

    cv_memzero(state, sizeof(state));
}

void cv_core_clear(cv_core_ctx_t *ctx) {
    if (ctx) {
        cv_memzero(ctx, sizeof(*ctx));
    }
}

int cv_core_self_test(void) {
    uint8_t key[CV_KEY_SIZE];
    uint8_t pt[CV_BLOCK_SIZE];
    uint8_t ct[CV_BLOCK_SIZE];
    uint8_t dt[CV_BLOCK_SIZE];

    for (int i = 0; i < CV_KEY_SIZE; i++) key[i] = (uint8_t)(i * 7 + 13);
    for (int i = 0; i < CV_BLOCK_SIZE; i++) pt[i] = (uint8_t)(i * 11 + 3);

    cv_core_ctx_t ctx;
    if (cv_core_expand_key(&ctx, key) != CV_CORE_SUCCESS) return CV_CORE_ERR_KAT;

    cv_core_encrypt_block(&ctx, pt, ct);
    cv_core_decrypt_block(&ctx, ct, dt);

    int cmp = cv_ct_memcmp(pt, dt, CV_BLOCK_SIZE);
    cv_core_clear(&ctx);
    cv_memzero(key, sizeof(key));
    cv_memzero(pt, sizeof(pt));
    cv_memzero(ct, sizeof(ct));
    cv_memzero(dt, sizeof(dt));

    return (cmp == 0) ? CV_CORE_SUCCESS : CV_CORE_ERR_KAT;
}
