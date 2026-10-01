#include "matrix.h"
#include "mem.h"
#include <string.h>

/* Irreducible polynomial P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B) */
#define GF256_POLY 0x11B

uint8_t cv_gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit;

    /* Constant-time Russian Peasant / shift-and-add algorithm */
    for (int i = 0; i < 8; i++) {
        uint8_t mask = 0 - (b & 1);
        p ^= (a & mask);
        hi_bit = (a & 0x80);
        a <<= 1;
        uint8_t poly_mask = 0 - ((hi_bit >> 7) & 1);
        a ^= (0x1B & poly_mask);
        b >>= 1;
    }
    return p;
}

uint8_t cv_gf256_inv(uint8_t a) {
    if (a == 0) return 0;

    /* Fermat's Little Theorem in GF(2^8): a^(254) = a^(-1) mod P(x) */
    /* Exponent 254 = 11111110 in binary */
    uint8_t a2 = cv_gf256_mul(a, a);       /* a^2 */
    uint8_t a3 = cv_gf256_mul(a2, a);      /* a^3 */
    uint8_t a6 = cv_gf256_mul(a3, a3);     /* a^6 */
    uint8_t a12 = cv_gf256_mul(a6, a6);    /* a^12 */
    uint8_t a14 = cv_gf256_mul(a12, a2);   /* a^14 */
    uint8_t a15 = cv_gf256_mul(a14, a);    /* a^15 */
    uint8_t a30 = cv_gf256_mul(a15, a15);  /* a^30 */
    uint8_t a60 = cv_gf256_mul(a30, a30);  /* a^60 */
    uint8_t a120 = cv_gf256_mul(a60, a60); /* a^120 */
    uint8_t a126 = cv_gf256_mul(a120, a6); /* a^126 */
    uint8_t a252 = cv_gf256_mul(a126, a126); /* a^252 */
    uint8_t a254 = cv_gf256_mul(a252, a2);   /* a^254 = a^(-1) */
    return a254;
}

/* 4x4 Circulant MDS Matrix: [02, 03, 01, 01] */
static const uint8_t MDS4[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

/* Inverse 4x4 Circulant MDS Matrix: [0E, 0B, 0D, 09] */
static const uint8_t INV_MDS4[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

void cv_mds_multiply_4x4(const uint8_t in[4], uint8_t out[4]) {
    for (int i = 0; i < 4; i++) {
        uint8_t acc = 0;
        for (int j = 0; j < 4; j++) {
            acc ^= cv_gf256_mul(MDS4[i][j], in[j]);
        }
        out[i] = acc;
    }
}

void cv_mds_inv_multiply_4x4(const uint8_t in[4], uint8_t out[4]) {
    for (int i = 0; i < 4; i++) {
        uint8_t acc = 0;
        for (int j = 0; j < 4; j++) {
            acc ^= cv_gf256_mul(INV_MDS4[i][j], in[j]);
        }
        out[i] = acc;
    }
}

/* 8x8 Hadamard-Cauchy MDS Matrix over GF(2^8) */
static const uint8_t MDS8[8][8] = {
    {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80},
    {0x02, 0x01, 0x08, 0x04, 0x20, 0x10, 0x80, 0x40},
    {0x04, 0x08, 0x01, 0x02, 0x40, 0x80, 0x10, 0x20},
    {0x08, 0x04, 0x02, 0x01, 0x80, 0x40, 0x20, 0x10},
    {0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08},
    {0x20, 0x10, 0x80, 0x40, 0x02, 0x01, 0x08, 0x04},
    {0x40, 0x80, 0x10, 0x20, 0x04, 0x08, 0x01, 0x02},
    {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
};

/* Inverse 8x8 Hadamard-Cauchy MDS Matrix over GF(2^8) */
static const uint8_t INV_MDS8[8][8] = {
    {0x4B, 0x96, 0x37, 0x6E, 0xDC, 0xA3, 0x5D, 0xBA},
    {0x96, 0x4B, 0x6E, 0x37, 0xA3, 0xDC, 0xBA, 0x5D},
    {0x37, 0x6E, 0x4B, 0x96, 0x5D, 0xBA, 0xDC, 0xA3},
    {0x6E, 0x37, 0x96, 0x4B, 0xBA, 0x5D, 0xA3, 0xDC},
    {0xDC, 0xA3, 0x5D, 0xBA, 0x4B, 0x96, 0x37, 0x6E},
    {0xA3, 0xDC, 0xBA, 0x5D, 0x96, 0x4B, 0x6E, 0x37},
    {0x5D, 0xBA, 0xDC, 0xA3, 0x37, 0x6E, 0x4B, 0x96},
    {0xBA, 0x5D, 0xA3, 0xDC, 0x6E, 0x37, 0x96, 0x4B}
};

void cv_mds_multiply_8x8(const uint8_t in[8], uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        uint8_t acc = 0;
        for (int j = 0; j < 8; j++) {
            acc ^= cv_gf256_mul(MDS8[i][j], in[j]);
        }
        out[i] = acc;
    }
}

void cv_mds_inv_multiply_8x8(const uint8_t in[8], uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        uint8_t acc = 0;
        for (int j = 0; j < 8; j++) {
            acc ^= cv_gf256_mul(INV_MDS8[i][j], in[j]);
        }
        out[i] = acc;
    }
}

uint8_t cv_poly_eval_gf256(const uint8_t *coeffs, size_t deg, uint8_t x) {
    if (!coeffs) return 0;
    if (deg == 0) return coeffs[0];

    /* Horner's method: f(x) = a_0 + x * (a_1 + x * (a_2 + ...)) */
    uint8_t res = coeffs[deg];
    for (int i = (int)deg - 1; i >= 0; i--) {
        res = cv_gf256_mul(res, x) ^ coeffs[i];
    }
    return res;
}

uint8_t cv_lagrange_interpolate_zero(const uint8_t *xs, const uint8_t *ys, size_t k) {
    if (!xs || !ys || k == 0) return 0;

    uint8_t secret = 0;

    for (size_t i = 0; i < k; i++) {
        uint8_t num = 1;
        uint8_t den = 1;

        for (size_t j = 0; j < k; j++) {
            if (i == j) continue;
            /* num = prod(0 - x_j) = prod(x_j) since -x = x in GF(2^8) */
            num = cv_gf256_mul(num, xs[j]);
            /* den = prod(x_i - x_j) = prod(x_i ^ x_j) */
            den = cv_gf256_mul(den, xs[i] ^ xs[j]);
        }

        uint8_t basis = cv_gf256_mul(num, cv_gf256_inv(den));
        uint8_t term = cv_gf256_mul(ys[i], basis);
        secret ^= term;
    }

    return secret;
}

int cv_matrix_self_test(void) {
    /* 1. Test GF(2^8) inversion: a * a^-1 == 1 for all a in [1..255] */
    for (int i = 1; i <= 255; i++) {
        uint8_t a = (uint8_t)i;
        uint8_t inv = cv_gf256_inv(a);
        if (cv_gf256_mul(a, inv) != 1) return CV_MATRIX_ERR_TEST;
    }

    /* 2. Test 4x4 MDS invertible roundtrip */
    uint8_t vec4[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t out4[4];
    uint8_t rec4[4];
    cv_mds_multiply_4x4(vec4, out4);
    cv_mds_inv_multiply_4x4(out4, rec4);
    if (cv_ct_memcmp(vec4, rec4, 4) != 0) return CV_MATRIX_ERR_TEST;

    /* 3. Test 8x8 MDS invertible roundtrip */
    uint8_t vec8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t out8[8];
    uint8_t rec8[8];
    cv_mds_multiply_8x8(vec8, out8);
    cv_mds_inv_multiply_8x8(out8, rec8);
    if (cv_ct_memcmp(vec8, rec8, 8) != 0) return CV_MATRIX_ERR_TEST;

    return CV_MATRIX_SUCCESS;
}
