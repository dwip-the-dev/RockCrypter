#include "shamir.h"
#include "matrix.h"
#include "entropy.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple CRC32 for share string validation */
static uint32_t compute_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (0 - (crc & 1)));
        }
    }
    return ~crc;
}

int cv_shamir_split(const uint8_t secret[CV_SHAMIR_SECRET_SIZE],
                    uint8_t k, uint8_t n,
                    cv_share_t *shares_out) {
    if (!secret || !shares_out) return -1;
    if (k < 2 || k > n) return -2;

    /* For each of the 32 bytes in secret, generate a random polynomial of degree k-1 */
    /* f(x) = secret[b] + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1} */
    uint8_t *poly_coeffs = (uint8_t *)cv_secure_alloc(k);
    if (!poly_coeffs) return -3;

    for (size_t byte_idx = 0; byte_idx < CV_SHAMIR_SECRET_SIZE; byte_idx++) {
        poly_coeffs[0] = secret[byte_idx];

        /* Generate random higher-degree coefficients */
        if (k > 1) {
            if (cv_entropy_get(poly_coeffs + 1, k - 1) != 0) {
                cv_secure_free(poly_coeffs, k);
                return -4;
            }
        }

        /* Evaluate polynomial at distinct non-zero coordinates x = 1, 2, ..., n */
        for (uint8_t share_idx = 0; share_idx < n; share_idx++) {
            uint8_t x = share_idx + 1;
            shares_out[share_idx].id = x;
            shares_out[share_idx].data[byte_idx] = cv_poly_eval_gf256(poly_coeffs, k - 1, x);
        }
    }

    cv_secure_free(poly_coeffs, k);
    return 0;
}

int cv_shamir_combine(const cv_share_t *shares,
                      uint8_t k,
                      uint8_t secret_out[CV_SHAMIR_SECRET_SIZE]) {
    if (!shares || !secret_out || k < 2) return -1;

    uint8_t *xs = (uint8_t *)malloc(k);
    uint8_t *ys = (uint8_t *)malloc(k);
    if (!xs || !ys) {
        free(xs);
        free(ys);
        return -2;
    }

    /* Verify distinct x coordinates */
    for (size_t i = 0; i < k; i++) {
        xs[i] = shares[i].id;
        if (xs[i] == 0) {
            free(xs); free(ys);
            return -3;
        }
        for (size_t j = 0; j < i; j++) {
            if (xs[i] == xs[j]) {
                free(xs); free(ys);
                return -4; /* Duplicate share coordinate */
            }
        }
    }

    /* Interpolate each of the 32 secret bytes at x = 0 */
    for (size_t byte_idx = 0; byte_idx < CV_SHAMIR_SECRET_SIZE; byte_idx++) {
        for (size_t i = 0; i < k; i++) {
            ys[i] = shares[i].data[byte_idx];
        }
        secret_out[byte_idx] = cv_lagrange_interpolate_zero(xs, ys, k);
    }

    cv_memzero(xs, k);
    cv_memzero(ys, k);
    free(xs);
    free(ys);
    return 0;
}

int cv_shamir_share_to_string(const cv_share_t *share, char *str_out, size_t max_len) {
    if (!share || !str_out || max_len < 80) return -1;

    uint8_t raw[1 + CV_SHAMIR_SECRET_SIZE];
    raw[0] = share->id;
    memcpy(raw + 1, share->data, CV_SHAMIR_SECRET_SIZE);

    uint32_t crc = compute_crc32(raw, sizeof(raw));

    char hex[65];
    for (int i = 0; i < CV_SHAMIR_SECRET_SIZE; i++) {
        snprintf(hex + (i * 2), 3, "%02x", share->data[i]);
    }

    snprintf(str_out, max_len, "CVSHARE-%02X-%s-%08X", share->id, hex, crc);
    return 0;
}

int cv_shamir_share_from_string(const char *str_in, cv_share_t *share_out) {
    if (!str_in || !share_out) return -1;

    if (strncmp(str_in, "CVSHARE-", 8) != 0) return -2;

    unsigned int id = 0;
    char hex[65];
    unsigned int crc_in = 0;

    if (sscanf(str_in + 8, "%02X-%64s-%08X", &id, hex, &crc_in) != 3) {
        return -3;
    }

    if (id == 0 || id > 255) return -4;
    share_out->id = (uint8_t)id;

    for (int i = 0; i < CV_SHAMIR_SECRET_SIZE; i++) {
        unsigned int byte_val;
        if (sscanf(hex + (i * 2), "%02x", &byte_val) != 1) {
            return -5;
        }
        share_out->data[i] = (uint8_t)byte_val;
    }

    uint8_t raw[1 + CV_SHAMIR_SECRET_SIZE];
    raw[0] = share_out->id;
    memcpy(raw + 1, share_out->data, CV_SHAMIR_SECRET_SIZE);

    uint32_t crc_calc = compute_crc32(raw, sizeof(raw));
    if (crc_calc != (uint32_t)crc_in) {
        cv_memzero(share_out, sizeof(*share_out));
        return -6; /* Checksum mismatch */
    }

    return 0;
}

int cv_shamir_self_test(void) {
    uint8_t secret[CV_SHAMIR_SECRET_SIZE];
    uint8_t recovered[CV_SHAMIR_SECRET_SIZE];
    for (int i = 0; i < CV_SHAMIR_SECRET_SIZE; i++) secret[i] = (uint8_t)(i * 9 + 42);

    cv_share_t shares[5];
    if (cv_shamir_split(secret, 3, 5, shares) != CV_SHAMIR_SUCCESS) {
        return CV_SHAMIR_ERR_SELFTEST;
    }

    /* Test subset of 3 shares: index 0, 2, 4 */
    cv_share_t subset[3];
    subset[0] = shares[0];
    subset[1] = shares[2];
    subset[2] = shares[4];

    if (cv_shamir_combine(subset, 3, recovered) != CV_SHAMIR_SUCCESS) {
        return CV_SHAMIR_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(secret, recovered, CV_SHAMIR_SECRET_SIZE) != 0) {
        return CV_SHAMIR_ERR_SELFTEST;
    }

    /* Test string serialization */
    char str[128];
    cv_share_t parsed;
    if (cv_shamir_share_to_string(&shares[1], str, sizeof(str)) != CV_SHAMIR_SUCCESS) {
        return CV_SHAMIR_ERR_SELFTEST;
    }
    if (cv_shamir_share_from_string(str, &parsed) != CV_SHAMIR_SUCCESS) {
        return CV_SHAMIR_ERR_SELFTEST;
    }
    if (parsed.id != shares[1].id || cv_ct_memcmp(parsed.data, shares[1].data, CV_SHAMIR_SECRET_SIZE) != 0) {
        return CV_SHAMIR_ERR_SELFTEST;
    }

    cv_memzero(secret, sizeof(secret));
    cv_memzero(recovered, sizeof(recovered));
    cv_memzero(shares, sizeof(shares));
    cv_memzero(subset, sizeof(subset));
    return CV_SHAMIR_SUCCESS;
}
