#include "hkdf.h"
#include "mac.h"
#include "mem.h"
#include <string.h>

int cv_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk_out[CV_HKDF_HASH_LEN]) {
    if (!ikm || !prk_out) return CV_HKDF_ERR_INVALID;

    uint8_t zero_salt[CV_HKDF_HASH_LEN];
    memset(zero_salt, 0, sizeof(zero_salt));

    const uint8_t *actual_salt = salt ? salt : zero_salt;
    size_t actual_salt_len = salt ? salt_len : sizeof(zero_salt);

    /* PRK = HMAC-Hash(actual_salt, IKM) */
    uint8_t salt_key[CV_HKDF_HASH_LEN];
    if (actual_salt_len == CV_HKDF_HASH_LEN) {
        memcpy(salt_key, actual_salt, CV_HKDF_HASH_LEN);
    } else {
        cv_mac_compute(zero_salt, actual_salt, actual_salt_len, salt_key);
    }

    int ret = cv_mac_compute(salt_key, ikm, ikm_len, prk_out);
    cv_memzero(salt_key, sizeof(salt_key));
    cv_memzero(zero_salt, sizeof(zero_salt));
    return (ret == 0) ? CV_HKDF_SUCCESS : CV_HKDF_ERR_INVALID;
}

int cv_hkdf_expand(const uint8_t prk[CV_HKDF_HASH_LEN],
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm_out, size_t okm_len) {
    if (!prk || !okm_out) return CV_HKDF_ERR_INVALID;
    if (okm_len > CV_HKDF_MAX_OKM_LEN) return CV_HKDF_ERR_TOO_BIG;
    if (okm_len == 0) return CV_HKDF_SUCCESS;

    size_t n = (okm_len + CV_HKDF_HASH_LEN - 1) / CV_HKDF_HASH_LEN;
    uint8_t T[CV_HKDF_HASH_LEN];
    size_t t_len = 0;
    size_t generated = 0;

    for (uint8_t i = 1; i <= (uint8_t)n; i++) {
        cv_mac_ctx_t ctx;
        if (cv_mac_init(&ctx, prk) != CV_MAC_SUCCESS) {
            cv_memzero(T, sizeof(T));
            return CV_HKDF_ERR_INVALID;
        }

        /* T(i) = HMAC(PRK, T(i-1) | info | i) */
        if (t_len > 0) {
            cv_mac_update(&ctx, T, t_len);
        }
        if (info && info_len > 0) {
            cv_mac_update(&ctx, info, info_len);
        }
        cv_mac_update(&ctx, &i, 1);
        cv_mac_final(&ctx, T);
        t_len = CV_HKDF_HASH_LEN;

        size_t to_copy = (okm_len - generated < CV_HKDF_HASH_LEN) ?
                         (okm_len - generated) : CV_HKDF_HASH_LEN;
        memcpy(okm_out + generated, T, to_copy);
        generated += to_copy;
    }

    cv_memzero(T, sizeof(T));
    return CV_HKDF_SUCCESS;
}

int cv_hkdf(const uint8_t *salt, size_t salt_len,
            const uint8_t *ikm, size_t ikm_len,
            const uint8_t *info, size_t info_len,
            uint8_t *okm_out, size_t okm_len) {
    uint8_t prk[CV_HKDF_HASH_LEN];
    int ret = cv_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (ret != CV_HKDF_SUCCESS) return ret;

    ret = cv_hkdf_expand(prk, info, info_len, okm_out, okm_len);
    cv_memzero(prk, sizeof(prk));
    return ret;
}

int cv_hkdf_self_test(void) {
    const uint8_t ikm[] = "0x0b0b0b0b0b0b0b0b0b0b";
    const uint8_t salt[] = "0x0001020304";
    const uint8_t info[] = "0xf0f1f2f3";

    uint8_t okm1[64];
    uint8_t okm2[64];
    uint8_t okm3[64];

    if (cv_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm1, sizeof(okm1)) != CV_HKDF_SUCCESS) {
        return CV_HKDF_ERR_SELFTEST;
    }
    if (cv_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm2, sizeof(okm2)) != CV_HKDF_SUCCESS) {
        return CV_HKDF_ERR_SELFTEST;
    }
    /* Changing info must produce totally distinct output */
    const uint8_t alt_info[] = "0xf0f1f2f4";
    if (cv_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), alt_info, sizeof(alt_info), okm3, sizeof(okm3)) != CV_HKDF_SUCCESS) {
        return CV_HKDF_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(okm1, okm2, sizeof(okm1)) != 0) return CV_HKDF_ERR_SELFTEST;
    if (cv_ct_memcmp(okm1, okm3, sizeof(okm1)) == 0) return CV_HKDF_ERR_SELFTEST;

    cv_memzero(okm1, sizeof(okm1));
    cv_memzero(okm2, sizeof(okm2));
    cv_memzero(okm3, sizeof(okm3));
    return CV_HKDF_SUCCESS;
}
