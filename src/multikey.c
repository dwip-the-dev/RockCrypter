/**
 * @file multikey.c
 * @brief Multi-Key Decryption, Dual-Authority Quorum & Recovery Key Management.
 *
 * Implements multi-party key encapsulation mechanisms for dual-authorization
 * (2-of-2 mandatory quorums) and multi-recipient key bags with offline recovery keys.
 */

#include "multikey.h"
#include "keywrap.h"
#include "aead.h"
#include "hkdf.h"
#include "sponge_hash.h"
#include "entropy.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void compute_key_id(const uint8_t key[32], uint8_t id_out[8]) {
    uint8_t digest[32];
    cv_hash256(key, 32, digest);
    memcpy(id_out, digest, 8);
    cv_memzero(digest, sizeof(digest));
}

static void derive_joint_key(const uint8_t k1[32], const uint8_t k2[32], uint8_t joint_out[32]) {
    cv_hkdf(k1, 32, k2, 32, (const uint8_t *)"DUAL_AUTHORITY_JOINT_KEY_V1", 28, joint_out, 32);
}

int cv_multikey_encrypt_dual(const uint8_t *plaintext, size_t pt_len,
                             const uint8_t key1[CV_MULTIKEY_KEY_SIZE],
                             const uint8_t key2[CV_MULTIKEY_KEY_SIZE],
                             uint8_t **out_buf, size_t *out_len) {
    if (!plaintext || !key1 || !key2 || !out_buf || !out_len) return CV_MK_ERR_PARAM;

    /* 1. Generate random 256-bit file session key */
    uint8_t session_key[32];
    if (cv_entropy_get(session_key, sizeof(session_key)) != 0) return CV_MK_ERR_PARAM;

    /* 2. Derive joint key requiring BOTH keys */
    uint8_t joint_key[32];
    derive_joint_key(key1, key2, joint_key);

    /* 3. Wrap session key under joint key */
    cv_multikey_header_t hdr;
    cv_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, CV_MULTIKEY_MAGIC, CV_MULTIKEY_MAGIC_LEN);
    hdr.version = 0x0200;
    hdr.num_slots = 1;
    hdr.flags = 0x0001; /* Dual-Auth */

    compute_key_id(joint_key, hdr.slots[0].key_id);
    if (cv_key_wrap(joint_key, session_key, 32, hdr.slots[0].wrapped_session_key) != 0) {
        cv_memzero(session_key, sizeof(session_key));
        cv_memzero(joint_key, sizeof(joint_key));
        return CV_MK_ERR_PARAM;
    }
    cv_memzero(joint_key, sizeof(joint_key));

    /* 4. Encrypt payload under session key */
    uint8_t *aead_buf = NULL;
    size_t aead_len = 0;
    int ret = cv_aead_encrypt(plaintext, pt_len, (const uint8_t *)"DUAL_AUTH_V1", 12,
                              session_key, 32, 0, 0, 0,
                              &aead_buf, &aead_len);
    cv_memzero(session_key, sizeof(session_key));

    if (ret != CV_SUCCESS) {
        cv_memzero(&hdr, sizeof(hdr));
        return ret;
    }

    /* 5. Calculate Header MAC */
    size_t header_body_len = offsetof(cv_multikey_header_t, header_mac);
    cv_hash256(&hdr, header_body_len, hdr.header_mac);

    /* 6. Assemble container */
    size_t total = sizeof(cv_multikey_header_t) + aead_len;
    uint8_t *container = (uint8_t *)cv_secure_alloc(total);
    if (!container) {
        cv_secure_free(aead_buf, aead_len);
        return CV_MK_ERR_ALLOC;
    }

    memcpy(container, &hdr, sizeof(hdr));
    memcpy(container + sizeof(hdr), aead_buf, aead_len);
    cv_secure_free(aead_buf, aead_len);

    *out_buf = container;
    *out_len = total;
    return CV_MK_SUCCESS;
}

int cv_multikey_decrypt_dual(const uint8_t *container, size_t cont_len,
                             const uint8_t key1[CV_MULTIKEY_KEY_SIZE],
                             const uint8_t key2[CV_MULTIKEY_KEY_SIZE],
                             uint8_t **out_pt, size_t *out_pt_len) {
    if (!container || !key1 || !key2 || !out_pt || !out_pt_len) return CV_MK_ERR_PARAM;
    if (cont_len < sizeof(cv_multikey_header_t)) return CV_MK_ERR_PARAM;

    const cv_multikey_header_t *hdr = (const cv_multikey_header_t *)container;
    if (cv_ct_memcmp(hdr->magic, CV_MULTIKEY_MAGIC, CV_MULTIKEY_MAGIC_LEN) != 0) {
        return CV_MK_ERR_PARAM;
    }

    /* Verify Header Seal */
    uint8_t expected_seal[32];
    size_t header_body_len = offsetof(cv_multikey_header_t, header_mac);
    cv_hash256(hdr, header_body_len, expected_seal);
    if (cv_ct_memcmp(hdr->header_mac, expected_seal, 32) != 0) {
        return CV_MK_ERR_AUTH;
    }

    /* Derive joint key */
    uint8_t joint_key[32];
    derive_joint_key(key1, key2, joint_key);

    /* Unwrap session key */
    uint8_t session_key[32];
    int unwrap_ret = cv_key_unwrap(joint_key, hdr->slots[0].wrapped_session_key, 40, session_key);
    cv_memzero(joint_key, sizeof(joint_key));
    if (unwrap_ret != 0) {
        return CV_MK_ERR_AUTH; /* Key mismatch or tampering */
    }

    /* Decrypt payload */
    const uint8_t *aead_buf = container + sizeof(cv_multikey_header_t);
    size_t aead_len = cont_len - sizeof(cv_multikey_header_t);

    int dec_ret = cv_aead_decrypt(aead_buf, aead_len, (const uint8_t *)"DUAL_AUTH_V1", 12,
                                  session_key, 32, 0,
                                  out_pt, out_pt_len);
    cv_memzero(session_key, sizeof(session_key));
    return dec_ret;
}

int cv_multikey_encrypt_multi_recipient(const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t (*recipient_keys)[CV_MULTIKEY_KEY_SIZE],
                                        size_t num_recipients,
                                        uint8_t **out_buf, size_t *out_len) {
    if (!plaintext || !recipient_keys || num_recipients == 0 ||
        num_recipients > CV_MULTIKEY_MAX_SLOTS || !out_buf || !out_len) {
        return CV_MK_ERR_PARAM;
    }

    uint8_t session_key[32];
    if (cv_entropy_get(session_key, sizeof(session_key)) != 0) return CV_MK_ERR_PARAM;

    cv_multikey_header_t hdr;
    cv_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, CV_MULTIKEY_MAGIC, CV_MULTIKEY_MAGIC_LEN);
    hdr.version = 0x0200;
    hdr.num_slots = (uint16_t)num_recipients;
    hdr.flags = 0x0002; /* Multi-Recipient */

    for (size_t i = 0; i < num_recipients; i++) {
        compute_key_id(recipient_keys[i], hdr.slots[i].key_id);
        if (cv_key_wrap(recipient_keys[i], session_key, 32, hdr.slots[i].wrapped_session_key) != 0) {
            cv_memzero(session_key, sizeof(session_key));
            return CV_MK_ERR_PARAM;
        }
    }

    uint8_t *aead_buf = NULL;
    size_t aead_len = 0;
    int ret = cv_aead_encrypt(plaintext, pt_len, (const uint8_t *)"MULTI_RECIPIENT_V1", 18,
                              session_key, 32, 0, 0, 0,
                              &aead_buf, &aead_len);
    cv_memzero(session_key, sizeof(session_key));

    if (ret != CV_SUCCESS) return ret;

    size_t header_body_len = offsetof(cv_multikey_header_t, header_mac);
    cv_hash256(&hdr, header_body_len, hdr.header_mac);

    size_t total = sizeof(cv_multikey_header_t) + aead_len;
    uint8_t *container = (uint8_t *)cv_secure_alloc(total);
    if (!container) {
        cv_secure_free(aead_buf, aead_len);
        return CV_MK_ERR_ALLOC;
    }

    memcpy(container, &hdr, sizeof(hdr));
    memcpy(container + sizeof(hdr), aead_buf, aead_len);
    cv_secure_free(aead_buf, aead_len);

    *out_buf = container;
    *out_len = total;
    return CV_MK_SUCCESS;
}

int cv_multikey_decrypt_recipient(const uint8_t *container, size_t cont_len,
                                  const uint8_t recipient_key[CV_MULTIKEY_KEY_SIZE],
                                  uint8_t **out_pt, size_t *out_pt_len) {
    if (!container || !recipient_key || !out_pt || !out_pt_len) return CV_MK_ERR_PARAM;
    if (cont_len < sizeof(cv_multikey_header_t)) return CV_MK_ERR_PARAM;

    const cv_multikey_header_t *hdr = (const cv_multikey_header_t *)container;
    if (cv_ct_memcmp(hdr->magic, CV_MULTIKEY_MAGIC, CV_MULTIKEY_MAGIC_LEN) != 0) {
        return CV_MK_ERR_PARAM;
    }

    uint8_t candidate_id[8];
    compute_key_id(recipient_key, candidate_id);

    int matched_slot = -1;
    for (size_t i = 0; i < hdr->num_slots; i++) {
        if (cv_ct_memcmp(hdr->slots[i].key_id, candidate_id, 8) == 0) {
            matched_slot = (int)i;
            break;
        }
    }

    if (matched_slot < 0) return CV_MK_ERR_NOT_FOUND;

    uint8_t session_key[32];
    if (cv_key_unwrap(recipient_key, hdr->slots[matched_slot].wrapped_session_key, 40, session_key) != 0) {
        return CV_MK_ERR_AUTH;
    }

    const uint8_t *aead_buf = container + sizeof(cv_multikey_header_t);
    size_t aead_len = cont_len - sizeof(cv_multikey_header_t);

    int ret = cv_aead_decrypt(aead_buf, aead_len, (const uint8_t *)"MULTI_RECIPIENT_V1", 18,
                              session_key, 32, 0,
                              out_pt, out_pt_len);
    cv_memzero(session_key, sizeof(session_key));
    return ret;
}

int cv_multikey_self_test(void) {
    const char *msg = "Multi-Key joint dual-authorization secret document test";
    size_t len = strlen(msg);

    uint8_t k1[32], k2[32], k3[32];
    for (int i = 0; i < 32; i++) {
        k1[i] = (uint8_t)(i + 1);
        k2[i] = (uint8_t)(i + 17);
        k3[i] = (uint8_t)(i + 45);
    }

    /* 1. Test Dual Authorization (k1 + k2 required) */
    uint8_t *dual_cont = NULL;
    size_t dual_len = 0;
    if (cv_multikey_encrypt_dual((const uint8_t *)msg, len, k1, k2, &dual_cont, &dual_len) != CV_MK_SUCCESS) {
        return CV_MK_ERR_SELFTEST;
    }

    /* Decrypt with both keys */
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    if (cv_multikey_decrypt_dual(dual_cont, dual_len, k1, k2, &dec, &dec_len) != CV_MK_SUCCESS) {
        cv_secure_free(dual_cont, dual_len);
        return CV_MK_ERR_SELFTEST;
    }
    if (dec_len != len || cv_ct_memcmp(dec, msg, len) != 0) {
        cv_secure_free(dual_cont, dual_len);
        cv_secure_free(dec, dec_len);
        return CV_MK_ERR_SELFTEST;
    }
    cv_secure_free(dec, dec_len); dec = NULL;

    /* Unauthorized attempt: k1 + k3 (wrong second key) */
    if (cv_multikey_decrypt_dual(dual_cont, dual_len, k1, k3, &dec, &dec_len) == CV_MK_SUCCESS) {
        cv_secure_free(dual_cont, dual_len);
        cv_secure_free(dec, dec_len);
        return CV_MK_ERR_SELFTEST; /* Must fail with invalid key */
    }
    cv_secure_free(dual_cont, dual_len);

    /* 2. Test Multi-Recipient (k1, k2, k3 each can decrypt independently) */
    uint8_t recipients[3][32];
    memcpy(recipients[0], k1, 32);
    memcpy(recipients[1], k2, 32);
    memcpy(recipients[2], k3, 32);

    uint8_t *multi_cont = NULL;
    size_t multi_len = 0;
    if (cv_multikey_encrypt_multi_recipient((const uint8_t *)msg, len,
                                            (const uint8_t (*)[32])(const void *)recipients, 3,
                                            &multi_cont, &multi_len) != CV_MK_SUCCESS) {
        return CV_MK_ERR_SELFTEST;
    }

    /* Recipient 2 decrypts */
    if (cv_multikey_decrypt_recipient(multi_cont, multi_len, k2, &dec, &dec_len) != CV_MK_SUCCESS) {
        cv_secure_free(multi_cont, multi_len);
        return CV_MK_ERR_SELFTEST;
    }
    if (dec_len != len || cv_ct_memcmp(dec, msg, len) != 0) {
        cv_secure_free(multi_cont, multi_len);
        cv_secure_free(dec, dec_len);
        return CV_MK_ERR_SELFTEST;
    }
    cv_secure_free(dec, dec_len);
    cv_secure_free(multi_cont, multi_len);

    return CV_MK_SUCCESS;
}
