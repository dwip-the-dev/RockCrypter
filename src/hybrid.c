#include "hybrid.h"
#include "ecdh.h"
#include "hkdf.h"
#include "keywrap.h"
#include "aead.h"
#include "stream.h"
#include "entropy.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int cv_hybrid_encrypt(const uint8_t recipient_pub[CV_ECDH_KEY_SIZE],
                      const uint8_t *plaintext, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t **out_buf, size_t *out_len) {
    if (!recipient_pub || !out_buf || !out_len) return -1;

    /* 1. Generate Ephemeral Keypair (d_A, Q_A) */
    cv_ecdh_keypair_t eph;
    if (cv_ecdh_keygen(&eph) != 0) return -2;

    /* 2. Compute ECDH shared secret S = d_A * Q_B */
    uint8_t shared[32];
    if (cv_ecdh_compute_shared(eph.priv, recipient_pub, shared) != 0) {
        cv_ecdh_keypair_clear(&eph);
        return -3;
    }

    /* 3. Derive KEK via HKDF */
    uint8_t kek[32];
    cv_hkdf(NULL, 0, shared, 32, (const uint8_t *)"HYBRID_PKE_KEK_V1", 17, kek, 32);
    cv_memzero(shared, sizeof(shared));

    /* 4. Generate random 256-bit file session key K_session */
    uint8_t session_key[32];
    if (cv_entropy_get(session_key, 32) != 0) {
        cv_memzero(kek, sizeof(kek));
        cv_ecdh_keypair_clear(&eph);
        return -4;
    }

    /* 5. Wrap session key with KEK using SP-ARX Key Wrap */
    uint8_t wrapped_key[40];
    if (cv_key_wrap(kek, session_key, 32, wrapped_key) != 0) {
        cv_memzero(kek, sizeof(kek));
        cv_memzero(session_key, sizeof(session_key));
        cv_ecdh_keypair_clear(&eph);
        return -5;
    }
    cv_memzero(kek, sizeof(kek));

    /* 6. Encrypt plaintext using session_key with AEAD */
    uint8_t *aead_buf = NULL;
    size_t aead_len = 0;
    int ret = cv_aead_encrypt(plaintext, pt_len, aad, aad_len,
                              session_key, 32, 0, 0, 0,
                              &aead_buf, &aead_len);
    cv_memzero(session_key, sizeof(session_key));

    if (ret != CV_SUCCESS) {
        cv_ecdh_keypair_clear(&eph);
        return ret;
    }

    /* 7. Assemble Hybrid Envelope: [Header (80B)] [AEAD Buffer] */
    size_t total = sizeof(cv_hybrid_header_t) + aead_len;
    uint8_t *envelope = (uint8_t *)malloc(total);
    if (!envelope) {
        cv_secure_free(aead_buf, aead_len);
        cv_ecdh_keypair_clear(&eph);
        return -6;
    }

    cv_hybrid_header_t *hdr = (cv_hybrid_header_t *)envelope;
    memcpy(hdr->magic, CV_HYBRID_MAGIC, CV_HYBRID_MAGIC_LEN);
    memcpy(hdr->ephemeral_pub, eph.pub, 32);
    memcpy(hdr->wrapped_session_key, wrapped_key, 40);

    memcpy(envelope + sizeof(cv_hybrid_header_t), aead_buf, aead_len);
    cv_secure_free(aead_buf, aead_len);
    cv_ecdh_keypair_clear(&eph);

    *out_buf = envelope;
    *out_len = total;
    return 0;
}

int cv_hybrid_decrypt(const uint8_t recipient_priv[CV_ECDH_KEY_SIZE],
                      const uint8_t *envelope, size_t env_len,
                      const uint8_t *expected_aad, size_t aad_len,
                      uint8_t **out_pt, size_t *out_pt_len) {
    if (!recipient_priv || !envelope || !out_pt || !out_pt_len) return -1;
    if (env_len < sizeof(cv_hybrid_header_t) + sizeof(cv_header_t) + CV_TAG_SIZE) {
        return -2;
    }

    const cv_hybrid_header_t *hdr = (const cv_hybrid_header_t *)envelope;
    if (cv_ct_memcmp(hdr->magic, CV_HYBRID_MAGIC, CV_HYBRID_MAGIC_LEN) != 0) {
        return -3; /* Magic mismatch */
    }

    /* 1. Compute ECDH shared secret S = d_B * Q_A */
    uint8_t shared[32];
    if (cv_ecdh_compute_shared(recipient_priv, hdr->ephemeral_pub, shared) != 0) {
        return -4;
    }

    /* 2. Derive KEK via HKDF */
    uint8_t kek[32];
    cv_hkdf(NULL, 0, shared, 32, (const uint8_t *)"HYBRID_PKE_KEK_V1", 17, kek, 32);
    cv_memzero(shared, sizeof(shared));

    /* 3. Unwrap session key */
    uint8_t session_key[32];
    if (cv_key_unwrap(kek, hdr->wrapped_session_key, 40, session_key) != 0) {
        cv_memzero(kek, sizeof(kek));
        return -5; /* Key unwrap failed / tampering */
    }
    cv_memzero(kek, sizeof(kek));

    /* 4. Decrypt inner AEAD container */
    const uint8_t *aead_data = envelope + sizeof(cv_hybrid_header_t);
    size_t aead_data_len = env_len - sizeof(cv_hybrid_header_t);

    int ret = cv_aead_decrypt(aead_data, aead_data_len,
                              expected_aad, aad_len,
                              session_key, 32, 0,
                              out_pt, out_pt_len);
    cv_memzero(session_key, sizeof(session_key));

    return ret;
}

int cv_hybrid_file_encrypt(const char *in_path, const char *out_path,
                           const uint8_t recipient_pub[CV_ECDH_KEY_SIZE],
                           const uint8_t *aad, size_t aad_len) {
    if (!in_path || !out_path || !recipient_pub) return -1;

    /* Generate ephemeral keypair & derive session key */
    cv_ecdh_keypair_t eph;
    if (cv_ecdh_keygen(&eph) != 0) return -2;

    uint8_t shared[32];
    if (cv_ecdh_compute_shared(eph.priv, recipient_pub, shared) != 0) {
        cv_ecdh_keypair_clear(&eph);
        return -3;
    }

    uint8_t kek[32];
    cv_hkdf(NULL, 0, shared, 32, (const uint8_t *)"HYBRID_PKE_KEK_V1", 17, kek, 32);
    cv_memzero(shared, sizeof(shared));

    uint8_t session_key[32];
    if (cv_entropy_get(session_key, 32) != 0) {
        cv_memzero(kek, sizeof(kek));
        cv_ecdh_keypair_clear(&eph);
        return -4;
    }

    uint8_t wrapped_key[40];
    if (cv_key_wrap(kek, session_key, 32, wrapped_key) != 0) {
        cv_memzero(kek, sizeof(kek));
        cv_memzero(session_key, sizeof(session_key));
        cv_ecdh_keypair_clear(&eph);
        return -5;
    }
    cv_memzero(kek, sizeof(kek));

    /* Write hybrid header prefix to temp file */
    char temp_out[512];
    snprintf(temp_out, sizeof(temp_out), "%s.tmp.stream", out_path);

    int ret = cv_file_encrypt(in_path, temp_out, session_key, 32, 0, aad, aad_len, 0, 0);
    cv_memzero(session_key, sizeof(session_key));

    if (ret != CV_SUCCESS) {
        unlink(temp_out);
        cv_ecdh_keypair_clear(&eph);
        return ret;
    }

    /* Merge: [cv_hybrid_header_t] + [temp_out stream] -> out_path */
    FILE *f_dest = fopen(out_path, "wb");
    FILE *f_src = fopen(temp_out, "rb");
    if (!f_dest || !f_src) {
        if (f_dest) fclose(f_dest);
        if (f_src) fclose(f_src);
        unlink(temp_out);
        cv_ecdh_keypair_clear(&eph);
        return -6;
    }

    cv_hybrid_header_t hdr;
    memcpy(hdr.magic, CV_HYBRID_MAGIC, CV_HYBRID_MAGIC_LEN);
    memcpy(hdr.ephemeral_pub, eph.pub, 32);
    memcpy(hdr.wrapped_session_key, wrapped_key, 40);

    fwrite(&hdr, 1, sizeof(hdr), f_dest);

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f_src)) > 0) {
        fwrite(buf, 1, n, f_dest);
    }

    fclose(f_dest);
    fclose(f_src);
    unlink(temp_out);
    cv_ecdh_keypair_clear(&eph);
    return 0;
}

int cv_hybrid_file_decrypt(const char *in_path, const char *out_path,
                           const uint8_t recipient_priv[CV_ECDH_KEY_SIZE],
                           const uint8_t *expected_aad, size_t aad_len) {
    if (!in_path || !out_path || !recipient_priv) return -1;

    FILE *f = fopen(in_path, "rb");
    if (!f) return -2;

    cv_hybrid_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return -3;
    }

    if (cv_ct_memcmp(hdr.magic, CV_HYBRID_MAGIC, CV_HYBRID_MAGIC_LEN) != 0) {
        fclose(f);
        return -4;
    }

    /* Derive KEK and unwrap session key */
    uint8_t shared[32];
    if (cv_ecdh_compute_shared(recipient_priv, hdr.ephemeral_pub, shared) != 0) {
        fclose(f);
        return -5;
    }

    uint8_t kek[32];
    cv_hkdf(NULL, 0, shared, 32, (const uint8_t *)"HYBRID_PKE_KEK_V1", 17, kek, 32);
    cv_memzero(shared, sizeof(shared));

    uint8_t session_key[32];
    if (cv_key_unwrap(kek, hdr.wrapped_session_key, 40, session_key) != 0) {
        cv_memzero(kek, sizeof(kek));
        fclose(f);
        return -6;
    }
    cv_memzero(kek, sizeof(kek));

    /* Dump remaining stream to temp file for streaming decryption */
    char temp_in[512];
    snprintf(temp_in, sizeof(temp_in), "%s.tmp.decstream", in_path);
    FILE *f_tmp = fopen(temp_in, "wb");
    if (!f_tmp) {
        cv_memzero(session_key, sizeof(session_key));
        fclose(f);
        return -7;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, 1, n, f_tmp);
    }
    fclose(f);
    fclose(f_tmp);

    int ret = cv_file_decrypt(temp_in, out_path, session_key, 32, 0, expected_aad, aad_len);
    cv_memzero(session_key, sizeof(session_key));
    unlink(temp_in);

    return ret;
}

int cv_hybrid_self_test(void) {
    cv_ecdh_keypair_t bob;
    if (cv_ecdh_keygen(&bob) != 0) return CV_HYBRID_ERR_SELFTEST;

    const uint8_t pt[64] = "CryptoVault Hybrid Asymmetric HPKE End-to-End Self Test Message";
    const uint8_t aad[16] = "ContextIdentity";

    uint8_t *envelope = NULL;
    size_t env_len = 0;
    if (cv_hybrid_encrypt(bob.pub, pt, sizeof(pt), aad, sizeof(aad), &envelope, &env_len) != 0) {
        cv_ecdh_keypair_clear(&bob);
        return CV_HYBRID_ERR_SELFTEST;
    }

    uint8_t *decrypted = NULL;
    size_t dec_len = 0;
    if (cv_hybrid_decrypt(bob.priv, envelope, env_len, aad, sizeof(aad), &decrypted, &dec_len) != 0) {
        free(envelope);
        cv_ecdh_keypair_clear(&bob);
        return CV_HYBRID_ERR_SELFTEST;
    }

    int match = (dec_len == sizeof(pt)) && (cv_ct_memcmp(pt, decrypted, sizeof(pt)) == 0);

    free(envelope);
    cv_memzero(decrypted, dec_len);
    free(decrypted);
    cv_ecdh_keypair_clear(&bob);

    return match ? CV_HYBRID_SUCCESS : CV_HYBRID_ERR_SELFTEST;
}
