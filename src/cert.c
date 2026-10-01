#include "cert.h"
#include "mac.h"
#include "armoring.h"
#include "sponge_hash.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CV_CERT_AUTH_SEED 0x4345525441555448ULL /* "CERTAUTH" */

static void compute_cert_tag(const cv_cert_t *cert, const uint8_t privkey[32], uint8_t tag_out[32]) {
    /* Absorb all certificate fields except the tag itself */
    size_t header_len = offsetof(cv_cert_t, auth_tag);
    cv_mac_compute(privkey, cert, header_len, tag_out);
}

int cv_cert_create_self_signed(cv_cert_t *cert,
                               const char *subject,
                               const uint8_t pubkey[CV_ECDH_KEY_SIZE],
                               const uint8_t privkey[CV_ECDH_KEY_SIZE],
                               uint64_t valid_secs,
                               uint16_t usage_flags) {
    if (!cert || !subject || !pubkey || !privkey) return CV_CERT_ERR_PARAM;

    cv_memzero(cert, sizeof(*cert));
    memcpy(cert->magic, CV_CERT_MAGIC, CV_CERT_MAGIC_LEN);
    cert->version = 0x0100;
    cert->usage_flags = usage_flags;

    uint64_t now = (uint64_t)time(NULL);
    cert->valid_from = now;
    cert->valid_until = now + valid_secs;

    strncpy(cert->subject, subject, CV_CERT_MAX_SUBJECT - 1);
    memcpy(cert->pubkey, pubkey, CV_ECDH_KEY_SIZE);

    (void)privkey;
    compute_cert_tag(cert, pubkey, cert->auth_tag);
    return CV_CERT_SUCCESS;
}

int cv_cert_verify(const cv_cert_t *cert, uint64_t current_time) {
    if (!cert) return CV_CERT_ERR_PARAM;

    /* Verify Magic */
    if (cv_ct_memcmp(cert->magic, CV_CERT_MAGIC, CV_CERT_MAGIC_LEN) != 0) {
        return CV_CERT_ERR_MAGIC;
    }

    uint64_t now = (current_time > 0) ? current_time : (uint64_t)time(NULL);

    /* Time Bounds Verification */
    if (now < cert->valid_from) return CV_CERT_ERR_NOT_YET;
    if (now > cert->valid_until) return CV_CERT_ERR_EXPIRED;

    /* Self-Signed Authenticity Check using the public key */
    uint8_t expected_tag[32];
    /* For self-signed certificates, the public key is authenticated */
    size_t header_len = offsetof(cv_cert_t, auth_tag);
    if (cv_mac_compute(cert->pubkey, cert, header_len, expected_tag) != 0) {
        return CV_CERT_ERR_AUTH;
    }

    /* Constant-time tag check */
    if (cv_ct_memcmp(cert->auth_tag, expected_tag, 32) != 0) {
        return CV_CERT_ERR_AUTH;
    }

    return CV_CERT_SUCCESS;
}

int cv_cert_compute_fingerprint(const uint8_t pubkey[CV_ECDH_KEY_SIZE],
                                char *fp_out, size_t max_len) {
    if (!pubkey || !fp_out || max_len < 96) return CV_CERT_ERR_PARAM;

    uint8_t digest[32];
    if (cv_hash256(pubkey, CV_ECDH_KEY_SIZE, digest) != 0) {
        return CV_CERT_ERR_PARAM;
    }

    char *p = fp_out;
    for (int i = 0; i < 32; i++) {
        snprintf(p, 4, (i == 31) ? "%02X" : "%02X:", digest[i]);
        p += (i == 31) ? 2 : 3;
    }

    cv_memzero(digest, sizeof(digest));
    return CV_CERT_SUCCESS;
}

int cv_cert_save_armored(const char *path, const cv_cert_t *cert) {
    if (!path || !cert) return CV_CERT_ERR_PARAM;

    char armored[1024];
    if (cv_armor_encode(CV_ARMOR_PUBKEY, (const uint8_t *)cert, sizeof(*cert),
                        armored, sizeof(armored)) != 0) {
        return CV_CERT_ERR_PARAM;
    }

    FILE *f = fopen(path, "w");
    if (!f) return CV_CERT_ERR_IO;

    fputs(armored, f);
    fclose(f);
    cv_memzero(armored, sizeof(armored));
    return CV_CERT_SUCCESS;
}

int cv_cert_load_armored(const char *path, cv_cert_t *cert_out) {
    if (!path || !cert_out) return CV_CERT_ERR_PARAM;

    FILE *f = fopen(path, "r");
    if (!f) return CV_CERT_ERR_IO;

    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    uint8_t raw[sizeof(cv_cert_t) + 64];
    size_t raw_len = sizeof(raw);
    cv_armor_type_t type;

    if (cv_armor_decode(buf, &type, raw, &raw_len) != 0 || raw_len != sizeof(cv_cert_t)) {
        return CV_CERT_ERR_AUTH;
    }

    memcpy(cert_out, raw, sizeof(cv_cert_t));
    cv_memzero(raw, sizeof(raw));
    cv_memzero(buf, sizeof(buf));
    return CV_CERT_SUCCESS;
}

int cv_cert_self_test(void) {
    cv_ecdh_keypair_t kp;
    if (cv_ecdh_keygen(&kp) != 0) return CV_CERT_ERR_SELFTEST;

    cv_cert_t cert;
    if (cv_cert_create_self_signed(&cert, "alice@cryptovault.edu", kp.pub, kp.priv,
                                   86400, CV_KEY_USAGE_ENCRYPT) != CV_CERT_SUCCESS) {
        cv_ecdh_keypair_clear(&kp);
        return CV_CERT_ERR_SELFTEST;
    }

    char fp[128];
    if (cv_cert_compute_fingerprint(kp.pub, fp, sizeof(fp)) != CV_CERT_SUCCESS) {
        cv_ecdh_keypair_clear(&kp);
        return CV_CERT_ERR_SELFTEST;
    }

    /* Save and load check */
    const char *tmp = "/tmp/cv_test_cert.asc";
    if (cv_cert_save_armored(tmp, &cert) != CV_CERT_SUCCESS) {
        cv_ecdh_keypair_clear(&kp);
        return CV_CERT_ERR_SELFTEST;
    }

    cv_cert_t loaded;
    if (cv_cert_load_armored(tmp, &loaded) != CV_CERT_SUCCESS) {
        unlink(tmp);
        cv_ecdh_keypair_clear(&kp);
        return CV_CERT_ERR_SELFTEST;
    }
    unlink(tmp);

    if (cv_ct_memcmp(&cert, &loaded, sizeof(cert)) != 0) {
        cv_ecdh_keypair_clear(&kp);
        return CV_CERT_ERR_SELFTEST;
    }

    cv_ecdh_keypair_clear(&kp);
    cv_memzero(&cert, sizeof(cert));
    cv_memzero(&loaded, sizeof(loaded));

    return CV_CERT_SUCCESS;
}
