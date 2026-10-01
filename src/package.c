#define _GNU_SOURCE
#include "package.h"
#include "hybrid.h"
#include "stream.h"
#include "sponge_hash.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

typedef struct __attribute__((packed)) {
    uint8_t  magic[CV_PKG_MAGIC_LEN];       /* "CVPKG200" */
    uint16_t version;                        /* 0x0200 */
    uint16_t mode;                           /* cv_pkg_mode_t */
    uint64_t created_time;                   /* Unix epoch seconds */
    char     orig_filename[CV_PKG_MAX_FILENAME];
    uint8_t  recipient_pub[CV_ECDH_KEY_SIZE];/* 32 bytes (or zeros if password mode) */
    uint8_t  seal_digest[32];                /* 32-byte integrity seal */
} cv_pkg_raw_header_t;

int cv_package_create_hybrid(const char *src_file,
                             const char *out_pkg_path,
                             const uint8_t recipient_pub[CV_ECDH_KEY_SIZE]) {
    if (!src_file || !out_pkg_path || !recipient_pub) return CV_PKG_ERR_PARAM;

    /* 1. Encrypt target file using hybrid streaming into temporary path */
    char temp_enc[512];
    snprintf(temp_enc, sizeof(temp_enc), "%s.tmp.hybrid", out_pkg_path);

    if (cv_hybrid_file_encrypt(src_file, temp_enc, recipient_pub,
                               (const uint8_t *)"CV_PACKAGE_HYBRID", 17) != 0) {
        unlink(temp_enc);
        return CV_PKG_ERR_DECRYPT;
    }

    /* 2. Assemble package container */
    FILE *f_out = fopen(out_pkg_path, "wb");
    if (!f_out) {
        unlink(temp_enc);
        return CV_PKG_ERR_IO;
    }

    cv_pkg_raw_header_t hdr;
    cv_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, CV_PKG_MAGIC, CV_PKG_MAGIC_LEN);
    hdr.version = 0x0200;
    hdr.mode = (uint16_t)CV_PKG_MODE_HYBRID;
    hdr.created_time = (uint64_t)time(NULL);

    /* Extract basename */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s", src_file);
    char *bname = basename(tmp_path);
    snprintf(hdr.orig_filename, sizeof(hdr.orig_filename), "%s", bname);

    memcpy(hdr.recipient_pub, recipient_pub, CV_ECDH_KEY_SIZE);

    /* Compute seal of payload */
    if (cv_hash_file(temp_enc, hdr.seal_digest) != 0) {
        fclose(f_out);
        unlink(temp_enc);
        unlink(out_pkg_path);
        return CV_PKG_ERR_AUTH;
    }

    fwrite(&hdr, 1, sizeof(hdr), f_out);

    /* Append encrypted payload */
    FILE *f_in = fopen(temp_enc, "rb");
    if (!f_in) {
        fclose(f_out);
        unlink(temp_enc);
        unlink(out_pkg_path);
        return CV_PKG_ERR_IO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f_in)) > 0) {
        fwrite(buf, 1, n, f_out);
    }

    fclose(f_in);
    fclose(f_out);
    unlink(temp_enc);
    cv_memzero(buf, sizeof(buf));

    return CV_PKG_SUCCESS;
}

int cv_package_extract_hybrid(const char *pkg_path,
                              const char *dest_file,
                              const uint8_t recipient_priv[CV_ECDH_KEY_SIZE]) {
    if (!pkg_path || !dest_file || !recipient_priv) return CV_PKG_ERR_PARAM;

    FILE *f_pkg = fopen(pkg_path, "rb");
    if (!f_pkg) return CV_PKG_ERR_IO;

    cv_pkg_raw_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f_pkg) != sizeof(hdr)) {
        fclose(f_pkg);
        return CV_PKG_ERR_CORRUPT;
    }

    if (cv_ct_memcmp(hdr.magic, CV_PKG_MAGIC, CV_PKG_MAGIC_LEN) != 0) {
        fclose(f_pkg);
        return CV_PKG_ERR_MAGIC;
    }

    if (hdr.mode != (uint16_t)CV_PKG_MODE_HYBRID) {
        fclose(f_pkg);
        return CV_PKG_ERR_PARAM;
    }

    /* Stream remaining encrypted payload to temporary file */
    char temp_enc[512];
    snprintf(temp_enc, sizeof(temp_enc), "%s.tmp.extract", dest_file);
    FILE *f_tmp = fopen(temp_enc, "wb");
    if (!f_tmp) {
        fclose(f_pkg);
        return CV_PKG_ERR_IO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f_pkg)) > 0) {
        fwrite(buf, 1, n, f_tmp);
    }
    fclose(f_pkg);
    fclose(f_tmp);

    /* Verify seal digest */
    uint8_t calc_seal[32];
    if (cv_hash_file(temp_enc, calc_seal) != 0 ||
        cv_ct_memcmp(calc_seal, hdr.seal_digest, 32) != 0) {
        unlink(temp_enc);
        return CV_PKG_ERR_CORRUPT;
    }

    /* Decrypt hybrid file */
    int ret = cv_hybrid_file_decrypt(temp_enc, dest_file, recipient_priv,
                                     (const uint8_t *)"CV_PACKAGE_HYBRID", 17);
    unlink(temp_enc);
    return (ret == 0) ? CV_PKG_SUCCESS : CV_PKG_ERR_DECRYPT;
}

int cv_package_create_password(const char *src_file,
                               const char *out_pkg_path,
                               const char *password) {
    if (!src_file || !out_pkg_path || !password) return CV_PKG_ERR_PARAM;

    char temp_enc[512];
    snprintf(temp_enc, sizeof(temp_enc), "%s.tmp.pw", out_pkg_path);

    /* Encrypt with 1 MiB base memory-hard streaming */
    if (cv_file_encrypt(src_file, temp_enc, password, strlen(password), 1,
                        (const uint8_t *)"CV_PACKAGE_PW", 13,
                        CV_DEFAULT_MEM_COST_KB, CV_DEFAULT_TIME_COST) != 0) {
        unlink(temp_enc);
        return CV_PKG_ERR_DECRYPT;
    }

    FILE *f_out = fopen(out_pkg_path, "wb");
    if (!f_out) {
        unlink(temp_enc);
        return CV_PKG_ERR_IO;
    }

    cv_pkg_raw_header_t hdr;
    cv_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, CV_PKG_MAGIC, CV_PKG_MAGIC_LEN);
    hdr.version = 0x0200;
    hdr.mode = (uint16_t)CV_PKG_MODE_PASSWORD;
    hdr.created_time = (uint64_t)time(NULL);

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s", src_file);
    char *bname = basename(tmp_path);
    snprintf(hdr.orig_filename, sizeof(hdr.orig_filename), "%s", bname);

    if (cv_hash_file(temp_enc, hdr.seal_digest) != 0) {
        fclose(f_out);
        unlink(temp_enc);
        unlink(out_pkg_path);
        return CV_PKG_ERR_AUTH;
    }

    fwrite(&hdr, 1, sizeof(hdr), f_out);

    FILE *f_in = fopen(temp_enc, "rb");
    if (!f_in) {
        fclose(f_out);
        unlink(temp_enc);
        unlink(out_pkg_path);
        return CV_PKG_ERR_IO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f_in)) > 0) {
        fwrite(buf, 1, n, f_out);
    }

    fclose(f_in);
    fclose(f_out);
    unlink(temp_enc);
    return CV_PKG_SUCCESS;
}

int cv_package_extract_password(const char *pkg_path,
                                const char *dest_file,
                                const char *password) {
    if (!pkg_path || !dest_file || !password) return CV_PKG_ERR_PARAM;

    FILE *f_pkg = fopen(pkg_path, "rb");
    if (!f_pkg) return CV_PKG_ERR_IO;

    cv_pkg_raw_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f_pkg) != sizeof(hdr)) {
        fclose(f_pkg);
        return CV_PKG_ERR_CORRUPT;
    }

    if (cv_ct_memcmp(hdr.magic, CV_PKG_MAGIC, CV_PKG_MAGIC_LEN) != 0) {
        fclose(f_pkg);
        return CV_PKG_ERR_MAGIC;
    }

    char temp_enc[512];
    snprintf(temp_enc, sizeof(temp_enc), "%s.tmp.pwext", dest_file);
    FILE *f_tmp = fopen(temp_enc, "wb");
    if (!f_tmp) {
        fclose(f_pkg);
        return CV_PKG_ERR_IO;
    }

    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f_pkg)) > 0) {
        fwrite(buf, 1, n, f_tmp);
    }
    fclose(f_pkg);
    fclose(f_tmp);

    uint8_t calc_seal[32];
    if (cv_hash_file(temp_enc, calc_seal) != 0 ||
        cv_ct_memcmp(calc_seal, hdr.seal_digest, 32) != 0) {
        unlink(temp_enc);
        return CV_PKG_ERR_CORRUPT;
    }

    int ret = cv_file_decrypt(temp_enc, dest_file, password, strlen(password), 1,
                              (const uint8_t *)"CV_PACKAGE_PW", 13);
    unlink(temp_enc);
    return (ret == 0) ? CV_PKG_SUCCESS : CV_PKG_ERR_DECRYPT;
}

int cv_package_inspect(const char *pkg_path, cv_pkg_manifest_t *manifest_out) {
    if (!pkg_path || !manifest_out) return CV_PKG_ERR_PARAM;

    FILE *f = fopen(pkg_path, "rb");
    if (!f) return CV_PKG_ERR_IO;

    cv_pkg_raw_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return CV_PKG_ERR_CORRUPT;
    }

    fseek(f, 0, SEEK_END);
    long total_size = ftell(f);
    fclose(f);

    if (cv_ct_memcmp(hdr.magic, CV_PKG_MAGIC, CV_PKG_MAGIC_LEN) != 0) {
        return CV_PKG_ERR_MAGIC;
    }

    snprintf(manifest_out->orig_filename, sizeof(manifest_out->orig_filename), "%s", hdr.orig_filename);
    manifest_out->mode = (cv_pkg_mode_t)hdr.mode;
    manifest_out->created_timestamp = hdr.created_time;
    manifest_out->payload_size = (total_size > (long)sizeof(hdr)) ? (uint64_t)(total_size - sizeof(hdr)) : 0;
    memcpy(manifest_out->recipient_pubkey, hdr.recipient_pub, CV_ECDH_KEY_SIZE);
    memcpy(manifest_out->package_seal, hdr.seal_digest, 32);

    return CV_PKG_SUCCESS;
}

int cv_package_self_test(void) {
    const char *test_src = "/tmp/cv_test_pkg_orig.txt";
    const char *test_pkg = "/tmp/cv_test_bundle.cvpkg";
    const char *test_dec = "/tmp/cv_test_pkg_dec.txt";

    FILE *f = fopen(test_src, "w");
    if (!f) return CV_PKG_ERR_SELFTEST;
    fprintf(f, "Testing CryptoVault Self-Contained Transmission Packaging 2026\n");
    fclose(f);

    cv_ecdh_keypair_t bob;
    if (cv_ecdh_keygen(&bob) != 0) {
        unlink(test_src);
        return CV_PKG_ERR_SELFTEST;
    }

    if (cv_package_create_hybrid(test_src, test_pkg, bob.pub) != CV_PKG_SUCCESS) {
        unlink(test_src);
        cv_ecdh_keypair_clear(&bob);
        return CV_PKG_ERR_SELFTEST;
    }

    cv_pkg_manifest_t manifest;
    if (cv_package_inspect(test_pkg, &manifest) != CV_PKG_SUCCESS) {
        unlink(test_src); unlink(test_pkg);
        cv_ecdh_keypair_clear(&bob);
        return CV_PKG_ERR_SELFTEST;
    }

    if (cv_package_extract_hybrid(test_pkg, test_dec, bob.priv) != CV_PKG_SUCCESS) {
        unlink(test_src); unlink(test_pkg);
        cv_ecdh_keypair_clear(&bob);
        return CV_PKG_ERR_SELFTEST;
    }

    uint8_t h1[32], h2[32];
    cv_hash_file(test_src, h1);
    cv_hash_file(test_dec, h2);
    int match = (cv_ct_memcmp(h1, h2, 32) == 0);

    unlink(test_src);
    unlink(test_pkg);
    unlink(test_dec);
    cv_ecdh_keypair_clear(&bob);

    return match ? CV_PKG_SUCCESS : CV_PKG_ERR_SELFTEST;
}
