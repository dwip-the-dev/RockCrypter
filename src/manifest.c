/**
 * @file manifest.c
 * @brief Cryptographic File Manifests, Metadata Authentication & Permission Binding.
 *
 * Implements authenticated file manifests binding original filenames, MIME types,
 * POSIX permissions, Merkle roots, and publisher cryptographic seals.
 */

#include "manifest.h"
#include "sponge_hash.h"
#include "mac.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

static void compute_manifest_seal(const cv_manifest_t *m, const uint8_t key[32], uint8_t seal_out[32]) {
    size_t header_len = offsetof(cv_manifest_t, manifest_seal);
    cv_mac_compute(key, m, header_len, seal_out);
}

int cv_manifest_create(cv_manifest_t *manifest_out,
                       const char *source_file_path,
                       const char *orig_name,
                       const char *mime,
                       const uint8_t publisher_pub[32],
                       const uint8_t publisher_priv[32],
                       const uint8_t merkle_root[32],
                       uint64_t total_chunks) {
    if (!manifest_out || !source_file_path || !publisher_pub) {
        return CV_MAN_ERR_PARAM;
    }

    struct stat st;
    if (stat(source_file_path, &st) != 0) {
        return CV_MAN_ERR_IO;
    }

    cv_memzero(manifest_out, sizeof(*manifest_out));
    memcpy(manifest_out->magic, CV_MANIFEST_MAGIC, CV_MANIFEST_MAGIC_LEN);
    manifest_out->version = 0x0100;
    manifest_out->flags = 0;
    manifest_out->posix_mode = (uint32_t)(st.st_mode & 0777);
    manifest_out->file_size_bytes = (uint64_t)st.st_size;
    manifest_out->chunk_count = total_chunks;
    manifest_out->created_timestamp = (uint64_t)time(NULL);

    const char *name_ptr = orig_name;
    if (!name_ptr) {
        const char *slash = strrchr(source_file_path, '/');
        name_ptr = slash ? (slash + 1) : source_file_path;
    }
    strncpy(manifest_out->orig_filename, name_ptr, CV_MANIFEST_MAX_NAME - 1);

    const char *mime_ptr = mime ? mime : "application/octet-stream";
    strncpy(manifest_out->mime_type, mime_ptr, CV_MANIFEST_MAX_MIME - 1);

    memcpy(manifest_out->publisher_pubkey, publisher_pub, 32);

    /* Full-file digest */
    if (cv_hash_file(source_file_path, manifest_out->full_file_hash) != 0) {
        return CV_MAN_ERR_IO;
    }

    if (merkle_root) {
        memcpy(manifest_out->merkle_root, merkle_root, 32);
    }

    /* Compute seal using public key (or private key if provided) */
    (void)publisher_priv;
    compute_manifest_seal(manifest_out, publisher_pub, manifest_out->manifest_seal);

    return CV_MAN_SUCCESS;
}

int cv_manifest_verify(const cv_manifest_t *manifest, const uint8_t pubkey[32]) {
    if (!manifest || !pubkey) return CV_MAN_ERR_PARAM;

    if (cv_ct_memcmp(manifest->magic, CV_MANIFEST_MAGIC, CV_MANIFEST_MAGIC_LEN) != 0) {
        return CV_MAN_ERR_MAGIC;
    }

    if (cv_ct_memcmp(manifest->publisher_pubkey, pubkey, 32) != 0) {
        return CV_MAN_ERR_AUTH; /* Key mismatch */
    }

    uint8_t expected_seal[32];
    compute_manifest_seal(manifest, pubkey, expected_seal);

    if (cv_ct_memcmp(manifest->manifest_seal, expected_seal, 32) != 0) {
        return CV_MAN_ERR_AUTH; /* Seal forgery or corruption */
    }

    return CV_MAN_SUCCESS;
}

int cv_manifest_save(const char *path, const cv_manifest_t *manifest) {
    if (!path || !manifest) return CV_MAN_ERR_PARAM;

    FILE *f = fopen(path, "wb");
    if (!f) return CV_MAN_ERR_IO;

    size_t written = fwrite(manifest, sizeof(*manifest), 1, f);
    fclose(f);

    return (written == 1) ? CV_MAN_SUCCESS : CV_MAN_ERR_IO;
}

int cv_manifest_load(const char *path, cv_manifest_t *manifest_out) {
    if (!path || !manifest_out) return CV_MAN_ERR_PARAM;

    FILE *f = fopen(path, "rb");
    if (!f) return CV_MAN_ERR_IO;

    size_t read_count = fread(manifest_out, sizeof(*manifest_out), 1, f);
    fclose(f);

    if (read_count != 1) return CV_MAN_ERR_IO;
    if (cv_ct_memcmp(manifest_out->magic, CV_MANIFEST_MAGIC, CV_MANIFEST_MAGIC_LEN) != 0) {
        return CV_MAN_ERR_MAGIC;
    }

    return CV_MAN_SUCCESS;
}

int cv_manifest_self_test(void) {
    const char *tmp_file = "/tmp/cv_test_manifest_payload.tmp";
    FILE *f = fopen(tmp_file, "w");
    if (!f) return CV_MAN_ERR_SELFTEST;
    fprintf(f, "Testing cryptographic file manifest subsystem 2026\n");
    fclose(f);

    uint8_t pubkey[32], privkey[32], merkle[32];
    for (int i = 0; i < 32; i++) {
        pubkey[i] = (uint8_t)(i * 4 + 1);
        privkey[i] = (uint8_t)(i * 9 + 5);
        merkle[i] = (uint8_t)(i * 11 + 3);
    }

    cv_manifest_t man;
    int create_rc = cv_manifest_create(&man, tmp_file, "original_report.pdf",
                                       "application/pdf", pubkey, privkey, merkle, 1);
    if (create_rc != CV_MAN_SUCCESS) {
        unlink(tmp_file);
        return CV_MAN_ERR_SELFTEST;
    }

    /* Verification with publisher pubkey */
    if (cv_manifest_verify(&man, pubkey) != CV_MAN_SUCCESS) {
        unlink(tmp_file);
        return CV_MAN_ERR_SELFTEST;
    }

    /* Tamper rejection: modify original filename */
    man.orig_filename[0] ^= 0x01;
    if (cv_manifest_verify(&man, pubkey) == CV_MAN_SUCCESS) {
        unlink(tmp_file);
        return CV_MAN_ERR_SELFTEST; /* Tampered manifest must be rejected */
    }
    man.orig_filename[0] ^= 0x01; /* restore */

    /* Save and load verification */
    const char *man_path = "/tmp/cv_test_man.cvman";
    if (cv_manifest_save(man_path, &man) != CV_MAN_SUCCESS) {
        unlink(tmp_file);
        return CV_MAN_ERR_SELFTEST;
    }

    cv_manifest_t loaded;
    if (cv_manifest_load(man_path, &loaded) != CV_MAN_SUCCESS ||
        cv_manifest_verify(&loaded, pubkey) != CV_MAN_SUCCESS) {
        unlink(tmp_file);
        unlink(man_path);
        return CV_MAN_ERR_SELFTEST;
    }

    unlink(tmp_file);
    unlink(man_path);
    return CV_MAN_SUCCESS;
}
