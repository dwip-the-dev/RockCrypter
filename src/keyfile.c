#include "keyfile.h"
#include "aead.h"
#include "armoring.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int cv_keyfile_save_encrypted(const char *path,
                              const uint8_t key[32],
                              const char *passphrase,
                              uint32_t mem_cost_kb) {
    if (!path || !key || !passphrase) return -1;
    if (mem_cost_kb == 0) mem_cost_kb = CV_DEFAULT_MEM_COST_KB; /* 1 MiB base */

    uint8_t *enc_buf = NULL;
    size_t enc_len = 0;

    int ret = cv_aead_encrypt(key, 32, (const uint8_t *)"ENCRYPTED_KEYBAG", 16,
                              passphrase, strlen(passphrase), 1,
                              mem_cost_kb, 4,
                              &enc_buf, &enc_len);
    if (ret != CV_SUCCESS) return ret;

    char *armored = (char *)malloc(enc_len * 2 + 512);
    if (!armored) {
        cv_secure_free(enc_buf, enc_len);
        return -2;
    }

    ret = cv_armor_encode(CV_ARMOR_KEY, enc_buf, enc_len, armored, enc_len * 2 + 512);
    cv_secure_free(enc_buf, enc_len);

    if (ret != 0) {
        free(armored);
        return ret;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        free(armored);
        return -3;
    }
    fputs(armored, f);
    fclose(f);
    free(armored);
    return 0;
}

int cv_keyfile_load_encrypted(const char *path,
                              const char *passphrase,
                              uint8_t key_out[32]) {
    if (!path || !passphrase || !key_out) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -2;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 1024 * 1024) {
        fclose(f);
        return -3;
    }

    char *armored = (char *)malloc(sz + 1);
    if (!armored) {
        fclose(f);
        return -4;
    }
    size_t read_bytes = fread(armored, 1, sz, f);
    armored[read_bytes] = '\0';
    fclose(f);

    uint8_t *bin = (uint8_t *)malloc(sz);
    size_t bin_len = sz;
    cv_armor_type_t t;
    int ret = cv_armor_decode(armored, &t, bin, &bin_len);
    free(armored);

    if (ret != 0) {
        free(bin);
        return ret;
    }

    uint8_t *pt = NULL;
    size_t pt_len = 0;
    ret = cv_aead_decrypt(bin, bin_len, (const uint8_t *)"ENCRYPTED_KEYBAG", 16,
                          passphrase, strlen(passphrase), 1,
                          &pt, &pt_len);
    free(bin);

    if (ret != CV_SUCCESS) {
        return ret;
    }

    if (pt_len != 32) {
        cv_secure_free(pt, pt_len);
        return -5;
    }

    memcpy(key_out, pt, 32);
    cv_secure_free(pt, pt_len);
    return 0;
}

int cv_pubkey_export_armored(const char *path, const uint8_t pub[CV_ECDH_KEY_SIZE]) {
    if (!path || !pub) return -1;

    char armored[512];
    int ret = cv_armor_encode(CV_ARMOR_PUBKEY, pub, CV_ECDH_KEY_SIZE, armored, sizeof(armored));
    if (ret != 0) return ret;

    FILE *f = fopen(path, "w");
    if (!f) return -2;
    fputs(armored, f);
    fclose(f);
    return 0;
}

int cv_pubkey_import_armored(const char *path, uint8_t pub_out[CV_ECDH_KEY_SIZE]) {
    if (!path || !pub_out) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -2;

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    uint8_t bin[64];
    size_t bin_len = sizeof(bin);
    cv_armor_type_t t;
    int ret = cv_armor_decode(buf, &t, bin, &bin_len);
    if (ret != 0 || bin_len != CV_ECDH_KEY_SIZE) {
        return -3;
    }
    memcpy(pub_out, bin, CV_ECDH_KEY_SIZE);
    return 0;
}

int cv_privkey_export_encrypted(const char *path,
                                const uint8_t priv[CV_ECDH_KEY_SIZE],
                                const char *passphrase) {
    return cv_keyfile_save_encrypted(path, priv, passphrase, CV_DEFAULT_MEM_COST_KB);
}

int cv_privkey_import_encrypted(const char *path,
                                const char *passphrase,
                                uint8_t priv_out[CV_ECDH_KEY_SIZE]) {
    return cv_keyfile_load_encrypted(path, passphrase, priv_out);
}

int cv_keyfile_self_test(void) {
    const char *tmp_path = "/tmp/cv_test_keyfile.asc";
    uint8_t original_key[32];
    uint8_t loaded_key[32];

    for (int i = 0; i < 32; i++) original_key[i] = (uint8_t)(i * 13 + 7);

    /* Use 64 KiB KDF for fast unit test */
    if (cv_keyfile_save_encrypted(tmp_path, original_key, "TestSecretKeyPass", 64) != 0) {
        return CV_KEYFILE_ERR_SELFTEST;
    }

    if (cv_keyfile_load_encrypted(tmp_path, "TestSecretKeyPass", loaded_key) != 0) {
        unlink(tmp_path);
        return CV_KEYFILE_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(original_key, loaded_key, 32) != 0) {
        unlink(tmp_path);
        return CV_KEYFILE_ERR_SELFTEST;
    }

    /* Wrong password must fail */
    if (cv_keyfile_load_encrypted(tmp_path, "WrongPassword", loaded_key) == 0) {
        unlink(tmp_path);
        return CV_KEYFILE_ERR_SELFTEST;
    }

    unlink(tmp_path);
    cv_memzero(original_key, sizeof(original_key));
    cv_memzero(loaded_key, sizeof(loaded_key));
    return CV_KEYFILE_SUCCESS;
}
