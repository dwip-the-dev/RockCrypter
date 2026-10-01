#define _GNU_SOURCE
#include "stream.h"
#include "core.h"
#include "mac.h"
#include "sponge.h"
#include "entropy.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static inline void store32_le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline uint32_t load32_le(const uint8_t *b) {
    return ((uint32_t)b[0]) |
           (((uint32_t)b[1]) << 8) |
           (((uint32_t)b[2]) << 16) |
           (((uint32_t)b[3]) << 24);
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

static int derive_keys_stream(const void *secret, size_t secret_len,
                              int is_passphrase, const uint8_t salt[32],
                              uint32_t mem_cost_kb, uint32_t time_cost,
                              cv_subkeys_t *keys) {
    if (is_passphrase) {
        return cv_kdf_derive(secret, secret_len, salt, mem_cost_kb, time_cost, keys);
    } else {
        cv_sponge_t sponge;
        cv_sponge_init(&sponge, 0x5241574B45595355ULL);
        cv_sponge_absorb(&sponge, secret, secret_len);
        cv_sponge_absorb(&sponge, salt, 32);

        cv_sponge_squeeze(&sponge, keys->k_enc, 32);
        cv_sponge_squeeze(&sponge, keys->k_white, 32);
        cv_sponge_squeeze(&sponge, keys->k_mac, 32);
        cv_sponge_squeeze(&sponge, keys->k_hdr, 32);
        cv_sponge_squeeze(&sponge, keys->k_cascade, 32);
        cv_sponge_clear(&sponge);
        return 0;
    }
}

static void apply_cipher_stream_chunk(const cv_core_ctx_t *core_ctx,
                                      const uint8_t k_white[32],
                                      const uint8_t k_cascade[32],
                                      const uint8_t nonce[24],
                                      uint64_t start_counter,
                                      const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t iv_block[CV_BLOCK_SIZE];
    uint8_t ks_raw[CV_BLOCK_SIZE];
    uint8_t ks[CV_BLOCK_SIZE];
    uint8_t cascade_keystream[CV_BLOCK_SIZE];

    memcpy(iv_block, nonce, 24);

    cv_sponge_t sponge_cascade;
    cv_sponge_init(&sponge_cascade, 0x4341534341444553ULL);
    cv_sponge_absorb(&sponge_cascade, k_cascade, 32);
    cv_sponge_absorb(&sponge_cascade, nonce, 24);
    uint8_t ctr_seed[8];
    store64_le(ctr_seed, start_counter);
    cv_sponge_absorb(&sponge_cascade, ctr_seed, 8);

    size_t processed = 0;
    uint64_t counter = start_counter;

    while (processed < len) {
        store64_le(iv_block + 24, counter);
        cv_core_encrypt_block(core_ctx, iv_block, ks_raw);

        for (int j = 0; j < CV_BLOCK_SIZE; j++) {
            uint8_t shift_key = k_white[(j + (counter & 31)) % 32];
            ks[j] = ks_raw[j] ^ k_white[j] ^ (uint8_t)(shift_key * 31);
        }

        size_t block_take = len - processed;
        if (block_take > CV_BLOCK_SIZE) {
            block_take = CV_BLOCK_SIZE;
        }

        cv_sponge_squeeze(&sponge_cascade, cascade_keystream, block_take);

        for (size_t j = 0; j < block_take; j++) {
            out[processed + j] = in[processed + j] ^ ks[j] ^ cascade_keystream[j];
        }

        processed += block_take;
        counter++;
    }

    cv_sponge_clear(&sponge_cascade);
    cv_memzero(iv_block, sizeof(iv_block));
    cv_memzero(ks_raw, sizeof(ks_raw));
    cv_memzero(ks, sizeof(ks));
    cv_memzero(cascade_keystream, sizeof(cascade_keystream));
}

int cv_file_encrypt(const char *in_path, const char *out_path,
                    const void *secret, size_t secret_len, int is_passphrase,
                    const uint8_t *aad, size_t aad_len,
                    uint32_t mem_cost_kb, uint32_t time_cost) {
    if (!in_path || !out_path || !secret) return CV_ERR_NULL_PARAM;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) return CV_ERR_IO;

    /* Linux sequential I/O optimization hint */
    posix_fadvise(fileno(fin), 0, 0, POSIX_FADV_SEQUENTIAL);

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        fclose(fin);
        return CV_ERR_IO;
    }

    if (is_passphrase) {
        if (mem_cost_kb == 0) mem_cost_kb = CV_DEFAULT_MEM_COST_KB; /* 1024 KB = 1 MiB base */
        if (time_cost == 0) time_cost = CV_DEFAULT_TIME_COST;
    }

    cv_header_t hdr;
    cv_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, CV_MAGIC_BYTES, CV_MAGIC_LEN);
    hdr.version = CV_VERSION_1;
    hdr.cipher_suite = CV_SUITE_STANDARD;
    hdr.flags = 1; /* Streaming chunked mode */
    hdr.mem_cost_kb = mem_cost_kb;
    hdr.time_cost = time_cost;

    if (cv_entropy_get(hdr.salt, 32) != 0) {
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return CV_ERR_ENTROPY_FAILED;
    }
    cv_nonce_generate(hdr.nonce);

    hdr.payload_len = 0; /* Dynamic streaming volume */
    hdr.aad_len = (uint32_t)aad_len;

    cv_subkeys_t keys;
    int ret = derive_keys_stream(secret, secret_len, is_passphrase, hdr.salt,
                                 mem_cost_kb, time_cost, &keys);
    if (ret != 0) {
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return ret;
    }

    /* Compute Header MAC (Tier 1 Integrity) */
    cv_mac_compute(keys.k_hdr, (const uint8_t *)&hdr, sizeof(hdr) - 32, hdr.header_mac);

    /* Write Header */
    if (fwrite(&hdr, 1, sizeof(hdr), fout) != sizeof(hdr)) {
        cv_subkeys_clear(&keys);
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return CV_ERR_IO;
    }

    /* Write AAD */
    if (aad_len > 0) {
        if (fwrite(aad, 1, aad_len, fout) != aad_len) {
            cv_subkeys_clear(&keys);
            fclose(fin);
            fclose(fout);
            unlink(out_path);
            return CV_ERR_IO;
        }
    }

    cv_core_ctx_t core_ctx;
    cv_core_expand_key(&core_ctx, keys.k_enc);

    uint8_t *in_buf = (uint8_t *)cv_secure_alloc(CV_CHUNK_SIZE);
    uint8_t *ct_buf = (uint8_t *)cv_secure_alloc(CV_CHUNK_SIZE);
    uint64_t chunk_idx = 0;
    uint64_t stream_block_counter = 0;

    /* Initialize ratcheted running digest for tamper-proof chaining */
    uint8_t running_ratchet[32];
    memcpy(running_ratchet, keys.k_mac, 32);
    for (int i = 0; i < 24; i++) running_ratchet[i] ^= hdr.nonce[i];

    int done = 0;
    while (!done) {
        size_t n = fread(in_buf, 1, CV_CHUNK_SIZE, fin);
        uint8_t is_final = feof(fin) ? 1 : 0;
        if (is_final) done = 1;

        apply_cipher_stream_chunk(&core_ctx, keys.k_white, keys.k_cascade, hdr.nonce,
                                  stream_block_counter, in_buf, ct_buf, n);
        stream_block_counter += (n + 31) / 32;

        /* Chunk framing: uint32 chunk_len (4) + uint8 is_final (1) + uint64 chunk_idx (8) */
        uint8_t chunk_meta[13];
        store32_le(chunk_meta, (uint32_t)n);
        chunk_meta[4] = is_final;
        store64_le(chunk_meta + 5, chunk_idx);

        /* Compute ratcheted chunk tag over running_ratchet + chunk_meta + ciphertext */
        uint8_t chunk_tag[CV_TAG_SIZE];
        cv_mac_ctx_t chunk_mac;
        cv_mac_init(&chunk_mac, keys.k_mac);
        cv_mac_update(&chunk_mac, running_ratchet, sizeof(running_ratchet));
        cv_mac_update(&chunk_mac, chunk_meta, sizeof(chunk_meta));
        if (n > 0) {
            cv_mac_update(&chunk_mac, ct_buf, n);
        }
        cv_mac_final(&chunk_mac, chunk_tag);

        /* Ratchet update: next chunk tag depends on current chunk tag */
        memcpy(running_ratchet, chunk_tag, sizeof(running_ratchet));

        /* Write chunk frame: meta (13) + ciphertext (n) + tag (32) */
        if (fwrite(chunk_meta, 1, sizeof(chunk_meta), fout) != sizeof(chunk_meta) ||
            (n > 0 && fwrite(ct_buf, 1, n, fout) != n) ||
            fwrite(chunk_tag, 1, CV_TAG_SIZE, fout) != CV_TAG_SIZE) {
            cv_memzero(chunk_tag, sizeof(chunk_tag));
            cv_memzero(running_ratchet, sizeof(running_ratchet));
            cv_secure_free(in_buf, CV_CHUNK_SIZE);
            cv_secure_free(ct_buf, CV_CHUNK_SIZE);
            cv_core_clear(&core_ctx);
            cv_subkeys_clear(&keys);
            fclose(fin);
            fclose(fout);
            unlink(out_path);
            return CV_ERR_IO;
        }

        chunk_idx++;
        if (n == 0 && is_final) break;
    }

    cv_memzero(running_ratchet, sizeof(running_ratchet));
    cv_secure_free(in_buf, CV_CHUNK_SIZE);
    cv_secure_free(ct_buf, CV_CHUNK_SIZE);
    cv_core_clear(&core_ctx);
    cv_subkeys_clear(&keys);
    fclose(fin);
    fclose(fout);
    return CV_SUCCESS;
}

int cv_file_decrypt(const char *in_path, const char *out_path,
                    const void *secret, size_t secret_len, int is_passphrase,
                    const uint8_t *expected_aad, size_t aad_len) {
    if (!in_path || !out_path || !secret) return CV_ERR_NULL_PARAM;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) return CV_ERR_IO;

    posix_fadvise(fileno(fin), 0, 0, POSIX_FADV_SEQUENTIAL);

    cv_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), fin) != sizeof(hdr)) {
        fclose(fin);
        return CV_ERR_INVALID_LENGTH;
    }

    if (cv_ct_memcmp(hdr.magic, CV_MAGIC_BYTES, CV_MAGIC_LEN) != 0) {
        fclose(fin);
        return CV_ERR_INVALID_MAGIC;
    }
    if (hdr.version != CV_VERSION_1) {
        fclose(fin);
        return CV_ERR_UNSUPPORTED_VERSION;
    }
    if (hdr.cipher_suite != CV_SUITE_STANDARD) {
        fclose(fin);
        return CV_ERR_UNSUPPORTED_SUITE;
    }
    if (hdr.aad_len != (uint32_t)aad_len) {
        fclose(fin);
        return CV_ERR_AAD_MISMATCH;
    }

    /* Verify AAD if present */
    if (aad_len > 0) {
        uint8_t *aad_disk = (uint8_t *)malloc(aad_len);
        if (!aad_disk || fread(aad_disk, 1, aad_len, fin) != aad_len) {
            free(aad_disk);
            fclose(fin);
            return CV_ERR_IO;
        }
        if (cv_ct_memcmp(aad_disk, expected_aad, aad_len) != 0) {
            free(aad_disk);
            fclose(fin);
            return CV_ERR_AAD_MISMATCH;
        }
        free(aad_disk);
    }

    cv_subkeys_t keys;
    int ret = derive_keys_stream(secret, secret_len, is_passphrase, hdr.salt,
                                 hdr.mem_cost_kb, hdr.time_cost, &keys);
    if (ret != 0) {
        fclose(fin);
        return ret;
    }

    /* Verify Header MAC (Tier 1 Integrity) */
    ret = cv_mac_verify(keys.k_hdr, (const uint8_t *)&hdr, sizeof(hdr) - 32, hdr.header_mac);
    if (ret != 0) {
        cv_subkeys_clear(&keys);
        fclose(fin);
        return CV_ERR_HEADER_CORRUPTED;
    }

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        cv_subkeys_clear(&keys);
        fclose(fin);
        return CV_ERR_IO;
    }

    cv_core_ctx_t core_ctx;
    cv_core_expand_key(&core_ctx, keys.k_enc);

    uint8_t *ct_buf = (uint8_t *)cv_secure_alloc(CV_CHUNK_SIZE);
    uint8_t *pt_buf = (uint8_t *)cv_secure_alloc(CV_CHUNK_SIZE);
    uint64_t expected_chunk_idx = 0;
    uint64_t stream_block_counter = 0;

    /* Initialize ratcheted running digest */
    uint8_t running_ratchet[32];
    memcpy(running_ratchet, keys.k_mac, 32);
    for (int i = 0; i < 24; i++) running_ratchet[i] ^= hdr.nonce[i];

    int finished = 0;
    while (!finished) {
        uint8_t chunk_meta[13];
        size_t r = fread(chunk_meta, 1, sizeof(chunk_meta), fin);
        if (r == 0) break;
        if (r != sizeof(chunk_meta)) {
            ret = CV_ERR_STREAM_CORRUPTED;
            break;
        }

        uint32_t chunk_len = load32_le(chunk_meta);
        uint8_t is_final = chunk_meta[4];
        uint64_t chunk_idx = load64_le(chunk_meta + 5);

        if (chunk_idx != expected_chunk_idx || chunk_len > CV_CHUNK_SIZE) {
            ret = CV_ERR_STREAM_CORRUPTED;
            break;
        }

        if (chunk_len > 0) {
            if (fread(ct_buf, 1, chunk_len, fin) != chunk_len) {
                ret = CV_ERR_IO;
                break;
            }
        }

        uint8_t read_tag[CV_TAG_SIZE];
        if (fread(read_tag, 1, CV_TAG_SIZE, fin) != CV_TAG_SIZE) {
            ret = CV_ERR_STREAM_CORRUPTED;
            break;
        }

        /* Verify Ratcheted Chunk MAC */
        uint8_t computed_tag[CV_TAG_SIZE];
        cv_mac_ctx_t chunk_mac;
        cv_mac_init(&chunk_mac, keys.k_mac);
        cv_mac_update(&chunk_mac, running_ratchet, sizeof(running_ratchet));
        cv_mac_update(&chunk_mac, chunk_meta, sizeof(chunk_meta));
        if (chunk_len > 0) {
            cv_mac_update(&chunk_mac, ct_buf, chunk_len);
        }
        cv_mac_final(&chunk_mac, computed_tag);

        if (cv_ct_memcmp(computed_tag, read_tag, CV_TAG_SIZE) != 0) {
            cv_memzero(computed_tag, sizeof(computed_tag));
            ret = CV_ERR_AUTH_FAILED;
            break;
        }
        cv_memzero(computed_tag, sizeof(computed_tag));
        memcpy(running_ratchet, read_tag, sizeof(running_ratchet));

        /* Authenticated: Decrypt chunk with dual-layer cascade */
        if (chunk_len > 0) {
            apply_cipher_stream_chunk(&core_ctx, keys.k_white, keys.k_cascade, hdr.nonce,
                                      stream_block_counter, ct_buf, pt_buf, chunk_len);
            stream_block_counter += (chunk_len + 31) / 32;

            if (fwrite(pt_buf, 1, chunk_len, fout) != chunk_len) {
                ret = CV_ERR_IO;
                break;
            }
        }

        expected_chunk_idx++;
        if (is_final) {
            finished = 1;
        }
    }

    cv_memzero(running_ratchet, sizeof(running_ratchet));
    cv_secure_free(ct_buf, CV_CHUNK_SIZE);
    cv_secure_free(pt_buf, CV_CHUNK_SIZE);
    cv_core_clear(&core_ctx);
    cv_subkeys_clear(&keys);
    fclose(fin);
    fclose(fout);

    if (ret != 0 || !finished) {
        unlink(out_path); /* Fail-secure unlinking on tamper */
        return (ret != 0) ? ret : CV_ERR_STREAM_CORRUPTED;
    }

    return CV_SUCCESS;
}

int cv_file_inspect(const char *path, cv_header_t *hdr_out) {
    if (!path || !hdr_out) return CV_ERR_NULL_PARAM;
    FILE *f = fopen(path, "rb");
    if (!f) return CV_ERR_IO;

    if (fread(hdr_out, 1, sizeof(cv_header_t), f) != sizeof(cv_header_t)) {
        fclose(f);
        return CV_ERR_INVALID_LENGTH;
    }
    fclose(f);

    if (cv_ct_memcmp(hdr_out->magic, CV_MAGIC_BYTES, CV_MAGIC_LEN) != 0) {
        return CV_ERR_INVALID_MAGIC;
    }
    return CV_SUCCESS;
}
