#include "aead.h"
#include "core.h"
#include "mac.h"
#include "sponge.h"
#include "entropy.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *cv_strerror(int err) {
    switch (err) {
        case CV_SUCCESS:                  return "Success";
        case CV_ERR_NULL_PARAM:          return "Null parameter provided";
        case CV_ERR_INVALID_LENGTH:      return "Invalid length";
        case CV_ERR_OUT_OF_MEMORY:       return "Out of memory";
        case CV_ERR_ENTROPY_FAILED:      return "Entropy generation failed";
        case CV_ERR_INVALID_MAGIC:       return "Invalid container magic header bytes";
        case CV_ERR_UNSUPPORTED_VERSION: return "Unsupported container format version";
        case CV_ERR_UNSUPPORTED_SUITE:   return "Unsupported cryptographic suite";
        case CV_ERR_HEADER_CORRUPTED:    return "Header metadata MAC verification failed (corrupted)";
        case CV_ERR_AUTH_FAILED:         return "Payload authentication failed (tampering detected)";
        case CV_ERR_AAD_MISMATCH:        return "Associated Authenticated Data (AAD) mismatch";
        case CV_ERR_IO:                  return "File I/O error";
        case CV_ERR_STREAM_CORRUPTED:    return "Stream chunk corrupted or out of sequence";
        default:                         return "Unknown error";
    }
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

static int derive_keys_internal(const void *secret, size_t secret_len,
                                int is_passphrase, const uint8_t salt[32],
                                uint32_t mem_cost_kb, uint32_t time_cost,
                                cv_subkeys_t *keys) {
    if (is_passphrase) {
        return cv_kdf_derive(secret, secret_len, salt, mem_cost_kb, time_cost, keys);
    } else {
        /* Direct domain separation for raw 256-bit key */
        cv_sponge_t sponge;
        cv_sponge_init(&sponge, 0x5241574B45595355ULL); /* "RAWKEYSU" */
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

static void apply_cipher_stream(const cv_core_ctx_t *core_ctx,
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

    /* Initialize secondary cascaded 512-bit sponge stream cipher layer */
    cv_sponge_t sponge_cascade;
    cv_sponge_init(&sponge_cascade, 0x4341534341444553ULL); /* "CASCADES" */
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

        /* Dynamic key-dependent whitening */
        for (int j = 0; j < CV_BLOCK_SIZE; j++) {
            uint8_t shift_key = k_white[(j + (counter & 31)) % 32];
            ks[j] = ks_raw[j] ^ k_white[j] ^ (uint8_t)(shift_key * 31);
        }

        size_t block_take = len - processed;
        if (block_take > CV_BLOCK_SIZE) {
            block_take = CV_BLOCK_SIZE;
        }

        /* Generate cascaded secondary keystream layer */
        cv_sponge_squeeze(&sponge_cascade, cascade_keystream, block_take);

        /* Multi-layer encryption: Plaintext ^ SP-ARX-256 ^ Sponge-Stream-512 */
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

int cv_aead_encrypt(const uint8_t *plaintext, size_t pt_len,
                    const uint8_t *aad, size_t aad_len,
                    const void *secret, size_t secret_len,
                    int is_passphrase,
                    uint32_t mem_cost_kb, uint32_t time_cost,
                    uint8_t **out_buf, size_t *out_len) {
    if (!secret || secret_len == 0 || !out_buf || !out_len) return CV_ERR_NULL_PARAM;
    if (pt_len > 0 && !plaintext) return CV_ERR_NULL_PARAM;
    if (aad_len > 0 && !aad) return CV_ERR_NULL_PARAM;

    if (is_passphrase) {
        if (mem_cost_kb == 0) mem_cost_kb = CV_DEFAULT_MEM_COST_KB; /* 1 MiB default */
        if (time_cost == 0) time_cost = CV_DEFAULT_TIME_COST;
    } else {
        mem_cost_kb = 0;
        time_cost = 0;
    }

    size_t total_len = sizeof(cv_header_t) + aad_len + pt_len + CV_TAG_SIZE;
    uint8_t *envelope = (uint8_t *)cv_secure_alloc(total_len);
    if (!envelope) return CV_ERR_OUT_OF_MEMORY;

    cv_header_t *hdr = (cv_header_t *)envelope;
    memcpy(hdr->magic, CV_MAGIC_BYTES, CV_MAGIC_LEN);
    hdr->version = CV_VERSION_1;
    hdr->cipher_suite = CV_SUITE_STANDARD;
    hdr->flags = 0;
    hdr->mem_cost_kb = mem_cost_kb;
    hdr->time_cost = time_cost;

    if (cv_entropy_get(hdr->salt, 32) != 0) {
        cv_secure_free(envelope, total_len);
        return CV_ERR_ENTROPY_FAILED;
    }
    cv_nonce_generate(hdr->nonce);

    hdr->payload_len = (uint64_t)pt_len;
    hdr->aad_len = (uint32_t)aad_len;

    /* Derive subkeys */
    cv_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr->salt,
                                   mem_cost_kb, time_cost, &keys);
    if (ret != 0) {
        cv_secure_free(envelope, total_len);
        return ret;
    }

    /* Compute 256-bit Header MAC over metadata fields (Tier 1 Integrity) */
    ret = cv_mac_compute(keys.k_hdr, (const uint8_t *)hdr,
                         sizeof(cv_header_t) - 32, hdr->header_mac);
    if (ret != 0) {
        cv_subkeys_clear(&keys);
        cv_secure_free(envelope, total_len);
        return ret;
    }

    /* Copy AAD if present */
    uint8_t *aad_dest = envelope + sizeof(cv_header_t);
    if (aad_len > 0) {
        memcpy(aad_dest, aad, aad_len);
    }

    /* Multi-layer Encrypt: SP-ARX-256 CTR + Sponge-Stream-512 */
    uint8_t *ct_dest = aad_dest + aad_len;
    if (pt_len > 0) {
        cv_core_ctx_t core_ctx;
        cv_core_expand_key(&core_ctx, keys.k_enc);
        apply_cipher_stream(&core_ctx, keys.k_white, keys.k_cascade, hdr->nonce, 0, plaintext, ct_dest, pt_len);
        cv_core_clear(&core_ctx);
    }

    /* Authenticate (Tier 2 Integrity): Header + AAD + Ciphertext */
    uint8_t *tag_dest = ct_dest + pt_len;
    cv_mac_ctx_t mac_ctx;
    cv_mac_init(&mac_ctx, keys.k_mac);
    cv_mac_update(&mac_ctx, hdr, sizeof(cv_header_t));
    if (aad_len > 0) {
        cv_mac_update(&mac_ctx, aad, aad_len);
    }
    if (pt_len > 0) {
        cv_mac_update(&mac_ctx, ct_dest, pt_len);
    }
    cv_mac_final(&mac_ctx, tag_dest);

    cv_subkeys_clear(&keys);

    *out_buf = envelope;
    *out_len = total_len;
    return CV_SUCCESS;
}

int cv_aead_decrypt(const uint8_t *envelope, size_t env_len,
                    const uint8_t *expected_aad, size_t aad_len,
                    const void *secret, size_t secret_len,
                    int is_passphrase,
                    uint8_t **out_plaintext, size_t *out_pt_len) {
    if (!envelope || !secret || secret_len == 0 || !out_plaintext || !out_pt_len) {
        return CV_ERR_NULL_PARAM;
    }
    *out_plaintext = NULL;
    *out_pt_len = 0;

    if (env_len < sizeof(cv_header_t) + CV_TAG_SIZE) {
        return CV_ERR_INVALID_LENGTH;
    }

    const cv_header_t *hdr = (const cv_header_t *)envelope;

    if (cv_ct_memcmp(hdr->magic, CV_MAGIC_BYTES, CV_MAGIC_LEN) != 0) {
        return CV_ERR_INVALID_MAGIC;
    }
    if (hdr->version != CV_VERSION_1) {
        return CV_ERR_UNSUPPORTED_VERSION;
    }
    if (hdr->cipher_suite != CV_SUITE_STANDARD) {
        return CV_ERR_UNSUPPORTED_SUITE;
    }

    if (hdr->aad_len != (uint32_t)aad_len) {
        return CV_ERR_AAD_MISMATCH;
    }

    size_t expected_total = sizeof(cv_header_t) + hdr->aad_len + (size_t)hdr->payload_len + CV_TAG_SIZE;
    if (env_len != expected_total) {
        return CV_ERR_INVALID_LENGTH;
    }

    const uint8_t *aad_ptr = envelope + sizeof(cv_header_t);
    if (aad_len > 0) {
        if (cv_ct_memcmp(aad_ptr, expected_aad, aad_len) != 0) {
            return CV_ERR_AAD_MISMATCH;
        }
    }

    const uint8_t *ct_ptr = aad_ptr + aad_len;
    const uint8_t *tag_ptr = ct_ptr + hdr->payload_len;

    /* Derive subkeys */
    cv_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr->salt,
                                   hdr->mem_cost_kb, hdr->time_cost, &keys);
    if (ret != 0) {
        return ret;
    }

    /* 1. Defensive Parsing: Validate Header MAC (Tier 1) */
    ret = cv_mac_verify(keys.k_hdr, (const uint8_t *)hdr,
                        sizeof(cv_header_t) - 32, hdr->header_mac);
    if (ret != 0) {
        cv_subkeys_clear(&keys);
        return CV_ERR_HEADER_CORRUPTED;
    }

    /* 2. Constant-time authentication check over Header + AAD + Ciphertext (Tier 2) */
    uint8_t computed_tag[CV_TAG_SIZE];
    cv_mac_ctx_t mac_ctx;
    cv_mac_init(&mac_ctx, keys.k_mac);
    cv_mac_update(&mac_ctx, hdr, sizeof(cv_header_t));
    if (aad_len > 0) {
        cv_mac_update(&mac_ctx, aad_ptr, aad_len);
    }
    if (hdr->payload_len > 0) {
        cv_mac_update(&mac_ctx, ct_ptr, (size_t)hdr->payload_len);
    }
    cv_mac_final(&mac_ctx, computed_tag);

    if (cv_ct_memcmp(computed_tag, tag_ptr, CV_TAG_SIZE) != 0) {
        cv_memzero(computed_tag, sizeof(computed_tag));
        cv_subkeys_clear(&keys);
        return CV_ERR_AUTH_FAILED; /* Fail-secure */
    }
    cv_memzero(computed_tag, sizeof(computed_tag));

    /* 3. Decrypt verified plaintext (dual-layer inverted stream) */
    uint8_t *pt = NULL;
    if (hdr->payload_len > 0) {
        pt = (uint8_t *)cv_secure_alloc((size_t)hdr->payload_len);
        if (!pt) {
            cv_subkeys_clear(&keys);
            return CV_ERR_OUT_OF_MEMORY;
        }

        cv_core_ctx_t core_ctx;
        cv_core_expand_key(&core_ctx, keys.k_enc);
        apply_cipher_stream(&core_ctx, keys.k_white, keys.k_cascade, hdr->nonce, 0,
                            ct_ptr, pt, (size_t)hdr->payload_len);
        cv_core_clear(&core_ctx);
    }

    cv_subkeys_clear(&keys);

    *out_plaintext = pt;
    *out_pt_len = (size_t)hdr->payload_len;
    return CV_SUCCESS;
}
