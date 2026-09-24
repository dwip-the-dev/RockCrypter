#include "rock_aead.h"
#include "rock_core.h"
#include "rock_mac.h"
#include "rock_sponge.h"
#include "rock_entropy.h"
#include "rock_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *rock_strerror(int err) {
    switch (err) {
        case ROCK_SUCCESS:                  return "Success";
        case ROCK_ERR_NULL_PARAM:          return "Null parameter provided";
        case ROCK_ERR_INVALID_LENGTH:      return "Invalid length";
        case ROCK_ERR_OUT_OF_MEMORY:       return "Out of memory";
        case ROCK_ERR_ENTROPY_FAILED:      return "Entropy generation failed";
        case ROCK_ERR_INVALID_MAGIC:       return "Invalid magic header bytes";
        case ROCK_ERR_UNSUPPORTED_VERSION: return "Unsupported RockCrypter format version";
        case ROCK_ERR_UNSUPPORTED_SUITE:   return "Unsupported cryptographic suite";
        case ROCK_ERR_HEADER_CORRUPTED:    return "Header metadata MAC verification failed (corrupted)";
        case ROCK_ERR_AUTH_FAILED:         return "Payload authentication failed (tampering detected)";
        case ROCK_ERR_AAD_MISMATCH:        return "Associated Authenticated Data (AAD) mismatch";
        case ROCK_ERR_IO:                  return "File I/O error";
        case ROCK_ERR_STREAM_CORRUPTED:    return "Stream chunk corrupted or out of sequence";
        default:                           return "Unknown error";
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

static int derive_keys_internal(const void *secret, size_t secret_len,
                                int is_passphrase, const uint8_t salt[32],
                                uint32_t mem_cost_kb, uint32_t time_cost,
                                rock_subkeys_t *keys) {
    if (is_passphrase) {
        return rock_kdf_derive(secret, secret_len, salt, mem_cost_kb, time_cost, keys);
    } else {
        /* Raw 256-bit key direct domain derivation */
        rock_sponge_t sponge;
        rock_sponge_init(&sponge, 0x5241574B45595355ULL); /* "RAWKEYSU" */
        rock_sponge_absorb(&sponge, secret, secret_len);
        rock_sponge_absorb(&sponge, salt, 32);

        rock_sponge_squeeze(&sponge, keys->k_enc, 32);
        rock_sponge_squeeze(&sponge, keys->k_white, 32);
        rock_sponge_squeeze(&sponge, keys->k_mac, 32);
        rock_sponge_squeeze(&sponge, keys->k_hdr, 32);
        rock_sponge_clear(&sponge);
        return 0;
    }
}

static void apply_cipher_stream(const rock_core_ctx_t *core_ctx,
                                const uint8_t k_white[32],
                                const uint8_t nonce[24],
                                uint64_t start_counter,
                                const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t iv_block[ROCK_CORE_BLOCK_SIZE];
    uint8_t ks_raw[ROCK_CORE_BLOCK_SIZE];
    uint8_t ks[ROCK_CORE_BLOCK_SIZE];

    memcpy(iv_block, nonce, 24);

    size_t processed = 0;
    uint64_t counter = start_counter;

    while (processed < len) {
        store64_le(iv_block + 24, counter);
        rock_core_encrypt_block(core_ctx, iv_block, ks_raw);

        /* Dynamic key-dependent keystream whitening */
        for (int j = 0; j < ROCK_CORE_BLOCK_SIZE; j++) {
            uint8_t shift_key = k_white[(j + (counter & 31)) % 32];
            ks[j] = ks_raw[j] ^ k_white[j] ^ (uint8_t)(shift_key * 31);
        }

        size_t block_take = len - processed;
        if (block_take > ROCK_CORE_BLOCK_SIZE) {
            block_take = ROCK_CORE_BLOCK_SIZE;
        }

        for (size_t j = 0; j < block_take; j++) {
            out[processed + j] = in[processed + j] ^ ks[j];
        }

        processed += block_take;
        counter++;
    }

    rock_memzero(iv_block, sizeof(iv_block));
    rock_memzero(ks_raw, sizeof(ks_raw));
    rock_memzero(ks, sizeof(ks));
}

int rock_aead_encrypt(const uint8_t *plaintext, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      const void *secret, size_t secret_len,
                      int is_passphrase,
                      uint32_t mem_cost_kb, uint32_t time_cost,
                      uint8_t **out_buf, size_t *out_len) {
    if (!secret || secret_len == 0 || !out_buf || !out_len) return ROCK_ERR_NULL_PARAM;
    if (pt_len > 0 && !plaintext) return ROCK_ERR_NULL_PARAM;
    if (aad_len > 0 && !aad) return ROCK_ERR_NULL_PARAM;

    if (is_passphrase) {
        if (mem_cost_kb == 0) mem_cost_kb = 16384; /* 16 MB default */
        if (time_cost == 0) time_cost = 4;
    } else {
        mem_cost_kb = 0;
        time_cost = 0;
    }

    /* Total envelope: Header + AAD + Ciphertext + Tag */
    size_t total_len = sizeof(rock_header_t) + aad_len + pt_len + ROCK_TAG_SIZE;
    uint8_t *envelope = (uint8_t *)rock_secure_alloc(total_len);
    if (!envelope) return ROCK_ERR_OUT_OF_MEMORY;

    rock_header_t *hdr = (rock_header_t *)envelope;
    memcpy(hdr->magic, ROCK_MAGIC_BYTES, ROCK_MAGIC_LEN);
    hdr->version = ROCK_VERSION_1;
    hdr->cipher_suite = ROCK_SUITE_ROCKCORE;
    hdr->flags = 0;
    hdr->mem_cost_kb = mem_cost_kb;
    hdr->time_cost = time_cost;

    if (rock_salt_generate(hdr->salt) != 0 || rock_nonce_generate(hdr->nonce) != 0) {
        rock_secure_free(envelope, total_len);
        return ROCK_ERR_ENTROPY_FAILED;
    }

    hdr->payload_len = (uint64_t)pt_len;
    hdr->aad_len = (uint32_t)aad_len;

    /* Derive subkeys */
    rock_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr->salt,
                                   mem_cost_kb, time_cost, &keys);
    if (ret != 0) {
        rock_secure_free(envelope, total_len);
        return ret;
    }

    /* Compute 256-bit Header MAC over metadata fields (all bytes preceding header_mac) */
    ret = rock_mac_compute(keys.k_hdr, (const uint8_t *)hdr,
                           sizeof(rock_header_t) - 32, hdr->header_mac);
    if (ret != 0) {
        rock_subkeys_clear(&keys);
        rock_secure_free(envelope, total_len);
        return ret;
    }

    /* Copy AAD if present */
    uint8_t *aad_dest = envelope + sizeof(rock_header_t);
    if (aad_len > 0) {
        memcpy(aad_dest, aad, aad_len);
    }

    /* Encrypt plaintext payload */
    uint8_t *ct_dest = aad_dest + aad_len;
    if (pt_len > 0) {
        rock_core_ctx_t core_ctx;
        rock_core_expand_key(&core_ctx, keys.k_enc);
        apply_cipher_stream(&core_ctx, keys.k_white, hdr->nonce, 0, plaintext, ct_dest, pt_len);
        rock_core_clear(&core_ctx);
    }

    /* Authenticate: Header + AAD + Ciphertext */
    uint8_t *tag_dest = ct_dest + pt_len;
    rock_mac_ctx_t mac_ctx;
    rock_mac_init(&mac_ctx, keys.k_mac);
    rock_mac_update(&mac_ctx, hdr, sizeof(rock_header_t));
    if (aad_len > 0) {
        rock_mac_update(&mac_ctx, aad, aad_len);
    }
    if (pt_len > 0) {
        rock_mac_update(&mac_ctx, ct_dest, pt_len);
    }
    rock_mac_final(&mac_ctx, tag_dest);

    /* Wipe keys */
    rock_subkeys_clear(&keys);

    *out_buf = envelope;
    *out_len = total_len;
    return ROCK_SUCCESS;
}

int rock_aead_decrypt(const uint8_t *envelope, size_t env_len,
                      const uint8_t *expected_aad, size_t aad_len,
                      const void *secret, size_t secret_len,
                      int is_passphrase,
                      uint8_t **out_plaintext, size_t *out_pt_len) {
    if (!envelope || !secret || secret_len == 0 || !out_plaintext || !out_pt_len) {
        return ROCK_ERR_NULL_PARAM;
    }
    *out_plaintext = NULL;
    *out_pt_len = 0;

    /* Zero-trust check: minimum envelope size */
    if (env_len < sizeof(rock_header_t) + ROCK_TAG_SIZE) {
        return ROCK_ERR_INVALID_LENGTH;
    }

    const rock_header_t *hdr = (const rock_header_t *)envelope;

    /* Header validation */
    if (rock_ct_memcmp(hdr->magic, ROCK_MAGIC_BYTES, ROCK_MAGIC_LEN) != 0) {
        return ROCK_ERR_INVALID_MAGIC;
    }
    if (hdr->version != ROCK_VERSION_1) {
        return ROCK_ERR_UNSUPPORTED_VERSION;
    }
    if (hdr->cipher_suite != ROCK_SUITE_ROCKCORE) {
        return ROCK_ERR_UNSUPPORTED_SUITE;
    }

    /* AAD checks */
    if (hdr->aad_len != (uint32_t)aad_len) {
        return ROCK_ERR_AAD_MISMATCH;
    }

    /* Length bounds check */
    size_t expected_total = sizeof(rock_header_t) + hdr->aad_len + (size_t)hdr->payload_len + ROCK_TAG_SIZE;
    if (env_len != expected_total) {
        return ROCK_ERR_INVALID_LENGTH;
    }

    const uint8_t *aad_ptr = envelope + sizeof(rock_header_t);
    if (aad_len > 0) {
        if (rock_ct_memcmp(aad_ptr, expected_aad, aad_len) != 0) {
            return ROCK_ERR_AAD_MISMATCH;
        }
    }

    const uint8_t *ct_ptr = aad_ptr + aad_len;
    const uint8_t *tag_ptr = ct_ptr + hdr->payload_len;

    /* Derive subkeys */
    rock_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr->salt,
                                   hdr->mem_cost_kb, hdr->time_cost, &keys);
    if (ret != 0) {
        return ret;
    }

    /* Step 1: Validate Header MAC before processing payload */
    ret = rock_mac_verify(keys.k_hdr, (const uint8_t *)hdr,
                          sizeof(rock_header_t) - 32, hdr->header_mac);
    if (ret != 0) {
        rock_subkeys_clear(&keys);
        return ROCK_ERR_HEADER_CORRUPTED;
    }

    /* Step 2: Constant-time authentication check over Header + AAD + Ciphertext */
    uint8_t computed_tag[ROCK_TAG_SIZE];
    rock_mac_ctx_t mac_ctx;
    rock_mac_init(&mac_ctx, keys.k_mac);
    rock_mac_update(&mac_ctx, hdr, sizeof(rock_header_t));
    if (aad_len > 0) {
        rock_mac_update(&mac_ctx, aad_ptr, aad_len);
    }
    if (hdr->payload_len > 0) {
        rock_mac_update(&mac_ctx, ct_ptr, (size_t)hdr->payload_len);
    }
    rock_mac_final(&mac_ctx, computed_tag);

    if (rock_ct_memcmp(computed_tag, tag_ptr, ROCK_TAG_SIZE) != 0) {
        rock_memzero(computed_tag, sizeof(computed_tag));
        rock_subkeys_clear(&keys);
        return ROCK_ERR_AUTH_FAILED; /* Fail-secure: Zero plaintext released */
    }
    rock_memzero(computed_tag, sizeof(computed_tag));

    /* Step 3: Authenticated — Decrypt plaintext payload */
    uint8_t *pt = NULL;
    if (hdr->payload_len > 0) {
        pt = (uint8_t *)rock_secure_alloc((size_t)hdr->payload_len);
        if (!pt) {
            rock_subkeys_clear(&keys);
            return ROCK_ERR_OUT_OF_MEMORY;
        }

        rock_core_ctx_t core_ctx;
        rock_core_expand_key(&core_ctx, keys.k_enc);
        apply_cipher_stream(&core_ctx, keys.k_white, hdr->nonce, 0,
                            ct_ptr, pt, (size_t)hdr->payload_len);
        rock_core_clear(&core_ctx);
    }

    rock_subkeys_clear(&keys);

    *out_plaintext = pt;
    *out_pt_len = (size_t)hdr->payload_len;
    return ROCK_SUCCESS;
}

/* File Streaming Chunk Framing */
int rock_file_encrypt(const char *in_path, const char *out_path,
                      const void *secret, size_t secret_len, int is_passphrase,
                      const uint8_t *aad, size_t aad_len,
                      uint32_t mem_cost_kb, uint32_t time_cost) {
    if (!in_path || !out_path || !secret) return ROCK_ERR_NULL_PARAM;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) return ROCK_ERR_IO;

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        fclose(fin);
        return ROCK_ERR_IO;
    }

    if (is_passphrase) {
        if (mem_cost_kb == 0) mem_cost_kb = 16384;
        if (time_cost == 0) time_cost = 4;
    }

    rock_header_t hdr;
    rock_memzero(&hdr, sizeof(hdr));
    memcpy(hdr.magic, ROCK_MAGIC_BYTES, ROCK_MAGIC_LEN);
    hdr.version = ROCK_VERSION_1;
    hdr.cipher_suite = ROCK_SUITE_ROCKCORE;
    hdr.flags = 1; /* Streaming chunked mode */
    hdr.mem_cost_kb = mem_cost_kb;
    hdr.time_cost = time_cost;

    if (rock_salt_generate(hdr.salt) != 0 || rock_nonce_generate(hdr.nonce) != 0) {
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return ROCK_ERR_ENTROPY_FAILED;
    }

    hdr.payload_len = 0; /* Dynamic streaming */
    hdr.aad_len = (uint32_t)aad_len;

    rock_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr.salt,
                                   mem_cost_kb, time_cost, &keys);
    if (ret != 0) {
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return ret;
    }

    /* Compute Header MAC */
    rock_mac_compute(keys.k_hdr, (const uint8_t *)&hdr, sizeof(hdr) - 32, hdr.header_mac);

    /* Write Header */
    if (fwrite(&hdr, 1, sizeof(hdr), fout) != sizeof(hdr)) {
        rock_subkeys_clear(&keys);
        fclose(fin);
        fclose(fout);
        unlink(out_path);
        return ROCK_ERR_IO;
    }

    /* Write AAD */
    if (aad_len > 0) {
        if (fwrite(aad, 1, aad_len, fout) != aad_len) {
            rock_subkeys_clear(&keys);
            fclose(fin);
            fclose(fout);
            unlink(out_path);
            return ROCK_ERR_IO;
        }
    }

    rock_core_ctx_t core_ctx;
    rock_core_expand_key(&core_ctx, keys.k_enc);

    uint8_t *in_buf = (uint8_t *)rock_secure_alloc(ROCK_CHUNK_SIZE);
    uint8_t *ct_buf = (uint8_t *)rock_secure_alloc(ROCK_CHUNK_SIZE);
    uint64_t chunk_idx = 0;
    uint64_t stream_block_counter = 0;

    int done = 0;
    while (!done) {
        size_t n = fread(in_buf, 1, ROCK_CHUNK_SIZE, fin);
        uint8_t is_final = feof(fin) ? 1 : 0;
        if (is_final) done = 1;

        apply_cipher_stream(&core_ctx, keys.k_white, hdr.nonce, stream_block_counter,
                            in_buf, ct_buf, n);
        stream_block_counter += (n + 31) / 32;

        /* Chunk framing: uint32 chunk_len (4) + uint8 is_final (1) + uint64 chunk_idx (8) */
        uint8_t chunk_meta[13];
        store32_le(chunk_meta, (uint32_t)n);
        chunk_meta[4] = is_final;
        store64_le(chunk_meta + 5, chunk_idx);

        /* Compute chunk tag over chunk_meta + ciphertext */
        uint8_t chunk_tag[ROCK_TAG_SIZE];
        rock_mac_ctx_t chunk_mac;
        rock_mac_init(&chunk_mac, keys.k_mac);
        rock_mac_update(&chunk_mac, chunk_meta, sizeof(chunk_meta));
        if (n > 0) {
            rock_mac_update(&chunk_mac, ct_buf, n);
        }
        rock_mac_final(&chunk_mac, chunk_tag);

        /* Write chunk frame: meta (13) + ciphertext (n) + tag (32) */
        if (fwrite(chunk_meta, 1, sizeof(chunk_meta), fout) != sizeof(chunk_meta) ||
            (n > 0 && fwrite(ct_buf, 1, n, fout) != n) ||
            fwrite(chunk_tag, 1, ROCK_TAG_SIZE, fout) != ROCK_TAG_SIZE) {
            rock_memzero(chunk_tag, sizeof(chunk_tag));
            rock_secure_free(in_buf, ROCK_CHUNK_SIZE);
            rock_secure_free(ct_buf, ROCK_CHUNK_SIZE);
            rock_core_clear(&core_ctx);
            rock_subkeys_clear(&keys);
            fclose(fin);
            fclose(fout);
            unlink(out_path);
            return ROCK_ERR_IO;
        }

        chunk_idx++;
        if (n == 0 && is_final) break;
    }

    rock_secure_free(in_buf, ROCK_CHUNK_SIZE);
    rock_secure_free(ct_buf, ROCK_CHUNK_SIZE);
    rock_core_clear(&core_ctx);
    rock_subkeys_clear(&keys);
    fclose(fin);
    fclose(fout);
    return ROCK_SUCCESS;
}

int rock_file_decrypt(const char *in_path, const char *out_path,
                      const void *secret, size_t secret_len, int is_passphrase,
                      const uint8_t *expected_aad, size_t aad_len) {
    if (!in_path || !out_path || !secret) return ROCK_ERR_NULL_PARAM;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) return ROCK_ERR_IO;

    rock_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), fin) != sizeof(hdr)) {
        fclose(fin);
        return ROCK_ERR_INVALID_LENGTH;
    }

    if (rock_ct_memcmp(hdr.magic, ROCK_MAGIC_BYTES, ROCK_MAGIC_LEN) != 0) {
        fclose(fin);
        return ROCK_ERR_INVALID_MAGIC;
    }
    if (hdr.version != ROCK_VERSION_1) {
        fclose(fin);
        return ROCK_ERR_UNSUPPORTED_VERSION;
    }
    if (hdr.cipher_suite != ROCK_SUITE_ROCKCORE) {
        fclose(fin);
        return ROCK_ERR_UNSUPPORTED_SUITE;
    }
    if (hdr.aad_len != (uint32_t)aad_len) {
        fclose(fin);
        return ROCK_ERR_AAD_MISMATCH;
    }

    /* Verify AAD if present */
    if (aad_len > 0) {
        uint8_t *aad_disk = (uint8_t *)malloc(aad_len);
        if (!aad_disk || fread(aad_disk, 1, aad_len, fin) != aad_len) {
            free(aad_disk);
            fclose(fin);
            return ROCK_ERR_IO;
        }
        if (rock_ct_memcmp(aad_disk, expected_aad, aad_len) != 0) {
            free(aad_disk);
            fclose(fin);
            return ROCK_ERR_AAD_MISMATCH;
        }
        free(aad_disk);
    }

    rock_subkeys_t keys;
    int ret = derive_keys_internal(secret, secret_len, is_passphrase, hdr.salt,
                                   hdr.mem_cost_kb, hdr.time_cost, &keys);
    if (ret != 0) {
        fclose(fin);
        return ret;
    }

    /* Verify Header MAC */
    ret = rock_mac_verify(keys.k_hdr, (const uint8_t *)&hdr, sizeof(hdr) - 32, hdr.header_mac);
    if (ret != 0) {
        rock_subkeys_clear(&keys);
        fclose(fin);
        return ROCK_ERR_HEADER_CORRUPTED;
    }

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        rock_subkeys_clear(&keys);
        fclose(fin);
        return ROCK_ERR_IO;
    }

    rock_core_ctx_t core_ctx;
    rock_core_expand_key(&core_ctx, keys.k_enc);

    uint8_t *ct_buf = (uint8_t *)rock_secure_alloc(ROCK_CHUNK_SIZE);
    uint8_t *pt_buf = (uint8_t *)rock_secure_alloc(ROCK_CHUNK_SIZE);
    uint64_t expected_chunk_idx = 0;
    uint64_t stream_block_counter = 0;

    int finished = 0;
    while (!finished) {
        uint8_t chunk_meta[13];
        size_t r = fread(chunk_meta, 1, sizeof(chunk_meta), fin);
        if (r == 0) break;
        if (r != sizeof(chunk_meta)) {
            ret = ROCK_ERR_STREAM_CORRUPTED;
            break;
        }

        uint32_t chunk_len = load32_le(chunk_meta);
        uint8_t is_final = chunk_meta[4];
        uint64_t chunk_idx = load64_le(chunk_meta + 5);

        if (chunk_idx != expected_chunk_idx || chunk_len > ROCK_CHUNK_SIZE) {
            ret = ROCK_ERR_STREAM_CORRUPTED;
            break;
        }

        if (chunk_len > 0) {
            if (fread(ct_buf, 1, chunk_len, fin) != chunk_len) {
                ret = ROCK_ERR_IO;
                break;
            }
        }

        uint8_t read_tag[ROCK_TAG_SIZE];
        if (fread(read_tag, 1, ROCK_TAG_SIZE, fin) != ROCK_TAG_SIZE) {
            ret = ROCK_ERR_STREAM_CORRUPTED;
            break;
        }

        /* Verify Chunk MAC */
        uint8_t computed_tag[ROCK_TAG_SIZE];
        rock_mac_ctx_t chunk_mac;
        rock_mac_init(&chunk_mac, keys.k_mac);
        rock_mac_update(&chunk_mac, chunk_meta, sizeof(chunk_meta));
        if (chunk_len > 0) {
            rock_mac_update(&chunk_mac, ct_buf, chunk_len);
        }
        rock_mac_final(&chunk_mac, computed_tag);

        if (rock_ct_memcmp(computed_tag, read_tag, ROCK_TAG_SIZE) != 0) {
            rock_memzero(computed_tag, sizeof(computed_tag));
            ret = ROCK_ERR_AUTH_FAILED;
            break;
        }
        rock_memzero(computed_tag, sizeof(computed_tag));

        /* Authenticated: now safe to decrypt */
        if (chunk_len > 0) {
            apply_cipher_stream(&core_ctx, keys.k_white, hdr.nonce, stream_block_counter,
                                ct_buf, pt_buf, chunk_len);
            stream_block_counter += (chunk_len + 31) / 32;

            if (fwrite(pt_buf, 1, chunk_len, fout) != chunk_len) {
                ret = ROCK_ERR_IO;
                break;
            }
        }

        expected_chunk_idx++;
        if (is_final) {
            finished = 1;
        }
    }

    rock_secure_free(ct_buf, ROCK_CHUNK_SIZE);
    rock_secure_free(pt_buf, ROCK_CHUNK_SIZE);
    rock_core_clear(&core_ctx);
    rock_subkeys_clear(&keys);
    fclose(fin);
    fclose(fout);

    if (ret != 0 || !finished) {
        unlink(out_path); /* Fail-secure: wipe untrusted/corrupt partial file */
        return (ret != 0) ? ret : ROCK_ERR_STREAM_CORRUPTED;
    }

    return ROCK_SUCCESS;
}
