/**
 * @file kdf.h
 * @brief 1 MiB Base Memory-Hard Key Derivation Function (KDF) Specification.
 *
 * ============================================================================
 * CryptoVault Memory-Hard Key Derivation Architecture (1 MiB Base)
 * ============================================================================
 *
 * This subsystem derives five cryptographically isolated subkeys from a user
 * passphrase or raw key material using a high-penalty memory-hard construction:
 *
 * ARCHITECTURAL DESIGN & ANTI-ASIC RATIONALE:
 * 1. 1 MiB Base RAM Scratchpad:
 *    - Default memory parameter: CV_DEFAULT_MEM_COST_KB = 1024 KiB (1 MiB).
 *    - Modern CPU cores typically have 32-64 KiB L1 and 512 KiB L2 caches.
 *      A 1024 KiB matrix deliberately overflows L1/L2 caches, forcing memory
 *      transfers across the DRAM bus.
 *    - For GPUs and ASICs, memory bandwidth is the primary bottleneck. Forcing
 *      1 MiB of locked memory per guess eliminates parallel hardware scaling.
 *
 * 2. Sequential & Non-Linear Memory Mixing:
 *    - Phase 1: Initialize 1 MiB state array using 512-bit sponge absorb-and-squeeze.
 *    - Phase 2: Pseudo-random non-linear lookup passes (time_cost passes):
 *      At step i, next index j is determined dynamically from the data itself:
 *      j = load64_le(M[i - 1]) % total_blocks;
 *      M[i] = SpongePermute(M[i] ^ M[j]);
 *      This creates strict sequential memory-hard dependency graphs.
 *
 * 3. Domain-Separated Cryptographic Subkeys:
 *    From the finalized memory state, 5 independent 256-bit subkeys are extracted:
 *    - k_enc:     Primary SP-ARX-256 block cipher key.
 *    - k_white:   Pre- and post-whitening key.
 *    - k_mac:     Payload & AAD authentication MAC key.
 *    - k_hdr:     Header envelope integrity MAC key.
 *    - k_cascade: Secondary 512-bit sponge stream cipher key.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef KDF_H
#define KDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory & Time Hardness Defaults */
#define CV_DEFAULT_MEM_COST_KB 1024 /* 1 MiB base memory cost */
#define CV_MIN_MEM_COST_KB     64   /* Minimum supported RAM cost */
#define CV_MAX_MEM_COST_KB     65536/* Maximum supported RAM cost (64 MiB) */
#define CV_DEFAULT_TIME_COST   4    /* 4 sequential memory mixing passes */
#define CV_MIN_TIME_COST       1
#define CV_MAX_TIME_COST       64

/* Subkey Array Lengths */
#define CV_SUBKEY_SIZE_BYTES   32

/* Return Status Codes */
#define CV_KDF_SUCCESS          0
#define CV_KDF_ERR_INVALID_PARAM -1
#define CV_KDF_ERR_OUT_OF_MEMORY -2
#define CV_KDF_ERR_SELF_TEST    -3

/**
 * @brief Isolated domain-separated subkeys derived from the master secret.
 */
typedef struct {
    uint8_t k_enc[CV_SUBKEY_SIZE_BYTES];     /* Primary SP-ARX-256 cipher key */
    uint8_t k_white[CV_SUBKEY_SIZE_BYTES];   /* Pre- and post-whitening key */
    uint8_t k_mac[CV_SUBKEY_SIZE_BYTES];     /* Payload & AAD authentication MAC key */
    uint8_t k_hdr[CV_SUBKEY_SIZE_BYTES];     /* Header envelope integrity MAC key */
    uint8_t k_cascade[CV_SUBKEY_SIZE_BYTES]; /* Cascaded secondary sponge cipher stream key */
} cv_subkeys_t;

/**
 * @brief Derive isolated subkeys using 1 MiB base memory-hard processing.
 *
 * @param password      Input secret (passphrase or key bytes).
 * @param pass_len      Length of input secret.
 * @param salt          256-bit cryptographic salt (32 bytes).
 * @param mem_cost_kb   RAM scratchpad in Kilobytes (default: 1024 for 1 MiB).
 * @param time_cost     Number of sequential mixing passes (default: 4).
 * @param keys_out      Output structure receiving the 5 domain-separated subkeys.
 * @return 0 on success, negative error code on failure.
 */
int cv_kdf_derive(const void *password, size_t pass_len,
                  const uint8_t salt[32],
                  uint32_t mem_cost_kb, uint32_t time_cost,
                  cv_subkeys_t *keys_out);

/**
 * @brief Securely wipe subkeys structure from memory.
 *
 * @param keys Pointer to subkeys structure to erase.
 */
void cv_subkeys_clear(cv_subkeys_t *keys);

/**
 * @brief Execute Known-Answer Test and sanity check on the KDF engine.
 *
 * @return 0 on success, negative error code on failure.
 */
int cv_kdf_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* KDF_H */
