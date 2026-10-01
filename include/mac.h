/**
 * @file mac.h
 * @brief Keyed Duplex Sponge Message Authentication Code (MAC) Specification.
 *
 * ============================================================================
 * CryptoVault Keyed Sponge Authentication Architecture
 * ============================================================================
 *
 * This subsystem computes and verifies cryptographic authentication tags using
 * a keyed duplex sponge construction over the 512-bit permutation primitive.
 *
 * CRYPTOGRAPHIC PROPERTIES:
 * 1. Length-Extension Attack Immunity:
 *    - Traditional hash-based MACs (e.g. naive Hash(Key || Message)) suffer from
 *      length-extension attacks due to the Merkle-Damgård iterative structure.
 *    - The sponge construction with a 256-bit hidden capacity provides provable
 *      immunity against length-extension attacks without requiring nested
 *      inner/outer hashing rounds like HMAC (RFC 2104).
 *
 * 2. Key Isolation & State Whitening:
 *    - Key material is absorbed into the sponge state with an explicit domain
 *      separation constant (0x415554484D414331ULL = "AUTHMAC1").
 *    - At finalization, the 64-bit total payload length is absorbed into the state
 *      before squeezing to prevent collision between prefixes of different lengths.
 *
 * 3. Constant-Time Tag Verification:
 *    - Verification compares the squeezed tag against the expected tag using
 *      cv_ct_memcmp() to prevent timing-based side-channel forgery attacks.
 *
 * 4. Multi-Part Streaming Interface:
 *    - Supports cv_mac_init, cv_mac_update, and cv_mac_final for large streams
 *      and incremental chunks without requiring all data in memory at once.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MAC_H
#define MAC_H

#include "sponge.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MAC Subsystem Parameters */
#define CV_MAC_KEY_SIZE     32 /* 256-bit authentication key */
#define CV_MAC_TAG_SIZE     32 /* 256-bit message authentication tag */

/* Return Status Codes */
#define CV_MAC_SUCCESS       0
#define CV_MAC_ERR_INVALID  -1
#define CV_MAC_ERR_FORGERY  -2
#define CV_MAC_ERR_SELFTEST -3

/**
 * @brief Streaming MAC execution context.
 */
typedef struct {
    cv_sponge_t sponge;
    uint64_t    total_bytes;
    int         finalized;
} cv_mac_ctx_t;

/**
 * @brief Initialize keyed duplex sponge MAC authenticator.
 *
 * @param ctx Pointer to MAC context to initialize.
 * @param key 32-byte secret authentication key.
 * @return 0 on success, negative error code on failure.
 */
int cv_mac_init(cv_mac_ctx_t *ctx, const uint8_t key[CV_MAC_KEY_SIZE]);

/**
 * @brief Absorb additional payload data into the ongoing MAC state.
 *
 * @param ctx Pointer to initialized MAC context.
 * @param data Input data buffer.
 * @param len Number of bytes to absorb.
 * @return 0 on success, negative error code on failure.
 */
int cv_mac_update(cv_mac_ctx_t *ctx, const void *data, size_t len);

/**
 * @brief Finalize and squeeze a 256-bit authentication tag.
 *
 * @param ctx Pointer to MAC context.
 * @param tag_out Destination buffer receiving the 32-byte MAC tag.
 * @return 0 on success, negative error code on failure.
 */
int cv_mac_final(cv_mac_ctx_t *ctx, uint8_t tag_out[CV_MAC_TAG_SIZE]);

/**
 * @brief One-shot MAC computation over an entire data buffer.
 *
 * @param key 32-byte secret authentication key.
 * @param data Input data buffer.
 * @param len Number of bytes.
 * @param tag_out Destination buffer receiving the 32-byte MAC tag.
 * @return 0 on success, negative error code on failure.
 */
int cv_mac_compute(const uint8_t key[CV_MAC_KEY_SIZE],
                   const void *data, size_t len,
                   uint8_t tag_out[CV_MAC_TAG_SIZE]);

/**
 * @brief Constant-time verification of authentication tag.
 *
 * @param key 32-byte secret authentication key.
 * @param data Input data buffer.
 * @param len Number of bytes.
 * @param expected_tag Expected 32-byte tag to match against.
 * @return 0 on valid tag, CV_MAC_ERR_FORGERY on mismatch.
 */
int cv_mac_verify(const uint8_t key[CV_MAC_KEY_SIZE],
                  const void *data, size_t len,
                  const uint8_t expected_tag[CV_MAC_TAG_SIZE]);

/**
 * @brief Execute Known-Answer Test and sanity checks on MAC subsystem.
 *
 * @return 0 on success, negative error code on failure.
 */
int cv_mac_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* MAC_H */
