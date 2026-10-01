/**
 * @file vault.h
 * @brief Unified Master Library Interface & High-Level Vault Container API.
 *
 * ============================================================================
 * CryptoVault High-Level Cryptographic Storage Suite
 * ============================================================================
 *
 * This umbrella header consolidates all core primitives, authenticated AEAD
 * pipelines, streaming engines, and asymmetric key management modules into a
 * clean, cohesive public programming interface:
 *
 * MODULAR ARCHITECTURE OVERVIEW:
 * 1. Low-Level Primitives:
 *    - mem.h:         Constant-time comparisons, volatile zeroization, locked pages.
 *    - entropy.h:     getrandom(2) with hardware cycle jitter harvesting.
 *    - sponge.h:      512-bit wide-state permutation primitive (24 rounds).
 *    - matrix.h:      Galois Field GF(2^8) arithmetic & MDS maximum diffusion.
 *    - core.h:        32-round 256-bit SP-ARX symmetric block cipher.
 *
 * 2. Key Derivation & Hashing:
 *    - kdf.h:         1 MiB base memory-hard key derivation function.
 *    - mac.h:         Keyed duplex sponge message authentication code.
 *    - hkdf.h:        RFC 5869 Extract-and-Expand PRK/OKM derivation.
 *    - sponge_hash.h: 256-bit and 512-bit sponge cryptographic digests.
 *
 * 3. Symmetric AEAD & Streaming:
 *    - aead.h:        Cascaded dual-layer envelope container (.cvlt format).
 *    - stream.h:      1 MiB chunked streaming with ratcheted tamper-proof chaining.
 *
 * 4. Asymmetric & Multi-Party Key Management:
 *    - ecdh.h:        Curve25519 (X25519) Montgomery scalar multiplication.
 *    - keywrap.h:     NIST SP 800-38F / RFC 3394 SP-ARX Key Wrap engine.
 *    - hybrid.h:      Public-key hybrid authenticated encryption envelope.
 *    - shamir.h:      Information-theoretic (k, n) threshold secret sharing.
 *    - armoring.h:    RFC 4880 OpenPGP-style ASCII armoring with 24-bit CRC.
 *    - keyfile.h:     Encrypted keybags and armored identity export/import.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef VAULT_H
#define VAULT_H

#include "mem.h"
#include "entropy.h"
#include "sponge.h"
#include "matrix.h"
#include "core.h"
#include "kdf.h"
#include "mac.h"
#include "hkdf.h"
#include "sponge_hash.h"
#include "aead.h"
#include "stream.h"
#include "ecdh.h"
#include "keywrap.h"
#include "hybrid.h"
#include "shamir.h"
#include "armoring.h"
#include "keyfile.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Master Versioning Constants */
#define CRYPTOVAULT_VERSION_MAJOR 2
#define CRYPTOVAULT_VERSION_MINOR 4
#define CRYPTOVAULT_VERSION_PATCH 0
#define CRYPTOVAULT_VERSION_STRING "2.4.0"

/* High-Level Vault Container Flags */
#define CV_VAULT_FLAG_COMPRESS    (1 << 0)
#define CV_VAULT_FLAG_AUTHENTIC   (1 << 1)
#define CV_VAULT_FLAG_LOCKED_RAM  (1 << 2)
#define CV_VAULT_FLAG_SHRED_SRC   (1 << 3)

/**
 * @brief High-level vault session descriptor.
 */
typedef struct {
    uint32_t flags;
    uint32_t mem_cost_kb;
    uint32_t time_cost;
    uint8_t  session_id[16];
    bool     initialized;
} cv_vault_session_t;

/**
 * @brief Initialize a secure high-level vault session.
 *
 * @param session Pointer to session structure.
 * @param flags Configuration bitmask (e.g. CV_VAULT_FLAG_LOCKED_RAM).
 * @return 0 on success, negative error code on failure.
 */
int cv_vault_init(cv_vault_session_t *session, uint32_t flags);

/**
 * @brief Close and wipe a high-level vault session.
 *
 * @param session Pointer to session structure.
 */
void cv_vault_close(cv_vault_session_t *session);

/**
 * @brief Run full comprehensive self-test suite across all subsystems.
 *
 * @return 0 if all cryptographic primitives and protocols pass, error mask otherwise.
 */
int cv_vault_full_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_H */
