/**
 * @file agility.h
 * @brief Cryptographic Algorithm Agility & Cipher Suite Dispatch Framework.
 *
 * ============================================================================
 * CryptoVault Cryptographic Algorithm Agility Architecture
 * ============================================================================
 *
 * This subsystem decouples high-level storage and transport interfaces from
 * specific underlying cryptographic primitives:
 * 1. Cryptographic Agility: Allows future cipher suites (e.g. NIST Post-Quantum
 *    FIPS 203 ML-KEM / Kyber, alternative block ciphers, and hash functions)
 *    to be deployed without breaking file format compatibility.
 * 2. Anti-Downgrade Defense: Cipher suite identifiers are cryptographically bound
 *    inside the Tier-1 Header MAC, preventing adversaries from forcing the system
 *    into executing deprecated or weaker fallback primitives.
 * 3. Formal Cipher Suite Registry: Validates security parameters, memory costs,
 *    and cryptographic requirements before dispatching operations.
 * 4. Algorithm Dispatch Table: Provides function pointers and capability flags
 *    for dynamic dispatch of symmetric AEAD, asymmetric key exchange, and
 *    sponge-based hashing.
 *
 * Threat Model Considerations:
 * - Downgrade Attacks: Adversaries who modify headers to request legacy or
 *   weaker suites are detected by checking `min_allowed_bits` and verifying
 *   the header MAC with the negotiating session key.
 * - Algorithm Deprecation: Suites can be flagged as deprecated without removing
 *   their registry entries, allowing legacy read while forbidding new writes.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef AGILITY_H
#define AGILITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standardized Cipher Suite Identifiers */
#define CV_SUITE_SPARX256_SPONGE   0x0001 /* SP-ARX-256 (CTR) + 512-bit Sponge Duplex (Default) */
#define CV_SUITE_HYBRID_PQC_SPARX  0x0002 /* Classical X25519 + Post-Quantum Lattice KEM + SP-ARX */
#define CV_SUITE_HIGH_THROUGHPUT   0x0003 /* Hardware Accelerated ARX + Sponge Hash */

/* Return Status Codes */
#define CV_AGILITY_SUCCESS          0
#define CV_AGILITY_ERR_PARAM       -1
#define CV_AGILITY_ERR_UNKNOWN     -2
#define CV_AGILITY_ERR_DOWNGRADE   -3
#define CV_AGILITY_ERR_INSECURE    -4
#define CV_AGILITY_ERR_SELFTEST    -5

/* Capability Flags */
#define CV_SUITE_CAP_AEAD          (1U << 0)
#define CV_SUITE_CAP_PQC           (1U << 1)
#define CV_SUITE_CAP_STREAMING     (1U << 2)
#define CV_SUITE_CAP_MERKLE        (1U << 3)
#define CV_SUITE_CAP_KEYWRAP       (1U << 4)

/**
 * @brief Formal descriptor for a supported cipher suite.
 */
typedef struct {
    uint16_t suite_id;                           /* 16-bit suite identifier */
    const char *name;                            /* Human-readable name */
    const char *kdf_algo;                        /* Key derivation algorithm */
    const char *enc_algo;                        /* Symmetric encryption algorithm */
    const char *mac_algo;                        /* Integrity/authentication algorithm */
    uint16_t min_version;                        /* Minimum format version supporting this suite */
    uint32_t security_bits;                      /* Classical security level (e.g. 256) */
    uint32_t pq_security_bits;                   /* Post-quantum security level (0 if classical) */
    uint32_t capability_flags;                   /* Bitmask of CV_SUITE_CAP_* */
    bool     is_deprecated;                      /* 1 if flagged for deprecation */
    bool     is_default;                         /* 1 if default for new files */
} cv_cipher_suite_desc_t;

/**
 * @brief Retrieve descriptor for a specific cipher suite ID.
 *
 * @param suite_id 16-bit identifier.
 * @param desc_out Pointer to descriptor structure populated on success.
 * @return CV_AGILITY_SUCCESS on success, CV_AGILITY_ERR_UNKNOWN if unsupported.
 */
int cv_agility_get_descriptor(uint16_t suite_id, cv_cipher_suite_desc_t *desc_out);

/**
 * @brief Verify that a requested suite ID is permitted and not subject to downgrade.
 *
 * @param suite_id         Suite requested in header.
 * @param min_allowed_bits Minimum allowed classical security level (e.g. 128, 256).
 * @return CV_AGILITY_SUCCESS if valid, CV_AGILITY_ERR_DOWNGRADE if insecure.
 */
int cv_agility_validate_suite(uint16_t suite_id, uint32_t min_allowed_bits);

/**
 * @brief Return total number of registered cipher suites.
 *
 * @return Count of registered suites.
 */
size_t cv_agility_get_suite_count(void);

/**
 * @brief Retrieve descriptor at a given index in the registry.
 *
 * @param index Index from 0 to cv_agility_get_suite_count() - 1.
 * @param desc_out Pointer to descriptor structure populated on success.
 * @return CV_AGILITY_SUCCESS on success, CV_AGILITY_ERR_PARAM if index out of bounds.
 */
int cv_agility_get_at_index(size_t index, cv_cipher_suite_desc_t *desc_out);

/**
 * @brief Check if a cipher suite supports a given capability flag.
 *
 * @param suite_id 16-bit identifier.
 * @param capability_flag Flag such as CV_SUITE_CAP_PQC.
 * @return 1 if supported, 0 if not supported or suite unknown.
 */
int cv_agility_has_capability(uint16_t suite_id, uint32_t capability_flag);

/**
 * @brief Self-test verifying cipher suite dispatch, downgrade rejection, and metadata.
 *
 * @return CV_AGILITY_SUCCESS on success, negative code on failure.
 */
int cv_agility_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* AGILITY_H */
