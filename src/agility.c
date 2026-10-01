/**
 * @file agility.c
 * @brief Implementation of Cryptographic Algorithm Agility & Cipher Suite Dispatch.
 *
 * ============================================================================
 * CryptoVault Algorithm Agility & Suite Management
 * ============================================================================
 *
 * Provides a standardized registry for cryptographic suites, strict validation
 * against downgrade attacks, capability discovery, and runtime self-tests.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "agility.h"
#include <string.h>

/* Formal Static Cipher Suite Registry */
static const cv_cipher_suite_desc_t SUITE_REGISTRY[] = {
    {
        .suite_id          = CV_SUITE_SPARX256_SPONGE,
        .name              = "SP-ARX-256 + 512-bit Sponge Duplex (Standard Academic)",
        .kdf_algo          = "Argon2id + HKDF-SHA512",
        .enc_algo          = "SP-ARX-256-CTR (Key-Dependent Permutation)",
        .mac_algo          = "Sponge-512 Duplex Authenticator",
        .min_version       = 1,
        .security_bits     = 256,
        .pq_security_bits  = 0,
        .capability_flags  = CV_SUITE_CAP_AEAD | CV_SUITE_CAP_STREAMING |
                             CV_SUITE_CAP_MERKLE | CV_SUITE_CAP_KEYWRAP,
        .is_deprecated     = false,
        .is_default        = true
    },
    {
        .suite_id          = CV_SUITE_HYBRID_PQC_SPARX,
        .name              = "Hybrid X25519 + Lattice-LWE Post-Quantum + SP-ARX-256",
        .kdf_algo          = "Dual-KDF HKDF-Tree Combiner",
        .enc_algo          = "SP-ARX-256-CTR Cascaded",
        .mac_algo          = "Sponge-512 Duplex Authenticator",
        .min_version       = 2,
        .security_bits     = 256,
        .pq_security_bits  = 128,
        .capability_flags  = CV_SUITE_CAP_AEAD | CV_SUITE_CAP_PQC |
                             CV_SUITE_CAP_STREAMING | CV_SUITE_CAP_MERKLE |
                             CV_SUITE_CAP_KEYWRAP,
        .is_deprecated     = false,
        .is_default        = false
    },
    {
        .suite_id          = CV_SUITE_HIGH_THROUGHPUT,
        .name              = "Parallel ARX-256 + Pipelined Sponge Digest",
        .kdf_algo          = "HKDF-SHA512 Fast Ratchet",
        .enc_algo          = "ARX-256-CTR Multi-Core",
        .mac_algo          = "Sponge-256 Fast Duplex",
        .min_version       = 2,
        .security_bits     = 256,
        .pq_security_bits  = 0,
        .capability_flags  = CV_SUITE_CAP_AEAD | CV_SUITE_CAP_STREAMING |
                             CV_SUITE_CAP_MERKLE,
        .is_deprecated     = false,
        .is_default        = false
    }
};

static const size_t SUITE_REGISTRY_COUNT = sizeof(SUITE_REGISTRY) / sizeof(SUITE_REGISTRY[0]);

int cv_agility_get_descriptor(uint16_t suite_id, cv_cipher_suite_desc_t *desc_out) {
    if (!desc_out) {
        return CV_AGILITY_ERR_PARAM;
    }

    for (size_t i = 0; i < SUITE_REGISTRY_COUNT; i++) {
        if (SUITE_REGISTRY[i].suite_id == suite_id) {
            *desc_out = SUITE_REGISTRY[i];
            return CV_AGILITY_SUCCESS;
        }
    }

    return CV_AGILITY_ERR_UNKNOWN;
}

int cv_agility_validate_suite(uint16_t suite_id, uint32_t min_allowed_bits) {
    cv_cipher_suite_desc_t desc;
    int ret = cv_agility_get_descriptor(suite_id, &desc);
    if (ret != CV_AGILITY_SUCCESS) {
        return ret;
    }

    /* Anti-Downgrade: Refuse deprecated suites in strict mode */
    if (desc.is_deprecated) {
        return CV_AGILITY_ERR_DOWNGRADE;
    }

    /* Verify security parameter meets or exceeds minimum required bits */
    if (desc.security_bits < min_allowed_bits) {
        return CV_AGILITY_ERR_INSECURE;
    }

    return CV_AGILITY_SUCCESS;
}

size_t cv_agility_get_suite_count(void) {
    return SUITE_REGISTRY_COUNT;
}

int cv_agility_get_at_index(size_t index, cv_cipher_suite_desc_t *desc_out) {
    if (!desc_out || index >= SUITE_REGISTRY_COUNT) {
        return CV_AGILITY_ERR_PARAM;
    }

    *desc_out = SUITE_REGISTRY[index];
    return CV_AGILITY_SUCCESS;
}

int cv_agility_has_capability(uint16_t suite_id, uint32_t capability_flag) {
    cv_cipher_suite_desc_t desc;
    int ret = cv_agility_get_descriptor(suite_id, &desc);
    if (ret != CV_AGILITY_SUCCESS) {
        return 0;
    }

    return (desc.capability_flags & capability_flag) ? 1 : 0;
}

int cv_agility_self_test(void) {
    /* 1. Verify default suite is present and valid */
    cv_cipher_suite_desc_t def_desc;
    int ret = cv_agility_get_descriptor(CV_SUITE_SPARX256_SPONGE, &def_desc);
    if (ret != CV_AGILITY_SUCCESS) {
        return CV_AGILITY_ERR_SELFTEST;
    }
    if (!def_desc.is_default || def_desc.security_bits < 256) {
        return CV_AGILITY_ERR_SELFTEST;
    }

    /* 2. Verify hybrid post-quantum suite has PQC capability */
    if (!cv_agility_has_capability(CV_SUITE_HYBRID_PQC_SPARX, CV_SUITE_CAP_PQC)) {
        return CV_AGILITY_ERR_SELFTEST;
    }

    /* 3. Verify anti-downgrade logic triggers when security threshold is unmet */
    if (cv_agility_validate_suite(CV_SUITE_SPARX256_SPONGE, 512) != CV_AGILITY_ERR_INSECURE) {
        return CV_AGILITY_ERR_SELFTEST;
    }

    /* 4. Verify rejection of unknown cipher suite ID */
    if (cv_agility_get_descriptor(0xDEAD, &def_desc) != CV_AGILITY_ERR_UNKNOWN) {
        return CV_AGILITY_ERR_SELFTEST;
    }

    /* 5. Verify index enumeration covers all items */
    for (size_t i = 0; i < SUITE_REGISTRY_COUNT; i++) {
        cv_cipher_suite_desc_t item;
        if (cv_agility_get_at_index(i, &item) != CV_AGILITY_SUCCESS) {
            return CV_AGILITY_ERR_SELFTEST;
        }
    }

    return CV_AGILITY_SUCCESS;
}
