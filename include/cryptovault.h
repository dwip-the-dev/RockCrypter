/**
 * @file cryptovault.h
 * @brief Master Umbrella Header for the CryptoVault Cryptographic Architecture.
 *
 * ============================================================================
 * CryptoVault: High-Assurance Zero-Trust Cryptographic Storage & Transport Suite
 * ============================================================================
 *
 * CryptoVault is an advanced, defense-in-depth cryptographic library designed
 * for academic research, high-assurance secure data storage, and zero-trust
 * encrypted file transmission over untrusted communication channels.
 *
 * ARCHITECTURAL PRINCIPLES:
 * 1. Cascaded Dual-Layer Symmetric Encryption:
 *    - Layer 1 (Inner): 32-round 256-bit SP-ARX Block Cipher in Counter Mode.
 *    - Layer 2 (Outer): 512-bit Wide Sponge Permutation Duplex Stream Cipher.
 *    - Both layers utilize independent, domain-separated cryptographic keys.
 *
 * 2. 1 MiB Base Memory-Hard Key Derivation (KDF):
 *    - Default memory footprint: 1024 KiB (1 MiB) matrix with non-linear mixing.
 *    - Designed to maximize ASIC and GPU memory bandwidth penalties.
 *    - Derives independent subkeys for encryption, whitening, MAC, header, cascade.
 *
 * 3. 1 MiB Base Chunked Streaming & Sponge Ratchet Authentication:
 *    - Stream encryption processes data in 1 MiB (1,048,576 byte) chunks.
 *    - Chunk tags are cryptographically chained in a forward-secure ratchet.
 *    - Tampering, truncation, reordering, or insertion immediately aborts with
 *      complete memory erasure and fail-secure deletion.
 *
 * 4. Asymmetric Public-Key Hybrid Encryption:
 *    - Curve25519 (X25519) Montgomery ladder scalar multiplication.
 *    - Ephemeral-Static Diffie-Hellman key encapsulation.
 *    - SP-ARX Key Wrap (NIST SP 800-38F / RFC 3394 inspired).
 *
 * 5. Threshold Secret Sharing:
 *    - Shamir's Secret Sharing over Galois Field GF(2^8).
 *    - Any k-of-n shares reconstruct the secret; k-1 shares yield zero information.
 *
 * 6. ASCII Armoring & Secure Packaging:
 *    - RFC 4880 OpenPGP-style Radix-64 encoding with 24-bit CRC error detection.
 *    - Self-contained packages (.cvpkg) for secure cross-network sharing.
 *
 * 7. Defensive Systems Engineering:
 *    - Constant-time arithmetic and memory comparisons (side-channel resistance).
 *    - Linux getrandom(2) kernel entropy with CPU jitter harvesting fallback.
 *    - Locked memory pages (mlock) to prevent swap leaks.
 *    - Hardware memory barriers and volatile writes for guaranteed key wiping.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Research Group
 * @license MIT Open-Source Academic License
 */

#ifndef CRYPTOVAULT_H
#define CRYPTOVAULT_H

#ifdef __cplusplus
extern "C" {
#endif

/* System Versioning Information */
#define CRYPTOVAULT_VERSION_MAJOR   2
#define CRYPTOVAULT_VERSION_MINOR   4
#define CRYPTOVAULT_VERSION_PATCH   0
#define CRYPTOVAULT_VERSION_STRING  "2.4.0"

/* Core Security & Architectural Parameters */
#define CV_SECURITY_BITS            256
#define CV_BLOCK_SIZE_BYTES         32
#define CV_KEY_SIZE_BYTES           32
#define CV_SPONGE_STATE_BYTES       64
#define CV_STREAM_CHUNK_SIZE_BYTES  1048576 /* 1 MiB base chunk size */
#define CV_KDF_BASE_MEM_COST_KB     1024    /* 1 MiB base memory hardness */

/* Modular Subsystem Headers */
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
#include "vault.h"

/**
 * @brief Global library initialization function.
 * Initializes secure memory subpools, validates entropy availability,
 * and performs self-test verification of all cryptographic primitives.
 *
 * @return 0 on success, negative error code on self-test failure.
 */
int cv_init(void);

/**
 * @brief Global library shutdown and cleanup function.
 * Flushes entropy pools and verifies that all registered secure memory
 * segments have been wiped cleanly.
 */
void cv_cleanup(void);

/**
 * @brief Returns the human-readable version string of CryptoVault.
 * @return Constant string pointer to "2.4.0".
 */
const char *cv_get_version(void);

/**
 * @brief Runs an exhaustive hardware & algorithmic self-test suite.
 * Tests SP-ARX block cipher KAT, Sponge hash KAT, X25519 scalarmult KAT,
 * Shamir GF(2^8) interpolation, and constant-time memory comparators.
 *
 * @return 0 if all tests pass, non-zero error mask if any test fails.
 */
int cv_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOVAULT_H */
