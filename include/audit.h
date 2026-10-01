/**
 * @file audit.h
 * @brief Cryptographic Security Auditing & Invariant Verification Framework.
 *
 * ============================================================================
 * CryptoVault Security Auditing & Invariant Verification Architecture
 * ============================================================================
 *
 * This subsystem provides automated security verification, memory leak detection,
 * constant-time side-channel checks, and integrity invariant monitoring across
 * the entire cryptographic runtime.
 *
 * AUDIT CAPABILITIES:
 * 1. Constant-Time Timing Invariant Verification:
 *    - Validates that cv_ct_memcmp() exhibits statistically indistinguishable
 *      execution timing distributions regardless of the byte offset of differing bits.
 *
 * 2. Secure Memory Leak & Canary Auditing:
 *    - Verifies that all allocated secure pages have intact canary boundaries and
 *      that zeroization effectively cleared the sensitive memory frame before freeing.
 *
 * 3. Comprehensive Zero-Trust Subsystem Health Checks:
 *    - Runs self-test diagnostic vectors across all 12 core cryptographic subsystems
 *      and reports a granular diagnostic status report.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef AUDIT_H
#define AUDIT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Subsystem Audit Bitmask Flags */
#define CV_AUDIT_MEM_OK       (1 << 0)
#define CV_AUDIT_ENTROPY_OK   (1 << 1)
#define CV_AUDIT_SPONGE_OK    (1 << 2)
#define CV_AUDIT_MATRIX_OK    (1 << 3)
#define CV_AUDIT_CORE_OK      (1 << 4)
#define CV_AUDIT_KDF_OK       (1 << 5)
#define CV_AUDIT_MAC_OK       (1 << 6)
#define CV_AUDIT_HKDF_OK      (1 << 7)
#define CV_AUDIT_HASH_OK      (1 << 8)
#define CV_AUDIT_KEYWRAP_OK   (1 << 9)
#define CV_AUDIT_ECDH_OK      (1 << 10)
#define CV_AUDIT_HYBRID_OK    (1 << 11)
#define CV_AUDIT_SHAMIR_OK    (1 << 12)
#define CV_AUDIT_ARMOR_OK     (1 << 13)
#define CV_AUDIT_PRNG_OK      (1 << 14)
#define CV_AUDIT_CERT_OK      (1 << 15)
#define CV_AUDIT_PACKAGE_OK   (1 << 16)
#define CV_AUDIT_DIFFIE_OK    (1 << 17)

/**
 * @brief Comprehensive audit report structure.
 */
typedef struct {
    uint32_t subsystem_status_mask;
    uint32_t total_subsystems_tested;
    uint32_t total_subsystems_passed;
    bool     constant_time_invariant_passed;
    bool     memory_canary_invariant_passed;
    double   shannon_entropy_rating;
    char     audit_summary[256];
} cv_audit_report_t;

/**
 * @brief Execute a full cryptographic invariant audit across all subsystems.
 *
 * @param report_out Output structure receiving detailed audit metrics.
 * @return 0 if all subsystems pass, negative error code if any invariant fails.
 */
int cv_audit_run_full(cv_audit_report_t *report_out);

/**
 * @brief Audit constant-time memory comparison behavior.
 * Compares execution cycles between first-byte mismatches and last-byte mismatches.
 *
 * @param trials Number of iterations for statistical sampling (e.g. 1000).
 * @return 0 on verified constant-time behavior, negative code on timing variance.
 */
int cv_audit_verify_constant_time(size_t trials);

/**
 * @brief Print a human-readable security audit report to standard output or log.
 *
 * @param report Pointer to completed audit report.
 */
void cv_audit_print_report(const cv_audit_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* AUDIT_H */
