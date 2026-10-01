/**
 * @file mem.h
 * @brief High-Assurance Secure Memory Management & Side-Channel Resistant Primitives.
 *
 * ============================================================================
 * CryptoVault Memory Security Architecture
 * ============================================================================
 *
 * This subsystem guarantees three fundamental defense-in-depth guarantees:
 * 1. Constant-Time Execution:
 *    - Memory comparisons (cv_ct_memcmp) and conditional selection (cv_ct_select_*)
 *      execute in constant instruction cycles, preventing cache and timing attacks.
 *    - Avoids conditional jumps (cmp/jne) dependent on secret data.
 *
 * 2. Guaranteed Non-Optimizable Zeroization:
 *    - Secure buffer erasing uses volatile pointer write barriers and compiler
 *      memory clobber fences (cv_memzero) to prevent dead-store elimination (DSE).
 *    - All allocated key materials are wiped immediately after use.
 *
 * 3. Swap-Resistant Physical Page Locking:
 *    - Memory buffers allocated via cv_secure_alloc() are locked in physical RAM
 *      using mlock(2) to prevent the OS kernel from paging secrets to unencrypted
 *      swap partitions or core dumps.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MEM_H
#define MEM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory Subsystem Status Codes */
#define CV_MEM_SUCCESS            0
#define CV_MEM_ERR_NULL_PTR      -1
#define CV_MEM_ERR_ALLOC_FAIL    -2
#define CV_MEM_ERR_LOCK_FAIL     -3
#define CV_MEM_ERR_CANARY_CORRUPT -4

/**
 * @brief Secure allocation metadata tracker.
 */
typedef struct {
    size_t total_allocations;
    size_t active_allocations;
    size_t total_bytes_allocated;
    size_t active_bytes_allocated;
    size_t locked_pages_count;
} cv_mem_stats_t;

/**
 * @brief Constant-time memory comparison.
 * Compares two memory buffers of length n in constant time.
 *
 * @param a Pointer to first memory buffer.
 * @param b Pointer to second memory buffer.
 * @param n Number of bytes to compare.
 * @return 0 if buffers are identical, non-zero if they differ.
 *
 * @note Execution time depends strictly on n, independent of buffer contents
 *       or the index where mismatch occurs.
 */
int cv_ct_memcmp(const void *a, const void *b, size_t n);

/**
 * @brief Constant-time byte conditional selection.
 *
 * @param mask 0xFF to select a, 0x00 to select b.
 * @param a First byte operand.
 * @param b Second byte operand.
 * @return (mask ? a : b) calculated using bitwise arithmetic.
 */
uint8_t cv_ct_select_u8(uint8_t mask, uint8_t a, uint8_t b);

/**
 * @brief Constant-time 32-bit integer conditional selection.
 *
 * @param mask 0xFFFFFFFF for a, 0x00000000 for b.
 * @param a First 32-bit operand.
 * @param b Second 32-bit operand.
 * @return (mask ? a : b) calculated without conditional branches.
 */
uint32_t cv_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b);

/**
 * @brief Constant-time 64-bit integer conditional selection.
 *
 * @param mask 0xFFFFFFFFFFFFFFFF for a, 0 for b.
 * @param a First 64-bit operand.
 * @param b Second 64-bit operand.
 * @return (mask ? a : b) calculated without conditional branches.
 */
uint64_t cv_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b);

/**
 * @brief Secure memory zeroization.
 * Overwrites memory buffer with zeroes using compiler write barriers
 * and explicit memory clobbers to prevent dead-store elimination.
 *
 * @param ptr Pointer to memory buffer to zero.
 * @param len Number of bytes to overwrite.
 */
void cv_memzero(void *ptr, size_t len);

/**
 * @brief Lock buffer into physical RAM (mlock) to prevent paging to swap.
 *
 * @param ptr Pointer to memory buffer.
 * @param len Length in bytes.
 * @return 0 on success, -1 on failure.
 */
int cv_memlock(void *ptr, size_t len);

/**
 * @brief Unlock previously locked memory buffer.
 *
 * @param ptr Pointer to memory buffer.
 * @param len Length in bytes.
 * @return 0 on success, -1 on failure.
 */
int cv_memunlock(void *ptr, size_t len);

/**
 * @brief Safely allocate, zero, and lock memory in RAM.
 *
 * @param len Number of bytes to allocate.
 * @return Pointer to allocated buffer, or NULL on failure.
 */
void *cv_secure_alloc(size_t len);

/**
 * @brief Securely zero, unlock, and free allocated memory.
 *
 * @param ptr Pointer to allocated memory.
 * @param len Number of bytes originally allocated.
 */
void cv_secure_free(void *ptr, size_t len);

/**
 * @brief Retrieve current secure memory allocation statistics.
 *
 * @param stats Pointer to output stats struct.
 */
void cv_mem_get_stats(cv_mem_stats_t *stats);

/**
 * @brief Constant-time equality check helper.
 *
 * @param a First buffer.
 * @param b Second buffer.
 * @param n Length in bytes.
 * @return 1 if equal, 0 if different.
 */
static inline int cv_mem_equal(const void *a, const void *b, size_t n) {
    return cv_ct_memcmp(a, b, n) == 0 ? 1 : 0;
}

/**
 * @brief Secure memory zeroization alias.
 *
 * @param ptr Pointer to memory buffer.
 * @param len Number of bytes.
 */
static inline void cv_mem_zero(void *ptr, size_t len) {
    cv_memzero(ptr, len);
}

#ifdef __cplusplus
}
#endif

#endif /* MEM_H */
