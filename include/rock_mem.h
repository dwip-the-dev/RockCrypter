#ifndef ROCK_MEM_H
#define ROCK_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Constant-time memory comparison.
 * Returns 0 if buffers are identical, non-zero if they differ.
 * Execution time does not depend on data contents or location of mismatch.
 */
int rock_ct_memcmp(const void *a, const void *b, size_t n);

/**
 * Constant-time byte conditional selection.
 * Returns (mask ? a : b) where mask is 0xFF for true, 0x00 for false.
 */
uint8_t rock_ct_select_u8(uint8_t mask, uint8_t a, uint8_t b);

/**
 * Constant-time 32-bit conditional selection.
 */
uint32_t rock_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b);

/**
 * Constant-time 64-bit conditional selection.
 */
uint64_t rock_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b);

/**
 * Secure memory zeroization.
 * Overwrites memory buffer with zeroes using compiler-barrier / explicit zeroing
 * to prevent dead-store elimination by optimizing compilers.
 */
void rock_memzero(void *ptr, size_t len);

/**
 * Attempt to lock memory into RAM (mlock) to prevent swapping to disk.
 * Returns 0 on success, -1 on failure.
 */
int rock_memlock(void *ptr, size_t len);

/**
 * Unlock previously locked memory.
 */
int rock_memunlock(void *ptr, size_t len);

/**
 * Safely allocate and zero memory.
 */
void *rock_secure_alloc(size_t len);

/**
 * Securely zero and free memory.
 */
void rock_secure_free(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_MEM_H */
