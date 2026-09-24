#define _GNU_SOURCE
#include "rock_mem.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int rock_ct_memcmp(const void *a, const void *b, size_t n) {
    const volatile uint8_t *p1 = (const volatile uint8_t *)a;
    const volatile uint8_t *p2 = (const volatile uint8_t *)b;
    uint32_t diff = 0;

    for (size_t i = 0; i < n; i++) {
        diff |= (uint32_t)(p1[i] ^ p2[i]);
    }

    /* Constant-time reduction to 0 (equal) or 1 (different) */
    return (int)((diff | (0 - diff)) >> 31);
}

uint8_t rock_ct_select_u8(uint8_t mask, uint8_t a, uint8_t b) {
    return (uint8_t)((mask & a) | (~mask & b));
}

uint32_t rock_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b) {
    return (mask & a) | (~mask & b);
}

uint64_t rock_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b) {
    return (mask & a) | (~mask & b);
}

void rock_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

int rock_memlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return 0;
    return mlock(ptr, len);
}

int rock_memunlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return 0;
    return munlock(ptr, len);
}

void *rock_secure_alloc(size_t len) {
    if (len == 0) return NULL;
    void *ptr = calloc(1, len);
    if (!ptr) return NULL;

    /* Best effort memory lock; non-fatal if unprivileged */
    (void)rock_memlock(ptr, len);
    return ptr;
}

void rock_secure_free(void *ptr, size_t len) {
    if (!ptr) return;
    rock_memzero(ptr, len);
    (void)rock_memunlock(ptr, len);
    free(ptr);
}
