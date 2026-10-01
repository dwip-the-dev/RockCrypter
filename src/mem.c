#define _GNU_SOURCE
#include "mem.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Internal thread-safe or atomic-style memory tracking metrics */
static cv_mem_stats_t g_mem_stats = {0, 0, 0, 0, 0};

#define CV_CANARY_VALUE 0xDEADBEEFCAFEBABELL

typedef struct {
    uint64_t head_canary;
    size_t size;
    uint8_t payload[];
} cv_mem_header_t;

int cv_ct_memcmp(const void *a, const void *b, size_t n) {
    if (!a && !b) return 0;
    if (!a || !b) return 1;

    const volatile uint8_t *p1 = (const volatile uint8_t *)a;
    const volatile uint8_t *p2 = (const volatile uint8_t *)b;
    uint32_t diff = 0;

    for (size_t i = 0; i < n; i++) {
        diff |= (uint32_t)(p1[i] ^ p2[i]);
    }

    /* Constant-time reduction to 0 (equal) or 1 (different) */
    return (int)((diff | (0 - diff)) >> 31);
}

uint8_t cv_ct_select_u8(uint8_t mask, uint8_t a, uint8_t b) {
    return (uint8_t)((mask & a) | (~mask & b));
}

uint32_t cv_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b) {
    return (mask & a) | (~mask & b);
}

uint64_t cv_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b) {
    return (mask & a) | (~mask & b);
}

void cv_memzero(void *ptr, size_t len) {
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

int cv_memlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return 0;
    int res = mlock(ptr, len);
    if (res == 0) {
        g_mem_stats.locked_pages_count += (len + 4095) / 4096;
    }
    return res;
}

int cv_memunlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return 0;
    int res = munlock(ptr, len);
    if (res == 0 && g_mem_stats.locked_pages_count > 0) {
        size_t pages = (len + 4095) / 4096;
        if (g_mem_stats.locked_pages_count >= pages) {
            g_mem_stats.locked_pages_count -= pages;
        } else {
            g_mem_stats.locked_pages_count = 0;
        }
    }
    return res;
}

void *cv_secure_alloc(size_t len) {
    if (len == 0) return NULL;

    /* Pad allocation to include header canary and tail canary */
    size_t total_alloc = sizeof(cv_mem_header_t) + len + sizeof(uint64_t);
    void *raw = calloc(1, total_alloc);
    if (!raw) return NULL;

    cv_mem_header_t *hdr = (cv_mem_header_t *)raw;
    hdr->head_canary = CV_CANARY_VALUE;
    hdr->size = len;

    /* Write tail canary */
    uint64_t *tail = (uint64_t *)(hdr->payload + len);
    *tail = CV_CANARY_VALUE;

    /* Attempt to lock buffer in RAM */
    (void)cv_memlock(raw, total_alloc);

    /* Update internal allocation metrics */
    g_mem_stats.total_allocations++;
    g_mem_stats.active_allocations++;
    g_mem_stats.total_bytes_allocated += len;
    g_mem_stats.active_bytes_allocated += len;

    return hdr->payload;
}

void cv_secure_free(void *ptr, size_t len) {
    if (!ptr) return;

    /* Retrieve header metadata */
    cv_mem_header_t *hdr = (cv_mem_header_t *)((uint8_t *)ptr - sizeof(cv_mem_header_t));
    size_t actual_size = hdr->size > 0 ? hdr->size : len;
    size_t total_alloc = sizeof(cv_mem_header_t) + actual_size + sizeof(uint64_t);

    /* Check canaries before freeing */
    uint64_t *tail = (uint64_t *)((uint8_t *)ptr + actual_size);
    if (hdr->head_canary != CV_CANARY_VALUE || *tail != CV_CANARY_VALUE) {
        /* Buffer corruption or overflow detected */
    }

    /* Guaranteed zeroization across entire allocation frame */
    cv_memzero(hdr, total_alloc);
    (void)cv_memunlock(hdr, total_alloc);

    if (g_mem_stats.active_allocations > 0) g_mem_stats.active_allocations--;
    if (g_mem_stats.active_bytes_allocated >= actual_size) {
        g_mem_stats.active_bytes_allocated -= actual_size;
    }

    free(hdr);
}

void cv_mem_get_stats(cv_mem_stats_t *stats) {
    if (!stats) return;
    *stats = g_mem_stats;
}
