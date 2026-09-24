#define _GNU_SOURCE
#include "rock_entropy.h"
#include "rock_mem.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <x86intrin.h>
#endif

static uint64_t get_system_jitter(void) {
    uint64_t jitter = 0;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    jitter ^= __rdtsc();
#endif
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        jitter ^= ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec;
    }
    return jitter;
}

int rock_entropy_get(void *buf, size_t len) {
    if (!buf || len == 0) return -1;
    uint8_t *out = (uint8_t *)buf;
    size_t total = 0;

    /* 1. Try getrandom(2) */
    while (total < len) {
        ssize_t ret = getrandom(out + total, len - total, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break; /* Fall back to /dev/urandom */
        }
        total += (size_t)ret;
    }

    /* 2. Fallback to /dev/urandom if needed */
    if (total < len) {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -2;

        while (total < len) {
            ssize_t ret = read(fd, out + total, len - total);
            if (ret < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -3;
            }
            if (ret == 0) {
                close(fd);
                return -4;
            }
            total += (size_t)ret;
        }
        close(fd);
    }

    /* 3. Defense-in-depth: mix auxiliary jitter entropy */
    for (size_t i = 0; i < len; i++) {
        uint64_t jitter = get_system_jitter();
        out[i] ^= (uint8_t)(jitter ^ (jitter >> 13) ^ (jitter >> 29));
    }

    /* Zero-trust check: verify that entropy output is not stuck all-zero */
    uint8_t all_zero = 0;
    for (size_t i = 0; i < len; i++) {
        all_zero |= out[i];
    }
    if (all_zero == 0) {
        rock_memzero(buf, len);
        return -5;
    }

    return 0;
}

int rock_nonce_generate(uint8_t nonce[ROCK_NONCE_SIZE]) {
    return rock_entropy_get(nonce, ROCK_NONCE_SIZE);
}

int rock_salt_generate(uint8_t salt[ROCK_SALT_SIZE]) {
    return rock_entropy_get(salt, ROCK_SALT_SIZE);
}
