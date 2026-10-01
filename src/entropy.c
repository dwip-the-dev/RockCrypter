#define _GNU_SOURCE
#include "entropy.h"
#include "mem.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <x86intrin.h>
#endif

/* Runtime diagnostic metrics */
static cv_entropy_stats_t g_entropy_stats = {
    0, 0, 0, CV_ENTROPY_SOURCE_HYBRID, true
};

static uint64_t get_hardware_jitter(void) {
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

/**
 * Continuous health verification (FIPS 140-3 inspired).
 * Ensures entropy does not produce identical consecutive bytes or stuck patterns.
 */
static int verify_entropy_health(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return CV_ENTROPY_ERR_INVALID_PARAM;

    uint8_t all_zero = 0;
    uint8_t all_ones = 0xFF;
    size_t consecutive_repeats = 0;
    size_t max_repeats = 0;

    for (size_t i = 0; i < len; i++) {
        all_zero |= buf[i];
        all_ones &= buf[i];

        if (i > 0) {
            if (buf[i] == buf[i - 1]) {
                consecutive_repeats++;
                if (consecutive_repeats > max_repeats) {
                    max_repeats = consecutive_repeats;
                }
            } else {
                consecutive_repeats = 0;
            }
        }
    }

    /* Reject stuck states */
    if (all_zero == 0 || (all_ones == 0xFF && len > 4)) {
        return CV_ENTROPY_ERR_HEALTH_FAIL;
    }

    /* If more than 32 consecutive identical bytes appear, fail-secure */
    if (len >= 32 && max_repeats >= 31) {
        return CV_ENTROPY_ERR_HEALTH_FAIL;
    }

    return CV_ENTROPY_SUCCESS;
}

int cv_entropy_get(void *buf, size_t len) {
    if (!buf || len == 0) return CV_ENTROPY_ERR_INVALID_PARAM;
    uint8_t *out = (uint8_t *)buf;
    size_t total = 0;

    /* 1. Linux getrandom(2) syscall */
    while (total < len) {
        ssize_t ret = getrandom(out + total, len - total, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break; /* Fallback to /dev/urandom */
        }
        total += (size_t)ret;
    }

    /* 2. Fallback to /dev/urandom */
    if (total < len) {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return CV_ENTROPY_ERR_DEVICE_OPEN;

        while (total < len) {
            ssize_t ret = read(fd, out + total, len - total);
            if (ret < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return CV_ENTROPY_ERR_DEVICE_READ;
            }
            if (ret == 0) {
                close(fd);
                return CV_ENTROPY_ERR_EOF;
            }
            total += (size_t)ret;
        }
        close(fd);
    }

    /* 3. Defense-in-depth: mix auxiliary hardware timer jitter */
    for (size_t i = 0; i < len; i++) {
        uint64_t jitter = get_hardware_jitter();
        out[i] ^= (uint8_t)(jitter ^ (jitter >> 13) ^ (jitter >> 29));
    }

    /* 4. Health verification check */
    if (verify_entropy_health(out, len) != CV_ENTROPY_SUCCESS) {
        cv_memzero(buf, len);
        g_entropy_stats.health_check_failures++;
        return CV_ENTROPY_ERR_HEALTH_FAIL;
    }

    g_entropy_stats.total_bytes_harvested += len;
    g_entropy_stats.health_check_passes++;
    return CV_ENTROPY_SUCCESS;
}

void cv_nonce_generate(uint8_t nonce[CV_NONCE_SIZE_BYTES]) {
    (void)cv_entropy_get(nonce, CV_NONCE_SIZE_BYTES);
}

void cv_salt_generate(uint8_t salt[CV_SALT_SIZE_BYTES]) {
    (void)cv_entropy_get(salt, CV_SALT_SIZE_BYTES);
}

void cv_key_generate(uint8_t key[CV_KEY_SIZE_BYTES]) {
    (void)cv_entropy_get(key, CV_KEY_SIZE_BYTES);
}

int cv_entropy_self_test(void) {
    uint8_t test_buf[64];
    int res = cv_entropy_get(test_buf, sizeof(test_buf));
    if (res != CV_ENTROPY_SUCCESS) {
        return res;
    }

    /* Verify non-triviality */
    uint8_t dummy[64];
    memset(dummy, 0, sizeof(dummy));
    if (cv_ct_memcmp(test_buf, dummy, sizeof(test_buf)) == 0) {
        return CV_ENTROPY_ERR_HEALTH_FAIL;
    }

    cv_memzero(test_buf, sizeof(test_buf));
    return CV_ENTROPY_SUCCESS;
}

void cv_entropy_get_stats(cv_entropy_stats_t *stats) {
    if (!stats) return;
    *stats = g_entropy_stats;
}
