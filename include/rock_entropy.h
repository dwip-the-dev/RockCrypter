#ifndef ROCK_ENTROPY_H
#define ROCK_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_NONCE_SIZE 24
#define ROCK_SALT_SIZE  32

/**
 * Harvest cryptographically secure random bytes from OS CSPRNG.
 * Uses getrandom(2) with fallback to /dev/urandom and auxiliary entropy mixing.
 * Returns 0 on success, negative on error.
 */
int rock_entropy_get(void *buf, size_t len);

/**
 * Generate a 192-bit (24-byte) cryptographic nonce.
 * Returns 0 on success, negative on error.
 */
int rock_nonce_generate(uint8_t nonce[ROCK_NONCE_SIZE]);

/**
 * Generate a 256-bit (32-byte) cryptographic salt.
 * Returns 0 on success, negative on error.
 */
int rock_salt_generate(uint8_t salt[ROCK_SALT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_ENTROPY_H */
