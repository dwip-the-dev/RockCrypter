#ifndef ROCK_AEAD_H
#define ROCK_AEAD_H

#include "rock_kdf.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_MAGIC_BYTES     "ROCKCRPT"
#define ROCK_MAGIC_LEN       8
#define ROCK_VERSION_1       0x0100
#define ROCK_SUITE_ROCKCORE  0x0001

#define ROCK_TAG_SIZE        32
#define ROCK_CHUNK_SIZE      (64 * 1024) /* 64 KB streaming chunks */

/* Status and Error Codes */
#define ROCK_SUCCESS                  0
#define ROCK_ERR_NULL_PARAM          -1
#define ROCK_ERR_INVALID_LENGTH      -2
#define ROCK_ERR_OUT_OF_MEMORY       -3
#define ROCK_ERR_ENTROPY_FAILED      -4
#define ROCK_ERR_INVALID_MAGIC       -10
#define ROCK_ERR_UNSUPPORTED_VERSION -11
#define ROCK_ERR_UNSUPPORTED_SUITE   -12
#define ROCK_ERR_HEADER_CORRUPTED    -13
#define ROCK_ERR_AUTH_FAILED         -14
#define ROCK_ERR_AAD_MISMATCH        -15
#define ROCK_ERR_IO                  -20
#define ROCK_ERR_STREAM_CORRUPTED    -21

typedef struct __attribute__((packed)) {
    uint8_t  magic[8];        /* "ROCKCRPT" */
    uint16_t version;         /* 0x0100 */
    uint16_t cipher_suite;    /* 0x0001 */
    uint32_t flags;           /* 0x0000 = single frame, 0x0001 = streaming chunks */
    uint32_t mem_cost_kb;     /* KDF memory parameter */
    uint32_t time_cost;       /* KDF iteration count */
    uint8_t  salt[32];        /* 256-bit KDF salt */
    uint8_t  nonce[24];       /* 192-bit Nonce */
    uint64_t payload_len;     /* Ciphertext payload length in bytes */
    uint32_t aad_len;         /* Associated Authenticated Data length */
    uint8_t  header_mac[32];  /* 256-bit integrity MAC of header metadata */
} rock_header_t;

#define ROCK_HEADER_SIZE (sizeof(rock_header_t))

/**
 * Encrypt plaintext buffer with zero-trust authenticated framing.
 * Output layout: [ rock_header_t ] [ AAD ] [ Ciphertext ] [ Tag (32 bytes) ]
 */
int rock_aead_encrypt(const uint8_t *plaintext, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      const void *secret, size_t secret_len,
                      int is_passphrase,
                      uint32_t mem_cost_kb, uint32_t time_cost,
                      uint8_t **out_buf, size_t *out_len);

/**
 * Decrypt and authenticate encrypted envelope buffer.
 * Fails securely without releasing plaintext if verification fails.
 */
int rock_aead_decrypt(const uint8_t *envelope, size_t env_len,
                      const uint8_t *expected_aad, size_t aad_len,
                      const void *secret, size_t secret_len,
                      int is_passphrase,
                      uint8_t **out_plaintext, size_t *out_pt_len);

/**
 * Encrypt file with authenticated streaming chunks.
 * Handles arbitrarily large files using fixed memory.
 */
int rock_file_encrypt(const char *in_path, const char *out_path,
                      const void *secret, size_t secret_len, int is_passphrase,
                      const uint8_t *aad, size_t aad_len,
                      uint32_t mem_cost_kb, uint32_t time_cost);

/**
 * Decrypt file with authenticated streaming chunks.
 * Aborts and securely deletes partial output on any corruption/tampering.
 */
int rock_file_decrypt(const char *in_path, const char *out_path,
                      const void *secret, size_t secret_len, int is_passphrase,
                      const uint8_t *expected_aad, size_t aad_len);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_AEAD_H */
