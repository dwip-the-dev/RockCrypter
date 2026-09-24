#ifndef ROCK_KDF_H
#define ROCK_KDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROCK_SUBKEY_SIZE 32 /* 256 bits each */

typedef struct {
    uint8_t k_enc[ROCK_SUBKEY_SIZE];   /* Core encryption key */
    uint8_t k_white[ROCK_SUBKEY_SIZE]; /* Keystream dynamic whitening key */
    uint8_t k_mac[ROCK_SUBKEY_SIZE];   /* Authenticator MAC key */
    uint8_t k_hdr[ROCK_SUBKEY_SIZE];   /* Header protection key */
} rock_subkeys_t;

/**
 * Memory-hard, domain-separated key derivation function (RockKDF).
 *
 * @param password      User secret / passphrase / master key
 * @param pass_len      Length of password in bytes
 * @param salt          32-byte cryptographic salt
 * @param mem_cost_kb   Memory requirement in KB (e.g. 16384 for 16MB)
 * @param time_cost     Number of memory mixing passes (e.g. 3 or 4)
 * @param keys_out      Pointer to subkeys structure to populate
 * @return 0 on success, negative error code on failure.
 */
int rock_kdf_derive(const void *password, size_t pass_len,
                    const uint8_t salt[32],
                    uint32_t mem_cost_kb, uint32_t time_cost,
                    rock_subkeys_t *keys_out);

/**
 * Securely clear subkeys structure.
 */
void rock_subkeys_clear(rock_subkeys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* ROCK_KDF_H */
