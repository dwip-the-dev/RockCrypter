/**
 * @file hybrid.h
 * @brief Asymmetric Hybrid Public-Key Encryption (HPKE) Container Architecture.
 *
 * ============================================================================
 * CryptoVault Hybrid Public-Key Cryptosystem (X25519 + SP-ARX KW + AEAD)
 * ============================================================================
 *
 * This subsystem implements asynchronous, public-key hybrid authenticated
 * encryption, enabling Alice to encrypt files directly for Bob using only Bob's
 * public identity key, with zero pre-shared secret:
 *
 * END-TO-END CRYPTOGRAPHIC PROTOCOL:
 * 1. Sender (Alice) Protocol:
 *    a) Ephemeral Key Generation:
 *       Alice samples a fresh, high-entropy ephemeral X25519 keypair (e_priv, e_pub).
 *    b) Diffie-Hellman Key Exchange:
 *       Alice computes raw shared secret: S = e_priv * Bob_pub.
 *    c) Key Encapsulation (HKDF):
 *       Alice derives a 256-bit Key-Encrypting Key (KEK) using HKDF-Extract and Expand:
 *       KEK = HKDF(salt = (e_pub || Bob_pub), IKM = S, info = "CRYPTOVAULT_HPKE_KEK").
 *    d) Session Key Generation & Wrapping:
 *       Alice generates a cryptographically uniform 256-bit session key K_session.
 *       Alice wraps K_session under KEK using SP-ARX Key Wrap -> C_key (40 bytes).
 *    e) Data Encryption:
 *       Alice encrypts the payload using K_session via cascaded AEAD or 1 MiB chunked stream.
 *    f) Header Output:
 *       Header = [ "CVHYB100" (8B) | e_pub (32B) | C_key (40B) ] (80 bytes total).
 *
 * 2. Recipient (Bob) Protocol:
 *    a) Bob extracts e_pub and wrapped session key C_key from envelope header.
 *    b) Bob computes S = Bob_priv * e_pub.
 *    c) Bob derives identical KEK via HKDF.
 *    d) Bob unwraps C_key using SP-ARX Key Unwrap -> recovers K_session.
 *    e) Bob decrypts and authenticates payload with K_session.
 *
 * 3. Forward Secrecy & Compromise Isolation:
 *    - Each hybrid envelope uses a unique ephemeral keypair. Even if Alice's
 *      long-term keys were later analyzed, past ephemeral exchanges remain secure.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef HYBRID_H
#define HYBRID_H

#include "ecdh.h"
#include "aead.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hybrid Envelope Constants */
#define CV_HYBRID_MAGIC         "CVHYB100"
#define CV_HYBRID_MAGIC_LEN     8
#define CV_HYBRID_HEADER_SIZE   (CV_HYBRID_MAGIC_LEN + CV_ECDH_KEY_SIZE + 40) /* 80 bytes */

/* Return Status Codes */
#define CV_HYBRID_SUCCESS        0
#define CV_HYBRID_ERR_PARAM     -1
#define CV_HYBRID_ERR_KEYGEN    -2
#define CV_HYBRID_ERR_ECDH      -3
#define CV_HYBRID_ERR_WRAP      -4
#define CV_HYBRID_ERR_UNWRAP    -5
#define CV_HYBRID_ERR_MAGIC     -6
#define CV_HYBRID_ERR_IO        -7
#define CV_HYBRID_ERR_SELFTEST  -8

/**
 * @brief Packed 80-byte hybrid envelope header.
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[CV_HYBRID_MAGIC_LEN];     /* "CVHYB100" */
    uint8_t ephemeral_pub[CV_ECDH_KEY_SIZE];/* 32-byte Ephemeral Public Key */
    uint8_t wrapped_session_key[40];        /* 32-byte session key wrapped (40 bytes) */
} cv_hybrid_header_t;

/**
 * @brief Encrypt memory buffer for a recipient identified by their public key.
 *
 * @param recipient_pub  32-byte recipient public key.
 * @param plaintext      Plaintext bytes to encrypt.
 * @param pt_len         Length of plaintext in bytes.
 * @param aad            Optional authenticated metadata.
 * @param aad_len        Length of metadata.
 * @param out_buf        Receives allocated encrypted hybrid envelope buffer.
 * @param out_len        Receives total length of envelope.
 * @return 0 on success, negative error code on failure.
 */
int cv_hybrid_encrypt(const uint8_t recipient_pub[CV_ECDH_KEY_SIZE],
                      const uint8_t *plaintext, size_t pt_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t **out_buf, size_t *out_len);

/**
 * @brief Decrypt a hybrid envelope using recipient's private key.
 *
 * @param recipient_priv 32-byte recipient private key.
 * @param envelope       Hybrid envelope buffer.
 * @param env_len        Length of hybrid envelope.
 * @param expected_aad   Expected authenticated metadata.
 * @param aad_len        Length of expected metadata.
 * @param out_pt         Receives allocated decrypted plaintext buffer.
 * @param out_pt_len     Receives length of decrypted plaintext.
 * @return 0 on success, negative code on authentication or integrity failure.
 */
int cv_hybrid_decrypt(const uint8_t recipient_priv[CV_ECDH_KEY_SIZE],
                      const uint8_t *envelope, size_t env_len,
                      const uint8_t *expected_aad, size_t aad_len,
                      uint8_t **out_pt, size_t *out_pt_len);

/**
 * @brief Encrypt a file on disk for a recipient's public key using hybrid streaming.
 *
 * @param in_path        Path to source unencrypted file.
 * @param out_path       Path to destination encrypted hybrid file.
 * @param recipient_pub  Recipient's 32-byte public key.
 * @param aad            Optional authenticated metadata.
 * @param aad_len        Length of metadata.
 * @return 0 on success, negative error code on failure.
 */
int cv_hybrid_file_encrypt(const char *in_path, const char *out_path,
                           const uint8_t recipient_pub[CV_ECDH_KEY_SIZE],
                           const uint8_t *aad, size_t aad_len);

/**
 * @brief Decrypt a hybrid encrypted file using recipient's private key.
 *
 * @param in_path        Path to hybrid encrypted file.
 * @param out_path       Path to destination decrypted file.
 * @param recipient_priv Recipient's 32-byte private key.
 * @param expected_aad   Expected authenticated metadata.
 * @param aad_len        Length of expected metadata.
 * @return 0 on success, negative error code on failure.
 */
int cv_hybrid_file_decrypt(const char *in_path, const char *out_path,
                           const uint8_t recipient_priv[CV_ECDH_KEY_SIZE],
                           const uint8_t *expected_aad, size_t aad_len);

/**
 * @brief Self-test verification of hybrid public-key encryption roundtrip.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_hybrid_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_H */
