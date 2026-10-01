/**
 * @file multikey.h
 * @brief Multi-Key Decryption, Dual-Authority Quorum & Recovery Key Management.
 *
 * ============================================================================
 * CryptoVault Multi-Party & Multi-Key Authorization Architecture
 * ============================================================================
 *
 * This subsystem implements multi-party key encapsulation mechanisms for:
 * 1. Dual-Key (2-of-2) Mandatory Joint Authorization: Requires two independent
 *    passphrases or keys (e.g. Corporate Officer + Independent Auditor) to unlock
 *    the encrypted document.
 * 2. Multi-Recipient Key Bags: Encapsulates a single random file session key under
 *    up to 16 independent recipient keys or offline recovery keys.
 * 3. Emergency Break-Glass Recovery: Supports offline recovery keys stored in
 *    physical air-gapped safes without compromising forward secrecy.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef MULTIKEY_H
#define MULTIKEY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_MULTIKEY_MAGIC        "CVMK0200"
#define CV_MULTIKEY_MAGIC_LEN    8
#define CV_MULTIKEY_MAX_SLOTS    16
#define CV_MULTIKEY_KEY_SIZE     32
#define CV_MULTIKEY_WRAPPED_SIZE 40

/* Return Status Codes */
#define CV_MK_SUCCESS            0
#define CV_MK_ERR_PARAM         -1
#define CV_MK_ERR_AUTH          -2
#define CV_MK_ERR_NOT_FOUND     -3
#define CV_MK_ERR_SLOT_FULL     -4
#define CV_MK_ERR_ALLOC         -5
#define CV_MK_ERR_SELFTEST      -6

/**
 * @brief Recipient Key Slot in Multi-Key Bag.
 */
typedef struct __attribute__((packed)) {
    uint8_t  key_id[8];                          /* First 8 bytes of SHA-3 digest of KEK */
    uint8_t  wrapped_session_key[CV_MULTIKEY_WRAPPED_SIZE]; /* KeyWrap(KEK, K_session) */
} cv_key_slot_t;

/**
 * @brief Multi-Key Header Header containing encapsulated session keys.
 */
typedef struct __attribute__((packed)) {
    uint8_t       magic[CV_MULTIKEY_MAGIC_LEN];  /* "CVMK0200" */
    uint16_t      version;                       /* 0x0200 */
    uint16_t      num_slots;                     /* Number of populated slots */
    uint32_t      flags;                         /* 0x01: Dual-Auth, 0x02: Any-Recipient */
    cv_key_slot_t slots[CV_MULTIKEY_MAX_SLOTS];  /* Up to 16 key slots */
    uint8_t       header_mac[32];                /* Authenticity tag over header */
} cv_multikey_header_t;

/**
 * @brief Encrypt a file buffer requiring DUAL authorization (2 independent keys).
 * Neither key alone can decrypt the file.
 *
 * @param plaintext    Input plaintext data.
 * @param pt_len       Length of plaintext.
 * @param key1         First 32-byte key (e.g. Officer).
 * @param key2         Second 32-byte key (e.g. Auditor).
 * @param out_buf      Receives allocated multi-key encrypted container.
 * @param out_len      Receives total length of container.
 * @return CV_MK_SUCCESS on success, negative error code on failure.
 */
int cv_multikey_encrypt_dual(const uint8_t *plaintext, size_t pt_len,
                             const uint8_t key1[CV_MULTIKEY_KEY_SIZE],
                             const uint8_t key2[CV_MULTIKEY_KEY_SIZE],
                             uint8_t **out_buf, size_t *out_len);

/**
 * @brief Decrypt a dual-authorized container. Requires BOTH keys.
 *
 * @param container    Encrypted container.
 * @param cont_len     Length of container.
 * @param key1         First 32-byte key.
 * @param key2         Second 32-byte key.
 * @param out_pt       Receives allocated decrypted plaintext.
 * @param out_pt_len   Receives decrypted length.
 * @return CV_MK_SUCCESS on success, CV_MK_ERR_AUTH on invalid key or tampering.
 */
int cv_multikey_decrypt_dual(const uint8_t *container, size_t cont_len,
                             const uint8_t key1[CV_MULTIKEY_KEY_SIZE],
                             const uint8_t key2[CV_MULTIKEY_KEY_SIZE],
                             uint8_t **out_pt, size_t *out_pt_len);

/**
 * @brief Encapsulate a file session key for MULTIPLE independent recipients.
 * Any single authorized recipient (or recovery key) can unlock the document.
 *
 * @param plaintext        Input plaintext.
 * @param pt_len           Length of plaintext.
 * @param recipient_keys   Array of 32-byte KEKs for authorized recipients.
 * @param num_recipients   Count of recipients [1, 16].
 * @param out_buf          Receives allocated multi-recipient container.
 * @param out_len          Receives total length.
 * @return CV_MK_SUCCESS on success, negative error code on failure.
 */
int cv_multikey_encrypt_multi_recipient(const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t (*recipient_keys)[CV_MULTIKEY_KEY_SIZE],
                                        size_t num_recipients,
                                        uint8_t **out_buf, size_t *out_len);

/**
 * @brief Decrypt a multi-recipient container using ANY ONE valid recipient key.
 *
 * @param container     Encrypted multi-recipient container.
 * @param cont_len      Total length.
 * @param recipient_key 32-byte candidate key of the recipient.
 * @param out_pt        Receives allocated decrypted plaintext.
 * @param out_pt_len    Receives decrypted length.
 * @return CV_MK_SUCCESS on success, CV_MK_ERR_NOT_FOUND if key not in bag.
 */
int cv_multikey_decrypt_recipient(const uint8_t *container, size_t cont_len,
                                  const uint8_t recipient_key[CV_MULTIKEY_KEY_SIZE],
                                  uint8_t **out_pt, size_t *out_pt_len);

/**
 * @brief Self-test verifying dual-authorization and multi-recipient encapsulation.
 *
 * @return CV_MK_SUCCESS on success, negative code on failure.
 */
int cv_multikey_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* MULTIKEY_H */
