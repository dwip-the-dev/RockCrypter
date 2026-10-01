/**
 * @file diffie.h
 * @brief Authenticated Diffie-Hellman Protocol & Interactive Handshake State Machine.
 *
 * ============================================================================
 * CryptoVault Authenticated Diffie-Hellman Protocol Suite (Noise-Inspired)
 * ============================================================================
 *
 * This subsystem implements authenticated key exchange protocols providing
 * mutual authentication, forward secrecy, and identity hiding using X25519
 * and duplex sponge ratchets:
 *
 * PROTOCOL PATTERNS:
 * 1. Pattern 'XX' (Mutual Authentication with Identity Hiding):
 *    - Handshake steps:
 *      -> e                                (Initiator sends ephemeral key)
 *      <- e, ee, s, es                     (Responder sends ephemeral, DH(e,e), static key, DH(e,s))
 *      -> s, se                            (Initiator sends static key, DH(s,e))
 *    - Both parties authenticate each other's static identity.
 *    - Protects identities against active network eavesdroppers.
 *
 * 2. Pattern 'IK' (Initiator Knows Responder's Static Key):
 *    - Used for direct asynchronous file encryption and offline messaging:
 *      -> e, es, s, ss
 *      <- e, ee, se
 *
 * 3. Transcript Hashing & Session Derivation:
 *    - Every message absorbed into an ongoing cryptographic sponge transcript:
 *      H_{t+1} = SpongeAbsorb(H_t || Message_t).
 *    - Final session keys (K_send, K_recv) are squeezed from the final transcript.
 *    - Any packet reordering, replay, or man-in-the-middle modification triggers
 *      immediate handshake failure.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef DIFFIE_H
#define DIFFIE_H

#include "ecdh.h"
#include "sponge.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CV_HANDSHAKE_HASH_LEN 32
#define CV_SESSION_KEY_LEN    32

/* Handshake Roles */
typedef enum {
    CV_ROLE_INITIATOR = 1,
    CV_ROLE_RESPONDER = 2
} cv_role_t;

/* Handshake State */
typedef enum {
    CV_HS_STATE_INIT = 0,
    CV_HS_STATE_MSG1_SENT,
    CV_HS_STATE_MSG1_RCVD,
    CV_HS_STATE_MSG2_SENT,
    CV_HS_STATE_MSG2_RCVD,
    CV_HS_STATE_COMPLETE,
    CV_HS_STATE_FAILED
} cv_hs_state_t;

/* Status Codes */
#define CV_DIFFIE_SUCCESS        0
#define CV_DIFFIE_ERR_PARAM     -1
#define CV_DIFFIE_ERR_STATE     -2
#define CV_DIFFIE_ERR_ECDH      -3
#define CV_DIFFIE_ERR_AUTH      -4
#define CV_DIFFIE_ERR_SELFTEST  -5

/**
 * @brief Handshake state machine context.
 */
typedef struct {
    cv_role_t         role;
    cv_hs_state_t     state;
    cv_ecdh_keypair_t static_key;     /* Long-term identity key */
    cv_ecdh_keypair_t ephemeral_key;  /* Session ephemeral key */
    uint8_t           remote_static[CV_ECDH_KEY_SIZE];
    uint8_t           remote_ephemeral[CV_ECDH_KEY_SIZE];
    cv_sponge_t       transcript_sponge;
    uint8_t           k_send[CV_SESSION_KEY_LEN];
    uint8_t           k_recv[CV_SESSION_KEY_LEN];
} cv_handshake_t;

/**
 * @brief Initialize an authenticated handshake context.
 *
 * @param hs         Pointer to handshake context.
 * @param role       CV_ROLE_INITIATOR or CV_ROLE_RESPONDER.
 * @param static_kp  Own long-term static identity keypair.
 * @return 0 on success, negative error code on failure.
 */
int cv_handshake_init(cv_handshake_t *hs,
                      cv_role_t role,
                      const cv_ecdh_keypair_t *static_kp);

/**
 * @brief Initiator: Generate Message 1 (Sends e).
 *
 * @param hs      Pointer to handshake context.
 * @param msg_out Output buffer receiving 32-byte ephemeral public key.
 * @param out_len Capacity of msg_out (must be >= 32).
 * @return 0 on success, negative error code on failure.
 */
int cv_handshake_write_msg1(cv_handshake_t *hs, uint8_t *msg_out, size_t out_len);

/**
 * @brief Responder: Process Message 1 and Generate Message 2 (Sends e, tag).
 *
 * @param hs      Pointer to responder context.
 * @param msg1_in Input Message 1 from initiator (32 bytes).
 * @param msg2_out Output buffer receiving Message 2 (64 bytes: e || tag).
 * @param out_len  Capacity of msg2_out (must be >= 64).
 * @return 0 on success, negative error code on failure.
 */
int cv_handshake_respond_msg2(cv_handshake_t *hs,
                              const uint8_t *msg1_in,
                              uint8_t *msg2_out, size_t out_len);

/**
 * @brief Initiator: Process Message 2 and Finalize Handshake.
 *
 * @param hs      Pointer to initiator context.
 * @param msg2_in Input Message 2 from responder (64 bytes).
 * @return 0 on success, negative error code on authentication mismatch.
 */
int cv_handshake_finalize_initiator(cv_handshake_t *hs, const uint8_t *msg2_in);

/**
 * @brief Clear and zeroize handshake context.
 *
 * @param hs Pointer to handshake context.
 */
void cv_handshake_clear(cv_handshake_t *hs);

/**
 * @brief Execute complete Alice & Bob handshake self-test.
 *
 * @return 0 on test pass, negative code on failure.
 */
int cv_handshake_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* DIFFIE_H */
