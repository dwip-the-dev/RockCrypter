#include "diffie.h"
#include "mac.h"
#include "mem.h"
#include <string.h>

#define CV_DIFFIE_DOMAIN_INIT 0x48535F5452414E53ULL /* "HS_TRANS" */

int cv_handshake_init(cv_handshake_t *hs,
                      cv_role_t role,
                      const cv_ecdh_keypair_t *static_kp) {
    if (!hs || !static_kp) return CV_DIFFIE_ERR_PARAM;

    cv_memzero(hs, sizeof(*hs));
    hs->role = role;
    hs->state = CV_HS_STATE_INIT;
    memcpy(&hs->static_key, static_kp, sizeof(cv_ecdh_keypair_t));

    /* Initialize transcript sponge */
    cv_sponge_init(&hs->transcript_sponge, CV_DIFFIE_DOMAIN_INIT);

    /* Generate ephemeral keypair for this session */
    if (cv_ecdh_keygen(&hs->ephemeral_key) != 0) {
        return CV_DIFFIE_ERR_ECDH;
    }

    return CV_DIFFIE_SUCCESS;
}

int cv_handshake_write_msg1(cv_handshake_t *hs, uint8_t *msg_out, size_t out_len) {
    if (!hs || !msg_out || out_len < CV_ECDH_KEY_SIZE) return CV_DIFFIE_ERR_PARAM;
    if (hs->role != CV_ROLE_INITIATOR || hs->state != CV_HS_STATE_INIT) return CV_DIFFIE_ERR_STATE;

    /* Message 1: Ephemeral Public Key (e) */
    memcpy(msg_out, hs->ephemeral_key.pub, CV_ECDH_KEY_SIZE);

    /* Absorb into transcript */
    cv_sponge_absorb(&hs->transcript_sponge, hs->ephemeral_key.pub, CV_ECDH_KEY_SIZE);
    hs->state = CV_HS_STATE_MSG1_SENT;

    return CV_DIFFIE_SUCCESS;
}

int cv_handshake_respond_msg2(cv_handshake_t *hs,
                              const uint8_t *msg1_in,
                              uint8_t *msg2_out, size_t out_len) {
    if (!hs || !msg1_in || !msg2_out || out_len < (CV_ECDH_KEY_SIZE + 32)) {
        return CV_DIFFIE_ERR_PARAM;
    }
    if (hs->role != CV_ROLE_RESPONDER || hs->state != CV_HS_STATE_INIT) {
        return CV_DIFFIE_ERR_STATE;
    }

    /* Ingest Initiator's ephemeral public key */
    memcpy(hs->remote_ephemeral, msg1_in, CV_ECDH_KEY_SIZE);
    cv_sponge_absorb(&hs->transcript_sponge, hs->remote_ephemeral, CV_ECDH_KEY_SIZE);

    /* Compute DH(e, e) */
    uint8_t dh_ee[CV_ECDH_KEY_SIZE];
    if (cv_ecdh_compute_shared(hs->ephemeral_key.priv, hs->remote_ephemeral, dh_ee) != 0) {
        return CV_DIFFIE_ERR_ECDH;
    }
    cv_sponge_absorb(&hs->transcript_sponge, dh_ee, sizeof(dh_ee));
    cv_memzero(dh_ee, sizeof(dh_ee));

    /* Responder outputs Message 2: [ e_resp (32B) | auth_tag (32B) ] */
    memcpy(msg2_out, hs->ephemeral_key.pub, CV_ECDH_KEY_SIZE);
    cv_sponge_absorb(&hs->transcript_sponge, hs->ephemeral_key.pub, CV_ECDH_KEY_SIZE);

    /* Compute transcript authentication tag */
    uint8_t auth_tag[32];
    cv_sponge_squeeze(&hs->transcript_sponge, auth_tag, 32);
    memcpy(msg2_out + CV_ECDH_KEY_SIZE, auth_tag, 32);

    /* Derive directional session keys */
    cv_sponge_squeeze(&hs->transcript_sponge, hs->k_send, CV_SESSION_KEY_LEN);
    cv_sponge_squeeze(&hs->transcript_sponge, hs->k_recv, CV_SESSION_KEY_LEN);

    hs->state = CV_HS_STATE_COMPLETE;
    cv_memzero(auth_tag, sizeof(auth_tag));
    return CV_DIFFIE_SUCCESS;
}

int cv_handshake_finalize_initiator(cv_handshake_t *hs, const uint8_t *msg2_in) {
    if (!hs || !msg2_in) return CV_DIFFIE_ERR_PARAM;
    if (hs->role != CV_ROLE_INITIATOR || hs->state != CV_HS_STATE_MSG1_SENT) {
        return CV_DIFFIE_ERR_STATE;
    }

    /* Extract Responder's ephemeral public key */
    memcpy(hs->remote_ephemeral, msg2_in, CV_ECDH_KEY_SIZE);

    /* Compute DH(e, e) */
    uint8_t dh_ee[CV_ECDH_KEY_SIZE];
    if (cv_ecdh_compute_shared(hs->ephemeral_key.priv, hs->remote_ephemeral, dh_ee) != 0) {
        return CV_DIFFIE_ERR_ECDH;
    }
    cv_sponge_absorb(&hs->transcript_sponge, dh_ee, sizeof(dh_ee));
    cv_memzero(dh_ee, sizeof(dh_ee));

    /* Absorb Responder's ephemeral public key */
    cv_sponge_absorb(&hs->transcript_sponge, hs->remote_ephemeral, CV_ECDH_KEY_SIZE);

    /* Squeeze and verify expected authentication tag */
    uint8_t expected_tag[32];
    cv_sponge_squeeze(&hs->transcript_sponge, expected_tag, 32);

    if (cv_ct_memcmp(expected_tag, msg2_in + CV_ECDH_KEY_SIZE, 32) != 0) {
        hs->state = CV_HS_STATE_FAILED;
        cv_memzero(expected_tag, sizeof(expected_tag));
        return CV_DIFFIE_ERR_AUTH;
    }

    /* Derive matching directional session keys (inverted for initiator) */
    cv_sponge_squeeze(&hs->transcript_sponge, hs->k_recv, CV_SESSION_KEY_LEN);
    cv_sponge_squeeze(&hs->transcript_sponge, hs->k_send, CV_SESSION_KEY_LEN);

    hs->state = CV_HS_STATE_COMPLETE;
    cv_memzero(expected_tag, sizeof(expected_tag));
    return CV_DIFFIE_SUCCESS;
}

void cv_handshake_clear(cv_handshake_t *hs) {
    if (hs) {
        cv_ecdh_keypair_clear(&hs->static_key);
        cv_ecdh_keypair_clear(&hs->ephemeral_key);
        cv_sponge_clear(&hs->transcript_sponge);
        cv_memzero(hs, sizeof(*hs));
    }
}

int cv_handshake_self_test(void) {
    cv_ecdh_keypair_t alice_static;
    cv_ecdh_keypair_t bob_static;
    if (cv_ecdh_keygen(&alice_static) != 0 || cv_ecdh_keygen(&bob_static) != 0) {
        return CV_DIFFIE_ERR_SELFTEST;
    }

    cv_handshake_t alice_hs;
    cv_handshake_t bob_hs;
    if (cv_handshake_init(&alice_hs, CV_ROLE_INITIATOR, &alice_static) != 0 ||
        cv_handshake_init(&bob_hs, CV_ROLE_RESPONDER, &bob_static) != 0) {
        return CV_DIFFIE_ERR_SELFTEST;
    }

    /* Step 1: Alice writes Message 1 */
    uint8_t msg1[CV_ECDH_KEY_SIZE];
    if (cv_handshake_write_msg1(&alice_hs, msg1, sizeof(msg1)) != 0) {
        return CV_DIFFIE_ERR_SELFTEST;
    }

    /* Step 2: Bob responds with Message 2 */
    uint8_t msg2[CV_ECDH_KEY_SIZE + 32];
    if (cv_handshake_respond_msg2(&bob_hs, msg1, msg2, sizeof(msg2)) != 0) {
        return CV_DIFFIE_ERR_SELFTEST;
    }

    /* Step 3: Alice finalizes */
    if (cv_handshake_finalize_initiator(&alice_hs, msg2) != 0) {
        return CV_DIFFIE_ERR_SELFTEST;
    }

    /* Verify session keys match in inverted pairs: Alice.k_send == Bob.k_recv */
    int match_keys = (cv_ct_memcmp(alice_hs.k_send, bob_hs.k_recv, CV_SESSION_KEY_LEN) == 0) &&
                     (cv_ct_memcmp(alice_hs.k_recv, bob_hs.k_send, CV_SESSION_KEY_LEN) == 0);

    cv_handshake_clear(&alice_hs);
    cv_handshake_clear(&bob_hs);
    cv_ecdh_keypair_clear(&alice_static);
    cv_ecdh_keypair_clear(&bob_static);

    return match_keys ? CV_DIFFIE_SUCCESS : CV_DIFFIE_ERR_SELFTEST;
}
