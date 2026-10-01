#include "vault.h"
#include "diffie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_diffie_handshake_roundtrip(void) {
    printf("[Diffie] Testing Authenticated Key Exchange Handshake State Machine... ");

    cv_ecdh_keypair_t alice_id;
    cv_ecdh_keypair_t bob_id;
    assert(cv_ecdh_keygen(&alice_id) == 0);
    assert(cv_ecdh_keygen(&bob_id) == 0);

    cv_handshake_t alice;
    cv_handshake_t bob;
    assert(cv_handshake_init(&alice, CV_ROLE_INITIATOR, &alice_id) == CV_DIFFIE_SUCCESS);
    assert(cv_handshake_init(&bob, CV_ROLE_RESPONDER, &bob_id) == CV_DIFFIE_SUCCESS);

    /* Step 1: Alice -> Bob (Msg1) */
    uint8_t msg1[CV_ECDH_KEY_SIZE];
    assert(cv_handshake_write_msg1(&alice, msg1, sizeof(msg1)) == CV_DIFFIE_SUCCESS);

    /* Step 2: Bob -> Alice (Msg2) */
    uint8_t msg2[CV_ECDH_KEY_SIZE + 32];
    assert(cv_handshake_respond_msg2(&bob, msg1, msg2, sizeof(msg2)) == CV_DIFFIE_SUCCESS);
    assert(bob.state == CV_HS_STATE_COMPLETE);

    /* Step 3: Alice processes Msg2 */
    assert(cv_handshake_finalize_initiator(&alice, msg2) == CV_DIFFIE_SUCCESS);
    assert(alice.state == CV_HS_STATE_COMPLETE);

    /* Verify derived directional session keys */
    assert(cv_ct_memcmp(alice.k_send, bob.k_recv, CV_SESSION_KEY_LEN) == 0);
    assert(cv_ct_memcmp(alice.k_recv, bob.k_send, CV_SESSION_KEY_LEN) == 0);

    /* Verify send and recv keys are independent */
    assert(cv_ct_memcmp(alice.k_send, alice.k_recv, CV_SESSION_KEY_LEN) != 0);

    cv_handshake_clear(&alice);
    cv_handshake_clear(&bob);
    cv_ecdh_keypair_clear(&alice_id);
    cv_ecdh_keypair_clear(&bob_id);

    printf("PASSED\n");
}

static void test_diffie_mitm_tamper_rejection(void) {
    printf("[Diffie] Testing Active Man-in-the-Middle Transcript Tamper Rejection... ");

    cv_ecdh_keypair_t alice_id;
    cv_ecdh_keypair_t bob_id;
    assert(cv_ecdh_keygen(&alice_id) == 0);
    assert(cv_ecdh_keygen(&bob_id) == 0);

    cv_handshake_t alice;
    cv_handshake_t bob;
    assert(cv_handshake_init(&alice, CV_ROLE_INITIATOR, &alice_id) == CV_DIFFIE_SUCCESS);
    assert(cv_handshake_init(&bob, CV_ROLE_RESPONDER, &bob_id) == CV_DIFFIE_SUCCESS);

    uint8_t msg1[CV_ECDH_KEY_SIZE];
    assert(cv_handshake_write_msg1(&alice, msg1, sizeof(msg1)) == CV_DIFFIE_SUCCESS);

    uint8_t msg2[CV_ECDH_KEY_SIZE + 32];
    assert(cv_handshake_respond_msg2(&bob, msg1, msg2, sizeof(msg2)) == CV_DIFFIE_SUCCESS);

    /* Active attacker corrupts 1 bit in Message 2 auth tag */
    msg2[CV_ECDH_KEY_SIZE + 5] ^= 0x01;

    /* Alice must detect forgery and abort with CV_DIFFIE_ERR_AUTH */
    assert(cv_handshake_finalize_initiator(&alice, msg2) == CV_DIFFIE_ERR_AUTH);
    assert(alice.state == CV_HS_STATE_FAILED);

    cv_handshake_clear(&alice);
    cv_handshake_clear(&bob);
    cv_ecdh_keypair_clear(&alice_id);
    cv_ecdh_keypair_clear(&bob_id);

    printf("PASSED\n");
}

static void test_diffie_replay_attack_prevention(void) {
    printf("[Diffie] Testing Replay and State Desynchronization Prevention... ");

    cv_ecdh_keypair_t alice_id, bob_id;
    assert(cv_ecdh_keygen(&alice_id) == 0);
    assert(cv_ecdh_keygen(&bob_id) == 0);

    cv_handshake_t alice, bob;
    assert(cv_handshake_init(&alice, CV_ROLE_INITIATOR, &alice_id) == CV_DIFFIE_SUCCESS);
    assert(cv_handshake_init(&bob, CV_ROLE_RESPONDER, &bob_id) == CV_DIFFIE_SUCCESS);

    uint8_t msg1[CV_ECDH_KEY_SIZE];
    assert(cv_handshake_write_msg1(&alice, msg1, sizeof(msg1)) == CV_DIFFIE_SUCCESS);

    /* Second write_msg1 must fail due to state lock */
    assert(cv_handshake_write_msg1(&alice, msg1, sizeof(msg1)) != CV_DIFFIE_SUCCESS);

    uint8_t msg2[CV_ECDH_KEY_SIZE + 32];
    assert(cv_handshake_respond_msg2(&bob, msg1, msg2, sizeof(msg2)) == CV_DIFFIE_SUCCESS);

    /* Second finalize must fail */
    assert(cv_handshake_finalize_initiator(&alice, msg2) == CV_DIFFIE_SUCCESS);
    assert(cv_handshake_finalize_initiator(&alice, msg2) != CV_DIFFIE_SUCCESS);

    cv_handshake_clear(&alice);
    cv_handshake_clear(&bob);
    cv_ecdh_keypair_clear(&alice_id);
    cv_ecdh_keypair_clear(&bob_id);

    printf("PASSED\n");
}

static void test_diffie_self_test(void) {
    printf("[Diffie] Testing Built-in cv_diffie_self_test()... ");
    assert(cv_handshake_self_test() == CV_DIFFIE_SUCCESS);
    printf("PASSED\n");
}

int main(void) {
    printf("====================================================\n");
    printf("      CryptoVault Authenticated Handshake Tests     \n");
    printf("====================================================\n");
    test_diffie_handshake_roundtrip();
    test_diffie_mitm_tamper_rejection();
    test_diffie_replay_attack_prevention();
    test_diffie_self_test();
    printf("All Authenticated Handshake Tests PASSED!\n\n");
    return 0;
}
