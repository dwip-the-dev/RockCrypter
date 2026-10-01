/**
 * @file pqc.c
 * @brief Post-Quantum Cryptography & Hybrid Key Encapsulation Mechanism Implementation.
 *
 * ============================================================================
 * CryptoVault Post-Quantum & Hybrid Cryptography Subsystem
 * ============================================================================
 *
 * Implements lattice-based Ring-LWE key encapsulation over R_q = Z_q[x]/(x^256 + 1)
 * with q = 3329 and 1-bit Peikert/Ding boundary reconciliation, combined with
 * classical Diffie-Hellman in a dual-PRF HKDF framework.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "pqc.h"
#include "entropy.h"
#include "mem.h"
#include "hkdf.h"
#include "sponge_hash.h"
#include <string.h>

#define Q_HALF   1664
#define Q_QUART   832
#define Q_EIGHT   416

/* Modular reduction to [0, q-1] */
static inline int16_t reduce_mod_q(int32_t val) {
    int32_t r = val % CV_PQC_PRIME_Q;
    if (r < 0) {
        r += CV_PQC_PRIME_Q;
    }
    return (int16_t)r;
}

/* Encode polynomial into 512 bytes (little-endian 16-bit words) */
static void encode_poly(const cv_pqc_poly_t *p, uint8_t *out) {
    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        uint16_t v = (uint16_t)p->coeffs[i];
        out[2 * i]     = (uint8_t)(v & 0xFF);
        out[2 * i + 1] = (uint8_t)((v >> 8) & 0xFF);
    }
}

/* Decode polynomial from 512 bytes */
static void decode_poly(const uint8_t *in, cv_pqc_poly_t *p) {
    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        uint16_t v = (uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8);
        p->coeffs[i] = reduce_mod_q((int32_t)v);
    }
}

/* Derive standard public parameter generator polynomial A(x) */
static void get_generator_a(cv_pqc_poly_t *a) {
    static const char *GEN_SEED = "CRYPTOVAULT_PQC_LATTICE_GENERATOR_A_POLY_V1";
    uint8_t stream[CV_PQC_POLY_DEGREE * 2];
    cv_hkdf(NULL, 0, (const uint8_t *)GEN_SEED, strlen(GEN_SEED),
            (const uint8_t *)"poly_a", 6, stream, sizeof(stream));

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        uint16_t val = (uint16_t)stream[2 * i] | ((uint16_t)stream[2 * i + 1] << 8);
        a->coeffs[i] = (int16_t)(val % CV_PQC_PRIME_Q);
    }
    cv_memzero(stream, sizeof(stream));
}

/* Sample small bounded noise with coefficients in {-1, 0, 1} */
static int sample_noise(cv_pqc_poly_t *p) {
    uint8_t rand_bytes[CV_PQC_POLY_DEGREE];
    if (cv_entropy_gather(rand_bytes, sizeof(rand_bytes)) != CV_ENTROPY_OK) {
        return CV_PQC_ERR_ENTROPY;
    }

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        int r = (int)(rand_bytes[i] % 3) - 1; /* {-1, 0, 1} */
        p->coeffs[i] = reduce_mod_q(r);
    }

    cv_mem_zero(rand_bytes, sizeof(rand_bytes));
    return CV_PQC_SUCCESS;
}

void cv_pqc_poly_add(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c) {
    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        c->coeffs[i] = reduce_mod_q((int32_t)a->coeffs[i] + (int32_t)b->coeffs[i]);
    }
}

void cv_pqc_poly_sub(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c) {
    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        c->coeffs[i] = reduce_mod_q((int32_t)a->coeffs[i] - (int32_t)b->coeffs[i]);
    }
}

/* Negacyclic polynomial multiplication: c(x) = a(x) * b(x) mod (x^256 + 1) mod q */
void cv_pqc_poly_mul(const cv_pqc_poly_t *a, const cv_pqc_poly_t *b, cv_pqc_poly_t *c) {
    int64_t acc[CV_PQC_POLY_DEGREE] = {0};

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        int64_t ai = a->coeffs[i];
        for (size_t j = 0; j < CV_PQC_POLY_DEGREE; j++) {
            int64_t term = ai * b->coeffs[j];
            if (i + j < CV_PQC_POLY_DEGREE) {
                acc[i + j] += term;
            } else {
                acc[i + j - CV_PQC_POLY_DEGREE] -= term;
            }
        }
    }

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        c->coeffs[i] = reduce_mod_q((int32_t)(acc[i] % CV_PQC_PRIME_Q));
    }
}

/* Reconciliation helper: compute 1-bit boundary hint */
static inline uint8_t compute_reconciliation_hint(int16_t v) {
    /* If v in [q/8, 3q/8) or [5q/8, 7q/8), hint is 0; else 1 */
    if ((v >= Q_EIGHT && v < 3 * Q_EIGHT) ||
        (v >= 5 * Q_EIGHT && v < 7 * Q_EIGHT)) {
        return 0;
    }
    return 1;
}

/* Reconciliation helper: recover common bit using shifted threshold */
static inline uint8_t recover_reconciliation_bit(int16_t v, uint8_t h) {
    int32_t shifted = v + (h ? Q_QUART : 0);
    shifted = shifted % CV_PQC_PRIME_Q;
    if (shifted < 0) {
        shifted += CV_PQC_PRIME_Q;
    }
    return (shifted >= Q_HALF) ? 1 : 0;
}

int cv_pqc_keygen(cv_pqc_keypair_t *kp) {
    if (!kp) {
        return CV_PQC_ERR_PARAM;
    }

    cv_pqc_poly_t a, s, e, t;
    get_generator_a(&a);

    if (sample_noise(&s) != CV_PQC_SUCCESS || sample_noise(&e) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_ENTROPY;
    }

    /* Public key: t = A * s + e mod (x^256 + 1, q) */
    cv_pqc_poly_mul(&a, &s, &t);
    cv_pqc_poly_add(&t, &e, &t);

    encode_poly(&t, kp->pk);
    encode_poly(&s, kp->sk);

    /* Wipe secret polynomial variables */
    cv_mem_zero(&s, sizeof(s));
    cv_mem_zero(&e, sizeof(e));
    cv_mem_zero(&t, sizeof(t));
    return CV_PQC_SUCCESS;
}

int cv_pqc_encapsulate(const uint8_t *pk_bytes, cv_pqc_ciphertext_t *ct_out, uint8_t *ss_out) {
    if (!pk_bytes || !ct_out || !ss_out) {
        return CV_PQC_ERR_PARAM;
    }

    cv_pqc_poly_t a, t, r, e1, u, v;
    get_generator_a(&a);
    decode_poly(pk_bytes, &t);

    if (sample_noise(&r) != CV_PQC_SUCCESS || sample_noise(&e1) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_ENTROPY;
    }

    /* Ciphertext poly: u = A * r + e1 mod (x^256 + 1, q) */
    cv_pqc_poly_mul(&a, &r, &u);
    cv_pqc_poly_add(&u, &e1, &u);
    encode_poly(&u, ct_out->data);

    /* Shared vector: v = t * r mod (x^256 + 1, q) */
    cv_pqc_poly_mul(&t, &r, &v);

    /* Generate 256 bits of key material and 256 bits of reconciliation hints */
    uint8_t raw_bits[32] = {0};
    uint8_t *hint_ptr = ct_out->data + 512;
    memset(hint_ptr, 0, 32);

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        uint8_t h = compute_reconciliation_hint(v.coeffs[i]);
        if (h) {
            hint_ptr[i / 8] |= (uint8_t)(1U << (i % 8));
        }
        uint8_t bit = recover_reconciliation_bit(v.coeffs[i], h);
        if (bit) {
            raw_bits[i / 8] |= (uint8_t)(1U << (i % 8));
        }
    }

    /* Hash raw extracted bit vector into uniform 32-byte shared secret */
    cv_sponge_hash(raw_bits, sizeof(raw_bits), ss_out, CV_PQC_SHARED_SECRET_SIZE);

    /* Secure cleanup */
    cv_mem_zero(&r, sizeof(r));
    cv_mem_zero(&e1, sizeof(e1));
    cv_mem_zero(&v, sizeof(v));
    cv_mem_zero(raw_bits, sizeof(raw_bits));
    return CV_PQC_SUCCESS;
}

int cv_pqc_decapsulate(const uint8_t *sk_bytes, const cv_pqc_ciphertext_t *ct, uint8_t *ss_out) {
    if (!sk_bytes || !ct || !ss_out) {
        return CV_PQC_ERR_PARAM;
    }

    cv_pqc_poly_t s, u, v_prime;
    decode_poly(sk_bytes, &s);
    decode_poly(ct->data, &u);

    /* Recovered vector: v' = u * s mod (x^256 + 1, q) */
    cv_pqc_poly_mul(&u, &s, &v_prime);

    const uint8_t *hint_ptr = ct->data + 512;
    uint8_t raw_bits[32] = {0};

    for (size_t i = 0; i < CV_PQC_POLY_DEGREE; i++) {
        uint8_t h = (hint_ptr[i / 8] >> (i % 8)) & 1U;
        uint8_t bit = recover_reconciliation_bit(v_prime.coeffs[i], h);
        if (bit) {
            raw_bits[i / 8] |= (uint8_t)(1U << (i % 8));
        }
    }

    /* Hash recovered bit vector into 32-byte shared secret */
    cv_sponge_hash(raw_bits, sizeof(raw_bits), ss_out, CV_PQC_SHARED_SECRET_SIZE);

    /* Secure cleanup */
    cv_mem_zero(&s, sizeof(s));
    cv_mem_zero(&v_prime, sizeof(v_prime));
    cv_mem_zero(raw_bits, sizeof(raw_bits));
    return CV_PQC_SUCCESS;
}

int cv_pqc_hybrid_combine(const uint8_t *classical_ss, size_t classical_len,
                          const uint8_t *pqc_ss, size_t pqc_len,
                          const uint8_t *context_info, size_t info_len,
                          uint8_t *hybrid_out, size_t out_len) {
    if (!classical_ss || classical_len == 0 ||
        !pqc_ss || pqc_len == 0 ||
        !hybrid_out || out_len == 0) {
        return CV_PQC_ERR_PARAM;
    }

    /* Dual-PRK combiner: IKM = Classical_SS || PQC_SS */
    uint8_t ikm[128];
    if (classical_len + pqc_len > sizeof(ikm)) {
        return CV_PQC_ERR_PARAM;
    }

    memcpy(ikm, classical_ss, classical_len);
    memcpy(ikm + classical_len, pqc_ss, pqc_len);

    static const uint8_t HYBRID_SALT[] = "CRYPTOVAULT_HYBRID_PQC_COMBINER_SALT_V2";
    int ret = cv_hkdf(HYBRID_SALT, sizeof(HYBRID_SALT) - 1,
                      ikm, classical_len + pqc_len,
                      context_info, info_len,
                      hybrid_out, out_len);

    cv_mem_zero(ikm, sizeof(ikm));
    return (ret == 0) ? CV_PQC_SUCCESS : CV_PQC_ERR_PARAM;
}

int cv_pqc_self_test(void) {
    cv_pqc_keypair_t kp;
    if (cv_pqc_keygen(&kp) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_SELFTEST;
    }

    cv_pqc_ciphertext_t ct;
    uint8_t ss_sender[CV_PQC_SHARED_SECRET_SIZE];
    uint8_t ss_receiver[CV_PQC_SHARED_SECRET_SIZE];

    if (cv_pqc_encapsulate(kp.pk, &ct, ss_sender) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_SELFTEST;
    }

    if (cv_pqc_decapsulate(kp.sk, &ct, ss_receiver) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_SELFTEST;
    }

    /* Verify sender and recipient derived identical shared secrets */
    if (cv_mem_equal(ss_sender, ss_receiver, CV_PQC_SHARED_SECRET_SIZE) != 1) {
        return CV_PQC_ERR_SELFTEST;
    }

    /* Test hybrid combiner */
    uint8_t classical[32] = {0x42};
    uint8_t hybrid1[32], hybrid2[32];
    const char *info = "cv_hybrid_test_context";

    if (cv_pqc_hybrid_combine(classical, 32, ss_sender, 32,
                              (const uint8_t *)info, strlen(info),
                              hybrid1, 32) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_SELFTEST;
    }

    if (cv_pqc_hybrid_combine(classical, 32, ss_receiver, 32,
                              (const uint8_t *)info, strlen(info),
                              hybrid2, 32) != CV_PQC_SUCCESS) {
        return CV_PQC_ERR_SELFTEST;
    }

    if (cv_mem_equal(hybrid1, hybrid2, 32) != 1) {
        return CV_PQC_ERR_SELFTEST;
    }

    /* Clean memory */
    cv_mem_zero(&kp, sizeof(kp));
    cv_mem_zero(&ct, sizeof(ct));
    cv_mem_zero(ss_sender, sizeof(ss_sender));
    cv_mem_zero(ss_receiver, sizeof(ss_receiver));
    return CV_PQC_SUCCESS;
}
