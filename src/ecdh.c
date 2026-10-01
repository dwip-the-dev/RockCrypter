#include "ecdh.h"
#include "entropy.h"
#include "mem.h"
#include <string.h>

/* Curve25519 field arithmetic modulo p = 2^255 - 19 */
/* Standard 16-limb radix-2^16 representation */
typedef int64_t gf[16];

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        int64_t c = o[i] >> 16;
        o[i] -= c << 16;
        if (i < 15) {
            o[i + 1] += c;
        } else {
            o[0] += 38 * c;
        }
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t mask = -((int64_t)b);
    for (int i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);

    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        m[14] &= 0xFFFF;
        int64_t b = (m[15] >> 16) & 1;
        m[15] &= 0xFFFF;
        sel25519(t, m, 1 - (int)b);
    }

    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7FFF;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; i++) {
        o[i] = t[i];
    }
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

/* Fermat's Little Theorem: o = i^(2^255 - 21) mod (2^255 - 19) */
static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

/* (A - 2) / 4 = (486662 - 2) / 4 = 121665 */
/* In TweetNaCl: 121666 with offset representation */
static const gf _121666 = {0xDB42, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* Montgomery Ladder for Curve25519 scalar multiplication */
static void curve25519_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p) {
    uint8_t e[32];
    for (int i = 0; i < 32; i++) e[i] = n[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    gf x1, x2, z2, x3, z3, a, b, c, d, e_gf, aa, bb, da, cb;
    unpack25519(x1, p);
    for (int i = 0; i < 16; i++) {
        x2[i] = 0; z2[i] = 0;
        x3[i] = x1[i]; z3[i] = 0;
    }
    x2[0] = 1;
    z3[0] = 1;

    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b_bit = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b_bit;
        sel25519(x2, x3, swap);
        sel25519(z2, z3, swap);
        swap = b_bit;

        A(a, x2, z2);
        S(aa, a);
        Z(b, x2, z2);
        S(bb, b);
        Z(e_gf, aa, bb);
        A(c, x3, z3);
        Z(d, x3, z3);
        M(da, d, a);
        M(cb, c, b);
        A(x3, da, cb);
        S(x3, x3);
        Z(z3, da, cb);
        S(z3, z3);
        M(z3, z3, x1);
        M(x2, aa, bb);
        M(z2, e_gf, _121666);
        A(z2, z2, aa);
        M(z2, e_gf, z2);
    }
    sel25519(x2, x3, swap);
    sel25519(z2, z3, swap);

    gf zm;
    inv25519(zm, z2);
    M(x2, x2, zm);
    pack25519(q, x2);

    cv_memzero(e, sizeof(e));
}

static const uint8_t BASE_POINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

int cv_ecdh_public_from_private(const uint8_t priv[CV_ECDH_KEY_SIZE],
                                uint8_t pub_out[CV_ECDH_KEY_SIZE]) {
    if (!priv || !pub_out) return -1;
    curve25519_scalarmult(pub_out, priv, BASE_POINT);
    return 0;
}

int cv_ecdh_keygen(cv_ecdh_keypair_t *kp) {
    if (!kp) return -1;
    if (cv_entropy_get(kp->priv, CV_ECDH_KEY_SIZE) != 0) {
        return -2;
    }
    /* Clamping */
    kp->priv[0] &= 248;
    kp->priv[31] &= 127;
    kp->priv[31] |= 64;

    return cv_ecdh_public_from_private(kp->priv, kp->pub);
}

int cv_ecdh_compute_shared(const uint8_t my_priv[CV_ECDH_KEY_SIZE],
                           const uint8_t peer_pub[CV_ECDH_KEY_SIZE],
                           uint8_t shared_out[CV_ECDH_KEY_SIZE]) {
    if (!my_priv || !peer_pub || !shared_out) return -1;
    curve25519_scalarmult(shared_out, my_priv, peer_pub);

    /* Zero-check against small-order points */
    uint8_t all_zero = 0;
    for (int i = 0; i < 32; i++) all_zero |= shared_out[i];
    if (all_zero == 0) return -3; /* Low-order point rejected */

    return 0;
}

void cv_ecdh_keypair_clear(cv_ecdh_keypair_t *kp) {
    if (kp) {
        cv_memzero(kp, sizeof(*kp));
    }
}

int cv_ecdh_self_test(void) {
    cv_ecdh_keypair_t alice, bob;
    uint8_t shared_alice[CV_ECDH_KEY_SIZE];
    uint8_t shared_bob[CV_ECDH_KEY_SIZE];

    if (cv_ecdh_keygen(&alice) != CV_ECDH_SUCCESS) return CV_ECDH_ERR_SELFTEST;
    if (cv_ecdh_keygen(&bob) != CV_ECDH_SUCCESS) {
        cv_ecdh_keypair_clear(&alice);
        return CV_ECDH_ERR_SELFTEST;
    }

    if (cv_ecdh_compute_shared(alice.priv, bob.pub, shared_alice) != CV_ECDH_SUCCESS) {
        cv_ecdh_keypair_clear(&alice);
        cv_ecdh_keypair_clear(&bob);
        return CV_ECDH_ERR_SELFTEST;
    }

    if (cv_ecdh_compute_shared(bob.priv, alice.pub, shared_bob) != CV_ECDH_SUCCESS) {
        cv_ecdh_keypair_clear(&alice);
        cv_ecdh_keypair_clear(&bob);
        return CV_ECDH_ERR_SELFTEST;
    }

    int match = cv_ct_memcmp(shared_alice, shared_bob, CV_ECDH_KEY_SIZE);

    cv_ecdh_keypair_clear(&alice);
    cv_ecdh_keypair_clear(&bob);
    cv_memzero(shared_alice, sizeof(shared_alice));
    cv_memzero(shared_bob, sizeof(shared_bob));

    return (match == 0) ? CV_ECDH_SUCCESS : CV_ECDH_ERR_SELFTEST;
}
