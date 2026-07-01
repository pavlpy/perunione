#ifndef ELLYPTIC_H
#define ELLYPTIC_H

#include <stdint.h>
#include <stdbool.h>

/* 1024-bit big integer: 16 x uint64_t */
#define BIGINT_WORDS 16

typedef struct {
    uint64_t w[BIGINT_WORDS];
} BigInt;

/* Point on elliptic curve y^2 = x^3 + 7 over GF(CURVE_P) */
typedef struct {
    BigInt x;
    BigInt y;
    bool is_infinity;
} ECPoint;

/* BigInt comparison / property checks */
bool bi_is_zero(const BigInt *a);
int  bi_compare(const BigInt *a, const BigInt *b);
bool bi_is_odd(const BigInt *a);
void bi_shift_right_1(BigInt *a);

/* Modular arithmetic */
void bi_mod_add(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p);
void bi_mod_sub(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p);
void bi_mod_mul(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p);
void bi_mod_inverse(BigInt *res, const BigInt *a, const BigInt *m);
void bi_mod_normalize(BigInt *a, const BigInt *p);

/* Elliptic curve point operations */
void ec_add(ECPoint *res, const ECPoint *p1, const ECPoint *p2);
void ec_mul(ECPoint *res, const ECPoint *p, const BigInt *k);

/* ECDH */
void ecdh_generate_public(ECPoint *public_key, const BigInt *private_key);
void ecdh_compute_shared_secret(BigInt *shared_secret, const ECPoint *their_public, const BigInt *my_private);
bool is_valid_public_key(const ECPoint *p);

/* Cryptographically secure 1024-bit random (RDRAND, fallback /dev/urandom, fallback LCG) */
BigInt generate_secure_random_1024(void);

#endif
