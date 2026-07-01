#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ellyptic.h"
#include <stdbool.h>
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#define HAS_RDRAND
#endif

#define BIGINT_WORDS 16
#define PACKET_BUF_SIZE 128

/* P = 2^1024 - 105, a pseudo-Mersenne prime */
static const BigInt CURVE_P = {{
    0xFFFFFFFFFFFFFF97ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};

/* Q = 2^1024 - P = 105, used for fast reduction */
static const BigInt CURVE_Q = {{
    0x0000000000000069ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL
}};

/* Curve: y^2 = x^3 + 7 */
static const BigInt CURVE_A = {{0x00ULL}};
static const BigInt CURVE_B = {{0x07ULL}};

/* Generator point G */
static const ECPoint CURVE_G = {
    .x = {{
        0x0A5D0B18FCF883B4ULL, 0xCC7E90CA2A4E7C82ULL, 0x7F43801072854F1AULL, 0x7E577224770DF7A9ULL,
        0x75ADB64D5B626D8EULL, 0x9772EDD95B11BB60ULL, 0xCB457696E4233D0DULL, 0x6880786C86E5BA5CULL,
        0xF228E9D316724C29ULL, 0x1D6E472010A3F48DULL, 0x39340E3A9215AA01ULL, 0x8C4C5F0DA15FB3F8ULL,
        0x272D56146B87780CULL, 0xE1D832FB9E7FA18DULL, 0xE8597B6AC9E8A8E9ULL, 0x9D2752C49358101FULL
    }},
    .y = {{
        0x24AA4097632AF942ULL, 0x069D76BA4070A5B2ULL, 0x2F5761F87B6E3B60ULL, 0x86BFA79F3E8F2ACAULL,
        0x9AE3E35F26BAE1C6ULL, 0x85D9A8A73D49E768ULL, 0xB324B8C052A35951ULL, 0xE23C7401FFC1BC59ULL,
        0x0A4FF809AC0B62CDULL, 0xE7A664087448B52DULL, 0xF63F35E3D7E39E07ULL, 0x3E54CBC12F942F32ULL,
        0x9374A10306550B3DULL, 0x1EC7C0BD4851BEC4ULL, 0xAA9AD212A70ADAFFULL, 0x5D7F05432093401BULL
    }},
    .is_infinity = false
};

const BigInt BI_ONE = {{1}};

/* Internal: pure 1024-bit big integer helpers */

static inline bool bi_is_zero_local(const BigInt *a) {
    for (int i = 0; i < BIGINT_WORDS; i++)
        if (a->w[i] != 0) return false;
    return true;
}

static int bi_compare_local(const BigInt *a, const BigInt *b) {
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        if (a->w[i] > b->w[i]) return 1;
        if (a->w[i] < b->w[i]) return -1;
    }
    return 0;
}

static void bi_copy(BigInt *dst, const BigInt *src) {
    for (int i = 0; i < BIGINT_WORDS; i++) dst->w[i] = src->w[i];
}

/* Unsigned subtraction: a - b (caller must ensure a >= b) */
static void bi_sub_raw(BigInt *res, const BigInt *a, const BigInt *b) {
    __int128_t borrow = 0;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        __int128_t ai = (__int128_t)a->w[i];
        __int128_t bi = (__int128_t)b->w[i];
        __int128_t v = ai - bi - borrow;
        if (v < 0) {
            v += (__int128_t)1 << 64;
            borrow = 1;
        } else {
            borrow = 0;
        }
        res->w[i] = (uint64_t)v;
    }
}

static bool bi_is_odd_local(const BigInt *a) {
    return (a->w[0] & 1ULL) != 0;
}

static void bi_shift_right_1_local(BigInt *a) {
    uint64_t carry = 0;
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        uint64_t next_carry = (a->w[i] & 1ULL) << 63;
        a->w[i] = (a->w[i] >> 1) | carry;
        carry = next_carry;
    }
}

static int bi_bitlen(const BigInt *a) {
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        if (a->w[i] != 0) {
            uint64_t x = a->w[i];
            int l = 0;
            while (x) { l++; x >>= 1; }
            return i * 64 + l;
        }
    }
    return 0;
}

/* Public BigInt API */
bool bi_is_zero(const BigInt *a)     { return bi_is_zero_local(a); }
int  bi_compare(const BigInt *a, const BigInt *b) { return bi_compare_local(a, b); }

/* Modular reduction via schoolbook long division */
static void bi_mod_reduce(BigInt *r, const BigInt *a, const BigInt *p) {
    BigInt rem;
    bi_copy(&rem, a);

    if (bi_compare_local(&rem, p) < 0) {
        bi_copy(r, &rem);
        return;
    }

    int p_len = bi_bitlen(p);
    int rem_len = bi_bitlen(&rem);

    while (rem_len >= p_len && rem_len != 0) {
        int shift = rem_len - p_len;

        BigInt shifted = {{0}};
        int word_shift = shift >> 6;
        int bit_shift = shift & 63;

        for (int i = 0; i < BIGINT_WORDS; i++) {
            int src_i = i - word_shift;
            if (src_i < 0 || src_i >= BIGINT_WORDS) continue;
            uint64_t val = p->w[src_i];
            if (bit_shift == 0) {
                shifted.w[i] |= val;
            } else {
                shifted.w[i] |= val << bit_shift;
                if (i + 1 < BIGINT_WORDS)
                    shifted.w[i + 1] |= val >> (64 - bit_shift);
            }
        }

        if (bi_compare_local(&rem, &shifted) < 0) {
            shift--;
            rem_len = bi_bitlen(&rem);
            continue;
        }
        bi_sub_raw(&rem, &rem, &shifted);
        rem_len = bi_bitlen(&rem);
    }

    bi_copy(r, &rem);
}

void bi_mod_normalize(BigInt *a, const BigInt *p) {
    BigInt r;
    bi_mod_reduce(&r, a, p);
    bi_copy(a, &r);
}

void bi_mod_add(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    BigInt tmp;
    __uint128_t carry = 0;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        __uint128_t sum = (__uint128_t)a->w[i] + b->w[i] + carry;
        tmp.w[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    if (carry || bi_compare_local(&tmp, p) >= 0) {
        if (carry) {
            __uint128_t ci = 0;
            for (int i = 0; i < BIGINT_WORDS; i++) {
                ci = (__uint128_t)tmp.w[i] + CURVE_Q.w[i] + ci;
                tmp.w[i] = (uint64_t)ci;
                ci >>= 64;
            }
        }
        if (bi_compare_local(&tmp, p) >= 0)
            bi_sub_raw(&tmp, &tmp, p);
    }
    bi_copy(res, &tmp);
}

void bi_mod_sub(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    if (bi_compare_local(a, b) >= 0) {
        bi_sub_raw(res, a, b);
        return;
    }
    BigInt tmp;
    bi_sub_raw(&tmp, b, a);
    bi_sub_raw(res, p, &tmp);
}

/* Multiply then reduce modulo P using pseudo-Mersenne identity 2^1024 = Q */
void bi_mod_mul(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    (void)p;
    uint64_t prod[32] = {0};
    for (int i = 0; i < BIGINT_WORDS; i++) {
        for (int j = 0; j < BIGINT_WORDS; j++) {
            __uint128_t cur = (__uint128_t)prod[i + j] + (__uint128_t)a->w[i] * b->w[j];
            prod[i + j] = (uint64_t)cur;
            __uint128_t carry = cur >> 64;
            for (int k = i + j + 1; carry && k < 32; k++) {
                __uint128_t c2 = (__uint128_t)prod[k] + carry;
                prod[k] = (uint64_t)c2;
                carry = c2 >> 64;
            }
        }
    }

    /* Fold high half (words 16..31) multiplied by Q into low half */
    BigInt r = {{0}};
    __uint128_t carry = 0;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        __uint128_t v = (__uint128_t)prod[i] + (__uint128_t)prod[i + BIGINT_WORDS] * CURVE_Q.w[0] + carry;
        r.w[i] = (uint64_t)v;
        carry = v >> 64;
    }
    if (carry) {
        BigInt addend = {{0}};
        addend.w[0] = (uint64_t)(carry * CURVE_Q.w[0]);
        bi_mod_add(&r, &r, &addend, p);
    }
    if (bi_compare_local(&r, p) >= 0)
        bi_sub_raw(&r, &r, p);
    bi_copy(res, &r);
}

/* Modular inverse via binary extended GCD */
void bi_mod_inverse(BigInt *res, const BigInt *a, const BigInt *m) {
    BigInt u, v, x1 = {{1}}, x2 = {{0}};
    bi_copy(&u, a);
    bi_copy(&v, m);
    bi_mod_reduce(&u, &u, m);

    while (!bi_is_zero_local(&u) && bi_compare_local(&u, &BI_ONE) != 0 &&
           !bi_is_zero_local(&v) && bi_compare_local(&v, &BI_ONE) != 0) {
        while (!bi_is_odd_local(&u) && !bi_is_zero_local(&u)) {
            bi_shift_right_1_local(&u);
            if (bi_is_odd_local(&x1)) {
                __uint128_t carry = 0;
                BigInt tmp;
                for (int i = 0; i < BIGINT_WORDS; i++) {
                    __uint128_t s = (__uint128_t)x1.w[i] + m->w[i] + carry;
                    tmp.w[i] = (uint64_t)s;
                    carry = s >> 64;
                }
                uint64_t sc = (uint64_t)carry << 63;
                for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
                    uint64_t nc = (tmp.w[i] & 1ULL) << 63;
                    tmp.w[i] = (tmp.w[i] >> 1) | sc;
                    sc = nc;
                }
                bi_copy(&x1, &tmp);
            } else {
                bi_shift_right_1_local(&x1);
            }
        }
        while (!bi_is_odd_local(&v) && !bi_is_zero_local(&v)) {
            bi_shift_right_1_local(&v);
            if (bi_is_odd_local(&x2)) {
                __uint128_t carry = 0;
                BigInt tmp;
                for (int i = 0; i < BIGINT_WORDS; i++) {
                    __uint128_t s = (__uint128_t)x2.w[i] + m->w[i] + carry;
                    tmp.w[i] = (uint64_t)s;
                    carry = s >> 64;
                }
                uint64_t sc = (uint64_t)carry << 63;
                for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
                    uint64_t nc = (tmp.w[i] & 1ULL) << 63;
                    tmp.w[i] = (tmp.w[i] >> 1) | sc;
                    sc = nc;
                }
                bi_copy(&x2, &tmp);
            } else {
                bi_shift_right_1_local(&x2);
            }
        }

        if (bi_compare_local(&u, &v) >= 0) {
            BigInt tmpu;
            bi_sub_raw(&tmpu, &u, &v);
            bi_copy(&u, &tmpu);
            if (bi_compare_local(&x1, &x2) >= 0) {
                BigInt tmpx;
                bi_sub_raw(&tmpx, &x1, &x2);
                bi_copy(&x1, &tmpx);
            } else {
                BigInt tmpx;
                bi_sub_raw(&tmpx, &x2, &x1);
                bi_sub_raw(&x1, m, &tmpx);
            }
            bi_mod_reduce(&x1, &x1, m);
        } else {
            BigInt tmpv;
            bi_sub_raw(&tmpv, &v, &u);
            bi_copy(&v, &tmpv);
            if (bi_compare_local(&x2, &x1) >= 0) {
                BigInt tmpx;
                bi_sub_raw(&tmpx, &x2, &x1);
                bi_copy(&x2, &tmpx);
            } else {
                BigInt tmpx;
                bi_sub_raw(&tmpx, &x1, &x2);
                bi_sub_raw(&x2, m, &tmpx);
            }
            bi_mod_reduce(&x2, &x2, m);
        }
    }

    if (bi_compare_local(&u, &BI_ONE) == 0)
        bi_copy(res, &x1);
    else
        bi_copy(res, &x2);
    bi_mod_reduce(res, res, m);
}

bool bi_is_odd(const BigInt *a)       { return bi_is_odd_local(a); }
void bi_shift_right_1(BigInt *a)      { bi_shift_right_1_local(a); }

/* Point addition / doubling on y^2 = x^3 + 7 */
void ec_add(ECPoint *res, const ECPoint *p1, const ECPoint *p2) {
    if (p1->is_infinity) { *res = *p2; return; }
    if (p2->is_infinity) { *res = *p1; return; }

    BigInt lambda, num = {{0}}, den = {{0}};

    if (bi_compare_local(&p1->x, &p2->x) == 0 && bi_compare_local(&p1->y, &p2->y) == 0) {
        if (bi_is_zero_local(&p1->y)) {
            res->is_infinity = true;
            return;
        }
        bi_mod_mul(&num, &p1->x, &p1->x, &CURVE_P);
        BigInt three = {{3}};
        bi_mod_mul(&num, &num, &three, &CURVE_P);
        bi_mod_add(&num, &num, &CURVE_A, &CURVE_P);
        bi_mod_add(&den, &p1->y, &p1->y, &CURVE_P);
    } else {
        if (bi_compare_local(&p1->x, &p2->x) == 0) {
            res->is_infinity = true;
            return;
        }
        bi_mod_sub(&num, &p2->y, &p1->y, &CURVE_P);
        bi_mod_sub(&den, &p2->x, &p1->x, &CURVE_P);
    }

    if (bi_is_zero_local(&den)) {
        res->is_infinity = true;
        return;
    }

    BigInt inv_den = {{0}};
    bi_mod_inverse(&inv_den, &den, &CURVE_P);
    bi_mod_mul(&lambda, &num, &inv_den, &CURVE_P);

    BigInt x3, y3;
    bi_mod_mul(&x3, &lambda, &lambda, &CURVE_P);
    bi_mod_sub(&x3, &x3, &p1->x, &CURVE_P);
    bi_mod_sub(&x3, &x3, &p2->x, &CURVE_P);
    bi_mod_sub(&y3, &p1->x, &x3, &CURVE_P);
    bi_mod_mul(&y3, &lambda, &y3, &CURVE_P);
    bi_mod_sub(&y3, &y3, &p1->y, &CURVE_P);

    res->x = x3;
    res->y = y3;
    res->is_infinity = false;
}

/* Scalar multiplication: double-and-add */
void ec_mul(ECPoint *res, const ECPoint *p, const BigInt *k) {
    ECPoint base = *p;
    ECPoint curr = {.is_infinity = true};
    BigInt scalar = *k;

    int max_bits = BIGINT_WORDS * 64;
    while (!bi_is_zero_local(&scalar) && max_bits-- > 0) {
        if (bi_is_odd_local(&scalar)) {
            ECPoint tmp;
            ec_add(&tmp, &curr, &base);
            curr = tmp;
        }
        ECPoint dbl;
        ec_add(&dbl, &base, &base);
        base = dbl;
        bi_shift_right_1_local(&scalar);
    }

    *res = curr;
}

/* Validate that p lies on the curve */
bool is_valid_public_key(const ECPoint *p) {
    if (p->is_infinity) return false;
    if (bi_compare_local(&p->x, &CURVE_P) >= 0 || bi_compare_local(&p->y, &CURVE_P) >= 0) return false;
    BigInt lhs, rhs, x3;
    bi_mod_mul(&lhs, &p->y, &p->y, &CURVE_P);
    bi_mod_mul(&x3, &p->x, &p->x, &CURVE_P);
    bi_mod_mul(&x3, &x3, &p->x, &CURVE_P);
    bi_mod_add(&rhs, &x3, &CURVE_B, &CURVE_P);
    return bi_compare_local(&lhs, &rhs) == 0;
}

/* Generate 1024 random bits using RDRAND, /dev/urandom, or fallback LCG */
BigInt generate_secure_random_1024(void) {
    BigInt res = {0};

#ifdef HAS_RDRAND
    int success_count = 0;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        for (int retry = 0; retry < 10; retry++) {
            if (_rdrand64_step((unsigned long long *)&res.w[i])) {
                success_count++;
                break;
            }
        }
    }
    if (success_count == BIGINT_WORDS) return res;
#endif

    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(res.w, 1, sizeof(res.w), f);
        fclose(f);
        if (n == sizeof(res.w)) return res;
    }

    uint64_t seed = 0x123456789ABCDEF1ULL;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        res.w[i] = seed;
    }

    return res;
}

void ecdh_generate_public(ECPoint *public_key, const BigInt *private_key) {
    ec_mul(public_key, &CURVE_G, private_key);
}

void ecdh_compute_shared_secret(BigInt *shared_secret,
                                const ECPoint *their_public,
                                const BigInt *my_private) {
    ECPoint shared_point;
    ec_mul(&shared_point, their_public, my_private);
    *shared_secret = shared_point.x;
}
