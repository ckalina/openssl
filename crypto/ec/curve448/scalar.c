/**
 * @file ed448goldilocks/scalar.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Decaf high-level functions.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include <openssl/crypto.h>

#include "word.h"
#include "constant_time.h"
#include "point_448.h"

static const decaf_word_t MONTGOMERY_FACTOR = (decaf_word_t)0x3bd440fae918bc5;
static const curve448_scalar_t sc_p = {{{
    SC_LIMB(0x2378c292ab5844f3), SC_LIMB(0x216cc2728dc58f55), SC_LIMB(0xc44edb49aed63690), SC_LIMB(0xffffffff7cca23e9), SC_LIMB(0xffffffffffffffff), SC_LIMB(0xffffffffffffffff), SC_LIMB(0x3fffffffffffffff)
}}}, sc_r2 = {{{
    SC_LIMB(0xe3539257049b9b60), SC_LIMB(0x7af32c4bc1b195d9), SC_LIMB(0x0d66de2388ea1859), SC_LIMB(0xae17cf725ee4d838), SC_LIMB(0x1a9cc14ba3c47c44), SC_LIMB(0x2052bcb7e4d070af), SC_LIMB(0x3402a939f823b729)
}}};
/* End of template stuff */

#define WBITS DECAF_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

const curve448_scalar_t curve448_scalar_one = {{{1}}}, curve448_scalar_zero = {{{0}}};

/** {extra,accum} - sub +? p
 * Must have extra <= 1
 */
static void sc_subx(
    curve448_scalar_t out,
    const decaf_word_t accum[DECAF_448_SCALAR_LIMBS],
    const curve448_scalar_t sub,
    const curve448_scalar_t p,
    decaf_word_t extra
) {
    decaf_dsword_t chain = 0;
    unsigned int i;
    decaf_word_t borrow;

    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + accum[i]) - sub->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    borrow = chain+extra; /* = 0 or -1 */
    
    chain = 0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
}

static void sc_montmul (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
) {
    unsigned int i,j;
    decaf_word_t accum[DECAF_448_SCALAR_LIMBS+1] = {0};
    decaf_word_t hi_carry = 0;
    
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        decaf_word_t mand = a->limb[i];
        const decaf_word_t *mier = b->limb;
        
        decaf_dword_t chain = 0;
        for (j=0; j<DECAF_448_SCALAR_LIMBS; j++) {
            chain += ((decaf_dword_t)mand)*mier[j] + accum[j];
            accum[j] = chain;
            chain >>= WBITS;
        }
        accum[j] = chain;
        
        mand = accum[0] * MONTGOMERY_FACTOR;
        chain = 0;
        mier = sc_p->limb;
        for (j=0; j<DECAF_448_SCALAR_LIMBS; j++) {
            chain += (decaf_dword_t)mand*mier[j] + accum[j];
            if (j) accum[j-1] = chain;
            chain >>= WBITS;
        }
        chain += accum[j];
        chain += hi_carry;
        accum[j-1] = chain;
        hi_carry = chain >> WBITS;
    }
    
    sc_subx(out, accum, sc_p, sc_p, hi_carry);
}

void curve448_scalar_mul (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
) {
    sc_montmul(out,a,b);
    sc_montmul(out,out,sc_r2);
}

void curve448_scalar_sub (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
) {
    sc_subx(out, a->limb, b, sc_p, 0);
}

void curve448_scalar_add (
    curve448_scalar_t out,
    const curve448_scalar_t a,
    const curve448_scalar_t b
) {
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + b->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    sc_subx(out, out->limb, sc_p, sc_p, chain);
}

static ossl_inline void scalar_decode_short (
    curve448_scalar_t s,
    const unsigned char *ser,
    unsigned int nbytes
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t) && k<nbytes; j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
}

decaf_error_t curve448_scalar_decode(
    curve448_scalar_t s,
    const unsigned char ser[DECAF_448_SCALAR_BYTES]
) {
    unsigned int i;
    decaf_dsword_t accum = 0;

    scalar_decode_short(s, ser, DECAF_448_SCALAR_BYTES);
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - sc_p->limb[i]) >> WBITS;
    }
    /* Here accum == 0 or -1 */
    
    curve448_scalar_mul(s,s,curve448_scalar_one); /* ham-handed reduce */
    
    return decaf_succeed_if(~word_is_zero(accum));
}

void curve448_scalar_destroy (
    curve448_scalar_t scalar
) {
    OPENSSL_cleanse(scalar, sizeof(curve448_scalar_t));
}

void curve448_scalar_decode_long(
    curve448_scalar_t s,
    const unsigned char *ser,
    size_t ser_len
) {
    size_t i;
    curve448_scalar_t t1, t2;

    if (ser_len == 0) {
        curve448_scalar_copy(s, curve448_scalar_zero);
        return;
    }

    i = ser_len - (ser_len%DECAF_448_SCALAR_BYTES);
    if (i==ser_len) i -= DECAF_448_SCALAR_BYTES;
    
    scalar_decode_short(t1, &ser[i], ser_len-i);

    if (ser_len == sizeof(curve448_scalar_t)) {
        assert(i==0);
        /* ham-handed reduce */
        curve448_scalar_mul(s,t1,curve448_scalar_one);
        curve448_scalar_destroy(t1);
        return;
    }

    while (i) {
        i -= DECAF_448_SCALAR_BYTES;
        sc_montmul(t1,t1,sc_r2);
        ignore_result( curve448_scalar_decode(t2, ser+i) );
        curve448_scalar_add(t1, t1, t2);
    }

    curve448_scalar_copy(s, t1);
    curve448_scalar_destroy(t1);
    curve448_scalar_destroy(t2);
}

void curve448_scalar_encode(
    unsigned char ser[DECAF_448_SCALAR_BYTES],
    const curve448_scalar_t s
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            ser[k] = s->limb[i] >> (8*j);
        }
    }
}

void curve448_scalar_halve (
    curve448_scalar_t out,
    const curve448_scalar_t a
) {
    decaf_word_t mask = -(a->limb[0] & 1);
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + (sc_p->limb[i] & mask);
        out->limb[i] = chain;
        chain >>= DECAF_WORD_BITS;
    }
    for (i=0; i<DECAF_448_SCALAR_LIMBS-1; i++) {
        out->limb[i] = out->limb[i]>>1 | out->limb[i+1]<<(WBITS-1);
    }
    out->limb[i] = out->limb[i]>>1 | chain<<(WBITS-1);
}

