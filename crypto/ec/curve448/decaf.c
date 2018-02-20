/**
 * @file ed448goldilocks/decaf.c
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
#include "field.h"

#include "point_448.h"
#include "ed448.h"
#include "curve448_lcl.h"

/* Template stuff */
#define API_NS(_id) decaf_448_##_id
#define SCALAR_BITS DECAF_448_SCALAR_BITS
#define SCALAR_SER_BYTES DECAF_448_SCALAR_BYTES
#define SCALAR_LIMBS DECAF_448_SCALAR_LIMBS
#define scalar_t API_NS(scalar_t)
#define point_t API_NS(point_t)
#define precomputed_s API_NS(precomputed_s)
#define COFACTOR 4

/* Comb config: number of combs, n, t, s. */
#define COMBS_N 5
#define COMBS_T 5
#define COMBS_S 18
#define DECAF_WINDOW_BITS 5
#define DECAF_WNAF_FIXED_TABLE_BITS 5
#define DECAF_WNAF_VAR_TABLE_BITS 3

static const int EDWARDS_D = -39081;
static const scalar_t precomputed_scalarmul_adjustment = {{{
    SC_LIMB(0xc873d6d54a7bb0cf), SC_LIMB(0xe933d8d723a70aad), SC_LIMB(0xbb124b65129c96fd), SC_LIMB(0x00000008335dc163)
}}};

const uint8_t decaf_x448_base_point[DECAF_X448_PUBLIC_BYTES] = { 0x05 };

#define RISTRETTO_FACTOR DECAF_448_RISTRETTO_FACTOR
const gf RISTRETTO_FACTOR = {{{
    0x42ef0f45572736, 0x7bf6aa20ce5296, 0xf4fd6eded26033, 0x968c14ba839a66, 0xb8d54b64a2d780, 0x6aa0a1f1a7b8a5, 0x683bf68d722fa2, 0x22d962fbeb24f7
}}};


#define TWISTED_D ((EDWARDS_D)-1)

#define EFF_D (-(TWISTED_D))
#define NEG_D 1

/* End of template stuff */

#define WBITS DECAF_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

/* Projective Niels coordinates */
typedef struct { gf a, b, c; } niels_s, niels_t[1];
typedef struct { niels_t n; gf z; } VECTOR_ALIGNED pniels_s, pniels_t[1];

/* Precomputed base */
struct precomputed_s { niels_t table [COMBS_N<<(COMBS_T-1)]; };

extern const gf API_NS(precomputed_base_as_fe)[];
const precomputed_s *API_NS(precomputed_base) =
    (const precomputed_s *) &API_NS(precomputed_base_as_fe);

/** Inverse. */
static void
gf_invert(gf y, const gf x, int assert_nonzero) {
    gf t1, t2;
    gf_sqr(t1, x); // o^2
    mask_t ret = gf_isr(t2, t1); // +-1/sqrt(o^2) = +-1/o
    (void)ret;
    if (assert_nonzero) assert(ret);
    gf_sqr(t1, t2);
    gf_mul(t2, t1, x); // not direct to y in case of alias.
    gf_copy(y, t2);
}

/** identity = (0,1) */
const point_t API_NS(point_identity) = {{{{{0}}},{{{1}}},{{{1}}},{{{0}}}}};

static DECAF_NOINLINE void
point_double_internal (
    point_t p,
    const point_t q,
    int before_double
) {
    gf a, b, c, d;
    gf_sqr ( c, q->x );
    gf_sqr ( a, q->y );
    gf_add_nr ( d, c, a );             /* 2+e */
    gf_add_nr ( p->t, q->y, q->x );    /* 2+e */
    gf_sqr ( b, p->t );
    gf_subx_nr ( b, b, d, 3 );         /* 4+e */
    gf_sub_nr ( p->t, a, c );          /* 3+e */
    gf_sqr ( p->x, q->z );
    gf_add_nr ( p->z, p->x, p->x );    /* 2+e */
    gf_subx_nr ( a, p->z, p->t, 4 );   /* 6+e */
    if (GF_HEADROOM == 5) gf_weak_reduce(a); /* or 1+e */
    gf_mul ( p->x, a, b );
    gf_mul ( p->z, p->t, a );
    gf_mul ( p->y, p->t, d );
    if (!before_double) gf_mul ( p->t, b, d );
}

void API_NS(point_double)(point_t p, const point_t q) {
    point_double_internal(p,q,0);
}

/* Operations on [p]niels */
static DECAF_INLINE void
cond_neg_niels (
    niels_t n,
    mask_t neg
) {
    gf_cond_swap(n->a, n->b, neg);
    gf_cond_neg(n->c, neg);
}

static DECAF_NOINLINE void pt_to_pniels (
    pniels_t b,
    const point_t a
) {
    gf_sub ( b->n->a, a->y, a->x );
    gf_add ( b->n->b, a->x, a->y );
    gf_mulw ( b->n->c, a->t, 2*TWISTED_D );
    gf_add ( b->z, a->z, a->z );
}

static DECAF_NOINLINE void pniels_to_pt (
    point_t e,
    const pniels_t d
) {
    gf eu;
    gf_add ( eu, d->n->b, d->n->a );
    gf_sub ( e->y, d->n->b, d->n->a );
    gf_mul ( e->t, e->y, eu);
    gf_mul ( e->x, d->z, e->y );
    gf_mul ( e->y, d->z, eu );
    gf_sqr ( e->z, d->z );
}

static DECAF_NOINLINE void
niels_to_pt (
    point_t e,
    const niels_t n
) {
    gf_add ( e->y, n->b, n->a );
    gf_sub ( e->x, n->b, n->a );
    gf_mul ( e->t, e->y, e->x );
    gf_copy ( e->z, ONE );
}

static DECAF_NOINLINE void
add_niels_to_pt (
    point_t d,
    const niels_t e,
    int before_double
) {
    gf a, b, c;
    gf_sub_nr ( b, d->y, d->x ); /* 3+e */
    gf_mul ( a, e->a, b );
    gf_add_nr ( b, d->x, d->y ); /* 2+e */
    gf_mul ( d->y, e->b, b );
    gf_mul ( d->x, e->c, d->t );
    gf_add_nr ( c, a, d->y );    /* 2+e */
    gf_sub_nr ( b, d->y, a );    /* 3+e */
    gf_sub_nr ( d->y, d->z, d->x ); /* 3+e */
    gf_add_nr ( a, d->x, d->z ); /* 2+e */
    gf_mul ( d->z, a, d->y );
    gf_mul ( d->x, d->y, b );
    gf_mul ( d->y, a, c );
    if (!before_double) gf_mul ( d->t, b, c );
}

static DECAF_NOINLINE void
sub_niels_from_pt (
    point_t d,
    const niels_t e,
    int before_double
) {
    gf a, b, c;
    gf_sub_nr ( b, d->y, d->x ); /* 3+e */
    gf_mul ( a, e->b, b );
    gf_add_nr ( b, d->x, d->y ); /* 2+e */
    gf_mul ( d->y, e->a, b );
    gf_mul ( d->x, e->c, d->t );
    gf_add_nr ( c, a, d->y );    /* 2+e */
    gf_sub_nr ( b, d->y, a );    /* 3+e */
    gf_add_nr ( d->y, d->z, d->x ); /* 2+e */
    gf_sub_nr ( a, d->z, d->x ); /* 3+e */
    gf_mul ( d->z, a, d->y );
    gf_mul ( d->x, d->y, b );
    gf_mul ( d->y, a, c );
    if (!before_double) gf_mul ( d->t, b, c );
}

static void
add_pniels_to_pt (
    point_t p,
    const pniels_t pn,
    int before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_copy ( p->z, L0 );
    add_niels_to_pt( p, pn->n, before_double );
}

static void
sub_pniels_from_pt (
    point_t p,
    const pniels_t pn,
    int before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_copy ( p->z, L0 );
    sub_niels_from_pt( p, pn->n, before_double );
}

decaf_bool_t API_NS(point_eq) ( const point_t p, const point_t q ) {
    /* equality mod 2-torsion compares x/y */
    gf a, b;
    gf_mul ( a, p->y, q->x );
    gf_mul ( b, q->y, p->x );
    mask_t succ = gf_eq(a,b);

    return mask_to_bool(succ);
}

decaf_bool_t API_NS(point_valid) (
    const point_t p
) {
    gf a,b,c;
    gf_mul(a,p->x,p->y);
    gf_mul(b,p->z,p->t);
    mask_t out = gf_eq(a,b);
    gf_sqr(a,p->x);
    gf_sqr(b,p->y);
    gf_sub(a,b,a);
    gf_sqr(b,p->t);
    gf_mulw(c,b,TWISTED_D);
    gf_sqr(b,p->z);
    gf_add(b,b,c);
    out &= gf_eq(a,b);
    out &= ~gf_eq(p->z,ZERO);
    return mask_to_bool(out);
}

static DECAF_INLINE void
constant_time_lookup_niels (
    niels_s *__restrict__ ni,
    const niels_t *table,
    int nelts,
    int idx
) {
    constant_time_lookup(ni, table, sizeof(niels_s), nelts, idx);
}

void API_NS(precomputed_scalarmul) (
    point_t out,
    const precomputed_s *table,
    const scalar_t scalar
) {
    int i;
    unsigned j,k;
    const unsigned int n = COMBS_N, t = COMBS_T, s = COMBS_S;
    
    scalar_t scalar1x;
    API_NS(scalar_add)(scalar1x, scalar, precomputed_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar1x,scalar1x);
    
    niels_t ni;
    
    for (i=s-1; i>=0; i--) {
        if (i != (int)s-1) point_double_internal(out,out,0);
        
        for (j=0; j<n; j++) {
            int tab = 0;
         
            for (k=0; k<t; k++) {
                unsigned int bit = i + s*(k + j*t);
                if (bit < SCALAR_BITS) {
                    tab |= (scalar1x->limb[bit/WBITS] >> (bit%WBITS) & 1) << k;
                }
            }
            
            mask_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;

            constant_time_lookup_niels(ni, &table->table[j<<(t-1)], 1<<(t-1), tab);

            cond_neg_niels(ni, invert);
            if ((i!=(int)s-1)||j) {
                add_niels_to_pt(out, ni, j==n-1 && i);
            } else {
                niels_to_pt(out, ni);
            }
        }
    }
    
    OPENSSL_cleanse(ni,sizeof(ni));
    OPENSSL_cleanse(scalar1x,sizeof(scalar1x));
}

void API_NS(point_mul_by_ratio_and_encode_like_eddsa) (
    uint8_t enc[DECAF_EDDSA_448_PUBLIC_BYTES],
    const point_t p
) {
    
    /* The point is now on the twisted curve.  Move it to untwisted. */
    gf x, y, z, t;
    point_t q;
    API_NS(point_copy)(q,p);

    {
        /* 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) */
        gf u;
        gf_sqr ( x, q->x );
        gf_sqr ( t, q->y );
        gf_add( u, x, t );
        gf_add( z, q->y, q->x );
        gf_sqr ( y, z);
        gf_sub ( y, y, u );
        gf_sub ( z, t, x );
        gf_sqr ( x, q->z );
        gf_add ( t, x, x); 
        gf_sub ( t, t, z);
        gf_mul ( x, t, y );
        gf_mul ( y, z, u );
        gf_mul ( z, u, t );
        OPENSSL_cleanse(u,sizeof(u));
    }

    /* Affinize */
    gf_invert(z,z,1);
    gf_mul(t,x,z);
    gf_mul(x,y,z);
    
    /* Encode */
    enc[DECAF_EDDSA_448_PRIVATE_BYTES-1] = 0;
    gf_serialize(enc, x, 1);
    enc[DECAF_EDDSA_448_PRIVATE_BYTES-1] |= 0x80 & gf_lobit(t);

    OPENSSL_cleanse(x,sizeof(x));
    OPENSSL_cleanse(y,sizeof(y));
    OPENSSL_cleanse(z,sizeof(z));
    OPENSSL_cleanse(t,sizeof(t));
    API_NS(point_destroy)(q);
}


decaf_error_t API_NS(point_decode_like_eddsa_and_mul_by_ratio) (
    point_t p,
    const uint8_t enc[DECAF_EDDSA_448_PUBLIC_BYTES]
) {
    uint8_t enc2[DECAF_EDDSA_448_PUBLIC_BYTES];
    memcpy(enc2,enc,sizeof(enc2));

    mask_t low = ~word_is_zero(enc2[DECAF_EDDSA_448_PRIVATE_BYTES-1] & 0x80);
    enc2[DECAF_EDDSA_448_PRIVATE_BYTES-1] &= ~0x80;
    
    mask_t succ = gf_deserialize(p->y, enc2, 1, 0);
#if 0 == 0
    succ &= word_is_zero(enc2[DECAF_EDDSA_448_PRIVATE_BYTES-1]);
#endif

    gf_sqr(p->x,p->y);
    gf_sub(p->z,ONE,p->x); /* num = 1-y^2 */
    gf_mulw(p->t,p->x,EDWARDS_D); /* dy^2 */
    gf_sub(p->t,ONE,p->t); /* denom = 1-dy^2 or 1-d + dy^2 */
    
    gf_mul(p->x,p->z,p->t);
    succ &= gf_isr(p->t,p->x); /* 1/sqrt(num * denom) */
    
    gf_mul(p->x,p->t,p->z); /* sqrt(num / denom) */
    gf_cond_neg(p->x,gf_lobit(p->x)^low);
    gf_copy(p->z,ONE);
  
    {
        /* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
        gf a, b, c, d;
        gf_sqr ( c, p->x );
        gf_sqr ( a, p->y );
        gf_add ( d, c, a );
        gf_add ( p->t, p->y, p->x );
        gf_sqr ( b, p->t );
        gf_sub ( b, b, d );
        gf_sub ( p->t, a, c );
        gf_sqr ( p->x, p->z );
        gf_add ( p->z, p->x, p->x );
        gf_sub ( a, p->z, d );
        gf_mul ( p->x, a, b );
        gf_mul ( p->z, p->t, a );
        gf_mul ( p->y, p->t, d );
        gf_mul ( p->t, b, d );
        OPENSSL_cleanse(a,sizeof(a));
        OPENSSL_cleanse(b,sizeof(b));
        OPENSSL_cleanse(c,sizeof(c));
        OPENSSL_cleanse(d,sizeof(d));
    }
    
    OPENSSL_cleanse(enc2,sizeof(enc2));
    assert(API_NS(point_valid)(p) || ~succ);
    
    return decaf_succeed_if(mask_to_bool(succ));
}

decaf_error_t decaf_x448 (
    uint8_t out[X_PUBLIC_BYTES],
    const uint8_t base[X_PUBLIC_BYTES],
    const uint8_t scalar[X_PRIVATE_BYTES]
) {
    gf x1, x2, z2, x3, z3, t1, t2;
    ignore_result(gf_deserialize(x1,base,1,0));
    gf_copy(x2,ONE);
    gf_copy(z2,ZERO);
    gf_copy(x3,x1);
    gf_copy(z3,ONE);
    
    int t;
    mask_t swap = 0;
    
    for (t = X_PRIVATE_BITS-1; t>=0; t--) {
        uint8_t sb = scalar[t/8];
        
        /* Scalar conditioning */
        if (t/8==0) sb &= -(uint8_t)COFACTOR;
        else if (t == X_PRIVATE_BITS-1) sb = -1;
        
        mask_t k_t = (sb>>(t%8)) & 1;
        k_t = -k_t; /* set to all 0s or all 1s */
        
        swap ^= k_t;
        gf_cond_swap(x2,x3,swap);
        gf_cond_swap(z2,z3,swap);
        swap = k_t;
        
        gf_add_nr(t1,x2,z2); /* A = x2 + z2 */        /* 2+e */
        gf_sub_nr(t2,x2,z2); /* B = x2 - z2 */        /* 3+e */
        gf_sub_nr(z2,x3,z3); /* D = x3 - z3 */        /* 3+e */
        gf_mul(x2,t1,z2);    /* DA */
        gf_add_nr(z2,z3,x3); /* C = x3 + z3 */        /* 2+e */
        gf_mul(x3,t2,z2);    /* CB */
        gf_sub_nr(z3,x2,x3); /* DA-CB */              /* 3+e */
        gf_sqr(z2,z3);       /* (DA-CB)^2 */
        gf_mul(z3,x1,z2);    /* z3 = x1(DA-CB)^2 */
        gf_add_nr(z2,x2,x3); /* (DA+CB) */            /* 2+e */
        gf_sqr(x3,z2);       /* x3 = (DA+CB)^2 */
        
        gf_sqr(z2,t1);       /* AA = A^2 */
        gf_sqr(t1,t2);       /* BB = B^2 */
        gf_mul(x2,z2,t1);    /* x2 = AA*BB */
        gf_sub_nr(t2,z2,t1); /* E = AA-BB */          /* 3+e */
        
        gf_mulw(t1,t2,-EDWARDS_D); /* E*-d = a24*E */
        gf_add_nr(t1,t1,z2); /* AA + a24*E */         /* 2+e */
        gf_mul(z2,t2,t1); /* z2 = E(AA+a24*E) */
    }
    
    /* Finish */
    gf_cond_swap(x2,x3,swap);
    gf_cond_swap(z2,z3,swap);
    gf_invert(z2,z2,0);
    gf_mul(x1,x2,z2);
    gf_serialize(out,x1,1);
    mask_t nz = ~gf_eq(x1,ZERO);
    
    OPENSSL_cleanse(x1,sizeof(x1));
    OPENSSL_cleanse(x2,sizeof(x2));
    OPENSSL_cleanse(z2,sizeof(z2));
    OPENSSL_cleanse(x3,sizeof(x3));
    OPENSSL_cleanse(z3,sizeof(z3));
    OPENSSL_cleanse(t1,sizeof(t1));
    OPENSSL_cleanse(t2,sizeof(t2));
    
    return decaf_succeed_if(mask_to_bool(nz));
}

/* Thanks Johan Pascal */
void decaf_ed448_convert_public_key_to_x448 (
    uint8_t x[DECAF_X448_PUBLIC_BYTES],
    const uint8_t ed[DECAF_EDDSA_448_PUBLIC_BYTES]
) {
    gf y;
    const uint8_t mask = (uint8_t)(0xFE<<(7));
    ignore_result(gf_deserialize(y, ed, 1, mask));
    
    {
        gf n,d;
        
        /* u = y^2 * (1-dy^2) / (1-y^2) */
        gf_sqr(n,y); /* y^2*/
        gf_sub(d,ONE,n); /* 1-y^2*/
        gf_invert(d,d,0); /* 1/(1-y^2)*/
        gf_mul(y,n,d); /* y^2 / (1-y^2) */
        gf_mulw(d,n,EDWARDS_D); /* dy^2*/
        gf_sub(d, ONE, d); /* 1-dy^2*/
        gf_mul(n, y, d); /* y^2 * (1-dy^2) / (1-y^2) */
        gf_serialize(x,n,1);
        
        OPENSSL_cleanse(y,sizeof(y));
        OPENSSL_cleanse(n,sizeof(n));
        OPENSSL_cleanse(d,sizeof(d));
    }
}

void API_NS(point_mul_by_ratio_and_encode_like_x448) (
    uint8_t out[X_PUBLIC_BYTES],
    const point_t p
) {
    point_t q;
    API_NS(point_copy)(q,p);
    gf_invert(q->t,q->x,0); /* 1/x */
    gf_mul(q->z,q->t,q->y); /* y/x */
    gf_sqr(q->y,q->z); /* (y/x)^2 */
    gf_serialize(out,q->y,1);
    API_NS(point_destroy(q));
}

void decaf_x448_derive_public_key (
    uint8_t out[X_PUBLIC_BYTES],
    const uint8_t scalar[X_PRIVATE_BYTES]
) {
    /* Scalar conditioning */
    uint8_t scalar2[X_PRIVATE_BYTES];
    memcpy(scalar2,scalar,sizeof(scalar2));
    scalar2[0] &= -(uint8_t)COFACTOR;
    
    scalar2[X_PRIVATE_BYTES-1] &= ~(-1u<<((X_PRIVATE_BITS+7)%8));
    scalar2[X_PRIVATE_BYTES-1] |= 1<<((X_PRIVATE_BITS+7)%8);
    
    scalar_t the_scalar;
    API_NS(scalar_decode_long)(the_scalar,scalar2,sizeof(scalar2));
    
    /* Compensate for the encoding ratio */
    for (unsigned i=1; i<DECAF_X448_ENCODE_RATIO; i<<=1) {
        API_NS(scalar_halve)(the_scalar,the_scalar);
    }
    point_t p;
    API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),the_scalar);
    API_NS(point_mul_by_ratio_and_encode_like_x448)(out,p);
    API_NS(point_destroy)(p);
}

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int recode_wnaf (
    struct smvt_control *control, /* [nbits/(table_bits+1) + 3] */
    const scalar_t scalar,
    unsigned int table_bits
) {
    unsigned int table_size = SCALAR_BITS/(table_bits+1) + 3;
    int position = table_size - 1; /* at the end */
    
    /* place the end marker */
    control[position].power = -1;
    control[position].addend = 0;
    position--;

    /* PERF: Could negate scalar if it's large.  But then would need more cases
     * in the actual code that uses it, all for an expected reduction of like 1/5 op.
     * Probably not worth it.
     */
    
    uint64_t current = scalar->limb[0] & 0xFFFF;
    uint32_t mask = (1<<(table_bits+1))-1;

    unsigned int w;
    const unsigned int B_OVER_16 = sizeof(scalar->limb[0]) / 2;
    for (w = 1; w<(SCALAR_BITS-1)/16+3; w++) {
        if (w < (SCALAR_BITS-1)/16+1) {
            /* Refill the 16 high bits of current */
            current += (uint32_t)((scalar->limb[w/B_OVER_16]>>(16*(w%B_OVER_16)))<<16);
        }
        
        while (current & 0xFFFF) {
            assert(position >= 0);
            uint32_t pos = __builtin_ctz((uint32_t)current), odd = (uint32_t)current >> pos;
            int32_t delta = odd & mask;
            if (odd & 1<<(table_bits+1)) delta -= (1<<(table_bits+1));
            current -= delta << pos;
            control[position].power = pos + 16*(w-1);
            control[position].addend = delta;
            position--;
        }
        current >>= 16;
    }
    assert(current==0);
    
    position++;
    unsigned int n = table_size - position;
    unsigned int i;
    for (i=0; i<n; i++) {
        control[i] = control[i+position];
    }
    return n-1;
}

static void
prepare_wnaf_table(
    pniels_t *output,
    const point_t working,
    unsigned int tbits
) {
    point_t tmp;
    int i;
    pt_to_pniels(output[0], working);

    if (tbits == 0) return;

    API_NS(point_double)(tmp,working);
    pniels_t twop;
    pt_to_pniels(twop, tmp);

    add_pniels_to_pt(tmp, output[0],0);
    pt_to_pniels(output[1], tmp);

    for (i=2; i < 1<<tbits; i++) {
        add_pniels_to_pt(tmp, twop,0);
        pt_to_pniels(output[i], tmp);
    }
    
    API_NS(point_destroy)(tmp);
    OPENSSL_cleanse(twop,sizeof(twop));
}

extern const gf API_NS(precomputed_wnaf_as_fe)[];
static const niels_t *API_NS(wnaf_base) = (const niels_t *)API_NS(precomputed_wnaf_as_fe);

void API_NS(base_double_scalarmul_non_secret) (
    point_t combo,
    const scalar_t scalar1,
    const point_t base2,
    const scalar_t scalar2
) {
    const int table_bits_var = DECAF_WNAF_VAR_TABLE_BITS,
        table_bits_pre = DECAF_WNAF_FIXED_TABLE_BITS;
    struct smvt_control control_var[SCALAR_BITS/(table_bits_var+1)+3];
    struct smvt_control control_pre[SCALAR_BITS/(table_bits_pre+1)+3];
    
    int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
    int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  
    pniels_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, base2, table_bits_var);
  
    int contp=0, contv=0, i = control_var[0].power;

    if (i < 0) {
        API_NS(point_copy)(combo, API_NS(point_identity));
        return;
    } else if (i > control_pre[0].power) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1], i);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1]);
        contp++;
    }
    
    for (i--; i >= 0; i--) {
        int cv = (i==control_var[contv].power), cp = (i==control_pre[contp].power);
        point_double_internal(combo,combo,i && !(cv||cp));

        if (cv) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                add_pniels_to_pt(combo, precmp_var[control_var[contv].addend >> 1], i&&!cp);
            } else {
                sub_pniels_from_pt(combo, precmp_var[(-control_var[contv].addend) >> 1], i&&!cp);
            }
            contv++;
        }

        if (cp) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[contp].addend >> 1], i);
            } else {
                sub_niels_from_pt(combo, API_NS(wnaf_base)[(-control_pre[contp].addend) >> 1], i);
            }
            contp++;
        }
    }
    
    /* This function is non-secret, but whatever this is cheap. */
    OPENSSL_cleanse(control_var,sizeof(control_var));
    OPENSSL_cleanse(control_pre,sizeof(control_pre));
    OPENSSL_cleanse(precmp_var,sizeof(precmp_var));

    assert(contv == ncb_var); (void)ncb_var;
    assert(contp == ncb_pre); (void)ncb_pre;
}

void API_NS(point_destroy) (
    point_t point
) {
    OPENSSL_cleanse(point, sizeof(point_t));
}

int X448(uint8_t out_shared_key[56], const uint8_t private_key[56],
         const uint8_t peer_public_value[56])
{
  return decaf_x448(out_shared_key, peer_public_value, private_key)
         == DECAF_SUCCESS;
}

void X448_public_from_private(uint8_t out_public_value[56],
                              const uint8_t private_key[56])
{
    decaf_x448_derive_public_key(out_public_value, private_key);
}
