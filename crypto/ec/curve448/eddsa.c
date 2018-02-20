/**
 * @file ed448goldilocks/eddsa.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @cond internal
 * @brief EdDSA routines.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "curve448_lcl.h"
#include "word.h"
#include "ed448.h"
#include <string.h>
#include "internal/numbers.h"

#define API_NAME "decaf_448"

#define NO_CONTEXT DECAF_EDDSA_448_SUPPORTS_CONTEXTLESS_SIGS
#define EDDSA_USE_SIGMA_ISOGENY 0
#define COFACTOR 4
#define EDDSA_PREHASH_BYTES 64

#if NO_CONTEXT
const uint8_t NO_CONTEXT_POINTS_HERE = 0;
const uint8_t * const DECAF_ED448_NO_CONTEXT = &NO_CONTEXT_POINTS_HERE;
#endif

/* EDDSA_BASE_POINT_RATIO = 1 or 2
 * Because EdDSA25519 is not on E_d but on the isogenous E_sigma_d,
 * its base point is twice ours.
 */
#define EDDSA_BASE_POINT_RATIO (1+EDDSA_USE_SIGMA_ISOGENY) /* TODO: remove */

static decaf_error_t oneshot_hash(uint8_t *out, size_t outlen,
                                  const uint8_t *in, size_t inlen)
{
    EVP_MD_CTX *hashctx = EVP_MD_CTX_new();

    if (hashctx == NULL)
        return DECAF_FAILURE;

    if (!EVP_DigestInit_ex(hashctx, EVP_shake256(), NULL)
            || !EVP_DigestUpdate(hashctx, in, inlen)
            || !EVP_DigestFinalXOF(hashctx, out, outlen)) {
        EVP_MD_CTX_free(hashctx);
        return DECAF_FAILURE;
    }

    EVP_MD_CTX_free(hashctx);
    return DECAF_SUCCESS;
}


static void clamp (
    uint8_t secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    uint8_t hibit = (1<<0)>>1;

    /* Blarg */
    secret_scalar_ser[0] &= -COFACTOR;
    if (hibit == 0) {
        secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES - 1] = 0;
        secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES - 2] |= 0x80;
    } else {
        secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES - 1] &= hibit-1;
        secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES - 1] |= hibit;
    }
}

static decaf_error_t hash_init_with_dom(
    EVP_MD_CTX *hashctx,
    uint8_t prehashed,
    uint8_t for_prehash,
    const uint8_t *context,
    size_t context_len
) {
    const char *dom_s = "SigEd448";
    uint8_t dom[2];

    dom[0] = 2 + word_is_zero(prehashed) + word_is_zero(for_prehash);
    dom[1] = (uint8_t)context_len;

    if (context_len > UINT8_MAX)
        return DECAF_FAILURE;

#if NO_CONTEXT
    if (context_len == 0 && context == DECAF_ED448_NO_CONTEXT) {
        (void)prehashed;
        (void)for_prehash;
        (void)context;
        (void)context_len;
        return DECAF_SUCCESS;
    }
#endif

    if (!EVP_DigestInit_ex(hashctx, EVP_shake256(), NULL)
            || !EVP_DigestUpdate(hashctx, dom_s, strlen(dom_s))
            || !EVP_DigestUpdate(hashctx, dom, sizeof(dom))
            || !EVP_DigestUpdate(hashctx, context, context_len))
        return DECAF_FAILURE;

    return DECAF_SUCCESS;
}

/* In this file because it uses the hash */
decaf_error_t decaf_ed448_convert_private_key_to_x448 (
    uint8_t x[DECAF_X448_PRIVATE_BYTES],
    const uint8_t ed[DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    /* pass the private key through oneshot_hash function */
    /* and keep the first DECAF_X448_PRIVATE_BYTES bytes */
    return oneshot_hash(
        x,
        DECAF_X448_PRIVATE_BYTES,
        ed,
        DECAF_EDDSA_448_PRIVATE_BYTES
    );
}
    
decaf_error_t decaf_ed448_derive_public_key (
    uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    /* only this much used for keygen */
    uint8_t secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES];
    curve448_scalar_t secret_scalar;
    unsigned int c;
    curve448_point_t p;

    if (!oneshot_hash(secret_scalar_ser, sizeof(secret_scalar_ser), privkey,
                      DECAF_EDDSA_448_PRIVATE_BYTES)) {
        return DECAF_FAILURE;
    }
    clamp(secret_scalar_ser);

    curve448_scalar_decode_long(secret_scalar, secret_scalar_ser, sizeof(secret_scalar_ser));
    
    /* Since we are going to mul_by_cofactor during encoding, divide by it here.
     * However, the EdDSA base point is not the same as the decaf base point if
     * the sigma isogeny is in use: the EdDSA base point is on Etwist_d/(1-d) and
     * the decaf base point is on Etwist_d, and when converted it effectively
     * picks up a factor of 2 from the isogenies.  So we might start at 2 instead of 1. 
     */
    for (c=1; c<DECAF_448_EDDSA_ENCODE_RATIO; c <<= 1) {
        curve448_scalar_halve(secret_scalar,secret_scalar);
    }
    
    curve448_precomputed_scalarmul(p,curve448_precomputed_base,secret_scalar);
    
    curve448_point_mul_by_ratio_and_encode_like_eddsa(pubkey, p);
        
    /* Cleanup */
    curve448_scalar_destroy(secret_scalar);
    curve448_point_destroy(p);
    OPENSSL_cleanse(secret_scalar_ser, sizeof(secret_scalar_ser));

    return DECAF_SUCCESS;
}

decaf_error_t decaf_ed448_sign (
    uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    size_t context_len
) {
    curve448_scalar_t secret_scalar;
    EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
    decaf_error_t ret = DECAF_FAILURE;
    curve448_scalar_t nonce_scalar;
    uint8_t nonce_point[DECAF_EDDSA_448_PUBLIC_BYTES] = {0};
    unsigned int c;
    curve448_scalar_t challenge_scalar;

    if (hashctx == NULL)
        return DECAF_FAILURE;

    {
        /* Schedule the secret key */
        struct {
            uint8_t secret_scalar_ser[DECAF_EDDSA_448_PRIVATE_BYTES];
            uint8_t seed[DECAF_EDDSA_448_PRIVATE_BYTES];
        } __attribute__((packed)) expanded;

        if (!oneshot_hash((uint8_t *)&expanded, sizeof(expanded), privkey,
                          DECAF_EDDSA_448_PRIVATE_BYTES))
            goto err;
        clamp(expanded.secret_scalar_ser);   
        curve448_scalar_decode_long(secret_scalar, expanded.secret_scalar_ser, sizeof(expanded.secret_scalar_ser));
    
        /* Hash to create the nonce */
        if (!hash_init_with_dom(hashctx, prehashed, 0, context, context_len)
                || !EVP_DigestUpdate(hashctx, expanded.seed,
                                     sizeof(expanded.seed))
                || !EVP_DigestUpdate(hashctx, message, message_len)) {
            OPENSSL_cleanse(&expanded, sizeof(expanded));
            goto err;
        }
        OPENSSL_cleanse(&expanded, sizeof(expanded));
    }
    
    /* Decode the nonce */
    {
        uint8_t nonce[2*DECAF_EDDSA_448_PRIVATE_BYTES];

        if (!EVP_DigestFinalXOF(hashctx, nonce, sizeof(nonce)))
            goto err;
        curve448_scalar_decode_long(nonce_scalar, nonce, sizeof(nonce));
        OPENSSL_cleanse(nonce, sizeof(nonce));
    }

    {
        /* Scalarmul to create the nonce-point */
        curve448_scalar_t nonce_scalar_2;
        curve448_point_t p;

        curve448_scalar_halve(nonce_scalar_2,nonce_scalar);
        for (c = 2; c < DECAF_448_EDDSA_ENCODE_RATIO; c <<= 1) {
            curve448_scalar_halve(nonce_scalar_2,nonce_scalar_2);
        }

        curve448_precomputed_scalarmul(p,curve448_precomputed_base,nonce_scalar_2);
        curve448_point_mul_by_ratio_and_encode_like_eddsa(nonce_point, p);
        curve448_point_destroy(p);
        curve448_scalar_destroy(nonce_scalar_2);
    }

    {
        uint8_t challenge[2*DECAF_EDDSA_448_PRIVATE_BYTES];

        /* Compute the challenge */
        if (!hash_init_with_dom(hashctx, prehashed, 0, context, context_len)
                || !EVP_DigestUpdate(hashctx, nonce_point, sizeof(nonce_point))
                || !EVP_DigestUpdate(hashctx, pubkey,
                                     DECAF_EDDSA_448_PUBLIC_BYTES)
                || !EVP_DigestUpdate(hashctx, message, message_len)
                || !EVP_DigestFinalXOF(hashctx, challenge, sizeof(challenge)))
            goto err;

        curve448_scalar_decode_long(challenge_scalar,challenge,sizeof(challenge));
        OPENSSL_cleanse(challenge,sizeof(challenge));
    }
    
    curve448_scalar_mul(challenge_scalar,challenge_scalar,secret_scalar);
    curve448_scalar_add(challenge_scalar,challenge_scalar,nonce_scalar);
    
    OPENSSL_cleanse(signature,DECAF_EDDSA_448_SIGNATURE_BYTES);
    memcpy(signature,nonce_point,sizeof(nonce_point));
    curve448_scalar_encode(&signature[DECAF_EDDSA_448_PUBLIC_BYTES],challenge_scalar);
    
    curve448_scalar_destroy(secret_scalar);
    curve448_scalar_destroy(nonce_scalar);
    curve448_scalar_destroy(challenge_scalar);

    ret = DECAF_SUCCESS;
 err:
    EVP_MD_CTX_free(hashctx);
    return ret;
}


decaf_error_t decaf_ed448_sign_prehash (
    uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t hash[64],
    const uint8_t *context,
    size_t context_len
) {
    return decaf_ed448_sign(signature,privkey,pubkey,hash,64,1,context,
                            context_len);
    /*OPENSSL_cleanse(hash,sizeof(hash));*/
}

decaf_error_t decaf_ed448_verify (
    const uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) { 
    curve448_point_t pk_point, r_point;
    decaf_error_t error = curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point,pubkey);
    curve448_scalar_t challenge_scalar;
    curve448_scalar_t response_scalar;
    unsigned int c;

    if (DECAF_SUCCESS != error) { return error; }
    
    error = curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point,signature);
    if (DECAF_SUCCESS != error) { return error; }
    
    {
        /* Compute the challenge */
        EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
        uint8_t challenge[2*DECAF_EDDSA_448_PRIVATE_BYTES];

        if (hashctx == NULL
                || !hash_init_with_dom(hashctx, prehashed, 0, context,
                                       context_len)
                || !EVP_DigestUpdate(hashctx, signature,
                                     DECAF_EDDSA_448_PUBLIC_BYTES)
                || !EVP_DigestUpdate(hashctx, pubkey,
                                     DECAF_EDDSA_448_PUBLIC_BYTES)
                || !EVP_DigestUpdate(hashctx, message, message_len)
                || !EVP_DigestFinalXOF(hashctx, challenge, sizeof(challenge))) {
            EVP_MD_CTX_free(hashctx);
            return DECAF_FAILURE;
        }

        EVP_MD_CTX_free(hashctx);
        curve448_scalar_decode_long(challenge_scalar,challenge,sizeof(challenge));
        OPENSSL_cleanse(challenge,sizeof(challenge));
    }
    curve448_scalar_sub(challenge_scalar, curve448_scalar_zero, challenge_scalar);

    curve448_scalar_decode_long(
        response_scalar,
        &signature[DECAF_EDDSA_448_PUBLIC_BYTES],
        DECAF_EDDSA_448_PRIVATE_BYTES
    );
    
    for (c=1; c<DECAF_448_EDDSA_DECODE_RATIO; c<<=1) {
        curve448_scalar_add(response_scalar,response_scalar,response_scalar);
    }
    
    
    /* pk_point = -c(x(P)) + (cx + k)G = kG */
    curve448_base_double_scalarmul_non_secret(
        pk_point,
        response_scalar,
        pk_point,
        challenge_scalar
    );
    return decaf_succeed_if(curve448_point_eq(pk_point,r_point));
}


decaf_error_t decaf_ed448_verify_prehash (
    const uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t hash[64],
    const uint8_t *context,
    uint8_t context_len
) {
    decaf_error_t ret;
    
    ret = decaf_ed448_verify(signature,pubkey,hash,64,1,context,context_len);
    
    return ret;
}

int ED448_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
               const uint8_t public_key[57], const uint8_t private_key[57],
               const uint8_t *context, size_t context_len)
{

    return decaf_ed448_sign(out_sig, private_key, public_key, message,
                            message_len, 0, context, context_len)
                            == DECAF_SUCCESS;
}


int ED448_verify(const uint8_t *message, size_t message_len,
                 const uint8_t signature[114], const uint8_t public_key[57],
                 const uint8_t *context, size_t context_len)
{
    return decaf_ed448_verify(signature, public_key, message, message_len, 0,
                              context, context_len) == DECAF_SUCCESS;
}

int ED448ph_sign(uint8_t *out_sig, const uint8_t hash[64],
                 const uint8_t public_key[57], const uint8_t private_key[57],
                 const uint8_t *context, size_t context_len)
{
    return decaf_ed448_sign_prehash(out_sig, private_key, public_key, hash,
                                    context, context_len) == DECAF_SUCCESS;

}

int ED448ph_verify(const uint8_t hash[64], const uint8_t signature[114],
                   const uint8_t public_key[57], const uint8_t *context,
                   size_t context_len)
{
    return decaf_ed448_verify_prehash(signature, public_key, hash, context,
                                      context_len) == DECAF_SUCCESS;
}

int ED448_public_from_private(uint8_t out_public_key[57],
                               const uint8_t private_key[57])
{
    return decaf_ed448_derive_public_key(out_public_key, private_key)
           == DECAF_SUCCESS;
}
