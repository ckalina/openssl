/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_locl.h"
#include "internal/ciphers/cipher_tdes.h"
#include "internal/rand_int.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"

void *tdes_newctx(void *provctx, int mode, size_t kbits, size_t blkbits,
                  size_t ivbits, const PROV_CIPHER_HW *hw)
{
    PROV_TDES_CTX *tctx = OPENSSL_zalloc(sizeof(*tctx));

    if (tctx != NULL)
        cipher_generic_initkey(tctx, kbits, blkbits, ivbits, mode, hw, provctx);
    return tctx;
}

void tdes_freectx(void *vctx)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static int tdes_init(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen, int enc)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;

    ctx->enc = enc;

    if (iv != NULL) {
        if (ivlen != TDES_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IVLEN);
            return 0;
        }
        memcpy(ctx->iv, iv, TDES_IVLEN);
    }

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEYLEN);
            return 0;
        }
        return ctx->hw->init(ctx, key, ctx->keylen);
    }
    return 1;
}

int tdes_einit(void *vctx, const unsigned char *key, size_t keylen,
               const unsigned char *iv, size_t ivlen)
{
    return tdes_init(vctx, key, keylen, iv, ivlen, 1);
}

int tdes_dinit(void *vctx, const unsigned char *key, size_t keylen,
               const unsigned char *iv, size_t ivlen)
{
    return tdes_init(vctx, key, keylen, iv, ivlen, 0);
}

static int tdes_generatekey(PROV_CIPHER_CTX *ctx, void *ptr)
{

    DES_cblock *deskey = ptr;
    size_t kl = ctx->keylen;

    if (kl == 0 || rand_priv_bytes_ex(ctx->libctx, ptr, kl) <= 0)
        return 0;
    DES_set_odd_parity(deskey);
    if (kl >= 16)
        DES_set_odd_parity(deskey + 1);
    if (kl >= 24) {
        DES_set_odd_parity(deskey + 2);
        return 1;
    }
    return 0;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(tdes)
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY, NULL, 0),
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(tdes)

int tdes_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CIPHER_CTX  *ctx = (PROV_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    if (!cipher_generic_get_ctx_params(vctx, params))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RANDOM_KEY);
    if (p != NULL && !tdes_generatekey(ctx, p->data)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }
    return 1;
}

/*
 * TODO(3.0) - ECB mode does not use an IV - but existing test code is setting
 * an IV. Fixing this could potentially make applications break.
 */

/* tdes_ede3_ecb_functions */
IMPLEMENT_tdes_cipher(ede3, EDE3, ecb, ECB, TDES_FLAGS, 64*3, 64, 64, block);
/* tdes_ede3_cbc_functions */
IMPLEMENT_tdes_cipher(ede3, EDE3, cbc, CBC, TDES_FLAGS, 64*3, 64, 64, block);
