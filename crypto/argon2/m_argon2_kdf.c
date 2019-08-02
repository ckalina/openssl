/*
 * Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Argon 2 KDF
 *
 * Argon2 implementation derived from the Argon2 reference implementation
 * written by Daniel Dinu et al.
 *
 * https://github.com/P-H-C/phc-winner-argon2
 *
 * Argon2 reference implementation is distributed under one of the two
 * licenses (and hence compatible with OpenSSL license):
 *
 * CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * For the latest RFC candidate, see:
 * https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/
 *
 */

#ifndef OPENSSL_NO_ARGON2

#include <internal/cryptlib.h>
#include <internal/evp_int.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/kdferr.h>
#include <openssl/objects.h>

#include "argon2.h"
//#include "core.h"

struct evp_kdf_impl_st {
    argon2_context ctx;
};

static int kdf_argon2_init(EVP_KDF_IMPL *impl, argon2_type t)
{
    return ARGON2_Init(&impl->ctx, t);
}

static EVP_KDF_IMPL * kdf_argon2d_new(void)
{
    EVP_KDF_IMPL *impl = OPENSSL_zalloc(sizeof(*impl));

    if (impl == NULL) {
        KDFerr(KDF_F_KDF_ARGON2_NEW, ERR_R_MALLOC_FAILURE);
	return NULL;
    }

    if (kdf_argon2_init(impl, Argon2_d) != 1) {
	KDFerr(KDF_F_KDF_ARGON2_NEW, KDF_R_NOT_SUPPORTED);
	return NULL;
    }

    return impl;
}

static EVP_KDF_IMPL * kdf_argon2i_new(void)
{
    EVP_KDF_IMPL *impl = OPENSSL_zalloc(sizeof(*impl));

    if (impl == NULL) {
        KDFerr(KDF_F_KDF_ARGON2_NEW, ERR_R_MALLOC_FAILURE);
	return NULL;
    }

    if (kdf_argon2_init(impl, Argon2_i) != 1) {
	KDFerr(KDF_F_KDF_ARGON2_NEW, KDF_R_NOT_SUPPORTED);
	return NULL;
    }

    return impl;
}

static EVP_KDF_IMPL * kdf_argon2id_new(void)
{
    EVP_KDF_IMPL *impl = OPENSSL_zalloc(sizeof(*impl));

    if (impl == NULL) {
        KDFerr(KDF_F_KDF_ARGON2_NEW, ERR_R_MALLOC_FAILURE);
	return NULL;
    }

    if (kdf_argon2_init(impl, Argon2_id) != 1) {
	KDFerr(KDF_F_KDF_ARGON2_NEW, KDF_R_NOT_SUPPORTED);
	return NULL;
    }

    return impl;
}

static void kdf_argon2_reset(EVP_KDF_IMPL *impl)
{
    if (impl == NULL)
	return;

    argon2_context *ctx = (argon2_context *) impl;

    argon2_type type = ctx->type;
    deallocate_fptr free_fn = NULL;

    if (ctx->free_cbk == NULL)
	free_fn = ossl_dealloc;
    else
	free_fn = ctx->free_cbk;

    if (ctx->outlen && ctx->out)
	free_fn(ctx->out, ctx->outlen);

    if (ctx->pwdlen && ctx->pwd)
	free_fn(ctx->pwd, ctx->pwdlen);

    if (ctx->saltlen && ctx->salt)
	free_fn(ctx->salt, ctx->saltlen);

    if (ctx->secretlen && ctx->secret)
	free_fn(ctx->secret, ctx->secretlen);

    if (ctx->adlen && ctx->ad)
	free_fn(ctx->ad, ctx->adlen);

    memset(impl, 0, sizeof(*impl));
    kdf_argon2_init(impl, type);
}


static void kdf_argon2_free(EVP_KDF_IMPL *impl)
{
    if (impl == NULL)
	return;

    kdf_argon2_reset(impl);
    OPENSSL_free(impl);
}

static int kdf_argon2_ctx_set_threads(argon2_context *ctx, uint32_t threads)
{
    if (threads > ARGON2_MAX_THREADS || threads < ARGON2_MIN_THREADS) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    ctx->threads = threads;
    return 1;
}


static int kdf_argon2_ctx_set_lanes(argon2_context *ctx, uint32_t lanes)
{
    if (lanes > ARGON2_MAX_LANES || lanes < ARGON2_MIN_LANES) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    ctx->lanes = lanes;
    return 1;
}

static int kdf_argon2_ctx_set_t_cost(argon2_context *ctx, uint32_t t_cost)
{
    if (t_cost < ARGON2_MIN_TIME || t_cost > ARGON2_MAX_TIME) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    ctx->t_cost = t_cost;
    return 1;
}

static int kdf_argon2_ctx_set_m_cost(argon2_context *ctx, uint32_t m_cost)
{
    if (m_cost < ARGON2_MIN_MEMORY || m_cost > ARGON2_MAX_MEMORY) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    ctx->m_cost = m_cost;
    return 1;
}

static int kdf_argon2_ctx_set_digest_length(argon2_context *ctx,
					    uint32_t hashlen)
{
    if (hashlen < ARGON2_MIN_PWD_LENGTH || hashlen > ARGON2_MAX_PWD_LENGTH) {
	KDFerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_WRONG_OUTPUT_BUFFER_SIZE);
	return 0;
    }

    ctx->outlen = hashlen;
    return 1;
}

static int kdf_argon2_ctx_set_secret(argon2_context *ctx, uint8_t *secret,
				     uint32_t secretlen)
{
    if (secretlen < ARGON2_MIN_SECRET || secretlen > ARGON2_MAX_SECRET) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    if (ctx->pwd != NULL) {
	ctx->free_cbk(ctx->secret, ctx->secretlen);
    }

    ctx->secretlen = secretlen;
    ctx->allocate_cbk(&ctx->secret, ctx->secretlen);

    memcpy(ctx->secret, secret, ctx->secretlen);
    return 1;
}

static int kdf_argon2_ctx_set_pwd(argon2_context *ctx, uint8_t *pwd,
				  uint32_t pwdlen)
{
    if (pwdlen < ARGON2_MIN_PWD_LENGTH || pwdlen > ARGON2_MAX_PWD_LENGTH) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    if (ctx->pwd != NULL) {
	ctx->free_cbk(ctx->pwd, ctx->pwdlen);
    }

    ctx->pwdlen = pwdlen;
    ctx->allocate_cbk(&ctx->pwd, ctx->pwdlen);

    memcpy(ctx->pwd, pwd, ctx->pwdlen);
    return 1;
}

static int kdf_argon2_ctx_set_salt(argon2_context *ctx, uint8_t *salt,
			uint32_t saltlen)
{
    if (saltlen < ARGON2_MIN_SALT_LENGTH || saltlen > ARGON2_MAX_SALT_LENGTH) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    if (ctx->salt != NULL) {
	ctx->free_cbk(ctx->salt, ctx->saltlen);
    }

    ctx->saltlen = saltlen;
    ctx->allocate_cbk(&ctx->salt, ctx->saltlen);

    memcpy(ctx->salt, salt, ctx->saltlen);
    return 1;
}

static int kdf_argon2_ctx_set_ad(argon2_context *ctx, uint8_t *ad, uint32_t adlen)
{
    if (adlen < ARGON2_MIN_AD_LENGTH || adlen > ARGON2_MAX_AD_LENGTH) {
	EVPerr(KDF_F_KDF_ARGON2_CTRL, KDF_R_VALUE_ERROR);
	return 0;
    }

    if (ctx->ad != NULL) {
	ctx->free_cbk(ctx->ad, ctx->adlen);
    }

    ctx->adlen = adlen;
    ctx->allocate_cbk(&ctx->ad, ctx->adlen);

    memcpy(ctx->salt, ad, ctx->adlen);
    return 1;
}

static void kdf_argon2_ctx_set_flags(argon2_context *ctx, uint32_t flags)
{
    ctx->flags = flags;
}

static int kdf_argon2_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    uint32_t len;
    uint8_t *buf;
    uint32_t p;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_ARGON2_SIZE:
        len = va_arg(args, size_t);
        return kdf_argon2_ctx_set_digest_length(&impl->ctx, len);
    case EVP_KDF_CTRL_SET_ITER:
        p = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_t_cost(&impl->ctx, p);
    case EVP_KDF_CTRL_SET_PASS:
        buf = va_arg(args, uint8_t *);
        len = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_pwd(&impl->ctx, buf, len);
    case EVP_KDF_CTRL_SET_ARGON2_SECRET:
        buf = va_arg(args, uint8_t *);
        len = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_secret(&impl->ctx, buf, len);
    case EVP_KDF_CTRL_SET_SALT:
        buf = va_arg(args, uint8_t *);
        len = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_salt(&impl->ctx, buf, len);
    case EVP_KDF_CTRL_SET_ARGON2_THREADS:
        p = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_threads(&impl->ctx, p);
    case EVP_KDF_CTRL_SET_ARGON2_LANES:
        p = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_lanes(&impl->ctx, p);
    case EVP_KDF_CTRL_SET_ARGON2_MEM_COST:
        p = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_m_cost(&impl->ctx, p);
    case EVP_KDF_CTRL_SET_ARGON2_AD:
        buf = va_arg(args, uint8_t *);
        p = va_arg(args, uint32_t);
        return kdf_argon2_ctx_set_ad(&impl->ctx, buf, p);
    case EVP_KDF_CTRL_SET_ARGON2_FLAGS:
        p = va_arg(args, uint32_t);
        kdf_argon2_ctx_set_flags(&impl->ctx, p);
	return 1;
    case EVP_KDF_CTRL_SET_MD:
        // Blake2b is the only message digest supported by the Argon2 KDF.
	return 0;
    default:
        return 0;
    }
}

static int kdf_argon2_derive(EVP_KDF_IMPL *impl, unsigned char *key,
			     size_t keylen)
{
    argon2_context *ctx = (argon2_context *) impl;

    if (ctx->pwd == NULL || ctx->pwdlen == 0) {
        KDFerr(KDF_F_KDF_ARGON2_DERIVE, KDF_R_MISSING_PASS);
        return 0;
    }

    if (ctx->salt == NULL || ctx->saltlen == 0) {
        KDFerr(KDF_F_KDF_ARGON2_DERIVE, KDF_R_MISSING_SALT);
        return 0;
    }

    if (keylen != ctx->outlen) {
	kdf_argon2_ctx_set_digest_length(ctx, keylen);
    }

    int ret = ARGON2_Update(ctx, ctx->pwd, ctx->pwdlen);
    if (ret != 1) {
	KDFerr(KDF_F_KDF_ARGON2_DERIVE, KDF_R_VALUE_ERROR);
	return ret;
    }

    memcpy(key, ctx->out, keylen);
    return 1;
}

const EVP_KDF argon2d_kdf_meth = {
    EVP_KDF_ARGON2D,
    kdf_argon2d_new,
    kdf_argon2_free,
    kdf_argon2_reset,
    kdf_argon2_ctrl,
    NULL,
    NULL,
    kdf_argon2_derive
};

const EVP_KDF argon2i_kdf_meth = {
    EVP_KDF_ARGON2I,
    kdf_argon2i_new,
    kdf_argon2_free,
    kdf_argon2_reset,
    kdf_argon2_ctrl,
    NULL,
    NULL,
    kdf_argon2_derive
};

const EVP_KDF argon2id_kdf_meth = {
    EVP_KDF_ARGON2ID,
    kdf_argon2id_new,
    kdf_argon2_free,
    kdf_argon2_reset,
    kdf_argon2_ctrl,
    NULL,
    NULL,
    kdf_argon2_derive
};

#endif
