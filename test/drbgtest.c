/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../crypto/rand/rand_lcl.h"
#include "../crypto/include/internal/rand_int.h"

#if defined(_WIN32)
# include <windows.h>
#endif

#include "testutil.h"
#include "drbgtest.h"

typedef struct drbg_selftest_data_st {
    int post;
    int nid;
    unsigned int flags;

    /* KAT data for no PR */
    const unsigned char *entropy;
    size_t entropylen;
    const unsigned char *nonce;
    size_t noncelen;
    const unsigned char *pers;
    size_t perslen;
    const unsigned char *adin;
    size_t adinlen;
    const unsigned char *entropyreseed;
    size_t entropyreseedlen;
    const unsigned char *adinreseed;
    size_t adinreseedlen;
    const unsigned char *adin2;
    size_t adin2len;
    const unsigned char *expected;
    size_t exlen;
    const unsigned char *kat2;
    size_t kat2len;

    /* KAT data for PR */
    const unsigned char *entropy_pr;
    size_t entropylen_pr;
    const unsigned char *nonce_pr;
    size_t noncelen_pr;
    const unsigned char *pers_pr;
    size_t perslen_pr;
    const unsigned char *adin_pr;
    size_t adinlen_pr;
    const unsigned char *entropypr_pr;
    size_t entropyprlen_pr;
    const unsigned char *ading_pr;
    size_t adinglen_pr;
    const unsigned char *entropyg_pr;
    size_t entropyglen_pr;
    const unsigned char *kat_pr;
    size_t katlen_pr;
    const unsigned char *kat2_pr;
    size_t kat2len_pr;
} DRBG_SELFTEST_DATA;

#define make_drbg_test_data(nid, flag, pr, post) {\
    post, nid, flag, \
    pr##_entropyinput, sizeof(pr##_entropyinput), \
    pr##_nonce, sizeof(pr##_nonce), \
    pr##_personalizationstring, sizeof(pr##_personalizationstring), \
    pr##_additionalinput, sizeof(pr##_additionalinput), \
    pr##_entropyinputreseed, sizeof(pr##_entropyinputreseed), \
    pr##_additionalinputreseed, sizeof(pr##_additionalinputreseed), \
    pr##_additionalinput2, sizeof(pr##_additionalinput2), \
    pr##_int_returnedbits, sizeof(pr##_int_returnedbits), \
    pr##_returnedbits, sizeof(pr##_returnedbits), \
    pr##_pr_entropyinput, sizeof(pr##_pr_entropyinput), \
    pr##_pr_nonce, sizeof(pr##_pr_nonce), \
    pr##_pr_personalizationstring, sizeof(pr##_pr_personalizationstring), \
    pr##_pr_additionalinput, sizeof(pr##_pr_additionalinput), \
    pr##_pr_entropyinputpr, sizeof(pr##_pr_entropyinputpr), \
    pr##_pr_additionalinput2, sizeof(pr##_pr_additionalinput2), \
    pr##_pr_entropyinputpr2, sizeof(pr##_pr_entropyinputpr2), \
    pr##_pr_int_returnedbits, sizeof(pr##_pr_int_returnedbits), \
    pr##_pr_returnedbits, sizeof(pr##_pr_returnedbits) \
    }

#define make_drbg_test_data_use_df(nid, pr, p) \
    make_drbg_test_data(nid, 0, pr, p)

#define make_drbg_test_data_no_df(nid, pr, p)                      \
    make_drbg_test_data(nid, RAND_DRBG_FLAG_CTR_NO_DF, pr, p)

#define make_drbg_test_data_hash(nid, pr, p) \
    make_drbg_test_data(nid, RAND_DRBG_FLAG_HMAC, hmac_##pr, p), \
    make_drbg_test_data(nid, 0, pr, p)

static DRBG_SELFTEST_DATA drbg_test[] = {
#ifndef FIPS_MODE
    /* FIPS mode doesn't support CTR DRBG without a derivation function */
    make_drbg_test_data_no_df (NID_aes_128_ctr, aes_128_no_df,  0),
    make_drbg_test_data_no_df (NID_aes_192_ctr, aes_192_no_df,  0),
    make_drbg_test_data_no_df (NID_aes_256_ctr, aes_256_no_df,  1),
#endif
    make_drbg_test_data_use_df(NID_aes_128_ctr, aes_128_use_df, 0),
    make_drbg_test_data_use_df(NID_aes_192_ctr, aes_192_use_df, 0),
    make_drbg_test_data_use_df(NID_aes_256_ctr, aes_256_use_df, 1),
    make_drbg_test_data_hash(NID_sha1, sha1, 0),
    make_drbg_test_data_hash(NID_sha224, sha224, 0),
    make_drbg_test_data_hash(NID_sha256, sha256, 1),
    make_drbg_test_data_hash(NID_sha384, sha384, 0),
    make_drbg_test_data_hash(NID_sha512, sha512, 0),
};

static int app_data_index;

/*
 * Test context data, attached as EXDATA to the RAND_DRBG
 */
typedef struct test_ctx_st {
    const unsigned char *entropy;
    size_t entropylen;
    int entropycnt;
    const unsigned char *nonce;
    size_t noncelen;
    int noncecnt;
} TEST_CTX;

static size_t kat_entropy(RAND_DRBG *drbg, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len,
                          int prediction_resistance)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t kat_nonce(RAND_DRBG *drbg, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

 /*
 * Disable CRNG testing if it is enabled.
 * If the DRBG is ready or in an error state, this means an instantiate cycle
 * for which the default personalisation string is used.
 */
static int disable_crngt(RAND_DRBG *drbg)
{
    static const char pers[] = DRBG_DEFAULT_PERS_STRING;
    const int instantiate = drbg->state != DRBG_UNINITIALISED;

    if (drbg->get_entropy != rand_crngt_get_entropy)
        return 1;

     if ((instantiate && !RAND_DRBG_uninstantiate(drbg))
        || !TEST_true(RAND_DRBG_set_callbacks(drbg, &rand_drbg_get_entropy,
                                              &rand_drbg_cleanup_entropy,
                                              &rand_drbg_get_nonce,
                                              &rand_drbg_cleanup_nonce))
        || (instantiate
            && !RAND_DRBG_instantiate(drbg, (const unsigned char *)pers,
                                      sizeof(pers) - 1)))
        return 0;
    return 1;
}

static int uninstantiate(RAND_DRBG *drbg)
{
    int ret = drbg == NULL ? 1 : RAND_DRBG_uninstantiate(drbg);

    ERR_clear_error();
    return ret;
}

/*
 * Do a single KAT test.  Return 0 on failure.
 */
static int single_kat(DRBG_SELFTEST_DATA *td)
{
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    int failures = 0;
    unsigned char buff[1024];

    /*
     * Test without PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL)))
        return 0;
    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))
        || !TEST_true(disable_crngt(drbg))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = td->entropy;
    t.entropylen = td->entropylen;
    t.nonce = td->nonce;
    t.noncelen = td->noncelen;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);

    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                             td->adin, td->adinlen))
            || !TEST_mem_eq(td->expected, td->exlen, buff, td->exlen))
        failures++;

    /* Reseed DRBG with test entropy and additional input */
    t.entropy = td->entropyreseed;
    t.entropylen = td->entropyreseedlen;
    if (!TEST_true(RAND_DRBG_reseed(drbg, td->adinreseed, td->adinreseedlen, 0)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len, 0,
                                             td->adin2, td->adin2len))
            || !TEST_mem_eq(td->kat2, td->kat2len, buff, td->kat2len)))
        failures++;
    uninstantiate(drbg);

    /*
     * Now test with PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                                  kat_nonce, NULL)))
        failures++;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);
    t.entropy = td->entropy_pr;
    t.entropylen = td->entropylen_pr;
    t.nonce = td->nonce_pr;
    t.noncelen = td->noncelen_pr;
    t.entropycnt = 0;
    t.noncecnt = 0;
    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers_pr, td->perslen_pr)))
        failures++;

    /*
     * Now generate with PR: we need to supply entropy as this will
     * perform a reseed operation.
     */
    t.entropy = td->entropypr_pr;
    t.entropylen = td->entropyprlen_pr;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->katlen_pr, 1,
                                      td->adin_pr, td->adinlen_pr))
            || !TEST_mem_eq(td->kat_pr, td->katlen_pr, buff, td->katlen_pr))
        failures++;

    /*
     * Now generate again with PR: supply new entropy again.
     */
    t.entropy = td->entropyg_pr;
    t.entropylen = td->entropyglen_pr;

    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len_pr, 1,
                                      td->ading_pr, td->adinglen_pr))
                || !TEST_mem_eq(td->kat2_pr, td->kat2len_pr,
                                buff, td->kat2len_pr))
        failures++;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}

/*
 * Initialise a DRBG based on selftest data
 */
static int init(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td, TEST_CTX *t)
{
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                                  kat_nonce, NULL)))
        return 0;
    RAND_DRBG_set_ex_data(drbg, app_data_index, t);
    t->entropy = td->entropy;
    t->entropylen = td->entropylen;
    t->nonce = td->nonce;
    t->noncelen = td->noncelen;
    t->entropycnt = 0;
    t->noncecnt = 0;
    return 1;
}

/*
 * Initialise and instantiate DRBG based on selftest data
 */
static int instantiate(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td,
                       TEST_CTX *t)
{
    if (!TEST_true(init(drbg, td, t))
            || !TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen)))
        return 0;
    return 1;
}

/*
 * Perform extensive error checking as required by SP800-90.
 * Induce several failure modes and check an error condition is set.
 */
static int error_check(DRBG_SELFTEST_DATA *td)
{
    static char zero[sizeof(RAND_DRBG)];
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    unsigned char buff[1024];
    unsigned int reseed_counter_tmp;
    int ret = 0;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;

    /*
     * Personalisation string tests
     */

    /* Test detection of too large personlisation string */
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, drbg->max_perslen + 1) > 0)
        goto err;

    /*
     * Entropy source tests
     */

    /* Test entropy source failure detection: i.e. returns no data */
    t.entropylen = 0;
    if (TEST_int_le(RAND_DRBG_instantiate(drbg, td->pers, td->perslen), 0))
        goto err;

    /* Try to generate output from uninstantiated DRBG */
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                       td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Test insufficient entropy */
    t.entropylen = drbg->min_entropylen - 1;
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0
            || !uninstantiate(drbg))
        goto err;

    /* Test too much entropy */
    t.entropylen = drbg->max_entropylen + 1;
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0
            || !uninstantiate(drbg))
        goto err;

    /*
     * Nonce tests
     */

    /* Test too small nonce */
    if (drbg->min_noncelen) {
        t.noncelen = drbg->min_noncelen - 1;
        if (!init(drbg, td, &t)
                || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0
                || !uninstantiate(drbg))
            goto err;
    }

    /* Test too large nonce */
    if (drbg->max_noncelen) {
        t.noncelen = drbg->max_noncelen + 1;
        if (!init(drbg, td, &t)
                || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0
                || !uninstantiate(drbg))
            goto err;
    }

    /* Instantiate with valid data, Check generation is now OK */
    if (!instantiate(drbg, td, &t)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                             td->adin, td->adinlen)))
        goto err;

    /* Request too much data for one request */
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, drbg->max_request + 1, 0,
                                       td->adin, td->adinlen)))
        goto err;

    /* Try too large additional input */
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                       td->adin, drbg->max_adinlen + 1)))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entropylen = 0;
    if (TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1,
                                      td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Instantiate again with valid data */
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = drbg->reseed_gen_counter;
    drbg->reseed_gen_counter = drbg->reseed_interval;

    /* Generate output and check entropy has been requested for reseed */
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(drbg->reseed_gen_counter, reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1,
                                       td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Test reseed counter works */
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = drbg->reseed_gen_counter;
    drbg->reseed_gen_counter = drbg->reseed_interval;

    /* Generate output and check entropy has been requested for reseed */
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(drbg->reseed_gen_counter, reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    /*
     * Explicit reseed tests
     */

    /* Test explicit reseed with too large additional input */
    if (!instantiate(drbg, td, &t)
            || RAND_DRBG_reseed(drbg, td->adin, drbg->max_adinlen + 1, 0) > 0)
        goto err;

    /* Test explicit reseed with entropy source failure */
    t.entropylen = 0;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    /* Test explicit reseed with too much entropy */
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = drbg->max_entropylen + 1;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    /* Test explicit reseed with too little entropy */
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = drbg->min_entropylen - 1;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    /* Standard says we have to check uninstantiate really zeroes */
    if (!TEST_mem_eq(zero, sizeof(drbg->data), &drbg->data, sizeof(drbg->data)))
        goto err;

    ret = 1;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return ret;
}

static int test_kats(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (!single_kat(td))
        goto err;
    rv = 1;

err:
    return rv;
}

static int test_error_checks(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (error_check(td))
        goto err;
    rv = 1;

err:
    return rv;
}

/*
 * Hook context data, attached as EXDATA to the RAND_DRBG
 */
typedef struct hook_ctx_st {
    RAND_DRBG *drbg;
    /*
     * Currently, all DRBGs use the same get_entropy() callback.
     * The tests however, don't assume this and store
     * the original callback for every DRBG separately.
     */
    RAND_DRBG_get_entropy_fn get_entropy;
    /* forces a failure of the get_entropy() call if nonzero */
    int fail;
    /* counts successful reseeds */
    int reseed_count;
} HOOK_CTX;

static HOOK_CTX master_ctx, public_ctx, private_ctx;

static HOOK_CTX *get_hook_ctx(RAND_DRBG *drbg)
{
    return (HOOK_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);
}

/* Intercepts and counts calls to the get_entropy() callback */
static size_t get_entropy_hook(RAND_DRBG *drbg, unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance)
{
    size_t ret;
    HOOK_CTX *ctx = get_hook_ctx(drbg);

    if (ctx->fail != 0)
        return 0;

    ret = ctx->get_entropy(drbg, pout, entropy, min_len, max_len,
                           prediction_resistance);

    if (ret != 0)
        ctx->reseed_count++;
    return ret;
}

/* Installs a hook for the get_entropy() callback of the given drbg */
static void hook_drbg(RAND_DRBG *drbg, HOOK_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->drbg = drbg;
    ctx->get_entropy = drbg->get_entropy;
    drbg->get_entropy = get_entropy_hook;
    RAND_DRBG_set_ex_data(drbg, app_data_index, ctx);
}

/* Installs the hook for the get_entropy() callback of the given drbg */
static void unhook_drbg(RAND_DRBG *drbg)
{
    HOOK_CTX *ctx = get_hook_ctx(drbg);

    drbg->get_entropy = ctx->get_entropy;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);
}

/* Resets the given hook context */
static void reset_hook_ctx(HOOK_CTX *ctx)
{
    ctx->fail = 0;
    ctx->reseed_count = 0;
}

/* Resets all drbg hook contexts */
static void reset_drbg_hook_ctx(void)
{
    reset_hook_ctx(&master_ctx);
    reset_hook_ctx(&public_ctx);
    reset_hook_ctx(&private_ctx);
}

/*
 * Generates random output using RAND_bytes() and RAND_priv_bytes()
 * and checks whether the three shared DRBGs were reseeded as
 * expected.
 *
 * |expect_success|: expected outcome (as reported by RAND_status())
 * |master|, |public|, |private|: pointers to the three shared DRBGs
 * |expect_xxx_reseed| =
 *       1:  it is expected that the specified DRBG is reseeded
 *       0:  it is expected that the specified DRBG is not reseeded
 *      -1:  don't check whether the specified DRBG was reseeded or not
 * |reseed_time|: if nonzero, used instead of time(NULL) to set the
 *                |before_reseed| time.
 */
static int test_drbg_reseed(int expect_success,
                            RAND_DRBG *master,
                            RAND_DRBG *public,
                            RAND_DRBG *private,
                            int expect_master_reseed,
                            int expect_public_reseed,
                            int expect_private_reseed,
                            time_t reseed_time
                           )
{
    unsigned char buf[32];
    time_t before_reseed, after_reseed;
    int expected_state = (expect_success ? DRBG_READY : DRBG_ERROR);

    /*
     * step 1: check preconditions
     */

    /* Test whether seed propagation is enabled */
    if (!TEST_int_ne(master->reseed_prop_counter, 0)
        || !TEST_int_ne(public->reseed_prop_counter, 0)
        || !TEST_int_ne(private->reseed_prop_counter, 0))
        return 0;

    /* Check whether the master DRBG's reseed counter is the largest one */
    if (!TEST_int_le(public->reseed_prop_counter, master->reseed_prop_counter)
        || !TEST_int_le(private->reseed_prop_counter, master->reseed_prop_counter))
        return 0;

    /*
     * step 2: generate random output
     */

    if (reseed_time == 0)
        reseed_time = time(NULL);

    /* Generate random output from the public and private DRBG */
    before_reseed = expect_master_reseed == 1 ? reseed_time : 0;
    if (!TEST_int_eq(RAND_bytes(buf, sizeof(buf)), expect_success)
        || !TEST_int_eq(RAND_priv_bytes(buf, sizeof(buf)), expect_success))
        return 0;
    after_reseed = time(NULL);


    /*
     * step 3: check postconditions
     */

    /* Test whether reseeding succeeded as expected */
    if (!TEST_int_eq(master->state, expected_state)
        || !TEST_int_eq(public->state, expected_state)
        || !TEST_int_eq(private->state, expected_state))
        return 0;

    if (expect_master_reseed >= 0) {
        /* Test whether master DRBG was reseeded as expected */
        if (!TEST_int_eq(master_ctx.reseed_count, expect_master_reseed))
            return 0;
    }

    if (expect_public_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_eq(public_ctx.reseed_count, expect_public_reseed))
            return 0;
    }

    if (expect_private_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_eq(private_ctx.reseed_count, expect_private_reseed))
            return 0;
    }

    if (expect_success == 1) {
        /* Test whether all three reseed counters are synchronized */
        if (!TEST_int_eq(public->reseed_prop_counter, master->reseed_prop_counter)
            || !TEST_int_eq(private->reseed_prop_counter, master->reseed_prop_counter))
            return 0;

        /* Test whether reseed time of master DRBG is set correctly */
        if (!TEST_time_t_le(before_reseed, master->reseed_time)
            || !TEST_time_t_le(master->reseed_time, after_reseed))
            return 0;

        /* Test whether reseed times of child DRBGs are synchronized with master */
        if (!TEST_time_t_ge(public->reseed_time, master->reseed_time)
            || !TEST_time_t_ge(private->reseed_time, master->reseed_time))
            return 0;
    } else {
        ERR_clear_error();
    }

    return 1;
}

/*
 * Test whether the default rand_method (RAND_OpenSSL()) is
 * setup correctly, in particular whether reseeding  works
 * as designed.
 */
static int test_rand_drbg_reseed(void)
{
    RAND_DRBG *master, *public, *private;
    unsigned char rand_add_buf[256];
    int rv=0;
    time_t before_reseed;

    /* Check whether RAND_OpenSSL() is the default method */
    if (!TEST_ptr_eq(RAND_get_rand_method(), RAND_OpenSSL()))
        return 0;

    /* All three DRBGs should be non-null */
    if (!TEST_ptr(master = RAND_DRBG_get0_master())
        || !TEST_ptr(public = RAND_DRBG_get0_public())
        || !TEST_ptr(private = RAND_DRBG_get0_private()))
        return 0;

    /* There should be three distinct DRBGs, two of them chained to master */
    if (!TEST_ptr_ne(public, private)
        || !TEST_ptr_ne(public, master)
        || !TEST_ptr_ne(private, master)
        || !TEST_ptr_eq(public->parent, master)
        || !TEST_ptr_eq(private->parent, master))
        return 0;

    /* Disable CRNG testing for the master DRBG */
    if (!TEST_true(disable_crngt(master)))
        return 0;

    /* uninstantiate the three global DRBGs */
    RAND_DRBG_uninstantiate(private);
    RAND_DRBG_uninstantiate(public);
    RAND_DRBG_uninstantiate(master);


    /* Install hooks for the following tests */
    hook_drbg(master,  &master_ctx);
    hook_drbg(public,  &public_ctx);
    hook_drbg(private, &private_ctx);


    /*
     * Test initial seeding of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 1, 1, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();


    /*
     * Test initial state of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();

    /*
     * Test whether the public and private DRBG are both reseeded when their
     * reseed counters differ from the master's reseed counter.
     */
    master->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 1, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();

    /*
     * Test whether the public DRBG is reseeded when its reseed counter differs
     * from the master's reseed counter.
     */
    master->reseed_prop_counter++;
    private->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 1, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();

    /*
     * Test whether the private DRBG is reseeded when its reseed counter differs
     * from the master's reseed counter.
     */
    master->reseed_prop_counter++;
    public->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();


    /* fill 'randomness' buffer with some arbitrary data */
    memset(rand_add_buf, 'r', sizeof(rand_add_buf));

#ifndef FIPS_MODE
    /*
     * Test whether all three DRBGs are reseeded by RAND_add().
     * The before_reseed time has to be measured here and passed into the
     * test_drbg_reseed() test, because the master DRBG gets already reseeded
     * in RAND_add(), whence the check for the condition
     * before_reseed <= master->reseed_time will fail if the time value happens
     * to increase between the RAND_add() and the test_drbg_reseed() call.
     */
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 1, 1, 1,
                                    before_reseed)))
        goto error;
    reset_drbg_hook_ctx();


    /*
     * Test whether none of the DRBGs is reseed if the master fails to reseed
     */
    master_ctx.fail = 1;
    master->reseed_prop_counter++;
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(0, master, public, private, 0, 0, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();
#else /* FIPS_MODE */
    /*
     * In FIPS mode, random data provided by the application via RAND_add()
     * is not considered a trusted entropy source. It is only treated as
     * additional_data and no reseeding is forced. This test assures that
     * no reseeding occurs.
     */
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 0,
                                    before_reseed)))
        goto error;
    reset_drbg_hook_ctx();
#endif

    rv = 1;

error:
    /* Remove hooks  */
    unhook_drbg(master);
    unhook_drbg(public);
    unhook_drbg(private);

    return rv;
}

#if defined(OPENSSL_THREADS)
static int multi_thread_rand_bytes_succeeded = 1;
static int multi_thread_rand_priv_bytes_succeeded = 1;

static void run_multi_thread_test(void)
{
    unsigned char buf[256];
    time_t start = time(NULL);
    RAND_DRBG *public = NULL, *private = NULL;

    if (!TEST_ptr(public = RAND_DRBG_get0_public())
            || !TEST_ptr(private = RAND_DRBG_get0_private())) {
        multi_thread_rand_bytes_succeeded = 0;
        return;
    }
    RAND_DRBG_set_reseed_time_interval(private, 1);
    RAND_DRBG_set_reseed_time_interval(public, 1);

    do {
        if (RAND_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_bytes_succeeded = 0;
        if (RAND_priv_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_priv_bytes_succeeded = 0;
    }
    while(time(NULL) - start < 5);
}

# if defined(OPENSSL_SYS_WINDOWS)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return 0;
}

static int run_thread(thread_t *t)
{
    *t = CreateThread(NULL, 0, thread_run, NULL, 0, NULL);
    return *t != NULL;
}

static int wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}

# else

typedef pthread_t thread_t;

static void *thread_run(void *arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return NULL;
}

static int run_thread(thread_t *t)
{
    return pthread_create(t, NULL, thread_run, NULL) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

# endif

/*
 * The main thread will also run the test, so we'll have THREADS+1 parallel
 * tests running
 */
# define THREADS 3

static int test_multi_thread(void)
{
    thread_t t[THREADS];
    int i;

    for (i = 0; i < THREADS; i++)
        run_thread(&t[i]);
    run_multi_thread_test();
    for (i = 0; i < THREADS; i++)
        wait_for_thread(t[i]);

    if (!TEST_true(multi_thread_rand_bytes_succeeded))
        return 0;
    if (!TEST_true(multi_thread_rand_priv_bytes_succeeded))
        return 0;

    return 1;
}
#endif

/*
 * Test that instantiation with RAND_seed() works as expected
 *
 * If no os entropy source is available then RAND_seed(buffer, bufsize)
 * is expected to succeed if and only if the buffer length is at least
 * rand_drbg_seedlen(master) bytes.
 *
 * If an os entropy source is available then RAND_seed(buffer, bufsize)
 * is expected to succeed always.
 */
static int test_rand_seed(void)
{
    RAND_DRBG *master = NULL;
    unsigned char rand_buf[256];
    size_t rand_buflen;
    size_t required_seed_buflen = 0;

    if (!TEST_ptr(master = RAND_DRBG_get0_master())
        || !TEST_true(disable_crngt(master)))
        return 0;

#ifdef OPENSSL_RAND_SEED_NONE
    required_seed_buflen = rand_drbg_seedlen(master);
#endif

    memset(rand_buf, 0xCD, sizeof(rand_buf));

    for ( rand_buflen = 256 ; rand_buflen > 0 ; --rand_buflen ) {
        RAND_DRBG_uninstantiate(master);
        RAND_seed(rand_buf, rand_buflen);

        if (!TEST_int_eq(RAND_status(),
                         (rand_buflen >= required_seed_buflen)))
            return 0;
    }

    return 1;
}

/*
 * Test that adding additional data with RAND_add() works as expected
 * when the master DRBG is instantiated (and below its reseed limit).
 *
 * This should succeed regardless of whether an os entropy source is
 * available or not.
 */
static int test_rand_add(void)
{
    unsigned char rand_buf[256];
    size_t rand_buflen;

    memset(rand_buf, 0xCD, sizeof(rand_buf));

    /* make sure it's instantiated */
    RAND_seed(rand_buf, sizeof(rand_buf));
    if (!TEST_true(RAND_status()))
        return 0;

    for ( rand_buflen = 256 ; rand_buflen > 0 ; --rand_buflen ) {
        RAND_add(rand_buf, rand_buflen, 0.0);
        if (!TEST_true(RAND_status()))
            return 0;
    }

    return 1;
}

static int test_rand_drbg_prediction_resistance(void)
{
    RAND_DRBG *m = NULL, *i = NULL, *s = NULL;
    unsigned char buf1[51], buf2[sizeof(buf1)];
    int ret = 0, mreseed, ireseed, sreseed;

    /* Initialise a three long DRBG chain */
    if (!TEST_ptr(m = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(m))
        || !TEST_true(RAND_DRBG_instantiate(m, NULL, 0))
        || !TEST_ptr(i = RAND_DRBG_new(0, 0, m))
        || !TEST_true(RAND_DRBG_instantiate(i, NULL, 0))
        || !TEST_ptr(s = RAND_DRBG_new(0, 0, i))
        || !TEST_true(RAND_DRBG_instantiate(s, NULL, 0)))
        goto err;

    /* During a normal reseed, only the slave DRBG should be reseed */
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    /*
     * When prediction resistance is requested, the request should be
     * propagated to the master, so that the entire DRBG chain reseeds.
     */
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 1))
        || !TEST_int_gt(m->reseed_prop_counter, mreseed)
        || !TEST_int_gt(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    /* During a normal generate, only the slave DRBG should be reseed */
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_generate(s, buf1, sizeof(buf1), 0, NULL, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    /*
     * When a prediction resistant generate is requested, the request
     * should be propagated to the master, reseeding the entire DRBG chain.
     */
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_generate(s, buf2, sizeof(buf2), 1, NULL, 0))
        || !TEST_int_gt(m->reseed_prop_counter, mreseed)
        || !TEST_int_gt(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed)
        || !TEST_mem_ne(buf1, sizeof(buf1), buf2, sizeof(buf2)))
        goto err;

    /* Verify that a normal reseed still only reseeds the slave DRBG */
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    ret = 1;
err:
    RAND_DRBG_free(s);
    RAND_DRBG_free(i);
    RAND_DRBG_free(m);
    return ret;
}

static int test_multi_set(void)
{
    int rv = 0;
    RAND_DRBG *drbg = NULL;

    /* init drbg with default CTR initializer */
    if (!TEST_ptr(drbg = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;
    /* change it to use hmac */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    /* change it to use hash */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    /* change it to use ctr */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    if (!TEST_int_gt(RAND_DRBG_instantiate(drbg, NULL, 0), 0))
        goto err;

    rv = 1;
err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return rv;
}

static int test_set_defaults(void)
{
    RAND_DRBG *master = NULL, *public = NULL, *private = NULL;

           /* Check the default type and flags for master, public and private */
    return TEST_ptr(master = RAND_DRBG_get0_master())
           && TEST_ptr(public = RAND_DRBG_get0_public())
           && TEST_ptr(private = RAND_DRBG_get0_private())
           && TEST_int_eq(master->type, RAND_DRBG_TYPE)
           && TEST_int_eq(master->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)

           /* change master DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256,
                                               RAND_DRBG_FLAG_MASTER))
           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)
           /* change private DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256,
                        RAND_DRBG_FLAG_PRIVATE|RAND_DRBG_FLAG_HMAC))
           && TEST_true(RAND_DRBG_uninstantiate(private))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           /* change public DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha1,
                                               RAND_DRBG_FLAG_PUBLIC
                                               | RAND_DRBG_FLAG_HMAC))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, NID_sha1)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_HMAC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           /* Change DRBG defaults and change public and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256, 0))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(public->type, NID_sha256)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAG_PUBLIC)

          /* FIPS mode doesn't support CTR DRBG without a derivation function */
#ifndef FIPS_MODE
          /* Change DRBG defaults and change master and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_aes_256_ctr,
                                               RAND_DRBG_FLAG_CTR_NO_DF))
           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_int_eq(master->type, NID_aes_256_ctr)
           && TEST_int_eq(master->flags,
                          RAND_DRBG_FLAG_MASTER|RAND_DRBG_FLAG_CTR_NO_DF)
#endif
           /* Reset back to the standard defaults */
           && TEST_true(RAND_DRBG_set_defaults(RAND_DRBG_TYPE,
                                               RAND_DRBG_FLAGS
                                               | RAND_DRBG_FLAG_MASTER
                                               | RAND_DRBG_FLAG_PUBLIC
                                               | RAND_DRBG_FLAG_PRIVATE))
           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_true(RAND_DRBG_uninstantiate(private));
}

/*
 * A list of the FIPS DRGB types.
 * Because of the way HMAC DRGBs are implemented, both the NID and flags
 * are required.
 */
static const struct s_drgb_types {
    int nid;
    int flags;
} drgb_types[] = {
    { NID_aes_128_ctr,  0                   },
    { NID_aes_192_ctr,  0                   },
    { NID_aes_256_ctr,  0                   },
    { NID_sha1,         0                   },
    { NID_sha224,       0                   },
    { NID_sha256,       0                   },
    { NID_sha384,       0                   },
    { NID_sha512,       0                   },
    { NID_sha512_224,   0                   },
    { NID_sha512_256,   0                   },
    { NID_sha3_224,     0                   },
    { NID_sha3_256,     0                   },
    { NID_sha3_384,     0                   },
    { NID_sha3_512,     0                   },
    { NID_sha1,         RAND_DRBG_FLAG_HMAC },
    { NID_sha224,       RAND_DRBG_FLAG_HMAC },
    { NID_sha256,       RAND_DRBG_FLAG_HMAC },
    { NID_sha384,       RAND_DRBG_FLAG_HMAC },
    { NID_sha512,       RAND_DRBG_FLAG_HMAC },
    { NID_sha512_224,   RAND_DRBG_FLAG_HMAC },
    { NID_sha512_256,   RAND_DRBG_FLAG_HMAC },
    { NID_sha3_224,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_256,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_384,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_512,     RAND_DRBG_FLAG_HMAC },
};

/* Six cases for each covers seed sizes up to 32 bytes */
static const size_t crngt_num_cases = 6;

static size_t crngt_case, crngt_idx;

static int crngt_entropy_cb(unsigned char *buf, unsigned char *md,
                            unsigned int *md_size)
{
    size_t i, z;

    if (!TEST_int_lt(crngt_idx, crngt_num_cases))
        return 0;
    /* Generate a block of unique data unless this is the duplication point */
    z = crngt_idx++;
    if (z > 0 && crngt_case == z)
        z--;
    for (i = 0; i < CRNGT_BUFSIZ; i++)
        buf[i] = (unsigned char)(i + 'A' + z);
    return EVP_Digest(buf, CRNGT_BUFSIZ, md, md_size, EVP_sha256(), NULL);
}

static int test_crngt(int n)
{
    const struct s_drgb_types *dt = drgb_types + n / crngt_num_cases;
    RAND_DRBG *drbg = NULL;
    unsigned char buff[100];
    size_t ent;
    int res = 0;
    int expect;

    if (!TEST_true(rand_crngt_single_init()))
        return 0;
    rand_crngt_cleanup();

    if (!TEST_ptr(drbg = RAND_DRBG_new(dt->nid, dt->flags, NULL)))
        return 0;
    ent = (drbg->min_entropylen + CRNGT_BUFSIZ - 1) / CRNGT_BUFSIZ;
    crngt_case = n % crngt_num_cases;
    crngt_idx = 0;
    crngt_get_entropy = &crngt_entropy_cb;
    if (!TEST_true(rand_crngt_init()))
        goto err;
#ifndef FIPS_MODE
    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, &rand_crngt_get_entropy,
                                           &rand_crngt_cleanup_entropy,
                                           &rand_drbg_get_nonce,
                                           &rand_drbg_cleanup_nonce)))
        goto err;
#endif
    expect = crngt_case == 0 || crngt_case > ent;
    if (!TEST_int_eq(RAND_DRBG_instantiate(drbg, NULL, 0), expect))
        goto err;
    if (!expect)
        goto fin;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, sizeof(buff), 0, NULL, 0)))
        goto err;

    expect = crngt_case == 0 || crngt_case > 2 * ent;
    if (!TEST_int_eq(RAND_DRBG_reseed(drbg, NULL, 0, 0), expect))
        goto err;
    if (!expect)
        goto fin;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, sizeof(buff), 0, NULL, 0)))
        goto err;

fin:
    res = 1;
err:
    if (!res)
        TEST_note("DRBG %zd case %zd block %zd", n / crngt_num_cases,
                  crngt_case, crngt_idx);
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    crngt_get_entropy = &rand_crngt_get_entropy_cb;
    return res;
}

int setup_tests(void)
{
    app_data_index = RAND_DRBG_get_ex_new_index(0L, NULL, NULL, NULL, NULL);

    ADD_ALL_TESTS(test_kats, OSSL_NELEM(drbg_test));
    ADD_ALL_TESTS(test_error_checks, OSSL_NELEM(drbg_test));
    ADD_TEST(test_rand_drbg_reseed);
    ADD_TEST(test_rand_seed);
    ADD_TEST(test_rand_add);
    ADD_TEST(test_rand_drbg_prediction_resistance);
    ADD_TEST(test_multi_set);
    ADD_TEST(test_set_defaults);
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_multi_thread);
#endif
    ADD_ALL_TESTS(test_crngt, crngt_num_cases * OSSL_NELEM(drgb_types));
    return 1;
}
