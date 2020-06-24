/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#if defined(OPENSSL_THREADS)

# include "task.h"

CRYPTO_TASK CRYPTO_TASK_new(CRYPTO_THREAD_ROUTINE start, void *data)
{
    struct crypto_task_st *t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->lock = CRYPTO_MUTEX_create();
    t->cond_finished = CRYPTO_CONDVAR_create();

    if (t->lock == NULL || t->cond_finished == NULL)
        goto fail;

    if (CRYPTO_MUTEX_init(t->lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(t->cond_finished) == 0)
        goto fail;

    t->data = data;
    t->routine = start;
    return t;

 fail:
    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->cond_finished);
    OPENSSL_free(t);
    return NULL;
}

void CRYPTO_TASK_clean(CRYPTO_TASK t)
{
    if (t == NULL)
        return;
    CRYPTO_MUTEX_destroy(&t->lock);
    CRYPTO_CONDVAR_destroy(&t->cond_finished);
    OPENSSL_free(t);
}

#endif /* defined(OPENSSL_THREADS) */
