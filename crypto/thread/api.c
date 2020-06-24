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

# include <openssl/crypto.h>
# include <internal/worker.h>
# include <internal/thread.h>
# include "openssl_threads.h"
# include "worker.h"

int CRYPTO_THREAD_enabled(OPENSSL_CTX *ctx)
{
    OPENSSL_CTX_THREADS tdata;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    return tdata->enabled;
}

int CRYPTO_THREAD_enable(OPENSSL_CTX *ctx, int max_threads)
{
    OPENSSL_CTX_THREADS tdata;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    tdata->threads.cap = max_threads;
    tdata->enabled = 1;
    return 1;
}

int CRYPTO_THREAD_disable(OPENSSL_CTX *ctx)
{
    OPENSSL_CTX_THREADS tdata;
    CRYPTO_WORKER worker;
    struct list *iter, *tmp;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);
    tdata->threads.cap = 0;
    tdata->enabled = 0;

    list_for_each_safe(iter, tmp, &tdata->workers.available) {
        worker = container_of(iter, struct crypto_worker_st, list);
        crypto_thread_native_terminate(worker->handle);
        crypto_thread_native_clean(worker->handle);
        list_del(iter);
        OPENSSL_free(worker);
    }
    list_for_each_safe(iter, tmp, &tdata->workers.busy) {
        worker = container_of(iter, struct crypto_worker_st, list);
        crypto_thread_native_terminate(worker->handle);
        crypto_thread_native_clean(worker->handle);
        list_del(iter);
        OPENSSL_free(worker);
    }
    list_for_each_safe(iter, tmp, &tdata->threads.active) {
        worker = container_of(iter, struct crypto_worker_st, list);
        crypto_thread_native_terminate(worker->handle);
        crypto_thread_native_clean(worker->handle);
        list_del(iter);
        OPENSSL_free(worker);
    }
    CRYPTO_MUTEX_unlock(tdata->lock);
    crypto_thread_clean(ctx, NULL);
    return 1;
}

int CRYPTO_THREAD_cap(OPENSSL_CTX *ctx, int max_threads)
{
    OPENSSL_CTX_THREADS tdata;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    if (tdata->enabled == 0)
        return 0;

    tdata->threads.cap = max_threads;
    return 1;
}

size_t crypto_thread_num_available_threads(OPENSSL_CTX *ctx)
{
    OPENSSL_CTX_THREADS t;

    t = OPENSSL_CTX_THREADS(ctx);
    if (t == NULL)
        return 0;

    if (t->enabled == 0)
        return 0;

    if (t->threads.cap < 0)
        return -1;

    return t->threads.cap - list_size(&t->threads.active) +
        list_size(&t->workers.available);
}

static int crypto_thread_spawn_worker_task(OPENSSL_CTX *ctx,
                                           CRYPTO_WORKER_CALLBACK cb,
                                           void *vtask)
{
    int available_threads;
    CRYPTO_WORKER worker;
    OPENSSL_CTX_THREADS tdata;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    if (tdata->enabled == 0)
        return 0;

    worker = CRYPTO_WORKER_new(ctx, cb, vtask);
    if (worker == NULL)
        goto fail;

    if (vtask != NULL)
        list_add_tail(&worker->list, &tdata->threads.active);

    available_threads = crypto_thread_num_available_threads(ctx);
    worker->handle = crypto_thread_native_start(worker_main, (void*)worker, 0);
    if (worker->handle == NULL) {
        list_del(&worker->list);
        goto fail;
    }

    while (vtask == NULL &&
           crypto_thread_num_available_threads(ctx) == available_threads)
        ossl_sleep(500);

    return 1;

 fail:
    OPENSSL_free(worker);
    return 0;
}

int CRYPTO_THREAD_spawn_worker(OPENSSL_CTX *ctx, CRYPTO_WORKER_CALLBACK cb)
{
    return crypto_thread_spawn_worker_task(ctx, cb, NULL);
}

void *crypto_thread_start(OPENSSL_CTX *ctx, CRYPTO_THREAD_ROUTINE start,
                          void *data)
{
    int queue_task;
    int available_threads;
    struct crypto_task_st *t;
    OPENSSL_CTX_THREADS tdata;

    queue_task = 1;
    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return NULL;

    if (tdata->enabled == 0)
        return 0;

    t = crypto_task_new(start, data);
    if (t == NULL)
        return NULL;

    CRYPTO_MUTEX_lock(tdata->lock);
    available_threads = crypto_thread_num_available_threads(ctx);
    if (openssl_ctx_threads_can_spawn_thread(tdata)) {
        list_add_tail(&t->list, &tdata->tasks.active);
        if (crypto_thread_spawn_worker_task(ctx, worker_internal_cb, t) == 1)
            queue_task = 0;
        else
            list_del(&t->list);
    }
    if (queue_task) {
        list_add_tail(&t->list, &tdata->tasks.queue);
        CRYPTO_CONDVAR_broadcast(tdata->tasks.cond_create);
        CRYPTO_MUTEX_unlock(tdata->lock);

        if (available_threads > 0)
            while (crypto_thread_num_available_threads(ctx) == available_threads) {
                ossl_sleep(500);
            }
    } else
        CRYPTO_MUTEX_unlock(tdata->lock);

    return (void*) t;
}

int crypto_thread_join(OPENSSL_CTX *ctx, void *vtask,
                       CRYPTO_THREAD_RETVAL *retval)
{
    CRYPTO_TASK task;
    OPENSSL_CTX_THREADS tdata;

    task = (CRYPTO_TASK) vtask;
    tdata = OPENSSL_CTX_THREADS(ctx);
    if (task == NULL || tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(task->lock);
    while (task->finished != 1)
        CRYPTO_CONDVAR_wait(task->cond_finished, task->lock);

    if (retval != NULL) {
        *retval = task->retval;
    }

    return 1;
}

int crypto_thread_clean(OPENSSL_CTX *ctx, void *vtask)
{
    CRYPTO_TASK task;
    OPENSSL_CTX_THREADS tdata;
    CRYPTO_WORKER worker;
    struct list *iter, *tmp;

    task = (CRYPTO_TASK) vtask;
    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return 0;

    CRYPTO_MUTEX_lock(tdata->lock);

    list_for_each_safe(iter, tmp, &tdata->workers.terminated) {
        worker = container_of(iter, struct crypto_worker_st, list);
        if (crypto_thread_native_clean(worker->handle) == 0)
            continue;
        list_del(iter);
        OPENSSL_free(worker);
    }

    if (task == NULL) {
        list_for_each_safe(iter, tmp, &tdata->tasks.done) {
            task = container_of(iter, struct crypto_task_st, list);
            list_del(iter);
            crypto_task_clean(task);
        }
    } else {
        list_del(&task->list);
        crypto_task_clean(task);
    }

    CRYPTO_MUTEX_unlock(tdata->lock);

    return 1;
}

#endif /* defined(OPENSSL_THREADS) */
