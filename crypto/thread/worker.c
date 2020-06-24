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

# include "openssl_threads.h"
# include "task.h"
# include "worker.h"
#include <stdio.h>
CRYPTO_WORKER CRYPTO_WORKER_new(OPENSSL_CTX *ctx, CRYPTO_WORKER_CALLBACK cb,
                                void *vtask)
{
    struct crypto_worker_st *worker;

    worker = OPENSSL_zalloc(sizeof(*worker));
    if (worker == NULL)
        return NULL;

    worker->cb = cb;
    worker->ctx = ctx;

    if (vtask != NULL) {
        worker->task = (CRYPTO_TASK) vtask;
        worker->type = CRYPTO_WORKER_INTERNAL;
    } else {
        worker->type = CRYPTO_WORKER_EXTERNAL;
    }
    return worker;
}

static CRYPTO_TASK worker_pick_task(OPENSSL_CTX_THREADS tdata, CRYPTO_WORKER worker)
{
    struct list *task_list;
    CRYPTO_TASK task;

    if (list_empty(&tdata->tasks.queue) == 1)
        return NULL;

    list_del(&worker->list);
    if (worker->type == CRYPTO_WORKER_INTERNAL)
        list_add_tail(&worker->list, &tdata->threads.active);
    else
        list_add_tail(&worker->list, &tdata->workers.busy);

    task_list = tdata->tasks.queue.next;
    task = container_of(task_list, struct crypto_task_st, list);

    list_del(&task->list);
    list_add_tail(&task->list, &tdata->tasks.active);

    return task;
}

static CRYPTO_TASK worker_poll_task(OPENSSL_CTX_THREADS tdata, CRYPTO_WORKER worker)
{
    CRYPTO_TASK task;

    CRYPTO_MUTEX_lock(tdata->lock);
    list_add_tail(&worker->list, &tdata->workers.available);

    while (list_empty(&tdata->tasks.queue) == 1){
        CRYPTO_CONDVAR_wait(tdata->tasks.cond_create, tdata->lock);
    }

    task = worker_pick_task(tdata, worker);
    CRYPTO_MUTEX_unlock(tdata->lock);

    return task;
}

static int worker_keep_alive(OPENSSL_CTX_THREADS tdata, CRYPTO_WORKER worker,
                             CRYPTO_TASK task)
{
    size_t task_cnt;
    CRYPTO_WORKER_CMD cmd;

    cmd = CRYPTO_WORKER_TERMINATE;
    CRYPTO_MUTEX_lock(tdata->lock);

    list_del(&task->list);
    list_add_tail(&task->list, &tdata->tasks.done);

    if (worker->cb != NULL) {
        task_cnt = list_size(&tdata->tasks.queue);
        cmd = worker->cb(worker->ctx, task_cnt);
    }

    list_del(&worker->list);
    if (cmd == CRYPTO_WORKER_POLL)
        worker->task = worker_pick_task(tdata, worker);

    task->finished = 1;
    CRYPTO_CONDVAR_broadcast(task->cond_finished);

    CRYPTO_MUTEX_unlock(tdata->lock);
    return (cmd == CRYPTO_WORKER_POLL);
}

CRYPTO_WORKER_CMD worker_internal_cb(OPENSSL_CTX *ctx, size_t queued_tasks)
{
    OPENSSL_CTX_THREADS tdata;

    tdata = OPENSSL_CTX_THREADS(ctx);
    if (tdata == NULL)
        return CRYPTO_WORKER_TERMINATE;

    if (OPENSSL_CTX_THREADS_all_busy(tdata))
        if (list_size(&tdata->tasks.queue) > 0)
            return CRYPTO_WORKER_POLL;

    return CRYPTO_WORKER_TERMINATE;
}

CRYPTO_THREAD_RETVAL worker_main(void *data)
{
    CRYPTO_TASK task;
    CRYPTO_WORKER worker;
    OPENSSL_CTX_THREADS tdata;

    if (data == NULL)
        return 0UL;

    worker = (CRYPTO_WORKER) data;
    tdata = OPENSSL_CTX_THREADS(worker->ctx);
    if (tdata == NULL)
        return 0UL;

    do {
        if (worker->task != NULL) {
            task = worker->task;
            worker->task = NULL;
        } else {
            task = worker_poll_task(tdata, worker);
        }

        task->retval = task->routine(task->data);

    } while(worker_keep_alive(tdata, worker, task));

    list_del(&worker->list);
    list_add_tail(&worker->list, &tdata->workers.terminated);

    return 0UL;
}

#endif /* defined(OPENSSL_THREADS) */
