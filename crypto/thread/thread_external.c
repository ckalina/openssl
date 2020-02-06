/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>

#if defined(OPENSSL_THREADS)
# include "e_os.h"

# include "thread.h"
# include "thread_external.h"
# include "internal/list.h"

# ifndef CALLBACK
#  define CALLBACK
# endif

volatile int CRYPTO_THREAD_EXTERN_enabled = 0;

# ifdef OPENSSL_NO_EXTERN_THREAD

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL **props)
{
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable()
{
    return 1;
}

# else /* ! OPENSSL_NO_EXTERN_THREAD */

static struct list    CRYPTO_THREAD_EXTERN_task_queue;
static struct list    CRYPTO_THREAD_EXTERN_task_done;
static CRYPTO_MUTEX   CRYPTO_THREAD_EXTERN_task_lock;
static CRYPTO_CONDVAR CRYPTO_THREAD_EXTERN_task_cond_create;
static CRYPTO_CONDVAR CRYPTO_THREAD_EXTERN_task_cond_finish;

int CRYPTO_THREAD_EXTERN_enable(CRYPTO_SIGNAL **props)
{
    if (CRYPTO_THREAD_EXTERN_enabled == 1)
        return 1;

    if (props != NULL && CRYPTO_SIGNAL_block_set(props) != 1)
        goto fail;

    list_init(&CRYPTO_THREAD_EXTERN_task_queue);
    list_init(&CRYPTO_THREAD_EXTERN_task_done);

    CRYPTO_THREAD_EXTERN_task_lock = CRYPTO_MUTEX_create();
    CRYPTO_THREAD_EXTERN_task_cond_create = CRYPTO_CONDVAR_create();
    CRYPTO_THREAD_EXTERN_task_cond_finish = CRYPTO_CONDVAR_create();

    if (CRYPTO_MUTEX_init(CRYPTO_THREAD_EXTERN_task_lock) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(CRYPTO_THREAD_EXTERN_task_cond_create) == 0)
        goto fail;

    if (CRYPTO_CONDVAR_init(CRYPTO_THREAD_EXTERN_task_cond_finish) == 0)
        goto fail;

    CRYPTO_mem_barrier();

    CRYPTO_THREAD_EXTERN_enabled = 1;
    return 1;

fail:
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_lock);
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_cond_create);
    OPENSSL_free(CRYPTO_THREAD_EXTERN_task_cond_finish);

    CRYPTO_THREAD_EXTERN_disable();
    return 0;
}

int CRYPTO_THREAD_EXTERN_disable(void)
{
    if (CRYPTO_THREAD_EXTERN_enabled) {
        CRYPTO_MUTEX_destroy(&CRYPTO_THREAD_EXTERN_task_lock);
        CRYPTO_CONDVAR_destroy(&CRYPTO_THREAD_EXTERN_task_cond_create);
        CRYPTO_CONDVAR_destroy(&CRYPTO_THREAD_EXTERN_task_cond_finish);
    }

    CRYPTO_THREAD_EXTERN_enabled = 0;
    return 1;
}

# endif

static CRYPTO_THREAD_RETVAL CALLBACK CRYPTO_THREAD_EXTERN_worker(CRYPTO_THREAD_DATA data)
{
    size_t task_cnt;

    CRYPTO_THREAD_TASK *task;
    CRYPTO_THREAD_CALLBACK worker_exit_cb;

    worker_exit_cb = ((struct crypto_thread_extern_cb*)data)->cb;

    OPENSSL_free(data);

    while (1) {
        struct list *job_l;

        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);

        /* Avoid spurious wakeups and allow immediate job processing: */
        while (list_empty(&CRYPTO_THREAD_EXTERN_task_queue) == 1)
            CRYPTO_CONDVAR_wait(CRYPTO_THREAD_EXTERN_task_cond_create,
                                CRYPTO_THREAD_EXTERN_task_lock);

        job_l = CRYPTO_THREAD_EXTERN_task_queue.next;
        task = container_of(job_l, CRYPTO_THREAD_TASK, list);
        list_del(job_l);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

        task->state = CRYPTO_THREAD_RUNNING;
        task->retval = task->task(task->data);
        task->state = CRYPTO_THREAD_STOPPED;

        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
        list_add_tail(&task->list, &CRYPTO_THREAD_EXTERN_task_done);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

        if (worker_exit_cb != NULL) {
            CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
            task_cnt = list_size(&CRYPTO_THREAD_EXTERN_task_queue);
            CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

            if (worker_exit_cb(task_cnt) == 0)
                break;
        }
    }

    return 0UL;
}

CRYPTO_THREAD CRYPTO_THREAD_EXTERN_provide(CRYPTO_THREAD_CALLBACK cb)
{
    CRYPTO_THREAD ret;
    struct crypto_thread_extern_cb *cb_wrap;

    cb_wrap = OPENSSL_zalloc(sizeof(*cb_wrap));
    if (cb_wrap == NULL)
        return NULL;
    cb_wrap->cb = cb;

    ret = CRYPTO_THREAD_arch_create(CRYPTO_THREAD_EXTERN_worker,
                                    (CRYPTO_THREAD_DATA) cb_wrap);

    if (ret == NULL)
        OPENSSL_free(cb_wrap);

    return ret;
}

CRYPTO_THREAD CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void *data)
{
    CRYPTO_THREAD_TASK *t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return NULL;

    t->task = task;
    t->data = data;
    t->state = CRYPTO_THREAD_AWAITING;

    /* Never write .handle here! */

    CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
    list_add_tail(&t->list, &CRYPTO_THREAD_EXTERN_task_queue);
    CRYPTO_CONDVAR_broadcast(CRYPTO_THREAD_EXTERN_task_cond_create);
    CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

    return (CRYPTO_THREAD) t;
}

int CRYPTO_THREAD_EXTERN_join(CRYPTO_THREAD task_id,
                              CRYPTO_THREAD_RETVAL *retval)
{
    struct list *i;
    CRYPTO_THREAD_TASK *task = NULL;

loop:
    CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
    list_for_each(i, &CRYPTO_THREAD_EXTERN_task_done) {
        task = container_of(i, CRYPTO_THREAD_TASK, list);
        if (task == (CRYPTO_THREAD_TASK*) task_id)
            break;
    }
    CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);

    if (task != (CRYPTO_THREAD_TASK*) task_id) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
        goto loop;
    }

    if (retval != NULL)
        *retval = task->retval;

    return 1;
}

int CRYPTO_THREAD_EXTERN_clean(CRYPTO_THREAD *thread)
{
    CRYPTO_THREAD_TASK *task = (CRYPTO_THREAD_TASK*) *thread;

    switch(CRYPTO_THREAD_state(*thread)) {
    case CRYPTO_THREAD_STOPPED:
    case CRYPTO_THREAD_FAILED:
    case CRYPTO_THREAD_AWAITING:
        CRYPTO_MUTEX_lock(CRYPTO_THREAD_EXTERN_task_lock);
        list_del(&task->list);
        CRYPTO_MUTEX_unlock(CRYPTO_THREAD_EXTERN_task_lock);
        break;
    default:
        return 0;
    }

    *thread = NULL;
    CRYPTO_mem_barrier();
    OPENSSL_free(task);
    return 1;
}

#endif
