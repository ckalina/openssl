/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#include <openssl/configuration.h>
#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_UNIX)
# include "thread_posix.h"
# include <internal/thread.h>

/*
 * This thunk is required due to architectural differences between WINAPI and
 * pthreads; on LLP64 the thread return value storage size is strictly smaller
 * than pointer storage size in some cases. Returning an integer that would fit
 * in either wouldn't word due to possible UB/trap representation, see 6.3.2.3
 * of ISO/IEC 9899:201x Committee Draft April 12, 2011 N1570. For that reason,
 * a small thunk is used to facilitate thread creation.
 */
static void *thread_start_thunk(void *vthread)
{
    CRYPTO_THREAD thread = (CRYPTO_THREAD) vthread;
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_RUNNING);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    thread->retval = thread->routine(thread->data);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_FINISHED);
    return NULL;
}

int CRYPTO_THREAD_native_spawn(CRYPTO_THREAD thread)
{
    int ret;
    pthread_attr_t attr;
    pthread_t *handle;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        goto fail;

    pthread_attr_init(&attr);
    if (thread->joinable)
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    else
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(handle, &attr, thread_start_thunk, thread);
    pthread_attr_destroy(&attr);

    if (ret != 0)
        goto fail;

    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_CREATED);
    thread->handle = handle;
    return 1;

fail:
    CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_CREATED);
    OPENSSL_free(handle);
    return 0;
}

int CRYPTO_THREAD_native_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL *retval)
{
    void *thread_retval;
    CRYPTO_THREAD_POSIX *handle;

    if (thread == NULL)
        return 0;

    CRYPTO_MUTEX_lock(thread->lock);

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_JOINED))
        goto pass;

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_FINISHED))
        goto pass;

    if (CRYPTO_THREAD_GET_STATE(thread, CRYPTO_THREAD_TERMINATED))
        goto fail;

    handle = (CRYPTO_THREAD_POSIX*) thread->handle;

    if (handle == NULL)
        goto fail;

    if (pthread_join(*handle, &thread_retval) != 0)
        goto fail;

    /*
     * Join return value may be non-NULL when the thread has been cancelled,
     * as indicated by thread_retval set to PTHREAD_CANCELLED.
     */
    if (thread_retval != NULL)
        goto fail;

pass:
    if (retval != NULL)
        *retval = thread->retval;

    CRYPTO_THREAD_UNSET_ERROR(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_MUTEX_unlock(thread->lock);
    return 1;

fail:
    CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_JOINED);
    CRYPTO_MUTEX_unlock(thread->lock);
    return 0;
}

int CRYPTO_THREAD_native_terminate(CRYPTO_THREAD thread)
{
    uint64_t mask;
    pthread_t *handle;

    mask = CRYPTO_THREAD_FINISHED;
    mask |= CRYPTO_THREAD_TERMINATED;
    mask |= CRYPTO_THREAD_JOINED;

    if (thread == NULL)
        return 1;

    if (thread->handle == NULL || CRYPTO_THREAD_GET_STATE(thread, mask))
        goto terminated;

    handle = thread->handle;
    if (pthread_cancel(*handle) != 0) {
        CRYPTO_THREAD_SET_ERROR(thread, CRYPTO_THREAD_TERMINATED);
        return 0;
    }

    thread->handle = NULL;
    OPENSSL_free(handle);

 terminated:
    CRYPTO_THREAD_UNSET_ERROR(thread, CRYPTO_THREAD_TERMINATED);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_TERMINATED);
    return 1;
}

int CRYPTO_THREAD_native_exit()
{
    pthread_exit(NULL);
    return 1;
}

int CRYPTO_THREAD_native_is_self(CRYPTO_THREAD thread)
{
    return pthread_equal(*(pthread_t*)thread->handle, pthread_self());
}

CRYPTO_MUTEX CRYPTO_MUTEX_create(void)
{
    CRYPTO_MUTEX_POSIX *mutex;

    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    return (CRYPTO_MUTEX) mutex;
}

int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX *mutex_p;

    mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    if (pthread_mutex_init(mutex_p, NULL) != 0)
        return 0;
    return 1;
}

void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX *mutex_p;

    mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_lock(mutex_p);
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex)
{
    CRYPTO_MUTEX_POSIX *mutex_p;

    mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_mutex_unlock(mutex_p);
}

void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX *mutex)
{
    CRYPTO_MUTEX_POSIX **mutex_p;

    mutex_p = (CRYPTO_MUTEX_POSIX**)mutex;
    if (*mutex_p != NULL)
        pthread_mutex_destroy(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void)
{
    CRYPTO_CONDVAR_POSIX *cv;

    if ((cv = OPENSSL_zalloc(sizeof(*cv))) == NULL)
        return NULL;
    return (CRYPTO_CONDVAR) cv;
}

void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    CRYPTO_CONDVAR_POSIX *cv_p;
    CRYPTO_MUTEX_POSIX *mutex_p;

    cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    mutex_p = (CRYPTO_MUTEX_POSIX*)mutex;
    pthread_cond_wait(cv_p, mutex_p);
}

int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX *cv_p;

    cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    if (pthread_cond_init(cv_p, NULL) != 0)
        return 0;
    return 1;
}

void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv)
{
    CRYPTO_CONDVAR_POSIX *cv_p;

    cv_p = (CRYPTO_CONDVAR_POSIX*)cv;
    pthread_cond_broadcast(cv_p);
}

void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR* cv)
{
    CRYPTO_CONDVAR_POSIX **cv_p;

    cv_p = (CRYPTO_CONDVAR_POSIX**)cv;
    if (*cv_p != NULL)
        pthread_cond_destroy(*cv_p);
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

void CRYPTO_mem_barrier()
{
    __asm__ volatile ("" : : : "memory");
}

#endif
