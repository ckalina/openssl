/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/configuration.h>
#include <openssl/e_os2.h>

#if defined(_WIN32)
# include <windows.h>
#endif

#if !defined(OPENSSL_THREADS) || ( \
    !defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_SYS_WINDOWS) ) || (\
    defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0600 )

# include <internal/thread.h>

int CRYPTO_THREAD_native_create(CRYPTO_THREAD thread)
{
    (void)thread;
    return 0;
}

int CRYPTO_THREAD_native_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL *retval)
{
    (void)thread;
    (void)retval;
    return 0;
}

int CRYPTO_THREAD_native_terminate(CRYPTO_THREAD thread)
{
    (void) thread;
    return 0;
}

int CRYPTO_THREAD_native_exit()
{
    return 0;
}

CRYPTO_MUTEX CRYPTO_MUTEX_create(void)
{
    return NULL;
}

int CRYPTO_MUTEX_init(CRYPTO_MUTEX mutex)
{
    (void)mutex;
    return 0;
}

void CRYPTO_MUTEX_lock(CRYPTO_MUTEX mutex)
{
    (void)mutex;
    return 0;
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX mutex)
{
    (void)mutex;
    return 0;
}

void CRYPTO_MUTEX_destroy(CRYPTO_MUTEX* mutex)
{
    (void)mutex;
    return 0;
}

CRYPTO_CONDVAR CRYPTO_CONDVAR_create(void)
{
    return 0;
}

void CRYPTO_CONDVAR_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex)
{
    (void)cv;
    (void)mutex;
    return 0;
}

int CRYPTO_CONDVAR_init(CRYPTO_CONDVAR cv)
{
    (void)cv;
    return 0;
}

void CRYPTO_CONDVAR_broadcast(CRYPTO_CONDVAR cv)
{
    (void)cv;
    return 0;
}

void CRYPTO_CONDVAR_destroy(CRYPTO_CONDVAR* cv)
{
    (void)cv;
    return 0;
}

void CRYPTO_mem_barrier(void)
{
    (void)0;
}

#endif
