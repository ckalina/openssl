/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_THREAD_H
# define OPENSSL_THREAD_H
# pragma once

# include <openssl/crypto.h>

CRYPTO_THREAD thread_create(CRYPTO_THREAD_ROUTINE routine,
                            CRYPTO_THREAD_DATA data);
int  thread_join(CRYPTO_THREAD thread, CRYPTO_THREAD_RETVAL* retval);
void thread_exit(CRYPTO_THREAD_RETVAL retval);

CRYPTO_MUTEX mutex_create(void);
int mutex_init(CRYPTO_MUTEX mutex);
void mutex_lock(CRYPTO_MUTEX mutex);
void mutex_unlock(CRYPTO_MUTEX mutex);
void mutex_destroy(CRYPTO_MUTEX* mutex);

CRYPTO_CONDVAR condvar_create(void);
void condvar_wait(CRYPTO_CONDVAR cv, CRYPTO_MUTEX mutex);
int condvar_init(CRYPTO_CONDVAR cv);
void condvar_broadcast(CRYPTO_CONDVAR cv);
void condvar_destroy(CRYPTO_CONDVAR cv);

void mem_barrier();

#endif