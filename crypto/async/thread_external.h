/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#if defined(OPENSSL_THREADS)
# ifndef OPENSSL_THREAD_EXTERNAL_H
#  define OPENSSL_THREAD_EXTERNAL_H
#  pragma once

#  include <openssl/crypto.h>
#  include <internal/list.h>

enum {
    THREAD_ASYNC_RDY = 1 << 0,
    THREAD_ASYNC_ERR = 1 << 1,
    THREAD_ASYNC_CAPABLE = 1 << 2,
};

typedef struct {
    CRYPTO_THREAD_ROUTINE    task;
    void* data;
    unsigned long            retval;
    struct list              list;
} CRYPTO_THREAD_TASK;

void* CRYPTO_THREAD_EXTERN_add_job(CRYPTO_THREAD_ROUTINE task, void* data);
int   CRYPTO_THREAD_EXTERN_join(void* task_id, unsigned long* retval);
CRYPTO_THREAD CRYPTO_THREAD_EXTERN_provide(CRYPTO_THREAD_CALLBACK cb);

# endif
#endif
