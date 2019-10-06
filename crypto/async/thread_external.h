/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_THREAD_EXTERNAL_H
# define OPENSSL_THREAD_EXTERNAL_H
# pragma once

# include <openssl/crypto.h>
# include <internal/list.h>

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

#endif