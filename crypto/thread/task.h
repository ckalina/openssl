/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTO_TASK_H
# define OPENSSL_CRYPTO_TASK_H
# include <openssl/configuration.h>
# if defined(OPENSSL_THREADS)

#  include <openssl/crypto.h>
#  include <internal/thread.h>
#  include "openssl_threads.h"

typedef struct crypto_task_st {
    void *data;
    struct list list;

    CRYPTO_THREAD_RETVAL retval;
    CRYPTO_THREAD_ROUTINE routine;

    CRYPTO_MUTEX lock;
    CRYPTO_CONDVAR cond_finished;
    int finished;
} * CRYPTO_TASK;

CRYPTO_TASK CRYPTO_TASK_new(CRYPTO_THREAD_ROUTINE start, void *data);
void CRYPTO_TASK_clean(CRYPTO_TASK t);

# endif /* defined(OPENSSL_THREADS) */
#endif /* OPENSSL_CRYPTO_TASK_H */
