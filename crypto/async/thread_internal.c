/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


# include "thread.h"
# include "thread_internal.h"

int CRYPTO_THREAD_INTERN_enabled = 0;

# ifdef OPENSSL_NO_INTERN_THREAD

int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS* props)
{
    return 0;
}

int CRYPTO_THREAD_INTERN_disable(void)
{
    return 1;
}
# else /* ! OPENSSL_NO_EXTERN_THREAD */

int CRYPTO_THREAD_INTERN_enable(CRYPTO_SIGNAL_PROPS* props)
{
    if (props == NULL)
        return 0;

    if (CRYPTO_THREAD_INTERN_enabled == 1)
        return 1;

    if (CRYPTO_SIGNAL_block_set(props) != 1)
        goto fail;

    CRYPTO_THREAD_INTERN_enabled = 1;
    return 1;

fail:
    CRYPTO_THREAD_INTERN_disable();
    return 0;
}

int CRYPTO_THREAD_INTERN_disable()
{
    /* @TODO unblock signals */
    CRYPTO_THREAD_INTERN_enabled = 0;
    return 1;
}

# endif

CRYPTO_THREAD CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE routine,
                                       CRYPTO_THREAD_DATA data)
{
    return thread_create(routine, data);
}

int CRYPTO_THREAD_INTERN_join(CRYPTO_THREAD thread,
                              CRYPTO_THREAD_RETVAL* retval)
{
    return thread_join(thread, retval);
}

void CRYPTO_THREAD_INTERN_exit(CRYPTO_THREAD_RETVAL retval)
{
    thread_exit(retval);
}
