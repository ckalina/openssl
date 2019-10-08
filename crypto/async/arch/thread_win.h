/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#if defined(OPENSSL_THREADS)
# if defined(OPENSSL_SYS_WINDOWS) && ( \
     defined(_WIN32_WINNT) && _WIN32_WINNT >= _WIN32_WINNT_VISTA \
  )
#  ifndef OPENSSL_CRYPTO_THREAD_WIN
#   define OPENSSL_CRYPTO_THREAD_WIN
#   pragma once

#include <windows.h>

typedef struct {
    CRYPTO_THREAD_STATE   state;
    HANDLE*               handle;
    CRYPTO_THREAD_ROUTINE routine;
    CRYPTO_THREAD_DATA    data;
    CRYPTO_THREAD_RETVAL  retval;
} CRYPTO_THREAD_WIN;

typedef CRITICAL_SECTION CRYPTO_MUTEX_WIN;
typedef CONDITION_VARIABLE CRYPTO_CONDVAR_WIN;

#  endif
# endif
#endif
