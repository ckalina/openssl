/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_THREAD_INTERNAL_H
# define OPENSSL_THREAD_INTERNAL_H
# pragma once

# include <openssl/crypto.h>

void * CRYPTO_THREAD_INTERN_new(CRYPTO_THREAD_ROUTINE start, void* data,
                                unsigned long* ret);
int    CRYPTO_THREAD_INTERN_join(void* thread, unsigned long* retval);
void   CRYPTO_THREAD_INTERN_exit(unsigned long retval);

#endif