/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl/crypto.h"
#include "internal/threads.h"

#undef CRYPTO_THREAD_exit

void * CRYPTO_THREAD_new(CRYPTO_THREAD_ROUTINE start, void* data,
                         unsigned long* ret)
{
	void* thread = NULL;
	if (CRYPTO_THREAD_EXTERN_enabled == 1) {
		thread = CRYPTO_THREAD_EXTERN_add_job(start, data);
		if (ret != NULL)
			*ret = (thread == NULL) ? 0 : 1;
	}
	else if (CRYPTO_THREAD_INTERN_enabled == 1) {
		thread = CRYPTO_THREAD_INTERN_new(start, data, ret);
	}
	return thread;
}

int CRYPTO_THREAD_join(void* thread, unsigned long* retval)
{
	if (CRYPTO_THREAD_EXTERN_enabled == 1)
		return CRYPTO_THREAD_EXTERN_join(thread, retval);
	if (CRYPTO_THREAD_INTERN_enabled == 1)
		return CRYPTO_THREAD_INTERN_join(thread, retval);
	return 0;
}

int CRYPTO_THREAD_exit(unsigned long retval)
{
    if (CRYPTO_THREAD_EXTERN_enabled == 1 && ASYNC_is_capable()) {
        CRYPTO_THREAD_INTERN_exit(retval);
        return 1;
    } else if (CRYPTO_THREAD_INTERN_enabled == 1) {
        CRYPTO_THREAD_INTERN_exit(retval);
        return 1;
    }
    return 0;
}

long int CRYPTO_THREAD_provide(CRYPTO_THREAD_CALLBACK cb)
{
	long ret;
	CRYPTO_THREAD_EXTERN_provide(&ret, cb);
	return ret;
}